//! Unified DNS request handler.
//!
//! All inbound transports (UDP, TCP, DoT, DoH, DoQ, DoJ) funnel through
//! this single handler. It performs cache lookup, upstream forwarding,
//! and response caching — no transport may bypass it.
//!
//! Sprint 2 optimizations:
//! - Returns `HandlerResponse` containing both pre-serialized wire bytes and
//!   the parsed `DnsMessage`. Wire bytes are serialized once; server paths
//!   (UDP/TCP/DoT/DoH) send them directly without re-encoding.
//! - Cache hit returns pre-serialized wire bytes with ID patched in-place
//!   (zero deep-clone).

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use dns_protocol::header::ResponseCode;
use dns_protocol::message::DnsMessage;
use dns_transport::RequestMeta;

use crate::RuntimeContext;

/// Result of the unified DNS handler pipeline.
///
/// Contains both the pre-serialized wire bytes (for direct sending) and the
/// parsed `DnsMessage` (for logging and DoJ JSON conversion).
#[derive(Debug)]
pub struct HandlerResponse {
    wire: Vec<u8>,
    message: DnsMessage,
}

impl HandlerResponse {
    /// Pre-serialized DNS wire bytes, ready to send.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// Owned wire bytes.
    #[must_use]
    pub fn into_wire(self) -> Vec<u8> {
        self.wire
    }

    /// Parsed DNS message (for logging / DoJ JSON conversion).
    #[must_use]
    pub fn message(&self) -> &DnsMessage {
        &self.message
    }
}

/// Handle a DNS query through the unified pipeline.
///
/// 1. Parse the query.
/// 2. Log the incoming query to console.
/// 3. Check cache.
/// 4. Forward to upstream.
/// 5. Cache the response.
/// 6. Return the resolved answer as pre-serialized wire bytes + parsed message.
pub async fn handle_dns_query(
    query_bytes: &[u8],
    ctx: &Arc<RuntimeContext>,
    meta: &RequestMeta,
) -> HandlerResponse {
    let total_start = Instant::now();

    // Parse DNS message.
    let query = match DnsMessage::from_wire(query_bytes) {
        Ok(q) => q,
        Err(_) => {
            tracing::warn!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                "QUERY malformed - failed to parse DNS wire"
            );
            return malformed_response();
        }
    };

    let (qtype, domain) = match query.first_question() {
        Some(q) => (q.qtype, q.qname.clone()),
        None => {
            tracing::warn!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                "QUERY empty - no question section"
            );
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = ResponseCode::FormErr;
            let wire = resp.to_wire();
            return HandlerResponse {
                wire,
                message: resp,
            };
        }
    };

    let domain_str = domain.to_string();
    let id = query.header.id;

    // ── Console query log ───────────────────────────────────────
    tracing::info!(
        transport = %meta.transport,
        peer = ?meta.peer_addr,
        id = id,
        qname = %domain_str,
        qtype = ?qtype,
        "QUERY"
    );

    // Cache lookup — returns CachedResponse with pre-serialized wire bytes.
    if let Some(cached) = ctx.cache.get(qtype, &domain) {
        let resp_wire = cached.wire_with_id(id);
        let answer_count = cached.message().answers.len();
        ctx.metrics.for_transport(meta.transport).record_cache_hit();
        tracing::info!(
            transport = %meta.transport,
            peer = ?meta.peer_addr,
            id = id,
            qname = %domain_str,
            qtype = ?qtype,
            rcode = "NOERROR",
            answers = answer_count,
            latency_ms = total_start.elapsed().as_millis(),
            source = "cache",
            "RESP"
        );
        return HandlerResponse {
            wire: resp_wire,
            message: (**cached.message()).clone(),
        };
    }

    // Forward to upstream.
    let timeout_dur = Duration::from_millis(ctx.config.server.default_timeout_ms);

    match border_dns_upstream::forward(&query, &ctx.config.upstreams.default, timeout_dur).await {
        Ok(upstream_resp) => {
            let elapsed = total_start.elapsed();
            let rcode = upstream_resp.message.header.rcode;
            let answer_count = upstream_resp.message.answers.len();

            tracing::info!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                id = id,
                qname = %domain_str,
                qtype = ?qtype,
                rcode = ?rcode,
                answers = answer_count,
                upstream = %upstream_resp.server_name,
                upstream_rtt_ms = upstream_resp.rtt.as_millis(),
                latency_ms = elapsed.as_millis(),
                source = "upstream",
                "RESP"
            );

            // Cache the response (only for successful answers with records).
            if rcode == ResponseCode::NoError && answer_count > 0 {
                ctx.cache.insert(qtype, &domain, &upstream_resp.message);
            }

            ctx.metrics.for_transport(meta.transport).record_response();

            let wire = upstream_resp.message.to_wire();
            HandlerResponse {
                wire,
                message: upstream_resp.message,
            }
        }
        Err(e) => {
            let elapsed = total_start.elapsed();
            tracing::error!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                id = id,
                qname = %domain_str,
                qtype = ?qtype,
                error = %e,
                latency_ms = elapsed.as_millis(),
                "RESP FAIL"
            );
            ctx.metrics.for_transport(meta.transport).record_error();

            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = ResponseCode::ServFail;
            let wire = resp.to_wire();
            HandlerResponse {
                wire,
                message: resp,
            }
        }
    }
}

/// Build a minimal malformed-request response.
fn malformed_response() -> HandlerResponse {
    let mut header = dns_protocol::header::DnsHeader::response(0, false);
    header.rcode = ResponseCode::FormErr;
    let msg = DnsMessage {
        header,
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    };
    let wire = msg.to_wire();
    HandlerResponse { wire, message: msg }
}
