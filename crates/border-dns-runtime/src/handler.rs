//! Unified DNS request handler.
//!
//! All inbound transports (UDP, TCP, DoT, DoH, DoQ, DoJ) funnel through
//! this single handler. It performs cache lookup, upstream forwarding,
//! and response caching — no transport may bypass it.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use dns_protocol::header::ResponseCode;
use dns_protocol::message::DnsMessage;
use dns_transport::RequestMeta;

use crate::RuntimeContext;

/// Handle a DNS query through the unified pipeline.
///
/// 1. Parse the query.
/// 2. Log the incoming query to console.
/// 3. Check cache.
/// 4. Forward to upstream.
/// 5. Cache the response.
/// 6. Return the resolved answer.
pub async fn handle_dns_query(
    query_bytes: &[u8],
    ctx: &Arc<RuntimeContext>,
    meta: &RequestMeta,
) -> DnsMessage {
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
            return resp;
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

    // Cache lookup.
    if let Some(cached) = ctx.cache.get(qtype, &domain) {
        let mut resp = cached;
        resp.header.id = query.header.id;
        let answer_count = resp.answers.len();
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
        return resp;
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
                ctx.cache
                    .insert(qtype, &domain, upstream_resp.message.clone());
            }

            ctx.metrics.for_transport(meta.transport).record_response();
            upstream_resp.message
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
            resp
        }
    }
}

/// Build a minimal malformed-request response.
fn malformed_response() -> DnsMessage {
    let mut header = dns_protocol::header::DnsHeader::response(0, false);
    header.rcode = ResponseCode::FormErr;
    DnsMessage {
        header,
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
    }
}
