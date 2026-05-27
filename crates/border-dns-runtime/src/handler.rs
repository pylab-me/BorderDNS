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
/// 2. Check cache.
/// 3. Forward to upstream.
/// 4. Cache the response.
/// 5. Return the resolved answer.
pub async fn handle_dns_query(
    query_bytes: &[u8],
    ctx: &Arc<RuntimeContext>,
    meta: &RequestMeta,
) -> DnsMessage {
    // Parse DNS message.
    let query = match DnsMessage::from_wire(query_bytes) {
        Ok(q) => q,
        Err(_) => {
            tracing::debug!(transport = %meta.transport, "failed to parse DNS query");
            return malformed_response();
        }
    };

    let (qtype, domain) = match query.first_question() {
        Some(q) => (q.qtype, q.qname.clone()),
        None => {
            tracing::debug!(transport = %meta.transport, "query has no question section");
            let mut resp = DnsMessage::response(&query);
            resp.header.rcode = ResponseCode::FormErr;
            return resp;
        }
    };

    let domain_str = domain.to_string();

    // Cache lookup.
    if let Some(cached) = ctx.cache.get(qtype, &domain) {
        let mut resp = cached;
        resp.header.id = query.header.id;
        ctx.metrics.for_transport(meta.transport).record_cache_hit();
        tracing::debug!(
            transport = %meta.transport,
            domain = %domain_str,
            qtype = ?qtype,
            "cache hit"
        );
        return resp;
    }

    // Forward to upstream.
    let timeout_dur = Duration::from_millis(ctx.config.server.default_timeout_ms);
    let start = Instant::now();

    match border_dns_upstream::forward(&query, &ctx.config.upstreams.default, timeout_dur).await {
        Ok(upstream_resp) => {
            let elapsed = start.elapsed();

            tracing::debug!(
                transport = %meta.transport,
                domain = %domain_str,
                qtype = ?qtype,
                upstream = %upstream_resp.server_name,
                rcode = ?upstream_resp.message.header.rcode,
                latency_ms = elapsed.as_millis(),
                "upstream resolved"
            );

            // Cache the response (only for successful answers).
            if upstream_resp.message.header.rcode == ResponseCode::NoError
                && !upstream_resp.message.answers.is_empty()
            {
                ctx.cache
                    .insert(qtype, &domain, upstream_resp.message.clone());
            }

            ctx.metrics.for_transport(meta.transport).record_response();
            upstream_resp.message
        }
        Err(e) => {
            tracing::warn!(
                transport = %meta.transport,
                domain = %domain_str,
                qtype = ?qtype,
                error = %e,
                "all upstreams failed"
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
