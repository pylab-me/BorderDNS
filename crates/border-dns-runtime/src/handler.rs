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

    // ── Hosts override ──────────────────────────────────────────
    if ctx.config.hosts.enabled {
        let host_ips = ctx.hosts.match_domain(&domain_str, qtype);
        if !host_ips.is_empty() {
            let mut resp = DnsMessage::response(&query);
            let rr_type = qtype.as_record_type().unwrap_or(dns_types::RecordType::A);
            for ip in &host_ips {
                use dns_protocol::rr::RData;
                let rdata = match ip {
                    std::net::IpAddr::V4(v4) => RData::A(*v4),
                    std::net::IpAddr::V6(v6) => RData::AAAA(*v6),
                };
                let rr = dns_protocol::rr::ResourceRecord {
                    name: domain.clone(),
                    rr_type,
                    class: dns_types::RecordClass::In,
                    ttl: ctx.config.hosts.ttl_secs,
                    rdata,
                };
                resp.add_answer(rr);
            }
            tracing::info!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                id = id,
                qname = %domain_str,
                qtype = ?qtype,
                answers = resp.answers.len(),
                source = "hosts",
                "RESP"
            );
            let wire = resp.to_wire();
            return HandlerResponse {
                wire,
                message: resp,
            };
        }
    }

    // ── Domain block ────────────────────────────────────────────
    if ctx.config.block.enabled && ctx.block_matcher.is_blocked(&domain_str) {
        tracing::info!(
            transport = %meta.transport,
            peer = ?meta.peer_addr,
            id = id,
            qname = %domain_str,
            qtype = ?qtype,
            source = "block",
            "RESP"
        );
        let resp = build_block_response(ctx, &query, qtype, &domain);
        let wire = resp.to_wire();
        return HandlerResponse {
            wire,
            message: resp,
        };
    }

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

    match border_dns_upstream::forward(
        &query,
        ctx.config.upstreams.default_upstreams(),
        timeout_dur,
    )
    .await
    {
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

/// Build a block response for a blocked domain query.
///
/// Behavior:
/// 1. If `qtype` is in `suppress_qtypes`, return SOA (fully suppressed).
/// 2. A → blackhole IPv4, AAAA → blackhole IPv6.
/// 3. All other types → SOA negative response.
fn build_block_response(
    ctx: &Arc<RuntimeContext>,
    query: &DnsMessage,
    qtype: dns_types::QType,
    domain: &dns_protocol::name::DomainName,
) -> DnsMessage {
    use dns_protocol::rr::RData;
    use dns_protocol::rr::ResourceRecord;
    use dns_types::RecordType;

    let mut resp = DnsMessage::response(query);

    // ── suppress_qtypes: if the qtype name matches, return SOA directly ──
    let qtype_suppressed = qtype.as_record_type().is_some_and(|rt| {
        let name = rt.as_str();
        ctx.config
            .block
            .suppress_qtypes
            .iter()
            .any(|s| s.eq_ignore_ascii_case(name))
    });

    if qtype_suppressed {
        return build_soa_suppress_response(&resp, domain);
    }

    // ── Standard blackhole response ──
    let blackhole_v4: std::net::Ipv4Addr = ctx
        .config
        .block
        .blackhole_ipv4
        .parse()
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
    let blackhole_v6: std::net::Ipv6Addr = ctx
        .config
        .block
        .blackhole_ipv6
        .parse()
        .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);

    match qtype {
        dns_types::QType::Type(RecordType::A) => {
            resp.add_answer(ResourceRecord {
                name: domain.clone(),
                rr_type: RecordType::A,
                class: dns_types::RecordClass::In,
                ttl: 60,
                rdata: RData::A(blackhole_v4),
            });
        }
        dns_types::QType::Type(RecordType::AAAA) => {
            resp.add_answer(ResourceRecord {
                name: domain.clone(),
                rr_type: RecordType::AAAA,
                class: dns_types::RecordClass::In,
                ttl: 60,
                rdata: RData::AAAA(blackhole_v6),
            });
        }
        _ => {
            return build_soa_suppress_response(&resp, domain);
        }
    }

    resp
}

/// Build a SOA negative (suppress) response for a blocked domain.
fn build_soa_suppress_response(
    resp: &DnsMessage,
    domain: &dns_protocol::name::DomainName,
) -> DnsMessage {
    use dns_protocol::rr::RData;
    use dns_protocol::rr::ResourceRecord;
    use dns_types::RecordType;

    let mut out = DnsMessage::response(resp);
    out.header.rcode = ResponseCode::NoError;
    let soa_name = dns_protocol::name::DomainName::from_str("block.borderdns.local")
        .unwrap_or_else(|_| dns_protocol::name::DomainName::root());
    out.add_authority(ResourceRecord {
        name: domain.clone(),
        rr_type: RecordType::SOA,
        class: dns_types::RecordClass::In,
        ttl: 60,
        rdata: RData::SOA(dns_protocol::rr::SoaRecord {
            mname: soa_name.clone(),
            rname: soa_name,
            serial: 1,
            refresh: 900,
            retry: 900,
            expire: 1800,
            minimum: 60,
        }),
    });
    out
}
