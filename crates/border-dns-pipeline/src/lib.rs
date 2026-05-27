//! DNS query hot-path orchestration for BorderDNS.
//!
//! Wires together: route stage → cache stage → upstream stage → aggregation.
//! This crate owns the pipeline logic but must not own scoring rules,
//! GeoIP logic, or domain knowledge.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use border_dns_cache::DnsCache;
use border_dns_config::Config;
use border_dns_domain_knowledge::BuiltInDomainKnowledge;
use border_dns_geoip::SimpleGeoIp;
use border_dns_route_policy::RouteDecision;
use border_dns_route_policy::RoutePolicy;
use border_dns_upstream;
use dns_protocol::header::ResponseCode;
use dns_protocol::message::DnsMessage;
use dns_transport::RequestMeta;
use dns_types::QType;
use dns_types::Route;

// ─── Query Context ───────────────────────────────────────────────

/// Context for a single DNS query flowing through the pipeline.
#[derive(Debug, Clone)]
pub struct QueryContext {
    /// The parsed DNS query message.
    pub query: DnsMessage,
    /// Request metadata (transport, peer, timing).
    pub meta: RequestMeta,
    /// Domain name from the query.
    pub domain: String,
    /// Query type.
    pub qtype: QType,
    /// The assigned route for this query.
    pub route: Route,
    /// Route decision details.
    pub decision: RouteDecision,
    /// When the pipeline started processing.
    pub started_at: Instant,
}

// ─── Pipeline ────────────────────────────────────────────────────

/// The DNS query pipeline.
///
/// Orchestrates: route determination → cache lookup → upstream resolve → answer selection.
#[derive(Debug)]
pub struct Pipeline {
    config: Arc<Config>,
    cache: Arc<DnsCache>,
    domain_knowledge: Arc<BuiltInDomainKnowledge>,
    geoip: Arc<SimpleGeoIp>,
    route_policy: Arc<RoutePolicy>,
}

impl Pipeline {
    /// Create a new pipeline from configuration and shared state.
    #[must_use]
    pub fn new(
        config: Arc<Config>,
        cache: Arc<DnsCache>,
        domain_knowledge: Arc<BuiltInDomainKnowledge>,
        geoip: Arc<SimpleGeoIp>,
    ) -> Self {
        let route_policy = Arc::new(RoutePolicy::new(config.resolver.location));
        Self {
            config,
            cache,
            domain_knowledge,
            geoip,
            route_policy,
        }
    }

    /// Execute the full pipeline for a DNS query.
    ///
    /// Returns a `DnsMessage` response.
    pub async fn resolve(&self, query_bytes: &[u8], meta: &RequestMeta) -> DnsMessage {
        let total_start = Instant::now();

        // ── Stage 1: Parse ─────────────────────────────────────
        let query = match DnsMessage::from_wire(query_bytes) {
            Ok(q) => q,
            Err(_) => {
                tracing::warn!(
                    transport = %meta.transport,
                    peer = ?meta.peer_addr,
                    "QUERY malformed"
                );
                return malformed_response();
            }
        };

        let (qtype, domain) = match query.first_question() {
            Some(q) => (q.qtype, q.qname.clone()),
            None => {
                let mut resp = DnsMessage::response(&query);
                resp.header.rcode = ResponseCode::FormErr;
                return resp;
            }
        };

        let domain_str = domain.to_string();
        let id = query.header.id;

        // ── Stage 2: Route Determination ───────────────────────
        let decision = self
            .route_policy
            .decide_by_domain_prior(&domain_str, &*self.domain_knowledge);
        let route = decision.execution_route;

        tracing::info!(
            transport = %meta.transport,
            peer = ?meta.peer_addr,
            id = id,
            qname = %domain_str,
            qtype = ?qtype,
            route = %route,
            route_source = %decision.route_source.as_str(),
            confidence = %decision.confidence.as_str(),
            "QUERY"
        );

        // ── Stage 3: Cache Lookup (route-scoped) ──────────────
        if let Some(cached) = self.cache.get_scoped(route, qtype, &domain) {
            let mut resp = (**cached.message()).clone();
            resp.header.id = query.header.id;
            let answer_count = resp.answers.len();
            tracing::info!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                id = id,
                qname = %domain_str,
                qtype = ?qtype,
                route = %route,
                rcode = "NOERROR",
                answers = answer_count,
                latency_ms = total_start.elapsed().as_millis(),
                source = "cache",
                "RESP"
            );
            return resp;
        }

        // ── Stage 4: Upstream Resolve ──────────────────────────
        let upstreams = self.config.upstreams.for_route(route);
        let timeout_dur = Duration::from_millis(self.config.server.default_timeout_ms);

        match border_dns_upstream::forward(&query, upstreams, timeout_dur).await {
            Ok(upstream_resp) => {
                let elapsed = total_start.elapsed();
                let rcode = upstream_resp.message.header.rcode;
                let answer_count = upstream_resp.message.answers.len();

                // ── Stage 5: Geo Evidence Analysis ─────────────
                let mut final_decision = decision.clone();
                let evidence = self
                    .route_policy
                    .analyze_answer_geo(&upstream_resp.message.answers, &*self.geoip);
                self.route_policy
                    .refine_by_answer_geo(&mut final_decision, &evidence);

                // ── Stage 6: Answer Selection ──────────────────
                let selected_answers = self.route_policy.select_answer_candidates(
                    &upstream_resp.message.answers,
                    &*self.geoip,
                    route,
                );

                tracing::info!(
                    transport = %meta.transport,
                    peer = ?meta.peer_addr,
                    id = id,
                    qname = %domain_str,
                    qtype = ?qtype,
                    route = %route,
                    rcode = ?rcode,
                    answers = answer_count,
                    selected = selected_answers.len(),
                    cn_ips = evidence.cn_count,
                    foreign_ips = evidence.foreign_count,
                    upstream = %upstream_resp.server_name,
                    upstream_rtt_ms = upstream_resp.rtt.as_millis(),
                    latency_ms = elapsed.as_millis(),
                    source = "upstream",
                    "RESP"
                );

                // ── Stage 7: Cache Insert ──────────────────────
                if rcode == ResponseCode::NoError && answer_count > 0 {
                    self.cache
                        .insert_scoped(route, qtype, &domain, &upstream_resp.message);
                }

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
                    route = %route,
                    error = %e,
                    latency_ms = elapsed.as_millis(),
                    "RESP FAIL"
                );

                let mut resp = DnsMessage::response(&query);
                resp.header.rcode = ResponseCode::ServFail;
                resp
            }
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

#[cfg(test)]
#[path = "pipeline_tests.rs"]
mod tests;
