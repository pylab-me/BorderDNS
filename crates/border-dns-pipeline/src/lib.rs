//! DNS query hot-path orchestration for BorderDNS.
//!
//! Wires together: route stage → cache stage → upstream stage → aggregation.
//! This crate owns the pipeline logic but must not own scoring rules,
//! GeoIP logic, or domain knowledge.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use border_dns_upstream;
use dns_protocol::header::ResponseCode;
use dns_protocol::message::DnsMessage;
use dns_transport::RequestMeta;
use dns_types::QType;
use dns_types::Route;
use domain_knowledge::BlockMatcher;
use domain_knowledge::BuiltInDomainKnowledge;
use domain_knowledge::HostsTable;
use facts::FactEmitter;
use facts::GovernancePhase;
use facts::GovernanceStateStore;
use facts::GovernanceThresholds;
use facts::MeaningfulEventKind;
use facts::ObservationTask;
use facts::ObservationTaskKind;
use geoip::SimpleGeoIp;
use route_cache::RouteScopedCache;
use route_policy::RouteDecision;
use route_policy::RoutePolicy;
use route_policy::governance_transition::GovernanceTransitionInput;
use route_policy::governance_transition::evaluate_governance_transition;
use route_policy::scoring::RouteEvidenceInput;
use route_policy::scoring::score_route_evidence;
use runtime_config::RuntimeConfig;

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
/// Orchestrates: hosts override → block → route determination → cache lookup → upstream resolve → answer selection.
#[derive(Debug)]
pub struct Pipeline {
    config: Arc<RuntimeConfig>,
    cache: Arc<RouteScopedCache>,
    domain_knowledge: Arc<BuiltInDomainKnowledge>,
    geoip: Arc<SimpleGeoIp>,
    route_policy: Arc<RoutePolicy>,
    governance_store: Arc<GovernanceStateStore>,
    governance_thresholds: Arc<GovernanceThresholds>,
    /// Hosts override table (static domain → IP).
    hosts: Arc<HostsTable>,
    /// Domain block matcher.
    block_matcher: Arc<BlockMatcher>,
    /// Channel sender for fact emissions (non-blocking).
    fact_tx: tokio::sync::mpsc::UnboundedSender<FactEmitter>,
    /// Channel sender for observation tasks (non-blocking).
    observation_tx: tokio::sync::mpsc::UnboundedSender<ObservationTask>,
}

impl Pipeline {
    /// Create a new pipeline from configuration and shared state.
    #[must_use]
    pub fn new(
        config: Arc<RuntimeConfig>,
        cache: Arc<RouteScopedCache>,
        domain_knowledge: Arc<BuiltInDomainKnowledge>,
        geoip: Arc<SimpleGeoIp>,
    ) -> Self {
        let route_policy = Arc::new(RoutePolicy::new(config.resolver.location));
        let governance_store = Arc::new(GovernanceStateStore::new());
        let mut governance_thresholds = GovernanceThresholds::default();
        governance_thresholds.third_party_mode = if config.third_party.enabled {
            facts::ThirdPartyMode::Enabled
        } else {
            facts::ThirdPartyMode::Disabled
        };
        let governance_thresholds = Arc::new(governance_thresholds);
        let (fact_tx, _fact_rx) = tokio::sync::mpsc::unbounded_channel();
        let (observation_tx, _observation_rx) = tokio::sync::mpsc::unbounded_channel();

        let hosts = Arc::new(Self::build_hosts_from_config(&config.hosts));
        let block_matcher = Arc::new(Self::build_block_matcher_from_config(&config.block));

        Self {
            config,
            cache,
            domain_knowledge,
            geoip,
            route_policy,
            governance_store,
            governance_thresholds,
            hosts,
            block_matcher,
            fact_tx,
            observation_tx,
        }
    }

    /// Create a pipeline with governance channels wired externally.
    ///
    /// The receivers should be consumed by background workers.
    #[must_use]
    pub fn with_governance_channels(
        config: Arc<RuntimeConfig>,
        cache: Arc<RouteScopedCache>,
        domain_knowledge: Arc<BuiltInDomainKnowledge>,
        geoip: Arc<SimpleGeoIp>,
        governance_store: Arc<GovernanceStateStore>,
        governance_thresholds: Arc<GovernanceThresholds>,
        fact_tx: tokio::sync::mpsc::UnboundedSender<FactEmitter>,
        observation_tx: tokio::sync::mpsc::UnboundedSender<ObservationTask>,
    ) -> Self {
        let route_policy = Arc::new(RoutePolicy::new(config.resolver.location));
        let hosts = Arc::new(Self::build_hosts_from_config(&config.hosts));
        let block_matcher = Arc::new(Self::build_block_matcher_from_config(&config.block));

        Self {
            config,
            cache,
            domain_knowledge,
            geoip,
            route_policy,
            governance_store,
            governance_thresholds,
            hosts,
            block_matcher,
            fact_tx,
            observation_tx,
        }
    }

    /// Access the governance store (for inspection / admin).
    #[must_use]
    pub fn governance_store(&self) -> &Arc<GovernanceStateStore> {
        &self.governance_store
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

        // ── Stage 1.5: Hosts Override ───────────────────────────
        if self.config.hosts.enabled {
            let host_ips = self.hosts.match_domain(&domain_str, qtype);
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
                        ttl: self.config.hosts.ttl_secs,
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
                return resp;
            }
        }

        // ── Stage 1.6: Domain Block ─────────────────────────────
        if self.config.block.enabled && self.block_matcher.is_blocked(&domain_str) {
            tracing::info!(
                transport = %meta.transport,
                peer = ?meta.peer_addr,
                id = id,
                qname = %domain_str,
                qtype = ?qtype,
                source = "block",
                "RESP"
            );
            return self.build_block_response(&query, qtype, &domain);
        }

        // ── Stage 2: Route Determination ───────────────────────
        let decision = self
            .route_policy
            .decide_by_domain_prior(&domain_str, &*self.domain_knowledge);
        let route = decision.execution_route;

        // ── Stage 2.5: Governance State ────────────────────────
        let prior_route_str = match route {
            Route::China => "china",
            Route::Foreign => "foreign",
            Route::Bootstrap => "bootstrap",
            Route::Fallback => "unknown",
        };
        let gov_state = self
            .governance_store
            .get_or_create(&domain_str, prior_route_str);
        let is_first_seen =
            gov_state.observation_count == 0 && gov_state.phase == GovernancePhase::New;

        tracing::info!(
            transport = %meta.transport,
            peer = ?meta.peer_addr,
            id = id,
            qname = %domain_str,
            qtype = ?qtype,
            route = %route,
            route_source = %decision.route_source.as_str(),
            confidence = %decision.confidence.as_str(),
            gov_phase = %gov_state.phase,
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

                // ── Stage 5.5: Scoring Engine ──────────────────
                let score_input = RouteEvidenceInput {
                    prior_route: prior_route_str.to_string(),
                    local_cn_ip_count: evidence.cn_count as u32,
                    local_foreign_ip_count: evidence.foreign_count as u32,
                    ..RouteEvidenceInput::default()
                };
                let score = score_route_evidence(&score_input);

                // ── Stage 5.6: Governance Transition ───────────
                let gov_input = GovernanceTransitionInput {
                    state: (*gov_state).clone(),
                    latest_can_promote: score.can_promote,
                    latest_is_mixed: evidence.cn_count > 0 && evidence.foreign_count > 0,
                    latest_tls_mismatch: false,
                    latest_hard_conflict: false,
                    latest_soft_conflict: false,
                    latest_local_aligned: score.can_promote,
                    latest_third_party_aligned: false,
                    is_first_seen,
                    upstream_failure: false,
                    thresholds: (*self.governance_thresholds).clone(),
                };
                let transition = evaluate_governance_transition(&gov_input);

                // Update governance state if phase changed
                if transition.phase_changed || is_first_seen {
                    let mut new_state = (*gov_state).clone();
                    new_state.phase = transition.new_phase.clone();
                    new_state.observation_count += 1;
                    new_state.china_score = score.china_score;
                    new_state.foreign_score = score.foreign_score;
                    new_state.score_margin = score.score_margin;
                    new_state.can_promote = score.can_promote;
                    new_state.state_version += 1;
                    self.governance_store.force_update(&domain_str, new_state);

                    // Emit meaningful event
                    let event_kind = if is_first_seen {
                        MeaningfulEventKind::FirstSeenDomain
                    } else {
                        MeaningfulEventKind::PhaseChanged
                    };
                    let mut fact = FactEmitter::new(
                        domain_str.clone(),
                        event_kind,
                        transition.reason_code.to_string(),
                    );
                    fact.phase_changed = true;
                    fact.new_phase = Some(transition.new_phase.clone());
                    let _ = self.fact_tx.send(fact);
                }

                // Enqueue observation task if we have IPs to analyze
                if evidence.cn_count + evidence.foreign_count > 0 {
                    let ip_addrs: Vec<String> = upstream_resp
                        .message
                        .answers
                        .iter()
                        .filter_map(|rr| {
                            use dns_protocol::rr::RData;
                            match &rr.rdata {
                                RData::A(a) => Some(a.to_string()),
                                RData::AAAA(a) => Some(a.to_string()),
                                _ => None,
                            }
                        })
                        .collect();

                    if !ip_addrs.is_empty() {
                        let task = ObservationTask {
                            job_id: format!("geo-{}-{}", domain_str, id),
                            domain: domain_str.clone(),
                            task_kind: ObservationTaskKind::GeoAnalysis {
                                ip_addresses: ip_addrs,
                                cname_chain: Vec::new(),
                            },
                            current_phase: transition.new_phase,
                            current_route: prior_route_str.to_string(),
                            enqueued_at: chrono::Utc::now(),
                        };
                        let _ = self.observation_tx.send(task);
                    }
                }

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
                    gov_phase = %transition.new_phase,
                    china_score = score.china_score,
                    foreign_score = score.foreign_score,
                    score_margin = score.score_margin,
                    "RESP"
                );

                // ── Stage 7: Cache Insert (location-aware TTL) ──
                if rcode == ResponseCode::NoError && answer_count > 0 {
                    // Location-aware TTL: china+china uses enhanced (longer) TTL.
                    let effective_ttl = if route == Route::China
                        && self.config.resolver.location == dns_types::ResolverLocation::China
                    {
                        self.config.cache.enhanced_ttl_secs
                    } else {
                        // Use the minimum answer TTL (normal behavior).
                        upstream_resp
                            .message
                            .answers
                            .iter()
                            .map(|rr| rr.ttl)
                            .min()
                            .unwrap_or(0)
                    };
                    self.cache.insert_scoped_with_ttl(
                        route,
                        qtype,
                        &domain,
                        &upstream_resp.message,
                        effective_ttl,
                    );
                }

                upstream_resp.message
            }
            Err(e) => {
                let elapsed = total_start.elapsed();

                // Enqueue failure observation job
                let task = ObservationTask {
                    job_id: format!("fail-{}-{}", domain_str, id),
                    domain: domain_str.clone(),
                    task_kind: ObservationTaskKind::GeoAnalysis {
                        ip_addresses: Vec::new(),
                        cname_chain: Vec::new(),
                    },
                    current_phase: gov_state.phase.clone(),
                    current_route: prior_route_str.to_string(),
                    enqueued_at: chrono::Utc::now(),
                };
                let _ = self.observation_tx.send(task);

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

    // ─── Hosts / Block config builder helpers ──────────────────────

    fn build_hosts_from_config(hosts_config: &runtime_config::HostsConfig) -> HostsTable {
        if !hosts_config.enabled {
            return HostsTable::new();
        }
        let mut builder = HostsTable::new();
        for (domain, ips) in &hosts_config.entries {
            for ip_str in ips {
                builder = builder.with_entry(domain, ip_str);
            }
        }
        for file_path in &hosts_config.files {
            builder = builder.with_file(std::path::PathBuf::from(file_path));
        }
        builder.build()
    }

    fn build_block_matcher_from_config(block_config: &runtime_config::BlockConfig) -> BlockMatcher {
        if !block_config.enabled {
            return BlockMatcher::default();
        }
        let exact_refs: Vec<&str> = block_config.domains.iter().map(String::as_str).collect();
        let suffix_refs: Vec<&str> = block_config.suffixes.iter().map(String::as_str).collect();
        BlockMatcher::new(&exact_refs, &suffix_refs)
    }

    // ─── Block response builder ──────────────────────────────────

    fn build_block_response(
        &self,
        query: &DnsMessage,
        qtype: QType,
        domain: &dns_protocol::name::DomainName,
    ) -> DnsMessage {
        use dns_protocol::header::ResponseCode;
        use dns_protocol::rr::RData;
        use dns_protocol::rr::ResourceRecord;
        use dns_types::RecordType;

        let mut resp = DnsMessage::response(query);

        let blackhole_v4: std::net::Ipv4Addr = self
            .config
            .block
            .blackhole_ipv4
            .parse()
            .unwrap_or(std::net::Ipv4Addr::LOCALHOST);
        let blackhole_v6: std::net::Ipv6Addr = self
            .config
            .block
            .blackhole_ipv6
            .parse()
            .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED);

        match qtype {
            QType::Type(RecordType::A) => {
                resp.add_answer(ResourceRecord {
                    name: domain.clone(),
                    rr_type: RecordType::A,
                    class: dns_types::RecordClass::In,
                    ttl: 60,
                    rdata: RData::A(blackhole_v4),
                });
            }
            QType::Type(RecordType::AAAA) => {
                resp.add_answer(ResourceRecord {
                    name: domain.clone(),
                    rr_type: RecordType::AAAA,
                    class: dns_types::RecordClass::In,
                    ttl: 60,
                    rdata: RData::AAAA(blackhole_v6),
                });
            }
            _ => {
                // Suppress: return SOA negative response.
                resp.header.rcode = ResponseCode::NoError;
                let soa_name = dns_protocol::name::DomainName::from_str("block.borderdns.local")
                    .unwrap_or_else(|_| dns_protocol::name::DomainName::root());
                resp.add_authority(ResourceRecord {
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
            }
        }

        resp
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
