//! Explicit route evidence scoring engine for BorderDNS.
//!
//! Ported from Python `route_score.py` — deterministic, coarse, and
//! deliberately absent of IP latency.
//!
//! Weight direction (hard-coded priority):
//! ```text
//! domain prior / domain-geo authority
//!   > local IP geo
//!   > third-party IP geo
//!   > CNAME provider hint
//!   > TLS identity consistency
//!   > probe quality / latency tie-break (NOT in this module)
//! ```
//!
//! Hard rules enforced:
//! - IP latency / ms never enters china_score / foreign_score
//! - TLS mismatch reduces both scores and sets can_promote = false
//! - global_intent cannot directly promote route class
//! - mixed geo (1 CN + 1 IP) = conflicting, not a route
//! - third-party evidence alone cannot permanently change route

use std::collections::BTreeMap;
use std::fmt;

use facts::CnameScope;
use facts::DomainIntent;
use facts::EvidenceStrength;
use facts::FactStatus;
use facts::GovernancePhase;
use facts::TlsIdentityStatus;

// ─── Weights ─────────────────────────────────────────────────────

/// Stable scoring weights for BorderDNS v1 route-intent evaluation.
///
/// Relative order matters more than exact numbers:
/// domain_prior > local_ip_geo > third_party_ip_geo > cname_provider > tls_identity
///
/// Probe latency never adds route-class authority.
#[derive(Debug, Clone)]
pub struct RouteEvidenceWeights {
    pub domain_prior: f32,
    pub local_ip_geo: f32,
    pub third_party_ip_geo: f32,
    pub cname_provider: f32,
    pub cname_global_each_side: f32,
    pub peer_route_vote: f32,
    pub tls_identity_bonus: f32,
    /// Multiplier applied to both scores when TLS identity is mismatch.
    /// Must be < 1.0 to penalize.
    pub tls_mismatch_multiplier: f32,
    /// Multiplier applied to the opposing score when it challenges a strong prior.
    /// Must be < 1.0 to protect priors from being overridden by a single observation.
    pub prior_conflict_multiplier: f32,
}

impl Default for RouteEvidenceWeights {
    fn default() -> Self {
        Self {
            domain_prior: 2.4,
            local_ip_geo: 1.4,
            third_party_ip_geo: 1.2,
            cname_provider: 0.9,
            cname_global_each_side: 0.25,
            peer_route_vote: 0.5,
            tls_identity_bonus: 0.20,
            tls_mismatch_multiplier: 0.65,
            prior_conflict_multiplier: 0.70,
        }
    }
}

// ─── Input ───────────────────────────────────────────────────────

/// Input for the route evidence scoring engine.
///
/// **Intentionally excludes IP latency** — latency is quality evidence
/// only and must not enter china_score / foreign_score.
#[derive(Debug, Clone)]
pub struct RouteEvidenceInput {
    /// Prior route from domain knowledge (china/foreign/unknown).
    pub prior_route: String,
    /// Number of CN IPs in the local DNS answer.
    pub local_cn_ip_count: u32,
    /// Number of non-CN IPs in the local DNS answer.
    pub local_foreign_ip_count: u32,
    /// Number of CN IPs reported by third-party observers.
    pub third_party_cn_ip_count: u32,
    /// Number of non-CN IPs reported by third-party observers.
    pub third_party_foreign_ip_count: u32,
    /// Third-party peer votes for China route.
    pub peer_china_votes: u32,
    /// Third-party peer votes for Foreign route.
    pub peer_foreign_votes: u32,
    /// IP scope classification of the DNS answer.
    pub ip_scope: String,
    /// CNAME scope classification.
    pub cname_scope: CnameScope,
    /// TLS identity consistency status.
    pub tls_identity_status: TlsIdentityStatus,
    /// Runtime confidence from previous observations (0.0 - 1.0).
    pub runtime_confidence: f32,
    /// Whether this is a first-seen domain for the given route scope.
    pub route_scoped_first_seen: bool,
    /// Scoring weights (use Default::default() for production values).
    pub weights: RouteEvidenceWeights,
}

impl Default for RouteEvidenceInput {
    fn default() -> Self {
        Self {
            prior_route: String::new(),
            local_cn_ip_count: 0,
            local_foreign_ip_count: 0,
            third_party_cn_ip_count: 0,
            third_party_foreign_ip_count: 0,
            peer_china_votes: 0,
            peer_foreign_votes: 0,
            ip_scope: "unknown".into(),
            cname_scope: CnameScope::Unknown,
            tls_identity_status: TlsIdentityStatus::Unknown,
            runtime_confidence: 0.0,
            route_scoped_first_seen: false,
            weights: RouteEvidenceWeights::default(),
        }
    }
}

// ─── Output ──────────────────────────────────────────────────────

/// Explainable score result consumed by fact mapping and governance policy.
#[derive(Debug, Clone)]
pub struct RouteEvidenceScore {
    /// High-level domain routing intent.
    pub domain_intent: DomainIntent,
    /// Overall evidence strength.
    pub evidence_strength: EvidenceStrength,
    /// Confidence level derived from runtime_confidence + evidence.
    pub confidence_level: ConfidenceLevel,
    /// Fact status (observed / candidate / conflicting).
    pub fact_status: FactStatus,
    /// Whether this score can promote the domain to a higher governance phase.
    pub can_promote: bool,
    /// Suggested next route for the domain.
    pub suggested_next_route: String,
    /// Recommended promote action.
    pub promote_action: PromoteAction,
    /// Recommended governance phase for this decision.
    pub decision_phase: GovernancePhase,
    /// Decision timing (immediate / next_query / observe_only).
    pub decision_timing: DecisionTiming,
    /// Primary reason code explaining this score.
    pub reason_code: String,
    /// Aggregate China score.
    pub china_score: f32,
    /// Aggregate Foreign score.
    pub foreign_score: f32,
    /// Absolute difference between china_score and foreign_score.
    pub score_margin: f32,
    /// Primary route authority source.
    pub route_authority: String,
    /// Per-component scores (e.g., "china.domain_prior" -> 2.4).
    pub component_scores: BTreeMap<String, f32>,
    /// Diagnostic notes from scoring.
    pub notes: Vec<String>,
}

// ─── Confidence Level ────────────────────────────────────────────

/// Confidence level for a route decision (mirrors Python Confidence enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfidenceLevel {
    None,
    Low,
    Medium,
    High,
    Conflict,
}

impl ConfidenceLevel {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Conflict => "conflict",
        }
    }
}

impl fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Promote Action ──────────────────────────────────────────────

/// Action recommended by the scoring engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PromoteAction {
    /// No promotion, just observe.
    ObserveOnly,
    /// Promote to Suggested (assisted next-query).
    PromoteAssisted,
}

impl PromoteAction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::PromoteAssisted => "promote_assisted",
        }
    }
}

// ─── Decision Timing ─────────────────────────────────────────────

/// When the route decision takes effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionTiming {
    /// Decision only records evidence, no route change.
    ObserveOnly,
    /// Decision can influence the next query's route.
    AssistedNextQuery,
}

impl DecisionTiming {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::AssistedNextQuery => "assisted_next_query",
        }
    }
}

// ─── Scoring Engine ──────────────────────────────────────────────

/// Compute route intent from schema-aligned evidence.
///
/// This function is deliberately deterministic and coarse. BorderDNS DNS-layer
/// feedback can be fast, but a score may only produce assisted-next-query
/// suggestions when domain/geo/CNAME/TLS evidence is coherent enough.
#[must_use]
pub fn score_route_evidence(data: &RouteEvidenceInput) -> RouteEvidenceScore {
    let weights = &data.weights;
    let prior_route = normalize_route(&data.prior_route);
    let mut china_components: BTreeMap<String, f32> = BTreeMap::new();
    let mut foreign_components: BTreeMap<String, f32> = BTreeMap::new();
    let mut notes: Vec<String> = Vec::new();

    // ── Domain prior ─────────────────────────────────────────
    if prior_route == "china" {
        china_components.insert("domain_prior".into(), weights.domain_prior);
    } else if prior_route == "foreign" {
        foreign_components.insert("domain_prior".into(), weights.domain_prior);
    } else {
        notes.push("no_domain_prior".into());
    }

    // ── Local IP geo ─────────────────────────────────────────
    if data.local_cn_ip_count > 0 {
        china_components.insert(
            "local_ip_geo".into(),
            data.local_cn_ip_count as f32 * weights.local_ip_geo,
        );
    }
    if data.local_foreign_ip_count > 0 {
        foreign_components.insert(
            "local_ip_geo".into(),
            data.local_foreign_ip_count as f32 * weights.local_ip_geo,
        );
    }

    // ── Third-party IP geo ───────────────────────────────────
    if data.third_party_cn_ip_count > 0 {
        china_components.insert(
            "third_party_ip_geo".into(),
            data.third_party_cn_ip_count as f32 * weights.third_party_ip_geo,
        );
    }
    if data.third_party_foreign_ip_count > 0 {
        foreign_components.insert(
            "third_party_ip_geo".into(),
            data.third_party_foreign_ip_count as f32 * weights.third_party_ip_geo,
        );
    }

    // ── Peer route votes ─────────────────────────────────────
    if data.peer_china_votes > 0 {
        china_components.insert(
            "peer_route_vote".into(),
            data.peer_china_votes as f32 * weights.peer_route_vote,
        );
    }
    if data.peer_foreign_votes > 0 {
        foreign_components.insert(
            "peer_route_vote".into(),
            data.peer_foreign_votes as f32 * weights.peer_route_vote,
        );
    }

    // ── CNAME provider hint ──────────────────────────────────
    match data.cname_scope {
        CnameScope::CnProvider => {
            china_components.insert("cname_provider".into(), weights.cname_provider);
        }
        CnameScope::ForeignProvider => {
            foreign_components.insert("cname_provider".into(), weights.cname_provider);
        }
        CnameScope::GlobalCdn => {
            china_components.insert("cname_global".into(), weights.cname_global_each_side);
            foreign_components.insert("cname_global".into(), weights.cname_global_each_side);
        }
        CnameScope::MixedChain => {
            notes.push("mixed_cname_chain".into());
        }
        _ => {}
    }

    // ── Aggregate before TLS ─────────────────────────────────
    let mut china_score: f32 = china_components.values().sum();
    let mut foreign_score: f32 = foreign_components.values().sum();

    // ── TLS identity ─────────────────────────────────────────
    // TLS match strengthens the leading side; mismatch penalizes both.
    match data.tls_identity_status {
        TlsIdentityStatus::ExactMatch | TlsIdentityStatus::CnameMatch => {
            if china_score > foreign_score {
                china_components.insert("tls_identity".into(), weights.tls_identity_bonus);
                china_score += weights.tls_identity_bonus;
            } else if foreign_score > china_score {
                foreign_components.insert("tls_identity".into(), weights.tls_identity_bonus);
                foreign_score += weights.tls_identity_bonus;
            } else {
                notes.push("tls_identity_match_without_route_bias".into());
            }
        }
        TlsIdentityStatus::Mismatch => {
            china_score *= weights.tls_mismatch_multiplier;
            foreign_score *= weights.tls_mismatch_multiplier;
            notes.push("tls_identity_mismatch_downweighted".into());
        }
        _ => {}
    }

    // ── Prior conflict dampening ─────────────────────────────
    // Domain prior has the largest single authority, but strong opposite geo
    // evidence is allowed to challenge it. The challenge becomes assisted at
    // most; maturity is still decided by governance phase transition.
    if !data.route_scoped_first_seen {
        if prior_route == "china" && foreign_score > china_score {
            foreign_score *= weights.prior_conflict_multiplier;
            notes.push("foreign_evidence_challenged_china_prior".into());
        } else if prior_route == "foreign" && china_score > foreign_score {
            china_score *= weights.prior_conflict_multiplier;
            notes.push("china_evidence_challenged_foreign_prior".into());
        }
    }

    // ── Round scores ─────────────────────────────────────────
    let china_score = round_4(china_score);
    let foreign_score = round_4(foreign_score);
    let score_margin = round_4((china_score - foreign_score).abs());

    // ── Derive classifications ───────────────────────────────
    let route_authority = route_authority(data);
    let domain_intent = domain_intent(
        china_score,
        foreign_score,
        &data.ip_scope,
        data.cname_scope,
        &prior_route,
    );
    let evidence_strength = evidence_strength(data, china_score, foreign_score, score_margin);
    let confidence_level = confidence_level(data.runtime_confidence, evidence_strength);
    let reason_code = reason_code(data);
    let can_promote = can_promote(data, domain_intent, evidence_strength, score_margin);
    let fact_status = fact_status(can_promote, evidence_strength);
    let suggested_next_route = suggested_next_route(domain_intent, can_promote);
    let promote_action = if can_promote {
        PromoteAction::PromoteAssisted
    } else {
        PromoteAction::ObserveOnly
    };
    let decision_phase = if can_promote {
        GovernancePhase::Suggested
    } else {
        GovernancePhase::Learning
    };
    let decision_timing = if can_promote {
        DecisionTiming::AssistedNextQuery
    } else {
        DecisionTiming::ObserveOnly
    };

    // ── Build component scores map ───────────────────────────
    let mut component_scores = BTreeMap::new();
    for (key, value) in &china_components {
        component_scores.insert(format!("china.{key}"), round_4(*value));
    }
    for (key, value) in &foreign_components {
        component_scores.insert(format!("foreign.{key}"), round_4(*value));
    }

    RouteEvidenceScore {
        domain_intent,
        evidence_strength,
        confidence_level,
        fact_status,
        can_promote,
        suggested_next_route,
        promote_action,
        decision_phase,
        decision_timing,
        reason_code,
        china_score,
        foreign_score,
        score_margin,
        route_authority,
        component_scores,
        notes,
    }
}

// ─── Helper functions ────────────────────────────────────────────

fn normalize_route(value: &str) -> &str {
    let v = value.trim().to_lowercase();
    match v.as_str() {
        "china" => "china",
        "foreign" => "foreign",
        _ => "unknown",
    }
}

fn route_authority(data: &RouteEvidenceInput) -> String {
    let prior = normalize_route(&data.prior_route);
    if prior == "china" || prior == "foreign" {
        return "domain_prior".into();
    }
    if data.local_cn_ip_count > 0 || data.local_foreign_ip_count > 0 {
        return "local_ip_geo".into();
    }
    if data.third_party_cn_ip_count > 0 || data.third_party_foreign_ip_count > 0 {
        return "third_party_ip_geo".into();
    }
    if !matches!(data.cname_scope, CnameScope::None | CnameScope::Unknown) {
        return "cname".into();
    }
    "unknown".into()
}

fn domain_intent(
    china_score: f32,
    foreign_score: f32,
    ip_scope: &str,
    cname_scope: CnameScope,
    prior_route: &str,
) -> DomainIntent {
    let margin = (china_score - foreign_score).abs();

    if cname_scope == CnameScope::GlobalCdn && margin < 1.0 {
        return DomainIntent::GlobalIntent;
    }
    if ip_scope == "mixed" && margin < 1.0 {
        return DomainIntent::MixedIntent;
    }
    if china_score <= 0.0 && foreign_score <= 0.0 {
        return DomainIntent::UnknownIntent;
    }
    if margin < 0.75 {
        return match prior_route {
            "china" => DomainIntent::ChinaIntent,
            "foreign" => DomainIntent::ForeignIntent,
            _ => DomainIntent::MixedIntent,
        };
    }
    if china_score > foreign_score {
        DomainIntent::ChinaIntent
    } else {
        DomainIntent::ForeignIntent
    }
}

fn evidence_strength(
    data: &RouteEvidenceInput,
    china_score: f32,
    foreign_score: f32,
    score_margin: f32,
) -> EvidenceStrength {
    // TLS mismatch is always conflicting
    if data.tls_identity_status == TlsIdentityStatus::Mismatch {
        return EvidenceStrength::Conflicting;
    }

    // Mixed geo without third-party alignment is conflicting
    if !data.route_scoped_first_seen {
        if data.ip_scope == "mixed"
            && (data.third_party_cn_ip_count + data.third_party_foreign_ip_count) == 0
        {
            return EvidenceStrength::Conflicting;
        }
        if data.ip_scope == "mixed" && score_margin < 2.0 {
            return EvidenceStrength::Conflicting;
        }
    } else if data.ip_scope == "mixed" && score_margin < 0.75 {
        return EvidenceStrength::Weak;
    }

    // Mixed CNAME chain is conflicting
    if data.cname_scope == CnameScope::MixedChain {
        return EvidenceStrength::Conflicting;
    }

    let max_score = china_score.max(foreign_score);
    if max_score <= 0.0 {
        return EvidenceStrength::None;
    }
    if data.runtime_confidence >= 0.80 && max_score >= 3.0 && score_margin >= 1.0 {
        return EvidenceStrength::Strong;
    }
    if data.runtime_confidence >= 0.55 || max_score >= 1.6 {
        return EvidenceStrength::Moderate;
    }
    EvidenceStrength::Weak
}

fn confidence_level(runtime_confidence: f32, evidence: EvidenceStrength) -> ConfidenceLevel {
    if evidence == EvidenceStrength::Conflicting {
        return ConfidenceLevel::Conflict;
    }
    let v = runtime_confidence.clamp(0.0, 1.0);
    if v >= 0.80 {
        ConfidenceLevel::High
    } else if v >= 0.55 {
        ConfidenceLevel::Medium
    } else if v > 0.0 {
        ConfidenceLevel::Low
    } else {
        ConfidenceLevel::None
    }
}

fn reason_code(data: &RouteEvidenceInput) -> String {
    if data.tls_identity_status == TlsIdentityStatus::Mismatch {
        return "tls_identity_mismatch".into();
    }
    if data.ip_scope == "mixed" {
        return "mixed_geo_conflict".into();
    }
    if matches!(
        data.tls_identity_status,
        TlsIdentityStatus::ExactMatch | TlsIdentityStatus::CnameMatch
    ) {
        return "tls_identity_match".into();
    }
    if matches!(
        data.cname_scope,
        CnameScope::CnProvider | CnameScope::ForeignProvider | CnameScope::GlobalCdn
    ) {
        return "cname_provider_hint".into();
    }
    if data.third_party_cn_ip_count > 0 || data.third_party_foreign_ip_count > 0 {
        let local_route = majority_route(data.local_cn_ip_count, data.local_foreign_ip_count);
        let tp_route = majority_route(
            data.third_party_cn_ip_count,
            data.third_party_foreign_ip_count,
        );
        if local_route == tp_route && local_route != "mixed" {
            return "local_third_party_geo_aligned".into();
        }
        return "local_third_party_geo_conflict".into();
    }
    "speed_tie_break_only".into()
}

fn majority_route(cn: u32, foreign: u32) -> &'static str {
    if cn > foreign {
        "china"
    } else if foreign > cn {
        "foreign"
    } else {
        "mixed"
    }
}

fn can_promote(
    data: &RouteEvidenceInput,
    domain_intent: DomainIntent,
    evidence: EvidenceStrength,
    score_margin: f32,
) -> bool {
    // Must have moderate or strong evidence
    if !matches!(
        evidence,
        EvidenceStrength::Moderate | EvidenceStrength::Strong
    ) {
        return false;
    }
    // Must have a clear directional intent
    if !matches!(
        domain_intent,
        DomainIntent::ChinaIntent | DomainIntent::ForeignIntent
    ) {
        return false;
    }
    // TLS mismatch blocks promotion
    if data.tls_identity_status == TlsIdentityStatus::Mismatch {
        return false;
    }
    // Mixed geo without third-party support blocks promotion
    if !data.route_scoped_first_seen {
        if data.ip_scope == "mixed"
            && (data.third_party_cn_ip_count + data.third_party_foreign_ip_count) == 0
        {
            return false;
        }
        if data.ip_scope == "mixed" && score_margin < 2.0 {
            return false;
        }
    } else if data.ip_scope == "mixed" && score_margin < 0.75 {
        return false;
    }
    true
}

fn fact_status(can_promote: bool, evidence: EvidenceStrength) -> FactStatus {
    if can_promote {
        return FactStatus::Candidate;
    }
    if evidence == EvidenceStrength::Conflicting {
        return FactStatus::Conflicting;
    }
    FactStatus::Observed
}

fn suggested_next_route(domain_intent: DomainIntent, can_promote: bool) -> String {
    if !can_promote {
        return "prior_route".into();
    }
    match domain_intent {
        DomainIntent::ChinaIntent => "china".into(),
        DomainIntent::ForeignIntent => "foreign".into(),
        _ => "prior_route".into(),
    }
}

fn round_4(v: f32) -> f32 {
    (v * 10000.0).round() / 10000.0
}

#[cfg(test)]
#[path = "scoring_tests.rs"]
mod tests;
