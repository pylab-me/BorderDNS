//! Fact event DTOs for BorderDNS governance events.
//!
//! `BorderDnsFactEvent` is the top-level event structure emitted by the
//! governance pipeline. Sub-fact structs represent individual aspects
//! of a DNS query observation.
//!
//! All DTOs are Serialize + Deserialize for JSONL persistence.

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

use crate::CnameScope;
use crate::ConflictKind;
use crate::DomainIntent;
use crate::EvidenceStrength;
use crate::FactStatus;
use crate::GovernancePhase;
use crate::MeaningfulEventKind;
use crate::ObserverScope;
use crate::ProbeQuality;
use crate::SCHEMA_REVISION;
use crate::SCHEMA_VERSION;
use crate::TlsIdentityStatus;

// ─── Top-level Fact Event ────────────────────────────────────────

/// BorderDNS fact event — the primary governance event DTO.
///
/// Schema version: `borderdns.fact.v1`
///
/// Every persisted fact event MUST include `schema_version` and `schema_revision`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorderDnsFactEvent {
    /// Schema version identifier (always "borderdns.fact.v1").
    pub schema_version: String,
    /// Schema revision number.
    pub schema_revision: u32,
    /// When this event was observed.
    pub observed_at: DateTime<Utc>,
    /// Source of observation (local, third-party, peer, synthetic).
    pub observer_scope: ObserverScope,
    /// What kind of meaningful event this is.
    pub event_kind: MeaningfulEventKind,
    /// Query details.
    pub query: QueryFact,
    /// Route decision details.
    pub decision: DecisionFact,
    /// DNS answer details.
    pub answer: AnswerFact,
    /// Evidence collected from the answer.
    pub evidence: EvidenceFact,
    /// Runtime outcome.
    pub outcome: RuntimeOutcomeFact,
    /// Governance state snapshot at time of event.
    pub governance: GovernanceFact,
}

impl BorderDnsFactEvent {
    /// Create a new fact event with the current schema version.
    #[must_use]
    pub fn new(
        observed_at: DateTime<Utc>,
        observer_scope: ObserverScope,
        event_kind: MeaningfulEventKind,
        query: QueryFact,
        decision: DecisionFact,
        answer: AnswerFact,
        evidence: EvidenceFact,
        outcome: RuntimeOutcomeFact,
        governance: GovernanceFact,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            schema_revision: SCHEMA_REVISION,
            observed_at,
            observer_scope,
            event_kind,
            query,
            decision,
            answer,
            evidence,
            outcome,
            governance,
        }
    }

    /// Serialize to a single JSONL line (compact, no pretty-printing).
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

// ─── Sub-fact DTOs ───────────────────────────────────────────────

/// Query details extracted from the DNS question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFact {
    /// Raw domain name from the query.
    pub domain: String,
    /// Normalized domain (lowercase, no trailing dot).
    pub normalized_domain: String,
    /// Query type (A, AAAA, etc.) as string.
    pub qtype: String,
}

/// Route decision snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionFact {
    /// The execution route chosen.
    pub route: String,
    /// How the route was determined.
    pub route_source: String,
    /// Governance phase at time of decision.
    pub phase: GovernancePhase,
    /// Domain intent classification.
    pub domain_intent: DomainIntent,
    /// Confidence level.
    pub confidence: String,
    /// Whether this decision can promote the domain's governance state.
    pub can_promote: bool,
    /// Why this route was chosen.
    pub reason_codes: Vec<String>,
}

/// DNS answer details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnswerFact {
    /// RCODE (NOERROR, NXDOMAIN, SERVFAIL, etc.).
    pub rcode: String,
    /// Number of answer records.
    pub record_count: usize,
    /// Number of A/AAAA records.
    pub ip_count: usize,
    /// Number of CNAME records.
    pub cname_count: usize,
}

/// Evidence collected from the DNS answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFact {
    /// IP geo scope (cn_only, foreign_only, mixed, etc.).
    pub ip_scope: String,
    /// Number of CN IPs.
    pub cn_ip_count: usize,
    /// Number of non-CN IPs.
    pub foreign_ip_count: usize,
    /// CNAME scope classification.
    pub cname_scope: CnameScope,
    /// TLS identity status.
    pub tls_identity: TlsIdentityStatus,
    /// Probe quality classification.
    pub probe_quality: ProbeQuality,
    /// Overall evidence strength.
    pub evidence_strength: EvidenceStrength,
    /// If there's a conflict, what kind.
    pub conflict_kind: Option<ConflictKind>,
}

/// Runtime outcome of the query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOutcomeFact {
    /// Response source (upstream, cache, etc.).
    pub response_source: String,
    /// Upstream round-trip time in milliseconds (if applicable).
    pub upstream_rtt_ms: Option<u64>,
    /// Total pipeline latency in milliseconds.
    pub total_latency_ms: u64,
    /// Cache status (hit, miss, etc.).
    pub cache_status: String,
}

/// Governance state snapshot at time of event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceFact {
    /// Current governance phase.
    pub phase: GovernancePhase,
    /// Current execution route.
    pub current_route: String,
    /// Fact status (observed, candidate, conflicting, etc.).
    pub fact_status: FactStatus,
    /// china_score at time of event.
    pub china_score: f32,
    /// foreign_score at time of event.
    pub foreign_score: f32,
    /// score_margin at time of event.
    pub score_margin: f32,
    /// Human-readable summary of why this event matters.
    pub summary: String,
}

#[cfg(test)]
#[path = "fact_event_tests.rs"]
mod tests;
