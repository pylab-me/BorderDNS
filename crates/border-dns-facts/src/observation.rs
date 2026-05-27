//! Async observation job model for BorderDNS governance.
//!
//! Observation jobs are enqueued by the pipeline hot path and consumed
//! by background workers. The hot path never blocks on observation results.

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

use crate::GovernancePhase;
use crate::MeaningfulEventKind;

// ─── Observation Job ─────────────────────────────────────────────

/// A background observation job enqueued from the pipeline hot path.
///
/// The hot path emits this to request async analysis. The worker processes
/// it and updates governance state off the hot path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationJob {
    /// Unique job identifier (ULID or similar).
    pub job_id: String,
    /// Domain being observed.
    pub domain: String,
    /// The type of observation requested.
    pub job_kind: ObservationJobKind,
    /// Current governance phase at time of enqueue.
    pub current_phase: GovernancePhase,
    /// Current route at time of enqueue.
    pub current_route: String,
    /// When the job was enqueued.
    pub enqueued_at: DateTime<Utc>,
}

/// The kind of observation job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationJobKind {
    /// Analyze DNS answer for geo evidence and CNAME chain.
    GeoAnalysis {
        /// IP addresses extracted from the answer (A/AAAA).
        ip_addresses: Vec<String>,
        /// CNAME chain extracted from the answer.
        cname_chain: Vec<String>,
    },
    /// TLS identity probe for the domain or its resolved IP.
    TlsProbe {
        /// The domain to probe (SNI).
        sni_domain: String,
        /// IP address to connect to.
        target_ip: String,
    },
    /// Latency/quality probe to a specific IP.
    LatencyProbe {
        /// IP address to probe.
        target_ip: String,
    },
    /// Third-party observation fetch.
    ThirdPartyFetch {
        /// Observer endpoint ID.
        observer_id: String,
        /// Domain to query.
        domain: String,
    },
}

// ─── Fact Emit ───────────────────────────────────────────────────

/// A lightweight fact emission from the pipeline hot path.
///
/// This is the structure that gets serialized to JSONL for meaningful events.
/// It wraps the existing `BorderDnsFactEvent` with a domain key and event kind
/// for efficient indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactEmit {
    /// Domain this fact relates to.
    pub domain: String,
    /// The kind of meaningful event.
    pub event_kind: MeaningfulEventKind,
    /// When this fact was emitted.
    pub observed_at: DateTime<Utc>,
    /// Whether this fact triggered a governance phase change.
    pub phase_changed: bool,
    /// New governance phase (if changed).
    pub new_phase: Option<GovernancePhase>,
    /// Reason code string.
    pub reason_code: String,
    /// Additional context fields (arbitrary key-value pairs for diagnostics).
    pub context: std::collections::BTreeMap<String, String>,
}

impl FactEmit {
    /// Create a new fact emit.
    #[must_use]
    pub fn new(domain: String, event_kind: MeaningfulEventKind, reason_code: String) -> Self {
        Self {
            domain,
            event_kind,
            observed_at: Utc::now(),
            phase_changed: false,
            new_phase: None,
            reason_code,
            context: std::collections::BTreeMap::new(),
        }
    }

    /// Serialize to a JSONL line.
    ///
    /// Returns `None` if serialization fails.
    #[must_use]
    pub fn to_jsonl_line(&self) -> Option<String> {
        serde_json::to_string(self).ok()
    }
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
