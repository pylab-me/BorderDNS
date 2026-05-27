//! Domain governance state and review candidate types.
//!
//! `DomainGovernanceState` is the per-domain state structure that tracks
//! governance phase, evidence counts, and promotion readiness.
//!
//! State structures are defined here (border-dns-facts), but state transition
//! logic lives in border-dns-route-policy (pure functions).

use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;

use crate::ConflictKind;
use crate::GovernancePhase;

// ─── Domain Governance State ─────────────────────────────────────

/// Per-domain governance state — the core state structure of Sprint 3.
///
/// This structure is persisted as part of the derived state store.
/// State transitions are computed by `border-dns-route-policy` pure functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainGovernanceState {
    /// The domain this state applies to.
    pub domain: String,

    /// Current governance phase.
    pub phase: GovernancePhase,

    /// Currently active execution route.
    pub current_route: String,
    /// Original route from domain prior (before any governance override).
    pub prior_route: String,
    /// Suggested route from latest evidence scoring.
    pub suggested_route: String,

    /// Latest china_score from route evidence scoring.
    pub china_score: f32,
    /// Latest foreign_score from route evidence scoring.
    pub foreign_score: f32,
    /// Absolute difference between china_score and foreign_score.
    pub score_margin: f32,

    /// Total number of observations for this domain.
    pub observation_count: u64,
    /// Number of meaningful events emitted for this domain.
    pub meaningful_event_count: u64,

    /// Number of observations where local evidence aligned with current route.
    pub local_alignment_count: u32,
    /// Number of third-party observations that aligned with current route.
    pub third_party_alignment_count: u32,
    /// Number of distinct third-party observers that have observed this domain.
    pub distinct_third_party_observers: u32,

    /// Number of mixed geo observations in the last 24 hours.
    pub mixed_count_24h: u32,
    /// Number of soft conflicts in the last 24 hours.
    pub soft_conflict_count_24h: u32,
    /// Number of hard conflicts in the last 24 hours.
    pub hard_conflict_count_24h: u32,

    /// Number of TLS mismatch observations in the last 24 hours.
    pub tls_mismatch_count_24h: u32,
    /// Number of route-opposite evidence in the last 24 hours.
    pub route_opposite_count_24h: u32,

    /// Consecutive observations with no conflict (soft or hard).
    pub consecutive_no_conflict_count: u32,
    /// Consecutive upstream failures.
    pub consecutive_failure_count: u32,

    /// Whether this domain can be promoted to a higher governance phase.
    pub can_promote: bool,
    /// Whether promotion is frozen (e.g., due to repeated mixed evidence).
    pub promotion_frozen: bool,

    /// Third-party observation summary.
    pub third_party_summary: ThirdPartyEvidenceSummary,

    /// When this domain was last observed.
    pub last_observed_at: DateTime<Utc>,
    /// When the governance phase last changed.
    pub last_transition_at: DateTime<Utc>,

    /// When the last mixed geo observation was recorded (for 24h decay).
    pub last_mixed_at: Option<DateTime<Utc>>,
    /// When the last hard conflict was recorded (for 24h decay).
    pub last_hard_conflict_at: Option<DateTime<Utc>>,
    /// When the last TLS mismatch was recorded (for 24h decay).
    pub last_tls_mismatch_at: Option<DateTime<Utc>>,
    /// When the last route-opposite evidence was recorded (for 24h decay).
    pub last_route_opposite_at: Option<DateTime<Utc>>,
    /// When the last soft conflict was recorded (for 24h decay).
    pub last_soft_conflict_at: Option<DateTime<Utc>>,

    /// Monotonically increasing version for optimistic concurrency control.
    pub state_version: u64,
}

impl DomainGovernanceState {
    /// Create a new state for a first-seen domain.
    #[must_use]
    pub fn new(domain: String, prior_route: String, now: DateTime<Utc>) -> Self {
        Self {
            domain,
            phase: GovernancePhase::New,
            current_route: prior_route.clone(),
            prior_route,
            suggested_route: String::new(),
            china_score: 0.0,
            foreign_score: 0.0,
            score_margin: 0.0,
            observation_count: 0,
            meaningful_event_count: 0,
            local_alignment_count: 0,
            third_party_alignment_count: 0,
            distinct_third_party_observers: 0,
            mixed_count_24h: 0,
            soft_conflict_count_24h: 0,
            hard_conflict_count_24h: 0,
            tls_mismatch_count_24h: 0,
            route_opposite_count_24h: 0,
            consecutive_no_conflict_count: 0,
            consecutive_failure_count: 0,
            can_promote: false,
            promotion_frozen: false,
            third_party_summary: ThirdPartyEvidenceSummary::default(),
            last_observed_at: now,
            last_transition_at: now,
            last_mixed_at: None,
            last_hard_conflict_at: None,
            last_tls_mismatch_at: None,
            last_route_opposite_at: None,
            last_soft_conflict_at: None,
            state_version: 1,
        }
    }

    /// Decay 24h rolling window counters.
    ///
    /// Resets any `_count_24h` field to 0 if its corresponding `last_*_at`
    /// timestamp is older than 24 hours from `now`. This is intended to be
    /// called periodically (e.g., by a background worker or on every Nth
    /// observation) to prevent stale counters from accumulating.
    pub fn decay_24h_counters(&mut self, now: DateTime<Utc>) {
        let window = chrono::Duration::hours(24);

        if self.last_mixed_at.is_some_and(|t| now - t > window) {
            self.mixed_count_24h = 0;
        }
        if self.last_soft_conflict_at.is_some_and(|t| now - t > window) {
            self.soft_conflict_count_24h = 0;
        }
        if self.last_hard_conflict_at.is_some_and(|t| now - t > window) {
            self.hard_conflict_count_24h = 0;
        }
        if self.last_tls_mismatch_at.is_some_and(|t| now - t > window) {
            self.tls_mismatch_count_24h = 0;
        }
        if self
            .last_route_opposite_at
            .is_some_and(|t| now - t > window)
        {
            self.route_opposite_count_24h = 0;
        }
    }
}

// ─── Third-Party Evidence Summary ────────────────────────────────

/// Summary of third-party observation evidence, segmented by observer location.
///
/// Cross-location divergence is NOT a hard conflict — it's expected that
/// China and Foreign observers see different DNS answers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThirdPartyEvidenceSummary {
    /// Whether third-party observation is enabled.
    pub enabled: bool,

    /// Total number of distinct observers.
    pub distinct_observers: u32,

    /// Number of observers located in China.
    pub china_observer_count: u32,
    /// Number of observers located outside China.
    pub foreign_observer_count: u32,
    /// Number of observers with unknown location.
    pub unknown_observer_count: u32,

    /// China observers whose evidence aligned with China route.
    pub china_observer_china_aligned: u32,
    /// China observers whose evidence aligned with Foreign route.
    pub china_observer_foreign_aligned: u32,

    /// Foreign observers whose evidence aligned with China route.
    pub foreign_observer_china_aligned: u32,
    /// Foreign observers whose evidence aligned with Foreign route.
    pub foreign_observer_foreign_aligned: u32,

    /// Cross-location divergence count (China observer vs Foreign observer — NOT a conflict).
    pub cross_location_divergence_count: u32,
    /// Same-location conflict count (e.g., China observer contradicts China local view).
    pub same_location_conflict_count: u32,

    /// Number of TLS mismatches reported by third-party observers.
    pub tls_mismatch_count: u32,
}

// ─── Review Candidates ───────────────────────────────────────────

/// Review candidate entry for startup summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCandidate {
    pub domain: String,
    pub phase: GovernancePhase,
    pub reason: ConflictKind,
    pub mixed_count_24h: u32,
    pub hard_conflict_count_24h: u32,
    pub tls_mismatch_count_24h: u32,
}

#[cfg(test)]
#[path = "review_tests.rs"]
mod tests;
