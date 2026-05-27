//! Domain governance state and threshold configurations.
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
use crate::ThirdPartyMode;
// TlsIdentityStatus is used by ThirdPartyEvidenceSummary (tls_mismatch_count)
// but only as a count, not as a type reference in this module.

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
            state_version: 1,
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

// ─── Threshold Configurations ────────────────────────────────────

/// Thresholds for mixed evidence behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedEvidenceThresholds {
    /// Number of mixed geo observations within window before freezing promotion.
    /// Default: 3.
    pub mixed_freeze_threshold: u32,
    /// Number of mixed geo observations within window before entering Review.
    /// Default: 10.
    pub mixed_degrade_threshold: u32,
    /// Time window in hours for counting mixed observations.
    /// Default: 24.
    pub mixed_window_hours: u32,
}

impl Default for MixedEvidenceThresholds {
    fn default() -> Self {
        Self {
            mixed_freeze_threshold: 3,
            mixed_degrade_threshold: 10,
            mixed_window_hours: 24,
        }
    }
}

/// Thresholds for promoting to Stable with third-party peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablePromotionThresholds {
    /// Minimum total observations before Stable promotion.
    pub min_observations: u32,
    /// Minimum local alignment observations.
    pub min_local_alignment: u32,
    /// Minimum third-party alignment observations.
    pub min_third_party_alignment: u32,
    /// Minimum distinct third-party observers.
    pub min_distinct_third_party: u32,
    /// Maximum mixed geo observations in 24h window.
    pub max_mixed_24h: u32,
    /// Maximum hard conflicts in 24h window (must be 0 for promotion).
    pub max_hard_conflict_24h: u32,
    /// Minimum consecutive no-conflict observations.
    pub min_no_conflict_streak: u32,
}

impl Default for StablePromotionThresholds {
    fn default() -> Self {
        Self {
            min_observations: 20,
            min_local_alignment: 5,
            min_third_party_alignment: 2,
            min_distinct_third_party: 2,
            max_mixed_24h: 2,
            max_hard_conflict_24h: 0,
            min_no_conflict_streak: 10,
        }
    }
}

/// Thresholds for promoting to Stable without third-party peers (local-only strict).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalOnlyStableThresholds {
    /// Minimum total observations before Stable promotion.
    pub min_observations: u32,
    /// Minimum local alignment observations.
    pub min_local_alignment: u32,
    /// Maximum mixed geo observations in 24h window.
    pub max_mixed_24h: u32,
    /// Maximum hard conflicts in 24h window.
    pub max_hard_conflict_24h: u32,
    /// Minimum consecutive no-conflict observations.
    pub min_no_conflict_streak: u32,
}

impl Default for LocalOnlyStableThresholds {
    fn default() -> Self {
        Self {
            min_observations: 50,
            min_local_alignment: 15,
            max_mixed_24h: 2,
            max_hard_conflict_24h: 0,
            min_no_conflict_streak: 20,
        }
    }
}

/// Thresholds for entering Review from any phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewThresholds {
    /// Hard conflict count in 24h to trigger Review.
    pub hard_conflict_threshold: u32,
    /// TLS mismatch count in 24h to trigger Review.
    pub tls_mismatch_threshold: u32,
    /// Route-opposite evidence count in 24h to trigger Review.
    pub route_opposite_threshold: u32,
    /// Mixed geo count in 24h to trigger Review.
    pub mixed_degrade_threshold: u32,
    /// Consecutive upstream failures to trigger Review.
    pub consecutive_failure_threshold: u32,
}

impl Default for ReviewThresholds {
    fn default() -> Self {
        Self {
            hard_conflict_threshold: 3,
            tls_mismatch_threshold: 2,
            route_opposite_threshold: 3,
            mixed_degrade_threshold: 10,
            consecutive_failure_threshold: 5,
        }
    }
}

/// Thresholds for entering Fallback from Review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackThresholds {
    /// Maximum hours in Review before forced Fallback.
    pub review_max_duration_hours: u32,
    /// Hard conflict count in 24h to trigger Fallback.
    pub fallback_hard_conflict_threshold: u32,
    /// Route-opposite count in 24h to trigger Fallback.
    pub fallback_route_opposite_threshold: u32,
}

impl Default for FallbackThresholds {
    fn default() -> Self {
        Self {
            review_max_duration_hours: 6,
            fallback_hard_conflict_threshold: 5,
            fallback_route_opposite_threshold: 5,
        }
    }
}

/// Combined governance thresholds configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceThresholds {
    pub mixed_evidence: MixedEvidenceThresholds,
    pub stable_with_third_party: StablePromotionThresholds,
    pub stable_local_only: LocalOnlyStableThresholds,
    pub review: ReviewThresholds,
    pub fallback: FallbackThresholds,
    pub third_party_mode: ThirdPartyMode,
}

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
#[path = "governance_state_tests.rs"]
mod tests;
