//! Governance threshold configurations.
//!
//! Thresholds control promotion, review, and fallback triggers.
//! Separate from domain governance state — purely configuration data.

use serde::Deserialize;
use serde::Serialize;

use crate::ThirdPartyMode;

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

#[cfg(test)]
#[path = "thresholds_tests.rs"]
mod tests;
