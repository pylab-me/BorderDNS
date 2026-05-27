//! Governance phase transition pure functions for BorderDNS.
//!
//! State transitions are computed here (border-dns-route-policy).
//! State structures live in border-dns-facts.
//!
//! This module enforces the hard rules:
//! - New -> Learning on first query
//! - Learning -> Suggested when local evidence aligns (no hard conflict)
//! - Suggested -> Stable only when thresholds are met
//! - Any -> Review when conflict thresholds are crossed
//! - Review -> Learning when evidence clears
//! - Review -> Fallback when review duration or conflicts exceed limits
//! - Fallback -> Learning on TTL expiry or manual reset

use border_dns_facts::DomainGovernanceState;
use border_dns_facts::FallbackThresholds;
use border_dns_facts::GovernancePhase;
use border_dns_facts::GovernanceThresholds;
use border_dns_facts::LocalOnlyStableThresholds;
use border_dns_facts::ReviewThresholds;
use border_dns_facts::StablePromotionThresholds;
use border_dns_facts::ThirdPartyMode;

// ─── Transition Input ────────────────────────────────────────────

/// Input for governance phase transition evaluation.
///
/// All fields are read-only snapshot of current domain state + config.
#[derive(Debug, Clone)]
pub struct GovernanceTransitionInput {
    /// Current governance state for the domain.
    pub state: DomainGovernanceState,
    /// Whether the latest evidence can promote (from scoring engine).
    pub latest_can_promote: bool,
    /// Whether the latest evidence is mixed geo.
    pub latest_is_mixed: bool,
    /// Whether the latest TLS status is mismatch.
    pub latest_tls_mismatch: bool,
    /// Whether the latest evidence is a hard conflict.
    pub latest_hard_conflict: bool,
    /// Whether the latest evidence is a soft conflict.
    pub latest_soft_conflict: bool,
    /// Whether the latest evidence aligns with current route.
    pub latest_local_aligned: bool,
    /// Whether third-party evidence aligned in latest observation.
    pub latest_third_party_aligned: bool,
    /// Whether this is a first-seen domain (no prior state).
    pub is_first_seen: bool,
    /// Whether upstream failure occurred.
    pub upstream_failure: bool,
    /// Governance thresholds configuration.
    pub thresholds: GovernanceThresholds,
}

// ─── Transition Result ───────────────────────────────────────────

/// Result of governance phase transition evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceTransitionResult {
    /// The recommended new governance phase.
    pub new_phase: GovernancePhase,
    /// Whether the phase actually changed.
    pub phase_changed: bool,
    /// Whether promotion should be frozen.
    pub freeze_promotion: bool,
    /// Whether the domain should be removed from governance (manual/external).
    pub remove_state: bool,
    /// Human-readable reason for the transition.
    pub reason_code: TransitionReason,
    /// Diagnostic notes.
    pub notes: Vec<String>,
}

/// Reason codes for governance phase transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionReason {
    /// First seen domain — initialize to Learning.
    FirstSeen,
    /// No change needed — staying in current phase.
    NoChange,
    /// Local evidence strong enough for Suggested.
    LocalEvidencePromote,
    /// Third-party alignment with local evidence promotes to Suggested.
    ThirdPartyAlignmentPromote,
    /// Suggested -> Stable with third-party assistance.
    StablePromotionWithPeers,
    /// Suggested -> Stable local-only strict.
    StablePromotionLocalOnly,
    /// Mixed evidence exceeds freeze threshold.
    MixedFreeze,
    /// Mixed evidence exceeds degrade threshold — enter Review.
    MixedDegradeToReview,
    /// Hard conflict count exceeded — enter Review.
    HardConflictToReview,
    /// TLS mismatch threshold exceeded — enter Review.
    TlsMismatchToReview,
    /// Route-opposite threshold exceeded — enter Review.
    RouteOppositeToReview,
    /// Consecutive failure threshold exceeded — enter Review.
    ConsecutiveFailureToReview,
    /// Review cleared — back to Learning.
    ReviewCleared,
    /// Review duration exceeded — enter Fallback.
    ReviewDurationFallback,
    /// Hard conflict during Review — enter Fallback.
    ReviewHardConflictFallback,
    /// Route-opposite during Review — enter Fallback.
    ReviewRouteOppositeFallback,
    /// Fallback TTL expired — back to Learning.
    FallbackExpired,
    /// Manual reset.
    ManualReset,
}

impl TransitionReason {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstSeen => "first_seen",
            Self::NoChange => "no_change",
            Self::LocalEvidencePromote => "local_evidence_promote",
            Self::ThirdPartyAlignmentPromote => "third_party_alignment_promote",
            Self::StablePromotionWithPeers => "stable_promotion_with_peers",
            Self::StablePromotionLocalOnly => "stable_promotion_local_only",
            Self::MixedFreeze => "mixed_freeze",
            Self::MixedDegradeToReview => "mixed_degrade_to_review",
            Self::HardConflictToReview => "hard_conflict_to_review",
            Self::TlsMismatchToReview => "tls_mismatch_to_review",
            Self::RouteOppositeToReview => "route_opposite_to_review",
            Self::ConsecutiveFailureToReview => "consecutive_failure_to_review",
            Self::ReviewCleared => "review_cleared",
            Self::ReviewDurationFallback => "review_duration_fallback",
            Self::ReviewHardConflictFallback => "review_hard_conflict_fallback",
            Self::ReviewRouteOppositeFallback => "review_route_opposite_fallback",
            Self::FallbackExpired => "fallback_expired",
            Self::ManualReset => "manual_reset",
        }
    }
}

impl std::fmt::Display for TransitionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Main Transition Function ────────────────────────────────────

/// Evaluate governance phase transition as a pure function.
///
/// Takes current state + latest observation inputs and returns the recommended
/// new phase without mutating any state.
#[must_use]
pub fn evaluate_governance_transition(
    input: &GovernanceTransitionInput,
) -> GovernanceTransitionResult {
    let current_phase = &input.state.phase;

    // ── First seen: New -> Learning ─────────────────────────────
    if input.is_first_seen || current_phase == &GovernancePhase::New {
        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Learning,
            phase_changed: current_phase != &GovernancePhase::Learning,
            freeze_promotion: false,
            remove_state: false,
            reason_code: TransitionReason::FirstSeen,
            notes: vec!["first_seen_domain_initialized_to_learning".into()],
        };
    }

    // ── Check for Review triggers (from any non-Fallback phase) ─
    if current_phase != &GovernancePhase::Fallback {
        if let Some(result) = check_review_triggers(input) {
            return result;
        }
    }

    // ── Phase-specific transitions ─────────────────────────────
    match current_phase {
        GovernancePhase::Learning => evaluate_learning(input),
        GovernancePhase::Suggested => evaluate_suggested(input),
        GovernancePhase::Stable => evaluate_stable(input),
        GovernancePhase::Review => evaluate_review(input),
        GovernancePhase::Fallback => evaluate_fallback(input),
        GovernancePhase::New => unreachable!("handled above"),
    }
}

// ─── Learning -> Suggested ───────────────────────────────────────

fn evaluate_learning(input: &GovernanceTransitionInput) -> GovernanceTransitionResult {
    let thresholds = &input.thresholds;
    let mixed = &thresholds.mixed_evidence;

    // Freeze if mixed count crossed freeze threshold
    if input.state.mixed_count_24h >= mixed.mixed_freeze_threshold {
        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Learning,
            phase_changed: false,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::MixedFreeze,
            notes: vec![format!(
                "mixed_count_24h={} >= freeze_threshold={}",
                input.state.mixed_count_24h, mixed.mixed_freeze_threshold
            )],
        };
    }

    // Learning -> Suggested: local strong evidence + no hard conflict
    if input.latest_can_promote
        && input.state.hard_conflict_count_24h == 0
        && input.state.mixed_count_24h < mixed.mixed_freeze_threshold
    {
        let reason = if input.latest_third_party_aligned {
            TransitionReason::ThirdPartyAlignmentPromote
        } else {
            TransitionReason::LocalEvidencePromote
        };

        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Suggested,
            phase_changed: true,
            freeze_promotion: false,
            remove_state: false,
            reason_code: reason,
            notes: vec![format!(
                "can_promote=true hard_conflict_24h={} mixed_24h={}",
                input.state.hard_conflict_count_24h, input.state.mixed_count_24h
            )],
        };
    }

    no_change(
        &input.state.phase,
        "learning: insufficient evidence for suggested",
    )
}

// ─── Suggested -> Stable ─────────────────────────────────────────

fn evaluate_suggested(input: &GovernanceTransitionInput) -> GovernanceTransitionResult {
    let thresholds = &input.thresholds;

    // Check if third-party is enabled
    let result = match thresholds.third_party_mode {
        ThirdPartyMode::Enabled => {
            check_stable_with_third_party(input, &thresholds.stable_with_third_party)
        }
        ThirdPartyMode::Disabled => check_stable_local_only(input, &thresholds.stable_local_only),
    };

    if result.is_some() {
        return result.unwrap();
    }

    // Check mixed freeze
    if input.state.mixed_count_24h >= thresholds.mixed_evidence.mixed_freeze_threshold {
        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Suggested,
            phase_changed: false,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::MixedFreeze,
            notes: vec![format!(
                "mixed_count_24h={} >= freeze_threshold={}",
                input.state.mixed_count_24h, thresholds.mixed_evidence.mixed_freeze_threshold
            )],
        };
    }

    no_change(&input.state.phase, "suggested: stable thresholds not met")
}

fn check_stable_with_third_party(
    input: &GovernanceTransitionInput,
    t: &StablePromotionThresholds,
) -> Option<GovernanceTransitionResult> {
    let s = &input.state;
    let ok = s.observation_count as u32 >= t.min_observations
        && s.local_alignment_count >= t.min_local_alignment
        && s.third_party_alignment_count >= t.min_third_party_alignment
        && s.distinct_third_party_observers >= t.min_distinct_third_party
        && s.hard_conflict_count_24h <= t.max_hard_conflict_24h
        && s.mixed_count_24h <= t.max_mixed_24h
        && s.consecutive_no_conflict_count >= t.min_no_conflict_streak;

    if ok {
        Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Stable,
            phase_changed: true,
            freeze_promotion: false,
            remove_state: false,
            reason_code: TransitionReason::StablePromotionWithPeers,
            notes: vec![format!(
                "obs={} local_align={} tp_align={} distinct_tp={} hard_conflict_24h={} mixed_24h={} no_conflict_streak={}",
                s.observation_count,
                s.local_alignment_count,
                s.third_party_alignment_count,
                s.distinct_third_party_observers,
                s.hard_conflict_count_24h,
                s.mixed_count_24h,
                s.consecutive_no_conflict_count
            )],
        })
    } else {
        None
    }
}

fn check_stable_local_only(
    input: &GovernanceTransitionInput,
    t: &LocalOnlyStableThresholds,
) -> Option<GovernanceTransitionResult> {
    let s = &input.state;
    let ok = s.observation_count as u32 >= t.min_observations
        && s.local_alignment_count >= t.min_local_alignment
        && s.hard_conflict_count_24h <= t.max_hard_conflict_24h
        && s.mixed_count_24h <= t.max_mixed_24h
        && s.consecutive_no_conflict_count >= t.min_no_conflict_streak;

    if ok {
        Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Stable,
            phase_changed: true,
            freeze_promotion: false,
            remove_state: false,
            reason_code: TransitionReason::StablePromotionLocalOnly,
            notes: vec![format!(
                "obs={} local_align={} hard_conflict_24h={} mixed_24h={} no_conflict_streak={}",
                s.observation_count,
                s.local_alignment_count,
                s.hard_conflict_count_24h,
                s.mixed_count_24h,
                s.consecutive_no_conflict_count
            )],
        })
    } else {
        None
    }
}

// ─── Stable (maintenance) ────────────────────────────────────────

fn evaluate_stable(_input: &GovernanceTransitionInput) -> GovernanceTransitionResult {
    // Stable domains: check if latest observation caused issues
    // (detailed triggers are in check_review_triggers, called before this)
    // If we reach here, no review trigger fired — stay Stable.
    no_change(&GovernancePhase::Stable, "stable: no degradation triggers")
}

// ─── Review -> Learning / Fallback ───────────────────────────────

fn evaluate_review(input: &GovernanceTransitionInput) -> GovernanceTransitionResult {
    let thresholds = &input.thresholds;
    let review = &thresholds.review;
    let fallback = &thresholds.fallback;

    // Check Review -> Fallback first (more severe)
    if let Some(result) = check_fallback_from_review(input, fallback, review) {
        return result;
    }

    // Check Review -> Learning (evidence cleared)
    let s = &input.state;
    let cleared = s.hard_conflict_count_24h == 0
        && s.mixed_count_24h < thresholds.mixed_evidence.mixed_freeze_threshold
        && s.consecutive_no_conflict_count >= 10;

    if cleared {
        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Learning,
            phase_changed: true,
            freeze_promotion: false,
            remove_state: false,
            reason_code: TransitionReason::ReviewCleared,
            notes: vec![format!(
                "hard_conflict_24h=0 mixed_24h={} no_conflict_streak={}",
                s.mixed_count_24h, s.consecutive_no_conflict_count
            )],
        };
    }

    no_change(&input.state.phase, "review: conditions not cleared")
}

fn check_fallback_from_review(
    input: &GovernanceTransitionInput,
    fallback: &FallbackThresholds,
    _review: &ReviewThresholds,
) -> Option<GovernanceTransitionResult> {
    let s = &input.state;

    // Review duration check (hours since last_transition_at)
    let review_hours = (chrono::Utc::now() - s.last_transition_at).num_hours() as u32;
    if review_hours >= fallback.review_max_duration_hours {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Fallback,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::ReviewDurationFallback,
            notes: vec![format!(
                "review_duration_hours={} >= max={}",
                review_hours, fallback.review_max_duration_hours
            )],
        });
    }

    // Severe hard conflicts during Review
    if s.hard_conflict_count_24h >= fallback.fallback_hard_conflict_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Fallback,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::ReviewHardConflictFallback,
            notes: vec![format!(
                "hard_conflict_24h={} >= fallback_threshold={}",
                s.hard_conflict_count_24h, fallback.fallback_hard_conflict_threshold
            )],
        });
    }

    // Severe route-opposite during Review
    if s.route_opposite_count_24h >= fallback.fallback_route_opposite_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Fallback,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::ReviewRouteOppositeFallback,
            notes: vec![format!(
                "route_opposite_24h={} >= fallback_threshold={}",
                s.route_opposite_count_24h, fallback.fallback_route_opposite_threshold
            )],
        });
    }

    None
}

// ─── Fallback -> Learning ────────────────────────────────────────

fn evaluate_fallback(input: &GovernanceTransitionInput) -> GovernanceTransitionResult {
    // Fallback -> Learning: when clean evidence appears
    // (TTL expiry or manual reset are handled externally by resetting phase)
    let s = &input.state;

    // If we're in Fallback and the latest evidence is clean (no conflicts)
    // and we have some alignment, consider returning to Learning
    if !input.latest_hard_conflict
        && !input.latest_tls_mismatch
        && !input.latest_is_mixed
        && s.hard_conflict_count_24h == 0
        && s.tls_mismatch_count_24h == 0
    {
        return GovernanceTransitionResult {
            new_phase: GovernancePhase::Learning,
            phase_changed: true,
            freeze_promotion: false,
            remove_state: false,
            reason_code: TransitionReason::FallbackExpired,
            notes: vec!["fallback: clean evidence detected, returning to learning".into()],
        };
    }

    no_change(
        &input.state.phase,
        "fallback: still in fallback, no clean evidence",
    )
}

// ─── Review Triggers (from any non-Fallback phase) ───────────────

fn check_review_triggers(input: &GovernanceTransitionInput) -> Option<GovernanceTransitionResult> {
    let s = &input.state;
    let review = &input.thresholds.review;
    let mixed = &input.thresholds.mixed_evidence;

    // TLS mismatch threshold
    if s.tls_mismatch_count_24h >= review.tls_mismatch_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Review,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::TlsMismatchToReview,
            notes: vec![format!(
                "tls_mismatch_24h={} >= threshold={}",
                s.tls_mismatch_count_24h, review.tls_mismatch_threshold
            )],
        });
    }

    // Hard conflict threshold
    if s.hard_conflict_count_24h >= review.hard_conflict_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Review,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::HardConflictToReview,
            notes: vec![format!(
                "hard_conflict_24h={} >= threshold={}",
                s.hard_conflict_count_24h, review.hard_conflict_threshold
            )],
        });
    }

    // Route-opposite threshold
    if s.route_opposite_count_24h >= review.route_opposite_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Review,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::RouteOppositeToReview,
            notes: vec![format!(
                "route_opposite_24h={} >= threshold={}",
                s.route_opposite_count_24h, review.route_opposite_threshold
            )],
        });
    }

    // Mixed evidence degrade threshold
    if s.mixed_count_24h >= mixed.mixed_degrade_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Review,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::MixedDegradeToReview,
            notes: vec![format!(
                "mixed_count_24h={} >= degrade_threshold={}",
                s.mixed_count_24h, mixed.mixed_degrade_threshold
            )],
        });
    }

    // Consecutive failure threshold
    if s.consecutive_failure_count >= review.consecutive_failure_threshold {
        return Some(GovernanceTransitionResult {
            new_phase: GovernancePhase::Review,
            phase_changed: true,
            freeze_promotion: true,
            remove_state: false,
            reason_code: TransitionReason::ConsecutiveFailureToReview,
            notes: vec![format!(
                "consecutive_failure={} >= threshold={}",
                s.consecutive_failure_count, review.consecutive_failure_threshold
            )],
        });
    }

    None
}

// ─── Helpers ─────────────────────────────────────────────────────

fn no_change(current_phase: &GovernancePhase, reason: &str) -> GovernanceTransitionResult {
    GovernanceTransitionResult {
        new_phase: current_phase.clone(),
        phase_changed: false,
        freeze_promotion: false,
        remove_state: false,
        reason_code: TransitionReason::NoChange,
        notes: vec![reason.to_string()],
    }
}

#[cfg(test)]
#[path = "governance_transition_tests.rs"]
mod tests;
