use facts::DomainGovernanceState;
use facts::GovernancePhase;
use facts::GovernanceThresholds;
use facts::ThirdPartyMode;

use super::*;

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

fn new_state(domain: &str, prior: &str) -> DomainGovernanceState {
    DomainGovernanceState::new(domain.to_string(), prior.to_string(), now())
}

fn default_thresholds() -> GovernanceThresholds {
    GovernanceThresholds::default()
}

fn default_input(state: DomainGovernanceState) -> GovernanceTransitionInput {
    GovernanceTransitionInput {
        state,
        latest_can_promote: false,
        latest_is_mixed: false,
        latest_tls_mismatch: false,
        latest_hard_conflict: false,
        latest_soft_conflict: false,
        latest_local_aligned: false,
        latest_third_party_aligned: false,
        is_first_seen: false,
        upstream_failure: false,
        thresholds: default_thresholds(),
    }
}

// ─── New -> Learning ─────────────────────────────────────────────

#[test]
fn test_first_seen_new_goes_to_learning() {
    let state = new_state("example.com", "china");
    let mut input = default_input(state);
    input.is_first_seen = true;

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Learning);
    assert_eq!(result.reason_code, TransitionReason::FirstSeen);
}

#[test]
fn test_new_phase_goes_to_learning() {
    let state = new_state("example.com", "china");
    let input = default_input(state);

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Learning);
    assert_eq!(result.reason_code, TransitionReason::FirstSeen);
}

// ─── Learning -> Suggested ───────────────────────────────────────

#[test]
fn test_learning_with_promote_goes_to_suggested() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Learning;
    state.hard_conflict_count_24h = 0;
    state.mixed_count_24h = 0;

    let mut input = default_input(state);
    input.latest_can_promote = true;

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Suggested);
    assert_eq!(result.reason_code, TransitionReason::LocalEvidencePromote);
}

#[test]
fn test_learning_with_tp_alignment_promote() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Learning;
    state.hard_conflict_count_24h = 0;
    state.mixed_count_24h = 0;

    let mut input = default_input(state);
    input.latest_can_promote = true;
    input.latest_third_party_aligned = true;

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Suggested);
    assert_eq!(
        result.reason_code,
        TransitionReason::ThirdPartyAlignmentPromote
    );
}

#[test]
fn test_learning_with_hard_conflict_stays() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Learning;
    state.hard_conflict_count_24h = 1;

    let mut input = default_input(state);
    input.latest_can_promote = true;

    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert_eq!(result.reason_code, TransitionReason::NoChange);
}

#[test]
fn test_learning_mixed_freeze() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Learning;
    state.mixed_count_24h = 3; // >= freeze_threshold

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert!(result.freeze_promotion);
    assert_eq!(result.reason_code, TransitionReason::MixedFreeze);
}

// ─── Suggested -> Stable with third-party ────────────────────────

#[test]
fn test_suggested_to_stable_with_tp() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Suggested;
    state.observation_count = 25;
    state.local_alignment_count = 6;
    state.third_party_alignment_count = 3;
    state.distinct_third_party_observers = 3;
    state.hard_conflict_count_24h = 0;
    state.mixed_count_24h = 1;
    state.consecutive_no_conflict_count = 12;

    let mut input = default_input(state);
    input.thresholds.third_party_mode = ThirdPartyMode::Enabled;

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Stable);
    assert_eq!(
        result.reason_code,
        TransitionReason::StablePromotionWithPeers
    );
}

#[test]
fn test_suggested_to_stable_local_only() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Suggested;
    state.observation_count = 55;
    state.local_alignment_count = 16;
    state.hard_conflict_count_24h = 0;
    state.mixed_count_24h = 1;
    state.consecutive_no_conflict_count = 22;

    let mut input = default_input(state);
    input.thresholds.third_party_mode = ThirdPartyMode::Disabled;

    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Stable);
    assert_eq!(
        result.reason_code,
        TransitionReason::StablePromotionLocalOnly
    );
}

#[test]
fn test_suggested_insufficient_stays() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Suggested;
    state.observation_count = 5;

    let mut input = default_input(state);
    input.thresholds.third_party_mode = ThirdPartyMode::Disabled;

    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert_eq!(result.reason_code, TransitionReason::NoChange);
}

// ─── Review triggers ─────────────────────────────────────────────

#[test]
fn test_tls_mismatch_triggers_review_from_stable() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Stable;
    state.tls_mismatch_count_24h = 2;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Review);
    assert_eq!(result.reason_code, TransitionReason::TlsMismatchToReview);
}

#[test]
fn test_hard_conflict_triggers_review_from_suggested() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Suggested;
    state.hard_conflict_count_24h = 3;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Review);
    assert_eq!(result.reason_code, TransitionReason::HardConflictToReview);
}

#[test]
fn test_route_opposite_triggers_review() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Stable;
    state.route_opposite_count_24h = 3;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Review);
    assert_eq!(result.reason_code, TransitionReason::RouteOppositeToReview);
}

#[test]
fn test_mixed_degrade_triggers_review() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Learning;
    state.mixed_count_24h = 10;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Review);
    assert_eq!(result.reason_code, TransitionReason::MixedDegradeToReview);
}

#[test]
fn test_consecutive_failure_triggers_review() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Suggested;
    state.consecutive_failure_count = 5;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Review);
    assert_eq!(
        result.reason_code,
        TransitionReason::ConsecutiveFailureToReview
    );
}

// ─── Review -> Learning / Fallback ───────────────────────────────

#[test]
fn test_review_cleared_goes_to_learning() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Review;
    state.hard_conflict_count_24h = 0;
    state.mixed_count_24h = 1;
    state.consecutive_no_conflict_count = 12;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Learning);
    assert_eq!(result.reason_code, TransitionReason::ReviewCleared);
}

#[test]
fn test_review_stays_when_not_cleared() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Review;
    state.hard_conflict_count_24h = 1;
    state.mixed_count_24h = 1;
    state.consecutive_no_conflict_count = 5;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert_eq!(result.reason_code, TransitionReason::NoChange);
}

// ─── Fallback -> Learning ────────────────────────────────────────

#[test]
fn test_fallback_to_learning_on_clean_evidence() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Fallback;
    state.hard_conflict_count_24h = 0;
    state.tls_mismatch_count_24h = 0;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(result.phase_changed);
    assert_eq!(result.new_phase, GovernancePhase::Learning);
    assert_eq!(result.reason_code, TransitionReason::FallbackExpired);
}

#[test]
fn test_fallback_stays_with_conflict() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Fallback;
    state.hard_conflict_count_24h = 2;

    let mut input = default_input(state);
    input.latest_hard_conflict = true;

    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert_eq!(result.reason_code, TransitionReason::NoChange);
}

// ─── Stable maintenance ──────────────────────────────────────────

#[test]
fn test_stable_no_issues_stays_stable() {
    let mut state = new_state("example.com", "china");
    state.phase = GovernancePhase::Stable;
    // No threshold breaches
    state.tls_mismatch_count_24h = 0;
    state.hard_conflict_count_24h = 0;
    state.route_opposite_count_24h = 0;
    state.mixed_count_24h = 0;
    state.consecutive_failure_count = 0;

    let input = default_input(state);
    let result = evaluate_governance_transition(&input);
    assert!(!result.phase_changed);
    assert_eq!(result.reason_code, TransitionReason::NoChange);
}

// ─── TransitionReason display ────────────────────────────────────

#[test]
fn test_transition_reason_display() {
    assert_eq!(TransitionReason::FirstSeen.to_string(), "first_seen");
    assert_eq!(TransitionReason::NoChange.to_string(), "no_change");
    assert_eq!(
        TransitionReason::LocalEvidencePromote.to_string(),
        "local_evidence_promote"
    );
    assert_eq!(
        TransitionReason::StablePromotionWithPeers.to_string(),
        "stable_promotion_with_peers"
    );
    assert_eq!(
        TransitionReason::HardConflictToReview.to_string(),
        "hard_conflict_to_review"
    );
    assert_eq!(
        TransitionReason::FallbackExpired.to_string(),
        "fallback_expired"
    );
}
