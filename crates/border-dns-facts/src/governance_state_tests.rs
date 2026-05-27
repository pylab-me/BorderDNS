use chrono::Utc;

use super::*;

#[test]
fn test_domain_governance_state_new() {
    let now = Utc::now();
    let state = DomainGovernanceState::new("example.com".into(), "china".into(), now);

    assert_eq!(state.domain, "example.com");
    assert_eq!(state.phase, GovernancePhase::New);
    assert_eq!(state.current_route, "china");
    assert_eq!(state.prior_route, "china");
    assert_eq!(state.suggested_route, "");
    assert_eq!(state.observation_count, 0);
    assert_eq!(state.state_version, 1);
    assert!(!state.can_promote);
    assert!(!state.promotion_frozen);
}

#[test]
fn test_thresholds_defaults() {
    let mixed = MixedEvidenceThresholds::default();
    assert_eq!(mixed.mixed_freeze_threshold, 3);
    assert_eq!(mixed.mixed_degrade_threshold, 10);
    assert_eq!(mixed.mixed_window_hours, 24);

    let stable_tp = StablePromotionThresholds::default();
    assert_eq!(stable_tp.min_observations, 20);
    assert_eq!(stable_tp.min_local_alignment, 5);
    assert_eq!(stable_tp.min_third_party_alignment, 2);
    assert_eq!(stable_tp.min_distinct_third_party, 2);
    assert_eq!(stable_tp.max_mixed_24h, 2);
    assert_eq!(stable_tp.max_hard_conflict_24h, 0);
    assert_eq!(stable_tp.min_no_conflict_streak, 10);

    let stable_lo = LocalOnlyStableThresholds::default();
    assert_eq!(stable_lo.min_observations, 50);
    assert_eq!(stable_lo.min_local_alignment, 15);
    assert_eq!(stable_lo.min_no_conflict_streak, 20);

    let review = ReviewThresholds::default();
    assert_eq!(review.hard_conflict_threshold, 3);
    assert_eq!(review.tls_mismatch_threshold, 2);
    assert_eq!(review.route_opposite_threshold, 3);
    assert_eq!(review.mixed_degrade_threshold, 10);
    assert_eq!(review.consecutive_failure_threshold, 5);

    let fallback = FallbackThresholds::default();
    assert_eq!(fallback.review_max_duration_hours, 6);
    assert_eq!(fallback.fallback_hard_conflict_threshold, 5);
    assert_eq!(fallback.fallback_route_opposite_threshold, 5);
}

#[test]
fn test_governance_thresholds_default() {
    let thresholds = GovernanceThresholds::default();
    assert_eq!(thresholds.mixed_evidence.mixed_freeze_threshold, 3);
    assert_eq!(thresholds.stable_with_third_party.min_observations, 20);
    assert_eq!(thresholds.stable_local_only.min_observations, 50);
    assert_eq!(thresholds.review.hard_conflict_threshold, 3);
    assert_eq!(thresholds.fallback.review_max_duration_hours, 6);
    assert_eq!(thresholds.third_party_mode, ThirdPartyMode::Disabled);
}

#[test]
fn test_state_serde_roundtrip() {
    let now = Utc::now();
    let state = DomainGovernanceState::new("qq.com".into(), "china".into(), now);
    let json = serde_json::to_string(&state).unwrap();
    let parsed: DomainGovernanceState = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.domain, "qq.com");
    assert_eq!(parsed.phase, GovernancePhase::New);
    assert_eq!(parsed.prior_route, "china");
}

#[test]
fn test_third_party_summary_default() {
    let summary = ThirdPartyEvidenceSummary::default();
    assert!(!summary.enabled);
    assert_eq!(summary.distinct_observers, 0);
    assert_eq!(summary.china_observer_count, 0);
    assert_eq!(summary.foreign_observer_count, 0);
    assert_eq!(summary.cross_location_divergence_count, 0);
    assert_eq!(summary.same_location_conflict_count, 0);
    assert_eq!(summary.tls_mismatch_count, 0);
}

#[test]
fn test_review_candidate_serde() {
    let candidate = ReviewCandidate {
        domain: "example.com".into(),
        phase: GovernancePhase::Review,
        reason: ConflictKind::MixedGeoSoft,
        mixed_count_24h: 5,
        hard_conflict_count_24h: 0,
        tls_mismatch_count_24h: 0,
    };
    let json = serde_json::to_string(&candidate).unwrap();
    let parsed: ReviewCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.domain, "example.com");
    assert_eq!(parsed.phase, GovernancePhase::Review);
}
