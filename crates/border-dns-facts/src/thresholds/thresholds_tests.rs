use super::*;

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
