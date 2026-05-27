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
