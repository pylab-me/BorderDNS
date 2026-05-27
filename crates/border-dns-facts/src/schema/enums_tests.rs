use super::*;

#[test]
fn test_governance_phase_display() {
    assert_eq!(GovernancePhase::New.as_str(), "new");
    assert_eq!(GovernancePhase::Learning.as_str(), "learning");
    assert_eq!(GovernancePhase::Suggested.as_str(), "suggested");
    assert_eq!(GovernancePhase::Stable.as_str(), "stable");
    assert_eq!(GovernancePhase::Review.as_str(), "review");
    assert_eq!(GovernancePhase::Fallback.as_str(), "fallback");
}

#[test]
fn test_governance_phase_default() {
    assert_eq!(GovernancePhase::default(), GovernancePhase::New);
}

#[test]
fn test_conflict_kind_is_hard() {
    assert!(ConflictKind::RouteOppositeHard.is_hard());
    assert!(ConflictKind::TlsIdentityMismatchHard.is_hard());
    assert!(!ConflictKind::MixedGeoSoft.is_hard());
    assert!(!ConflictKind::ThirdPartyMismatchSoft.is_hard());
    assert!(!ConflictKind::ProbeQualityWeak.is_hard());
}

#[test]
fn test_third_party_mode() {
    assert!(ThirdPartyMode::Enabled.is_enabled());
    assert!(!ThirdPartyMode::Disabled.is_enabled());
    assert_eq!(ThirdPartyMode::default(), ThirdPartyMode::Disabled);
}

#[test]
fn test_enum_serde_roundtrip() {
    let phase = GovernancePhase::Suggested;
    let json = serde_json::to_string(&phase).unwrap();
    assert_eq!(json, "\"suggested\"");
    let parsed: GovernancePhase = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, phase);

    let conflict = ConflictKind::TlsIdentityMismatchHard;
    let json = serde_json::to_string(&conflict).unwrap();
    assert_eq!(json, "\"tls_identity_mismatch_hard\"");
    let parsed: ConflictKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, conflict);

    let event = MeaningfulEventKind::FirstSeenDomain;
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, "\"first_seen_domain\"");
    let parsed: MeaningfulEventKind = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, event);
}

#[test]
fn test_tls_identity_status_display() {
    assert_eq!(TlsIdentityStatus::ExactMatch.as_str(), "exact_match");
    assert_eq!(TlsIdentityStatus::CnameMatch.as_str(), "cname_match");
    assert_eq!(TlsIdentityStatus::Mismatch.as_str(), "mismatch");
    assert_eq!(TlsIdentityStatus::ProbeFailed.as_str(), "probe_failed");
    assert_eq!(TlsIdentityStatus::NotApplicable.as_str(), "not_applicable");
    assert_eq!(TlsIdentityStatus::Unknown.as_str(), "unknown");
}

#[test]
fn test_evidence_strength_display() {
    assert_eq!(EvidenceStrength::None.as_str(), "none");
    assert_eq!(EvidenceStrength::Weak.as_str(), "weak");
    assert_eq!(EvidenceStrength::Moderate.as_str(), "moderate");
    assert_eq!(EvidenceStrength::Strong.as_str(), "strong");
    assert_eq!(EvidenceStrength::Conflicting.as_str(), "conflicting");
}

#[test]
fn test_domain_intent_display() {
    assert_eq!(DomainIntent::ChinaIntent.as_str(), "china_intent");
    assert_eq!(DomainIntent::ForeignIntent.as_str(), "foreign_intent");
    assert_eq!(DomainIntent::GlobalIntent.as_str(), "global_intent");
    assert_eq!(DomainIntent::MixedIntent.as_str(), "mixed_intent");
    assert_eq!(DomainIntent::UnknownIntent.as_str(), "unknown_intent");
}
