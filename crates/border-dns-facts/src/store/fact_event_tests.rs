use chrono::Utc;

use super::*;

fn make_test_event() -> BorderDnsFactEvent {
    BorderDnsFactEvent::new(
        Utc::now(),
        ObserverScope::Local,
        MeaningfulEventKind::FirstSeenDomain,
        QueryFact {
            domain: "example.com".into(),
            normalized_domain: "example.com".into(),
            qtype: "A".into(),
        },
        DecisionFact {
            route: "china".into(),
            route_source: "domain_prior".into(),
            phase: GovernancePhase::Learning,
            domain_intent: DomainIntent::ChinaIntent,
            confidence: "strong".into(),
            can_promote: false,
            reason_codes: vec!["domain_prior_cn".into()],
        },
        AnswerFact {
            rcode: "NOERROR".into(),
            record_count: 2,
            ip_count: 2,
            cname_count: 0,
        },
        EvidenceFact {
            ip_scope: "cn_only".into(),
            cn_ip_count: 2,
            foreign_ip_count: 0,
            cname_scope: CnameScope::None,
            tls_identity: TlsIdentityStatus::Unknown,
            probe_quality: ProbeQuality::Unknown,
            evidence_strength: EvidenceStrength::Moderate,
            conflict_kind: None,
        },
        RuntimeOutcomeFact {
            response_source: "upstream".into(),
            upstream_rtt_ms: Some(42),
            total_latency_ms: 45,
            cache_status: "miss".into(),
        },
        GovernanceFact {
            phase: GovernancePhase::Learning,
            current_route: "china".into(),
            fact_status: FactStatus::Observed,
            china_score: 3.8,
            foreign_score: 0.0,
            score_margin: 3.8,
            summary: "First seen domain, CN prior.".into(),
        },
    )
}

#[test]
fn test_fact_event_schema_version() {
    let event = make_test_event();
    assert_eq!(event.schema_version, "borderdns.fact.v1");
    assert_eq!(event.schema_revision, 1);
}

#[test]
fn test_fact_event_jsonl_roundtrip() {
    let event = make_test_event();
    let line = event.to_jsonl_line().unwrap();
    assert!(line.ends_with('\n'));

    let parsed: BorderDnsFactEvent = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(parsed.schema_version, event.schema_version);
    assert_eq!(parsed.event_kind, MeaningfulEventKind::FirstSeenDomain);
    assert_eq!(parsed.query.domain, "example.com");
    assert_eq!(parsed.decision.phase, GovernancePhase::Learning);
    assert_eq!(parsed.evidence.cname_scope, CnameScope::None);
}

#[test]
fn test_fact_event_serde_preserves_nested() {
    let event = make_test_event();
    let json = serde_json::to_string_pretty(&event).unwrap();
    let parsed: BorderDnsFactEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.answer.record_count, 2);
    assert_eq!(parsed.outcome.upstream_rtt_ms, Some(42));
    assert_eq!(parsed.governance.china_score, 3.8);
    assert_eq!(parsed.governance.phase, GovernancePhase::Learning);
}

#[test]
fn test_fact_event_with_conflict() {
    let mut event = make_test_event();
    event.event_kind = MeaningfulEventKind::MixedGeoObserved;
    event.evidence.conflict_kind = Some(ConflictKind::MixedGeoSoft);
    event.evidence.ip_scope = "mixed".into();
    event.evidence.cn_ip_count = 1;
    event.evidence.foreign_ip_count = 1;

    let line = event.to_jsonl_line().unwrap();
    let parsed: BorderDnsFactEvent = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(
        parsed.evidence.conflict_kind,
        Some(ConflictKind::MixedGeoSoft)
    );
    assert_eq!(parsed.evidence.cn_ip_count, 1);
    assert_eq!(parsed.evidence.foreign_ip_count, 1);
}

#[test]
fn test_fact_event_tls_mismatch() {
    let mut event = make_test_event();
    event.event_kind = MeaningfulEventKind::TlsIdentityMismatch;
    event.evidence.tls_identity = TlsIdentityStatus::Mismatch;
    event.evidence.evidence_strength = EvidenceStrength::Conflicting;
    event.evidence.conflict_kind = Some(ConflictKind::TlsIdentityMismatchHard);

    let line = event.to_jsonl_line().unwrap();
    let parsed: BorderDnsFactEvent = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(parsed.evidence.tls_identity, TlsIdentityStatus::Mismatch);
    assert_eq!(
        parsed.evidence.conflict_kind,
        Some(ConflictKind::TlsIdentityMismatchHard)
    );
}
