use super::*;
use crate::MeaningfulEventKind;

#[test]
fn test_fact_emit_new() {
    let emit = FactEmitter::new(
        "example.com".into(),
        MeaningfulEventKind::FirstSeenDomain,
        "first_seen".into(),
    );
    assert_eq!(emit.domain, "example.com");
    assert_eq!(emit.event_kind, MeaningfulEventKind::FirstSeenDomain);
    assert_eq!(emit.reason_code, "first_seen");
    assert!(!emit.phase_changed);
    assert!(emit.new_phase.is_none());
}

#[test]
fn test_fact_emit_jsonl_roundtrip() {
    let mut emit = FactEmitter::new(
        "example.com".into(),
        MeaningfulEventKind::PhaseChanged,
        "tls_mismatch_to_review".into(),
    );
    emit.phase_changed = true;
    emit.new_phase = Some(GovernancePhase::Review);
    emit.context.insert("tls_mismatch_count".into(), "3".into());

    let line = emit.to_jsonl_line().unwrap();
    let parsed: FactEmitter = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed.domain, "example.com");
    assert_eq!(parsed.event_kind, MeaningfulEventKind::PhaseChanged);
    assert!(parsed.phase_changed);
    assert_eq!(parsed.new_phase, Some(GovernancePhase::Review));
}

#[test]
fn test_observation_job_geo_analysis() {
    let job = ObservationTask {
        job_id: "test-001".into(),
        domain: "example.com".into(),
        task_kind: ObservationTaskKind::GeoAnalysis {
            ip_addresses: vec!["1.1.1.1".into(), "223.5.5.5".into()],
            cname_chain: vec!["cdn.example.com.".into()],
        },
        current_phase: GovernancePhase::Learning,
        current_route: "china".into(),
        enqueued_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&job).unwrap();
    let parsed: ObservationTask = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.domain, "example.com");
    assert_eq!(parsed.current_phase, GovernancePhase::Learning);
    if let ObservationTaskKind::GeoAnalysis { ip_addresses, .. } = &parsed.task_kind {
        assert_eq!(ip_addresses.len(), 2);
    } else {
        panic!("expected GeoAnalysis");
    }
}

#[test]
fn test_observation_job_tls_probe() {
    let job = ObservationTask {
        job_id: "test-002".into(),
        domain: "example.com".into(),
        task_kind: ObservationTaskKind::TlsProbe {
            sni_domain: "example.com".into(),
            target_ip: "223.5.5.5".into(),
        },
        current_phase: GovernancePhase::Suggested,
        current_route: "china".into(),
        enqueued_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&job).unwrap();
    let parsed: ObservationTask = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.task_kind,
        ObservationTaskKind::TlsProbe {
            sni_domain: "example.com".into(),
            target_ip: "223.5.5.5".into(),
        }
    );
}

#[test]
fn test_observation_job_latency_probe() {
    let job = ObservationTask {
        job_id: "test-003".into(),
        domain: "example.com".into(),
        task_kind: ObservationTaskKind::LatencyProbe {
            target_ip: "1.1.1.1".into(),
        },
        current_phase: GovernancePhase::Learning,
        current_route: "foreign".into(),
        enqueued_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&job).unwrap();
    let parsed: ObservationTask = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.task_kind,
        ObservationTaskKind::LatencyProbe {
            target_ip: "1.1.1.1".into()
        }
    );
}

#[test]
fn test_observation_job_third_party_fetch() {
    let job = ObservationTask {
        job_id: "test-004".into(),
        domain: "example.com".into(),
        task_kind: ObservationTaskKind::ThirdPartyFetch {
            observer_id: "cn-shanghai-1".into(),
            domain: "example.com".into(),
        },
        current_phase: GovernancePhase::Stable,
        current_route: "china".into(),
        enqueued_at: chrono::Utc::now(),
    };

    let json = serde_json::to_string(&job).unwrap();
    let parsed: ObservationTask = serde_json::from_str(&json).unwrap();
    assert_eq!(
        parsed.task_kind,
        ObservationTaskKind::ThirdPartyFetch {
            observer_id: "cn-shanghai-1".into(),
            domain: "example.com".into(),
        }
    );
}
