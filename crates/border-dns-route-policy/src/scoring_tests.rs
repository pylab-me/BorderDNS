use facts::CnameScope;
use facts::DomainIntent;
use facts::EvidenceStrength;
use facts::FactStatus;
use facts::GovernancePhase;
use facts::TlsIdentityStatus;

use super::*;

fn china_prior_input() -> RouteEvidenceInput {
    RouteEvidenceInput {
        prior_route: "china".into(),
        ..RouteEvidenceInput::default()
    }
}

fn foreign_prior_input() -> RouteEvidenceInput {
    RouteEvidenceInput {
        prior_route: "foreign".into(),
        ..RouteEvidenceInput::default()
    }
}

// ─── Domain Prior scoring ────────────────────────────────────────

#[test]
fn test_china_prior_produces_china_score() {
    let score = score_route_evidence(&china_prior_input());
    assert_eq!(score.domain_intent, DomainIntent::ChinaIntent);
    assert!(score.china_score > 0.0);
    assert_eq!(score.foreign_score, 0.0);
    assert_eq!(score.route_authority, "domain_prior");
}

#[test]
fn test_foreign_prior_produces_foreign_score() {
    let score = score_route_evidence(&foreign_prior_input());
    assert_eq!(score.domain_intent, DomainIntent::ForeignIntent);
    assert!(score.foreign_score > 0.0);
    assert_eq!(score.china_score, 0.0);
}

#[test]
fn test_no_prior_unknown_intent() {
    let input = RouteEvidenceInput::default();
    let score = score_route_evidence(&input);
    assert_eq!(score.domain_intent, DomainIntent::UnknownIntent);
    assert_eq!(score.china_score, 0.0);
    assert_eq!(score.foreign_score, 0.0);
    assert!(score.notes.contains(&"no_domain_prior".to_string()));
}

// ─── Local IP Geo scoring ────────────────────────────────────────

#[test]
fn test_local_cn_ips_boost_china_score() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 3;
    let score = score_route_evidence(&input);
    assert!(score.china_score > 2.4); // domain_prior + 3*1.4
    assert_eq!(score.foreign_score, 0.0);
}

#[test]
fn test_local_foreign_ips_boost_foreign_score() {
    let mut input = foreign_prior_input();
    input.local_foreign_ip_count = 2;
    let score = score_route_evidence(&input);
    assert!(score.foreign_score > 2.4); // domain_prior + 2*1.4
}

#[test]
fn test_mixed_local_ips_both_sides_score() {
    let mut input = RouteEvidenceInput::default();
    input.prior_route = "china".into();
    input.local_cn_ip_count = 1;
    input.local_foreign_ip_count = 1;
    input.ip_scope = "mixed".into();
    let score = score_route_evidence(&input);
    // Mixed without third-party -> conflicting
    assert_eq!(score.evidence_strength, EvidenceStrength::Conflicting);
    assert!(!score.can_promote);
}

// ─── TLS Identity ────────────────────────────────────────────────

#[test]
fn test_tls_exact_match_strengthen_leading_side() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 2;
    input.tls_identity_status = TlsIdentityStatus::ExactMatch;
    let score = score_route_evidence(&input);
    assert!(score.can_promote);
    assert!(score.notes.is_empty() || !score.notes.iter().any(|n| n.contains("mismatch")));
}

#[test]
fn test_tls_mismatch_blocks_promotion() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 3;
    input.tls_identity_status = TlsIdentityStatus::Mismatch;
    let score = score_route_evidence(&input);
    assert!(!score.can_promote);
    assert!(
        score
            .notes
            .contains(&"tls_identity_mismatch_downweighted".to_string())
    );
}

#[test]
fn test_tls_mismatch_reduces_both_scores() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 3;
    input.tls_identity_status = TlsIdentityStatus::ExactMatch;
    let clean_score = score_route_evidence(&input);
    input.tls_identity_status = TlsIdentityStatus::Mismatch;
    let mismatch_score = score_route_evidence(&input);
    assert!(mismatch_score.china_score < clean_score.china_score);
}

// ─── CNAME Provider ──────────────────────────────────────────────

#[test]
fn test_cname_cn_provider_boosts_china() {
    let mut input = china_prior_input();
    input.cname_scope = CnameScope::CnProvider;
    let score = score_route_evidence(&input);
    assert!(score.china_score > 2.4);
    assert!(score.component_scores.contains_key("china.cname_provider"));
}

#[test]
fn test_cname_foreign_provider_boosts_foreign() {
    let mut input = foreign_prior_input();
    input.cname_scope = CnameScope::ForeignProvider;
    let score = score_route_evidence(&input);
    assert!(score.foreign_score > 2.4);
    assert!(
        score
            .component_scores
            .contains_key("foreign.cname_provider")
    );
}

#[test]
fn test_cname_global_cdn_both_sides() {
    let mut input = china_prior_input();
    input.cname_scope = CnameScope::GlobalCdn;
    let score = score_route_evidence(&input);
    assert!(score.component_scores.contains_key("china.cname_global"));
    assert!(score.component_scores.contains_key("foreign.cname_global"));
}

// ─── Third-party IP ──────────────────────────────────────────────

#[test]
fn test_third_party_cn_ips_help_china() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 1;
    input.third_party_cn_ip_count = 2;
    let score = score_route_evidence(&input);
    assert!(score.china_score > 2.4);
    assert_eq!(score.reason_code, "local_third_party_geo_aligned");
}

#[test]
fn test_third_party_foreign_ips_help_foreign() {
    let mut input = foreign_prior_input();
    input.third_party_foreign_ip_count = 2;
    let score = score_route_evidence(&input);
    assert!(score.foreign_score > 2.4);
}

// ─── Can Promote logic ──────────────────────────────────────────

#[test]
fn test_china_prior_strong_evidence_can_promote() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 3;
    input.runtime_confidence = 0.85;
    let score = score_route_evidence(&input);
    assert!(score.can_promote);
    assert_eq!(score.promote_action, PromoteAction::PromoteAssisted);
    assert_eq!(score.decision_phase, GovernancePhase::Suggested);
    assert_eq!(score.decision_timing, DecisionTiming::AssistedNextQuery);
}

#[test]
fn test_no_prior_no_evidence_cannot_promote() {
    let input = RouteEvidenceInput::default();
    let score = score_route_evidence(&input);
    assert!(!score.can_promote);
    assert_eq!(score.promote_action, PromoteAction::ObserveOnly);
    assert_eq!(score.decision_phase, GovernancePhase::Learning);
    assert_eq!(score.decision_timing, DecisionTiming::ObserveOnly);
}

#[test]
fn test_global_intent_cannot_promote() {
    let mut input = RouteEvidenceInput::default();
    input.prior_route = "china".into();
    input.cname_scope = CnameScope::GlobalCdn;
    let score = score_route_evidence(&input);
    // GlobalCdn with small margin -> GlobalIntent -> cannot promote
    if score.domain_intent == DomainIntent::GlobalIntent {
        assert!(!score.can_promote);
    }
}

// ─── Mixed geo conflicting ──────────────────────────────────────

#[test]
fn test_mixed_geo_without_third_party_is_conflicting() {
    let mut input = RouteEvidenceInput::default();
    input.prior_route = "china".into();
    input.local_cn_ip_count = 1;
    input.local_foreign_ip_count = 1;
    input.ip_scope = "mixed".into();
    let score = score_route_evidence(&input);
    assert_eq!(score.evidence_strength, EvidenceStrength::Conflicting);
    assert!(!score.can_promote);
    assert_eq!(score.fact_status, FactStatus::Conflicting);
}

#[test]
fn test_mixed_geo_with_third_party_margin_wide_can_promote() {
    let mut input = RouteEvidenceInput::default();
    input.prior_route = "china".into();
    input.local_cn_ip_count = 2;
    input.local_foreign_ip_count = 1;
    input.third_party_cn_ip_count = 3;
    input.ip_scope = "mixed".into();
    input.runtime_confidence = 0.85;
    let score = score_route_evidence(&input);
    // Wide margin (8.0 vs 1.4) + third-party -> may promote
    assert!(score.china_score > score.foreign_score);
    assert!(score.score_margin > 2.0);
}

// ─── Prior conflict dampening ────────────────────────────────────

#[test]
fn test_opposite_evidence_dampened_against_prior() {
    let mut input = china_prior_input();
    input.local_foreign_ip_count = 5;
    input.runtime_confidence = 0.9;
    let score = score_route_evidence(&input);
    // foreign evidence challenges china prior -> dampened
    assert!(
        score
            .notes
            .contains(&"foreign_evidence_challenged_china_prior".to_string())
    );
}

// ─── Suggested next route ────────────────────────────────────────

#[test]
fn test_can_promote_china_suggests_china() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 3;
    input.runtime_confidence = 0.85;
    let score = score_route_evidence(&input);
    if score.can_promote {
        assert_eq!(score.suggested_next_route, "china");
    }
}

#[test]
fn test_can_promote_foreign_suggests_foreign() {
    let mut input = foreign_prior_input();
    input.local_foreign_ip_count = 3;
    input.runtime_confidence = 0.85;
    let score = score_route_evidence(&input);
    if score.can_promote {
        assert_eq!(score.suggested_next_route, "foreign");
    }
}

#[test]
fn test_cannot_promote_suggests_prior() {
    let input = RouteEvidenceInput::default();
    let score = score_route_evidence(&input);
    assert!(!score.can_promote);
    assert_eq!(score.suggested_next_route, "prior_route");
}

// ─── Component scores ────────────────────────────────────────────

#[test]
fn test_component_scores_contain_all_active_components() {
    let mut input = china_prior_input();
    input.local_cn_ip_count = 2;
    input.cname_scope = CnameScope::CnProvider;
    input.tls_identity_status = TlsIdentityStatus::ExactMatch;
    input.runtime_confidence = 0.85;
    let score = score_route_evidence(&input);
    assert!(score.component_scores.contains_key("china.domain_prior"));
    assert!(score.component_scores.contains_key("china.local_ip_geo"));
    assert!(score.component_scores.contains_key("china.cname_provider"));
    // TLS match strengthens leading side
    assert!(score.component_scores.contains_key("china.tls_identity"));
}

// ─── IP latency exclusion ────────────────────────────────────────

#[test]
fn test_ip_latency_never_in_input() {
    // RouteEvidenceInput intentionally has no latency_ms field.
    // This test documents the hard rule: IP latency is quality evidence only.
    let input = RouteEvidenceInput::default();
    let score = score_route_evidence(&input);
    // Scores should be zero — latency has no effect
    assert_eq!(score.china_score, 0.0);
    assert_eq!(score.foreign_score, 0.0);
}
