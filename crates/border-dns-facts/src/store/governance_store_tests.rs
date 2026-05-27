use chrono::Utc;

use super::*;
use crate::GovernancePhase;

fn make_store() -> GovernanceStateStore {
    GovernanceStateStore::new()
}

#[test]
fn test_empty_store() {
    let store = make_store();
    assert!(store.is_empty());
    assert_eq!(store.len(), 0);
    assert!(store.get("example.com").is_none());
}

#[test]
fn test_get_or_create() {
    let store = make_store();
    let state = store.get_or_create("example.com", "china");
    assert_eq!(state.domain, "example.com");
    assert_eq!(state.prior_route, "china");
    assert_eq!(state.phase, GovernancePhase::New);
    assert_eq!(store.len(), 1);
}

#[test]
fn test_get_or_create_idempotent() {
    let store = make_store();
    let s1 = store.get_or_create("example.com", "china");
    let s2 = store.get_or_create("example.com", "foreign");
    // Second call should not overwrite
    assert_eq!(s1.prior_route, "china");
    assert_eq!(s2.prior_route, "china");
    assert_eq!(store.len(), 1);
}

#[test]
fn test_get_existing() {
    let store = make_store();
    store.get_or_create("example.com", "china");
    let got = store.get("example.com");
    assert!(got.is_some());
    assert_eq!(got.unwrap().domain, "example.com");
}

#[test]
fn test_update_with_matching_version() {
    let store = make_store();
    store.get_or_create("example.com", "china");

    let mut new_state =
        DomainGovernanceState::new("example.com".into(), "china".into(), Utc::now());
    new_state.phase = GovernancePhase::Learning;
    new_state.state_version = 1; // matches the new() default

    let updated = store.update("example.com", 1, new_state);
    assert!(updated);
    let got = store.get("example.com").unwrap();
    assert_eq!(got.phase, GovernancePhase::Learning);
}

#[test]
fn test_update_with_wrong_version_fails() {
    let store = make_store();
    store.get_or_create("example.com", "china");

    let new_state = DomainGovernanceState::new("example.com".into(), "china".into(), Utc::now());
    let updated = store.update("example.com", 999, new_state);
    assert!(!updated);
}

#[test]
fn test_force_update() {
    let store = make_store();
    store.get_or_create("example.com", "china");

    let mut new_state =
        DomainGovernanceState::new("example.com".into(), "foreign".into(), Utc::now());
    new_state.phase = GovernancePhase::Suggested;

    store.force_update("example.com", new_state);
    let got = store.get("example.com").unwrap();
    assert_eq!(got.phase, GovernancePhase::Suggested);
    assert_eq!(got.prior_route, "foreign");
}

#[test]
fn test_domains_list() {
    let store = make_store();
    store.get_or_create("a.com", "china");
    store.get_or_create("b.com", "foreign");
    let mut domains = store.domains();
    domains.sort();
    assert_eq!(domains, vec!["a.com".to_string(), "b.com".to_string()]);
}

#[test]
fn test_default_trait() {
    let store = GovernanceStateStore::default();
    assert!(store.is_empty());
}
