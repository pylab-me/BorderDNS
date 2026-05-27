//! In-memory governance store for per-domain governance state.
//!
//! `GovernanceStore` is a concurrent map of domain → `DomainGovernanceState`.
//! It supports read/update from the pipeline hot path and background workers.
//!
//! The store is intentionally simple: an in-memory `DashMap` with no persistence.
//! Persistence is handled by the facts store (JSONL/Parquet) at a lower frequency.

use std::sync::Arc;

use chrono::Utc;

use crate::DomainGovernanceState;

/// Thread-safe, in-memory governance state store.
///
/// Key: domain name (FQDN, e.g. "example.com.")
/// Value: `DomainGovernanceState`
#[derive(Debug)]
pub struct GovernanceStore {
    inner: dashmap::DashMap<String, Arc<DomainGovernanceState>>,
}

impl GovernanceStore {
    /// Create an empty governance store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: dashmap::DashMap::new(),
        }
    }

    /// Get the governance state for a domain, if it exists.
    #[must_use]
    pub fn get(&self, domain: &str) -> Option<Arc<DomainGovernanceState>> {
        self.inner.get(domain).map(|r| Arc::clone(r.value()))
    }

    /// Get the governance state for a domain, or create a new one from domain prior.
    ///
    /// If the domain is not in the store, creates a new state with the given
    /// prior route and inserts it.
    pub fn get_or_create(&self, domain: &str, prior_route: &str) -> Arc<DomainGovernanceState> {
        self.inner
            .entry(domain.to_string())
            .or_insert_with(|| {
                Arc::new(DomainGovernanceState::new(
                    domain.to_string(),
                    prior_route.to_string(),
                    Utc::now(),
                ))
            })
            .value()
            .clone()
    }

    /// Update the governance state for a domain.
    ///
    /// Uses optimistic concurrency: the update is only applied if the stored
    /// state version matches `expected_version`. Returns `true` if the update
    /// was applied.
    pub fn update(
        &self,
        domain: &str,
        expected_version: u64,
        new_state: DomainGovernanceState,
    ) -> bool {
        if let Some(mut entry) = self.inner.get_mut(domain) {
            if entry.state_version == expected_version {
                *entry = Arc::new(new_state);
                return true;
            }
        }
        false
    }

    /// Force-update the governance state for a domain (no version check).
    pub fn force_update(&self, domain: &str, new_state: DomainGovernanceState) {
        self.inner.insert(domain.to_string(), Arc::new(new_state));
    }

    /// Number of domains in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Collect all domains currently in the store (snapshot).
    pub fn domains(&self) -> Vec<String> {
        self.inner.iter().map(|r| r.key().clone()).collect()
    }
}

impl Default for GovernanceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "governance_store_tests.rs"]
mod tests;
