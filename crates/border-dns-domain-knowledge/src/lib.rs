//! Domain-level business knowledge for BorderDNS routing.
//!
//! Provides domain classification (China/foreign/global CDN/CNAME hints)
//! using a trie-based rule matcher. This replaces the semantic parts of
//! Python `structures/domain_sets.py`, `structures/domain_rules.py`,
//! and `structures/dns_filters.py`.
//!
//! Also provides:
//! - `HostsTable`: static domain → IP overrides (like /etc/hosts).
//! - `BlockMatcher`: domain blocking by exact name, suffix, or wildcard pattern.
//!
//! This crate must not depend on runtime, upstream, or network crates.

mod block_matcher;
mod domain_knowledge;
mod hosts_table;

// ─── Re-exports ─────────────────────────────────────────────────

pub use block_matcher::BlockMatcher;
pub use domain_knowledge::BuiltInDomainKnowledge;
pub use domain_knowledge::DomainKnowledge;
pub use hosts_table::HostEntry;
pub use hosts_table::HostsTable;

#[cfg(test)]
#[path = "domain_knowledge_tests.rs"]
mod tests;
