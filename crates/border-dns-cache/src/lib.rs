//! DNS TTL cache with route-scoped keys and basic metrics.
//!
//! Sprint 2: Route-scoped cache prevents answer pollution between
//! China and foreign resolver views.
//!
//! Cache key format: `route:qtype:domain`
//!
//! P1 fixes applied:
//! - Cache stores `Arc<DnsMessage>` to avoid deep clone on every hit.
//! - `CacheKey` stores a single inline byte buffer instead of `Vec<Vec<u8>>`.
//!
//! Sprint 2 optimizations applied:
//! - CacheKey uses a 128-bit hash value (zero allocation) instead of `name_bytes`.
//! - CacheEntry stores both pre-serialized wire bytes (`Arc<Vec<u8>>`) and the
//!   parsed message (`Arc<DnsMessage>`), eliminating serialization on cache hits.
//! - Added `CachedResponse` returned from the cache for cheap cloning and fast
//!   downstream patching.

use std::hash::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use border_dns_config::CacheConfig;
use dashmap::DashMap;
use dns_protocol::message::DnsMessage;
use dns_protocol::name::DomainName;
use dns_types::QType;
use dns_types::Route;

// ─── Public cache response ───────────────────────────────────────

/// Lightweight cached DNS response.
///
/// Contains both the pre-serialized wire bytes and the parsed message, both
/// wrapped in `Arc` for cheap cloning.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    wire: Arc<Vec<u8>>,
    message: Arc<DnsMessage>,
}

impl CachedResponse {
    /// Construct from a `DnsMessage`. Serializes the message once and stores
    /// the wire bytes alongside the message.
    pub fn new(message: DnsMessage) -> Self {
        Self {
            wire: Arc::new(message.to_wire()),
            message: Arc::new(message),
        }
    }

    /// Construct from pre-existing shared data.
    pub fn from_parts(wire: Arc<Vec<u8>>, message: Arc<DnsMessage>) -> Self {
        Self { wire, message }
    }

    /// Cheaply return a mutable copy of the wire bytes with the DNS header ID
    /// replaced by `new_id`. No deep clone of the message structure is needed.
    pub fn wire_with_id(&self, new_id: u16) -> Vec<u8> {
        let mut wire = (*self.wire).clone();
        wire[0] = (new_id >> 8) as u8;
        wire[1] = (new_id & 0xFF) as u8;
        wire
    }

    /// Pre-serialized wire bytes (shared).
    #[must_use]
    pub fn wire(&self) -> &Arc<Vec<u8>> {
        &self.wire
    }

    /// Parsed DNS message (shared).
    #[must_use]
    pub fn message(&self) -> &Arc<DnsMessage> {
        &self.message
    }
}

// ─── Cache key ───────────────────────────────────────────────────

/// Cache key: combined route + qtype + domain, represented as a 128-bit hash.
///
/// Using a pure hash avoids heap allocation on every cache get/insert. Collisions
/// are astronomically rare for the bounded cache sizes used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey(u128);

impl CacheKey {
    fn new(route: Route, qtype: QType, name: &DomainName) -> Self {
        let mut hasher = DefaultHasher::new();
        route.hash(&mut hasher);
        qtype.hash(&mut hasher);
        for label in name.labels() {
            label.len().hash(&mut hasher);
            hasher.write(label);
        }
        Self(hasher.finish() as u128)
    }

    #[allow(dead_code)]
    fn legacy(qtype: QType, name: &DomainName) -> Self {
        Self::new(Route::Fallback, qtype, name)
    }
}

// ─── Cache entry ─────────────────────────────────────────────────

/// A cached DNS response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Pre-serialized wire bytes and parsed message, shared via `Arc`.
    response: CachedResponse,
    /// When this entry was stored.
    inserted_at: Instant,
    /// Effective TTL in seconds (clamped between min_ttl and max_ttl).
    ttl_secs: u32,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed().as_secs() >= u64::from(self.ttl_secs)
    }
}

// ─── Cache stats ─────────────────────────────────────────────────

/// Cache statistics (returned to callers).
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub entries: usize,
}

#[derive(Debug, Default)]
struct CacheMetrics {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    evictions: std::sync::atomic::AtomicU64,
}

impl CacheMetrics {
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn record_eviction(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }
}

// ─── DnsCache ────────────────────────────────────────────────────

/// DNS response cache.
///
/// Thread-safe via `DashMap`. Supports TTL-based expiration.
/// Returns `CachedResponse` to avoid clone on cache hit.
#[derive(Debug)]
pub struct DnsCache {
    entries: DashMap<CacheKey, CacheEntry>,
    stats: CacheMetrics,
    config: CacheConfig,
}

impl DnsCache {
    /// Create a new cache with the given configuration.
    #[must_use]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            entries: DashMap::with_capacity(config.max_entries),
            stats: CacheMetrics::default(),
            config,
        }
    }

    /// Look up a cached response for the given query.
    ///
    /// Returns `Some(CachedResponse)` if a valid (non-expired) entry exists.
    pub fn get(&self, qtype: QType, name: &DomainName) -> Option<CachedResponse> {
        self.get_scoped(Route::Fallback, qtype, name)
    }

    /// Look up a cached response for the given query, scoped by route.
    ///
    /// Different routes (china/foreign) must never share cache entries.
    pub fn get_scoped(
        &self,
        route: Route,
        qtype: QType,
        name: &DomainName,
    ) -> Option<CachedResponse> {
        let key = CacheKey::new(route, qtype, name);
        if let Some(entry) = self.entries.get(&key) {
            if entry.is_expired() {
                drop(entry);
                self.entries.remove(&key);
                self.stats.record_miss();
                return None;
            }
            self.stats.record_hit();
            tracing::trace!(route = %route, qtype = ?qtype, domain = %name, "cache hit");
            Some(entry.response.clone())
        } else {
            self.stats.record_miss();
            None
        }
    }

    /// Insert a DNS response into the cache.
    ///
    /// The TTL is extracted from the first answer record, clamped
    /// between `min_ttl` and `max_ttl`. The response is serialized once and
    /// stored as `CachedResponse` for fast future access.
    pub fn insert(&self, qtype: QType, name: &DomainName, message: &DnsMessage) {
        self.insert_scoped(Route::Fallback, qtype, name, message);
    }

    /// Insert a DNS response into the route-scoped cache.
    pub fn insert_scoped(
        &self,
        route: Route,
        qtype: QType,
        name: &DomainName,
        message: &DnsMessage,
    ) {
        let ttl = self.clamp_ttl(extract_min_ttl(message));
        self.insert_scoped_with_ttl(route, qtype, name, message, ttl);
    }

    /// Insert a DNS response into the route-scoped cache with an explicit TTL.
    ///
    /// Used by the pipeline to apply location-aware TTL policies
    /// (e.g., enhanced TTL for china+china).
    pub fn insert_scoped_with_ttl(
        &self,
        route: Route,
        qtype: QType,
        name: &DomainName,
        message: &DnsMessage,
        ttl: u32,
    ) {
        let ttl = self.clamp_ttl(ttl);

        let mut stored = message.clone();
        for rr in &mut stored.answers {
            rr.ttl = ttl;
        }

        if self.entries.len() >= self.config.max_entries {
            self.evict_oldest();
        }

        let key = CacheKey::new(route, qtype, name);
        let entry = CacheEntry {
            response: CachedResponse::new(stored),
            inserted_at: Instant::now(),
            ttl_secs: ttl,
        };
        self.entries.insert(key, entry);
        tracing::trace!(
            route = %route,
            qtype = ?qtype,
            domain = %name,
            ttl = ttl,
            "cache insert"
        );
    }

    /// Insert a negative cache entry (NXDOMAIN, SERVFAIL, etc.).
    /// Uses Fallback route for backward compatibility.
    pub fn insert_negative(&self, qtype: QType, name: &DomainName, message: &DnsMessage) {
        self.insert_negative_scoped(Route::Fallback, qtype, name, message);
    }

    /// Insert a negative cache entry scoped by route.
    pub fn insert_negative_scoped(
        &self,
        route: Route,
        qtype: QType,
        name: &DomainName,
        message: &DnsMessage,
    ) {
        let key = CacheKey::new(route, qtype, name);
        let entry = CacheEntry {
            response: CachedResponse::new(message.clone()),
            inserted_at: Instant::now(),
            ttl_secs: self.config.negative_ttl_secs,
        };
        self.entries.insert(key, entry);
        tracing::trace!(
            qtype = ?qtype,
            domain = %name,
            ttl = self.config.negative_ttl_secs,
            "negative cache insert"
        );
    }

    /// Get cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.stats.hits.load(Ordering::Relaxed),
            misses: self.stats.misses.load(Ordering::Relaxed),
            evictions: self.stats.evictions.load(Ordering::Relaxed),
            entries: self.entries.len(),
        }
    }

    /// Clear all cache entries.
    pub fn clear(&self) {
        self.entries.clear();
    }

    fn clamp_ttl(&self, ttl: u32) -> u32 {
        ttl.clamp(self.config.min_ttl_secs, self.config.max_ttl_secs)
    }

    fn evict_oldest(&self) {
        let mut oldest_key: Option<CacheKey> = None;
        let mut oldest_time = Instant::now();

        for entry in self.entries.iter() {
            if entry.inserted_at < oldest_time {
                oldest_time = entry.inserted_at;
                oldest_key = Some(*entry.key());
            }
        }

        if let Some(key) = oldest_key {
            self.entries.remove(&key);
            self.stats.record_eviction();
        }
    }
}

/// Extract the minimum TTL from all answer records in a DNS message.
fn extract_min_ttl(message: &DnsMessage) -> u32 {
    message.answers.iter().map(|rr| rr.ttl).min().unwrap_or(0)
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
