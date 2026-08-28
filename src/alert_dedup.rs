//! Alert deduplication and suppression (issue #686).
//!
//! Repeated failures can generate alert storms where the same condition fires
//! dozens of times before an operator responds.  This module provides:
//!
//! - [`AlertDeduplicator`] — tracks recently fired alerts by a fingerprint key
//!   and suppresses duplicates within a configurable time window.
//! - [`AlertSuppressor`] — allows operators to explicitly silence an alert
//!   fingerprint for a fixed duration (e.g. during a planned maintenance window).
//! - [`DedupConfig`] — controls the deduplication window and maximum tracked keys.
//!
//! Both structures use interior mutability (`RefCell`) so they can be threaded
//! through `&self` closures, mirroring the pattern used by `MetricsRegistry`
//! and `StructuredLogger`.
//!
//! # Fingerprinting
//!
//! The caller is responsible for choosing the fingerprint key.  A good key
//! uniquely identifies the *condition*, not each individual event.  For
//! example:
//!
//! ```text
//! "anchor:example.com:health:critical"
//! "contract:attestor_replay:GADDR..."
//! ```
//!
//! # Example
//!
//! ```rust
//! use anchorkit::alert_dedup::{AlertDeduplicator, DedupConfig};
//!
//! let dedup = AlertDeduplicator::new(DedupConfig { window_seconds: 300, max_keys: 1000 });
//!
//! // First occurrence fires.
//! assert!(dedup.should_fire("anchor:example.com:critical", 1_000));
//!
//! // Same fingerprint within the window is suppressed.
//! assert!(!dedup.should_fire("anchor:example.com:critical", 1_100));
//!
//! // After the window expires the alert fires again.
//! assert!(dedup.should_fire("anchor:example.com:critical", 1_000 + 300 + 1));
//! ```

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::cell::RefCell;

// ---------------------------------------------------------------------------
// DedupConfig
// ---------------------------------------------------------------------------

/// Configuration for [`AlertDeduplicator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DedupConfig {
    /// How long (in seconds) to suppress duplicate alerts after one fires.
    /// Setting this to `0` disables deduplication (every event fires).
    pub window_seconds: u64,
    /// Maximum number of fingerprint keys tracked simultaneously.
    /// When the map is full the oldest entry is evicted before inserting a new
    /// one, so memory stays bounded.  Set to `0` for unlimited (use with care).
    pub max_keys: usize,
}

impl Default for DedupConfig {
    fn default() -> Self {
        DedupConfig {
            window_seconds: 300, // 5 minutes
            max_keys: 10_000,
        }
    }
}

// ---------------------------------------------------------------------------
// AlertDeduplicator
// ---------------------------------------------------------------------------

/// Suppresses duplicate alerts that fire within a rolling time window.
///
/// For each fingerprint key, the deduplicator records the Unix timestamp (in
/// seconds) of the last fired alert.  A subsequent alert with the same key is
/// suppressed unless `now - last_fired >= window_seconds`.
#[derive(Debug, Default)]
pub struct AlertDeduplicator {
    config: DedupConfig,
    /// Maps fingerprint → Unix timestamp (seconds) of last fired alert.
    last_fired: RefCell<BTreeMap<String, u64>>,
}

impl AlertDeduplicator {
    /// Create a deduplicator with the given configuration.
    pub fn new(config: DedupConfig) -> Self {
        AlertDeduplicator {
            config,
            last_fired: RefCell::new(BTreeMap::new()),
        }
    }

    /// Decide whether an alert with `fingerprint` should fire at `now`.
    ///
    /// Returns `true` and records `now` as the last-fired timestamp when the
    /// alert should be delivered.  Returns `false` (and leaves the timestamp
    /// unchanged) when the alert is within its suppression window.
    ///
    /// When `window_seconds` is `0` every call returns `true`.
    pub fn should_fire(&self, fingerprint: &str, now: u64) -> bool {
        if self.config.window_seconds == 0 {
            return true;
        }

        let mut map = self.last_fired.borrow_mut();

        if let Some(&last) = map.get(fingerprint) {
            if now.saturating_sub(last) < self.config.window_seconds {
                return false; // still within suppression window
            }
        }

        // Evict oldest entry when at capacity (before inserting).
        if self.config.max_keys > 0 && map.len() >= self.config.max_keys {
            if let Some(oldest_key) = map.keys().next().cloned() {
                map.remove(&oldest_key);
            }
        }

        map.insert(fingerprint.into(), now);
        true
    }

    /// Forcibly clear the suppression record for `fingerprint`, allowing the
    /// next occurrence to fire regardless of the window.
    pub fn reset(&self, fingerprint: &str) {
        self.last_fired.borrow_mut().remove(fingerprint);
    }

    /// Clear all tracked fingerprints.
    pub fn reset_all(&self) {
        self.last_fired.borrow_mut().clear();
    }

    /// Return the last-fired timestamp for `fingerprint`, if any.
    pub fn last_fired_at(&self, fingerprint: &str) -> Option<u64> {
        self.last_fired.borrow().get(fingerprint).copied()
    }

    /// Number of fingerprints currently tracked.
    pub fn tracked_count(&self) -> usize {
        self.last_fired.borrow().len()
    }

    /// Reference to the active configuration.
    pub fn config(&self) -> &DedupConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// SuppressedEntry
// ---------------------------------------------------------------------------

/// One entry in the manual suppression list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuppressedEntry {
    /// The fingerprint pattern being suppressed.  Exact-string match only.
    pub fingerprint: String,
    /// Unix timestamp (seconds) when the suppression expires.
    pub expires_at: u64,
    /// Optional human-readable reason for the suppression.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// AlertSuppressor
// ---------------------------------------------------------------------------

/// Explicit, time-bounded suppression list.
///
/// Operators can suppress specific alert fingerprints for a fixed duration
/// (e.g. during planned maintenance).  Unlike [`AlertDeduplicator`], which
/// auto-suppresses based on recency, [`AlertSuppressor`] fires only when an
/// entry has been explicitly added.
#[derive(Debug, Default)]
pub struct AlertSuppressor {
    /// Active suppression entries, keyed by fingerprint.
    entries: RefCell<BTreeMap<String, SuppressedEntry>>,
}

impl AlertSuppressor {
    /// Create an empty suppressor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Suppress alerts matching `fingerprint` until `expires_at` (Unix seconds).
    ///
    /// If an entry already exists for the fingerprint it is overwritten so the
    /// operator can extend or shorten an active suppression.
    pub fn suppress(
        &self,
        fingerprint: impl Into<String>,
        expires_at: u64,
        reason: impl Into<String>,
    ) {
        let key: String = fingerprint.into();
        self.entries.borrow_mut().insert(
            key.clone(),
            SuppressedEntry {
                fingerprint: key,
                expires_at,
                reason: reason.into(),
            },
        );
    }

    /// Returns `true` when `fingerprint` is actively suppressed at time `now`.
    ///
    /// Expired entries are removed lazily on access.
    pub fn is_suppressed(&self, fingerprint: &str, now: u64) -> bool {
        let mut entries = self.entries.borrow_mut();
        match entries.get(fingerprint) {
            None => false,
            Some(entry) if entry.expires_at <= now => {
                // Expired — remove lazily and report not suppressed.
                let key = entry.fingerprint.clone();
                entries.remove(&key);
                false
            }
            Some(_) => true,
        }
    }

    /// Lift the suppression for `fingerprint` immediately.
    pub fn unsuppress(&self, fingerprint: &str) {
        self.entries.borrow_mut().remove(fingerprint);
    }

    /// Remove all suppression entries that have already expired at `now`.
    pub fn purge_expired(&self, now: u64) {
        let mut entries = self.entries.borrow_mut();
        entries.retain(|_, e| e.expires_at > now);
    }

    /// Number of active (not-yet-expired) suppression entries at `now`.
    pub fn active_count(&self, now: u64) -> usize {
        self.entries
            .borrow()
            .values()
            .filter(|e| e.expires_at > now)
            .count()
    }

    /// Return a snapshot of all current suppression entries (including expired).
    pub fn entries(&self) -> alloc::vec::Vec<SuppressedEntry> {
        self.entries.borrow().values().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// AlertFilter — combines deduplication and suppression
// ---------------------------------------------------------------------------

/// Convenience wrapper that applies both deduplication and explicit suppression
/// in a single `should_deliver` call.
///
/// An alert is delivered only when:
/// 1. It is **not** covered by an active [`AlertSuppressor`] entry, **and**
/// 2. It is **not** within the [`AlertDeduplicator`]'s suppression window.
pub struct AlertFilter {
    dedup: AlertDeduplicator,
    suppressor: AlertSuppressor,
}

impl AlertFilter {
    /// Create a filter with the given deduplication config and an empty
    /// suppression list.
    pub fn new(dedup_config: DedupConfig) -> Self {
        AlertFilter {
            dedup: AlertDeduplicator::new(dedup_config),
            suppressor: AlertSuppressor::new(),
        }
    }

    /// Returns `true` when the alert should be delivered.
    pub fn should_deliver(&self, fingerprint: &str, now: u64) -> bool {
        if self.suppressor.is_suppressed(fingerprint, now) {
            return false;
        }
        self.dedup.should_fire(fingerprint, now)
    }

    /// Access the underlying suppressor to add or lift suppressions.
    pub fn suppressor(&self) -> &AlertSuppressor {
        &self.suppressor
    }

    /// Access the underlying deduplicator to inspect state.
    pub fn dedup(&self) -> &AlertDeduplicator {
        &self.dedup
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── AlertDeduplicator ────────────────────────────────────────────────────

    #[test]
    fn first_occurrence_fires() {
        let d = AlertDeduplicator::new(DedupConfig::default());
        assert!(d.should_fire("k1", 1000));
    }

    #[test]
    fn second_occurrence_within_window_is_suppressed() {
        let d = AlertDeduplicator::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        d.should_fire("k1", 1000);
        assert!(!d.should_fire("k1", 1100));
    }

    #[test]
    fn occurrence_after_window_fires_again() {
        let d = AlertDeduplicator::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        d.should_fire("k1", 1000);
        assert!(d.should_fire("k1", 1000 + 300 + 1));
    }

    #[test]
    fn alert_fires_exactly_at_ttl_boundary() {
        let d = AlertDeduplicator::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        d.should_fire("k1", 1000);
        // now - last == window_seconds → expired, fires (inclusive boundary).
        assert!(d.should_fire("k1", 1000 + 300));
        // Just before boundary remains suppressed.
        let d2 = AlertDeduplicator::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        d2.should_fire("k1", 1000);
        assert!(!d2.should_fire("k1", 1000 + 299));
    }

    #[test]
    fn different_fingerprints_are_independent() {
        let d = AlertDeduplicator::new(DedupConfig::default());
        d.should_fire("k1", 1000);
        assert!(d.should_fire("k2", 1001));
    }

    #[test]
    fn window_zero_disables_dedup() {
        let d = AlertDeduplicator::new(DedupConfig { window_seconds: 0, max_keys: 100 });
        d.should_fire("k1", 1000);
        assert!(d.should_fire("k1", 1001));
    }

    #[test]
    fn reset_clears_suppression() {
        let d = AlertDeduplicator::new(DedupConfig::default());
        d.should_fire("k1", 1000);
        d.reset("k1");
        assert!(d.should_fire("k1", 1001));
    }

    #[test]
    fn max_keys_evicts_oldest() {
        let d = AlertDeduplicator::new(DedupConfig { window_seconds: 9999, max_keys: 2 });
        d.should_fire("a", 1000);
        d.should_fire("b", 1001);
        // Adding "c" should evict "a" (alphabetically first in BTreeMap)
        d.should_fire("c", 1002);
        assert_eq!(d.tracked_count(), 2);
        // "a" was evicted; it should fire again
        assert!(d.should_fire("a", 1003));
    }

    #[test]
    fn last_fired_at_returns_correct_timestamp() {
        let d = AlertDeduplicator::new(DedupConfig::default());
        d.should_fire("k1", 5000);
        assert_eq!(d.last_fired_at("k1"), Some(5000));
        assert_eq!(d.last_fired_at("missing"), None);
    }

    // ── AlertSuppressor ──────────────────────────────────────────────────────

    #[test]
    fn suppressed_fingerprint_is_active() {
        let s = AlertSuppressor::new();
        s.suppress("maint:anchor.com", 2000, "planned maintenance");
        assert!(s.is_suppressed("maint:anchor.com", 1000));
    }

    #[test]
    fn expired_suppression_is_not_active() {
        let s = AlertSuppressor::new();
        s.suppress("maint:anchor.com", 1500, "window ended");
        assert!(!s.is_suppressed("maint:anchor.com", 2000));
    }

    #[test]
    fn unsuppress_lifts_immediately() {
        let s = AlertSuppressor::new();
        s.suppress("k", 9999, "test");
        s.unsuppress("k");
        assert!(!s.is_suppressed("k", 1000));
    }

    #[test]
    fn purge_expired_removes_stale_entries() {
        let s = AlertSuppressor::new();
        s.suppress("old", 100, "expired");
        s.suppress("current", 9999, "active");
        s.purge_expired(500);
        assert_eq!(s.active_count(500), 1);
    }

    #[test]
    fn active_count_excludes_expired() {
        let s = AlertSuppressor::new();
        s.suppress("a", 100, "expired");
        s.suppress("b", 9999, "active");
        assert_eq!(s.active_count(500), 1);
    }

    #[test]
    fn overwriting_suppression_extends_expiry() {
        let s = AlertSuppressor::new();
        s.suppress("k", 1500, "short window");
        s.suppress("k", 9999, "extended");
        assert!(s.is_suppressed("k", 5000));
    }

    // ── AlertFilter ──────────────────────────────────────────────────────────

    #[test]
    fn filter_delivers_first_occurrence() {
        let f = AlertFilter::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        assert!(f.should_deliver("critical:anchor.com", 1000));
    }

    #[test]
    fn filter_deduplicates_rapid_repeats() {
        let f = AlertFilter::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        f.should_deliver("critical:anchor.com", 1000);
        assert!(!f.should_deliver("critical:anchor.com", 1001));
    }

    #[test]
    fn filter_respects_manual_suppression() {
        let f = AlertFilter::new(DedupConfig { window_seconds: 300, max_keys: 100 });
        f.suppressor().suppress("maint:anchor.com", 9999, "maintenance");
        // Would fire on first occurrence via dedup alone, but suppressor blocks it.
        assert!(!f.should_deliver("maint:anchor.com", 1000));
    }

    #[test]
    fn filter_delivers_after_suppression_expires() {
        let f = AlertFilter::new(DedupConfig { window_seconds: 60, max_keys: 100 });
        f.suppressor().suppress("k", 1500, "short maintenance");
        // Suppressed within window.
        assert!(!f.should_deliver("k", 1000));
        // Suppression expired and dedup window also passed → fires.
        assert!(f.should_deliver("k", 2000));
    }
}
