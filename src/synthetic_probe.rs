//! Synthetic health probes (issue #687).
//!
//! Synthetic probes provide early warning of service degradation even when
//! real user traffic is low or absent.  Rather than waiting for a genuine
//! request to fail, the monitoring workflow periodically issues artificial
//! "probes" against each anchor's well-known endpoints and records the result
//! as a health observation.
//!
//! # Probe types
//!
//! | Type | What is checked |
//! |------|----------------|
//! | `Ping` | Round-trip latency and basic connectivity to the anchor root URL |
//! | `StellarToml` | Fetch and parse `/.well-known/stellar.toml` |
//! | `Sep6Info` | Fetch the SEP-6 `/info` endpoint and check the response shape |
//! | `Custom` | Arbitrary operator-supplied label (e.g. a deep-health URL) |
//!
//! # Running probes
//!
//! [`SyntheticProbeRunner`] accepts a list of [`ProbeConfig`]s and a
//! `probe_fn` closure, executes them in order, and returns a
//! [`ProbeReport`] for each one.  The `probe_fn` is injected so the runner is
//! fully testable without a live network.
//!
//! # Integration with health scoring
//!
//! Probe results can be converted into [`HealthWindow`](crate::anchor_health::HealthWindow)
//! observations via [`probe_result_to_health_window`], feeding directly into
//! the existing composite health-scoring pipeline.
//!
//! # Example
//!
//! ```rust
//! use anchorkit::synthetic_probe::{
//!     ProbeConfig, ProbeKind, ProbeResult, SyntheticProbeRunner,
//! };
//!
//! let probes = alloc::vec![
//!     ProbeConfig::new(1, ProbeKind::Ping, "https://anchor.example.com").unwrap(),
//!     ProbeConfig::new(2, ProbeKind::StellarToml, "https://anchor.example.com/.well-known/stellar.toml").unwrap(),
//! ];
//!
//! let mut runner = SyntheticProbeRunner::new(probes);
//!
//! let reports = runner.run_all(
//!     |config| {
//!         // Simulate a successful probe.
//!         Ok(ProbeResult::success(config.id, 42))
//!     },
//!     || 1_000_000,
//! );
//!
//! assert_eq!(reports.len(), 2);
//! assert!(reports.iter().all(|r| r.result.is_ok()));
//! ```

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use crate::anchor_health::{HealthWindow, EndpointOutcome};
use crate::errors::AnchorKitError;

// ---------------------------------------------------------------------------
// ProbeKind
// ---------------------------------------------------------------------------

/// The type of synthetic probe to execute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// Basic connectivity and latency check against the anchor root URL.
    Ping,
    /// Fetch and validate `/.well-known/stellar.toml`.
    StellarToml,
    /// Fetch the SEP-6 `/info` endpoint and verify the response shape.
    Sep6Info,
    /// Fetch the SEP-24 `/info` endpoint and verify the response shape.
    Sep24Info,
    /// Operator-defined probe with a custom label.
    Custom(String),
}

impl ProbeKind {
    /// Human-readable label.
    pub fn label(&self) -> &str {
        match self {
            ProbeKind::Ping        => "ping",
            ProbeKind::StellarToml => "stellar_toml",
            ProbeKind::Sep6Info    => "sep6_info",
            ProbeKind::Sep24Info   => "sep24_info",
            ProbeKind::Custom(l)   => l.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeConfig
// ---------------------------------------------------------------------------

/// Configuration for one synthetic probe.
#[derive(Clone, Debug)]
pub struct ProbeConfig {
    /// Unique identifier for this probe (used to correlate results).
    pub id: u64,
    /// Kind of probe to execute.
    pub kind: ProbeKind,
    /// Target URL or identifier for this probe.
    pub target: String,
    /// Maximum allowed latency in milliseconds.
    /// A successful probe that exceeds this threshold is classified as a
    /// [`ProbeOutcome::SlowSuccess`] rather than a full success.
    pub latency_threshold_ms: u64,
}

impl ProbeConfig {
    /// Create a probe configuration with a default latency threshold of 2 000 ms.
    ///
    /// Returns `Err` if `target` is blank (empty or whitespace-only), using the
    /// same [`AnchorKitError::invalid_endpoint_format`] error returned by the
    /// shared domain validator so callers see a consistent error type.
    pub fn new(id: u64, kind: ProbeKind, target: impl Into<String>) -> Result<Self, AnchorKitError> {
        let target = target.into();
        if target.trim().is_empty() {
            return Err(AnchorKitError::invalid_endpoint_format());
        }
        Ok(ProbeConfig {
            id,
            kind,
            target,
            latency_threshold_ms: 2_000,
        })
    }

    /// Set the latency threshold (builder-style).
    pub fn with_latency_threshold(mut self, ms: u64) -> Self {
        self.latency_threshold_ms = ms;
        self
    }
}

// ---------------------------------------------------------------------------
// ProbeOutcome
// ---------------------------------------------------------------------------

/// Fine-grained outcome of a probe execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Probe succeeded within the latency threshold.
    Success,
    /// Probe succeeded but took longer than `latency_threshold_ms`.
    SlowSuccess,
    /// Probe failed (network error, unexpected response, timeout, etc.).
    Failure(String),
}

impl ProbeOutcome {
    /// Returns `true` for `Success` and `SlowSuccess`.
    pub fn is_ok(&self) -> bool {
        matches!(self, ProbeOutcome::Success | ProbeOutcome::SlowSuccess)
    }

    /// Convert to the coarser [`EndpointOutcome`] used by health scoring.
    pub fn to_endpoint_outcome(&self) -> EndpointOutcome {
        match self {
            ProbeOutcome::Success | ProbeOutcome::SlowSuccess => EndpointOutcome::Success,
            ProbeOutcome::Failure(r) => EndpointOutcome::Failure(r.clone()),
        }
    }
}

// ---------------------------------------------------------------------------
// ProbeResult
// ---------------------------------------------------------------------------

/// The measured result of executing one probe.
#[derive(Clone, Debug)]
pub struct ProbeResult {
    /// ID of the probe this result belongs to.
    pub probe_id: u64,
    /// Outcome of the probe.
    pub outcome: ProbeOutcome,
    /// Observed round-trip latency in milliseconds.
    pub latency_ms: u64,
}

impl ProbeResult {
    /// Convenience constructor for a successful probe.
    pub fn success(probe_id: u64, latency_ms: u64) -> Self {
        ProbeResult {
            probe_id,
            outcome: ProbeOutcome::Success,
            latency_ms,
        }
    }

    /// Convenience constructor for a failed probe.
    pub fn failure(probe_id: u64, latency_ms: u64, reason: impl Into<String>) -> Self {
        ProbeResult {
            probe_id,
            outcome: ProbeOutcome::Failure(reason.into()),
            latency_ms,
        }
    }

    /// Returns `true` for successful outcomes (including slow success).
    pub fn is_ok(&self) -> bool {
        self.outcome.is_ok()
    }
}

// ---------------------------------------------------------------------------
// ProbeReport
// ---------------------------------------------------------------------------

/// Combined configuration and result for one probe execution.
#[derive(Clone, Debug)]
pub struct ProbeReport {
    /// A copy of the probe configuration that was run.
    pub config: ProbeConfig,
    /// The measured result.
    pub result: ProbeResult,
    /// Unix timestamp (seconds) when the probe was executed.
    pub executed_at: u64,
}

impl ProbeReport {
    /// Apply the slow-success threshold: if the result was `Success` but
    /// `latency_ms > config.latency_threshold_ms`, reclassify as `SlowSuccess`.
    fn apply_latency_threshold(mut result: ProbeResult, config: &ProbeConfig) -> ProbeResult {
        if result.outcome == ProbeOutcome::Success
            && result.latency_ms > config.latency_threshold_ms
        {
            result.outcome = ProbeOutcome::SlowSuccess;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// SyntheticProbeRunner
// ---------------------------------------------------------------------------

/// Runs a set of synthetic probes and collects [`ProbeReport`]s.
///
/// The `probe_fn` closure is injected for testability: in production it makes
/// a real HTTP request; in tests it returns a canned result.
pub struct SyntheticProbeRunner {
    probes: Vec<ProbeConfig>,
}

impl SyntheticProbeRunner {
    /// Create a runner from a list of probe configurations.
    pub fn new(probes: Vec<ProbeConfig>) -> Self {
        SyntheticProbeRunner { probes }
    }

    /// Execute all probes using `probe_fn` and return one [`ProbeReport`] per probe.
    ///
    /// - `probe_fn`: given a reference to the [`ProbeConfig`], returns
    ///   `Ok(ProbeResult)` or `Err(String)`.  On error a failure result is
    ///   synthesised automatically.
    /// - `timestamp_fn`: called once per probe to record `executed_at`.
    ///
    /// Probes are run sequentially.
    pub fn run_all<F, T>(
        &self,
        mut probe_fn: F,
        timestamp_fn: T,
    ) -> Vec<ProbeReport>
    where
        F: FnMut(&ProbeConfig) -> Result<ProbeResult, String>,
        T: Fn() -> u64,
    {
        self.probes
            .iter()
            .map(|config| {
                let executed_at = timestamp_fn();
                let raw_result = probe_fn(config).unwrap_or_else(|err| {
                    ProbeResult::failure(config.id, 0, err)
                });
                let result = ProbeReport::apply_latency_threshold(raw_result, config);
                ProbeReport {
                    config: config.clone(),
                    result,
                    executed_at,
                }
            })
            .collect()
    }

    /// Execute only probes whose kind matches `kind_filter`.
    pub fn run_by_kind<F, T>(
        &self,
        kind_filter: &ProbeKind,
        mut probe_fn: F,
        timestamp_fn: T,
    ) -> Vec<ProbeReport>
    where
        F: FnMut(&ProbeConfig) -> Result<ProbeResult, String>,
        T: Fn() -> u64,
    {
        self.probes
            .iter()
            .filter(|c| &c.kind == kind_filter)
            .map(|config| {
                let executed_at = timestamp_fn();
                let raw_result = probe_fn(config).unwrap_or_else(|err| {
                    ProbeResult::failure(config.id, 0, err)
                });
                let result = ProbeReport::apply_latency_threshold(raw_result, config);
                ProbeReport {
                    config: config.clone(),
                    result,
                    executed_at,
                }
            })
            .collect()
    }

    /// Return a reference to the configured probes.
    pub fn probes(&self) -> &[ProbeConfig] {
        &self.probes
    }
}

// ---------------------------------------------------------------------------
// Health window integration
// ---------------------------------------------------------------------------

/// Convert a slice of [`ProbeReport`]s into a single [`HealthWindow`] that can
/// be fed directly into [`crate::anchor_health::score_window`].
///
/// The window's time bounds are derived from the earliest and latest
/// `executed_at` values in the slice.  Pass a non-empty slice; an empty slice
/// returns a zeroed window anchored at timestamp `0`.
///
/// Routing and recovery signals are not derived from probe reports (probes do
/// not carry that information) so `routing_attempt_count` is set to 0 and
/// `recovery_time_seconds` is left at 0.
pub fn probe_results_to_health_window(reports: &[ProbeReport]) -> HealthWindow {
    if reports.is_empty() {
        return HealthWindow {
            started_at: 0, ended_at: 0,
            success_count: 0, failure_count: 0,
            p50_latency_ms: 0.0,
            routing_failure_count: 0, routing_attempt_count: 0,
            recovery_time_seconds: 0,
        };
    }

    let started_at = reports.iter().map(|r| r.executed_at).min().unwrap_or(0);
    let ended_at   = reports.iter().map(|r| r.executed_at).max().unwrap_or(0);

    let success_count = reports.iter().filter(|r| r.result.is_ok()).count() as u64;
    let failure_count = reports.len() as u64 - success_count;

    // Compute the p50 latency over successful probes.
    let mut ok_latencies: Vec<u64> = reports
        .iter()
        .filter(|r| r.result.is_ok())
        .map(|r| r.result.latency_ms)
        .collect();
    ok_latencies.sort_unstable();
    let p50_latency_ms = if ok_latencies.is_empty() {
        0.0
    } else {
        ok_latencies[ok_latencies.len() / 2] as f64
    };

    HealthWindow {
        started_at,
        ended_at,
        success_count,
        failure_count,
        p50_latency_ms,
        routing_failure_count: 0,
        routing_attempt_count: 0,
        recovery_time_seconds: 0,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_probes() -> Vec<ProbeConfig> {
        alloc::vec![
            ProbeConfig::new(1, ProbeKind::Ping, "https://anchor.example.com").unwrap(),
            ProbeConfig::new(2, ProbeKind::StellarToml, "https://anchor.example.com/.well-known/stellar.toml").unwrap(),
            ProbeConfig::new(3, ProbeKind::Sep6Info, "https://anchor.example.com/sep6/info").unwrap(),
        ]
    }

    #[test]
    fn run_all_returns_one_report_per_probe() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 50)),
            || 1000,
        );
        assert_eq!(reports.len(), 3);
    }

    #[test]
    fn run_all_records_executed_at() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let mut ts = 1000u64;
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 50)),
            || { let t = ts; ts += 1; t },
        );
        assert_eq!(reports[0].executed_at, 1000);
        assert_eq!(reports[1].executed_at, 1001);
        assert_eq!(reports[2].executed_at, 1002);
    }

    #[test]
    fn probe_fn_error_produces_failure_report() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let reports = runner.run_all(
            |_| Err("connection refused".into()),
            || 1000,
        );
        assert!(reports.iter().all(|r| !r.result.is_ok()));
        assert!(matches!(reports[0].result.outcome, ProbeOutcome::Failure(_)));
    }

    #[test]
    fn latency_above_threshold_becomes_slow_success() {
        let probes = alloc::vec![
            ProbeConfig::new(1, ProbeKind::Ping, "https://anchor.example.com")
                .unwrap()
                .with_latency_threshold(100),
        ];
        let runner = SyntheticProbeRunner::new(probes);
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 999)),
            || 0,
        );
        assert_eq!(reports[0].result.outcome, ProbeOutcome::SlowSuccess);
    }

    #[test]
    fn latency_within_threshold_stays_success() {
        let probes = alloc::vec![
            ProbeConfig::new(1, ProbeKind::Ping, "https://anchor.example.com")
                .unwrap()
                .with_latency_threshold(1000),
        ];
        let runner = SyntheticProbeRunner::new(probes);
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 500)),
            || 0,
        );
        assert_eq!(reports[0].result.outcome, ProbeOutcome::Success);
    }

    #[test]
    fn run_by_kind_filters_correctly() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let reports = runner.run_by_kind(
            &ProbeKind::Ping,
            |c| Ok(ProbeResult::success(c.id, 10)),
            || 0,
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].config.kind, ProbeKind::Ping);
    }

    #[test]
    fn run_by_kind_returns_empty_when_no_match() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let reports = runner.run_by_kind(
            &ProbeKind::Sep24Info,
            |c| Ok(ProbeResult::success(c.id, 10)),
            || 0,
        );
        assert!(reports.is_empty());
    }

    #[test]
    fn probe_result_is_ok_for_slow_success() {
        let r = ProbeResult {
            probe_id: 1,
            outcome: ProbeOutcome::SlowSuccess,
            latency_ms: 3000,
        };
        assert!(r.is_ok());
    }

    #[test]
    fn probe_result_is_not_ok_for_failure() {
        let r = ProbeResult::failure(1, 0, "timeout");
        assert!(!r.is_ok());
    }

    // ── probe_results_to_health_window ───────────────────────────────────────

    #[test]
    fn empty_reports_yield_zeroed_window() {
        let w = probe_results_to_health_window(&[]);
        assert_eq!(w.success_count, 0);
        assert_eq!(w.failure_count, 0);
        assert_eq!(w.p50_latency_ms, 0.0);
    }

    #[test]
    fn all_success_window_has_correct_counts() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 100)),
            || 5000,
        );
        let w = probe_results_to_health_window(&reports);
        assert_eq!(w.success_count, 3);
        assert_eq!(w.failure_count, 0);
        assert!((w.p50_latency_ms - 100.0).abs() < 1e-9);
    }

    #[test]
    fn mixed_results_window_counts_failures() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let mut call = 0usize;
        let reports = runner.run_all(
            |c| {
                call += 1;
                if call == 2 {
                    Err("timeout".into())
                } else {
                    Ok(ProbeResult::success(c.id, 200))
                }
            },
            || 1000,
        );
        let w = probe_results_to_health_window(&reports);
        assert_eq!(w.success_count, 2);
        assert_eq!(w.failure_count, 1);
    }

    #[test]
    fn window_timestamps_span_probe_execution_times() {
        let runner = SyntheticProbeRunner::new(make_probes());
        let ts_values = alloc::vec![1000u64, 1005, 1010];
        let mut ts_idx = 0usize;
        let reports = runner.run_all(
            |c| Ok(ProbeResult::success(c.id, 50)),
            || { let t = ts_values[ts_idx]; ts_idx += 1; t },
        );
        let w = probe_results_to_health_window(&reports);
        assert_eq!(w.started_at, 1000);
        assert_eq!(w.ended_at, 1010);
    }

    #[test]
    fn p50_is_median_of_successful_latencies() {
        let probes = alloc::vec![
            ProbeConfig::new(1, ProbeKind::Ping, "a").unwrap(),
            ProbeConfig::new(2, ProbeKind::Ping, "b").unwrap(),
            ProbeConfig::new(3, ProbeKind::Ping, "c").unwrap(),
        ];
        let latencies = [300u64, 100, 500];
        let mut idx = 0usize;
        let runner = SyntheticProbeRunner::new(probes);
        let reports = runner.run_all(
            |c| { let l = latencies[idx]; idx += 1; Ok(ProbeResult::success(c.id, l)) },
            || 0,
        );
        let w = probe_results_to_health_window(&reports);
        // sorted: [100, 300, 500] → median index 1 → 300
        assert!((w.p50_latency_ms - 300.0).abs() < 1e-9);
    }

    #[test]
    fn custom_probe_kind_label() {
        let kind = ProbeKind::Custom("deep-health-v2".into());
        assert_eq!(kind.label(), "deep-health-v2");
    }

    #[test]
    fn probe_outcome_to_endpoint_outcome_slow_success_is_success() {
        let o = ProbeOutcome::SlowSuccess;
        assert_eq!(o.to_endpoint_outcome(), EndpointOutcome::Success);
    }

    #[test]
    fn probe_outcome_to_endpoint_outcome_failure_carries_reason() {
        let o = ProbeOutcome::Failure("HTTP 503".into());
        assert!(matches!(o.to_endpoint_outcome(), EndpointOutcome::Failure(_)));
    }

    // ── ProbeConfig::new blank-URL guard (#821) ──────────────────────────────

    #[test]
    fn new_rejects_empty_target() {
        assert!(ProbeConfig::new(1, ProbeKind::Ping, "").is_err());
    }

    #[test]
    fn new_rejects_whitespace_only_target() {
        assert!(ProbeConfig::new(1, ProbeKind::Ping, "   ").is_err());
    }

    #[test]
    fn new_accepts_valid_https_endpoint() {
        assert!(ProbeConfig::new(1, ProbeKind::Ping, "https://anchor.example.com").is_ok());
    }
}
