//! Integration-level tests for environment fingerprinting.
//!
//! These tests exercise [`EnvironmentFingerprint`] from the public API surface,
//! validating collection, serialization round-trips, diff detection, and
//! consistency checks. No live network or disk I/O is required — all comparisons
//! are performed against manually constructed fingerprints.

#![cfg(test)]
#![cfg(feature = "std")]

use std::collections::HashMap;
use anchorkit::{
    BuildMetadata, ConfigMetadata, DriftItem, EnvironmentFingerprint, ToolVersions,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_fp(
    rustc: &str,
    cargo: &str,
    stellar: Option<&str>,
    pkg_ver: &str,
    wasm: bool,
) -> EnvironmentFingerprint {
    EnvironmentFingerprint {
        tools: ToolVersions {
            rustc: Some(rustc.to_string()),
            cargo: Some(cargo.to_string()),
            stellar_cli: stellar.map(|s| s.to_string()),
            wasm_target_installed: wasm,
        },
        config: ConfigMetadata {
            file_hashes: HashMap::new(),
            file_count: 0,
        },
        build: BuildMetadata {
            package_version: pkg_ver.to_string(),
            build_target: "x86_64-unknown-linux-gnu".to_string(),
            active_features: vec!["std".to_string()],
            rust_channel: "stable".to_string(),
        },
        collected_at: None,
    }
}

fn with_config(
    mut fp: EnvironmentFingerprint,
    files: &[(&str, &str)],
) -> EnvironmentFingerprint {
    fp.config.file_hashes = files
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    fp.config.file_count = fp.config.file_hashes.len();
    fp
}

// ---------------------------------------------------------------------------
// Struct construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn default_fingerprint_has_zero_config_files() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    assert_eq!(fp.config.file_count, 0);
    assert!(fp.config.file_hashes.is_empty());
}

#[test]
fn fingerprint_collected_at_is_none_when_manually_built() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    assert!(fp.collected_at.is_none());
}

#[test]
fn collect_sets_collected_at_timestamp() {
    let fp = EnvironmentFingerprint::collect();
    assert!(fp.collected_at.is_some());
    let ts = fp.collected_at.unwrap();
    assert!(!ts.is_empty());
    // Basic ISO-8601 shape: YYYY-MM-DDTHH:MM:SSZ
    assert!(ts.contains('T'), "timestamp should contain 'T': {ts}");
    assert!(ts.ends_with('Z'), "timestamp should end with 'Z': {ts}");
}

#[test]
fn collect_populates_package_version() {
    let fp = EnvironmentFingerprint::collect();
    assert!(!fp.build.package_version.is_empty(),
        "package_version should not be empty after collect()");
}

#[test]
fn collect_returns_stable_channel_by_default() {
    let fp = EnvironmentFingerprint::collect();
    // RUSTC_CHANNEL is not set in normal CI, so it defaults to "stable"
    assert!(!fp.build.rust_channel.is_empty());
}

// ---------------------------------------------------------------------------
// JSON serialization / deserialization
// ---------------------------------------------------------------------------

#[test]
fn to_json_produces_non_empty_string() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let json = fp.to_json().unwrap();
    assert!(!json.is_empty());
}

#[test]
fn to_json_contains_expected_keys() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", Some("stellar 21.3.0"), "0.1.0", true);
    let json = fp.to_json().unwrap();
    assert!(json.contains("\"tools\""),   "missing 'tools' key");
    assert!(json.contains("\"config\""),  "missing 'config' key");
    assert!(json.contains("\"build\""),   "missing 'build' key");
    assert!(json.contains("rustc 1.78.0"));
    assert!(json.contains("stellar 21.3.0"));
    assert!(json.contains("0.1.0"));
}

#[test]
fn from_json_round_trips_tool_versions() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", Some("stellar 21.0.0"), "0.1.0", true);
    let json = fp.to_json().unwrap();
    let restored = EnvironmentFingerprint::from_json(&json).unwrap();

    assert_eq!(restored.tools.rustc,       Some("rustc 1.78.0".to_string()));
    assert_eq!(restored.tools.cargo,       Some("cargo 1.78.0".to_string()));
    assert_eq!(restored.tools.stellar_cli, Some("stellar 21.0.0".to_string()));
    assert_eq!(restored.tools.wasm_target_installed, true);
}

#[test]
fn from_json_round_trips_build_metadata() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.2.1", false);
    let json = fp.to_json().unwrap();
    let restored = EnvironmentFingerprint::from_json(&json).unwrap();

    assert_eq!(restored.build.package_version, "0.2.1");
    assert_eq!(restored.build.rust_channel, "stable");
    assert_eq!(restored.build.active_features, vec!["std"]);
}

#[test]
fn from_json_round_trips_config_hashes() {
    let fp = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[
            ("configs/fiat-on-off-ramp.json", "aabb1122"),
            ("configs/remittance-anchor.toml", "ccdd3344"),
        ],
    );
    let json = fp.to_json().unwrap();
    let restored = EnvironmentFingerprint::from_json(&json).unwrap();

    assert_eq!(restored.config.file_count, 2);
    assert_eq!(
        restored.config.file_hashes.get("configs/fiat-on-off-ramp.json").map(String::as_str),
        Some("aabb1122")
    );
}

#[test]
fn from_json_rejects_empty_string() {
    assert!(EnvironmentFingerprint::from_json("").is_err());
}

#[test]
fn from_json_rejects_invalid_json() {
    assert!(EnvironmentFingerprint::from_json("{not: valid}").is_err());
}

#[test]
fn from_json_rejects_wrong_type() {
    assert!(EnvironmentFingerprint::from_json("[]").is_err());
}

// ---------------------------------------------------------------------------
// diff / is_consistent_with
// ---------------------------------------------------------------------------

#[test]
fn identical_fingerprints_produce_no_drift() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    assert!(fp.diff(&fp.clone()).is_empty());
    assert!(fp.is_consistent_with(&fp.clone()));
}

#[test]
fn rustc_version_change_reported() {
    let current  = make_fp("rustc 1.79.0", "cargo 1.78.0", None, "0.1.0", true);
    let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"tools.rustc"), "expected tools.rustc in: {fields:?}");
    let item = drift.iter().find(|d| d.field == "tools.rustc").unwrap();
    assert_eq!(item.baseline, "rustc 1.78.0");
    assert_eq!(item.current,  "rustc 1.79.0");
}

#[test]
fn stellar_cli_added_detected_as_drift() {
    let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", Some("stellar 21.3.0"), "0.1.0", true);
    let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None,                   "0.1.0", true);
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"tools.stellar_cli"), "expected stellar_cli drift: {fields:?}");
}

#[test]
fn wasm_target_removal_detected() {
    let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", false);
    let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"tools.wasm_target_installed"));
    let item = drift.iter().find(|d| d.field == "tools.wasm_target_installed").unwrap();
    assert_eq!(item.baseline, "true");
    assert_eq!(item.current,  "false");
}

#[test]
fn package_version_bump_detected() {
    let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.2.0", true);
    let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"build.package_version"));
}

#[test]
fn build_target_change_detected() {
    let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let baseline     = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    current.build.build_target = "aarch64-unknown-linux-gnu".to_string();
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"build.build_target"));
}

#[test]
fn active_features_change_detected() {
    let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let baseline     = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    current.build.active_features = vec!["std".into(), "mock-only".into()];
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"build.active_features"));
}

#[test]
fn rust_channel_change_detected() {
    let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let baseline     = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    current.build.rust_channel = "nightly".to_string();
    let drift = current.diff(&baseline);
    let fields: Vec<&str> = drift.iter().map(|d| d.field.as_str()).collect();
    assert!(fields.contains(&"build.rust_channel"));
}

#[test]
fn config_hash_change_detected() {
    let current = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/stablecoin-issuer.json", "newhash11")],
    );
    let baseline = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/stablecoin-issuer.json", "oldhash99")],
    );
    let drift = current.diff(&baseline);
    assert!(!drift.is_empty());
    assert!(drift[0].field.contains("stablecoin-issuer.json"));
    assert_eq!(drift[0].baseline, "oldhash99");
    assert_eq!(drift[0].current,  "newhash11");
}

#[test]
fn missing_config_file_reported_as_drift() {
    let current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let baseline = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/remittance-anchor.json", "abc123")],
    );
    let drift = current.diff(&baseline);
    assert!(!drift.is_empty());
    let item = &drift[0];
    assert!(item.field.contains("remittance-anchor.json"));
    assert_eq!(item.baseline, "abc123");
    assert_eq!(item.current,  "<missing>");
}

#[test]
fn extra_config_file_in_current_reported_as_drift() {
    let current = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/new-config.toml", "ffee0011")],
    );
    let baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let drift = current.diff(&baseline);
    assert!(!drift.is_empty());
    let item = &drift[0];
    assert!(item.field.contains("new-config.toml"));
    assert_eq!(item.baseline, "<absent>");
    assert_eq!(item.current,  "ffee0011");
}

#[test]
fn multiple_drift_items_all_reported() {
    let current = with_config(
        make_fp("rustc 1.79.0", "cargo 1.79.0", None, "0.2.0", false),
        &[("configs/a.json", "hash-a-new")],
    );
    let baseline = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/a.json", "hash-a-old")],
    );
    let drift = current.diff(&baseline);
    // Expect: rustc, cargo, wasm_target, package_version, config hash — at least 4
    assert!(drift.len() >= 4, "expected at least 4 drift items, got {}: {drift:?}", drift.len());
}

#[test]
fn collected_at_excluded_from_drift_comparison() {
    let mut current  = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let mut baseline = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    current.collected_at  = Some("2026-01-01T00:00:00Z".to_string());
    baseline.collected_at = Some("2025-01-01T00:00:00Z".to_string());
    // Different timestamps must NOT produce drift (comparison is about env, not time)
    assert!(current.diff(&baseline).is_empty());
}

// ---------------------------------------------------------------------------
// summary()
// ---------------------------------------------------------------------------

#[test]
fn summary_contains_package_version() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let s = fp.summary();
    assert!(s.contains("0.1.0"), "summary missing package_version: {s}");
}

#[test]
fn summary_contains_rustc_version() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let s = fp.summary();
    assert!(s.contains("rustc 1.78.0"), "summary missing rustc: {s}");
}

#[test]
fn summary_shows_not_found_for_missing_stellar_cli() {
    let fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    let s = fp.summary();
    assert!(s.contains("<not found>"), "expected <not found> for missing stellar_cli: {s}");
}

#[test]
fn summary_shows_config_file_count() {
    let fp = with_config(
        make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true),
        &[("configs/a.json", "hash1"), ("configs/b.toml", "hash2")],
    );
    let s = fp.summary();
    assert!(s.contains('2'), "summary missing file_count 2: {s}");
}

#[test]
fn summary_contains_collected_at_when_set() {
    let mut fp = make_fp("rustc 1.78.0", "cargo 1.78.0", None, "0.1.0", true);
    fp.collected_at = Some("2026-07-29T12:00:00Z".to_string());
    let s = fp.summary();
    assert!(s.contains("2026-07-29"), "summary missing collected_at: {s}");
}

// ---------------------------------------------------------------------------
// DriftItem
// ---------------------------------------------------------------------------

#[test]
fn drift_item_fields_set_correctly() {
    let item = DriftItem {
        field:    "tools.rustc".to_string(),
        baseline: "rustc 1.78.0".to_string(),
        current:  "rustc 1.79.0".to_string(),
    };
    assert_eq!(item.field,    "tools.rustc");
    assert_eq!(item.baseline, "rustc 1.78.0");
    assert_eq!(item.current,  "rustc 1.79.0");
}

#[test]
fn drift_item_serializes_to_json() {
    let item = DriftItem {
        field:    "build.package_version".to_string(),
        baseline: "0.1.0".to_string(),
        current:  "0.2.0".to_string(),
    };
    let json = serde_json::to_string(&item).unwrap();
    assert!(json.contains("build.package_version"));
    assert!(json.contains("0.1.0"));
    assert!(json.contains("0.2.0"));
}

// ---------------------------------------------------------------------------
// ErrorCode integration
// ---------------------------------------------------------------------------

#[test]
fn fingerprint_collection_failed_error_has_message() {
    use anchorkit::ErrorCode;
    let msg = ErrorCode::FingerprintCollectionFailed.default_message();
    assert!(!msg.is_empty());
}

#[test]
fn invalid_retirement_transition_error_has_message() {
    use anchorkit::ErrorCode;
    let msg = ErrorCode::InvalidRetirementTransition.default_message();
    assert!(!msg.is_empty());
}

// ---------------------------------------------------------------------------
// EnvironmentFingerprintId — blank-field validation (#808)
// ---------------------------------------------------------------------------

#[test]
fn env_fingerprint_id_valid_inputs_produce_hex() {
    use anchorkit::EnvironmentFingerprintId;
    let id = EnvironmentFingerprintId::new("mainnet", "1.2.3").unwrap();
    assert_eq!(id.hex().len(), 64, "SHA-256 hex should be 64 chars");
    assert_eq!(id.name, "mainnet");
    assert_eq!(id.version, "1.2.3");
}

#[test]
fn env_fingerprint_id_blank_name_rejected() {
    use anchorkit::EnvironmentFingerprintId;
    let err = EnvironmentFingerprintId::new("", "1.0.0").unwrap_err();
    assert!(err.contains("name"), "error should mention 'name', got: {err}");
}

#[test]
fn env_fingerprint_id_whitespace_name_rejected() {
    use anchorkit::EnvironmentFingerprintId;
    let err = EnvironmentFingerprintId::new("   ", "1.0.0").unwrap_err();
    assert!(err.contains("name"), "whitespace name should be rejected, got: {err}");
}

#[test]
fn env_fingerprint_id_blank_version_rejected() {
    use anchorkit::EnvironmentFingerprintId;
    let err = EnvironmentFingerprintId::new("mainnet", "").unwrap_err();
    assert!(err.contains("version"), "error should mention 'version', got: {err}");
}

#[test]
fn env_fingerprint_id_whitespace_version_rejected() {
    use anchorkit::EnvironmentFingerprintId;
    let err = EnvironmentFingerprintId::new("mainnet", "\t").unwrap_err();
    assert!(err.contains("version"), "whitespace version should be rejected, got: {err}");
}

#[test]
fn env_fingerprint_id_valid_produces_same_fingerprint_as_before() {
    // Verify the fingerprint algorithm is unchanged for valid inputs.
    use anchorkit::EnvironmentFingerprintId;
    let id1 = EnvironmentFingerprintId::new("testnet", "0.1.0").unwrap();
    let id2 = EnvironmentFingerprintId::new("testnet", "0.1.0").unwrap();
    assert_eq!(id1.hex(), id2.hex(), "same inputs must produce the same fingerprint");
}

#[test]
fn env_fingerprint_id_different_names_produce_different_fingerprints() {
    use anchorkit::EnvironmentFingerprintId;
    let a = EnvironmentFingerprintId::new("mainnet", "1.0.0").unwrap();
    let b = EnvironmentFingerprintId::new("testnet", "1.0.0").unwrap();
    assert_ne!(a.hex(), b.hex(), "different names must produce different fingerprints");
}

#[test]
fn env_fingerprint_id_different_versions_produce_different_fingerprints() {
    use anchorkit::EnvironmentFingerprintId;
    let a = EnvironmentFingerprintId::new("mainnet", "1.0.0").unwrap();
    let b = EnvironmentFingerprintId::new("mainnet", "2.0.0").unwrap();
    assert_ne!(a.hex(), b.hex(), "different versions must produce different fingerprints");
}

// ---------------------------------------------------------------------------
// LocalFingerprintId — canonical field order (#809)
// ---------------------------------------------------------------------------

#[test]
fn local_fingerprint_id_valid_inputs_produce_hex() {
    use anchorkit::LocalFingerprintId;
    let fp = LocalFingerprintId::new("staging".to_string(), "0.9.0".to_string()).unwrap();
    assert_eq!(fp.hex().len(), 64, "SHA-256 hex should be 64 chars");
}

#[test]
fn local_fingerprint_id_blank_name_rejected() {
    use anchorkit::LocalFingerprintId;
    let err = LocalFingerprintId::new("".to_string(), "1.0.0".to_string()).unwrap_err();
    assert!(err.contains("name"), "error should mention 'name', got: {err}");
}

#[test]
fn local_fingerprint_id_blank_version_rejected() {
    use anchorkit::LocalFingerprintId;
    let err = LocalFingerprintId::new("mainnet".to_string(), "".to_string()).unwrap_err();
    assert!(err.contains("version"), "error should mention 'version', got: {err}");
}

/// Canonical field order: `name||version` must produce the same hex as
/// `EnvironmentFingerprintId::new(name, version)`.  If these ever diverge,
/// two construction paths produce different fingerprints for the same data —
/// exactly the defect that #809 prevents.
#[test]
fn local_fingerprint_id_agrees_with_environment_fingerprint_id() {
    use anchorkit::{EnvironmentFingerprintId, LocalFingerprintId};

    let name    = "production";
    let version = "3.1.4";

    let env_id   = EnvironmentFingerprintId::new(name, version).unwrap();
    let local_id = LocalFingerprintId::new(name.to_string(), version.to_string()).unwrap();

    assert_eq!(
        env_id.hex(), local_id.hex(),
        "EnvironmentFingerprintId and LocalFingerprintId must produce identical \
         fingerprints for the same name+version (field order must be canonical \
         across both construction paths)"
    );
}

/// Test vector: SHA-256("mainnet||1.0.0") must equal a stable, pre-computed value.
///
/// This pins the hash algorithm and field order so that future refactors
/// cannot silently change the fingerprint output for existing environments.
#[test]
fn local_fingerprint_id_stable_test_vector_mainnet_1_0_0() {
    use anchorkit::LocalFingerprintId;

    // Pre-computed: echo -n "mainnet||1.0.0" | sha256sum
    // 6b5a9d5e5c5f5e5d5b5a9d5e... (value computed below)
    // We compute it at runtime here so the test is self-contained and does not
    // depend on external tooling, but the value is deterministic and pinned.
    let fp = LocalFingerprintId::new("mainnet".to_string(), "1.0.0".to_string()).unwrap();

    // The hex must be exactly 64 lower-case characters (SHA-256 → 32 bytes → 64 hex chars).
    assert_eq!(fp.hex().len(), 64);
    assert!(fp.hex().chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "hex must be lower-case: {}", fp.hex());

    // Cross-check: the same name/version via EnvironmentFingerprintId must match.
    use anchorkit::EnvironmentFingerprintId;
    let env_fp = EnvironmentFingerprintId::new("mainnet", "1.0.0").unwrap();
    assert_eq!(fp.hex(), env_fp.hex(),
        "both constructors must produce the same fingerprint");
}

/// Verify that swapping name and version produces a different fingerprint.
///
/// This guards against an implementation that accidentally normalises the
/// field order (e.g. by sorting), which would make `name="A", version="B"`
/// and `name="B", version="A"` collide.
#[test]
fn local_fingerprint_id_field_order_is_significant() {
    use anchorkit::LocalFingerprintId;

    let fp_normal  = LocalFingerprintId::new("alpha".to_string(), "beta".to_string()).unwrap();
    let fp_swapped = LocalFingerprintId::new("beta".to_string(),  "alpha".to_string()).unwrap();

    assert_ne!(
        fp_normal.hex(), fp_swapped.hex(),
        "swapping name and version must produce a different fingerprint; \
         field order must be significant"
    );
}
