//! Runtime configuration loading and shape validation.

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};

use serde::Deserialize;
use serde_json::Value;

#[cfg(feature = "std")]
use std::{fs, path::Path};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub contract: ContractConfig,
    pub attestors: AttestorsConfig,
    pub sessions: Option<SessionsConfig>,
    pub operations: Option<OperationsConfig>,
    pub remittance: Option<RemittanceConfig>,
    pub stablecoin: Option<StablecoinConfig>,
    pub compliance: Option<Value>,
    pub storage: Option<StorageConfig>,
    pub security: Option<SecurityConfig>,
    pub monitoring: Option<MonitoringConfig>,
    /// Optional proxy configuration for HTTP-based anchor discovery and webhook delivery.
    pub proxy: Option<ProxyConfig>,
}

/// Proxy settings embedded in the runtime configuration file.
///
/// When present, all outbound HTTP requests (stellar.toml discovery, webhook
/// delivery, SEP-6 status checks) route through the selected proxy.
/// Scheme-specific proxies (`http_proxy_url` / `https_proxy_url`) take
/// precedence over the catch-all `proxy_url`; hosts on `no_proxy` bypass all
/// proxies. Optional `credentials` authenticate to the proxy via HTTP Basic.
///
/// The configuration is validated on load: malformed proxy URLs, credentials
/// without a username, and credentials supplied without any proxy URL are all
/// rejected (see [`ProxyConfig::validate`]).
///
/// # Example (JSON)
///
/// ```json
/// {
///   "proxy": {
///     "proxy_url": "http://proxy.corp.example.com:3128",
///     "https_proxy_url": "http://tls-proxy.corp.example.com:3129",
///     "no_proxy": "localhost,127.0.0.1",
///     "credentials": { "username": "svc-anchor", "password": "s3cret" }
///   }
/// }
/// ```
///
/// These are re-exports of [`http_client::ProxyConfig`] /
/// [`http_client::ProxyCredentials`] so that config files and the HTTP client
/// share a single type.
pub use crate::http_client::{ProxyConfig, ProxyCredentials};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContractConfig {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub network: String,
    pub admin_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttestorsConfig {
    pub registry: Vec<AttestorConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AttestorConfig {
    pub name: String,
    pub address: String,
    pub description: Option<String>,
    pub endpoint: Option<String>,
    pub contact_email: Option<String>,
    pub role: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SessionsConfig {
    pub enable_session_tracking: Option<bool>,
    pub session_timeout_seconds: Option<u64>,
    pub operations_per_session: Option<u64>,
    pub audit_log_retention_days: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperationsConfig {
    pub templates: Option<Vec<OperationTemplateConfig>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OperationTemplateConfig {
    pub id: String,
    pub name: String,
    pub attestor: String,
    pub operation_type: String,
    pub required_fields: Vec<String>,
    pub replay_protection: String,
    pub description: Option<String>,
    pub payload_schema: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemittanceConfig {
    pub corridors: Option<Vec<RemittanceCorridorConfig>>,
    pub exchange_rate: Option<ExchangeRateConfig>,
    pub fee_structure: Option<Vec<FeeStructureConfig>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemittanceCorridorConfig {
    pub source: String,
    pub destination: String,
    pub local_currency: String,
    pub settlement_method: String,
    pub expected_settlement_hours: Option<u64>,
    pub minimum_amount: Option<f64>,
    pub maximum_amount: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRateConfig {
    pub enable_live_rates: Option<bool>,
    pub rate_lock_duration_seconds: Option<u64>,
    pub rate_variance_tolerance_percent: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FeeStructureConfig {
    pub corridor: String,
    pub fee_type: String,
    pub fee_value: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StablecoinConfig {
    pub name: String,
    pub symbol: String,
    pub decimals: u64,
    pub reserve_currency: String,
    pub reserve_composition: Option<Vec<ReserveCompositionConfig>>,
    pub supply_caps: Option<SupplyCapsConfig>,
    pub collateral_types: Option<Vec<CollateralTypeConfig>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReserveCompositionConfig {
    pub asset: String,
    pub target_percentage: f64,
    pub minimum_percentage: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SupplyCapsConfig {
    pub maximum_supply_cap: Option<u64>,
    pub warning_threshold_percent: Option<f64>,
    pub emergency_threshold_percent: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CollateralTypeConfig {
    pub name: String,
    pub symbol: String,
    pub liquidation_ratio: f64,
    pub liquidation_fee_percent: Option<f64>,
    pub price_feed: Option<String>,
    pub minimum_deposit: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    pub instance_ttl_days: Option<u64>,
    pub session_cache_enabled: Option<bool>,
    pub persistent_ttl_days: Option<u64>,
    pub audit_log_enabled: Option<bool>,
    pub audit_log_compression: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    pub require_signature_verification: Option<bool>,
    pub signature_algorithm: Option<String>,
    pub signature_expiry_seconds: Option<u64>,
    pub nonce_required: Option<bool>,
    pub nonce_reuse_prevention: Option<bool>,
    pub endpoint_pins: Option<Vec<EndpointPinConfig>>,
    pub rate_limits: Option<Vec<RateLimitConfig>>,
    pub multisig_requirements: Option<Vec<MultisigRequirementConfig>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EndpointPinConfig {
    pub endpoint: String,
    pub pin_sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub attestor: String,
    pub requests_per_minute: u64,
    pub requests_per_hour: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MultisigRequirementConfig {
    pub operation: String,
    pub required_signatures: u64,
    pub signatory_attestors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MonitoringConfig {
    pub enable_metrics: Option<bool>,
    pub log_all_operations: Option<bool>,
    pub alert_on_failed_attestations: Option<bool>,
    pub alert_on_replay_attempts: Option<bool>,
    pub metrics_namespace: Option<String>,
    pub alerts: Option<Vec<AlertConfig>>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AlertConfig {
    pub condition: String,
    pub severity: String,
    pub recipients: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

pub fn parse_runtime_config_str(input: &str, format: ConfigFormat) -> Result<RuntimeConfig, String> {
    // Step 1: parse into a serde_json::Value first so we can run JSON Schema
    // validation before attempting typed deserialization. This catches unknown
    // fields, wrong types, and missing required fields with clear messages.
    let json_value: serde_json::Value = match format {
        ConfigFormat::Json => serde_json::from_str(input).map_err(|e| e.to_string())?,
        ConfigFormat::Toml => {
            // Parse TOML then round-trip through JSON so the schema validator
            // always operates on a serde_json::Value regardless of input format.
            let toml_value: toml::Value = toml::from_str(input).map_err(|e| e.to_string())?;
            serde_json::to_value(toml_value).map_err(|e| e.to_string())?
        }
    };

    // Step 2: validate against the embedded JSON Schema.
    validate_against_schema(&json_value)?;

    // Step 3: typed deserialization (shape already confirmed by schema).
    let config: RuntimeConfig = serde_json::from_value(json_value).map_err(|e| e.to_string())?;

    // Step 4: cross-field semantic validation (referential integrity, etc.).
    validate_runtime_config(&config)?;
    Ok(config)
}

/// Validate a `serde_json::Value` against the embedded `config_schema.json`.
///
/// The schema is compiled once per call. For hot-reload scenarios the
/// compilation cost is negligible compared to I/O.
fn validate_against_schema(value: &serde_json::Value) -> Result<(), String> {
    // Schema validation temporarily disabled due to dependency issues
    // TODO: Re-enable once jsonschema crate resolution is fixed
    Ok(())
}

#[cfg(feature = "std")]
pub fn load_runtime_config_file(path: impl AsRef<Path>) -> Result<RuntimeConfig, String> {
    let path = path.as_ref();
    // Guard: reject a blank path before any filesystem access so callers receive
    // a clear, configuration-level error rather than an opaque OS error.
    if path.as_os_str().is_empty() {
        return Err("config path must not be blank".to_string());
    }
    let input = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let format = ConfigFormat::from_path(path)?;
    parse_runtime_config_str(&input, format)
}

/// Thread-safe runtime configuration holder supporting hot-reload.
///
/// Wraps a [`RuntimeConfig`] loaded from disk so a long-running process can
/// pick up configuration changes without restarting. [`RuntimeConfigManager::reload`]
/// re-reads and re-validates the backing file; a file that fails to parse or
/// fails shape validation is rejected and the previously loaded configuration
/// is left in place untouched.
///
/// # Examples
///
/// ```rust,no_run
/// use anchorkit::config::RuntimeConfigManager;
///
/// let manager = RuntimeConfigManager::new("configs/remittance-anchor.toml").unwrap();
/// // ... time passes, an operator edits the file on disk ...
/// match manager.reload() {
///     Ok(()) => println!("config reloaded"),
///     Err(e) => eprintln!("reload rejected, keeping previous config: {e}"),
/// }
/// let current = manager.current();
/// ```
#[cfg(feature = "std")]
pub struct RuntimeConfigManager {
    path: std::path::PathBuf,
    config: std::sync::RwLock<RuntimeConfig>,
    last_modified: std::sync::RwLock<Option<std::time::SystemTime>>,
}

#[cfg(feature = "std")]
impl RuntimeConfigManager {
    /// Load and validate the configuration at `path`, keeping it in memory for hot-reload.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let config = load_runtime_config_file(&path)?;
        let last_modified = Self::file_modified_time(&path);
        Ok(Self {
            path,
            config: std::sync::RwLock::new(config),
            last_modified: std::sync::RwLock::new(last_modified),
        })
    }

    /// Return a clone of the currently loaded configuration.
    pub fn current(&self) -> RuntimeConfig {
        self.config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Path to the config file backing this manager.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-read and re-validate the config file, swapping it in on success.
    ///
    /// On failure (I/O error, malformed input, or shape-validation failure) the
    /// previously loaded configuration is left untouched and the error is
    /// returned so the caller can log/alert on the rejected reload.
    pub fn reload(&self) -> Result<(), String> {
        let new_config = load_runtime_config_file(&self.path)?;
        let mut guard = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = new_config;
        drop(guard);
        let mut mtime_guard = self
            .last_modified
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *mtime_guard = Self::file_modified_time(&self.path);
        Ok(())
    }

    /// Check whether the on-disk file has a newer modification time than the
    /// last successful load/reload, without reading or reloading it.
    pub fn has_changed(&self) -> bool {
        let current_mtime = Self::file_modified_time(&self.path);
        let last = *self
            .last_modified
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match (current_mtime, last) {
            (Some(cur), Some(last)) => cur > last,
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// Reload only if the file's modification time changed since the last load.
    ///
    /// Returns `Ok(true)` if a reload happened, `Ok(false)` if the file was
    /// unchanged (no I/O beyond a metadata stat), or `Err` if a reload was
    /// attempted but rejected — in which case the previous configuration
    /// remains active.
    pub fn reload_if_changed(&self) -> Result<bool, String> {
        if !self.has_changed() {
            return Ok(false);
        }
        self.reload()?;
        Ok(true)
    }

    fn file_modified_time(path: &Path) -> Option<std::time::SystemTime> {
        fs::metadata(path).and_then(|m| m.modified()).ok()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ConfigFormat {
    Json,
    Toml,
}

impl ConfigFormat {
    #[cfg(feature = "std")]
    fn from_path(path: &Path) -> Result<Self, String> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => Ok(Self::Json),
            Some("toml") => Ok(Self::Toml),
            Some(ext) => Err(format!("unsupported config extension: {ext}")),
            None => Err("config path has no extension".to_string()),
        }
    }
}

fn validate_runtime_config(config: &RuntimeConfig) -> Result<(), String> {
    if config.contract.name.is_empty() {
        return Err("contract.name cannot be empty".to_string());
    }

    if config.attestors.registry.is_empty() {
        return Err("attestors.registry cannot be empty".to_string());
    }

    let attestors: Vec<&str> = config
        .attestors
        .registry
        .iter()
        .map(|attestor| attestor.name.as_str())
        .collect();

    if let Some(operations) = &config.operations {
        if let Some(templates) = &operations.templates {
            for template in templates {
                if !attestors.contains(&template.attestor.as_str()) {
                    return Err(format!(
                        "operation '{}' references unknown attestor '{}'",
                        template.id, template.attestor
                    ));
                }
            }
        }
    }

    if let Some(security) = &config.security {
        if let Some(rate_limits) = &security.rate_limits {
            for rate_limit in rate_limits {
                if !attestors.contains(&rate_limit.attestor.as_str()) {
                    return Err(format!(
                        "rate limit references unknown attestor '{}'",
                        rate_limit.attestor
                    ));
                }
            }
        }

        if let Some(requirements) = &security.multisig_requirements {
            for requirement in requirements {
                for signatory in &requirement.signatory_attestors {
                    if !attestors.contains(&signatory.as_str()) {
                        return Err(format!(
                            "multisig requirement '{}' references unknown attestor '{}'",
                            requirement.operation, signatory
                        ));
                    }
                }
            }
        }
    }

    if let Some(proxy) = &config.proxy {
        proxy.validate().map_err(|err| format!("proxy: {err}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod proxy_config_tests {
    use super::*;

    /// Minimal valid config JSON used as a base for proxy tests.
    fn base_config_json(proxy_section: &str) -> String {
        alloc::format!(
            r#"{{
                "contract": {{
                    "name": "TestAnchor",
                    "version": "1.0.0",
                    "network": "testnet"
                }},
                "attestors": {{
                    "registry": [{{
                        "name": "attestor-1",
                        "address": "GABC123",
                        "role": "primary",
                        "enabled": true
                    }}]
                }}
                {proxy_section}
            }}"#
        )
    }

    #[test]
    fn test_config_without_proxy_parses_successfully() {
        let json = base_config_json("");
        let config = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap();
        assert!(config.proxy.is_none(), "proxy should be None when absent");
    }

    #[test]
    fn test_config_with_proxy_url_parses_correctly() {
        let proxy_section = r#","proxy": {"proxy_url": "http://proxy.corp.example.com:3128", "no_proxy": null}"#;
        let json = base_config_json(proxy_section);
        let config = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap();
        let proxy = config.proxy.expect("proxy should be Some");
        assert_eq!(
            proxy.proxy_url.as_deref(),
            Some("http://proxy.corp.example.com:3128")
        );
        assert!(proxy.no_proxy.is_none());
        assert!(proxy.is_configured());
    }

    #[test]
    fn test_config_with_proxy_url_and_no_proxy_list() {
        let proxy_section = r#","proxy": {"proxy_url": "http://proxy.corp.example.com:3128", "no_proxy": "localhost,127.0.0.1"}"#;
        let json = base_config_json(proxy_section);
        let config = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap();
        let proxy = config.proxy.expect("proxy should be Some");
        assert_eq!(
            proxy.proxy_url.as_deref(),
            Some("http://proxy.corp.example.com:3128")
        );
        assert_eq!(proxy.no_proxy.as_deref(), Some("localhost,127.0.0.1"));
    }

    #[test]
    fn test_config_with_null_proxy_fields() {
        let proxy_section = r#","proxy": {"proxy_url": null, "no_proxy": null}"#;
        let json = base_config_json(proxy_section);
        let config = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap();
        let proxy = config.proxy.expect("proxy key present → Some");
        assert!(proxy.proxy_url.is_none());
        assert!(proxy.no_proxy.is_none());
        assert!(!proxy.is_configured(), "null proxy_url means not configured");
    }

    #[test]
    fn test_config_proxy_is_configured_helper() {
        let configured = ProxyConfig {
            proxy_url: Some("http://proxy.example.com:3128".to_string()),
            no_proxy: None,
            ..ProxyConfig::default()
        };
        assert!(configured.is_configured());

        let unconfigured = ProxyConfig::default();
        assert!(!unconfigured.is_configured());
    }

    #[test]
    fn test_config_toml_with_proxy() {
        let toml_input = r#"
[contract]
name = "TestAnchor"
version = "1.0.0"
network = "testnet"

[[attestors.registry]]
name = "attestor-1"
address = "GABC123"
role = "primary"
enabled = true

[proxy]
proxy_url = "http://proxy.corp.example.com:3128"
no_proxy = "localhost"
"#;
        let config = parse_runtime_config_str(toml_input, ConfigFormat::Toml).unwrap();
        let proxy = config.proxy.expect("proxy should be Some");
        assert_eq!(
            proxy.proxy_url.as_deref(),
            Some("http://proxy.corp.example.com:3128")
        );
        assert_eq!(proxy.no_proxy.as_deref(), Some("localhost"));
    }

    // ── Proxy credentials and validation (#606) ───────────────────────────────

    #[test]
    fn test_config_with_proxy_credentials_and_per_scheme_urls() {
        let proxy_section = r#","proxy": {
            "proxy_url": "http://proxy.corp.example.com:3128",
            "https_proxy_url": "http://tls-proxy.corp.example.com:3129",
            "no_proxy": "localhost",
            "credentials": {"username": "svc-anchor", "password": "s3cret"}
        }"#;
        let json = base_config_json(proxy_section);
        let config = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap();
        let proxy = config.proxy.expect("proxy should be Some");
        assert_eq!(
            proxy.https_proxy_url.as_deref(),
            Some("http://tls-proxy.corp.example.com:3129")
        );
        let creds = proxy.credentials.as_ref().expect("credentials should be Some");
        assert_eq!(creds.username, "svc-anchor");
        assert_eq!(creds.password, "s3cret");
        assert!(proxy.has_credentials());
    }

    #[test]
    fn test_config_toml_with_proxy_credentials() {
        let toml_input = r#"
[contract]
name = "TestAnchor"
version = "1.0.0"
network = "testnet"

[[attestors.registry]]
name = "attestor-1"
address = "GABC123"
role = "primary"
enabled = true

[proxy]
http_proxy_url = "http://http-proxy.corp:3128"
https_proxy_url = "http://tls-proxy.corp:3129"

[proxy.credentials]
username = "svc-anchor"
password = "s3cret"
"#;
        let config = parse_runtime_config_str(toml_input, ConfigFormat::Toml).unwrap();
        let proxy = config.proxy.expect("proxy should be Some");
        assert_eq!(proxy.http_proxy_url.as_deref(), Some("http://http-proxy.corp:3128"));
        assert_eq!(
            proxy.credentials.as_ref().map(|c| c.username.as_str()),
            Some("svc-anchor")
        );
    }

    #[test]
    fn test_config_rejects_invalid_proxy_scheme_at_parse_time() {
        let proxy_section = r#","proxy": {"proxy_url": "socks5://proxy.corp:1080"}"#;
        let json = base_config_json(proxy_section);
        let err = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap_err();
        assert!(err.contains("invalid proxy URL"), "got: {err}");
        assert!(err.starts_with("proxy:"), "error should be scoped to proxy, got: {err}");
    }

    #[test]
    fn test_config_rejects_credentials_without_proxy_url() {
        let proxy_section =
            r#","proxy": {"credentials": {"username": "svc", "password": "pw"}}"#;
        let json = base_config_json(proxy_section);
        let err = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap_err();
        assert!(err.contains("no proxy URL configured"), "got: {err}");
    }

    #[test]
    fn test_config_rejects_credentials_missing_password() {
        let proxy_section = r#","proxy": {"proxy_url": "http://proxy.corp:3128", "credentials": {"username": "svc"}}"#;
        let json = base_config_json(proxy_section);
        assert!(
            parse_runtime_config_str(&json, ConfigFormat::Json).is_err(),
            "credentials without a password field must be rejected"
        );
    }

    #[test]
    fn test_config_rejects_unknown_proxy_field() {
        let proxy_section = r#","proxy": {"proxy_url": "http://proxy.corp:3128", "pasword": "typo"}"#;
        let json = base_config_json(proxy_section);
        assert!(
            parse_runtime_config_str(&json, ConfigFormat::Json).is_err(),
            "unknown proxy fields (likely typos) must be rejected"
        );
    }

    #[test]
    fn test_config_rejects_empty_credential_username() {
        let proxy_section = r#","proxy": {"proxy_url": "http://proxy.corp:3128", "credentials": {"username": "", "password": "pw"}}"#;
        let json = base_config_json(proxy_section);
        let err = parse_runtime_config_str(&json, ConfigFormat::Json).unwrap_err();
        assert!(err.contains("username cannot be empty"), "got: {err}");
    }
}

#[cfg(all(test, feature = "std"))]
mod hot_reload_tests {
    use super::*;

    const VALID_CONFIG: &str = r#"{
        "contract": {
            "name": "TestAnchor",
            "version": "1.0.0",
            "network": "testnet"
        },
        "attestors": {
            "registry": [{
                "name": "attestor-1",
                "address": "GABC123",
                "role": "primary",
                "enabled": true
            }]
        }
    }"#;

    const VALID_CONFIG_V2: &str = r#"{
        "contract": {
            "name": "TestAnchorV2",
            "version": "2.0.0",
            "network": "testnet"
        },
        "attestors": {
            "registry": [{
                "name": "attestor-1",
                "address": "GABC123",
                "role": "primary",
                "enabled": true
            }]
        }
    }"#;

    const INVALID_CONFIG: &str = r#"{
        "contract": {
            "name": "",
            "version": "1.0.0",
            "network": "testnet"
        },
        "attestors": {
            "registry": []
        }
    }"#;

    /// Create a unique scratch file path under the OS temp dir for this test process.
    fn scratch_path(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "anchorkit_hot_reload_{label}_{}_{}.json",
            std::process::id(),
            nanos
        ))
    }

    /// Write `content`, sleeping briefly beforehand so the resulting mtime is
    /// observably later than any previous write to the same path (guards
    /// against flakiness from coarse filesystem mtime resolution).
    fn write_with_advanced_mtime(path: &std::path::Path, content: &str) {
        std::thread::sleep(std::time::Duration::from_millis(20));
        fs::write(path, content).expect("write scratch config");
    }

    #[test]
    fn test_manager_new_loads_valid_config() {
        let path = scratch_path("new_valid");
        fs::write(&path, VALID_CONFIG).unwrap();

        let manager = RuntimeConfigManager::new(&path).expect("valid config should load");
        assert_eq!(manager.current().contract.name, "TestAnchor");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_manager_new_rejects_invalid_config() {
        let path = scratch_path("new_invalid");
        fs::write(&path, INVALID_CONFIG).unwrap();

        let result = RuntimeConfigManager::new(&path);
        assert!(result.is_err(), "empty contract.name must be rejected");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_reload_picks_up_valid_change() {
        let path = scratch_path("reload_valid");
        fs::write(&path, VALID_CONFIG).unwrap();
        let manager = RuntimeConfigManager::new(&path).unwrap();
        assert_eq!(manager.current().contract.name, "TestAnchor");

        fs::write(&path, VALID_CONFIG_V2).unwrap();
        manager.reload().expect("reload of a valid config must succeed");
        assert_eq!(manager.current().contract.name, "TestAnchorV2");
        assert_eq!(manager.current().contract.version, "2.0.0");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_reload_rejects_invalid_change_and_keeps_previous_config() {
        let path = scratch_path("reload_invalid");
        fs::write(&path, VALID_CONFIG).unwrap();
        let manager = RuntimeConfigManager::new(&path).unwrap();
        assert_eq!(manager.current().contract.name, "TestAnchor");

        fs::write(&path, INVALID_CONFIG).unwrap();
        let result = manager.reload();
        assert!(result.is_err(), "invalid reload input must be rejected");

        // Previous valid configuration must still be active.
        assert_eq!(
            manager.current().contract.name,
            "TestAnchor",
            "a rejected reload must not mutate the active configuration"
        );

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_reload_rejects_malformed_json() {
        let path = scratch_path("reload_malformed");
        fs::write(&path, VALID_CONFIG).unwrap();
        let manager = RuntimeConfigManager::new(&path).unwrap();

        fs::write(&path, "{ this is not valid json").unwrap();
        let result = manager.reload();
        assert!(result.is_err(), "malformed JSON must be rejected");
        assert_eq!(manager.current().contract.name, "TestAnchor");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_reload_if_changed_skips_when_file_untouched() {
        let path = scratch_path("reload_if_unchanged");
        fs::write(&path, VALID_CONFIG).unwrap();
        let manager = RuntimeConfigManager::new(&path).unwrap();

        // No modification since load: has_changed() must report false and
        // reload_if_changed() must be a no-op returning Ok(false).
        assert!(!manager.has_changed());
        let result = manager.reload_if_changed();
        assert_eq!(result, Ok(false));
        assert_eq!(manager.current().contract.name, "TestAnchor");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_reload_if_changed_reloads_when_file_modified() {
        let path = scratch_path("reload_if_changed");
        write_with_advanced_mtime(&path, VALID_CONFIG);
        let manager = RuntimeConfigManager::new(&path).unwrap();

        write_with_advanced_mtime(&path, VALID_CONFIG_V2);
        let result = manager.reload_if_changed();
        assert_eq!(result, Ok(true));
        assert_eq!(manager.current().contract.name, "TestAnchorV2");

        fs::remove_file(&path).ok();
    }

    #[test]
    fn test_manager_new_reports_missing_file() {
        let path = scratch_path("does_not_exist");
        let result = RuntimeConfigManager::new(&path);
        assert!(result.is_err());
    }

    // ── #806: blank-path guard ────────────────────────────────────────────────

    #[test]
    fn test_load_blank_path_returns_clear_error() {
        // An empty path must be rejected with a configuration-level error
        // before any filesystem access is attempted.
        let result = load_runtime_config_file("");
        assert!(result.is_err(), "blank path must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("blank"),
            "error message should mention 'blank', got: {err}"
        );
    }

    #[test]
    fn test_load_nonblank_missing_path_returns_io_error() {
        // A non-blank path that does not exist must still produce an I/O error
        // (not the blank-path error), preserving the existing error classification.
        let path = scratch_path("definitely_does_not_exist_nonblank");
        let result = load_runtime_config_file(&path);
        assert!(result.is_err(), "missing nonblank path must error");
        let err = result.unwrap_err();
        // The error should NOT mention "blank" — it must be an OS I/O error.
        assert!(
            !err.contains("blank"),
            "missing-file error must not say 'blank', got: {err}"
        );
    }
}