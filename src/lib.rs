//! # AnchorKit
//!
//! AnchorKit is a Soroban smart-contract library for building and interacting with
//! Stellar anchor services. It provides both an on-chain contract layer and an
//! off-chain service layer that normalises responses from anchors implementing the
//! [Stellar Ecosystem Proposals (SEPs)](https://github.com/stellar/stellar-protocol/tree/master/ecosystem).
//!
//! ## Architecture
//!
//! The library is split into two logical layers:
//!
//! ### On-chain contract layer (`contract` module)
//! The [`contract::AnchorKitContract`] Soroban contract manages:
//! - Attestor registration and revocation (with SEP-10 JWT verification)
//! - Attestation submission with replay protection and rate limiting
//! - Session-based multi-step operations with audit logging
//! - Quote routing across multiple anchors
//! - KYC / compliance record tracking
//! - Anchor metadata and capability caching
//! - Anchor discovery via `stellar.toml`
//!
//! ### Off-chain service layer (SEP modules)
//! Four thin normalisation modules translate raw anchor HTTP responses into
//! typed Rust structs so callers never have to parse raw JSON themselves:
//!
//! | Module | SEP | Purpose |
//! |--------|-----|---------|
//! | [`sep6`] | SEP-6 | Non-interactive deposit / withdrawal |
//! | [`sep24`] | SEP-24 | Interactive deposit / withdrawal |
//! | [`sep31`] | SEP-31 | Direct payment |
//! | [`sep38`] | SEP-38 | Anchor RFQ / firm quotes |
//!
//! ### Cross-cutting utilities
//! | Module | Purpose |
//! |--------|---------|
//! | `domain_validator` | HTTPS-only URL validation before any outbound request |
//! | `errors` | Unified [`AnchorKitError`] / [`ErrorCode`] type hierarchy |
//! | `rate_limiter` | Per-attestor sliding-window rate limiting |
//! | `retry` | Exponential-backoff retry for transient failures |
//! | `sep10_jwt` | EdDSA JWT verification (SEP-10 authentication) |
//! | `deterministic_hash` | Canonical SHA-256 hashing for attestation payloads |
//! | `transaction_state_tracker` | State-machine tracking for on-chain transactions |
//! | `response_validator` | Schema validation for anchor API responses |
//! | `structured_log` | Structured JSON-line logging for operational workflows |
//!
//! ## Quick-start example
//!
//! ```rust,no_run
//! use anchorkit::{
//!     validate_anchor_domain,
//!     sep6::{initiate_deposit, RawDepositResponse},
//!     sep24::{initiate_interactive_deposit, RawInteractiveDepositResponse},
//!     retry::{retry_with_backoff, RetryConfig},
//! };
//!
//! // 1. Validate the anchor domain before making any requests.
//! validate_anchor_domain("https://anchor.example.com").expect("invalid domain");
//!
//! // 2. Normalise a SEP-6 deposit response received from the anchor's HTTP API.
//! let raw = RawDepositResponse {
//!     transaction_id: "txn-001".into(),
//!     how: "Send to bank account 1234".into(),
//!     extra_info: None,
//!     min_amount: Some(10),
//!     max_amount: Some(10_000),
//!     fee_fixed: Some(1),
//!     status: Some("pending_external".into()),
//!     clawback_enabled: None,
//!     stellar_memo: None,
//!     stellar_memo_type: None,
//!     asset_code: None,
//! };
//! let deposit = initiate_deposit(raw).expect("invalid deposit response");
//! println!("Transaction ID: {}", deposit.transaction_id);
//!
//! // 3. Normalise a SEP-24 interactive deposit response.
//! let raw24 = RawInteractiveDepositResponse {
//!     url: "https://anchor.example.com/interactive/deposit".into(),
//!     id: "txn-002".into(),
//! };
//! let interactive = initiate_interactive_deposit(raw24).expect("invalid response");
//! println!("Redirect user to: {}", interactive.url);
//!
//! // 4. Wrap any fallible call with exponential-backoff retry.
//! let config = RetryConfig::default();
//! let mut js = anchorkit::retry::MockJitterSource::new(vec![0]);
//! let result = retry_with_backoff(
//!     &config,
//!     |_attempt| -> Result<&str, u32> { Ok("success") },
//!     |_err| false,
//!     |_ms| {},
//!     &mut js,
//! );
//! assert_eq!(result, Ok("success"));
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Build command | What it gates |
//! |------|---------|---------------|---------------|
//! | `std` | ✓ | `cargo build` | Filesystem config loader ([`load_runtime_config_file`]), `config` module |
//! | `wasm` | — | `cargo build --no-default-features --features wasm --target wasm32-unknown-unknown` | Excludes all HTTP/host modules; only on-chain contract code is compiled |
//! | `mock-only` | — | `cargo test --features mock-only` | Enables the [`mock`] module with pre-built response fixtures for testing without a live anchor |
//! | `stress-tests` | — | `cargo test --features stress-tests` | Enables the load-simulation integration test suite (excluded from normal CI) |
//!
//! ### Combining features
//!
//! ```text
//! # Native development (default)
//! cargo build
//!
//! # Soroban on-chain deployment (excludes all host-only modules)
//! cargo build --release --target wasm32-unknown-unknown --no-default-features --features wasm
//!
//! # Testing with mocks (no live anchor required)
//! cargo test --features mock-only
//!
//! # Full test suite including stress tests
//! cargo test --features std,mock-only,stress-tests
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

// ── Core modules (all build variants) ────────────────────────────────────────
pub mod deterministic_hash;
pub mod domain_validator;
pub mod errors;
pub mod sep10_jwt;
pub mod rate_limiter;
pub mod retry;
pub mod trace_context;
pub mod replay_detection;
pub mod request_deduplication;
pub mod retry_budget;
pub mod distributed_correlation;
pub mod request_provenance;
pub mod transaction_state_tracker;
pub mod contract;
#[cfg(not(feature = "wasm"))]
pub mod anchor_health;
pub mod service_management;
pub mod admin_audit_log;
pub mod cache_governance;
pub mod compliance_policy;
pub mod session_state_machine;
pub mod migration;
#[cfg(not(feature = "wasm"))]
pub mod url_normalizer;
// Issue #679: configurable request record retention policies
// Issue #680: request record export and archival support
#[cfg(not(feature = "wasm"))]
pub mod request_record;
// Issue #678: host-boundary replay prevention
#[cfg(not(feature = "wasm"))]
pub mod host_replay_prevention;

// ── std-only modules (filesystem, runtime config, env fingerprinting) ─────────
#[cfg(feature = "std")]
pub mod config;
#[cfg(feature = "std")]
pub mod env_fingerprint;
#[cfg(feature = "std")]
pub use env_fingerprint::EnvironmentFingerprint;
#[cfg(feature = "std")]
pub use env_fingerprint::{EnvironmentFingerprintId, LocalFingerprintId};

// ── Host-only modules (HTTP, threading) ───────────────────────────────────────
// Excluded from `wasm` builds: on-chain Soroban contracts have no network access.
#[cfg(not(feature = "wasm"))]
mod response_validator;
#[cfg(not(feature = "wasm"))]
pub mod http_client;
#[cfg(not(feature = "wasm"))]
pub mod metrics;
#[cfg(not(feature = "wasm"))]
pub mod webhook;
#[cfg(not(feature = "wasm"))]
pub mod sep6;
#[cfg(not(feature = "wasm"))]
pub mod sep24;
#[cfg(not(feature = "wasm"))]
pub mod sep31;
#[cfg(not(feature = "wasm"))]
pub mod sep38;
#[cfg(not(feature = "wasm"))]
pub mod stellar_toml;
#[cfg(not(feature = "wasm"))]
pub mod streaming_monitor;
#[cfg(not(feature = "wasm"))]
pub mod structured_log;

// ── Transaction archive (#675), compaction (#676) ────────────────────────────
#[cfg(not(feature = "wasm"))]
pub mod transaction_archive;
#[cfg(not(feature = "wasm"))]
pub mod transaction_compaction;

// ── Artifact provenance tracking (#674) ──────────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub mod artifact_provenance;

// ── Deployment drift detection (#673) ────────────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub mod deployment_drift;

// ── Multi-asset quote routing (#656) ─────────────────────────────────────────
// Available in host (non-WASM) builds. Provides asset-pair routing across
// multiple corridors in a single pass.
#[cfg(not(feature = "wasm"))]
pub mod multi_asset_routing;

// ── Alert routing, deduplication, and synthetic probes (#685, #686, #687) ───
// Host-only: alert routing decisions, dedup/suppression logic, and synthetic
// endpoint probes all require `alloc` and run off-chain.
#[cfg(not(feature = "wasm"))]
pub mod alert_routing;
#[cfg(not(feature = "wasm"))]
pub mod alert_dedup;
#[cfg(not(feature = "wasm"))]
pub mod synthetic_probe;

// ── Mock helpers (test / CI without live anchor) ──────────────────────────────
#[cfg(feature = "mock-only")]
pub mod mock;

// ── Core re-exports ───────────────────────────────────────────────────────────
pub use domain_validator::validate_anchor_domain;
pub use domain_validator::{validate_anchor_domain_with_policy, DomainPolicy, DomainPolicyRule, PolicyAction};
pub use errors::{AnchorKitError, ErrorCode};
pub use errors::normalize_asset_code;
/// Backward-compatible alias. Prefer [`AnchorKitError`] for new code.
pub use errors::Error;
pub use rate_limiter::{RateLimiter, RateLimitConfig, RateLimitState};
pub use retry::{retry_with_backoff, is_retryable, RetryConfig, JitterSource, LedgerJitterSource, MockJitterSource};
pub use retry::{BackoffStrategy, JitterPolicy};
pub use retry::retry_with_backoff_traced;
pub use trace_context::{TraceContext, TraceError, TRACEPARENT_HEADER, TRACE_ID_HEADER, SPAN_ID_HEADER};
pub use request_deduplication::{DeduplicationStore, DeduplicationKey, DeduplicationResult, DeduplicationStats, execute_deduplicated};
pub use retry_budget::{RetryBudget, RetryBudgetConfig, BudgetExhaustedError, execute_with_budget};
pub use distributed_correlation::{CorrelationContext, CorrelationError, CORRELATION_ID_HEADER, ORIGIN_SERVICE_HEADER, HOP_COUNT_HEADER, BAGGAGE_HEADER};
pub use request_provenance::{ProvenanceRecord, ProvenanceError, PROVENANCE_ID_HEADER, PARENT_ID_HEADER, DEPTH_HEADER, ORIGIN_HEADER, OPERATION_HEADER};
pub use deterministic_hash::{compute_payload_hash, verify_payload_hash};
pub use contract::{AnchorKitContract, AnchorTomlProvenance, EndpointUpdated, CacheConfig};
pub use contract::{AttestorRevocationRecord};
pub use contract::{
    ContractInitializedEvent, AttestorRegisteredEvent, AttestorRevokedEvent,
    AttestorReactivatedEvent, RateLimitHitEvent, QuoteExpiredEvent,
    WebhookRegisteredEvent, ServicesConfiguredEvent,
};
pub use transaction_state_tracker::{TransactionState, TransactionStateRecord, RecoveryMetadata, OptRecovery};
pub use transaction_state_tracker::{StorageBudgetMonitor, TransactionStateTracker};
pub use transaction_state_tracker::TransactionSummary;
pub use url_normalizer::{normalize_url, normalize_and_validate, extract_hostname, UrlFilterPolicy, UrlFilterEntry};
pub use cache_governance::{CachePolicy, CachePolicySet, CacheEntryType, CacheGovernanceConfig};

// ── std-only re-exports ───────────────────────────────────────────────────────
#[cfg(feature = "std")]
pub use config::{load_runtime_config_file, parse_runtime_config_str, ConfigFormat, RuntimeConfig, RuntimeConfigManager};

// ── Host-only re-exports ──────────────────────────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use http_client::ProxyConfig;
#[cfg(all(not(feature = "wasm"), feature = "std"))]
pub use http_client::{build_client, build_client_with_policy, fetch_stellar_toml_with_proxy, deliver_webhook_with_proxy, deliver_webhook_with_proxy_traced};
#[cfg(not(feature = "wasm"))]
pub use http_client::{ConnectionPolicy, TransportErrorKind, classify_transport_error, is_transport_error_retryable};
#[cfg(not(feature = "wasm"))]
pub use http_client::{OutboundRequestOptions, post_with_options, verify_outbound_signature};
#[cfg(not(feature = "wasm"))]
pub use response_validator::{
    validate_anchor_info_response, validate_deposit_response, validate_quote_response,
    validate_sep38_quote_response, validate_withdraw_response, validate_stellar_asset,
    validate_stellar_account_id, normalize_stellar_account_id,
    validate_transaction_status_response, validate_transaction_status_response_v2,
    validate_deposit_with_version, validate_withdraw_with_version, validate_quote_with_version,
    validate_sep38_quote_with_version, validate_anchor_info_with_version,
    validate_transaction_status_with_version,
    AnchorInfoResponse, DepositResponse as ValidatorDepositResponse, QuoteResponse,
    Sep38QuoteResponse, WithdrawResponse, TransactionStatusResponseValidated,
    SchemaVersion, VALIDATOR_SCHEMA_V1,
    // Issue #831: unknown SEP-6 status strings classify as Unknown, never success
    Sep6StatusClass, sep6_status_class,
    // Issue #661: response shape compatibility checks for older anchors
    CompatibilityLevel, CompatibilityReport,
    check_deposit_compatibility, check_withdraw_compatibility,
    check_sep38_quote_compatibility, check_anchor_info_compatibility,
    check_transaction_status_compatibility,
};
#[cfg(not(feature = "wasm"))]
pub use webhook::{deliver_webhook, deliver_webhook_traced, dlq_entries_for_trace, get_dead_letter_webhooks, query_dlq, verify_webhook_signature, WebhookDeliveryConfig, DlqEntry};
#[cfg(not(feature = "wasm"))]
pub use stellar_toml::{ParsedCurrency, ParsedStellarToml, parse_stellar_toml, fetch_stellar_toml_url};
#[cfg(not(feature = "wasm"))]
pub use sep6::{
    fetch_transaction_status, initiate_deposit, initiate_withdrawal, DepositResponse,
    RawDepositResponse, RawTransactionResponse, RawWithdrawalResponse, TransactionKind,
    TransactionStatus, TransactionStatusResponse, WithdrawalResponse,
    poll_transaction_status, PollConfig, PollResult,
    StatusCategory, classify_status_str,
    VendorStatusMap, VendorStatusEntry,
};
#[cfg(not(feature = "wasm"))]
pub use sep31::{
    initiate_sep31_payment, RawSep31PaymentResponse, Sep31PaymentResponse,
};
#[cfg(not(feature = "wasm"))]
pub use sep24::{
    initiate_interactive_deposit, initiate_interactive_deposit_with_origin,
    initiate_interactive_withdrawal, initiate_interactive_withdrawal_with_origin,
    fetch_sep24_transaction_status,
    validate_interactive_url, validate_transaction_id,
    InteractiveDepositResponse, InteractiveWithdrawalResponse, Sep24TransactionStatusResponse,
    RawInteractiveDepositResponse, RawInteractiveWithdrawalResponse, RawSep24TransactionResponse,
};
pub use contract::{ServiceRetirementInfo, AnchorServices};
pub use contract::{AttestationFilter, AttestationPage};
pub use contract::{AttestationSortOrder};
#[cfg(not(feature = "wasm"))]
pub use contract::sort_attestations;
pub use service_management::{ServiceManager, ServiceToggleState, ServiceConfigSnapshot};
pub use service_management::{MaintenanceWindow, MaintenanceManager};
pub use service_management::{ServiceDependency, ServiceDependencyGraph, DependencyManager};
pub use service_management::{
    ServiceTemplate, TemplateApplication, TemplateManager,
    TEMPLATE_FIAT_ON_RAMP, TEMPLATE_REMITTANCE, TEMPLATE_STABLECOIN_ISSUER,
};
pub use admin_audit_log::{AdminAuditLog, AdminConfigChangeEvent, AdminAuditLogConfig};
pub use contract::{HealthStatus, MetadataFreshnessReport, RateLimiterHealth};
pub use contract::{AnchorHealthMetrics, AnchorProofRecord};
pub use transaction_state_tracker::{BudgetStatus, BudgetAlert};
// Issue #657: multi-anchor reputation weightingpub use contract::{AnchorReputationRecord, ReputationWeights};
// Issue #658: time-based routing policies
pub use contract::{RoutingTimeWindow, TimedRoutingPolicy};
// Issue #659: per-network routing profiles
pub use contract::NetworkRoutingProfile;
#[cfg(not(feature = "wasm"))]
pub use anchor_health::{
    AnchorHealthReport, HealthReportFormat,
    build_health_report, export_health_report,
    build_health_report_with_maintenance, should_suppress_alert,
    SloTarget, SloEvaluation, SloViolationDetail, SloHealthReport,
    evaluate_slo, evaluate_slo_for_report, build_slo_report,
};
#[cfg(not(feature = "wasm"))]
pub use sep38::{CrossAnchorFeeAggregator, FeeAnomalyReport};
#[cfg(not(feature = "wasm"))]
pub use sep38::{
    RawPartialFirmQuote, PartialFirmQuote, parse_partial_quote,
    sort_quotes, QuoteSortOrder,
};
#[cfg(not(feature = "wasm"))]
pub use streaming_monitor::{StreamingTransactionMonitor, TransactionStatusUpdate, StateTransition, BackpressureConfig};
#[cfg(not(feature = "wasm"))]
pub use multi_asset_routing::{
    route_multi_asset, validate_asset_pair_request, normalize_asset_code as normalize_asset_code_routing,
    pair_key, select_best,
    AssetPairRequest, AssetPairQuote, CandidateQuote, MultiAssetRoutingResult,
};
#[cfg(not(feature = "wasm"))]
pub use structured_log::{StructuredLogger, LogLevel, LogRecord, FieldValue, log_attestor_registration};
#[cfg(not(feature = "wasm"))]
pub use alert_routing::{AlertRouter, AlertRouterConfig, AlertRule, AlertRoute, AlertSeverity};
#[cfg(not(feature = "wasm"))]
pub use alert_dedup::{AlertDeduplicator, AlertFilter, AlertSuppressor, DedupConfig, SuppressedEntry};
#[cfg(not(feature = "wasm"))]
pub use synthetic_probe::{
    SyntheticProbeRunner, ProbeConfig, ProbeKind, ProbeResult, ProbeOutcome,
    ProbeReport, probe_results_to_health_window,
};

// ── Issue #675: archived transaction histories ────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use transaction_archive::{
    TransactionArchive, TransactionArchiveManager, ArchiveRetrievalStatus,
    compute_archive_commitment, verify_archive_commitment,
};

// ── Issue #676: transaction history compaction ────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use transaction_compaction::{
    compact_history, CompactionConfig, RawTransactionRecord,
    TransactionSummaryRecord, CompactionResult, CompactionAggregate,
};

// ── Issue #674: artifact provenance tracking ──────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use artifact_provenance::{
    ArtifactProvenance, ProvenanceStore, ProvenanceVerifier,
    VerificationReport, FieldVerdict,
};

// ── Issue #673: deployment drift detection ────────────────────────────────────
#[cfg(not(feature = "wasm"))]
pub use deployment_drift::{
    detect_drift, ConfigEntry, DeploymentSpec, DeploymentSnapshot,
    DriftReport, DriftItem, DriftSeverity,
};

#[cfg(all(test, not(feature = "wasm")))]
mod stellar_toml_tests;

