//! Error types for AnchorKit
//!
//! All errors are represented as [`AnchorKitError`], a unified base error type
//! carrying a [`code`](AnchorKitError::code), [`message`](AnchorKitError::message),
//! and optional [`context`](AnchorKitError::context).
//!
//! The [`ErrorCode`] enum enumerates every distinct error kind. Use the
//! provided constructor helpers (e.g. [`AnchorKitError::already_initialized`])
//! to build errors without touching raw codes.


extern crate alloc;

use alloc::string::String;
use soroban_sdk::contracterror;

// ---------------------------------------------------------------------------
// ErrorCode — the canonical list of all error kinds (replaces the old Error enum)
// ---------------------------------------------------------------------------

/// Numeric error codes for every AnchorKit error kind.
///
/// # Numbering scheme
///
/// Codes are grouped by category. Gaps are intentional to allow future additions
/// within each group without renumbering existing codes.
///
/// | Range  | Category                        |
/// |--------|---------------------------------|
/// |  1–10  | Auth / attestor errors          |
/// | 11–19  | Validation / quote / flow errors|
/// | 20–29  | KYC / webhook / state errors    |
/// | 48–49  | Cache errors                    |
///
/// # Discriminant changelog (issue #160 — merge-conflict resolution)
///
/// The following values changed from their conflicted branch values to the
/// canonical values below. Downstream consumers that hard-code numeric codes
/// must update accordingly:
///
/// | Variant              | Old (conflicted)  | Canonical |
/// |----------------------|-------------------|-----------|
/// | `KycPending`         | 20 or 22          | 20        |
/// | `KycRejected`        | 21 or 23          | 21        |
/// | `WebhookDeliveryFailed` | 24             | 22        |
/// | `NotInitialized`     | 22, 25            | 23        |
/// | `IllegalTransition`  | 23, 24, 26        | 24        |
/// | `SessionExpired`     | 25, 27            | 25        |
/// | `SessionClosed`      | 26 (one branch)   | 26        |
// `export = false` skips XDR spec generation: the SCSpecUDTErrorEnumV0 spec
// entry caps error enums at 50 cases, and this enum now has 51. All error
// conversions (`panic_with_error!`, `From<ErrorCode> for Error`) still work.
#[contracterror(export = false)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ErrorCode {
    // Auth / attestor errors (1–10)
    AlreadyInitialized        = 1,
    AttestorAlreadyRegistered = 2,
    AttestorNotRegistered     = 3,
    UnauthorizedAttestor      = 4,
    InvalidTimestamp          = 5,
    ReplayAttack              = 6,
    InvalidQuote              = 7,
    InvalidServiceType        = 8,
    InvalidTransactionIntent  = 9,
    StaleQuote                = 10,

    // Validation / quote / flow errors (11–19)
    ComplianceNotMet          = 11,
    InvalidEndpointFormat     = 12,
    NoQuotesAvailable         = 13,
    ServicesNotConfigured     = 14,
    ValidationError           = 15,
    RateLimitExceeded         = 16,
    AttestationNotFound       = 17,
    InvalidSep10Token         = 18,
    KycNotFound               = 19,

    // Item not found errors (specific variants — replaces reuse of AttestationNotFound)
    SessionNotFound           = 32,
    QuoteNotFound             = 33,
    AuditLogNotFound          = 34,
    TransactionNotFound       = 35,

    // KYC / webhook / state errors (20–29)
    KycPending                = 20,
    KycRejected               = 21,
    WebhookDeliveryFailed     = 22,
    NotInitialized            = 23,
    IllegalTransition         = 24,
    SessionExpired            = 25,
    SessionClosed             = 26,
    UnsupportedCapabilityVersion = 27,
    /// Caller does not hold the required admin role for this operation.
    Unauthorized              = 28,

    // Session / routing errors (30–31)
    SessionOperationLimitExceeded = 30,
    InvalidWeights                = 31,

    // Cache errors (48–49)
    CacheExpired              = 48,
    CacheNotFound             = 49,

    // Capacity errors (54–55)
    /// Maximum number of registered attestors exceeded
    AttestorCapacityExceeded  = 54,
    /// Maximum number of cache entries exceeded
    CacheCapacityExceeded     = 55,

    // Profile / metadata validation errors (50–52)
    /// Attestor profile not found (no profile record exists yet).
    AttestorProfileNotFound   = 50,
    /// RequestContext has an empty operation name or invalid chain.
    InvalidRequestContext     = 51,
    /// Session metadata is malformed (empty operation type, zero timestamp, etc.).
    InvalidSessionMetadata    = 52,
    /// Asset code is empty, too long, or contains invalid characters.
    InvalidAssetCode          = 53,

    // URL-not-set errors (56–57)
    /// Attestor has no endpoint URL set (profile exists but field is empty).
    EndpointNotSet            = 56,
    /// Attestor has no webhook URL set (profile exists but field is empty).
    WebhookUrlNotSet          = 57,

    // Precise failure-mode variants (58–62)
    /// KYC record exists but the approval has passed its expiry timestamp.
    KycExpired                = 58,
    /// Attestor address is known but currently revoked; reactivation is required.
    AttestorRevoked           = 59,
    /// Quote record exists but `valid_until` has passed.
    QuoteExpired              = 60,
    /// EdDSA signature length or value is invalid for the given public key.
    SignatureVerificationFailed = 61,
    /// Batch submission contains more items than the per-call maximum.
    BatchSizeExceeded         = 62,
    /// Base and quote asset are the same (circular corridor).
    InvalidAssetPair          = 63,
    /// Amount is zero or otherwise invalid for routing.
    InvalidAmount             = 64,

    // Precise retirement / fingerprint errors (65–66)
    /// A service retirement transition is invalid (e.g. from/to state labels).
    InvalidRetirementTransition = 65,
    /// Fingerprint collection failed.
    FingerprintCollectionFailed = 66,

    // Maintenance window errors (77–79)
    /// No maintenance window exists for the requested ID.
    MaintenanceWindowNotFound = 77,
    /// A new maintenance window conflicts with an existing one for the same anchor.
    MaintenanceWindowConflict = 78,
    /// The requested operation is blocked because the anchor is in a maintenance window.
    ServiceInMaintenance      = 79,

    // Dependency graph errors (68–70)
    /// A required service dependency is not present or not enabled.
    DependencyNotMet          = 68,
    /// The dependency graph contains a cycle (circular dependency).
    DependencyCycleDetected   = 69,
    /// A referenced dependency service code does not exist.
    DependencyNotFound        = 70,

    // Service template errors (71–73)
    /// No template exists with the requested name.
    TemplateNotFound          = 71,
    /// A template contains an invalid or inconsistent service configuration.
    InvalidTemplate           = 72,
    /// Template has already been applied to this anchor and cannot be re-applied.
    TemplateAlreadyApplied    = 73,

    // SLO errors (74–76)
    /// An SLO target was violated (composite score fell below the configured threshold).
    SloViolation              = 74,
    /// The SLO configuration is invalid (e.g. threshold out of range).
    InvalidSloConfig          = 75,
    /// No SLO has been configured for this anchor.
    SloNotConfigured          = 76,
}

impl ErrorCode {
    /// Returns the canonical human-readable message for this error code.
    ///
    /// The returned string is a static `&str` suitable for embedding in
    /// [`AnchorKitError::message`] without heap allocation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::ErrorCode;
    ///
    /// assert_eq!(
    ///     ErrorCode::AlreadyInitialized.default_message(),
    ///     "Contract is already initialized"
    /// );
    /// assert!(!ErrorCode::ValidationError.default_message().is_empty());
    /// ```
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::AlreadyInitialized        => "Contract is already initialized",
            ErrorCode::AttestorAlreadyRegistered => "Attestor is already registered",
            ErrorCode::AttestorNotRegistered     => "Attestor is not registered",
            ErrorCode::UnauthorizedAttestor      => "Attestor is not authorized",
            ErrorCode::InvalidTimestamp          => "Timestamp is invalid",
            ErrorCode::ReplayAttack              => "Replay attack detected",
            ErrorCode::InvalidQuote              => "Quote is invalid",
            ErrorCode::InvalidServiceType        => "Service type is invalid",
            ErrorCode::InvalidTransactionIntent  => "Transaction intent is invalid",
            ErrorCode::StaleQuote                => "Quote has expired",
            ErrorCode::ComplianceNotMet          => "Compliance requirements not met",
            ErrorCode::InvalidEndpointFormat     => "Endpoint format is invalid",
            ErrorCode::NoQuotesAvailable         => "No quotes are available",
            ErrorCode::ServicesNotConfigured     => "Services are not configured",
            ErrorCode::ValidationError           => "Response schema validation failed",
            ErrorCode::RateLimitExceeded         => "Rate limit exceeded",
            ErrorCode::AttestationNotFound       => "Attestation not found",
            ErrorCode::InvalidSep10Token         => "SEP-10 JWT is missing, expired, or invalid",
            ErrorCode::KycNotFound               => "KYC record not found",
            ErrorCode::KycPending                => "KYC verification is pending",
            ErrorCode::KycRejected               => "KYC verification was rejected",
            ErrorCode::WebhookDeliveryFailed     => "Webhook delivery failed validation",
            ErrorCode::NotInitialized            => "Contract is not initialized",
            ErrorCode::IllegalTransition         => "Illegal transaction state transition",
            ErrorCode::SessionExpired            => "Session has expired",
            ErrorCode::SessionClosed                  => "Session is closed",
            ErrorCode::SessionNotFound               => "Session not found",
            ErrorCode::UnsupportedCapabilityVersion    => "Service capability version is unsupported",
            ErrorCode::Unauthorized                    => "Caller is not authorized for this operation",
            ErrorCode::SessionOperationLimitExceeded   => "Session operation limit exceeded",
            ErrorCode::InvalidWeights                  => "Routing weights must sum to 1.0",
            ErrorCode::CacheExpired              => "Cache entry has expired",
            ErrorCode::CacheNotFound             => "Cache entry not found",
            ErrorCode::AttestorCapacityExceeded  => "Maximum number of registered attestors exceeded",
            ErrorCode::CacheCapacityExceeded     => "Maximum number of cache entries exceeded",
            ErrorCode::AttestorProfileNotFound   => "Attestor profile not found",
            ErrorCode::InvalidRequestContext     => "Request context is invalid",
            ErrorCode::InvalidSessionMetadata    => "Session metadata is invalid",
            ErrorCode::InvalidAssetCode          => "Asset code is invalid",
            ErrorCode::QuoteNotFound             => "Quote not found",
            ErrorCode::AuditLogNotFound          => "Audit log not found",
            ErrorCode::TransactionNotFound       => "Transaction record not found",
            ErrorCode::EndpointNotSet            => "Attestor endpoint URL is not set",
            ErrorCode::WebhookUrlNotSet          => "Attestor webhook URL is not set",
            ErrorCode::KycExpired                => "KYC approval has expired",
            ErrorCode::AttestorRevoked           => "Attestor is revoked; reactivation required",
            ErrorCode::QuoteExpired              => "Quote has passed its validity deadline",
            ErrorCode::SignatureVerificationFailed => "Attestation signature verification failed",
            ErrorCode::BatchSizeExceeded         => "Batch size exceeds the per-call maximum",
            ErrorCode::InvalidAssetPair          => "Base and quote asset must differ",
            ErrorCode::InvalidAmount             => "Amount is zero or otherwise invalid",
            ErrorCode::MaintenanceWindowNotFound => "Maintenance window not found",
            ErrorCode::MaintenanceWindowConflict => "Maintenance window conflicts with an existing window",
            ErrorCode::ServiceInMaintenance      => "Service is currently in a maintenance window",
            ErrorCode::DependencyNotMet          => "A required service dependency is not enabled",
            ErrorCode::DependencyCycleDetected   => "Circular dependency detected in service graph",
            ErrorCode::DependencyNotFound        => "Referenced dependency service does not exist",
            ErrorCode::TemplateNotFound          => "Service template not found",
            ErrorCode::InvalidTemplate           => "Service template configuration is invalid",
            ErrorCode::TemplateAlreadyApplied    => "Template has already been applied to this anchor",
            ErrorCode::SloViolation              => "Service level objective was violated",
            ErrorCode::InvalidSloConfig          => "SLO configuration is invalid",
            ErrorCode::SloNotConfigured          => "No SLO has been configured for this anchor",
        }
    }
}

// ---------------------------------------------------------------------------
// AnchorKitError — the unified base error type
// ---------------------------------------------------------------------------

/// The base error type for all AnchorKit errors.
///
/// Every error carries:
/// - `code`: the [`ErrorCode`] identifying the error kind
/// - `message`: a human-readable description
/// - `context`: optional extra detail (field name, received value, etc.)
///
/// Prefer the named constructors (e.g. [`AnchorKitError::replay_attack`]) over
/// constructing this struct directly so that messages stay consistent.
///
/// # Examples
///
/// ```rust
/// use anchorkit::{AnchorKitError, ErrorCode};
///
/// // Named constructor
/// let err = AnchorKitError::replay_attack();
/// assert_eq!(err.code, ErrorCode::ReplayAttack);
///
/// // Custom message
/// let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
/// assert_eq!(err.message, "Quote amount is zero");
///
/// // With context detail
/// let err = AnchorKitError::with_context(
///     ErrorCode::ValidationError,
///     "Schema mismatch",
///     "field: transaction_id",
/// );
/// assert_eq!(err.context.as_deref(), Some("field: transaction_id"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorKitError {
    pub code: ErrorCode,
    pub message: String,
    pub context: Option<String>,
}

impl AnchorKitError {
    /// Create a new error with a custom message and no context.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant that classifies this error.
    /// * `message` - A human-readable description of what went wrong.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] with `context` set to `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
    /// assert_eq!(err.code, ErrorCode::InvalidQuote);
    /// assert_eq!(err.message, "Quote amount is zero");
    /// assert!(err.context.is_none());
    /// ```
    pub fn new(code: ErrorCode, message: &str) -> Self {
        AnchorKitError {
            code,
            message: String::from(message),
            context: None,
        }
    }

    /// Create a new error with a custom message and context detail.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant that classifies this error.
    /// * `message` - A human-readable description of what went wrong.
    /// * `context` - Additional detail such as a field name or received value.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] with `context` populated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::with_context(
    ///     ErrorCode::ValidationError,
    ///     "Schema mismatch",
    ///     "field: transaction_id",
    /// );
    /// assert_eq!(err.context.as_deref(), Some("field: transaction_id"));
    /// ```
    pub fn with_context(code: ErrorCode, message: &str, context: &str) -> Self {
        AnchorKitError {
            code,
            message: String::from(message),
            context: Some(String::from(context)),
        }
    }

    /// Create an error using the default message for the given code.
    ///
    /// This is the preferred way to construct errors when no additional context
    /// is needed, as it keeps messages consistent across the codebase.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant to construct an error for.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] whose `message` is [`ErrorCode::default_message`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::from_code(ErrorCode::AlreadyInitialized);
    /// assert_eq!(err.message, "Contract is already initialized");
    /// ```
    pub fn from_code(code: ErrorCode) -> Self {
        let message = code.default_message();
        AnchorKitError::new(code, message)
    }

    // ------------------------------------------------------------------
    // Named constructors — one per ErrorCode variant
    // ------------------------------------------------------------------

    pub fn already_initialized() -> Self { Self::from_code(ErrorCode::AlreadyInitialized) }
    pub fn attestor_already_registered() -> Self { Self::from_code(ErrorCode::AttestorAlreadyRegistered) }
    pub fn attestor_not_registered() -> Self { Self::from_code(ErrorCode::AttestorNotRegistered) }
    pub fn unauthorized_attestor() -> Self { Self::from_code(ErrorCode::UnauthorizedAttestor) }
    pub fn invalid_timestamp() -> Self { Self::from_code(ErrorCode::InvalidTimestamp) }
    pub fn replay_attack() -> Self { Self::from_code(ErrorCode::ReplayAttack) }
    pub fn invalid_quote() -> Self { Self::from_code(ErrorCode::InvalidQuote) }
    pub fn invalid_service_type() -> Self { Self::from_code(ErrorCode::InvalidServiceType) }
    pub fn invalid_transaction_intent() -> Self { Self::from_code(ErrorCode::InvalidTransactionIntent) }
    pub fn stale_quote() -> Self { Self::from_code(ErrorCode::StaleQuote) }
    pub fn compliance_not_met() -> Self { Self::from_code(ErrorCode::ComplianceNotMet) }
    pub fn invalid_endpoint_format() -> Self { Self::from_code(ErrorCode::InvalidEndpointFormat) }
    pub fn no_quotes_available() -> Self { Self::from_code(ErrorCode::NoQuotesAvailable) }
    pub fn services_not_configured() -> Self { Self::from_code(ErrorCode::ServicesNotConfigured) }
    pub fn not_initialized() -> Self { Self::from_code(ErrorCode::NotInitialized) }
    pub fn attestation_not_found() -> Self { Self::from_code(ErrorCode::AttestationNotFound) }
    pub fn invalid_sep10_token() -> Self { Self::from_code(ErrorCode::InvalidSep10Token) }
    pub fn kyc_not_found() -> Self { Self::from_code(ErrorCode::KycNotFound) }
    pub fn kyc_pending() -> Self { Self::from_code(ErrorCode::KycPending) }
    pub fn kyc_rejected() -> Self { Self::from_code(ErrorCode::KycRejected) }
    pub fn webhook_delivery_failed() -> Self { Self::from_code(ErrorCode::WebhookDeliveryFailed) }
    pub fn rate_limit_exceeded() -> Self { Self::from_code(ErrorCode::RateLimitExceeded) }
    pub fn session_expired() -> Self { Self::from_code(ErrorCode::SessionExpired) }
    pub fn session_closed() -> Self { Self::from_code(ErrorCode::SessionClosed) }
    pub fn session_not_found() -> Self { Self::from_code(ErrorCode::SessionNotFound) }
    pub fn session_operation_limit_exceeded() -> Self { Self::from_code(ErrorCode::SessionOperationLimitExceeded) }
    pub fn invalid_weights() -> Self { Self::from_code(ErrorCode::InvalidWeights) }
    pub fn unauthorized() -> Self { Self::from_code(ErrorCode::Unauthorized) }
    pub fn cache_expired() -> Self { Self::from_code(ErrorCode::CacheExpired) }
    pub fn cache_not_found() -> Self { Self::from_code(ErrorCode::CacheNotFound) }
    pub fn attestor_capacity_exceeded() -> Self { Self::from_code(ErrorCode::AttestorCapacityExceeded) }
    pub fn cache_capacity_exceeded() -> Self { Self::from_code(ErrorCode::CacheCapacityExceeded) }
    pub fn attestor_profile_not_found() -> Self { Self::from_code(ErrorCode::AttestorProfileNotFound) }
    pub fn invalid_request_context() -> Self { Self::from_code(ErrorCode::InvalidRequestContext) }
    pub fn invalid_session_metadata() -> Self { Self::from_code(ErrorCode::InvalidSessionMetadata) }
    pub fn quote_not_found() -> Self { Self::from_code(ErrorCode::QuoteNotFound) }
    pub fn endpoint_not_set() -> Self { Self::from_code(ErrorCode::EndpointNotSet) }
    pub fn webhook_url_not_set() -> Self { Self::from_code(ErrorCode::WebhookUrlNotSet) }
    pub fn kyc_expired() -> Self { Self::from_code(ErrorCode::KycExpired) }
    pub fn attestor_revoked() -> Self { Self::from_code(ErrorCode::AttestorRevoked) }
    pub fn quote_expired() -> Self { Self::from_code(ErrorCode::QuoteExpired) }
    pub fn signature_verification_failed() -> Self { Self::from_code(ErrorCode::SignatureVerificationFailed) }
    pub fn fingerprint_collection_failed() -> Self { Self::from_code(ErrorCode::FingerprintCollectionFailed) }
    /// Build an invalid retirement transition error with from/to state labels.
    pub fn invalid_retirement_transition(from: &str, to: &str) -> Self {
        Self::with_context(
            ErrorCode::InvalidRetirementTransition,
            ErrorCode::InvalidRetirementTransition.default_message(),
            &alloc::format!("[E65] {} -> {}", from, to),
        )
    }
    pub fn batch_size_exceeded(limit: usize, given: usize) -> Self {
        Self::with_context(
            ErrorCode::BatchSizeExceeded,
            ErrorCode::BatchSizeExceeded.default_message(),
            &alloc::format!("limit={} given={}", limit, given),
        )
    }
    pub fn invalid_asset_code(code: &str) -> Self {
        Self::with_context(
            ErrorCode::InvalidAssetCode,
            ErrorCode::InvalidAssetCode.default_message(),
            code,
        )
    }

    /// Richer constructor that captures how many attempts were made and the
    /// last transport/HTTP error string.
    pub fn webhook_delivery_failed_with_details(attempts_made: u32, last_error: &str) -> Self {
        Self::with_context(
            ErrorCode::WebhookDeliveryFailed,
            ErrorCode::WebhookDeliveryFailed.default_message(),
            &alloc::format!("attempts_made={} last_error={}", attempts_made, last_error),
        )
    }

    pub fn validation_error(context: &str) -> Self {
        Self::with_context(
            ErrorCode::ValidationError,
            ErrorCode::ValidationError.default_message(),
            context,
        )
    }

    pub fn illegal_transition(from: &str, to: &str) -> Self {
        Self::with_context(
            ErrorCode::IllegalTransition,
            ErrorCode::IllegalTransition.default_message(),
            &alloc::format!("{} -> {}", from, to),
        )
    }

    // Maintenance window constructors
    pub fn maintenance_window_not_found() -> Self { Self::from_code(ErrorCode::MaintenanceWindowNotFound) }
    pub fn maintenance_window_conflict() -> Self { Self::from_code(ErrorCode::MaintenanceWindowConflict) }
    pub fn service_in_maintenance(service_code: u32) -> Self {
        Self::with_context(
            ErrorCode::ServiceInMaintenance,
            ErrorCode::ServiceInMaintenance.default_message(),
            &alloc::format!("service_code={service_code}"),
        )
    }

    // Dependency graph constructors
    pub fn dependency_not_met(service_code: u32, dependency_code: u32) -> Self {
        Self::with_context(
            ErrorCode::DependencyNotMet,
            ErrorCode::DependencyNotMet.default_message(),
            &alloc::format!("service={service_code} requires={dependency_code}"),
        )
    }
    pub fn dependency_cycle_detected() -> Self { Self::from_code(ErrorCode::DependencyCycleDetected) }
    pub fn dependency_not_found(service_code: u32) -> Self {
        Self::with_context(
            ErrorCode::DependencyNotFound,
            ErrorCode::DependencyNotFound.default_message(),
            &alloc::format!("service_code={service_code}"),
        )
    }

    // Template constructors
    pub fn template_not_found(name: &str) -> Self {
        Self::with_context(
            ErrorCode::TemplateNotFound,
            ErrorCode::TemplateNotFound.default_message(),
            name,
        )
    }
    pub fn invalid_template(reason: &str) -> Self {
        Self::with_context(
            ErrorCode::InvalidTemplate,
            ErrorCode::InvalidTemplate.default_message(),
            reason,
        )
    }
    pub fn template_already_applied(name: &str) -> Self {
        Self::with_context(
            ErrorCode::TemplateAlreadyApplied,
            ErrorCode::TemplateAlreadyApplied.default_message(),
            name,
        )
    }

    // SLO constructors
    pub fn slo_violation(anchor_id: &str, composite: f64, threshold: f64) -> Self {
        Self::with_context(
            ErrorCode::SloViolation,
            ErrorCode::SloViolation.default_message(),
            &alloc::format!("anchor={anchor_id} score={composite:.2} threshold={threshold:.2}"),
        )
    }
    pub fn invalid_slo_config(reason: &str) -> Self {
        Self::with_context(
            ErrorCode::InvalidSloConfig,
            ErrorCode::InvalidSloConfig.default_message(),
            reason,
        )
    }
    pub fn slo_not_configured() -> Self { Self::from_code(ErrorCode::SloNotConfigured) }
}

// ---------------------------------------------------------------------------
// Backward-compat type alias so existing code using `Error` still compiles
// ---------------------------------------------------------------------------

/// Backward-compatible alias. Prefer [`AnchorKitError`] for new code.
pub type Error = AnchorKitError;

// ---------------------------------------------------------------------------
// Asset code normalization
// ---------------------------------------------------------------------------

/// Normalize and validate a Stellar asset code.
///
/// - Trims whitespace.
/// - Uppercases ASCII letters.
/// - Rejects codes that are empty or longer than 12 characters after normalization.
/// - Rejects codes containing characters other than ASCII alphanumerics.
///
/// Returns the normalized (uppercased) code on success, or
/// [`AnchorKitError::invalid_asset_code`] on failure.
///
/// # Examples
///
/// ```rust
/// use anchorkit::errors::normalize_asset_code;
///
/// assert_eq!(normalize_asset_code("usdc").unwrap(), "USDC");
/// assert_eq!(normalize_asset_code("XLM").unwrap(), "XLM");
/// assert!(normalize_asset_code("").is_err());
/// assert!(normalize_asset_code("TOOLONGCODE!!").is_err());
/// assert!(normalize_asset_code("BAD CODE").is_err());
/// ```
pub fn normalize_asset_code(code: &str) -> Result<String, AnchorKitError> {
    let trimmed = code.trim();
    if trimmed.is_empty() || trimmed.len() > 12 {
        return Err(AnchorKitError::invalid_asset_code(code));
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(AnchorKitError::invalid_asset_code(code));
    }
    Ok(trimmed.to_ascii_uppercase())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_code_sets_message() {
        let err = AnchorKitError::from_code(ErrorCode::AlreadyInitialized);
        assert_eq!(err.code, ErrorCode::AlreadyInitialized);
        assert_eq!(err.message, "Contract is already initialized");
        assert!(err.context.is_none());
    }

    #[test]
    fn test_new_custom_message() {
        let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
        assert_eq!(err.code, ErrorCode::InvalidQuote);
        assert_eq!(err.message, "Quote amount is zero");
        assert!(err.context.is_none());
    }

    #[test]
    fn test_with_context() {
        let err = AnchorKitError::with_context(
            ErrorCode::ValidationError,
            "Schema mismatch",
            "field: transaction_id",
        );
        assert_eq!(err.code, ErrorCode::ValidationError);
        assert_eq!(err.message, "Schema mismatch");
        assert_eq!(err.context, Some(String::from("field: transaction_id")));
    }

    #[test]
    fn test_named_constructors() {
        assert_eq!(AnchorKitError::already_initialized().code,          ErrorCode::AlreadyInitialized);
        assert_eq!(AnchorKitError::attestor_already_registered().code,  ErrorCode::AttestorAlreadyRegistered);
        assert_eq!(AnchorKitError::attestor_not_registered().code,      ErrorCode::AttestorNotRegistered);
        assert_eq!(AnchorKitError::unauthorized_attestor().code,        ErrorCode::UnauthorizedAttestor);
        assert_eq!(AnchorKitError::invalid_timestamp().code,            ErrorCode::InvalidTimestamp);
        assert_eq!(AnchorKitError::replay_attack().code,                ErrorCode::ReplayAttack);
        assert_eq!(AnchorKitError::invalid_quote().code,                ErrorCode::InvalidQuote);
        assert_eq!(AnchorKitError::invalid_service_type().code,         ErrorCode::InvalidServiceType);
        assert_eq!(AnchorKitError::invalid_transaction_intent().code,   ErrorCode::InvalidTransactionIntent);
        assert_eq!(AnchorKitError::stale_quote().code,                  ErrorCode::StaleQuote);
        assert_eq!(AnchorKitError::compliance_not_met().code,           ErrorCode::ComplianceNotMet);
        assert_eq!(AnchorKitError::invalid_endpoint_format().code,      ErrorCode::InvalidEndpointFormat);
        assert_eq!(AnchorKitError::no_quotes_available().code,          ErrorCode::NoQuotesAvailable);
        assert_eq!(AnchorKitError::services_not_configured().code,      ErrorCode::ServicesNotConfigured);
        assert_eq!(AnchorKitError::invalid_sep10_token().code,          ErrorCode::InvalidSep10Token);
        assert_eq!(AnchorKitError::kyc_not_found().code,                ErrorCode::KycNotFound);
        assert_eq!(AnchorKitError::kyc_pending().code,                  ErrorCode::KycPending);
        assert_eq!(AnchorKitError::kyc_rejected().code,                 ErrorCode::KycRejected);
        assert_eq!(AnchorKitError::webhook_delivery_failed().code,      ErrorCode::WebhookDeliveryFailed);
        assert_eq!(AnchorKitError::session_not_found().code,            ErrorCode::SessionNotFound);
        assert_eq!(AnchorKitError::quote_not_found().code,              ErrorCode::QuoteNotFound);
        assert_eq!(AnchorKitError::unauthorized().code,                 ErrorCode::Unauthorized);
    }

    #[test]
    fn test_validation_error_has_context() {
        let err = AnchorKitError::validation_error("missing field: status");
        assert_eq!(err.code, ErrorCode::ValidationError);
        assert_eq!(err.context, Some(String::from("missing field: status")));
    }

    #[test]
    fn test_error_code_default_messages_are_non_empty() {
        let codes = [
            ErrorCode::AlreadyInitialized,
            ErrorCode::AttestorAlreadyRegistered,
            ErrorCode::AttestorNotRegistered,
            ErrorCode::UnauthorizedAttestor,
            ErrorCode::InvalidTimestamp,
            ErrorCode::ReplayAttack,
            ErrorCode::InvalidQuote,
            ErrorCode::InvalidServiceType,
            ErrorCode::InvalidTransactionIntent,
            ErrorCode::StaleQuote,
            ErrorCode::ComplianceNotMet,
            ErrorCode::InvalidEndpointFormat,
            ErrorCode::NoQuotesAvailable,
            ErrorCode::ServicesNotConfigured,
            ErrorCode::ValidationError,
            ErrorCode::RateLimitExceeded,
            ErrorCode::AttestationNotFound,
            ErrorCode::InvalidSep10Token,
            ErrorCode::KycNotFound,
            ErrorCode::KycPending,
            ErrorCode::KycRejected,
            ErrorCode::WebhookDeliveryFailed,
            ErrorCode::NotInitialized,
            ErrorCode::IllegalTransition,
            ErrorCode::SessionExpired,
            ErrorCode::SessionClosed,
            ErrorCode::SessionOperationLimitExceeded,
            ErrorCode::InvalidWeights,
            ErrorCode::CacheExpired,
            ErrorCode::CacheNotFound,
            ErrorCode::AttestorProfileNotFound,
            ErrorCode::InvalidRequestContext,
            ErrorCode::InvalidSessionMetadata,
            ErrorCode::SessionNotFound,
            ErrorCode::QuoteNotFound,
            ErrorCode::Unauthorized,
            ErrorCode::EndpointNotSet,
            ErrorCode::WebhookUrlNotSet,
            ErrorCode::KycExpired,
            ErrorCode::AttestorRevoked,
            ErrorCode::QuoteExpired,
            ErrorCode::SignatureVerificationFailed,
            ErrorCode::BatchSizeExceeded,
            ErrorCode::InvalidRetirementTransition,
            ErrorCode::FingerprintCollectionFailed,
        ];
        for code in codes {
            assert!(!code.default_message().is_empty());
        }
    }

    #[test]
    fn test_no_duplicate_discriminants() {
        // Verify canonical discriminant values
        assert_eq!(ErrorCode::KycPending            as u32, 20);
        assert_eq!(ErrorCode::KycRejected           as u32, 21);
        assert_eq!(ErrorCode::WebhookDeliveryFailed as u32, 22);
        assert_eq!(ErrorCode::NotInitialized        as u32, 23);
        assert_eq!(ErrorCode::IllegalTransition     as u32, 24);
        assert_eq!(ErrorCode::SessionExpired        as u32, 25);
        assert_eq!(ErrorCode::SessionClosed         as u32, 26);
        assert_eq!(ErrorCode::UnsupportedCapabilityVersion as u32, 27);
        assert_eq!(ErrorCode::Unauthorized          as u32, 28);
        assert_eq!(ErrorCode::SessionOperationLimitExceeded as u32, 30);
        assert_eq!(ErrorCode::InvalidWeights        as u32, 31);
        assert_eq!(ErrorCode::SessionNotFound       as u32, 32);
        assert_eq!(ErrorCode::QuoteNotFound         as u32, 33);
        assert_eq!(ErrorCode::CacheExpired          as u32, 48);
        assert_eq!(ErrorCode::CacheNotFound         as u32, 49);
        assert_eq!(ErrorCode::AttestorProfileNotFound as u32, 50);
        assert_eq!(ErrorCode::InvalidRequestContext as u32, 51);
        assert_eq!(ErrorCode::InvalidSessionMetadata as u32, 52);
        assert_eq!(ErrorCode::InvalidAssetCode      as u32, 53);
        assert_eq!(ErrorCode::AttestorCapacityExceeded as u32, 54);
        assert_eq!(ErrorCode::CacheCapacityExceeded as u32, 55);
        assert_eq!(ErrorCode::EndpointNotSet        as u32, 56);
        assert_eq!(ErrorCode::WebhookUrlNotSet      as u32, 57);
        assert_eq!(ErrorCode::KycExpired            as u32, 58);
        assert_eq!(ErrorCode::AttestorRevoked       as u32, 59);
        assert_eq!(ErrorCode::QuoteExpired          as u32, 60);
        assert_eq!(ErrorCode::SignatureVerificationFailed as u32, 61);
        assert_eq!(ErrorCode::BatchSizeExceeded     as u32, 62);
        assert_eq!(ErrorCode::InvalidRetirementTransition as u32, 65);
        assert_eq!(ErrorCode::FingerprintCollectionFailed as u32, 66);
    }

    #[test]
    fn test_new_precise_error_variants_have_messages() {
        assert!(!ErrorCode::KycExpired.default_message().is_empty());
        assert!(!ErrorCode::AttestorRevoked.default_message().is_empty());
        assert!(!ErrorCode::QuoteExpired.default_message().is_empty());
        assert!(!ErrorCode::SignatureVerificationFailed.default_message().is_empty());
        assert!(!ErrorCode::BatchSizeExceeded.default_message().is_empty());
    }

    #[test]
    fn test_batch_size_exceeded_carries_context() {
        let err = AnchorKitError::batch_size_exceeded(100, 150);
        assert_eq!(err.code, ErrorCode::BatchSizeExceeded);
        let ctx = err.context.expect("context must be present");
        assert!(ctx.contains("limit=100"));
        assert!(ctx.contains("given=150"));
    }

    #[test]
    fn test_type_alias_error_works() {        let err: Error = AnchorKitError::from_code(ErrorCode::InvalidEndpointFormat);
        assert_eq!(err.code, ErrorCode::InvalidEndpointFormat);
    }

    #[test]
    fn test_errors_are_cloneable_and_comparable() {
        let a = AnchorKitError::from_code(ErrorCode::StaleQuote);
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_normalize_asset_code_uppercases() {
        assert_eq!(super::normalize_asset_code("usdc").unwrap(), "USDC");
        assert_eq!(super::normalize_asset_code("xlm").unwrap(), "XLM");
        assert_eq!(super::normalize_asset_code("Eurc").unwrap(), "EURC");
    }

    #[test]
    fn test_normalize_asset_code_already_upper() {
        assert_eq!(super::normalize_asset_code("USDC").unwrap(), "USDC");
    }

    #[test]
    fn test_normalize_asset_code_trims_whitespace() {
        assert_eq!(super::normalize_asset_code("  USDC  ").unwrap(), "USDC");
    }

    #[test]
    fn test_normalize_asset_code_empty_rejected() {
        let err = super::normalize_asset_code("").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidAssetCode);
    }

    #[test]
    fn test_normalize_asset_code_too_long_rejected() {
        let err = super::normalize_asset_code("TOOLONGCODE13").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidAssetCode);
    }

    #[test]
    fn test_normalize_asset_code_invalid_chars_rejected() {
        for bad in &["BAD CODE", "USD-C", "USD.C", "USD@C"] {
            let err = super::normalize_asset_code(bad).unwrap_err();
            assert_eq!(err.code, ErrorCode::InvalidAssetCode);
        }
    }

    #[test]
    fn test_normalize_asset_code_max_length_accepted() {
        // 12 chars is the Stellar maximum
        assert!(super::normalize_asset_code("ABCDEFGHIJKL").is_ok());
    }
}
