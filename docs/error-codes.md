# AnchorKit Error Code Reference

All errors are represented as `AnchorKitError` (see `src/errors.rs`), carrying a
numeric `ErrorCode`, a human-readable `message`, and an optional `context` string.

## Compatibility expectations

The canonical assignments belong to the contract API in
[`src/errors.rs`](../src/errors.rs). Preserve existing numeric discriminants and
their meanings; use unused values for new errors instead of renumbering or reusing
codes. Clients should branch on numeric `ErrorCode` values. Human-readable
`message` and optional `context` strings are diagnostics and may be clarified
without changing the numeric code.

Changing an assignment or which error an operation returns can break client
handling even if the text stays the same. Explain the impact and any client
migration in the PR for maintainer review under the existing
[governance rules](governance-and-security.md#decision-making). This states the
current compatibility expectation, not an additional release or semver promise.
Update this reference and affected constructor/call-site tests together; do not
silently refresh assertions to hide a mapping change. Consult the
[API snapshot guidance](api-contract-snapshots.md#6-what-counts-as-a-breaking-change),
but also review numeric values and behavior directly.

Exact regression coverage in
[`tests/error_code_round_trip_tests.rs`](../tests/error_code_round_trip_tests.rs)
includes `replay_attack_round_trips_through_u32`,
`replay_attack_discriminant_is_stable`, and
`replay_attack_value_is_distinct_from_neighbours`. These pin the representative
`ReplayAttack = 6` mapping, not every code. In
[`src/errors.rs`](../src/errors.rs), `test_no_duplicate_discriminants` and
`test_named_constructors` cover uniqueness and constructor behavior. Extend the
relevant regression coverage for additions or intentional mapping changes.

## Numbering scheme

| Range  | Category                              |
|--------|---------------------------------------|
|  1–10  | Auth / attestor errors                |
| 11–19  | Validation / quote / flow errors      |
| 20–31  | KYC / webhook / state / session errors |
| 48–49  | Cache errors                          |
| 50–55  | Profile / metadata / capacity errors   |

---

## Auth / attestor errors (1–10)

| Code | Variant                    | Message                                      | Raised by                                      |
|------|----------------------------|----------------------------------------------|------------------------------------------------|
| 1    | `AlreadyInitialized`       | Contract is already initialized              | `initialize` called twice                      |
| 2    | `AttestorAlreadyRegistered`| Attestor is already registered               | `register_attestor` with duplicate address     |
| 3    | `AttestorNotRegistered`    | Attestor is not registered                   | Any attestor-gated call with unknown address   |
| 4    | `UnauthorizedAttestor`     | Attestor is not authorized                   | Signature mismatch on attestation              |
| 5    | `InvalidTimestamp`         | Timestamp is invalid                         | Attestation timestamp too old/future           |
| 6    | `ReplayAttack`             | Replay attack detected                       | Duplicate `(issuer, payload_hash)` pair        |
| 7    | `InvalidQuote`             | Quote is invalid                             | `submit_quote` with bad fee or amounts         |
| 8    | `InvalidServiceType`       | Service type is invalid                      | `configure_services` with unknown/duplicate    |
| 9    | `InvalidTransactionIntent` | Transaction intent is invalid                | SEP-6/24 intent validation                     |
| 10   | `StaleQuote`               | Quote has expired                            | `route_transaction` with expired quote         |

---

## Validation / quote / flow errors (11–19)

| Code | Variant                  | Message                                      | Raised by                                      |
|------|--------------------------|----------------------------------------------|------------------------------------------------|
| 11   | `ComplianceNotMet`       | Compliance requirements not met              | `route_transaction` with `require_compliance`  |
| 12   | `InvalidEndpointFormat`  | Endpoint format is invalid                   | `set_endpoint`, `register_webhook` (non-HTTPS) |
| 13   | `NoQuotesAvailable`      | No quotes are available                      | `route_transaction` with no matching quotes    |
| 14   | `ServicesNotConfigured`  | Services are not configured                  | `get_supported_services` before configuration  |
| 15   | `ValidationError`        | Response schema validation failed            | Schema checks, empty strings, bad lengths      |
| 16   | `RateLimitExceeded`      | Rate limit exceeded                          | `submit_attestation` over per-attestor limit   |
| 17   | `AttestationNotFound`    | Attestation not found                        | `get_attestation` with unknown ID              |
| 18   | `InvalidSep10Token`      | SEP-10 JWT is missing, expired, or invalid   | `verify_sep10_token*` family                   |
| 19   | `KycNotFound`            | KYC record not found                         | `approve_kyc`, `reject_kyc` before `submit_kyc`|

---

## KYC / webhook / state errors (20–29)

| Code | Variant                  | Message                                      | Raised by                                      |
|------|--------------------------|----------------------------------------------|------------------------------------------------|
| 20   | `KycPending`             | KYC verification is pending                  | `submit_attestation_kyc_check` (pending KYC)   |
| 21   | `KycRejected`            | KYC verification was rejected                | `submit_attestation_kyc_check` (rejected KYC)  |
| 22   | `WebhookDeliveryFailed`  | Webhook delivery failed validation           | `deliver_webhook` after max retries            |
| 23   | `NotInitialized`         | Contract is not initialized                  | Any call before `initialize`                   |
| 24   | `IllegalTransition`      | Illegal transaction state transition         | `TransactionStateTracker::transition`          |
| 25   | `SessionExpired`         | Session has expired                          | Session-gated calls after TTL                  |
| 26   | `SessionClosed`          | Session is closed                            | Session-gated calls on a closed session        |
| 27   | `UnsupportedCapabilityVersion` | Service capability version is unsupported | `configure_services_versioned`               |
| 28   | `Unauthorized`           | Caller is not authorized                   | Admin-gated operations from non-admin         |

---

## Session / routing errors (30–31)

| Code | Variant                    | Message                              | Raised by                                      |
|------|----------------------------|--------------------------------------|------------------------------------------------|
| 30   | `SessionOperationLimitExceeded` | Session operation limit exceeded | Session-gated calls exceeding max operations  |
| 31   | `InvalidWeights`           | Routing weights must sum to 1.0      | `route_transaction` with invalid weights      |

---

## Cache errors (48–49)

| Code | Variant        | Message                    | Raised by                                          |
|------|----------------|----------------------------|----------------------------------------------------|
| 48   | `CacheExpired` | Cache entry has expired    | `get_cached_metadata`, `get_cached_capabilities`   |
| 49   | `CacheNotFound`| Cache entry not found      | `get_cached_metadata`, `get_cached_capabilities`   |

---

## Profile / metadata validation errors (50–55)

| Code | Variant                    | Message                              | Raised by                                          |
|------|----------------------------|--------------------------------------|----------------------------------------------------|
| 50   | `AttestorProfileNotFound`  | Attestor profile not found           | `get_attestor_profile` before any profile write    |
| 51   | `InvalidRequestContext`    | Request context is invalid           | `create_request_context` with empty/zero fields    |
| 52   | `InvalidSessionMetadata`   | Session metadata is invalid          | Session creation with malformed operation context  |
| 53   | `InvalidAssetCode`         | Asset code is invalid                | Asset-related operations with bad code format     |
| 54   | `AttestorCapacityExceeded` | Attestor capacity has been exceeded  | Attestor registration beyond capacity limits      |
| 55   | `CacheCapacityExceeded`    | Cache capacity has been exceeded     | Caching beyond capacity limits                    |

---

## Error conversion boundaries

The crate exposes more than one error type. Contract entry points in
[`src/contract.rs`](../src/contract.rs) return `AnchorKitError` (whose `code`
field is an `ErrorCode`), while host-side helpers such as the deterministic
hashing utilities in [`src/deterministic_hash.rs`](../src/deterministic_hash.rs)
return their own host/parser error types. A conversion between them does not
necessarily preserve every detail, so integrators should not assume a host error
survives intact once it crosses into the contract boundary.

| Public boundary | Error type returned |
|-----------------|---------------------|
| Contract entry points in [`src/contract.rs`](../src/contract.rs) (e.g. `initialize`, `register_attestor`, `submit_quote`, `route_transaction`) | Contract errors: `AnchorKitError` with an `ErrorCode` (see the [code reference](#numbering-scheme) above and [`src/errors.rs`](../src/errors.rs)) |
| Parser / validation helpers in [`src/deterministic_hash.rs`](../src/deterministic_hash.rs) and other host modules | Host/parser errors, distinct from `AnchorKitError` |

### Lossy conversions

Where a host/parser error is surfaced through the contract, only the numeric
`ErrorCode` is guaranteed to survive. For example, `panic_with_error!` discards
the human-readable `message` and optional `context` and preserves only the
numeric code. Do not rely on message or context text crossing a boundary; branch
on the numeric `ErrorCode` as described in
[Compatibility expectations](#compatibility-expectations).

---

## Usage

```rust
use anchorkit::{AnchorKitError, ErrorCode};

// Named constructor (preferred)
let err = AnchorKitError::replay_attack();
assert_eq!(err.code, ErrorCode::ReplayAttack);  // code = 6

// With context detail
let err = AnchorKitError::validation_error("field: operation_type");
assert_eq!(err.code as u32, 15);

// New profile error
let err = AnchorKitError::attestor_profile_not_found();
assert_eq!(err.code as u32, 50);
```
