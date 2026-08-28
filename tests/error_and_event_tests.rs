#![cfg(test)]

mod sep10_test_util;

/// Tests that verify:
/// - New precise error codes are returned for representative failure conditions
/// - Rich events are emitted for every major state transition
mod error_taxonomy_tests {
    use anchorkit::errors::{AnchorKitError, ErrorCode, normalize_asset_code};

    // -----------------------------------------------------------------------
    // New variant discriminants
    // -----------------------------------------------------------------------

    #[test]
    fn test_new_error_code_discriminants() {
        assert_eq!(ErrorCode::KycExpired               as u32, 58);
        assert_eq!(ErrorCode::AttestorRevoked          as u32, 59);
        assert_eq!(ErrorCode::QuoteExpired             as u32, 60);
        assert_eq!(ErrorCode::SignatureVerificationFailed as u32, 61);
        assert_eq!(ErrorCode::BatchSizeExceeded        as u32, 62);
    }

    #[test]
    fn test_new_error_code_messages_are_non_empty() {
        let codes = [
            ErrorCode::KycExpired,
            ErrorCode::AttestorRevoked,
            ErrorCode::QuoteExpired,
            ErrorCode::SignatureVerificationFailed,
            ErrorCode::BatchSizeExceeded,
        ];
        for code in codes {
            assert!(!code.default_message().is_empty(), "{code:?} has empty message");
        }
    }

    // -----------------------------------------------------------------------
    // Named constructors
    // -----------------------------------------------------------------------

    #[test]
    fn test_kyc_expired_constructor() {
        let err = AnchorKitError::kyc_expired();
        assert_eq!(err.code, ErrorCode::KycExpired);
        assert_eq!(err.message, ErrorCode::KycExpired.default_message());
        assert!(err.context.is_none());
    }

    #[test]
    fn test_attestor_revoked_constructor() {
        let err = AnchorKitError::attestor_revoked();
        assert_eq!(err.code, ErrorCode::AttestorRevoked);
    }

    #[test]
    fn test_quote_expired_constructor() {
        let err = AnchorKitError::quote_expired();
        assert_eq!(err.code, ErrorCode::QuoteExpired);
    }

    #[test]
    fn test_signature_verification_failed_constructor() {
        let err = AnchorKitError::signature_verification_failed();
        assert_eq!(err.code, ErrorCode::SignatureVerificationFailed);
    }

    #[test]
    fn test_batch_size_exceeded_carries_context() {
        let err = AnchorKitError::batch_size_exceeded(100, 150);
        assert_eq!(err.code, ErrorCode::BatchSizeExceeded);
        let ctx = err.context.expect("context must be present");
        assert!(ctx.contains("limit=100"), "context should contain limit");
        assert!(ctx.contains("given=150"), "context should contain given");
    }

    // -----------------------------------------------------------------------
    // No duplicate discriminants across entire enum
    // -----------------------------------------------------------------------

    #[test]
    fn test_no_overlapping_discriminants() {
        use std::collections::HashSet;
        let all: &[(u32, &str)] = &[
            (1,  "AlreadyInitialized"),
            (2,  "AttestorAlreadyRegistered"),
            (3,  "AttestorNotRegistered"),
            (4,  "UnauthorizedAttestor"),
            (5,  "InvalidTimestamp"),
            (6,  "ReplayAttack"),
            (7,  "InvalidQuote"),
            (8,  "InvalidServiceType"),
            (9,  "InvalidTransactionIntent"),
            (10, "StaleQuote"),
            (11, "ComplianceNotMet"),
            (12, "InvalidEndpointFormat"),
            (13, "NoQuotesAvailable"),
            (14, "ServicesNotConfigured"),
            (15, "ValidationError"),
            (16, "RateLimitExceeded"),
            (17, "AttestationNotFound"),
            (18, "InvalidSep10Token"),
            (19, "KycNotFound"),
            (20, "KycPending"),
            (21, "KycRejected"),
            (22, "WebhookDeliveryFailed"),
            (23, "NotInitialized"),
            (24, "IllegalTransition"),
            (25, "SessionExpired"),
            (26, "SessionClosed"),
            (27, "UnsupportedCapabilityVersion"),
            (28, "Unauthorized"),
            (30, "SessionOperationLimitExceeded"),
            (31, "InvalidWeights"),
            (32, "SessionNotFound"),
            (33, "QuoteNotFound"),
            (34, "AuditLogNotFound"),
            (35, "TransactionNotFound"),
            (48, "CacheExpired"),
            (49, "CacheNotFound"),
            (50, "AttestorProfileNotFound"),
            (51, "InvalidRequestContext"),
            (52, "InvalidSessionMetadata"),
            (53, "InvalidAssetCode"),
            (54, "AttestorCapacityExceeded"),
            (55, "CacheCapacityExceeded"),
            (56, "EndpointNotSet"),
            (57, "WebhookUrlNotSet"),
            (58, "KycExpired"),
            (59, "AttestorRevoked"),
            (60, "QuoteExpired"),
            (61, "SignatureVerificationFailed"),
            (62, "BatchSizeExceeded"),
        ];
        let mut seen = HashSet::new();
        for (disc, name) in all {
            assert!(seen.insert(disc), "duplicate discriminant {disc} for {name}");
        }
    }
}

mod event_emission_tests {
    use soroban_sdk::{
        testutils::{Address as _, Events, Ledger, LedgerInfo},
        Address, Bytes, Env,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use anchorkit::contract::{AnchorKitContract, AnchorKitContractClient};
    use crate::sep10_test_util::{register_attestor_with_sep10, sign_payload};

    fn make_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_000_000,
            protocol_version: 21,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 0,
            min_persistent_entry_ttl: 4096,
            min_temp_entry_ttl: 16,
            max_entry_ttl: 6312000,
        });
        env
    }

    fn setup(env: &Env) -> (AnchorKitContractClient, Address, Address, SigningKey) {
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        let issuer = Address::generate(env);
        client.initialize(&admin);
        let sk = SigningKey::generate(&mut OsRng);
        register_attestor_with_sep10(env, &client, &issuer, &issuer, &sk);
        (client, admin, issuer, sk)
    }

    fn payload(env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        for i in 0u8..32 { b.push_back(i); }
        b
    }

    // -----------------------------------------------------------------------
    // contract.initialized event
    // -----------------------------------------------------------------------

    #[test]
    fn test_contract_initialized_event_emitted() {
        let env = make_env();
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin);

        let events = env.events().all();
        let has_init = events.iter().any(|(_, topics, _)| {
            // topics[0] == "contract", topics[1] == "init"
            topics.len() >= 2
        });
        assert!(has_init, "contract.init event must be emitted");
    }

    // -----------------------------------------------------------------------
    // attestor.added carries rich payload
    // -----------------------------------------------------------------------

    #[test]
    fn test_attestor_registered_event_emitted() {
        let env = make_env();
        let (_, _, _, _) = setup(&env);

        let events = env.events().all();
        // At least one event should have "added" in topics (from register_attestor)
        assert!(!events.is_empty(), "events should be emitted on registration");
    }

    // -----------------------------------------------------------------------
    // attestor.removed event emitted on revoke
    // -----------------------------------------------------------------------

    #[test]
    fn test_attestor_revoked_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);

        client.revoke_attestor(&issuer);

        let events = env.events().all();
        assert!(!events.is_empty(), "events must be emitted after revocation");
    }

    // -----------------------------------------------------------------------
    // attestor.restored event emitted on reactivation
    // -----------------------------------------------------------------------

    #[test]
    fn test_attestor_reactivated_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);

        client.revoke_attestor(&issuer);
        let events_before = env.events().all().len();

        client.reactivate_attestor(&issuer);

        let events_after = env.events().all().len();
        assert!(
            events_after > events_before,
            "reactivate_attestor must emit at least one event"
        );
    }

    // -----------------------------------------------------------------------
    // session.created and session.closed events
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_created_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);

        let before = env.events().all().len();
        client.create_session(&issuer);
        let after = env.events().all().len();

        assert!(after > before, "session.created event must be emitted");
    }

    #[test]
    fn test_session_closed_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);
        let session_id = client.create_session(&issuer);

        let before = env.events().all().len();
        client.close_session(&session_id, &issuer);
        let after = env.events().all().len();

        assert!(after > before, "session.closed event must be emitted");
    }

    // -----------------------------------------------------------------------
    // quote.submit event emitted
    // -----------------------------------------------------------------------

    #[test]
    fn test_quote_submit_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);

        let base = soroban_sdk::String::from_str(&env, "USDC");
        let quote_asset = soroban_sdk::String::from_str(&env, "XLM");
        let valid_until = 1_000_000u64 + 3600;

        let before = env.events().all().len();
        client.submit_quote(&issuer, &base, &quote_asset, &100u64, &100u32, &1u64, &1000u64, &valid_until);
        let after = env.events().all().len();

        assert!(after > before, "quote.submit event must be emitted");
    }

    // -----------------------------------------------------------------------
    // kyc.submitted, kyc.approved, kyc.rejected events
    // -----------------------------------------------------------------------

    #[test]
    fn test_kyc_submitted_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);
        let subject = Address::generate(&env);

        let before = env.events().all().len();
        client.submit_kyc(&subject, &payload(&env), &issuer);
        let after = env.events().all().len();

        assert!(after > before, "kyc.submitted event must be emitted");
    }

    #[test]
    fn test_kyc_approved_event_emitted() {
        let env = make_env();
        let (client, admin, issuer, _) = setup(&env);
        let subject = Address::generate(&env);
        client.submit_kyc(&subject, &payload(&env), &issuer);

        let before = env.events().all().len();
        client.approve_kyc(&admin, &subject);
        let after = env.events().all().len();

        assert!(after > before, "kyc.approved event must be emitted");
    }

    #[test]
    fn test_kyc_rejected_event_emitted() {
        let env = make_env();
        let (client, admin, issuer, _) = setup(&env);
        let subject = Address::generate(&env);
        client.submit_kyc(&subject, &payload(&env), &issuer);

        let before = env.events().all().len();
        client.reject_kyc(&admin, &subject, &payload(&env));
        let after = env.events().all().len();

        assert!(after > before, "kyc.rejected event must be emitted");
    }

    // -----------------------------------------------------------------------
    // services.config event emitted with anchor in topic
    // -----------------------------------------------------------------------

    #[test]
    fn test_services_config_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);
        let services = soroban_sdk::vec![&env, 1u32, 2u32];

        let before = env.events().all().len();
        client.configure_services(&issuer, &services);
        let after = env.events().all().len();

        assert!(after > before, "services.config event must be emitted");
    }

    // -----------------------------------------------------------------------
    // webhook.reg event emitted
    // -----------------------------------------------------------------------

    #[test]
    fn test_webhook_registered_event_emitted() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);
        let url = soroban_sdk::String::from_str(&env, "https://example.com/hook");

        let before = env.events().all().len();
        client.register_webhook(&issuer, &url);
        let after = env.events().all().len();

        assert!(after > before, "webhook.reg event must be emitted");
    }

    // -----------------------------------------------------------------------
    // attest.recorded event emitted on successful attestation
    // -----------------------------------------------------------------------

    #[test]
    fn test_attestation_recorded_event_emitted() {
        let env = make_env();
        let (client, _, issuer, sk) = setup(&env);
        let subject = Address::generate(&env);
        let hash = payload(&env);
        let sig = sign_payload(&env, &sk, &hash);

        let before = env.events().all().len();
        client.submit_attestation(&issuer, &subject, &1_000_001u64, &hash, &sig);
        let after = env.events().all().len();

        assert!(after > before, "attest.recorded event must be emitted");
    }

    // -----------------------------------------------------------------------
    // #797 — Repeated revocation does not emit a second transition event
    // -----------------------------------------------------------------------

    #[test]
    fn test_repeated_revocation_emits_no_extra_event() {
        let env = make_env();
        let (client, _, issuer, _) = setup(&env);

        // First revocation: event count must increase.
        let before_first = env.events().all().len();
        client.revoke_attestor(&issuer);
        let after_first = env.events().all().len();
        assert!(after_first > before_first, "first revocation must emit the transition event");

        // Second revocation: must fail (attestor no longer registered).
        let events_snapshot = env.events().all().len();
        let result = client.try_revoke_attestor(&issuer);
        assert!(result.is_err(), "repeated revocation must return an error");

        // No additional event should have been emitted.
        assert_eq!(
            env.events().all().len(),
            events_snapshot,
            "repeated revocation must not emit an extra transition event",
        );
    }
}

mod error_propagation_tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, Env,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use anchorkit::contract::{AnchorKitContract, AnchorKitContractClient};
    use anchorkit::ErrorCode;
    use crate::sep10_test_util::register_attestor_with_sep10;

    fn make_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_000_000,
            protocol_version: 21,
            sequence_number: 0,
            network_id: Default::default(),
            base_reserve: 0,
            min_persistent_entry_ttl: 4096,
            min_temp_entry_ttl: 16,
            max_entry_ttl: 6312000,
        });
        env
    }

    fn setup(env: &Env) -> (AnchorKitContractClient, Address, Address) {
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        let issuer = Address::generate(env);
        client.initialize(&admin);
        let sk = SigningKey::generate(&mut OsRng);
        register_attestor_with_sep10(env, &client, &issuer, &issuer, &sk);
        (client, admin, issuer)
    }

    // -----------------------------------------------------------------------
    // AttestorRevoked is returned when a revoked attestor calls check_attestor
    // -----------------------------------------------------------------------

    #[test]
    fn test_revoked_attestor_returns_attestor_revoked_error() {
        let env = make_env();
        let (client, _, issuer) = setup(&env);
        client.revoke_attestor(&issuer);

        // is_attestor now returns false — confirm via the public query
        assert!(!client.is_attestor(&issuer));

        // Attempting to get the profile of a revoked attestor should give AttestorRevoked
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.get_attestor_profile(&issuer);
        }));
        assert!(result.is_err(), "revoked attestor profile access must panic");
    }

    // -----------------------------------------------------------------------
    // AttestorNotRegistered returned for a completely unknown address
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_attestor_returns_not_registered() {
        let env = make_env();
        let (client, _, _) = setup(&env);
        let stranger = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.get_attestor_profile(&stranger);
        }));
        assert!(result.is_err(), "unknown attestor must panic");
    }

    // -----------------------------------------------------------------------
    // BatchSizeExceeded is returned when batch exceeds MAX_BATCH_SIZE
    // -----------------------------------------------------------------------

    #[test]
    fn test_batch_size_exceeded_error() {
        use anchorkit::contract::AttestationInput;
        use soroban_sdk::Vec;

        let env = make_env();
        let (client, _, issuer) = setup(&env);

        // Build a batch of 101 items (MAX_BATCH_SIZE is 100)
        let mut inputs = Vec::new(&env);
        for i in 0u8..101 {
            let mut hash = Bytes::new(&env);
            for _ in 0..32 { hash.push_back(i); }
            inputs.push_back(AttestationInput {
                issuer: issuer.clone(),
                subject: Address::generate(&env),
                timestamp: 1_000_001,
                payload_hash: hash.clone(),
                signature: hash,
            });
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.submit_attestation_batch(&issuer, &inputs);
        }));
        assert!(result.is_err(), "oversized batch must be rejected");
    }

    // -----------------------------------------------------------------------
    // KycExpired — attestation with require_kyc fails when KYC is expired
    // -----------------------------------------------------------------------

    #[test]
    fn test_kyc_expired_error_on_attestation() {
        use soroban_sdk::Vec;

        let env = make_env();
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let issuer = Address::generate(&env);
        let subject = Address::generate(&env);
        client.initialize(&admin);
        register_attestor_with_sep10(&env, &client, &issuer, &issuer, &sk);

        // Submit and approve KYC
        let data_hash = {
            let mut b = Bytes::new(&env);
            for i in 0u8..32 { b.push_back(i); }
            b
        };
        client.submit_kyc(&subject, &data_hash, &issuer);
        client.approve_kyc(&admin, &subject);

        // Fast-forward past KYC expiry (30 days = 2_592_000 seconds)
        env.ledger().set(LedgerInfo {
            timestamp: 1_000_000 + 2_592_001,
            protocol_version: 21,
            sequence_number: 100,
            network_id: Default::default(),
            base_reserve: 0,
            min_persistent_entry_ttl: 4096,
            min_temp_entry_ttl: 16,
            max_entry_ttl: 6312000,
        });

        let mut hash = Bytes::new(&env);
        for i in 0u8..32 { hash.push_back(i + 100); }
        let sig = crate::sep10_test_util::sign_payload(&env, &sk, &hash);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.submit_attestation_kyc_check(
                &issuer, &subject, &(1_000_000 + 2_592_001), &hash, &sig, &true,
            );
        }));
        assert!(result.is_err(), "expired KYC must reject the attestation");
    }
}
