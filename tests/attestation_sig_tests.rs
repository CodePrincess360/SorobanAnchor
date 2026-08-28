#![cfg(test)]

mod sep10_test_util;

mod attestation_sig_tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, Env,
    };

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use anchorkit::contract::{AnchorKitContract, AnchorKitContractClient};
    use anchorkit::errors::ErrorCode;
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

    fn setup(env: &Env) -> (AnchorKitContractClient, Address, SigningKey) {
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(env, &contract_id);
        let admin = Address::generate(env);
        client.initialize(&admin);
        let sk = SigningKey::generate(&mut OsRng);
        let attestor = Address::generate(env);
        register_attestor_with_sep10(env, &client, &attestor, &attestor, &sk);
        (client, attestor, sk)
    }

    fn payload(env: &Env, byte: u8) -> Bytes {
        let mut b = Bytes::new(env);
        for _ in 0..32 {
            b.push_back(byte);
        }
        b
    }

    // -----------------------------------------------------------------------
    // Valid signature accepted
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_signature_accepted() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        let ph = payload(&env, 0xAB);
        let sig = sign_payload(&env, &sk, &ph);

        let id = client.submit_attestation(&attestor, &subject, &1_000_001u64, &ph, &sig);
        assert_eq!(id, 0);
    }

    // -----------------------------------------------------------------------
    // Invalid signature rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_signature_rejected() {
        let env = make_env();
        let (client, attestor, _sk) = setup(&env);
        let subject = Address::generate(&env);

        let ph = payload(&env, 0xAB);
        // Wrong key — generate a different key and sign with it
        let wrong_sk = SigningKey::generate(&mut OsRng);
        let bad_sig = sign_payload(&env, &wrong_sk, &ph);

        let result = client.try_submit_attestation(&attestor, &subject, &1_000_001u64, &ph, &bad_sig);
        assert!(result.is_err(), "expected contract error");
    }

    // -----------------------------------------------------------------------
    // Tampered payload rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_tampered_payload_rejected() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        let ph = payload(&env, 0xAB);
        let sig = sign_payload(&env, &sk, &ph);

        // Submit with a different payload hash but the same signature
        let tampered = payload(&env, 0xCD);
        let result = client.try_submit_attestation(&attestor, &subject, &1_000_001u64, &tampered, &sig);
        assert!(result.is_err(), "expected contract error");
    }

    // -----------------------------------------------------------------------
    // Zero timestamp rejected (#794)
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_timestamp_rejected() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        let ph = payload(&env, 0xAB);
        let sig = sign_payload(&env, &sk, &ph);

        let result = client.try_submit_attestation(&attestor, &subject, &0u64, &ph, &sig);
        assert_eq!(
            result.unwrap_err().unwrap(),
            anchorkit::errors::ErrorCode::InvalidTimestamp,
        );
    }

    // -----------------------------------------------------------------------
    // Revoked attestor's signature rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_revoked_attestor_signature_rejected() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Revoke the attestor
        client.revoke_attestor(&attestor);

        let ph = payload(&env, 0xAB);
        let sig = sign_payload(&env, &sk, &ph);

        let result = client.try_submit_attestation(&attestor, &subject, &1_000_001u64, &ph, &sig);
        assert!(result.is_err(), "expected contract error");
    }

    // -----------------------------------------------------------------------
    // Public key stored at registration and removed at revocation
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_removed_on_revocation() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Before revocation: valid sig works
        let ph = payload(&env, 0x01);
        let sig = sign_payload(&env, &sk, &ph);
        let id = client.submit_attestation(&attestor, &subject, &1_000_001u64, &ph, &sig);
        assert_eq!(id, 0);

        // Revoke
        client.revoke_attestor(&attestor);

        // After revocation: attestor is gone
        assert!(!client.is_attestor(&attestor));

        // Re-register with a new key
        let new_sk = SigningKey::generate(&mut OsRng);
        register_attestor_with_sep10(&env, &client, &attestor, &attestor, &new_sk);

        // Old sig no longer works (wrong key for new registration)
        let ph2 = payload(&env, 0x02);
        let old_sig = sign_payload(&env, &sk, &ph2);
        let result = client.try_submit_attestation(&attestor, &subject, &1_000_002u64, &ph2, &old_sig);
        assert!(result.is_err(), "expected contract error");

        // New sig works
        let new_sig = sign_payload(&env, &new_sk, &ph2);
        let id2 = client.submit_attestation(&attestor, &subject, &1_000_002u64, &ph2, &new_sig);
        assert_eq!(id2, 1);
    }
}
