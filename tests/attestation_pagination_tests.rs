#![cfg(test)]

mod sep10_test_util;

mod attestation_pagination_tests {
    use soroban_sdk::{
        testutils::{Address as _, Ledger, LedgerInfo},
        Address, Bytes, Env, Vec,
    };

    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use anchorkit::contract::{
        AnchorKitContract, AnchorKitContractClient, AttestationFilter,
    };
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

    fn unique_payload(env: &Env, seed: u8) -> Bytes {
        let mut b = Bytes::new(env);
        for _ in 0..31 {
            b.push_back(0xAA);
        }
        b.push_back(seed);
        b
    }

    // -----------------------------------------------------------------------
    // Empty result set
    // -----------------------------------------------------------------------

    #[test]
    fn empty_store_returns_empty_page() {
        let env = make_env();
        let (client, _, _) = setup(&env);

        let page = client.get_attestations_paginated(&0u64, &10u64, &None);
        assert_eq!(page.records.len(), 0);
        assert_eq!(page.total, 0);
        assert_eq!(page.next_offset, 0);
    }

    #[test]
    fn filter_with_no_matching_issuer_returns_empty_page() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Submit one attestation
        let ph = unique_payload(&env, 0x01);
        let sig = sign_payload(&env, &sk, &ph);
        client.submit_attestation(&attestor, &subject, &1_000_001u64, &ph, &sig);

        // Filter for a different issuer — should return zero records
        let other = Address::generate(&env);
        let filter = AttestationFilter {
            issuer: Some(other),
            subject: None,
            from_timestamp: None,
            to_timestamp: None,
            min_id: None,
        };
        let page = client.get_attestations_paginated(&0u64, &10u64, &Some(filter));
        assert_eq!(page.records.len(), 0);
        assert_eq!(page.total, 1); // total unfiltered count is still 1
    }

    // -----------------------------------------------------------------------
    // Single page — no filter
    // -----------------------------------------------------------------------

    #[test]
    fn retrieves_all_records_when_limit_exceeds_count() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        for seed in 0u8..5 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(
                &attestor,
                &subject,
                &(1_000_001u64 + seed as u64),
                &ph,
                &sig,
            );
        }

        let page = client.get_attestations_paginated(&0u64, &50u64, &None);
        assert_eq!(page.records.len(), 5);
        assert_eq!(page.total, 5);
        assert_eq!(page.next_offset, 5); // last page → next_offset == total
    }

    // -----------------------------------------------------------------------
    // Multi-page retrieval
    // -----------------------------------------------------------------------

    #[test]
    fn multi_page_retrieval_covers_all_records() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Submit 7 attestations
        for seed in 0u8..7 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(
                &attestor,
                &subject,
                &(1_000_001u64 + seed as u64),
                &ph,
                &sig,
            );
        }

        // Page 1: records 0-2
        let page1 = client.get_attestations_paginated(&0u64, &3u64, &None);
        assert_eq!(page1.records.len(), 3);
        assert_eq!(page1.next_offset, 3);
        assert_eq!(page1.total, 7);

        // Page 2: records 3-5
        let page2 = client.get_attestations_paginated(&page1.next_offset, &3u64, &None);
        assert_eq!(page2.records.len(), 3);
        assert_eq!(page2.next_offset, 6);

        // Page 3: record 6 (last page)
        let page3 = client.get_attestations_paginated(&page2.next_offset, &3u64, &None);
        assert_eq!(page3.records.len(), 1);
        assert_eq!(page3.next_offset, 7); // == total → signals last page

        // No duplicates across all pages — collect all IDs
        let mut all_ids: std::vec::Vec<u64> = std::vec::Vec::new();
        for r in page1.records.iter() { all_ids.push(r.id); }
        for r in page2.records.iter() { all_ids.push(r.id); }
        for r in page3.records.iter() { all_ids.push(r.id); }
        all_ids.sort_unstable();
        all_ids.dedup();
        assert_eq!(all_ids.len(), 7, "duplicates or gaps across pages");
    }

    #[test]
    fn page_beyond_end_returns_empty() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        for seed in 0u8..3 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(
                &attestor,
                &subject,
                &(1_000_001u64 + seed as u64),
                &ph,
                &sig,
            );
        }

        // Offset past the total count
        let page = client.get_attestations_paginated(&100u64, &10u64, &None);
        assert_eq!(page.records.len(), 0);
        assert_eq!(page.total, 3);
    }

    // -----------------------------------------------------------------------
    // Filter: issuer
    // -----------------------------------------------------------------------

    #[test]
    fn filter_by_issuer_returns_only_matching_records() {
        let env = make_env();
        let contract_id = env.register_contract(None, AnchorKitContract);
        let client = AnchorKitContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        // Register two attestors
        let sk_a = SigningKey::generate(&mut OsRng);
        let attestor_a = Address::generate(&env);
        register_attestor_with_sep10(&env, &client, &attestor_a, &attestor_a, &sk_a);

        let sk_b = SigningKey::generate(&mut OsRng);
        let attestor_b = Address::generate(&env);
        register_attestor_with_sep10(&env, &client, &attestor_b, &attestor_b, &sk_b);

        let subject = Address::generate(&env);

        // attestor_a submits 3, attestor_b submits 2
        for seed in 0u8..3 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk_a, &ph);
            client.submit_attestation(&attestor_a, &subject, &(1_000_001u64 + seed as u64), &ph, &sig);
        }
        for seed in 3u8..5 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk_b, &ph);
            client.submit_attestation(&attestor_b, &subject, &(1_000_004u64 + seed as u64), &ph, &sig);
        }

        let filter = AttestationFilter {
            issuer: Some(attestor_a.clone()),
            subject: None,
            from_timestamp: None,
            to_timestamp: None,
            min_id: None,
        };
        let page = client.get_attestations_paginated(&0u64, &50u64, &Some(filter));
        assert_eq!(page.records.len(), 3);
        for r in page.records.iter() {
            assert_eq!(r.issuer, attestor_a);
        }
    }

    // -----------------------------------------------------------------------
    // Filter: subject
    // -----------------------------------------------------------------------

    #[test]
    fn filter_by_subject_returns_only_matching_records() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject_a = Address::generate(&env);
        let subject_b = Address::generate(&env);

        for seed in 0u8..3 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(&attestor, &subject_a, &(1_000_001u64 + seed as u64), &ph, &sig);
        }
        for seed in 3u8..5 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(&attestor, &subject_b, &(1_000_004u64 + seed as u64), &ph, &sig);
        }

        let filter = AttestationFilter {
            issuer: None,
            subject: Some(subject_b.clone()),
            from_timestamp: None,
            to_timestamp: None,
            min_id: None,
        };
        let page = client.get_attestations_paginated(&0u64, &50u64, &Some(filter));
        assert_eq!(page.records.len(), 2);
        for r in page.records.iter() {
            assert_eq!(r.subject, subject_b);
        }
    }

    // -----------------------------------------------------------------------
    // Filter: timestamp range
    // -----------------------------------------------------------------------

    #[test]
    fn filter_by_timestamp_range_returns_correct_records() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Submit 5 records with timestamps 100, 200, 300, 400, 500
        for i in 1u8..=5 {
            let ph = unique_payload(&env, i);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(&attestor, &subject, &(i as u64 * 100), &ph, &sig);
        }

        let filter = AttestationFilter {
            issuer: None,
            subject: None,
            from_timestamp: Some(200),
            to_timestamp: Some(400),
            min_id: None,
        };
        let page = client.get_attestations_paginated(&0u64, &50u64, &Some(filter));
        assert_eq!(page.records.len(), 3); // ts 200, 300, 400
        for r in page.records.iter() {
            assert!(r.timestamp >= 200 && r.timestamp <= 400);
        }
    }

    // -----------------------------------------------------------------------
    // Filter: min_id
    // -----------------------------------------------------------------------

    #[test]
    fn filter_by_min_id_skips_earlier_records() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        for seed in 0u8..6 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(&attestor, &subject, &(1_000_001u64 + seed as u64), &ph, &sig);
        }

        // IDs are 0-5; min_id=3 should return IDs 3,4,5
        let filter = AttestationFilter {
            issuer: None,
            subject: None,
            from_timestamp: None,
            to_timestamp: None,
            min_id: Some(3),
        };
        let page = client.get_attestations_paginated(&0u64, &50u64, &Some(filter));
        assert_eq!(page.records.len(), 3);
        for r in page.records.iter() {
            assert!(r.id >= 3);
        }
    }

    // -----------------------------------------------------------------------
    // Determinism — same inputs, same output
    // -----------------------------------------------------------------------

    #[test]
    fn pagination_is_deterministic() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        for seed in 0u8..4 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(&attestor, &subject, &(1_000_001u64 + seed as u64), &ph, &sig);
        }

        let page_a = client.get_attestations_paginated(&0u64, &10u64, &None);
        let page_b = client.get_attestations_paginated(&0u64, &10u64, &None);

        assert_eq!(page_a.records.len(), page_b.records.len());
        for i in 0..page_a.records.len() {
            assert_eq!(page_a.records.get(i as u32).unwrap().id,
                       page_b.records.get(i as u32).unwrap().id);
        }
    }

    // -----------------------------------------------------------------------
    // Limit is capped at 50
    // -----------------------------------------------------------------------

    #[test]
    fn limit_is_capped_at_50() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Submit 55 records — pagination cap should never return more than 50
        for seed in 0u8..55 {
            let ph = unique_payload(&env, seed % 200);
            // Make each hash unique by mixing seed into two bytes
            let mut unique = Bytes::new(&env);
            for _ in 0..30 { unique.push_back(0xBB); }
            unique.push_back(seed);
            unique.push_back(seed.wrapping_add(1));
            let sig = sign_payload(&env, &sk, &unique);
            client.submit_attestation(&attestor, &subject, &(1_000_001u64 + seed as u64), &unique, &sig);
        }

        let page = client.get_attestations_paginated(&0u64, &200u64, &None);
        assert!(page.records.len() <= 50, "page returned more than 50 records");
    }

    // -----------------------------------------------------------------------
    // #800 — Zero limit is rejected
    // -----------------------------------------------------------------------

    #[test]
    fn zero_limit_is_rejected() {
        let env = make_env();
        let (client, _, _) = setup(&env);

        // A zero limit must be rejected before any storage access.
        let result = client.try_get_attestations_paginated(&0u64, &0u64, &None);
        assert!(
            result.is_err(),
            "expected error for zero limit, but got Ok"
        );
    }

    // -----------------------------------------------------------------------
    // #799 — Cursor beyond collection boundary returns empty page
    // -----------------------------------------------------------------------

    #[test]
    fn cursor_beyond_end_returns_empty_page() {
        let env = make_env();
        let (client, attestor, sk) = setup(&env);
        let subject = Address::generate(&env);

        // Submit 3 attestations so total == 3.
        for seed in 0u8..3 {
            let ph = unique_payload(&env, seed);
            let sig = sign_payload(&env, &sk, &ph);
            client.submit_attestation(
                &attestor,
                &subject,
                &(1_000_001u64 + seed as u64),
                &ph,
                &sig,
            );
        }

        // A cursor exactly at the boundary (offset == total) must return empty.
        let page_at_boundary = client.get_attestations_paginated(&3u64, &10u64, &None);
        assert_eq!(
            page_at_boundary.records.len(),
            0,
            "expected empty page when offset == total"
        );
        assert_eq!(page_at_boundary.total, 3);

        // A cursor well past the end must also return empty without panic.
        let page_past_end = client.get_attestations_paginated(&1000u64, &10u64, &None);
        assert_eq!(
            page_past_end.records.len(),
            0,
            "expected empty page when offset >> total"
        );
        assert_eq!(page_past_end.total, 3);
    }
}
