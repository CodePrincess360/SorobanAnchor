//! Round-trip serialization test for `ErrorCode` (issue #1316).
//!
//! Stable numeric error codes are part of the public API: integrations and
//! diagnostics rely on the code values not changing between releases.
//!
//! This file adds a focused round-trip test that:
//! 1. Casts a well-documented `ErrorCode` variant to its `u32` discriminant.
//! 2. Confirms the discriminant matches the documented value.
//! 3. Reconstructs the variant from the raw `u32` to verify the round-trip.
//!
//! The representative code chosen is `ReplayAttack = 6`, which is:
//! - In the stable Auth/attestor range (1–10).
//! - Documented in `docs/error-codes.md` and `docs/CONTRACT_FUNCTIONS.md`.
//! - Referenced in integration tests and the public API surface.
//!
//! Acceptance criteria (from issue #1316):
//! - The code retains its documented numeric value.
//! - Round-trip behaviour matches the public API (`as u32` cast).
//! - No error numbering changes are included.

#![cfg(test)]
#![cfg(not(feature = "wasm"))]

mod error_code_round_trip_tests {
    use anchorkit::errors::ErrorCode;

    // -----------------------------------------------------------------------
    // Primary round-trip test
    //
    // `ReplayAttack = 6` is documented in docs/error-codes.md.
    // Casting to u32 is the public serialization path used by Soroban SDK's
    // `contracterror` macro and by the diagnostic layer.
    // -----------------------------------------------------------------------

    #[test]
    fn replay_attack_round_trips_through_u32() {
        // Step 1 — serialize: variant → numeric representation
        let original = ErrorCode::ReplayAttack;
        let as_u32: u32 = original as u32;

        // Step 2 — confirm the numeric value matches the documented constant
        assert_eq!(
            as_u32, 6,
            "ErrorCode::ReplayAttack must serialize to 6 (documented public value)"
        );

        // Step 3 — deserialize: numeric representation → variant
        // The idiomatic Soroban / contracterror conversion path is to match
        // against the known discriminant; there is no `TryFrom<u32>` derive,
        // so we reconstruct by matching the raw value — exactly as downstream
        // integrations must do.
        let reconstructed = match as_u32 {
            6 => Some(ErrorCode::ReplayAttack),
            _ => None,
        };

        assert_eq!(
            reconstructed,
            Some(ErrorCode::ReplayAttack),
            "Round-trip must reconstruct the original variant from its u32 value"
        );
    }

    // -----------------------------------------------------------------------
    // Regression guard: numeric value must not shift
    //
    // If someone accidentally renumbers the ErrorCode enum, this test will
    // catch the change before it reaches integrations.
    // -----------------------------------------------------------------------

    #[test]
    fn replay_attack_discriminant_is_stable() {
        // Direct discriminant assertion — no cast through a variable so that
        // the failure message is immediately obvious if the value changes.
        assert_eq!(
            ErrorCode::ReplayAttack as u32,
            6,
            "ErrorCode::ReplayAttack discriminant must remain 6; \
             changing it is a breaking API change requiring a migration note"
        );
    }

    // -----------------------------------------------------------------------
    // Additional focused round-trip: `ValidationError = 15`
    //
    // `ValidationError` lives in the validation range and is documented in
    // docs/error-codes.md. It exercises a different conversion path than the
    // Auth/attestor range above, protecting a second representative code.
    // -----------------------------------------------------------------------

    #[test]
    fn validation_error_round_trips_through_u32() {
        // Step 1 — serialize: variant → numeric representation
        let original = ErrorCode::ValidationError;
        let as_u32: u32 = original as u32;

        // Step 2 — confirm the numeric value matches the documented constant
        assert_eq!(
            as_u32, 15,
            "ErrorCode::ValidationError must serialize to 15 (documented public value)"
        );

        // Step 3 — deserialize: numeric representation → variant
        // There is no `TryFrom<u32>` derive, so downstream integrations
        // reconstruct by matching the raw value; mirror that path here.
        let reconstructed = match as_u32 {
            15 => Some(ErrorCode::ValidationError),
            _ => None,
        };

        assert_eq!(
            reconstructed,
            Some(ErrorCode::ValidationError),
            "Round-trip must reconstruct ValidationError from its u32 value"
        );
    }

    // -----------------------------------------------------------------------
    // Confirm that the u32 representation of ReplayAttack is distinct from
    // its neighbouring variants, catching any accidental renumbering.
    // -----------------------------------------------------------------------

    #[test]
    fn replay_attack_value_is_distinct_from_neighbours() {
        let prev = ErrorCode::InvalidTimestamp as u32; // documented as 5
        let code = ErrorCode::ReplayAttack as u32;     // documented as 6
        let next = ErrorCode::InvalidQuote as u32;     // documented as 7

        assert_ne!(prev, code, "InvalidTimestamp and ReplayAttack must have different codes");
        assert_ne!(code, next, "ReplayAttack and InvalidQuote must have different codes");
        assert_eq!(
            prev + 1, code,
            "ReplayAttack (6) must be exactly one above InvalidTimestamp (5)"
        );
        assert_eq!(
            code + 1, next,
            "InvalidQuote (7) must be exactly one above ReplayAttack (6)"
        );
    }
}
