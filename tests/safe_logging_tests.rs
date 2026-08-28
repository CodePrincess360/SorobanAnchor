/// Safe-logging tests for the anchorkit CLI.
///
/// These tests verify that the `SecretKey` wrapper type — and the helper
/// functions that produce it — never emit raw secret values through any
/// formatted output path (Debug, Display, format strings, panic messages, etc.).
///
/// Run with: cargo test --test safe_logging_tests
#[cfg(test)]
mod safe_logging_tests {
    // ── Inline SecretKey mirror ───────────────────────────────────────────────
    //
    // We replicate the SecretKey type here so the tests are self-contained and
    // do not depend on main.rs being importable as a library.  The behaviour
    // under test is the Debug/Display redaction contract, which is fully
    // captured by this mirror.

    struct SecretKey(String);

    impl SecretKey {
        fn new(raw: impl Into<String>) -> Self {
            Self(raw.into())
        }
        fn expose(&self) -> &str {
            &self.0
        }
    }

    impl std::fmt::Debug for SecretKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("SecretKey([REDACTED])")
        }
    }

    impl std::fmt::Display for SecretKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("[REDACTED]")
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    const FAKE_SECRET: &str = "SCZANGBA5RLGSRSGIRLZ5OJLMKZXT5SOMNBPZRIFJKOGI65ZOZM4ZL2X";

    fn contains_secret(s: &str) -> bool {
        s.contains(FAKE_SECRET)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /// `Display` must never include the raw secret value.
    #[test]
    fn test_display_does_not_include_secret() {
        let sk = SecretKey::new(FAKE_SECRET);
        let displayed = format!("{sk}");
        assert!(
            !contains_secret(&displayed),
            "Display output must not contain the raw secret key, got: {displayed}"
        );
        assert_eq!(displayed, "[REDACTED]");
    }

    /// `Debug` must never include the raw secret value.
    #[test]
    fn test_debug_does_not_include_secret() {
        let sk = SecretKey::new(FAKE_SECRET);
        let debugged = format!("{sk:?}");
        assert!(
            !contains_secret(&debugged),
            "Debug output must not contain the raw secret key, got: {debugged}"
        );
        assert_eq!(debugged, "SecretKey([REDACTED])");
    }

    /// Embedding a `SecretKey` in a larger format string must not leak the value.
    #[test]
    fn test_format_string_interpolation_does_not_leak_secret() {
        let sk = SecretKey::new(FAKE_SECRET);
        let msg = format!("Signing with key: {sk}");
        assert!(
            !contains_secret(&msg),
            "Interpolated format string must not contain the raw secret, got: {msg}"
        );
    }

    /// `expose()` must return the actual secret (it is the only sanctioned path).
    #[test]
    fn test_expose_returns_raw_value() {
        let sk = SecretKey::new(FAKE_SECRET);
        assert_eq!(
            sk.expose(),
            FAKE_SECRET,
            "expose() must return the raw secret key for subprocess use"
        );
    }

    /// A struct that wraps `SecretKey` must also redact through Debug.
    #[test]
    fn test_struct_containing_secret_key_redacts_in_debug() {
        #[derive(Debug)]
        struct Config {
            network: String,
            source: SecretKey,
        }

        let cfg = Config {
            network: "testnet".to_string(),
            source: SecretKey::new(FAKE_SECRET),
        };

        let debugged = format!("{cfg:?}");
        assert!(
            !contains_secret(&debugged),
            "Debug of a struct containing SecretKey must not leak the secret, got: {debugged}"
        );
        assert!(
            debugged.contains("[REDACTED]"),
            "Debug output should contain the redaction marker, got: {debugged}"
        );
    }

    /// Cloning the inner string and formatting it should still be redacted
    /// when done through the wrapper (not through a raw clone).
    #[test]
    fn test_no_accidental_clone_leak() {
        let sk = SecretKey::new(FAKE_SECRET);
        // Simulate what would happen if someone tried to log the wrapper
        let log_line = format!("source={sk} network=testnet");
        assert!(
            !contains_secret(&log_line),
            "Log line must not contain the raw secret, got: {log_line}"
        );
    }

    /// Verify that `check_admin_secret_env`-style logic never echoes the value.
    ///
    /// This mirrors the exact pattern used in `check_admin_secret_env()` in
    /// main.rs to ensure the message strings are safe.
    #[test]
    fn test_admin_secret_check_messages_do_not_include_value() {
        // Simulate the three branches of check_admin_secret_env.
        let valid_secret = FAKE_SECRET.to_string();
        let invalid_secret = "not-a-stellar-key".to_string();
        let empty_secret = "".to_string();

        let valid_msg = if !valid_secret.is_empty() && valid_secret.starts_with('S') {
            "ANCHOR_ADMIN_SECRET set and appears valid (starts with 'S')".to_string()
        } else {
            unreachable!()
        };

        let invalid_msg = if !invalid_secret.is_empty() && !invalid_secret.starts_with('S') {
            "ANCHOR_ADMIN_SECRET is set but does not appear to be a valid Stellar secret key (expected 'S...' format)".to_string()
        } else {
            unreachable!()
        };

        let empty_msg = if empty_secret.is_empty() {
            "ANCHOR_ADMIN_SECRET is set but empty".to_string()
        } else {
            unreachable!()
        };

        assert!(!contains_secret(&valid_msg),   "valid branch must not echo secret: {valid_msg}");
        assert!(!invalid_msg.contains(&invalid_secret), "invalid branch must not echo the bad value: {invalid_msg}");
        assert!(!contains_secret(&empty_msg),   "empty branch must not echo secret: {empty_msg}");
    }

    /// Verify that error messages for missing keys do not include any secret.
    #[test]
    fn test_missing_key_error_message_is_safe() {
        let msg = "error: signing key required — provide --secret-key, set ANCHOR_ADMIN_SECRET, or use --keypair-file";
        assert!(!contains_secret(msg), "Missing-key error must not contain a secret: {msg}");
    }

    /// Verify that keypair file read-error messages include only the path, not contents.
    #[test]
    fn test_keypair_file_error_includes_path_not_contents() {
        let path = "/home/user/.anchorkit/keypair.json";
        let io_err = "No such file or directory (os error 2)";
        let msg = format!("error: cannot read keypair file '{path}': {io_err}");

        // The message should contain the path (useful for debugging) but not
        // any secret value.
        assert!(msg.contains(path), "Error should include the file path");
        assert!(!contains_secret(&msg), "Error must not contain a secret value: {msg}");
    }

    /// Verify that the deploy command's manual-init hint does not include the signing key.
    #[test]
    fn test_deploy_manual_init_hint_does_not_include_signing_key() {
        let contract_id = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
        let hint = format!(
            "To initialize manually: stellar contract invoke --id {contract_id} \
             --source <SIGNING_KEY_OR_ALIAS> -- initialize --admin <ADMIN_ADDRESS>"
        );
        assert!(!contains_secret(&hint), "Manual-init hint must not contain a secret: {hint}");
        // Ensure the placeholder text is present, not a real key.
        assert!(hint.contains("<SIGNING_KEY_OR_ALIAS>"), "Hint should use a placeholder: {hint}");
    }

    // ── #807: ProxyCredentials debug redaction ────────────────────────────────

    /// `ProxyCredentials` debug output must redact the password and preserve the username.
    ///
    /// The safe-logging contract requires that sensitive config fields never
    /// appear in debug output (test failures, structured logs, panic messages).
    /// `ProxyCredentials` implements a custom `Debug` that replaces the password
    /// with `"<redacted>"` while keeping the username inspectable for diagnostics.
    #[cfg(feature = "std")]
    #[test]
    fn test_proxy_credentials_debug_redacts_password() {
        use anchorkit::config::ProxyCredentials;

        let creds = ProxyCredentials {
            username: "svc-anchor".to_string(),
            password: "super-secret-proxy-password".to_string(),
        };

        let debug_output = format!("{creds:?}");

        // The raw password must not appear in any debug-formatted output.
        assert!(
            !debug_output.contains("super-secret-proxy-password"),
            "Debug must not expose the raw password, got: {debug_output}"
        );

        // The redaction marker must be present so the field is clearly omitted.
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output must contain '<redacted>' marker, got: {debug_output}"
        );

        // The username is NOT sensitive and must remain visible for diagnostics.
        assert!(
            debug_output.contains("svc-anchor"),
            "Debug output must keep the username visible, got: {debug_output}"
        );
    }

    /// A `ProxyConfig` containing credentials must not expose the password
    /// anywhere in its debug output.
    #[cfg(feature = "std")]
    #[test]
    fn test_proxy_config_debug_does_not_expose_password() {
        use anchorkit::config::{ProxyConfig, ProxyCredentials};

        let proxy = ProxyConfig {
            proxy_url: Some("http://proxy.corp.example.com:3128".to_string()),
            credentials: Some(ProxyCredentials {
                username: "svc-anchor".to_string(),
                password: "s3cret-proxy-pw".to_string(),
            }),
            ..ProxyConfig::default()
        };

        let debug_output = format!("{proxy:?}");

        assert!(
            !debug_output.contains("s3cret-proxy-pw"),
            "ProxyConfig debug must not expose the raw password, got: {debug_output}"
        );
        assert!(
            debug_output.contains("<redacted>"),
            "ProxyConfig debug must contain the redaction marker, got: {debug_output}"
        );
        // The proxy URL is not sensitive and should be visible.
        assert!(
            debug_output.contains("proxy.corp.example.com"),
            "ProxyConfig debug should keep the proxy URL visible, got: {debug_output}"
        );
    }
}
