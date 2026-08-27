//! Off-chain trace context that survives retries, webhook delivery attempts and
//! background monitoring.
//!
//! A single logical request usually fans out into many physical operations: an
//! anchor call is retried three times, a webhook is delivered on the fourth
//! attempt, a streaming monitor polls the same transaction for an hour. Without
//! an explicit carrier, each of those operations looks unrelated in the logs.
//!
//! [`TraceContext`] is that carrier. It holds a `trace_id` that stays constant
//! for the whole logical request and a `span_id` that identifies the current
//! step. Every derived step ([`TraceContext::child`],
//! [`TraceContext::child_for_attempt`]) keeps the `trace_id` and records the
//! span it came from, so an operator can follow a request from entry to
//! completion by grepping a single identifier.
//!
//! # Relationship to the on-chain tracing types
//!
//! The contract layer has its own [`RequestId`](crate::contract::RequestId) /
//! [`TracingSpan`](crate::contract::TracingSpan) pair for on-ledger spans. This
//! module is the host-side equivalent: same parent/child span model, but built
//! on `alloc` strings so it can travel in HTTP headers and log lines.
//!
//! # Wire format
//!
//! [`TraceContext::to_traceparent`] and [`TraceContext::parse_traceparent`]
//! implement the W3C Trace Context `traceparent` header, so context propagates
//! to and from services that already speak that format:
//!
//! ```text
//! 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01
//! ^  ^                                ^                ^
//! |  trace-id (16 bytes)              span-id (8 bytes) flags
//! version
//! ```
//!
//! # Determinism
//!
//! Span IDs are derived with SHA-256 rather than drawn from an RNG. The same
//! parent span and the same seed always produce the same child span, which
//! keeps retry behaviour reproducible in tests and avoids requiring a random
//! source in `no_std` builds.
//!
//! # Examples
//!
//! ```rust
//! use anchorkit::trace_context::TraceContext;
//!
//! // Start a trace at the edge of the system.
//! let root = TraceContext::root_from_seed("deposit:txn-001");
//!
//! // Every retry attempt gets its own span but keeps the trace.
//! let attempt_0 = root.child_for_attempt(0);
//! let attempt_1 = root.child_for_attempt(1);
//! assert_eq!(attempt_0.trace_id(), root.trace_id());
//! assert_eq!(attempt_1.trace_id(), root.trace_id());
//! assert_ne!(attempt_0.span_id(), attempt_1.span_id());
//! assert_eq!(attempt_1.parent_span_id(), Some(root.span_id()));
//! ```

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

/// Number of hex characters in a trace ID (16 bytes).
pub const TRACE_ID_HEX_LEN: usize = 32;
/// Number of hex characters in a span ID (8 bytes).
pub const SPAN_ID_HEX_LEN: usize = 16;

/// The `traceparent` version prefix this module emits and accepts.
const TRACEPARENT_VERSION: &str = "00";

/// Header name carrying the full W3C trace context.
pub const TRACEPARENT_HEADER: &str = "traceparent";
/// Header name carrying the bare trace ID, for log-friendly correlation.
pub const TRACE_ID_HEADER: &str = "X-Trace-Id";
/// Header name carrying the current span ID.
pub const SPAN_ID_HEADER: &str = "X-Span-Id";

/// Reasons a trace identifier or `traceparent` header could not be accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceError {
    /// A `traceparent` header did not have the expected four dash-separated fields.
    MalformedTraceparent,
    /// The `traceparent` version field is not `00`.
    UnsupportedVersion,
    /// The trace ID was not 32 lowercase hex characters, or was all zeroes.
    InvalidTraceId,
    /// The span ID was not 16 lowercase hex characters, or was all zeroes.
    InvalidSpanId,
    /// The trace flags field was not two hex characters.
    InvalidFlags,
}

/// Trace context for a single step of a logical request.
///
/// Cloning is cheap relative to the work it accompanies (three short strings),
/// and clones are intentional: each retry attempt, each webhook POST and each
/// poll cycle owns its own context while sharing the trace ID.
///
/// See the [module documentation](self) for the propagation model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceContext {
    trace_id: String,
    span_id: String,
    parent_span_id: Option<String>,
    sampled: bool,
}

impl TraceContext {
    /// Build a context from already-validated parts.
    ///
    /// Returns [`TraceError`] when `trace_id` or `span_id` is not a non-zero
    /// lowercase hex string of the required length.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::new(
    ///     "4bf92f3577b34da6a3ce929d0e0e4736",
    ///     "00f067aa0ba902b7",
    ///     None,
    ///     true,
    /// ).unwrap();
    /// assert_eq!(ctx.span_id(), "00f067aa0ba902b7");
    /// ```
    pub fn new(
        trace_id: &str,
        span_id: &str,
        parent_span_id: Option<&str>,
        sampled: bool,
    ) -> Result<Self, TraceError> {
        if !is_valid_id(trace_id, TRACE_ID_HEX_LEN) {
            return Err(TraceError::InvalidTraceId);
        }
        if !is_valid_id(span_id, SPAN_ID_HEX_LEN) {
            return Err(TraceError::InvalidSpanId);
        }
        if let Some(parent) = parent_span_id {
            if !is_valid_id(parent, SPAN_ID_HEX_LEN) {
                return Err(TraceError::InvalidSpanId);
            }
        }
        Ok(TraceContext {
            trace_id: trace_id.to_owned(),
            span_id: span_id.to_owned(),
            parent_span_id: parent_span_id.map(|p| p.to_owned()),
            sampled,
        })
    }

    /// Start a new root trace whose identifiers are derived from `seed`.
    ///
    /// The same seed always yields the same trace, which makes a natural
    /// idempotency pairing: seed with the transaction ID or payload digest that
    /// already identifies the logical request.
    ///
    /// The result is always valid — a seed that would hash to all zeroes is
    /// nudged so the identifiers stay non-zero.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let a = TraceContext::root_from_seed("withdrawal:txn-77");
    /// let b = TraceContext::root_from_seed("withdrawal:txn-77");
    /// assert_eq!(a.trace_id(), b.trace_id());
    /// assert!(a.parent_span_id().is_none());
    /// ```
    pub fn root_from_seed(seed: &str) -> Self {
        let digest = sha256_hex(seed.as_bytes());
        let trace_id = non_zero_id(&digest[..TRACE_ID_HEX_LEN]);
        let span_id = non_zero_id(&digest[TRACE_ID_HEX_LEN..TRACE_ID_HEX_LEN + SPAN_ID_HEX_LEN]);
        TraceContext {
            trace_id,
            span_id,
            parent_span_id: None,
            sampled: true,
        }
    }

    /// The trace ID shared by every span of this logical request.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The span ID of this particular step.
    pub fn span_id(&self) -> &str {
        &self.span_id
    }

    /// The span this one was derived from, or `None` for a root span.
    pub fn parent_span_id(&self) -> Option<&str> {
        self.parent_span_id.as_deref()
    }

    /// Whether downstream systems are asked to record this trace.
    pub fn sampled(&self) -> bool {
        self.sampled
    }

    /// Return a copy with the sampling flag set to `sampled`.
    pub fn with_sampled(mut self, sampled: bool) -> Self {
        self.sampled = sampled;
        self
    }

    /// Derive a child span under this one, keeping the trace ID.
    ///
    /// `seed` distinguishes siblings — use the operation name, the attempt
    /// number, or anything else stable for that step.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let root = TraceContext::root_from_seed("session-1");
    /// let child = root.child("webhook-delivery");
    /// assert_eq!(child.trace_id(), root.trace_id());
    /// assert_eq!(child.parent_span_id(), Some(root.span_id()));
    /// ```
    pub fn child(&self, seed: &str) -> Self {
        let mut material = String::with_capacity(
            self.trace_id.len() + self.span_id.len() + seed.len() + 2,
        );
        material.push_str(&self.trace_id);
        material.push(':');
        material.push_str(&self.span_id);
        material.push(':');
        material.push_str(seed);

        let digest = sha256_hex(material.as_bytes());
        TraceContext {
            trace_id: self.trace_id.clone(),
            span_id: non_zero_id(&digest[..SPAN_ID_HEX_LEN]),
            parent_span_id: Some(self.span_id.clone()),
            sampled: self.sampled,
        }
    }

    /// Derive the child span for retry attempt `attempt` (0-based).
    ///
    /// Each attempt of a retried operation is a distinct span under the same
    /// trace, so an operator can see how many times a step ran and which
    /// attempt finally succeeded.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let root = TraceContext::root_from_seed("quote-refresh");
    /// let first = root.child_for_attempt(0);
    /// let second = root.child_for_attempt(1);
    /// assert_eq!(first.trace_id(), second.trace_id());
    /// assert_ne!(first.span_id(), second.span_id());
    /// ```
    pub fn child_for_attempt(&self, attempt: u32) -> Self {
        let mut seed = String::from("attempt-");
        push_u32(&mut seed, attempt);
        self.child(&seed)
    }

    /// Render this context as a W3C `traceparent` header value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::new(
    ///     "4bf92f3577b34da6a3ce929d0e0e4736",
    ///     "00f067aa0ba902b7",
    ///     None,
    ///     true,
    /// ).unwrap();
    /// assert_eq!(
    ///     ctx.to_traceparent(),
    ///     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    /// );
    /// ```
    pub fn to_traceparent(&self) -> String {
        let mut out = String::with_capacity(55);
        out.push_str(TRACEPARENT_VERSION);
        out.push('-');
        out.push_str(&self.trace_id);
        out.push('-');
        out.push_str(&self.span_id);
        out.push('-');
        out.push_str(if self.sampled { "01" } else { "00" });
        out
    }

    /// Parse an inbound W3C `traceparent` header value.
    ///
    /// The incoming span becomes this context's span; callers that want to
    /// record themselves as a separate step should follow up with
    /// [`child`](Self::child).
    ///
    /// # Errors
    ///
    /// Returns [`TraceError`] when the header is malformed, uses an unsupported
    /// version, or carries an all-zero identifier.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::parse_traceparent(
    ///     "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    /// ).unwrap();
    /// assert_eq!(ctx.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
    /// assert!(ctx.sampled());
    /// ```
    pub fn parse_traceparent(header: &str) -> Result<Self, TraceError> {
        // Trim transport-level surrounding whitespace at the input boundary only.
        // Individual components after splitting are never trimmed so that
        // internal spaces (e.g. "4bf9 2f35...") are caught by is_valid_id.
        let header = header.trim();
        let mut parts = header.split('-');
        let version = parts.next().ok_or(TraceError::MalformedTraceparent)?;
        let trace_id = parts.next().ok_or(TraceError::MalformedTraceparent)?;
        let span_id = parts.next().ok_or(TraceError::MalformedTraceparent)?;
        let flags = parts.next().ok_or(TraceError::MalformedTraceparent)?;
        if parts.next().is_some() {
            return Err(TraceError::MalformedTraceparent);
        }

        if version != TRACEPARENT_VERSION {
            return Err(TraceError::UnsupportedVersion);
        }
        // Reject an empty trace ID outright. An empty context would otherwise
        // make unrelated requests look correlated and cause downstream exporters
        // to reject the record, so it must never be accepted as a valid trace.
        if trace_id.is_empty() {
            return Err(TraceError::InvalidTraceId);
        }
        if !is_valid_id(trace_id, TRACE_ID_HEX_LEN) {
            return Err(TraceError::InvalidTraceId);
        }
        if !is_valid_id(span_id, SPAN_ID_HEX_LEN) {
            return Err(TraceError::InvalidSpanId);
        }
        if flags.len() != 2 || !flags.bytes().all(is_lower_hex) {
            return Err(TraceError::InvalidFlags);
        }

        let sampled = u8::from_str_radix(flags, 16)
            .map_err(|_| TraceError::InvalidFlags)?
            & 0x01
            != 0;

        Ok(TraceContext {
            trace_id: trace_id.to_owned(),
            span_id: span_id.to_owned(),
            parent_span_id: None,
            sampled,
        })
    }

    /// Headers that carry this context to a downstream service.
    ///
    /// Emits the standard `traceparent` plus the bare `X-Trace-Id` /
    /// `X-Span-Id` pair, which anchors that do not speak W3C trace context can
    /// still log verbatim.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::root_from_seed("payment-9");
    /// let headers = ctx.header_pairs();
    /// assert_eq!(headers.len(), 3);
    /// assert_eq!(headers[0].0, "traceparent");
    /// ```
    pub fn header_pairs(&self) -> Vec<(String, String)> {
        let mut headers = Vec::with_capacity(3);
        headers.push((TRACEPARENT_HEADER.to_owned(), self.to_traceparent()));
        headers.push((TRACE_ID_HEADER.to_owned(), self.trace_id.clone()));
        headers.push((SPAN_ID_HEADER.to_owned(), self.span_id.clone()));
        headers
    }

    /// Render this context as `key=value` pairs for a log line.
    ///
    /// A root span omits `parent_span_id` rather than printing an empty value,
    /// so log parsers can treat its absence as "this is where the trace began".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::trace_context::TraceContext;
    ///
    /// let ctx = TraceContext::root_from_seed("deposit-3");
    /// let fields = ctx.log_fields();
    /// assert!(fields.starts_with("trace_id="));
    /// assert!(!fields.contains("parent_span_id="));
    /// ```
    pub fn log_fields(&self) -> String {
        let mut out = String::with_capacity(80);
        out.push_str("trace_id=");
        out.push_str(&self.trace_id);
        out.push_str(" span_id=");
        out.push_str(&self.span_id);
        if let Some(parent) = &self.parent_span_id {
            out.push_str(" parent_span_id=");
            out.push_str(parent);
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// `true` when `b` is an ASCII lowercase hex digit.
fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// `true` when `id` is exactly `len` lowercase hex characters and not all zero.
///
/// The all-zero check follows the W3C spec: an all-zero trace or span ID means
/// "no trace", and silently accepting one would break correlation downstream.
fn is_valid_id(id: &str, len: usize) -> bool {
    id.len() == len && id.bytes().all(is_lower_hex) && id.bytes().any(|b| b != b'0')
}

/// Return `hex` unchanged, or a non-zero substitute when it is all zeroes.
fn non_zero_id(hex: &str) -> String {
    if hex.bytes().any(|b| b != b'0') {
        hex.to_owned()
    } else {
        let mut fixed = String::from("1");
        fixed.push_str(&hex[1..]);
        fixed
    }
}

/// Lowercase hex SHA-256 of `bytes` (64 characters).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

/// Map a 0..=15 value to its lowercase hex character.
fn hex_nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + (value - 10)) as char,
    }
}

/// Append the decimal representation of `value` to `out`.
///
/// Hand-rolled so the module does not need `alloc::format!` on this hot path —
/// it runs once per retry attempt.
fn push_u32(out: &mut String, value: u32) {
    if value == 0 {
        out.push('0');
        return;
    }
    let mut digits = [0u8; 10];
    let mut len = 0usize;
    let mut n = value;
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    while len > 0 {
        len -= 1;
        out.push(digits[len] as char);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN: &str = "00f067aa0ba902b7";

    #[test]
    fn new_accepts_valid_ids() {
        let ctx = TraceContext::new(TRACE, SPAN, None, true).unwrap();
        assert_eq!(ctx.trace_id(), TRACE);
        assert_eq!(ctx.span_id(), SPAN);
        assert!(ctx.parent_span_id().is_none());
        assert!(ctx.sampled());
    }

    #[test]
    fn new_rejects_bad_trace_id() {
        assert_eq!(
            TraceContext::new("short", SPAN, None, true),
            Err(TraceError::InvalidTraceId)
        );
        assert_eq!(
            TraceContext::new(&"0".repeat(32), SPAN, None, true),
            Err(TraceError::InvalidTraceId)
        );
        assert_eq!(
            TraceContext::new(&"A".repeat(32), SPAN, None, true),
            Err(TraceError::InvalidTraceId)
        );
    }

    #[test]
    fn new_rejects_bad_span_id() {
        assert_eq!(
            TraceContext::new(TRACE, "nope", None, true),
            Err(TraceError::InvalidSpanId)
        );
        assert_eq!(
            TraceContext::new(TRACE, SPAN, Some("nope"), true),
            Err(TraceError::InvalidSpanId)
        );
    }

    #[test]
    fn root_from_seed_is_deterministic_and_valid() {
        let a = TraceContext::root_from_seed("deposit:txn-1");
        let b = TraceContext::root_from_seed("deposit:txn-1");
        assert_eq!(a, b);
        assert_eq!(a.trace_id().len(), TRACE_ID_HEX_LEN);
        assert_eq!(a.span_id().len(), SPAN_ID_HEX_LEN);
        assert!(a.parent_span_id().is_none());
        // Round-trips through the wire format, which validates both IDs.
        assert!(TraceContext::parse_traceparent(&a.to_traceparent()).is_ok());
    }

    #[test]
    fn root_from_seed_differs_per_seed() {
        let a = TraceContext::root_from_seed("deposit:txn-1");
        let b = TraceContext::root_from_seed("deposit:txn-2");
        assert_ne!(a.trace_id(), b.trace_id());
    }

    #[test]
    fn child_keeps_trace_and_records_parent() {
        let root = TraceContext::root_from_seed("session-42");
        let child = root.child("webhook");
        assert_eq!(child.trace_id(), root.trace_id());
        assert_ne!(child.span_id(), root.span_id());
        assert_eq!(child.parent_span_id(), Some(root.span_id()));
    }

    #[test]
    fn child_inherits_sampling_flag() {
        let root = TraceContext::root_from_seed("session-42").with_sampled(false);
        assert!(!root.child("webhook").sampled());
    }

    #[test]
    fn grandchild_still_carries_the_root_trace() {
        let root = TraceContext::root_from_seed("session-42");
        let grandchild = root.child("webhook").child_for_attempt(2);
        assert_eq!(grandchild.trace_id(), root.trace_id());
    }

    #[test]
    fn child_for_attempt_is_stable_and_distinct() {
        let root = TraceContext::root_from_seed("quote");
        assert_eq!(root.child_for_attempt(3), root.child_for_attempt(3));
        assert_ne!(root.child_for_attempt(3), root.child_for_attempt(4));
        for attempt in 0..8u32 {
            let ctx = root.child_for_attempt(attempt);
            assert_eq!(ctx.trace_id(), root.trace_id());
            assert_eq!(ctx.span_id().len(), SPAN_ID_HEX_LEN);
        }
    }

    #[test]
    fn traceparent_round_trip() {
        let ctx = TraceContext::new(TRACE, SPAN, None, true).unwrap();
        let header = ctx.to_traceparent();
        assert_eq!(header, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01");
        let parsed = TraceContext::parse_traceparent(&header).unwrap();
        assert_eq!(parsed.trace_id(), ctx.trace_id());
        assert_eq!(parsed.span_id(), ctx.span_id());
        assert_eq!(parsed.sampled(), ctx.sampled());
    }

    #[test]
    fn traceparent_encodes_unsampled_flag() {
        let ctx = TraceContext::new(TRACE, SPAN, None, false).unwrap();
        assert!(ctx.to_traceparent().ends_with("-00"));
        assert!(!TraceContext::parse_traceparent(&ctx.to_traceparent())
            .unwrap()
            .sampled());
    }

    #[test]
    fn parse_traceparent_rejects_malformed_headers() {
        assert_eq!(
            TraceContext::parse_traceparent("00-abc-def"),
            Err(TraceError::MalformedTraceparent)
        );
        assert_eq!(
            TraceContext::parse_traceparent(&alloc::format!("00-{TRACE}-{SPAN}-01-extra")),
            Err(TraceError::MalformedTraceparent)
        );
        assert_eq!(
            TraceContext::parse_traceparent(&alloc::format!("01-{TRACE}-{SPAN}-01")),
            Err(TraceError::UnsupportedVersion)
        );
        assert_eq!(
            TraceContext::parse_traceparent(&alloc::format!("00-{}-{SPAN}-01", "0".repeat(32))),
            Err(TraceError::InvalidTraceId)
        );
        assert_eq!(
            TraceContext::parse_traceparent(&alloc::format!("00-{TRACE}-{}-01", "0".repeat(16))),
            Err(TraceError::InvalidSpanId)
        );
        assert_eq!(
            TraceContext::parse_traceparent(&alloc::format!("00-{TRACE}-{SPAN}-0")),
            Err(TraceError::InvalidFlags)
        );
    }

    #[test]
    fn header_pairs_carry_all_three_headers() {
        let ctx = TraceContext::new(TRACE, SPAN, None, true).unwrap();
        let headers = ctx.header_pairs();
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0], (TRACEPARENT_HEADER.into(), ctx.to_traceparent()));
        assert_eq!(headers[1], (TRACE_ID_HEADER.into(), TRACE.into()));
        assert_eq!(headers[2], (SPAN_ID_HEADER.into(), SPAN.into()));
    }

    #[test]
    fn log_fields_include_parent_only_for_child_spans() {
        let root = TraceContext::new(TRACE, SPAN, None, true).unwrap();
        assert_eq!(
            root.log_fields(),
            alloc::format!("trace_id={TRACE} span_id={SPAN}")
        );

        let child = root.child("step");
        let fields = child.log_fields();
        assert!(fields.contains(&alloc::format!("trace_id={TRACE}")));
        assert!(fields.contains(&alloc::format!("parent_span_id={SPAN}")));
    }

    #[test]
    fn push_u32_matches_decimal_formatting() {
        for value in [0u32, 1, 9, 10, 99, 100, 4_294_967_295] {
            let mut out = String::new();
            push_u32(&mut out, value);
            assert_eq!(out, alloc::format!("{value}"));
        }
    }

    #[test]
    fn non_zero_id_replaces_all_zero_input() {
        assert_eq!(non_zero_id("0000000000000000"), "1000000000000000");
        assert_eq!(non_zero_id("00f067aa0ba902b7"), "00f067aa0ba902b7");
    }

    // ── Trim-boundary behaviour ──────────────────────────────────────────

    /// Surrounding whitespace on the raw header value is transport noise and
    /// should be tolerated.
    #[test]
    fn parse_traceparent_tolerates_surrounding_whitespace() {
        let header = alloc::format!("  00-{TRACE}-{SPAN}-01  ");
        let ctx = TraceContext::parse_traceparent(&header)
            .expect("surrounding whitespace should be stripped before parsing");
        assert_eq!(ctx.trace_id(), TRACE);
        assert_eq!(ctx.span_id(), SPAN);
        assert!(ctx.sampled());
    }

    /// Internal whitespace inside a semantic field must not be silently
    /// normalised — it is a malformed identifier and must be rejected.
    #[test]
    fn parse_traceparent_rejects_internal_whitespace_in_trace_id() {
        // Inject a space inside the trace-id field.
        let malformed = alloc::format!("00-4bf92f3577b34da6 a3ce929d0e0e4736-{SPAN}-01");
        assert_eq!(
            TraceContext::parse_traceparent(&malformed),
            Err(TraceError::InvalidTraceId),
            "internal whitespace in trace-id must be rejected, not silently trimmed"
        );
    }
}
