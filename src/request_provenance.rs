//! Request provenance and lineage tracking (#682).
//!
//! Debugging a multi-step anchor workflow is difficult when requests carry no
//! record of where they came from or what triggered them. This module
//! introduces a [`ProvenanceRecord`] that every request can carry, capturing
//! its origin, immediate parent, and the chain of ancestors that led to it.
//!
//! # Design
//!
//! * **Lineage chain.** A [`ProvenanceRecord`] holds a `parent_id` (the
//!   request that directly spawned this one) and an `ancestors` list (the
//!   full chain back to the root). This lets operators reconstruct the entire
//!   call tree from any node.
//! * **Origin metadata.** Records carry the originating service name, an
//!   optional operation label, and a creation timestamp so the time between
//!   hops is visible.
//! * **Immutable once built.** Records are created at request entry and
//!   threaded through the call chain read-only. Child records are derived via
//!   [`ProvenanceRecord::child`], which copies the lineage chain and appends
//!   the current record's ID.
//! * **No `std` dependency.** Works in `no_std + alloc`.
//!
//! # Example
//!
//! ```rust
//! use anchorkit::request_provenance::ProvenanceRecord;
//!
//! // Root request created by the gateway.
//! let root = ProvenanceRecord::root("gateway", "deposit-initiate", 1000).unwrap();
//! assert!(root.parent_id().is_none());
//! assert_eq!(root.depth(), 0);
//!
//! // Downstream service derives a child.
//! let child = root.child("anchor-service", "sep6-deposit", 1001).unwrap();
//! assert_eq!(child.parent_id(), Some(root.request_id()));
//! assert_eq!(child.depth(), 1);
//!
//! // Grandchild keeps the full lineage.
//! let grandchild = child.child("webhook-dispatcher", "notify", 1002).unwrap();
//! assert_eq!(grandchild.depth(), 2);
//! assert_eq!(grandchild.ancestors()[0], root.request_id());
//! assert_eq!(grandchild.ancestors()[1], child.request_id());
//! ```

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

// ---------------------------------------------------------------------------
// ProvenanceError
// ---------------------------------------------------------------------------

/// Reasons a [`ProvenanceRecord`] could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The actor (origin service) identifier was empty or contained only
    /// whitespace. Every provenance record must be attributable to a named
    /// actor so audit logs can be filtered by origin.
    EmptyActor,
    /// Metadata exceeds the maximum allowed length (`MAX_METADATA_LEN`).
    MetadataTooLong {
        len: usize,
        max: usize,
    },
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProvenanceError::EmptyActor => {
                write!(f, "provenance actor (origin service) must not be empty")
            }
            ProvenanceError::MetadataTooLong { len, max } => {
                write!(f, "provenance metadata length {len} exceeds limit of {max} bytes")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ProvenanceRecord
// ---------------------------------------------------------------------------

/// Maximum allowed length in bytes for custom provenance metadata strings.
pub const MAX_METADATA_LEN: usize = 1024;

/// Backward-compatible alias for [`MAX_METADATA_LEN`].
pub const MAX_METADATA_LENGTH: usize = MAX_METADATA_LEN;

/// Provenance and lineage record for a single request.
///
/// Attach one of these to every request that enters the system so that
/// parent–child relationships are preserved across service boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceRecord {
    /// Stable identifier for this request (32 lowercase hex chars).
    request_id: String,
    /// ID of the immediately preceding request, or `None` for root requests.
    parent_id: Option<String>,
    /// Full ancestor chain, oldest first (does not include `request_id` itself).
    ancestors: Vec<String>,
    /// Name of the service that created this record.
    origin_service: String,
    /// Optional label for the operation being performed.
    operation: Option<String>,
    /// Optional custom metadata attached to this record (bounded by [`MAX_METADATA_LEN`]).
    metadata: Option<String>,
    /// Unix timestamp (seconds) when this record was created.
    created_at: u64,
}

impl ProvenanceRecord {
    /// Create a root provenance record (no parent, depth 0).
    ///
    /// `seed` is used to derive a deterministic `request_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError::EmptyActor`] when `origin_service` is empty
    /// or contains only whitespace. Every record must be attributable.
    pub fn root(
        origin_service: impl Into<String>,
        operation: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let svc = origin_service.into();
        if svc.trim().is_empty() {
            return Err(ProvenanceError::EmptyActor);
        }
        let op = operation.into();
        let id = derive_request_id(&format!("root:{}:{}:{}", svc, op, created_at));
        Ok(ProvenanceRecord {
            request_id: id,
            parent_id: None,
            ancestors: Vec::new(),
            origin_service: svc,
            operation: Some(op),
            metadata: None,
            created_at,
        })
    }

    /// Create a root record with an explicit, caller-supplied `request_id`.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError::EmptyActor`] when `origin_service` is empty
    /// or contains only whitespace.
    pub fn root_with_id(
        request_id: impl Into<String>,
        origin_service: impl Into<String>,
        operation: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let svc = origin_service.into();
        if svc.trim().is_empty() {
            return Err(ProvenanceError::EmptyActor);
        }
        Ok(ProvenanceRecord {
            request_id: request_id.into(),
            parent_id: None,
            ancestors: Vec::new(),
            origin_service: svc,
            operation: Some(operation.into()),
            metadata: None,
            created_at,
        })
    }

    /// Create a root record with custom metadata attached, validating that its
    /// length does not exceed [`MAX_METADATA_LEN`].
    pub fn root_with_metadata(
        origin_service: impl Into<String>,
        operation: impl Into<String>,
        metadata: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let root = Self::root(origin_service, operation, created_at)?;
        root.with_metadata(metadata)
    }

    /// Derive a child record from this one.
    ///
    /// The child's `ancestors` list is this record's ancestors plus this
    /// record's own ID, forming a complete lineage chain.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError::EmptyActor`] when `child_service` is empty
    /// or contains only whitespace.
    pub fn child(
        &self,
        child_service: impl Into<String>,
        operation: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let svc = child_service.into();
        if svc.trim().is_empty() {
            return Err(ProvenanceError::EmptyActor);
        }
        let op = operation.into();
        let id = derive_request_id(&format!(
            "child:{}:{}:{}:{}",
            self.request_id, svc, op, created_at
        ));

        let mut ancestors = self.ancestors.clone();
        ancestors.push(self.request_id.clone());

        Ok(ProvenanceRecord {
            request_id: id,
            parent_id: Some(self.request_id.clone()),
            ancestors,
            origin_service: svc,
            operation: Some(op),
            metadata: None,
            created_at,
        })
    }

    /// Derive a child with an explicit caller-supplied ID.
    ///
    /// # Errors
    ///
    /// Returns [`ProvenanceError::EmptyActor`] when `child_service` is empty
    /// or contains only whitespace.
    pub fn child_with_id(
        &self,
        child_id: impl Into<String>,
        child_service: impl Into<String>,
        operation: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let svc = child_service.into();
        if svc.trim().is_empty() {
            return Err(ProvenanceError::EmptyActor);
        }
        let mut ancestors = self.ancestors.clone();
        ancestors.push(self.request_id.clone());

        Ok(ProvenanceRecord {
            request_id: child_id.into(),
            parent_id: Some(self.request_id.clone()),
            ancestors,
            origin_service: svc,
            operation: Some(operation.into()),
            metadata: None,
            created_at,
        })
    }

    /// Derive a child record with custom metadata attached, validating that its
    /// length does not exceed [`MAX_METADATA_LEN`].
    pub fn child_with_metadata(
        &self,
        child_service: impl Into<String>,
        operation: impl Into<String>,
        metadata: impl Into<String>,
        created_at: u64,
    ) -> Result<Self, ProvenanceError> {
        let child = self.child(child_service, operation, created_at)?;
        child.with_metadata(metadata)
    }

    /// Validate that a metadata string does not exceed [`MAX_METADATA_LEN`].
    pub fn validate_metadata(metadata: &str) -> Result<(), ProvenanceError> {
        if metadata.len() > MAX_METADATA_LEN {
            Err(ProvenanceError::MetadataTooLong {
                len: metadata.len(),
                max: MAX_METADATA_LEN,
            })
        } else {
            Ok(())
        }
    }

    /// Return `true` if `metadata` is within the maximum permitted length.
    pub fn is_metadata_valid(metadata: &str) -> bool {
        metadata.len() <= MAX_METADATA_LEN
    }

    /// Attach metadata to this record, validating that its length does not exceed [`MAX_METADATA_LEN`].
    pub fn with_metadata(mut self, metadata: impl Into<String>) -> Result<Self, ProvenanceError> {
        let meta = metadata.into();
        Self::validate_metadata(&meta)?;
        self.metadata = Some(meta);
        Ok(self)
    }

    /// Set or update metadata on this record, validating length against [`MAX_METADATA_LEN`].
    pub fn set_metadata(&mut self, metadata: impl Into<String>) -> Result<(), ProvenanceError> {
        let meta = metadata.into();
        Self::validate_metadata(&meta)?;
        self.metadata = Some(meta);
        Ok(())
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    /// The unique identifier for this request.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The ID of the immediately preceding request, or `None` for roots.
    pub fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }

    /// Full ancestor chain, oldest first.
    ///
    /// Does not include `request_id` itself; use `parent_id()` to get the
    /// immediate predecessor.
    pub fn ancestors(&self) -> &[String] {
        &self.ancestors
    }

    /// The root request ID of this lineage (oldest ancestor).
    ///
    /// Returns `request_id()` when there are no ancestors (i.e. this is the root).
    pub fn root_id(&self) -> &str {
        self.ancestors.first().map(String::as_str).unwrap_or(&self.request_id)
    }

    /// Number of hops from the root (0 = this is the root).
    pub fn depth(&self) -> usize {
        self.ancestors.len()
    }

    /// The service that created this provenance record.
    pub fn origin_service(&self) -> &str {
        &self.origin_service
    }

    /// The operation label, if one was set.
    pub fn operation(&self) -> Option<&str> {
        self.operation.as_deref()
    }

    /// Custom metadata attached to this record, if set.
    pub fn metadata(&self) -> Option<&str> {
        self.metadata.as_deref()
    }

    /// Unix timestamp (seconds) when this record was created.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// `true` when this record has no parent (it is a root request).
    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    // ── Serialisation helpers ──────────────────────────────────────────────

    /// Produce a compact log-friendly summary.
    ///
    /// ```text
    /// req=<id> parent=<id|none> depth=<n> svc=<name> op=<op> [meta=<meta>]
    /// ```
    pub fn log_fields(&self) -> String {
        if let Some(ref meta) = self.metadata {
            format!(
                "req={} parent={} depth={} svc={} op={} meta={}",
                self.request_id,
                self.parent_id.as_deref().unwrap_or("none"),
                self.depth(),
                self.origin_service,
                self.operation.as_deref().unwrap_or("unknown"),
                meta,
            )
        } else {
            format!(
                "req={} parent={} depth={} svc={} op={}",
                self.request_id,
                self.parent_id.as_deref().unwrap_or("none"),
                self.depth(),
                self.origin_service,
                self.operation.as_deref().unwrap_or("unknown"),
            )
        }
    }

    /// Serialize to a list of `(header_name, header_value)` pairs for HTTP propagation.
    ///
    /// | Header | Value |
    /// |--------|-------|
    /// | `X-Request-Provenance-Id` | This request's ID |
    /// | `X-Request-Parent-Id` | Parent ID or `"root"` |
    /// | `X-Request-Depth` | Depth as decimal |
    /// | `X-Request-Origin` | Originating service |
    /// | `X-Request-Operation` | Operation label |
    /// | `X-Request-Metadata` | Custom metadata (if set) |
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        headers.push((PROVENANCE_ID_HEADER.to_string(), self.request_id.clone()));
        headers.push((
            PARENT_ID_HEADER.to_string(),
            self.parent_id.clone().unwrap_or_else(|| "root".to_string()),
        ));
        headers.push((DEPTH_HEADER.to_string(), self.depth().to_string()));
        headers.push((ORIGIN_HEADER.to_string(), self.origin_service.clone()));
        if let Some(ref op) = self.operation {
            headers.push((OPERATION_HEADER.to_string(), op.clone()));
        }
        if let Some(ref meta) = self.metadata {
            headers.push((METADATA_HEADER.to_string(), meta.clone()));
        }
        headers
    }

    /// Parse a [`ProvenanceRecord`] from HTTP headers.
    ///
    /// Returns `None` when the required `X-Request-Provenance-Id` header is absent,
    /// or if any metadata header exceeds [`MAX_METADATA_LEN`].
    pub fn from_headers(headers: &[(String, String)]) -> Option<Self> {
        let mut request_id: Option<String> = None;
        let mut parent_id: Option<String> = None;
        let mut depth: usize = 0;
        let mut origin_service = String::new();
        let mut operation: Option<String> = None;
        let mut metadata: Option<String> = None;

        for (name, value) in headers {
            let n = name.as_str();
            if n.eq_ignore_ascii_case(PROVENANCE_ID_HEADER) {
                request_id = Some(value.clone());
            } else if n.eq_ignore_ascii_case(PARENT_ID_HEADER) {
                if value != "root" {
                    parent_id = Some(value.clone());
                }
            } else if n.eq_ignore_ascii_case(DEPTH_HEADER) {
                depth = value.parse().unwrap_or(0);
            } else if n.eq_ignore_ascii_case(ORIGIN_HEADER) {
                origin_service = value.clone();
            } else if n.eq_ignore_ascii_case(OPERATION_HEADER) {
                operation = Some(value.clone());
            } else if n.eq_ignore_ascii_case(METADATA_HEADER) {
                if value.len() > MAX_METADATA_LEN {
                    return None; // Reject over-limit metadata
                }
                metadata = Some(value.clone());
            }
        }

        let id = request_id?;
        // Ancestors cannot be fully reconstructed from headers alone;
        // we leave the slice empty. Callers that need the full chain should
        // propagate the ProvenanceRecord directly (e.g. via gRPC metadata).
        Some(ProvenanceRecord {
            request_id: id,
            parent_id,
            ancestors: Vec::new(),
            origin_service,
            operation,
            metadata,
            created_at: 0, // not propagated via headers
        })
    }
}

// ---------------------------------------------------------------------------
// Header name constants
// ---------------------------------------------------------------------------

/// `X-Request-Provenance-Id`
pub const PROVENANCE_ID_HEADER: &str = "X-Request-Provenance-Id";
/// `X-Request-Parent-Id`
pub const PARENT_ID_HEADER: &str = "X-Request-Parent-Id";
/// `X-Request-Depth`
pub const DEPTH_HEADER: &str = "X-Request-Depth";
/// `X-Request-Origin`
pub const ORIGIN_HEADER: &str = "X-Request-Origin";
/// `X-Request-Operation`
pub const OPERATION_HEADER: &str = "X-Request-Operation";
/// `X-Request-Metadata`
pub const METADATA_HEADER: &str = "X-Request-Metadata";

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn derive_request_id(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(seed.as_bytes());
    let result = h.finalize();
    result[..16]
        .iter()
        .fold(String::new(), |mut s, b| {
            s.push(hex_nibble(b >> 4));
            s.push(hex_nibble(b & 0x0f));
            s
        })
}

fn hex_nibble(v: u8) -> char {
    match v {
        0..=9 => (b'0' + v) as char,
        _ => (b'a' + v - 10) as char,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_no_parent_and_depth_zero() {
        let r = ProvenanceRecord::root("gateway", "deposit", 1000).unwrap();
        assert!(r.is_root());
        assert!(r.parent_id().is_none());
        assert_eq!(r.depth(), 0);
        assert_eq!(r.root_id(), r.request_id());
    }

    #[test]
    fn child_links_to_parent() {
        let root = ProvenanceRecord::root("gateway", "deposit", 1000).unwrap();
        let child = root.child("anchor-service", "sep6", 1001).unwrap();

        assert_eq!(child.parent_id(), Some(root.request_id()));
        assert_eq!(child.depth(), 1);
        assert_eq!(child.ancestors().len(), 1);
        assert_eq!(child.ancestors()[0], root.request_id());
        assert_eq!(child.root_id(), root.request_id());
    }

    #[test]
    fn grandchild_carries_full_lineage() {
        let root = ProvenanceRecord::root("a", "op", 0).unwrap();
        let child = root.child("b", "op2", 1).unwrap();
        let grandchild = child.child("c", "op3", 2).unwrap();

        assert_eq!(grandchild.depth(), 2);
        assert_eq!(grandchild.ancestors()[0], root.request_id());
        assert_eq!(grandchild.ancestors()[1], child.request_id());
        assert_eq!(grandchild.root_id(), root.request_id());
    }

    #[test]
    fn request_ids_are_distinct() {
        let r1 = ProvenanceRecord::root("svc", "op-a", 1000).unwrap();
        let r2 = ProvenanceRecord::root("svc", "op-b", 1000).unwrap();
        assert_ne!(r1.request_id(), r2.request_id());
    }

    #[test]
    fn header_round_trip_preserves_key_fields() {
        let root = ProvenanceRecord::root("gateway", "deposit", 1000).unwrap();
        let child = root.child("anchor", "sep6", 1001).unwrap();
        let headers = child.to_headers();
        let parsed = ProvenanceRecord::from_headers(&headers).unwrap();

        assert_eq!(parsed.request_id(), child.request_id());
        assert_eq!(parsed.parent_id(), child.parent_id());
        assert_eq!(parsed.depth(), child.depth());
        assert_eq!(parsed.origin_service(), child.origin_service());
        assert_eq!(parsed.operation(), child.operation());
    }

    #[test]
    fn from_headers_missing_id_returns_none() {
        let headers = alloc::vec![
            ("X-Request-Origin".to_string(), "svc".to_string()),
        ];
        assert!(ProvenanceRecord::from_headers(&headers).is_none());
    }

    #[test]
    fn root_header_parent_id_encodes_as_root_string() {
        let root = ProvenanceRecord::root("svc", "op", 0).unwrap();
        let headers = root.to_headers();
        let parent_header = headers
            .iter()
            .find(|(k, _)| k == PARENT_ID_HEADER)
            .map(|(_, v)| v.as_str());
        assert_eq!(parent_header, Some("root"));
    }

    #[test]
    fn log_fields_contains_expected_fields() {
        let r = ProvenanceRecord::root("gateway", "deposit", 1000).unwrap();
        let fields = r.log_fields();
        assert!(fields.contains("req="));
        assert!(fields.contains("parent=none"));
        assert!(fields.contains("depth=0"));
        assert!(fields.contains("svc=gateway"));
        assert!(fields.contains("op=deposit"));
    }

    #[test]
    fn with_explicit_id() {
        let r = ProvenanceRecord::root_with_id("my-id-000", "svc", "op", 0).unwrap();
        assert_eq!(r.request_id(), "my-id-000");
        let child = r.child_with_id("child-id-001", "svc2", "op2", 1).unwrap();
        assert_eq!(child.request_id(), "child-id-001");
        assert_eq!(child.parent_id(), Some("my-id-000"));
    }

    // ── Empty-actor rejection ─────────────────────────────────────────────

    /// An empty string actor is unattributable and must be rejected.
    #[test]
    fn root_rejects_empty_actor() {
        assert_eq!(
            ProvenanceRecord::root("", "op", 0),
            Err(ProvenanceError::EmptyActor),
            "empty origin_service must be rejected at construction"
        );
    }

    /// A whitespace-only actor is equally unattributable.
    #[test]
    fn root_rejects_whitespace_only_actor() {
        assert_eq!(
            ProvenanceRecord::root("   ", "op", 0),
            Err(ProvenanceError::EmptyActor),
            "whitespace-only origin_service must be rejected at construction"
        );
        assert_eq!(
            ProvenanceRecord::root("\t\n", "op", 0),
            Err(ProvenanceError::EmptyActor),
        );
    }

    /// Valid actors (including ones with internal spaces) are recorded exactly.
    #[test]
    fn root_accepts_valid_actor() {
        let r = ProvenanceRecord::root("anchor service", "op", 0).unwrap();
        assert_eq!(r.origin_service(), "anchor service",
            "valid actor must be stored without modification");
    }

    /// child() also rejects empty/whitespace-only actors.
    #[test]
    fn child_rejects_empty_actor() {
        let root = ProvenanceRecord::root("gateway", "op", 0).unwrap();
        assert_eq!(
            root.child("", "sub-op", 1),
            Err(ProvenanceError::EmptyActor),
        );
        assert_eq!(
            root.child("  ", "sub-op", 1),
            Err(ProvenanceError::EmptyActor),
        );
    }
}
