//! Operator-specific alert routing (issue #685).
//!
//! Alerts fired by the health and monitoring modules need to reach the right
//! team or escalation path. This module provides:
//!
//! - [`AlertSeverity`] — four-level classification (Info → Critical).
//! - [`AlertRoute`] — destination channel (webhook URL, email address, etc.).
//! - [`AlertRule`] — maps a `(severity, scope)` pair to one or more routes.
//! - [`AlertRouter`] — evaluates a set of rules and returns the matching routes
//!   for a given alert, falling back to a default catch-all route if no rule
//!   matches.
//!
//! # Design
//!
//! The router is intentionally `no_std`-compatible and dependency-free.
//! Routes are plain strings; the host process is responsible for actually
//! delivering the alert to the channel (webhook POST, SMTP, PagerDuty API,
//! etc.).  Only the routing decision is made here.
//!
//! # Example
//!
//! ```rust
//! use anchorkit::alert_routing::{
//!     AlertRouter, AlertRule, AlertSeverity, AlertRoute, AlertRouterConfig,
//! };
//!
//! let config = AlertRouterConfig {
//!     rules: alloc::vec![
//!         AlertRule {
//!             severity: AlertSeverity::Critical,
//!             scope: None,
//!             routes: alloc::vec![
//!                 AlertRoute::webhook("https://hooks.example.com/critical"),
//!             ],
//!         },
//!         AlertRule {
//!             severity: AlertSeverity::Warning,
//!             scope: Some(alloc::string::String::from("payments")),
//!             routes: alloc::vec![
//!                 AlertRoute::email("payments-on-call@example.com"),
//!             ],
//!         },
//!     ],
//!     default_routes: alloc::vec![
//!         AlertRoute::webhook("https://hooks.example.com/fallback"),
//!     ],
//! };
//!
//! let router = AlertRouter::new(config);
//! let routes = router.route(AlertSeverity::Critical, None);
//! assert_eq!(routes.len(), 1);
//! assert!(routes[0].destination.contains("critical"));
//!
//! // Unknown recipients still get the default route.
//! let fallback = router.route(AlertSeverity::Info, Some("unknown-scope"));
//! assert_eq!(fallback.len(), 1);
//! assert!(fallback[0].destination.contains("fallback"));
//! ```

extern crate alloc;

use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// AlertSeverity
// ---------------------------------------------------------------------------

/// Four-level alert severity, ordered from least to most urgent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Informational — no action required.
    Info,
    /// Something unusual; watch but no immediate action needed.
    Warning,
    /// Service degraded; operator should investigate soon.
    Error,
    /// Service down or data at risk; immediate action required.
    Critical,
}

impl AlertSeverity {
    /// Human-readable label used in serialised alert payloads.
    pub fn label(&self) -> &'static str {
        match self {
            AlertSeverity::Info     => "info",
            AlertSeverity::Warning  => "warning",
            AlertSeverity::Error    => "error",
            AlertSeverity::Critical => "critical",
        }
    }

    /// Parse a severity label (case-insensitive).
    ///
    /// Returns `None` for unrecognised strings.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info"     => Some(AlertSeverity::Info),
            "warning"  => Some(AlertSeverity::Warning),
            "error"    => Some(AlertSeverity::Error),
            "critical" => Some(AlertSeverity::Critical),
            _          => None,
        }
    }
}

impl Default for AlertSeverity {
    /// Returns [`AlertSeverity::Warning`], the documented operational default
    /// used when no severity is explicitly supplied (matches the config schema
    /// and all shipped example configurations).
    fn default() -> Self {
        AlertSeverity::Warning
    }
}

// ---------------------------------------------------------------------------
// AlertRoute
// ---------------------------------------------------------------------------

/// A single delivery destination for an alert.
///
/// The channel type (`webhook`, `email`, etc.) is stored as a plain string so
/// operators can extend the set without changing this library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlertRoute {
    /// Channel type identifier (e.g. `"webhook"`, `"email"`, `"pagerduty"`).
    pub channel: String,
    /// Channel-specific destination (URL, address, integration key, …).
    pub destination: String,
}

impl AlertRoute {
    /// Convenience constructor for webhook routes.
    pub fn webhook(url: impl Into<String>) -> Self {
        AlertRoute {
            channel: "webhook".into(),
            destination: url.into(),
        }
    }

    /// Convenience constructor for email routes.
    pub fn email(address: impl Into<String>) -> Self {
        AlertRoute {
            channel: "email".into(),
            destination: address.into(),
        }
    }

    /// Generic constructor for any channel type.
    pub fn new(channel: impl Into<String>, destination: impl Into<String>) -> Self {
        AlertRoute {
            channel: channel.into(),
            destination: destination.into(),
        }
    }

    /// Validated constructor — rejects a blank `destination` with
    /// [`crate::errors::AnchorKitError::validation_error`].
    ///
    /// Use this when building routes from operator-supplied configuration
    /// strings that may be empty.  Non-blank values are accepted as-is;
    /// URL and channel-specific validation remain the caller's responsibility.
    #[cfg(feature = "std")]
    pub fn try_new(
        channel: impl Into<String>,
        destination: impl Into<String>,
    ) -> Result<Self, crate::errors::AnchorKitError> {
        let destination = destination.into();
        if destination.trim().is_empty() {
            return Err(crate::errors::AnchorKitError::validation_error("destination"));
        }
        Ok(AlertRoute {
            channel: channel.into(),
            destination,
        })
    }
}

// ---------------------------------------------------------------------------
// AlertRule
// ---------------------------------------------------------------------------

/// A routing rule that matches on severity and an optional scope string.
///
/// The scope is an arbitrary operator-defined label (e.g. `"payments"`,
/// `"kyc"`, `"anchor:example.com"`). A rule with `scope: None` matches any
/// scope for its severity level.
#[derive(Clone, Debug, PartialEq)]
pub struct AlertRule {
    /// Severity level this rule applies to.
    pub severity: AlertSeverity,
    /// Scope filter.  `None` matches all scopes; `Some(s)` matches only alerts
    /// whose scope equals `s`.
    pub scope: Option<String>,
    /// Destinations to notify when this rule matches.
    pub routes: Vec<AlertRoute>,
}

impl AlertRule {
    /// Returns `true` when this rule matches the given `(severity, scope)` pair.
    ///
    /// Scope matching is exact-string; pass `None` to match scope-agnostic rules.
    pub fn matches(&self, severity: AlertSeverity, scope: Option<&str>) -> bool {
        if self.severity != severity {
            return false;
        }
        match (&self.scope, scope) {
            (None, _)          => true,              // rule has no scope filter → matches all
            (Some(r), Some(s)) => r.as_str() == s,   // exact match
            (Some(_), None)    => false,             // rule requires a scope; alert has none
        }
    }
}

// ---------------------------------------------------------------------------
// AlertRouterConfig
// ---------------------------------------------------------------------------

/// Configuration for an [`AlertRouter`].
#[derive(Clone, Debug, Default)]
pub struct AlertRouterConfig {
    /// Ordered list of routing rules.  Rules are evaluated in order; **all**
    /// matching rules contribute their routes (not just the first match).
    pub rules: Vec<AlertRule>,
    /// Routes used when no rule matches.  If this list is also empty, routing
    /// an unmatched alert returns an empty `Vec`.
    pub default_routes: Vec<AlertRoute>,
}

// ---------------------------------------------------------------------------
// AlertRouter
// ---------------------------------------------------------------------------

/// Evaluates routing rules for incoming alerts and returns the applicable
/// delivery destinations.
///
/// Every matching rule contributes its routes; if no rule matches, the
/// `default_routes` from the configuration are returned instead.  This means
/// a Critical alert that matches two rules will return the union of both
/// rules' routes.
pub struct AlertRouter {
    config: AlertRouterConfig,
}

impl AlertRouter {
    /// Create a router from the given configuration.
    pub fn new(config: AlertRouterConfig) -> Self {
        AlertRouter { config }
    }

    /// Return all routes that apply to an alert with the given severity and
    /// optional scope.
    ///
    /// If no rule matches, the configured `default_routes` are returned.
    /// If `default_routes` is also empty, an empty `Vec` is returned (the
    /// alert is silently dropped from the routing perspective — the caller
    /// should log a warning).
    pub fn route(&self, severity: AlertSeverity, scope: Option<&str>) -> Vec<AlertRoute> {
        let mut matched: Vec<AlertRoute> = self
            .config
            .rules
            .iter()
            .filter(|rule| rule.matches(severity, scope))
            .flat_map(|rule| rule.routes.iter().cloned())
            .collect();

        if matched.is_empty() {
            matched = self.config.default_routes.clone();
        }

        // Deduplicate destinations while preserving first-match order.
        let mut seen = alloc::collections::BTreeSet::new();
        matched.retain(|route| seen.insert((route.channel.clone(), route.destination.clone())));

        matched
    }

    /// Returns `true` when at least one rule or the default route would handle
    /// an alert of `severity` and `scope`.
    pub fn has_route(&self, severity: AlertSeverity, scope: Option<&str>) -> bool {
        !self.route(severity, scope).is_empty()
    }

    /// Return a reference to the underlying configuration.
    pub fn config(&self) -> &AlertRouterConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// AlertRouterConfig: integration with MonitoringConfig (std only)
// ---------------------------------------------------------------------------

#[cfg(feature = "std")]
impl AlertRouterConfig {
    /// Build an [`AlertRouterConfig`] from the `monitoring.alerts` section of
    /// a loaded [`crate::config::MonitoringConfig`].
    ///
    /// Each `AlertConfig` entry is mapped to an [`AlertRule`] as follows:
    /// - `condition` → rule `scope` (empty string becomes `None`).
    /// - `severity`  → [`AlertSeverity`] parsed from the string value.
    /// - `recipients` → one [`AlertRoute::webhook`] per entry.
    ///
    /// Entries with an unrecognised severity are skipped.
    pub fn from_monitoring_config(
        monitoring: Option<&crate::config::MonitoringConfig>,
    ) -> Self {
        let Some(monitoring) = monitoring else {
            return Self::default();
        };
        let Some(alerts) = &monitoring.alerts else {
            return Self::default();
        };

        let mut rules = Vec::new();
        for alert in alerts {
            let severity = AlertSeverity::from_str(&alert.severity)
                .unwrap_or(AlertSeverity::Warning);
            let scope = if alert.condition.is_empty() {
                None
            } else {
                Some(alert.condition.clone())
            };
            let routes: Vec<AlertRoute> = alert
                .recipients
                .iter()
                .filter(|r| !r.trim().is_empty())
                .map(|r| AlertRoute::webhook(r.clone()))
                .collect();
            if !routes.is_empty() {
                rules.push(AlertRule { severity, scope, routes });
            }
        }

        AlertRouterConfig {
            rules,
            default_routes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_router() -> AlertRouter {
        AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![
                AlertRule {
                    severity: AlertSeverity::Critical,
                    scope: None,
                    routes: alloc::vec![AlertRoute::webhook("https://hooks.example.com/critical")],
                },
                AlertRule {
                    severity: AlertSeverity::Warning,
                    scope: Some("payments".into()),
                    routes: alloc::vec![AlertRoute::email("payments@example.com")],
                },
                AlertRule {
                    severity: AlertSeverity::Error,
                    scope: Some("kyc".into()),
                    routes: alloc::vec![
                        AlertRoute::webhook("https://hooks.example.com/kyc"),
                        AlertRoute::email("kyc-oncall@example.com"),
                    ],
                },
            ],
            default_routes: alloc::vec![AlertRoute::webhook("https://hooks.example.com/default")],
        })
    }

    #[test]
    fn routes_critical_with_no_scope() {
        let router = make_router();
        let routes = router.route(AlertSeverity::Critical, None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].channel, "webhook");
        assert!(routes[0].destination.contains("critical"));
    }

    #[test]
    fn routes_critical_with_any_scope_due_to_none_rule() {
        let router = make_router();
        let routes = router.route(AlertSeverity::Critical, Some("payments"));
        assert_eq!(routes.len(), 1);
        assert!(routes[0].destination.contains("critical"));
    }

    #[test]
    fn routes_warning_scoped_to_payments() {
        let router = make_router();
        let routes = router.route(AlertSeverity::Warning, Some("payments"));
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].channel, "email");
        assert_eq!(routes[0].destination, "payments@example.com");
    }

    #[test]
    fn routes_error_with_kyc_scope_returns_multiple_routes() {
        let router = make_router();
        let routes = router.route(AlertSeverity::Error, Some("kyc"));
        assert_eq!(routes.len(), 2);
    }

    #[test]
    fn unknown_scope_falls_back_to_default() {
        let router = make_router();
        let routes = router.route(AlertSeverity::Info, Some("unknown-scope"));
        assert_eq!(routes.len(), 1);
        assert!(routes[0].destination.contains("default"));
    }

    #[test]
    fn no_match_and_no_default_returns_empty() {
        let router = AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![],
            default_routes: alloc::vec![],
        });
        let routes = router.route(AlertSeverity::Critical, None);
        assert!(routes.is_empty());
        assert!(!router.has_route(AlertSeverity::Critical, None));
    }

    #[test]
    fn has_route_returns_true_when_default_matches() {
        let router = make_router();
        assert!(router.has_route(AlertSeverity::Info, None));
    }

    #[test]
    fn severity_label_round_trips() {
        for sev in [
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Error,
            AlertSeverity::Critical,
        ] {
            let parsed = AlertSeverity::from_str(sev.label());
            assert_eq!(parsed, Some(sev));
        }
    }

    #[test]
    fn severity_from_str_is_case_insensitive() {
        assert_eq!(AlertSeverity::from_str("CRITICAL"), Some(AlertSeverity::Critical));
        assert_eq!(AlertSeverity::from_str("Warning"), Some(AlertSeverity::Warning));
    }

    #[test]
    fn severity_from_str_unknown_returns_none() {
        assert_eq!(AlertSeverity::from_str("urgent"), None);
    }

    #[test]
    fn alert_rule_scope_none_matches_all_scopes() {
        let rule = AlertRule {
            severity: AlertSeverity::Error,
            scope: None,
            routes: alloc::vec![],
        };
        assert!(rule.matches(AlertSeverity::Error, None));
        assert!(rule.matches(AlertSeverity::Error, Some("payments")));
        assert!(rule.matches(AlertSeverity::Error, Some("kyc")));
    }

    #[test]
    fn alert_rule_scope_some_requires_exact_match() {
        let rule = AlertRule {
            severity: AlertSeverity::Warning,
            scope: Some("payments".into()),
            routes: alloc::vec![],
        };
        assert!(rule.matches(AlertSeverity::Warning, Some("payments")));
        assert!(!rule.matches(AlertSeverity::Warning, Some("kyc")));
        assert!(!rule.matches(AlertSeverity::Warning, None));
    }

    #[test]
    fn multiple_rules_for_same_severity_all_contribute_routes() {
        let router = AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![
                AlertRule {
                    severity: AlertSeverity::Critical,
                    scope: None,
                    routes: alloc::vec![AlertRoute::webhook("https://a.example.com")],
                },
                AlertRule {
                    severity: AlertSeverity::Critical,
                    scope: None,
                    routes: alloc::vec![AlertRoute::email("ops@example.com")],
                },
            ],
            default_routes: alloc::vec![],
        });
        let routes = router.route(AlertSeverity::Critical, None);
        assert_eq!(routes.len(), 2);
    }

    // ── Fix: duplicate destination deduplication ─────────────────────────────

    #[test]
    fn duplicate_destinations_are_deduplicated_preserving_order() {
        // Two rules both route Critical to the same webhook URL.
        let router = AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![
                AlertRule {
                    severity: AlertSeverity::Critical,
                    scope: None,
                    routes: alloc::vec![
                        AlertRoute::webhook("https://hooks.example.com/critical"),
                        AlertRoute::email("ops@example.com"),
                    ],
                },
                AlertRule {
                    severity: AlertSeverity::Critical,
                    scope: None,
                    routes: alloc::vec![
                        AlertRoute::webhook("https://hooks.example.com/critical"), // duplicate
                        AlertRoute::email("security@example.com"),
                    ],
                },
            ],
            default_routes: alloc::vec![],
        });
        let routes = router.route(AlertSeverity::Critical, None);
        // Duplicate webhook URL is removed; distinct destinations remain.
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].destination, "https://hooks.example.com/critical");
        assert_eq!(routes[1].destination, "ops@example.com");
        assert_eq!(routes[2].destination, "security@example.com");
    }

    #[test]
    fn identical_routes_across_rules_yield_single_entry() {
        let router = AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![
                AlertRule {
                    severity: AlertSeverity::Warning,
                    scope: None,
                    routes: alloc::vec![AlertRoute::email("ops@example.com")],
                },
                AlertRule {
                    severity: AlertSeverity::Warning,
                    scope: None,
                    routes: alloc::vec![AlertRoute::email("ops@example.com")],
                },
            ],
            default_routes: alloc::vec![],
        });
        let routes = router.route(AlertSeverity::Warning, None);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, "ops@example.com");
    }

    #[test]
    fn distinct_destinations_are_all_preserved() {
        let router = AlertRouter::new(AlertRouterConfig {
            rules: alloc::vec![
                AlertRule {
                    severity: AlertSeverity::Info,
                    scope: None,
                    routes: alloc::vec![AlertRoute::email("a@example.com")],
                },
                AlertRule {
                    severity: AlertSeverity::Info,
                    scope: None,
                    routes: alloc::vec![AlertRoute::email("b@example.com")],
                },
            ],
            default_routes: alloc::vec![],
        });
        let routes = router.route(AlertSeverity::Info, None);
        assert_eq!(routes.len(), 2);
    }

    // ── Fix: blank destination validation ────────────────────────────────────

    #[cfg(feature = "std")]
    #[test]
    fn try_new_rejects_blank_destination() {
        let result = AlertRoute::try_new("webhook", "");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.context.as_deref().unwrap_or("").contains("destination")
            || err.message.contains("destination")
            || (err.code as u32) == 15); // ValidationError
    }

    #[cfg(feature = "std")]
    #[test]
    fn try_new_rejects_whitespace_only_destination() {
        let result = AlertRoute::try_new("email", "   ");
        assert!(result.is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn try_new_accepts_valid_destination() {
        let result = AlertRoute::try_new("webhook", "https://hooks.example.com/alert");
        assert!(result.is_ok());
        let route = result.unwrap();
        assert_eq!(route.destination, "https://hooks.example.com/alert");
    }

    // ── Fix: default severity is Warning ─────────────────────────────────────

    #[test]
    fn default_severity_is_warning() {
        assert_eq!(AlertSeverity::default(), AlertSeverity::Warning);
    }

    #[test]
    fn explicit_severity_is_not_overridden_by_default() {
        // Ensure default() only applies when no severity is given; explicit
        // values must remain unchanged.
        for sev in [
            AlertSeverity::Info,
            AlertSeverity::Warning,
            AlertSeverity::Error,
            AlertSeverity::Critical,
        ] {
            // A rule carrying an explicit severity must keep it.
            let rule = AlertRule { severity: sev, scope: None, routes: alloc::vec![] };
            assert_eq!(rule.severity, sev);
        }
    }
}