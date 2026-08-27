//! End-to-end trace context propagation (issue #610).
//!
//! The unit tests inside each module check that module in isolation. These
//! tests check the property an operator actually cares about: that a single
//! trace ID survives a whole request as it fans out into retried anchor calls,
//! retried webhook deliveries and background monitoring — including when a
//! delivery ends up in the dead-letter queue.
//!
//! Run with: `cargo test --test trace_propagation_tests`

#![cfg(test)]

mod trace_propagation_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use anchorkit::{
        errors::ErrorCode,
        http_client::{post_with_options, OutboundRequestOptions},
        retry::{retry_with_backoff_traced, MockJitterSource, RetryConfig},
        streaming_monitor::{PollResult, StreamingTransactionMonitor},
        trace_context::TraceContext,
        transaction_state_tracker::TransactionState,
        webhook::{
            deliver_webhook, deliver_webhook_traced, dlq_entries_for_trace,
            get_dead_letter_webhooks, DlqEntry, WebhookDeliveryConfig,
        },
    };

    fn webhook_config(max_attempts: u32) -> WebhookDeliveryConfig {
        WebhookDeliveryConfig {
            endpoint_url: "https://example.com/hook".into(),
            timeout_ms: 1000,
            retry_config: RetryConfig::new(max_attempts, 0, 0, 1),
            dead_letter_storage_key: "trace_dlq".into(),
            signing_key: None,
            max_payload_age_seconds: None,
            require_nonce_for_replay_protection: false,
        }
    }

    /// A record of one observed operation, as an operator would see it in logs.
    #[derive(Debug, Clone)]
    struct Observed {
        stage: &'static str,
        trace_id: String,
        span_id: String,
    }

    // -----------------------------------------------------------------------
    // 1. One request, three subsystems, one trace ID
    // -----------------------------------------------------------------------

    /// The headline acceptance criterion: an operator can follow a request from
    /// entry to completion across a retried anchor call, a retried webhook
    /// delivery and a background monitor, using a single trace ID.
    #[test]
    fn one_trace_id_spans_anchor_retries_webhook_retries_and_monitoring() {
        let request = TraceContext::root_from_seed("sep24:deposit:txn-001");
        let observed: RefCell<Vec<Observed>> = RefCell::new(Vec::new());

        // ── Stage 1: a retried anchor call ───────────────────────────────────
        let anchor_span = request.child("anchor:initiate-deposit");
        let mut jitter = MockJitterSource::new(vec![0]);
        let anchor_result = retry_with_backoff_traced(
            &RetryConfig::new(3, 0, 0, 1),
            &anchor_span,
            |attempt, trace| {
                observed.borrow_mut().push(Observed {
                    stage: "anchor",
                    trace_id: trace.trace_id().into(),
                    span_id: trace.span_id().into(),
                });
                if attempt < 2 {
                    Err("503 from anchor")
                } else {
                    Ok("txn-001")
                }
            },
            |_| true,
            |_| {},
            &mut jitter,
        );
        assert_eq!(anchor_result, Ok("txn-001"));

        // ── Stage 2: a webhook that succeeds on its third attempt ────────────
        let mut dlq: BTreeMap<String, Vec<DlqEntry>> = BTreeMap::new();
        let webhook_attempts = RefCell::new(0u32);
        let delivery = deliver_webhook_traced(
            &webhook_config(4),
            r#"{"event":"deposit_completed"}"#,
            &request,
            &mut dlq,
            |_url, _body, _sig, trace| {
                observed.borrow_mut().push(Observed {
                    stage: "webhook",
                    trace_id: trace.trace_id().into(),
                    span_id: trace.span_id().into(),
                });
                let mut n = webhook_attempts.borrow_mut();
                *n += 1;
                if *n < 3 {
                    Ok(500)
                } else {
                    Ok(200)
                }
            },
            |_| {},
            || 1_000_000,
        );
        assert!(delivery.is_ok());
        assert!(dlq.is_empty());

        // ── Stage 3: background monitoring of the same transaction ───────────
        let mut monitor = StreamingTransactionMonitor::new(1, 0).with_trace(&request);
        let poll_calls = RefCell::new(0u32);
        monitor.run_traced(
            |_id, trace| {
                observed.borrow_mut().push(Observed {
                    stage: "monitor",
                    trace_id: trace.trace_id().into(),
                    span_id: trace.span_id().into(),
                });
                let mut n = poll_calls.borrow_mut();
                *n += 1;
                match *n {
                    1 => Err("transient".to_string()),
                    2 => Ok(PollResult::Pending(TransactionState::InProgress)),
                    _ => Ok(PollResult::Completed {
                        stellar_tx_id: "abc".into(),
                    }),
                }
            },
            |_event| {},
            |_| {},
            || 1_000_000,
        );

        // ── The property under test ──────────────────────────────────────────
        let observed = observed.into_inner();
        for stage in ["anchor", "webhook", "monitor"] {
            assert!(
                observed.iter().any(|o| o.stage == stage),
                "expected the {stage} stage to have run"
            );
        }
        assert!(
            observed.iter().all(|o| o.trace_id == request.trace_id()),
            "one trace ID must cover every stage; got {observed:#?}"
        );

        // Every observed operation is still individually addressable.
        let mut spans: Vec<&str> = observed.iter().map(|o| o.span_id.as_str()).collect();
        spans.sort_unstable();
        let total = spans.len();
        spans.dedup();
        assert_eq!(spans.len(), total, "each operation should have its own span");
    }

    // -----------------------------------------------------------------------
    // 2. Retries specifically
    // -----------------------------------------------------------------------

    /// Trace context survives a retry sequence that exhausts every attempt.
    #[test]
    fn trace_survives_exhausted_retries() {
        let request = TraceContext::root_from_seed("retry-exhaustion");
        let mut jitter = MockJitterSource::new(vec![0]);
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());

        let result: Result<(), &str> = retry_with_backoff_traced(
            &RetryConfig::new(5, 0, 0, 1),
            &request,
            |_attempt, trace| {
                seen.borrow_mut().push(trace.trace_id().into());
                Err("still failing")
            },
            |_| true,
            |_| {},
            &mut jitter,
        );

        assert_eq!(result, Err("still failing"));
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 5);
        assert!(seen.iter().all(|id| id == request.trace_id()));
    }

    /// Delays and attempt counts are unchanged by adding trace propagation —
    /// tracing must not alter retry behaviour.
    #[test]
    fn tracing_does_not_change_retry_timing() {
        let config = RetryConfig::new(4, 100, 10_000, 2);
        let request = TraceContext::root_from_seed("timing");

        let mut untraced_delays: Vec<u64> = Vec::new();
        let mut jitter = MockJitterSource::new(vec![7]);
        let untraced: Result<(), &str> = anchorkit::retry::retry_with_backoff(
            &config,
            |_| Err("fail"),
            |_| true,
            |ms| untraced_delays.push(ms),
            &mut jitter,
        );

        let mut traced_delays: Vec<u64> = Vec::new();
        let mut jitter = MockJitterSource::new(vec![7]);
        let traced: Result<(), &str> = retry_with_backoff_traced(
            &config,
            &request,
            |_, _| Err("fail"),
            |_| true,
            |ms| traced_delays.push(ms),
            &mut jitter,
        );

        assert_eq!(untraced, traced);
        assert_eq!(untraced_delays, traced_delays);
    }

    // -----------------------------------------------------------------------
    // 3. Webhook delivery and the dead-letter queue
    // -----------------------------------------------------------------------

    /// A webhook that exhausts its attempts leaves a DLQ entry stamped with the
    /// originating trace, so the failure is reachable from the request's logs.
    #[test]
    fn exhausted_webhook_dead_letters_under_the_request_trace() {
        let request = TraceContext::root_from_seed("sep6:withdrawal:txn-99");
        let mut dlq: BTreeMap<String, Vec<DlqEntry>> = BTreeMap::new();

        let result = deliver_webhook_traced(
            &webhook_config(3),
            r#"{"event":"withdrawal_failed"}"#,
            &request,
            &mut dlq,
            |_url, _body, _sig, _trace| Err("connection refused".to_string()),
            |_| {},
            || 4_242,
        );

        let err = result.expect_err("delivery should fail");
        assert_eq!(err.code, ErrorCode::WebhookDeliveryFailed);

        let entries = get_dead_letter_webhooks(&dlq, "trace_dlq");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].trace_id, request.trace_id());
        assert_eq!(entries[0].attempts_made, 3);
        assert_eq!(entries[0].last_status_code, 0, "transport failure");
        assert!(!entries[0].last_attempt_span_id.is_empty());

        // And the operator-facing lookup finds it by trace ID alone.
        let found = dlq_entries_for_trace(&dlq, "trace_dlq", request.trace_id());
        assert_eq!(found.len(), 1);
    }

    /// Deliveries belonging to different requests stay separable in the DLQ.
    #[test]
    fn dlq_entries_from_different_requests_do_not_mix() {
        let first = TraceContext::root_from_seed("request-A");
        let second = TraceContext::root_from_seed("request-B");
        let config = webhook_config(1);
        let mut dlq: BTreeMap<String, Vec<DlqEntry>> = BTreeMap::new();

        for (trace, payload) in [(&first, "a1"), (&second, "b1"), (&first, "a2")] {
            let _ = deliver_webhook_traced(
                &config,
                payload,
                trace,
                &mut dlq,
                |_url, _body, _sig, _t| Ok(500),
                |_| {},
                || 1_000,
            );
        }

        assert_eq!(get_dead_letter_webhooks(&dlq, "trace_dlq").len(), 3);

        let from_first = dlq_entries_for_trace(&dlq, "trace_dlq", first.trace_id());
        assert_eq!(from_first.len(), 2);
        let payloads: Vec<&str> = from_first.iter().map(|e| e.payload.as_str()).collect();
        assert_eq!(payloads, vec!["a1", "a2"]);

        assert_eq!(
            dlq_entries_for_trace(&dlq, "trace_dlq", second.trace_id()).len(),
            1
        );
    }

    /// The pre-existing untraced entry point keeps working and still yields a
    /// usable trace, so callers that have not been updated are not left blind.
    #[test]
    fn untraced_callers_still_get_a_traceable_dlq_entry() {
        let mut dlq: BTreeMap<String, Vec<DlqEntry>> = BTreeMap::new();
        let result = deliver_webhook(
            &webhook_config(2),
            r#"{"event":"legacy"}"#,
            &mut dlq,
            |_url, _body, _sig| Ok(503),
            |_| {},
            || 7_777,
        );

        assert!(result.is_err());
        let entries = get_dead_letter_webhooks(&dlq, "trace_dlq");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].trace_id.len(), 32);
        assert!(!dlq_entries_for_trace(&dlq, "trace_dlq", &entries[0].trace_id).is_empty());
    }

    // -----------------------------------------------------------------------
    // 4. Propagation onto the wire
    // -----------------------------------------------------------------------

    /// The attempt context reaches the transport, where it becomes W3C headers —
    /// this is what lets the receiving system log the same trace ID.
    #[test]
    fn every_delivery_attempt_sends_its_own_traceparent() {
        let request = TraceContext::root_from_seed("wire-propagation");
        let mut dlq: BTreeMap<String, Vec<DlqEntry>> = BTreeMap::new();
        let headers: RefCell<Vec<Vec<(String, String)>>> = RefCell::new(Vec::new());

        let _ = deliver_webhook_traced(
            &webhook_config(3),
            "payload",
            &request,
            &mut dlq,
            |_url, _body, _sig, trace| {
                headers.borrow_mut().push(trace.header_pairs());
                Ok(500)
            },
            |_| {},
            || 1_000,
        );

        let headers = headers.into_inner();
        assert_eq!(headers.len(), 3);

        let value = |set: &Vec<(String, String)>, name: &str| {
            set.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };

        // Same trace on every attempt...
        for set in &headers {
            assert_eq!(value(set, "X-Trace-Id"), request.trace_id());
            assert!(value(set, "traceparent").contains(request.trace_id()));
        }
        // ...but a different span, so the receiver can tell retries apart.
        assert_ne!(value(&headers[0], "X-Span-Id"), value(&headers[1], "X-Span-Id"));
        assert_ne!(value(&headers[1], "X-Span-Id"), value(&headers[2], "X-Span-Id"));
    }

    /// An inbound `traceparent` can be adopted and carried onward, so a request
    /// that arrives already traced does not start a new trace.
    #[test]
    fn inbound_traceparent_is_adopted_and_carried_onward() {
        let inbound = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let request = TraceContext::parse_traceparent(inbound).expect("valid traceparent");

        let opts = OutboundRequestOptions::with_idempotency_key("txn-1").with_trace(&request);
        let mut captured: Vec<(String, String)> = Vec::new();
        let status = post_with_options(
            "https://anchor.example.com/sep6/deposit",
            "{}",
            Some(&opts),
            |_url, _body, hdrs| {
                captured.extend(hdrs.iter().cloned());
                Ok(200u16)
            },
        );

        assert_eq!(status, Ok(200));
        let outbound = captured
            .iter()
            .find(|(k, _)| k == "traceparent")
            .map(|(_, v)| v.as_str())
            .expect("traceparent forwarded");
        assert_eq!(outbound, inbound);
    }

    /// An empty trace ID must be rejected as invalid context rather than
    /// accepted as a valid propagated trace, so unrelated requests never look
    /// correlated and downstream exporters never receive an empty record.
    #[test]
    fn empty_trace_id_is_rejected() {
        let inbound = "00--00f067aa0ba902b7-01";
        assert_eq!(
            TraceContext::parse_traceparent(inbound),
            Err(anchorkit::trace_context::TraceError::InvalidTraceId),
            "an empty trace ID must not be accepted as valid propagated context"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Background monitoring
    // -----------------------------------------------------------------------

    /// A long-running monitor keeps the request's trace across many poll cycles.
    #[test]
    fn background_monitor_keeps_the_trace_across_poll_cycles() {
        let request = TraceContext::root_from_seed("long-running-monitor");
        let mut monitor = StreamingTransactionMonitor::new(5, 0).with_trace(&request);
        let calls = RefCell::new(0u32);
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());

        monitor.run_traced(
            |_id, trace| {
                seen.borrow_mut().push(trace.trace_id().into());
                let mut n = calls.borrow_mut();
                *n += 1;
                match *n {
                    1 => Ok(PollResult::Pending(TransactionState::Pending)),
                    2 => Ok(PollResult::Pending(TransactionState::InProgress)),
                    3 => Ok(PollResult::Pending(TransactionState::InProgress)),
                    _ => Ok(PollResult::Completed {
                        stellar_tx_id: "final".into(),
                    }),
                }
            },
            |_event| {},
            |_| {},
            || 2_000,
        );

        let seen = seen.into_inner();
        assert!(seen.len() >= 4, "monitor should have polled repeatedly");
        assert!(seen.iter().all(|id| id == request.trace_id()));

        // The recorded transition history is joinable on the same trace ID.
        let transitions = monitor.get_transitions();
        assert!(!transitions.is_empty());
        assert!(transitions
            .iter()
            .all(|t| t.trace_id == request.trace_id()));
    }

    /// A monitor whose polls fail outright still reports under the request trace.
    #[test]
    fn background_monitor_failure_stays_within_the_request_trace() {
        let request = TraceContext::root_from_seed("monitor-failure");
        let mut monitor = StreamingTransactionMonitor::new(6, 0)
            .with_trace(&request)
            .with_retry(RetryConfig::new(2, 0, 0, 1));
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let mut failed = false;

        monitor.run_traced(
            |_id, trace| {
                seen.borrow_mut().push(trace.trace_id().into());
                Err::<PollResult, String>("anchor unreachable".to_string())
            },
            |event| {
                if matches!(
                    event,
                    anchorkit::streaming_monitor::TransactionStatusUpdate::Failed { .. }
                ) {
                    failed = true;
                }
            },
            |_| {},
            || 3_000,
        );

        assert!(failed, "monitor should surface the failure");
        let seen = seen.into_inner();
        assert_eq!(seen.len(), 2, "both retry attempts should have run");
        assert!(seen.iter().all(|id| id == request.trace_id()));
    }
}
