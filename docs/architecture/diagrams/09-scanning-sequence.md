# 9. Email scanning sequence

The step 4.1 scan stage ([design S5](../../plan/steps/09-rspamd.md#s5-one-engine-delivery-the-handler-generic-scanningengine-consumerts--round-servicets), [ADR-0026](../adr/0026-security-scan-pipeline.md)): the email-worker **scan role** consumes `mail.message.parsed.v1` (round 0) or `mail.message.rescan_requested.v1` (round ≥ 1) from the engine's own queue (`scan.spam` for Rspamd, broker user `eg-scanner`), opens the scan round, streams the EML from S3 to Rspamd `/checkv2` with the trusted envelope, records the result and, once every required engine has a final result, completes the round and writes `mail.message.scanned.v1` in the same transaction. A failed call is a recorded **attempt** (`timeout`/`error`, never final, never clean) and is retried; the last allowed failure is a final `error`/`timeout` and the round ends `scan_failed`. Engines classify; they never reject, quarantine or deliver (policy 5.2 does; locally the dev pass-through approves scanned mail, E27). How rounds, the registry and the deadline fit together: [diagram 23](23-scan-pipeline.md).

```mermaid
sequenceDiagram
  autonumber
  participant MQ as RabbitMQ scan.spam (work queue, topology v3)
  participant EW as email-worker scan role (QueueConsumer, prefetch SCAN_RSPAMD_CONCURRENCY)
  participant DB as MySQL writer
  participant S3 as S3 mail bucket
  participant BR as circuit breaker (per engine, in memory)
  participant RS as Rspamd normal worker /checkv2
  participant OB as message_outbox → event-relay

  MQ->>EW: envelope {eventId, organizationId, payload messageId, receivedAt, emlS3Key, [lifecycleRound]}
  EW->>DB: ledger check message_idempotency (email-worker.scan.rspamd, eventId)
  alt duplicate
    EW->>MQ: ack (no effect)
  end
  EW->>DB: load the message by (id, received_at, organization_id = envelope org)
  Note over EW,DB: absent → ledger row, skipped. EML key must start with org/{envelope org}/<br/>and equal the row's key, else a final error eml_key_mismatch
  EW->>DB: short txn: lock message row; persisted + round 0 → E3 scanning (key scan-open:id:0);<br/>scanning of this round → no transition; other state or round → ledger row, skipped<br/>INSERT email_scans if absent (round, scan_kind, running, deadline_at, required_engines snapshot)
  EW->>DB: this engine's rows of the round: final row present → completion re-check only
  EW->>EW: settings: platform SCAN_RSPAMD_* + tenant scan_engine_settings (validated, cached)
  EW->>S3: GET EML (streamed, SCAN_S3_TIMEOUT_MS)
  EW->>BR: allow call?
  alt breaker open
    BR-->>EW: failure error / engine.circuit_open (no call)
  else closed or half-open probe
    EW->>RS: POST /checkv2 (body streamed, IP, Helo, Hostname, From, Rcpt, Queue-Id, Settings-Id, Log-Tag)
    RS-->>EW: JSON reply (score, action, symbols, options) + Server rspamd/3.12.1
    EW->>EW: normalize (auth: SPF, DKIM, DMARC, ARC), map R0–R10 → verdict + reason codes
  end
  alt failure, retryable, attempts left and before deadline_at
    EW->>DB: INSERT scan_engine_results non-final (attempt n, timeout/error, error_code)
    EW->>MQ: retry (hold strategy, SCAN_RETRY_BASE_MS doubling to SCAN_RETRY_MAX_MS); no ledger row
  else definite verdict, or the last allowed failure
    EW->>DB: processOnce txn: lock message → lock scan; INSERT final scan_engine_results<br/>(+ email_auth_results for Rspamd); every required engine final?
    alt round complete
      EW->>DB: UPDATE email_scans (completed | failed | timed_out, scan_verdict, reason_codes)
      EW->>DB: E6 scanned or E7 scan_failed (key scan-complete:id:round, expectedRound)
      EW->>OB: INSERT mail.message.scanned.v1 (outcome, verdict, engines, reasonCodes; no symbols)
    end
    EW->>DB: ledger row, COMMIT
    EW->>MQ: ack
  end
  alt MySQL writer or S3 unavailable
    EW->>MQ: transient: held and retried, no attempt row, no ledger row
  end
```

**Legend.** Every participant and message is IMPLEMENTED (step 4.1). `scanned.v1` goes through the outbox and the event-relay to `email.security`, where topology v3 binds it to the dormant `email.policy.evaluate` (policy 5.2) and the analytics firehose; locally the dev pass-through reads it from the outbox and applies E27 for `outcome = scanned` only.

## Status

| Element                                                                                   | Status          | Evidence                                                                                                                                  |
| ----------------------------------------------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `scan.spam` work queue, `eg-scanner` user, `scan.auth` unbound (topology v3)              | IMPLEMENTED 4.1 | `topology.ts`, `init.mjs`; stack `messaging-topology`, `messaging-permissions`, `scan-pipeline`                                           |
| Round open (E3), engine call, attempts, final result, completion (E6/E7) and `scanned.v1` | IMPLEMENTED 4.1 | `apps/email-worker/src/scanning/*` unit tests; email-worker `scan-rounds`, `scan-corpus`; stack `scan-pipeline`                           |
| `@email-gateway/rspamd` (streamed `/checkv2`, header builder, reply schema, normalizer)   | IMPLEMENTED 4.1 | `packages/rspamd` unit and integration suites (corpus against the real Rspamd 3.12.1)                                                     |
| Verdict mapping R0–R10, aggregation, tenant settings                                      | IMPLEMENTED 4.1 | `verdict-mapper.test.ts`, `aggregate.test.ts`, `settings-resolver.test.ts`, `security-contracts` tests                                    |
| Breaker, retries, budget, deadline sweeper                                                | IMPLEMENTED 4.1 | `circuit-breaker.test.ts`, `deadline-sweeper.test.ts`; email-worker `scan-resilience`; stack `scan-resilience` (Rspamd stopped/restarted) |
| Rescan (`rescan_requested.v1` → round N, old rounds unchanged)                            | IMPLEMENTED 4.1 | email-worker `scan-rounds`; stack `scan-resilience`, `lifecycle-rescan`                                                                   |
| Engines after Rspamd (ClamAV/YARA, URL, BEC, DLP, sandbox) on their own queues            | PLANNED 4.2–4.6 | Catalog entries and adapters only; the orchestrator is unchanged                                                                          |
| Risk score (`email_scans.verdict`, `risk_score`) and policy consumption of `scanned.v1`   | PLANNED 5.1/5.2 |                                                                                                                                           |
