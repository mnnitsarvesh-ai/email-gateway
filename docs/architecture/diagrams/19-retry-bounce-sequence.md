# 19. Deferral, retry, bounce and expiry sequence

How delivery failures are handled and recorded (step 2.3, [design R4, R8, R9, R12](../../plan/steps/05-routing.md), [ADR-0006](../adr/0006-postfix-mail-path.md), [ADR-0021](../adr/0021-mail-routing-and-delivery-status.md)): **Postfix owns every retry to a remote server**, its backoff, `maximal_queue_lifetime` and DSN generation; the delivery-worker retries only its own reinjection hop. Status comes from Postfix's delivery log (primary) and the postmaster DSN copies (corroboration), both matched on the queue id bound to the reinjection token; every signal is idempotent. Missing signals end in `unknown`, never in a guessed outcome.

```mermaid
sequenceDiagram
  autonumber
  participant DW as delivery-worker reinjector
  participant PX as postfix-outbound (10026 / 10027, queue)
  participant D as Destination / recipient MX
  participant LOG as maillog_file
  participant ST as delivery-worker status tailer
  participant BH as smtp-adapter bounce LMTP 10052
  participant SD as Sender domain's destination (DSN)
  participant DB as MySQL writer (recorder)
  participant RC as delivery-worker reconciler

  DW->>PX: reinjection (token, ENVID), 250 queued as QID
  PX->>LOG: QID: client=…, orig_queue_id=dw1-<token> (binding, survives a worker crash after 250)
  PX->>D: SMTP attempt
  alt connection refused / timeout / remote 4xx
    D--xPX: no answer or 4xx
    PX->>LOG: QID: to=<a>, relay=…, dsn=4.x.x, status=deferred (connect to …)
    ST->>DB: deferred, attempt_count + 1, last_error_class connect / timeout / remote_4xx / tls / dns
    Note over PX: backoff from the environment: production 300s → 4000s (≈ 5, 10, 20, 40, 66… min),<br/>test profile 10s → 60s, queue_run_delay 10s#59; nothing in code depends on it
    PX->>D: retry after the backoff (no operator action, never postqueue -f)
    D-->>PX: 250
    PX->>LOG: status=sent → delivered (deferred → delivered)
  else remote 5xx (permanent)
    D-->>PX: 550 5.1.1
    PX->>LOG: status=bounced → bounced
    alt outbound / internal (NOTIFY=FAILURE,DELAY)
      PX->>LOG: QID: sender non-delivery notification: DSNQID
      ST->>DB: dsn_queue_id = DSNQID on the bounced delivery
      PX->>SD: DSN to the authenticated sender (transport_maps: the sender domain's destination)
    else inbound (NOTIFY=NEVER)
      Note over PX: no sender notification: no backscatter to external senders
    end
    PX->>BH: postmaster copy (X-Postfix-Queue-ID, Original-Envelope-Id = token)
    BH->>DB: match reinjection by queue id / ENVID → bounce_notice signal (duplicate of the log's → no change)#59;<br/>outbound with a valid d=out trace: bounce_events (message_id linked) + hard-bounce suppression
  else still deferred after maximal_queue_lifetime (5d)
    PX->>LOG: QID: from=<…>, status=expired, returned to sender (message level)
    ST->>DB: every non-final recipient of QID → expired (+ DSN to the sender unless NOTIFY=NEVER)
  end
  PX->>LOG: QID: removed
  ST->>DB: any delivery of QID still non-terminal → unknown (should never happen)
  loop every DELIVERY_RECONCILE_INTERVAL_MS
    RC->>DB: expired lease: bound queue id → queued#59; log passed the session → pending#59; else wait
    RC->>DB: queued/deferred with no signal for DELIVERY_STATUS_STALE_AFTER_SECONDS → unknown (status_signal_missing)
  end
  Note over ST,DB: every signal: audit row keyed (delivery, signal_key) first — a re-read log line or a<br/>redelivered notice is a duplicate: no transition, no email_events, no outbox row
```

**Legend.** Every participant and message is IMPLEMENTED in step 2.3, with these limits: real remote DSN handling and asynchronous remote bounces after a `250` (VERP/SRS) are out of scope (design §10); gateway-generated notifications for worker-side failures are step 6.2.

## Status

| Step in the sequence                                                   | Status                                | Evidence or delivering step                                                                                                                                           |
| ---------------------------------------------------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Deferred with attempts and error class, recovery by Postfix retry      | IMPLEMENTED                           | `error-class.test.ts`, `postfix-log-parser.test.ts`; `routing-retry.test.ts` (sink-m365 stopped → deferred `connect`, started → delivered, no flush)                  |
| Backoff from the environment (test profile 10s/60s/10s)                | IMPLEMENTED                           | `infrastructure/postfix*/entrypoint.sh`, [mail-routing.md](../../deployment/mail-routing.md#retry-schedule-r4); CI `stack` job env                                    |
| Bounce with DSN (`dsn_queue_id`), DSN at the sender's server           | IMPLEMENTED                           | `status-signal-applier.test.ts`; `routing-bounces.test.ts`                                                                                                            |
| Postmaster copy matched (queue id / ENVID), `bounce_events.message_id` | IMPLEMENTED                           | `bounce-notice.service.test.ts`, `apps/smtp-adapter/integration/bounces.test.ts`; `routing-bounces.test.ts`                                                           |
| Inbound bounce without DSN                                             | IMPLEMENTED                           | `routing-bounces.test.ts`                                                                                                                                             |
| Expiry (message-level qmgr line)                                       | IMPLEMENTED (parser, recorder)        | `postfix-log-parser.test.ts` (captured line), `status-tailer.test.ts`; not run end to end by a stack suite (5-day lifetime; WP2 captured it with a 1-minute lifetime) |
| Duplicate / re-read signals are no-ops                                 | IMPLEMENTED                           | `transitions.test.ts`, `recorder.test.ts`; `routing-signals.test.ts` (cursor reset, whole log re-read, notice redelivered)                                            |
| Reconciler (leases, stale → unknown)                                   | IMPLEMENTED                           | `apps/delivery-worker/integration/status-tailer.test.ts` (ambiguous crash window resolved by the bound line or by the log passing the session; stale → `unknown`)     |
| Real remote DSN handling, asynchronous remote bounces                  | not verifiable locally / out of scope | design §10                                                                                                                                                            |
