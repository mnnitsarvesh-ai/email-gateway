# 16. Inbound routing and delivery sequence

What happens to an inbound message **after** ingestion (diagram 6 ends with the commit): approval, planning into reinjection groups, reinjection into `postfix-outbound` 10026 with the reinjection token, `XFORWARD` and the gateway trace, Postfix's delivery to the organization's destination servers (customer server, Microsoft 365 or Google Workspace preset, next-hop list with failover) and the per-recipient status read from Postfix's own delivery log (step 2.3, [design R1–R10](../../plan/steps/05-routing.md), [ADR-0021](../adr/0021-mail-routing-and-delivery-status.md), [operations](../../deployment/mail-routing.md)).

**Approval today is the development-only pass-through** (`DELIVERY_DEV_PASSTHROUGH_ENABLED=true`, refused unless `APP_ENV` is `local` or `ci`): it approves every pending recipient without scanning or policy. The real producers of `mail.delivery.approved.v1` (policy engine 5.x, quarantine release 5.3/6.1) are planned; the contract they will use exists.

```mermaid
sequenceDiagram
  autonumber
  participant DB as MySQL writer (outbox, deliveries)
  participant PE as policy-engine (PLANNED 5.2)
  participant DP as delivery-worker dev pass-through (local/CI only)
  participant PL as delivery-worker planner
  participant RJ as delivery-worker reinjector
  participant S3 as S3 mail bucket
  participant PX as postfix-outbound 10026 reinject-inbound
  participant SM as smtp-adapter socketmap transport / tls_policy
  participant D as Tenant destination servers (customer, M365, Google)
  participant LOG as postfix-outbound maillog_file
  participant ST as delivery-worker status tailer

  Note over DB: ingestion committed email_messages, email_recipients,<br/>outbox mail.message.received.v1 (diagram 6)
  alt today (development and CI only)
    DP->>DB: poll outbox (cursor in stream_cursors, safety lag), processOnce
    DP->>DB: outbox mail.delivery.approved.v1 source=dev_passthrough,<br/>email_events delivery.approved (one transaction)
  else production
    rect rgb(255, 248, 225)
      PE->>DB: mail.delivery.approved.v1 source=policy (PLANNED 5.2)
    end
  end
  PL->>DB: poll outbox approvals (consumer delivery-worker.planner), processOnce
  PL->>DB: load message + approved recipients (organization from the row, never the payload)
  Note over PL: re-check direction (R1): inbound recipient domain still owned by the<br/>same organization? suspended → hold (gateway_hold), other owner → failed
  PL->>DB: one transaction: email_deliveries (pending, direction inbound,<br/>destination_key tenant:<domainId>), delivery_reinjections per<br/>(listener, direction, destination) chunked ≤ 100, planner audit rows,<br/>message → delivery_queued
  RJ->>DB: claim due rows FOR UPDATE SKIP LOCKED, lease
  RJ->>S3: GetObject org/<orgId>/… (prefix checked), read header block only
  Note over RJ: hop check (R10): Received count, gateway passes in both directions;<br/>over the limit → failed loop_detected, nothing sent
  RJ->>PX: EHLO delivery.gateway.local<br/>XFORWARD NAME/ADDR/HELO (original client), XFORWARD IDENT=dw1-<token><br/>MAIL FROM:<original sender> RET=HDRS ENVID=dw1-<token><br/>RCPT TO NOTIFY=NEVER ORCPT=rfc822;…
  PX->>SM: transport (user@domain): next-hop list of the domain's servers
  alt usable destination
    SM-->>PX: OK smtp:[h1]:25,[h2]:25 (priority order, hosts re-validated)
    PX-->>RJ: 250 per RCPT
  else no destination / gateway host / invalid
    SM-->>PX: OK retry:4.4.1 Destination not configured
    PX-->>RJ: 450 4.4.1 at RCPT
    RJ->>DB: delivery deferred (no_destination), worker retry with backoff
  end
  RJ->>PX: DATA: X-Gateway-Trace d=in (organization-neutral HMAC) + stored EML unchanged
  PX->>LOG: QID: client=…, orig_queue_id=dw1-<token>  (binding)
  PX-->>RJ: 250 queued as QID
  RJ->>DB: reinjection queued, deliveries queued (outbound_queue_id = QID)
  ST->>LOG: tail (cursor: file id + offset, committed after the batch)
  PX->>SM: tls_policy [h1]:25 → secure match=<preset names> / encrypt / may
  PX->>D: SMTP to h1 (verified TLS for M365/Google), failover to h2 on connect failure
  alt 2xx after the final dot
    D-->>PX: 250
    PX->>LOG: QID: to=<a>, relay=h1…, dsn=2.0.0, status=sent (250 …)
    ST->>DB: delivered (only from status=sent + 2.x.x), delivery_attempts success,<br/>audit row, email_events, outbox mail.delivery.status_changed.v1;<br/>all terminal → email_messages delivered / partially_delivered / failed
  else 4xx or connection failure
    PX->>LOG: status=deferred (… ) → deferred, retried by Postfix (diagram 19)
  else 5xx
    PX->>LOG: status=bounced → bounced; NO DSN to the external sender (NOTIFY=NEVER)
  end
```

**Legend.** Plain participants and messages: IMPLEMENTED (step 2.3). The shaded block and `(PLANNED x.y)` participants: PLANNED. The dev pass-through is IMPLEMENTED but **development and CI only**; it is not production behaviour and is replaced by the policy engine's approvals (5.x).

## Status

| Step in the sequence                                              | Status                 | Evidence or delivering step                                                                                                                                                              |
| ----------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dev pass-through approval (local/CI only, refused elsewhere)      | IMPLEMENTED            | `dev-passthrough.approver.test.ts`, `config.test.ts` (refusal outside local/ci), `apps/delivery-worker/integration/approvals.test.ts`; every `tests/integration/routing-*.test.ts` suite |
| Outbox poller (cursor, safety lag, processOnce, lock)             | IMPLEMENTED            | `outbox-poller.test.ts`, `approvals.test.ts`                                                                                                                                             |
| Policy approvals                                                  | PLANNED 5.2            | contract `deliveryApprovedV1` (`packages/event-contracts`)                                                                                                                               |
| Planning, groups per destination, direction re-check              | IMPLEMENTED            | `route-plan.test.ts`, `delivery-planner.test.ts`, `planning.test.ts`; `routing-inbound.test.ts` (two domains → two groups)                                                               |
| Reinjection session (token, XFORWARD, ENVID, NOTIFY=NEVER)        | IMPLEMENTED            | `smtp-client.test.ts`, `reinjection.test.ts`; `routing-inbound.test.ts` (binding line with `orig_queue_id=dw1-…`)                                                                        |
| Headers preserved, one trace, `Received: by out.gateway.local`    | IMPLEMENTED            | `routing-inbound.test.ts` (stored EML is a byte-identical suffix of the delivered copy; no tenant name or id in added headers)                                                           |
| Next-hop list, failover, provider TLS names                       | IMPLEMENTED            | `socketmap-lookup.service.test.ts`, `apps/smtp-adapter/integration/socketmap.test.ts`; `routing-retry.test.ts` (failover to alt1), `routing-mixed.test.ts` (verified TLS to M365)        |
| No destination → `450 4.4.1` → deferred `no_destination`          | IMPLEMENTED            | `reinjector.test.ts`; `routing-loops.test.ts` (self-referencing destination)                                                                                                             |
| Status from the delivery log, recorder, message aggregate         | IMPLEMENTED            | `postfix-log-parser.test.ts`, `status-signal-applier.test.ts`, `status-tailer.test.ts`, `packages/mail-routing/integration/recorder.test.ts`; `routing-inbound.test.ts`                  |
| Inbound bounce without DSN to the sender                          | IMPLEMENTED            | `routing-bounces.test.ts`                                                                                                                                                                |
| Real Microsoft 365 / Google Workspace connectors and certificates | not verifiable locally | test-CA sinks with the providers' SAN sets stand in for them ([mail-routing.md](../../deployment/mail-routing.md) V3)                                                                    |
