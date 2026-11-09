# 17. Outbound routing and delivery sequence

What happens to an outbound message after ingestion (diagram 7 covers submission and ingestion): per-recipient direction from ingestion (`outbound` unless the recipient domain is an active domain of the **same** organization), approval, the delivery-worker's outbound rate limits, reinjection into `postfix-outbound` 10027, where `content_filter=smtp:` makes Postfix resolve the **recipient domain's MX** and never consult `transport_maps` — so a recipient in **another tenant's** domain on this gateway is reached through that tenant's public MX and ingested as that tenant's own inbound message — DKIM signing, delivery, and the status from the delivery log (step 2.3, [design R1, R4, R8, R9, R11](../../plan/steps/05-routing.md), [ADR-0021](../adr/0021-mail-routing-and-delivery-status.md)).

```mermaid
sequenceDiagram
  autonumber
  participant ING as smtp-adapter LMTP 10051 (outbound listener)
  participant DB as MySQL writer
  participant PE as policy-engine (PLANNED 5.2)
  participant DW as delivery-worker (pass-through, planner, reinjector)
  participant RL as Redis (dw:rl:* counters)
  participant PR as postfix-outbound 10027 reinject-outbound
  participant SA as smtp-adapter policy reinject-outbound
  participant RO as rspamd-outbound (DKIM)
  participant MX as Recipient MX (Internet)
  participant GW as Gateway inbound MX (other tenant's domain)
  participant LOG as maillog_file → status tailer

  ING->>DB: per recipient classifyRecipient: own active domain → internal,<br/>anything else (incl. another tenant's domain) → outbound#59;<br/>email_recipients.direction, email_messages.direction (internal only if all internal)
  alt today (development and CI only)
    DW->>DB: dev pass-through: mail.delivery.approved.v1 source=dev_passthrough
  else production
    rect rgb(255, 248, 225)
      PE->>DB: mail.delivery.approved.v1 source=policy (PLANNED 5.2)
    end
  end
  DW->>DB: plan: one group per recipient domain (destination_key mx:<domain>),<br/>suppressed recipients → suppressed, direction changed → failed
  DW->>RL: one Lua script: tenant, tenant×domain, destination-domain minute windows#59;<br/>increment only if the whole group fits
  alt over a limit
    RL-->>DW: over
    DW->>DB: deliveries deferred gateway_rate_limited, row pending until the next window
  else Redis error
    DW->>DB: deferred gateway_rate_limit_unavailable (fail closed, nothing sent)
  else fits
    RL-->>DW: ok
    DW->>PR: EHLO, XFORWARD (original client), XFORWARD IDENT=dw1-<token>,<br/>MAIL FROM:<authenticated sender> RET=HDRS ENVID=dw1-<token>,<br/>RCPT NOTIFY=FAILURE,DELAY ORCPT=…, DATA: X-Gateway-Trace d=out + EML
    PR->>SA: sender active + outbound-enabled, suppression, DKIM selector published
    PR->>RO: milter: DKIM-sign with the domain's key
    PR-->>DW: 250 queued as QID
    DW->>DB: reinjection + deliveries queued (outbound_queue_id)
  end
  Note over PR: content_filter=smtp: (empty next hop = recipient domain):<br/>MX lookup, transport_maps NEVER consulted (no tenant shortcut)
  alt external domain
    PR->>MX: SMTP (TLS may), Postfix retries 4xx itself
    MX-->>PR: 250
  else another tenant's domain on this gateway
    PR->>GW: SMTP to its public MX (the gateway)
    Note over GW: full inbound path for that tenant (diagram 6, 16):<br/>own message row, own policies, own destination
    GW-->>PR: 250
  end
  PR->>LOG: QID: to=<a>, relay=…, dsn=2.0.0, status=sent
  LOG->>DB: delivered + attempt + audit + email_events + outbox status_changed.v1
```

**Legend.** Plain messages: IMPLEMENTED (step 2.2 for submission, policy and DKIM; step 2.3 for everything from classification on). Shaded block: PLANNED 5.2. The dev pass-through is development and CI only. Failure paths (deferral, bounce with DSN, expiry) are diagram 19.

## Status

| Step in the sequence                                               | Status                 | Evidence or delivering step                                                                                                                                                   |
| ------------------------------------------------------------------ | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Classification at ingestion (`email_recipients.direction`)         | IMPLEMENTED            | `direction.test.ts`, `ingestion.service.test.ts`, `apps/smtp-adapter/integration/ingestion.test.ts`; `routing-mixed.test.ts`                                                  |
| Message direction `internal` only when every recipient is internal | IMPLEMENTED            | `routing-mixed.test.ts` (all-internal submission)                                                                                                                             |
| Per-domain groups, suppressed recipients                           | IMPLEMENTED            | `route-plan.test.ts`, `planning.test.ts`                                                                                                                                      |
| Outbound rate limits, fail closed                                  | IMPLEMENTED            | `outbound-rate-limiter.test.ts`, `apps/delivery-worker/integration/rate-limit.test.ts`; `routing-rate-limit.test.ts` (1/min, three windows; Redis stopped)                    |
| 10027 bypasses `transport_maps`; other tenant via its public MX    | IMPLEMENTED            | `infrastructure/postfix-outbound/master.cf`; [mail-routing.md](../../deployment/mail-routing.md) V1; `routing-mixed.test.ts` (`relay=gw-mx.sink.test`, own message row for B) |
| DKIM signing on 10027                                              | IMPLEMENTED            | `smtp-outbound.test.ts` (step 2.2)                                                                                                                                            |
| Delivered only from the delivery log                               | IMPLEMENTED            | `postfix-log-parser.test.ts`, `transitions.test.ts`; `routing-mixed.test.ts`                                                                                                  |
| Policy approvals, outbound scanning                                | PLANNED 5.2, 4.5       |                                                                                                                                                                               |
| Delivery to real Internet MX hosts                                 | not verifiable locally | `dns-sink` + `mail-sink` stand in for the Internet                                                                                                                            |
