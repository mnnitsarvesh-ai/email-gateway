# 7. Outbound SMTP sequence

A tenant's mail system (Microsoft 365, Google Workspace or on-premises) relays outbound mail through the gateway. The gateway authenticates the **connection**, never a header: an organization-level **SMTP connector** authorizes it — SASL (`AUTH PLAIN/LOGIN` after STARTTLS on 587), a registered source network, or a pinned TLS client-certificate fingerprint (25). The envelope sender's domain must be an active domain of the **same** organization with `outbound_enabled`. The message is then ingested like inbound mail (`direction = outbound`), and later reinjected for delivery into `postfix-outbound` 10027, where `rspamd-outbound` DKIM-signs it and Postfix owns MX lookup, TLS, retries and DSNs (step 2.2, [design D9–D13](../../plan/steps/04-smtp-gateway.md), [ADR-0019](../adr/0019-smtp-gateway-topology.md), [ADR-0020](../adr/0020-dkim-signing.md)).

**There is no direct submission-to-Internet path.** Since step 2.3 the delivery-worker reinjects approved mail per recipient group ([diagram 17](17-outbound-routing-sequence.md): rate limits, 10027 via the recipient domain's MX, status from the delivery log; [diagram 19](19-retry-bounce-sequence.md): deferrals, bounces with DSN, expiry). Scanning (4.x/4.5) and policy (5.2) are planned; until they exist the only approval source is the **development-only pass-through** (local/CI).

```mermaid
sequenceDiagram
  autonumber
  participant T as Tenant mail server
  participant PO as postfix-outbound (587 submission, 25 connector relay)
  participant SA as smtp-adapter (SASL :10042, socketmap :10041, policy :10040)
  participant ING as smtp-adapter LMTP :10051 (direction outbound)
  participant DB as MySQL writer + S3
  participant W as email-worker, policy-engine (PLANNED 4.x, 5.2)
  participant DW as delivery-worker (step 2.3)
  participant PR as postfix-outbound 10027 reinject-outbound
  participant RO as rspamd-outbound (DKIM) + redis-dkim
  participant MX as Recipient MX
  participant BH as smtp-adapter bounce LMTP :10052

  alt 587 submission
    T->>PO: EHLO, STARTTLS (required, no AUTH offered before), AUTH PLAIN
    PO->>SA: Dovecot auth: AUTH secured, PLAIN
    alt valid connector secret (Argon2id), connector and organization active
      SA-->>PO: OK user=egc-…
    else wrong credentials
      SA-->>PO: FAIL (PO answers 535 5.7.8)
    else DB/Redis failure or throttled
      SA-->>PO: connection closed (PO answers 454 4.7.0)
    end
  else 25 connector relay
    T->>PO: EHLO, optional STARTTLS with client certificate
    PO->>SA: socketmap relay_ccert (certificate SHA-256) or relay_client (client IP)
    alt no matching connector
      PO-->>T: 554 5.7.1 Access denied
    end
  end
  T->>PO: MAIL FROM, RCPT TO
  PO->>SA: policy_context=submission or relay
  alt sender domain of another organization / not outbound-enabled
    PO-->>T: 550 5.7.1 Sender address not authorized
  else recipient suppressed
    PO-->>T: 550 5.7.1 Recipient address suppressed
  else per-tenant per-minute/day limit
    PO-->>T: 450 4.7.1 Rate limit exceeded
  else source-IP connector with require_tls and no TLS
    PO-->>T: 550 5.7.1 Must issue a STARTTLS command first
  else Redis/DB failure or adapter unreachable
    PO-->>T: 4xx (fail closed)
  else pass
    SA-->>PO: DUNNO
  end
  T->>PO: DATA
  PO->>PO: spool, 250 queued (content_filter = LMTP 10051)
  PO->>ING: LMTP with XFORWARD IDENT
  alt From header domain differs from the authenticated sender domain
    ING-->>PO: 550 5.7.1 From header does not match … (DSN to the authenticated sender)
  else stored
    ING->>DB: S3 EML + one transaction (email_messages direction=outbound, outbox), then 250
  end
  rect rgb(255, 248, 225)
    Note over W: scanning (diagram 9) incl. DLP 4.5, then policy: deliver, tag, quarantine or discard
    W->>DW: mail.delivery.approved.v1 source=policy (PLANNED 4.x, 5.2)
  end
  Note over DW: approval by the policy-engine (step 5.2)#59;<br/>plan per recipient domain, outbound rate limits (diagram 17)
  DW->>PR: SMTP reinject from POSTFIX_REINJECT_NETWORKS: XFORWARD (IDENT = token),<br/>MAIL … RET=HDRS ENVID=token, RCPT NOTIFY=FAILURE,DELAY, X-Gateway-Trace d=out
  PR->>SA: policy_context=reinject-outbound: sender tenant + outbound-enabled,<br/>suppression, HEXISTS dkim_selectors (fail closed: 4.7.0)
  PR->>RO: milter: sign with the domain's active RSA key (keys published by the api)
  PR->>MX: content_filter=smtp: → MX lookup of the recipient domain (never transport_maps), TLS may, SMTP
  alt 2xx
    MX-->>PR: 250
    Note over PR,DW: delivery log status=sent → delivered (diagram 17)
  else 4xx or connection failure
    MX-->>PR: deferred, Postfix retries with backoff until maximal_queue_lifetime
  else 5xx or queue lifetime exceeded
    PR-->>T: DSN to the envelope sender (authenticated tenant user)
    PR->>BH: postmaster copy from double-bounce@ (notify_classes bounce, delay)
    Note over BH: counted only with the outbound X-Gateway-Trace of the sender organization
    BH->>DB: bounce_events#59; hard address failure: delivery_suppressions (hard_bounce)
  end
```

**Legend.** Plain messages: IMPLEMENTED. Messages inside the shaded (amber) block and participants marked `(PLANNED x.y)`: PLANNED. Locally "the Internet" is `mail-sink`, reached through `dns-sink` MX records (profile `smtp-test`); `postfix-outbound` resolves nothing else.

## Status

| Step in the sequence                                          | Status                  | Evidence or delivering step                                                                                                                                                                |
| ------------------------------------------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 587: STARTTLS required, AUTH only after STARTTLS, `530`/`535` | IMPLEMENTED             | `infrastructure/postfix-outbound/master.cf`; `smtp-relay-control.test.ts` suites 3, 4                                                                                                      |
| SASL against `smtp_connectors` (Argon2id), temp → `454`       | IMPLEMENTED             | `sasl-server.service.test.ts`, `apps/smtp-adapter/integration/sasl.test.ts`, `smtp-fail-closed.test.ts`                                                                                    |
| Source-IP and client-certificate connectors on 25             | IMPLEMENTED             | `socketmap-lookup.service.test.ts`, `smtp-outbound.test.ts` (cert fingerprint, smtp-tools /32, `require_tls`)                                                                              |
| Sender ownership, suppressions, per-tenant limits             | IMPLEMENTED             | `policy-decision.service.test.ts`, `smtp-outbound.test.ts` (`550 5.7.1`, `450 4.7.1`)                                                                                                      |
| Outbound ingestion (`direction = outbound`), From check       | IMPLEMENTED             | `ingestion.service.test.ts`, `smtp-outbound.test.ts` (stored; mismatch bounced)                                                                                                            |
| Connector API, recipient allow-lists                          | IMPLEMENTED             | `apps/api/integration/smtp-connectors.test.ts`, `tenant-isolation-smtp.test.ts`                                                                                                            |
| Reinject-outbound 10027 + DKIM signing                        | IMPLEMENTED             | `smtp-outbound.test.ts` (signature verified with mailauth against `domain_dkim_keys.public_key`), `dkim-signing-publisher.test.ts`                                                         |
| Reinject-inbound 10026 via transport and TLS maps             | IMPLEMENTED             | `smtp-outbound.test.ts` (tenant destination `mx.sink.test`, `required` → TLS)                                                                                                              |
| Bounce notices → `bounce_events`, `delivery_suppressions`     | IMPLEMENTED             | `bounces.test.ts`, `smtp-outbound.test.ts` (hard bounce from mail-sink; counted only with the outbound trace, §12.7)                                                                       |
| Connector types for M365 / Google                             | PLANNED 8.2             |                                                                                                                                                                                            |
| Outbound scanning and policy                                  | PLANNED 4.5, 5.2        | `organization_features` (`outbound_filtering`, `dlp`)                                                                                                                                      |
| delivery-worker reinjection, `email_deliveries` tracking      | IMPLEMENTED 2.3         | diagrams 17 and 19; `routing-mixed.test.ts`, `routing-bounces.test.ts`, `routing-rate-limit.test.ts`; [contracts.md §15](../contracts.md#15-reinjection-delivery-worker--postfix-outbound) |
| Approval by scanning and policy                               | IMPLEMENTED 4.1–5.2     | policy-engine approvals after the scan (`policy-smtp.test.ts`); the development-only pass-through was removed in 5.2                                                                       |
| Ed25519 dual signing, MTA-STS / DANE                          | PLANNED (not scheduled) | design §10                                                                                                                                                                                 |
