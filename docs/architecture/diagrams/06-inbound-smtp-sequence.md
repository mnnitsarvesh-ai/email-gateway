# 6. Inbound SMTP sequence

An Internet sender delivers mail for a tenant domain. In-session (pre-queue), only the `smtp-adapter` policy service and the Rspamd milter may reject or defer, and both **fail closed to 4xx** (ADR-0006). After Postfix has queued the message, ingestion stores it and commits the message and its outbox row in **one** MySQL transaction, and answers `250` only after the commit.

```mermaid
sequenceDiagram
  autonumber
  participant S as Sending MTA
  participant PF as Postfix inbound MX
  participant SA as smtp-adapter policy :10040
  participant R as Rspamd milter :11332
  participant ING as smtp-adapter LMTP ingestion (PLANNED 2.2, 3.1)
  participant S3 as S3 mail bucket
  participant DB as MySQL writer
  participant RL as Outbox relay (PLANNED 3.2)
  participant MQ as RabbitMQ mail.events

  S->>PF: EHLO, MAIL FROM, RCPT TO
  Note over PF: relay control first: unknown domain gets 554 Relay access denied
  PF->>SA: request=smtpd_access_policy, protocol_state=RCPT,<br/>sender, recipient, client_address, helo_name, instance
  rect rgb(255, 248, 225)
    Note over SA,DB: PLANNED 2.2: resolve the tenant from the recipient domain (domains.verified_name: verified owner only,<br/>inbound_enabled), validate the recipient, apply per-tenant rate limits in Redis
  end
  SA-->>PF: action=DUNNO (implemented today)
  alt policy service unreachable or slower than 10 s
    PF-->>S: 450 4.3.5 (smtpd_policy_service_default_action = DEFER_IF_PERMIT)
  else decision throws or request malformed
    SA-->>PF: action=DEFER_IF_PERMIT 4.3.5 Policy service temporarily unavailable
    PF-->>S: 4xx tempfail, the sender retries
  end
  S->>PF: DATA
  PF->>R: milter: connect, headers, body
  alt score at or above 15
    R-->>PF: reject
    PF-->>S: 5xx in-session reject, no backscatter
  else Rspamd unreachable or times out
    PF-->>S: 4xx (milter_default_action = tempfail)
  else accepted
    R-->>PF: continue, add X-Spamd-Result and Authentication-Results
  end
  PF->>PF: write to the disk spool (queue id)
  PF-->>S: 250 queued
  Note over PF: Today relay_transport = discard. The message stops here locally.
  rect rgb(255, 248, 225)
    PF->>ING: LMTP LHLO, MAIL, RCPT per recipient, DATA (PLANNED 2.2)
    ING->>S3: stream EML to org/{organizationId}/eml/yyyy/mm/dd/{messageId}.eml (PLANNED 3.1)
    ING->>DB: BEGIN
    ING->>DB: INSERT message_identities (organization_id, ingest_key)
    alt duplicate ingest_key
      DB-->>ING: unique violation, already ingested
      ING-->>PF: 250 per recipient, nothing written again
    else new message
      ING->>DB: INSERT email_messages (id = registry id, status received),<br/>email_recipients, email_headers, email_attachments
      ING->>DB: INSERT message_outbox (mail.message.received.v1)
      ING->>DB: COMMIT
      ING-->>PF: 250 per recipient, only after COMMIT
    end
    alt S3 or MySQL failure
      ING-->>PF: 4xx, Postfix keeps the message in its spool and retries
    end
    RL->>DB: SELECT unpublished rows FOR UPDATE SKIP LOCKED (PLANNED 3.2)
    RL->>MQ: publish with publisher confirms, routing key mail.message.received.v1
    MQ-->>RL: confirm
    RL->>DB: SET published_at
  end
```

**Legend.** Plain messages: IMPLEMENTED. Messages inside the shaded (amber) blocks and participants marked `(PLANNED x.y)`: PLANNED. The policy request attributes come from Postfix ([SMTPD_POLICY_README](http://www.postfix.org/SMTPD_POLICY_README.html)); the adapter parses any `name=value` attribute today and uses none of them yet.

## Status

| Step in the sequence                                    | Status      | Evidence or delivering step                                                                                                                 |
| ------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Relay denial `554`                                      | IMPLEMENTED | `main.cf` `smtpd_relay_restrictions`; `mail-plane.test.ts` "refuses to relay"                                                               |
| Policy delegation, `DUNNO`                              | IMPLEMENTED | `policy-server.service.test.ts`; `mail-plane.test.ts` (250 when the adapter runs)                                                           |
| Fail closed when the policy service is down             | IMPLEMENTED | `mail-plane.test.ts` (4xx when the apps profile is stopped)                                                                                 |
| Tempfail when the decision throws or input is malformed | IMPLEMENTED | `policy-server.service.test.ts` ("tempfails (never accepts)"), `policy-protocol.test.ts`                                                    |
| Rspamd milter, `reject = 15`, `milter_default_action`   | IMPLEMENTED | `main.cf`, `local.d/actions.conf`. Configured, but no automated test drives a message through the milter; Rspamd itself is tested over HTTP |
| Disk spool, `250 queued`                                | IMPLEMENTED | Postfix with the `postfix-spool` volume. Locally the queued message is discarded                                                            |
| Tenant resolution, recipient validation, rate limits    | PLANNED 2.2 | `domains`, `domain_settings`, `organization_limits` tables exist                                                                            |
| LMTP handoff                                            | PLANNED 2.2 | `POSTFIX_RELAY_TRANSPORT=lmtp:inet:smtp-adapter:24` (comment in `infrastructure/postfix/entrypoint.sh`)                                     |
| S3 write, registry, single ingestion transaction        | PLANNED 3.1 | Tables `message_identities` (unique `(organization_id, ingest_key)`, tested in `schema.test.ts`), `email_*`, `message_outbox`               |
| Outbox relay with publisher confirms                    | PLANNED 3.2 | `RabbitMqService` opens a confirm channel today; no relay exists                                                                            |
