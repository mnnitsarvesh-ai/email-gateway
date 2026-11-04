# 6. Inbound SMTP sequence

An Internet sender delivers mail for a tenant domain. In-session (pre-queue), only `smtp-adapter` (socketmap relay domains, the policy service) and the Rspamd milter may reject or defer, and all of them **fail closed to 4xx** (ADR-0006, ADR-0019). After Postfix has queued the message, LMTP ingestion streams it to S3 and commits, **per organization**, the registry, message, recipient, event and outbox rows in one MySQL writer transaction, and answers `250` per recipient only after that commit (step 2.2, [design D2–D8](../../plan/steps/04-smtp-gateway.md)). What happens next — approval, planning, reinjection on 10026 and per-recipient delivery status — is [diagram 16](16-inbound-routing-sequence.md) (step 2.3).

```mermaid
sequenceDiagram
  autonumber
  participant S as Sending MTA
  participant PF as postfix (inbound MX :25, postscreen)
  participant SM as smtp-adapter socketmap :10041
  participant SA as smtp-adapter policy :10040
  participant R as Rspamd milter :11332
  participant ING as smtp-adapter LMTP ingestion :10050
  participant S3 as S3 mail bucket
  participant DB as MySQL writer
  participant RL as event-relay (3.2)
  participant MQ as RabbitMQ email.ingestion

  S->>PF: EHLO (STARTTLS, TLS >= 1.2), MAIL FROM, RCPT TO
  PF->>SM: relay_domain (recipient domain)
  alt active, verified, inbound-enabled tenant domain
    SM-->>PF: OK active
  else unknown or inactive domain
    SM-->>PF: NOTFOUND
    PF-->>S: 554 5.7.1 Relay access denied (no open relay)
  else adapter unreachable or DB error
    PF-->>S: 451 4.3.0 Temporary lookup failure
  end
  PF->>SA: policy_context=inbound, protocol_state=RCPT,<br/>recipient, client_address, size, instance
  Note over SA: tenant from the recipient domain (verified owner, Redis cache),<br/>per-IP and per-tenant rate, recipient validation, size
  alt unknown recipient, authoritative allow-list
    SA-->>PF: REJECT 5.1.1
    PF-->>S: 550 5.1.1 User unknown
  else rate limited
    SA-->>PF: DEFER_IF_PERMIT 4.7.1
    PF-->>S: 450 4.7.1
  else Redis/DB failure, timeout, unreachable
    PF-->>S: 450 4.3.5 (DEFER_IF_PERMIT, fail closed)
  else pass
    SA-->>PF: DUNNO
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
  PF->>SA: protocol_state=END-OF-MESSAGE (size vs recorded tenant limit)
  PF->>PF: fsync the queue file (postfix-spool), long queue id
  PF-->>S: 250 2.0.0 Ok: queued as QUEUE-ID
  PF->>ING: LMTP LHLO mx.gateway.local, XFORWARD (ADDR, HELO, IDENT=QUEUE-ID),<br/>MAIL, RCPT per recipient, DATA
  Note over ING: each RCPT: owner of the recipient domain (resolveDomainOwner)<br/>no owner: 451 4.3.0 for that recipient
  ING->>S3: stream EML once to org/{orgId}/eml/yyyy/mm/dd/{objectRef}.eml,<br/>CopyObject per additional organization
  alt valid X-Gateway-Trace for this organization and direction
    ING-->>PF: 554 5.4.6 Routing loop detected (that organization's recipients)
  end
  loop one writer transaction per organization
    ING->>DB: INSERT message_identities (organization_id, ingest_key)
    alt duplicate ingest_key (LMTP retry after a lost 250)
      DB-->>ING: already committed
      ING-->>PF: 250 for that organization's recipients, nothing written again
    else new message
      ING->>DB: email_messages (status received), email_recipients,<br/>email_events received, message_outbox mail.message.received.v1
      ING->>DB: COMMIT
      ING-->>PF: 250 2.0.0 Ok per recipient, only after COMMIT
    end
  end
  alt S3 or MySQL failure or timeout
    ING-->>PF: 451 4.3.0 for that organization's recipients; Postfix keeps them queued and retries
  end
  RL->>DB: SELECT unpublished rows of its shard (GET_LOCK er:relay#i/n), id order
  RL->>MQ: publish with confirms, mandatory, routing key org.<id>.mail.message.received.v1
  MQ-->>RL: confirm (routed to email.received and the email.analytics firehose)
  RL->>DB: SET published_at = NOW(3) WHERE published_at IS NULL (confirmed rows only)
```

**Legend.** Plain messages: IMPLEMENTED. Messages inside the shaded (amber) block and participants marked `(PLANNED x.y)`: PLANNED. MIME parsing, `email_headers` and `email_attachments` rows are implemented post-queue by the email-worker (step 3.1, [diagram 20](20-mime-ingestion-sequence.md)); the event-relay (step 3.2, [diagram 21](21-event-relay-sequence.md)) publishes the outbox; the email-worker consumes `email.received` and the delivery-worker `email.delivery.pending`. Only the development pass-through (local/CI) still reads the outbox itself (diagram 16).

## Status

| Step in the sequence                                        | Status          | Evidence or delivering step                                                                                                                        |
| ----------------------------------------------------------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Relay domains from the adapter, `554` for unknown domains   | IMPLEMENTED     | `infrastructure/postfix/main.cf` `relay_domains = socketmap:…`; `smtp-inbound.test.ts` suite 2/3; `mail-plane.test.ts` (451 without the adapter)   |
| STARTTLS (TLS ≥ 1.2), no AUTH on 25                         | IMPLEMENTED     | `smtp-relay-control.test.ts` suite 4                                                                                                               |
| Policy `inbound`: tenant, rates, recipient validation, size | IMPLEMENTED     | `policy-decision.service.test.ts`, `apps/smtp-adapter/integration/policy.test.ts`, `smtp-inbound.test.ts` (550 5.1.1 allow-list, monitor accepted) |
| Fail closed (policy, Redis, adapter)                        | IMPLEMENTED     | `smtp-fail-closed.test.ts` (Redis down; adapter container stopped in CI), `mail-plane.test.ts`                                                     |
| Rspamd milter, `reject = 15`, `milter_default_action`       | IMPLEMENTED     | `main.cf`, `local.d/actions.conf`; every stack suite message passes through it                                                                     |
| Disk spool, `250 queued`, survives `docker compose restart` | IMPLEMENTED     | `smtp-durability.test.ts` suite 6                                                                                                                  |
| LMTP handoff with XFORWARD, per-recipient replies           | IMPLEMENTED     | `lmtp-listener.test.ts`, `apps/smtp-adapter/integration/ingestion.test.ts`, `smtp-inbound.test.ts` suite 1                                         |
| S3 write, per-organization transaction, outbox row          | IMPLEMENTED     | `smtp-inbound.test.ts` suite 1 (bytes + SHA-256, rows, `messageReceivedV1`), suite 8 (multi-tenant split)                                          |
| `451` on S3 failure, stored exactly once after recovery     | IMPLEMENTED     | `smtp-durability.test.ts` suite 5 (`docker compose stop minio`)                                                                                    |
| Duplicate delivery (lost `250`) answers `250`, no new rows  | IMPLEMENTED     | `smtp-durability.test.ts` suite 7 (raw LMTP replay with the same IDENT and bytes)                                                                  |
| Loop guard `554 5.4.6`                                      | IMPLEMENTED     | `ingestion.service.test.ts`, `smtp-inbound.test.ts` suite 11                                                                                       |
| 40 sessions × 1 000 messages, zero loss                     | IMPLEMENTED     | `smtp-concurrency.test.ts` suite 9 (figures in the step note §12)                                                                                  |
| MIME parsing, `email_headers`, `email_attachments`          | IMPLEMENTED     | step 3.1, post-queue in the email-worker ([diagram 20](20-mime-ingestion-sequence.md)); `tests/integration/mime-ingestion.test.ts`                 |
| Outbox relay with publisher confirms                        | IMPLEMENTED 3.2 | `apps/event-relay`; `relay.test.ts`, stack `messaging-*.test.ts` (every outbox row of each run published)                                          |
| Delivery to the tenant after ingestion                      | IMPLEMENTED     | step 2.3, [diagram 16](16-inbound-routing-sequence.md); `tests/integration/routing-inbound.test.ts`                                                |
