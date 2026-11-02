# 7. Outbound SMTP sequence

A tenant's mail system (Microsoft 365, Google Workspace or on-premises) relays outbound mail through the gateway. The gateway authenticates the **connection**, never a header: either the client IP is in the tenant's allow-list (`domain_mail_servers` rows with `role = outbound_source` and an `ip_cidr`) or the connector authenticates (SMTP AUTH or a TLS client certificate). The envelope sender's domain must be a verified domain of the **same** organization with `outbound_enabled`. The message is then ingested and scanned like inbound mail, DKIM-signed, and handed to an outbound Postfix that owns MX lookup, TLS, retries and DSNs.

**Everything in this sequence is PLANNED.** The tables it uses exist (step 1.1). Steps: listener and relay authentication 2.2, direction and routing 2.3, scanning 4.x (DLP 4.5), policy 5.2, delivery tracking 2.3, suppressions 6.x, connectors 8.2.

```mermaid
sequenceDiagram
  autonumber
  participant T as Tenant mail server
  participant PO as Postfix outbound listener (PLANNED 2.2)
  participant SA as smtp-adapter policy (PLANNED 2.2)
  participant DB as MySQL writer
  participant ING as Ingestion (PLANNED 3.1)
  participant W as email-worker and policy-engine (PLANNED 4.x, 5.2)
  participant DW as delivery-worker (PLANNED 2.3)
  participant PX as Postfix outbound MTA with DKIM signer (PLANNED 2.2)
  participant MX as Recipient MX

  rect rgb(255, 248, 225)
    T->>PO: connect from client IP, optional STARTTLS with client cert, optional AUTH
    PO->>SA: policy request: client_address, sasl_username, ccert_fingerprint, sender, recipient
    SA->>DB: domains by sender domain, domain_mail_servers role outbound_source
    alt client IP not in ip_cidr and no authenticated connector
      SA-->>PO: action=REJECT 5.7.1 relay not permitted
      PO-->>T: 554 5.7.1
    else sender domain not verified for that organization or outbound disabled
      SA-->>PO: action=REJECT 5.7.1 sender domain not authorized
    else lookup fails (MySQL or Redis down)
      SA-->>PO: action=DEFER_IF_PERMIT 4.3.5, fail closed
      PO-->>T: 4xx, the tenant server retries
    else authorized, per-tenant outbound rate limit ok
      SA-->>PO: action=DUNNO, organization from the connection
    end
    T->>PO: DATA
    PO->>PO: spool, 250 queued
    PO->>ING: LMTP, direction resolved from listener + connector (see diagram 8)
    ING->>DB: registry, email_messages direction=outbound, outbox, COMMIT, then 250
    Note over W: scanning (diagram 9) with outbound engines such as DLP 4.5,<br/>then policy decides deliver, tag, quarantine or discard. Never a bounce.
    W->>DW: mail.policy.decided.v1 action=deliver
    DW->>DB: processOnce, INSERT email_deliveries status in_progress
    DW->>PX: SMTP reinject with the routing decision, record outbound_queue_id
    PX->>PX: DKIM sign with the active domain_dkim_keys selector<br/>(private key fetched by private_key_ref, never stored in MySQL)
    PX->>MX: MX lookup, TLS per policy, SMTP
    alt 2xx
      MX-->>PX: 250
    else 4xx or connection failure
      MX-->>PX: deferred, Postfix retries with backoff until maximal_queue_lifetime
    else 5xx or queue lifetime exceeded
      PX-->>T: DSN to the envelope sender (a real bounce, the sender is authenticated)
    end
    PX-->>DW: delivery status (mechanism decided in 2.3: DSN NOTIFY with ENVID or log feed)
    DW->>DB: delivery_attempts, email_deliveries status, bounce_events,<br/>delivery_suppressions on hard bounce
  end
```

**Legend.** Every participant and message is PLANNED (shaded block). The DKIM signing component (Rspamd `dkim_signing` or a separate milter on the outbound Postfix) is chosen in step 2.2.

## Status

| Step in the sequence                           | Status           | Evidence or delivering step                                                                        |
| ---------------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------- |
| Outbound listener and relay authentication     | PLANNED 2.2      | `domain_mail_servers` (`role`, `ip_cidr`, `tls_mode`), `domains.outbound_enabled` exist (step 1.1) |
| Connector types for M365 / Google              | PLANNED 8.2      |                                                                                                    |
| Direction `outbound` from listener + connector | PLANNED 2.3      | `email_messages.direction` enum exists                                                             |
| Outbound scanning and policy                   | PLANNED 4.5, 5.2 | `organization_features` (`outbound_filtering`, `dlp`)                                              |
| DKIM signing                                   | PLANNED 2.2      | Key lifecycle in 2.1 (`domain_dkim_keys.private_key_ref`, `status`)                                |
| Outbound Postfix retries, backoff and DSNs     | PLANNED 2.2      | ADR-0006: no retry scheduler in Node                                                               |
| Delivery tracking, bounces, suppressions       | PLANNED 2.3, 6.x | `email_deliveries`, `delivery_attempts`, `bounce_events`, `delivery_suppressions` exist            |
| Outbound TLS policy (MTA-STS, DANE)            | PLANNED 2.2      | `docs/security/README.md` lists it for the delivery phase                                          |
