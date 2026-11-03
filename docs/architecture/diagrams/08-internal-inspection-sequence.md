# 8. Internal email inspection and direction resolution

Internal mail is mail between two users of the **same** organization that the tenant routes through the gateway (for example a Microsoft 365 connector that sends internal mail out for inspection, then back in). Direction (`inbound`, `outbound` or `internal`) decides which policies, engines and routes apply, so it must not be spoofable.

**Direction is derived from the listener or connector the message arrived on and the organization's verified domains. It is never derived from headers** (`From`, `X-MS-Exchange-Organization-*`, `Received` or any other), because every header is sender-controlled. This rule is already stated in `packages/shared-types` (`MailDirection`) and the overview; its implementation is **PLANNED 2.3**.

## Direction resolution

```mermaid
flowchart TB
  classDef impl fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b1b1b
  classDef planned fill:#fff8e1,stroke:#b26a00,stroke-width:2px,stroke-dasharray:6 4,color:#1b1b1b
  classDef ext fill:#eceff1,stroke:#546e7a,stroke-width:1px,color:#1b1b1b

  arrive["Message arrives<br/>PLANNED 2.3"]:::planned
  listener{"Which listener?<br/>IMPLEMENTED 2.2 (port decides the LMTP direction)"}:::impl
  mxRcpt["Inbound MX listener:<br/>organization = verified owner of the recipient domain<br/>domains.verified_name, inbound_enabled"]:::planned
  inbound["direction = inbound<br/>even when the sender domain is the tenant's own:<br/>spoofed internal senders are handled by SPF, DMARC, BEC"]:::planned
  conn["Outbound listener:<br/>organization = authenticated SMTP connector<br/>(SASL, source IP, client certificate)<br/>IMPLEMENTED 2.2"]:::impl
  senderOk{"Envelope sender domain verified<br/>for the same organization?"}:::planned
  reject["REJECT 5.7.1 in-session"]:::planned
  perRcpt{"For each recipient: is the recipient<br/>domain a verified domain of the<br/>same organization?"}:::planned
  internal["direction = internal"]:::planned
  outbound["direction = outbound"]:::planned
  split["Mixed recipients: per-recipient split<br/>into one message per direction<br/>PLANNED 2.3"]:::planned
  headers["Headers: From, Received, X-MS-*<br/>NEVER used for direction"]:::ext

  arrive --> listener
  listener -->|"MX :25"| mxRcpt --> inbound
  listener -->|"relay listener"| conn --> senderOk
  senderOk -->|"no"| reject
  senderOk -->|"yes"| perRcpt
  perRcpt -->|"all yes"| internal
  perRcpt -->|"all no"| outbound
  perRcpt -->|"some"| split
  headers -.-x listener
```

## Internal inspection sequence

```mermaid
sequenceDiagram
  autonumber
  participant U as Tenant mail system (connector)
  participant PO as postfix-outbound connector listener
  participant SA as smtp-adapter policy and ingestion (direction internal PLANNED 2.3)
  participant DB as MySQL writer
  participant EW as email-worker (PLANNED 4.x)
  participant PE as policy-engine (PLANNED 5.2)
  participant DW as delivery-worker (PLANNED 2.3)
  participant PX as postfix-outbound 10026 reinject-inbound
  participant UD as Tenant inbound destination

  rect rgb(255, 248, 225)
    U->>PO: SMTP from the tenant connector (IP allow-list or TLS client cert)
    PO->>SA: policy request, then LMTP after queueing
    SA->>DB: organization from the connector, sender and recipient domains<br/>both verified for that organization
    SA->>DB: INSERT email_messages direction=internal, outbox, COMMIT
    SA-->>PO: 250 only after COMMIT
    Note over EW: only when organization_features internal_inspection is enabled,<br/>otherwise policy short-circuits to deliver
    EW->>DB: email_scans, scan_engine_results (malware, URL, DLP for lateral movement)
    PE->>DB: policies with direction internal or any, policy_execution_logs
    PE->>DW: mail.policy.decided.v1 deliver or quarantine
    DW->>DB: delivery_routes direction inbound, domain_mail_servers role inbound_destination
    DW->>PX: reinject with the route to the tenant's own mail system
    PX->>UD: SMTP with tls_mode from the route (loop prevention: PLANNED 2.3)
  end
```

**Legend.** The listener decision and the connector authentication are IMPLEMENTED (step 2.2); everything else is PLANNED (amber dashed boxes, shaded sequence block). The grey "Headers" node is an external input that is deliberately **not** connected to the decision (the `-.-x` arrow).

## Status

| Element                                     | Status      | Evidence or delivering step                                                                                                                                                                          |
| ------------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "Never from headers" rule                   | Documented  | `packages/shared-types` (`MailDirection` comment), overview, ADR-0012. No code resolves direction yet                                                                                                |
| Direction resolution, per-recipient split   | PLANNED 2.3 | `email_messages.direction`, `domains`, `domain_mail_servers` exist                                                                                                                                   |
| Listeners and connector authentication      | IMPLEMENTED | `infrastructure/postfix-outbound/master.cf`, smtp-adapter connectors; `smtp-outbound.test.ts`. Today such mail is ingested with `direction = outbound` (the listener's direction); `internal` is 2.3 |
| Reinjection to the tenant's own server      | IMPLEMENTED | 10026 + transport/TLS maps; `smtp-outbound.test.ts` ("reinject-inbound … transport and TLS maps")                                                                                                    |
| M365 / Google connector specifics           | PLANNED 8.2 |                                                                                                                                                                                                      |
| Internal-inspection feature flag            | PLANNED 1.2 | `organization_features.feature_key = internal_inspection` (table exists)                                                                                                                             |
| Routing back to the tenant, loop prevention | PLANNED 2.3 | `delivery_routes`, `domain_mail_servers` (`inbound_destination`) exist                                                                                                                               |
