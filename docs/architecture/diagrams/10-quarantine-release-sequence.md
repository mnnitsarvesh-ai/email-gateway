# 10. Quarantine and release sequence

`policy-engine` decides per recipient. A quarantine decision writes a `quarantine_messages` row (one per message and recipient) that points at the EML in S3. A release, by an admin or by an approved end-user request, goes through `api`, is recorded in `quarantine_actions` and `quarantine_release_logs`, and **re-validates** the message with a fresh scan before it is delivered. Nothing is bounced.

**Everything in this sequence is PLANNED** (policy 5.2, quarantine 5.3, REST conventions 6.1, authentication and RBAC 1.3, digests 6.2). The tables are IMPLEMENTED in step 1.1. The event types for release (`mail.quarantine.*`) do not exist in `packages/event-contracts` yet; their names are placeholders to be fixed in step 5.3.

```mermaid
sequenceDiagram
  autonumber
  participant MQ as RabbitMQ
  participant PE as policy-engine (PLANNED 5.2, 5.3)
  participant DB as MySQL writer
  participant NW as notification-worker (PLANNED 6.2)
  actor A as Admin or end user
  participant API as api (PLANNED 5.3, 6.1)
  participant EW as email-worker (PLANNED 5.3)
  participant DW as delivery-worker (PLANNED 2.3)

  rect rgb(255, 248, 225)
    MQ->>PE: mail.message.scanned.v1 (queue policy-engine.message-scanned)
    PE->>DB: processOnce, load scans, active policy versions, exceptions
    PE->>DB: INSERT policy_execution_logs (decisive version, matched ids, trace)
    PE->>DB: INSERT quarantine_messages per quarantined recipient<br/>(reason, eml_object_key, expires_at from organization_settings)
    PE->>DB: UPDATE email_messages status quarantined, final_action, status history
    PE->>DB: INSERT message_outbox mail.policy.decided.v1 action quarantine
    PE->>MQ: published by the outbox relay
    MQ->>NW: mail.policy.decided.v1, digest or alert (organization_settings digest_enabled)
  end

  rect rgb(255, 248, 225)
    A->>API: POST /v1/quarantine/{publicId}/release with Idempotency-Key
    API->>API: authenticate, organization from the principal (never a header),<br/>RBAC quarantine:release or quarantine:request_release
    API->>DB: SELECT quarantine_messages by public_id AND organization_id (writer)
    API->>DB: BEGIN, INSERT quarantine_actions (unique organization_id + idempotency_key)
    alt duplicate idempotency key
      DB-->>API: unique violation
      API-->>A: 200 with the original action, nothing repeated
    else end user without release permission
      API->>DB: status release_requested, action request_release, COMMIT
      API-->>A: 202 waiting for approval (approve_release by an admin repeats this flow)
    else admin release
      API->>DB: INSERT quarantine_release_logs status pending, audit_logs,<br/>message_outbox mail.quarantine.release_requested.v1 (name TBD in 5.3), COMMIT
      API-->>A: 202 accepted
    end
    MQ->>EW: release requested
    EW->>DB: email_scans scan_kind release_revalidation, scan_engine_results
    alt re-validation finds malware or a blocking verdict
      EW->>DB: quarantine_release_logs status blocked_by_revalidation, revalidation_verdict
    else allowed
      EW->>MQ: release approved for delivery
      MQ->>DW: deliver to released_to
      DW->>DB: email_deliveries delivery_seq 1 or higher, delivery_attempts
      DW->>DB: quarantine_release_logs status delivered, delivery_id,<br/>quarantine_messages status released, released_at
    end
  end
```

**Legend.** Every message is PLANNED (shaded blocks). `actor` marks a human.

## Status

| Element                                                                | Status                | Evidence or delivering step                                                                                                                   |
| ---------------------------------------------------------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `quarantine_messages`, `quarantine_actions`, `quarantine_release_logs` | IMPLEMENTED           | Step 1.1 schema. Not partitioned; unique `(message_id, recipient_id)` and `(organization_id, idempotency_key)`                                |
| `policy_execution_logs`                                                | IMPLEMENTED           | Partitioned table, step 1.1                                                                                                                   |
| Queue `policy-engine.message-scanned`, event `policyDecidedV1`         | IMPLEMENTED           | `topology.ts`, `events.test.ts`                                                                                                               |
| Policy evaluation and quarantine writes                                | PLANNED 5.2, 5.3      |                                                                                                                                               |
| Release endpoint, idempotency key, RBAC                                | PLANNED 5.3, 6.1, 1.3 | Permissions `quarantine:release`, `quarantine:request_release`, `quarantine:delete` are defined in the step 1.1 seed catalog (WP4, same wave) |
| Re-validation scan                                                     | PLANNED 5.3           | `email_scans.scan_kind = release_revalidation`                                                                                                |
| Release event types                                                    | PLANNED 5.3           | Not in `events.ts`                                                                                                                            |
| Digests and notifications                                              | PLANNED 6.2           |                                                                                                                                               |
| Quarantine expiry purge                                                | PLANNED 5.3           | By `quarantine_messages.expires_at` (indexed `(status, expires_at)`)                                                                          |
