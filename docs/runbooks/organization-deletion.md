# Runbook: deleting a customer organization

Deleting a tenant is irreversible once its data is purged, so it is a deliberate, audited, two-person procedure with a cooling-off period. This runbook covers what the API does today (request, confirmation, cancellation, state) and the **purge job, which does not exist yet** (deferred; its required safeguards are specified below). Design: [D12 in the step design](../plan/steps/02-tenants-auth-rbac.md#d12-organizations-wp5). Endpoints: [docs/api/README.md](../api/README.md#organizations-organizations-tag).

## Who may do it

- Users of the **platform organization** holding `platform:organizations` (the `super_admin` and `platform_admin` roles), with a session that completed **MFA** (`403 MFA required` otherwise). API keys and platform-override sessions can never run these steps.
- **Four eyes:** the user who confirms must be a different platform user than the one who requested (`403`).
- The **platform organization** itself can never be suspended or deleted (`409`).

## States

```
active ──PATCH status──▶ suspended ──request──▶ pending_deletion ──confirm (2nd user, ≤ 72 h)──▶ deleted ──(purge job, deferred, after purge_after)──▶ purged
   ▲                        ▲                         │                                             │
   └──PATCH status──────────┴────────── cancel ───────┴──────────── cancel (before purge_after) ────┘
```

While an organization is `pending_deletion` or `deleted`, every change to it (name, plan, settings, features, limits, status) is refused with `409`. `deleted` organizations are hidden from `GET /organizations` unless `status=deleted` is asked for.

## Procedure

All calls are under `/api/v1`, with a platform user's MFA access token.

1. **Suspend** the organization (this already cuts off access: every session is revoked, cached principals and API keys stop working on the next request):
   `PATCH /organizations/{id}/status { "status": "suspended", "reason": "Offboarding per ticket 1234" }`
2. **Check legal holds and archives** with compliance before going further. An active row in `archive_legal_holds` for the organization blocks the request and the confirmation (`409 Active legal hold`); release holds only through the legal process that created them, never to unblock a deletion.
3. **Request** (user 1):
   `POST /organizations/{id}/deletion { "reason": "Contract ended 2026-10-31, ticket 1234", "confirmSlug": "<the organization slug>" }`
   The organization must be `suspended` (`409` otherwise) and `confirmSlug` must equal its slug (`400`). The state becomes `pending_deletion`; `GET /organizations/{id}/deletion` shows `confirmationDeadline`.
4. **Confirm** (user 2, a different platform user) within `ORG_DELETION_CONFIRM_WINDOW_HOURS` (default 72 h) of the request:
   `POST /organizations/{id}/deletion/confirm { "confirmSlug": "<slug>" }`
   After the window the confirmation is refused (`409`): cancel and request again. On success the organization is `deleted` (`deleted_at` set), **every API key is revoked** (`api_keys.revoked_at`), **every session is revoked** and the authentication caches are invalidated. `purge_after` is set (below).
5. **Verify** with `GET /organizations/{id}/deletion` (`state: deleted`, `purgeAfter`, `requestedBy`, `confirmedBy`) and the audit trail (below).

### Cancelling

`POST /organizations/{id}/deletion/cancel { "reason": "Customer renewed, ticket 1240" }` works from `pending_deletion`, and from `deleted` while `now < purge_after` (`409` afterwards). The organization returns to **`suspended`**; reactivate it with a separate `PATCH /organizations/{id}/status { "status": "active" }`. The deletion columns are cleared (the audit row keeps the history). Note what a cancelled confirmation does **not** restore: API keys revoked by the confirmation stay revoked (the customer creates new ones) and revoked sessions stay revoked (users log in again).

## `purge_after`

Computed at confirmation:

```
purge_after = max(now + ORG_DELETION_RETENTION_DAYS, MAX(email_archives.retain_until) of the organization's live archives)
```

`ORG_DELETION_RETENTION_DAYS` defaults to 30 (minimum 7). An organization with archives under a longer retention obligation therefore keeps its data until the last archive may be deleted. The value is fixed at confirmation; archives or legal holds added later are handled by the purge job's own checks (below).

## Audit trail

Each step writes one `audit_logs` row (`resource_type = organization`, `resource_id` = organization public id, `actor_id` = platform user public id, `organization_id` = the organization):

| Action                            | Metadata                                                                                                          |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `organization.status_changed`     | `from`, `to`, `reason`                                                                                            |
| `organization.deletion_requested` | `reason`, `confirmationWindowHours`                                                                               |
| `organization.deletion_confirmed` | `purgeAfter`, `apiKeysRevoked`                                                                                    |
| `organization.deletion_cancelled` | `reason`, `fromStatus`, `requestedAt`, `requestedBy`, `requestReason`, `confirmedAt`, `confirmedBy`, `purgeAfter` |

```sql
SELECT created_at, action, actor_id, JSON_PRETTY(metadata)
FROM audit_logs
WHERE resource_type = 'organization' AND resource_id = '<organization public id>'
ORDER BY id;
```

## The purge job (deferred)

**Not implemented in step 1.2.** Until it exists, a `deleted` organization keeps all of its rows and S3 objects indefinitely (it is inaccessible: no sessions, no API keys, no logins, hidden from lists). Find candidates with:

```sql
SELECT public_id, slug, deleted_at, purge_after
FROM organizations
WHERE status = 'deleted' AND purge_after <= NOW(3);   -- uses the (status, purge_after) index
```

The future job (a scheduled worker, one instance at a time under a lock) must apply these safeguards, in this order, for each candidate:

1. **Re-read the organization under a row lock** and skip it unless it is still `status = 'deleted'` and `purge_after <= now`. Never purge before `purge_after`, never purge a cancelled or re-requested organization, never the platform organization.
2. **Skip while any legal hold is active** (`archive_legal_holds.status = 'active'`), even one created after confirmation, and alert compliance.
3. **Keep archives under retention:** skip (or keep) any `email_archives` row with `legal_hold = true` or `retain_until > now`, and the S3 objects they reference; S3 Object Lock retention in production enforces the same independently.
4. Delete S3 objects first (mail EMLs, attachments, quarantine copies, exports) by the keys recorded in the database, in batches, idempotently (a missing object is success), then the tenant's database rows in foreign-key-safe order, in batches, partition-aware for the partitioned tables (`email_messages` and friends are pruned by `received_at`; dropping partitions is not possible per tenant).
5. **Free verified domain names:** deleting the organization's `domains` rows releases `domains.verified_name` (the generated unique column), so the domain can be verified by another organization. This must happen only in the purge, never at confirmation, so a cancelled deletion keeps its domains.
6. Keep `audit_logs` (append-only, retained by policy) and `login_audit_logs` until their own retention ends; write `organization.purged` with counts, then hard-delete or tombstone the `organizations` row (keep the slug reserved for a period to avoid confusion).
7. Make every step resumable: a crash mid-purge must leave the organization `deleted` and be safe to re-run.

Until then, operators must **not** purge tenant data by hand. If a purge is legally required before the job exists, escalate: it needs a reviewed, one-off script that implements the same safeguards and is run by two people.

## Troubleshooting

| Symptom                                       | Cause and action                                                                                              |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `403 MFA required`                            | The session did not complete TOTP. Log in again with MFA                                                      |
| `403` on confirm                              | The requester tried to confirm. A second platform user must confirm                                           |
| `409 Active legal hold`                       | A legal hold is active. Resolve through compliance; do not release holds to unblock deletion                  |
| `409 … confirmation window has elapsed`       | More than `ORG_DELETION_CONFIRM_WINDOW_HOURS` since the request. Cancel, then request again                   |
| `409 The organization must be suspended …`    | Suspend first (step 1)                                                                                        |
| `409 … no longer be cancelled (purge time …)` | `purge_after` has passed. The data may be purged at any time once the job exists; escalate immediately        |
| Customer still reachable after confirmation   | Should not happen (sessions and keys are revoked). Check Redis health; if Redis was down the API fails closed |
