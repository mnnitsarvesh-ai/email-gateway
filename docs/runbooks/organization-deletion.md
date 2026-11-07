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
   **Phishing and BEC tables (step 4.4).** The six non-partitioned BEC tables reference `organizations` with `ON DELETE RESTRICT` (no cascade), so the organization row cannot be deleted while they hold rows. The purge deletes them with `BecTenantDataRepository.purgeOrganization(systemScope(<organization id>))` (`apps/api/src/modules/tenant-data/bec-tenant-data.repository.ts`), which runs batched autocommit statements (`DELETE … WHERE organization_id = ? ORDER BY id LIMIT 5000`, resumable, idempotent) in this order: `bec_suppression_rules` (they name feedback ids), `bec_feedback` (it names result ids), `bec_trusted_senders`, `bec_vendor_profiles`, `bec_executive_profiles`, `bec_contact_history` (keyed hashes and counts, ADR-0035), then the partitioned `bec_scan_results` (no foreign keys; matched on its `(organization_id, received_at)` index, before or together with the other message-graph tables). It returns the deleted count per table for the `organization.purged` audit row. `bec_feedback` is training data with its own 24-month retention, but it never outlives its organization. Verify with:

   ```sql
   SELECT 'bec_suppression_rules' t, COUNT(*) FROM bec_suppression_rules WHERE organization_id = ?
   UNION ALL SELECT 'bec_feedback', COUNT(*) FROM bec_feedback WHERE organization_id = ?
   UNION ALL SELECT 'bec_trusted_senders', COUNT(*) FROM bec_trusted_senders WHERE organization_id = ?
   UNION ALL SELECT 'bec_vendor_profiles', COUNT(*) FROM bec_vendor_profiles WHERE organization_id = ?
   UNION ALL SELECT 'bec_executive_profiles', COUNT(*) FROM bec_executive_profiles WHERE organization_id = ?
   UNION ALL SELECT 'bec_contact_history', COUNT(*) FROM bec_contact_history WHERE organization_id = ?
   UNION ALL SELECT 'bec_scan_results', COUNT(*) FROM bec_scan_results WHERE organization_id = ?;
   ```

   A tenant can also remove its communication history at any time without deleting the organization (`DELETE /api/v1/bec/history`, MFA, audited `bec_history.purged`).

   **Data loss prevention tables and evidence objects (step 4.5).** The six non-partitioned DLP tables (`dlp_policies`, `dlp_policy_rules`, `dlp_exceptions`, `dlp_custom_patterns`, `dlp_keyword_dictionaries`, `dlp_compliance_settings`) reference `organizations` with `ON DELETE RESTRICT`, rules reference policies and exceptions reference policies and rules (`RESTRICT`), and the evidence rows (`dlp_evidence`, partitioned, no foreign keys) point at encrypted objects in the mail bucket under `org/<org>/dlp-evidence/`. The purge deletes them with `DlpTenantDataRepository.purgeOrganization(systemScope(<organization id>))` (`apps/api/src/modules/tenant-data/dlp-tenant-data.repository.ts`), batched (500 rows per statement), resumable and idempotent, in this order:

   1. `dlp_evidence`, per batch ordered by id: **crypto-shred** (`wrapped_key = NULL`, `purged_at`, `purge_reason = organization_deleted`; the data key exists only in the row, so the object and any noncurrent version of it are undecryptable from that moment), then delete each object (only keys under `org/<org>/dlp-evidence/`; a missing object is success; any other S3 error aborts the run, which is simply re-run), then delete the rows;
   2. `dlp_scan_results` (partitioned, no foreign keys; matched on its `(organization_id, received_at)` index);
   3. `dlp_exceptions` (before the rules and policies they target), `dlp_policy_rules` (before their policies), `dlp_policies`, `dlp_custom_patterns`, `dlp_keyword_dictionaries`, `dlp_compliance_settings`.

   It returns the deleted count per table plus `evidenceObjects` for the `organization.purged` audit row. Objects of attempts that crashed before their row was committed (orphans) are undecryptable by construction (no wrapped key anywhere) but have no row: the purge job must also list and delete the `org/<org>/dlp-evidence/` prefix (the repository deletes only keys recorded in rows). Verify with:

   ```sql
   SELECT 'dlp_evidence' t, COUNT(*) FROM dlp_evidence WHERE organization_id = ?
   UNION ALL SELECT 'dlp_scan_results', COUNT(*) FROM dlp_scan_results WHERE organization_id = ?
   UNION ALL SELECT 'dlp_exceptions', COUNT(*) FROM dlp_exceptions WHERE organization_id = ?
   UNION ALL SELECT 'dlp_policy_rules', COUNT(*) FROM dlp_policy_rules WHERE organization_id = ?
   UNION ALL SELECT 'dlp_policies', COUNT(*) FROM dlp_policies WHERE organization_id = ?
   UNION ALL SELECT 'dlp_custom_patterns', COUNT(*) FROM dlp_custom_patterns WHERE organization_id = ?
   UNION ALL SELECT 'dlp_keyword_dictionaries', COUNT(*) FROM dlp_keyword_dictionaries WHERE organization_id = ?
   UNION ALL SELECT 'dlp_compliance_settings', COUNT(*) FROM dlp_compliance_settings WHERE organization_id = ?;
   ```

   and list `org/<org>/dlp-evidence/` in the mail bucket (expected empty). A tenant can purge its DLP evidence at any time without deleting the organization (`DELETE /api/v1/dlp/evidence`, `dlp:manage` + MFA, audited `dlp_evidence.purged`); evidence also expires by the tenant's retention (≤ 180 days, swept by the email-worker).

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
