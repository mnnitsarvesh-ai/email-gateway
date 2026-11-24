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

   **Risk scoring tables (step 5.1).** `RiskTenantDataRepository` (api `tenant-data`, `RISK_PURGE_ORDER`) deletes, in batches of 500: `message_risk_scores` (partitioned, no foreign keys; `LIMIT` without `ORDER BY`, matched on its `(organization_id, received_at)` index), then `risk_scoring_profile_versions` (they reference the profile with `RESTRICT`), then the `risk_scoring_profiles` row (`organization_id` `RESTRICT`; its `active_version_id` has no foreign key). The rows hold codes, integers, versions and ids only (no message content, no S3 object). Verify with:

   ```sql
   SELECT 'message_risk_scores' t, COUNT(*) FROM message_risk_scores WHERE organization_id = ?
   UNION ALL SELECT 'risk_scoring_profile_versions', COUNT(*) FROM risk_scoring_profile_versions WHERE organization_id = ?
   UNION ALL SELECT 'risk_scoring_profiles', COUNT(*) FROM risk_scoring_profiles WHERE organization_id = ?;
   ```

   **Policy engine and directory tables (step 5.2).** `PolicyTenantDataRepository` (api `tenant-data`, `POLICY_PURGE_ORDER`) deletes, in batches of 500, in this RESTRICT-safe order: `policy_execution_logs` (partitioned, no foreign keys; `LIMIT` without `ORDER BY`, on its `(organization_id, received_at)` index), `policy_actions` and `policy_conditions` (retired legacy rows; they reference versions), `policy_versions`, `policy_exceptions`, `email_policies` (`active_version_id` has no foreign key), `policy_settings`, `tenant_department_members` (they reference departments with `RESTRICT`), `tenant_departments`. Every one of these tables references the organization with `RESTRICT`. The rows hold ids, codes, hashes and policy definitions (tenant configuration); member addresses are tenant directory data; no message content and no S3 object (policy copies under `org/<org>/policy/` are mail-bucket objects written by the policy-engine; they expire after `POLICY_COPY_RETENTION_DAYS` through the `eg-policy-copy-expiry` lifecycle rule). Verify with:

   ```sql
   SELECT 'policy_execution_logs' t, COUNT(*) FROM policy_execution_logs WHERE organization_id = ?
   UNION ALL SELECT 'policy_actions', COUNT(*) FROM policy_actions WHERE organization_id = ?
   UNION ALL SELECT 'policy_conditions', COUNT(*) FROM policy_conditions WHERE organization_id = ?
   UNION ALL SELECT 'policy_versions', COUNT(*) FROM policy_versions WHERE organization_id = ?
   UNION ALL SELECT 'policy_exceptions', COUNT(*) FROM policy_exceptions WHERE organization_id = ?
   UNION ALL SELECT 'email_policies', COUNT(*) FROM email_policies WHERE organization_id = ?
   UNION ALL SELECT 'policy_settings', COUNT(*) FROM policy_settings WHERE organization_id = ?
   UNION ALL SELECT 'tenant_department_members', COUNT(*) FROM tenant_department_members WHERE organization_id = ?
   UNION ALL SELECT 'tenant_departments', COUNT(*) FROM tenant_departments WHERE organization_id = ?;
   ```

   **Archive and eDiscovery (step 8.1, [A24](../plan/steps/23-journaling-archiving.md)).** `ArchiveTenantDataRepository.purgeOrganization(systemScope(org))` (api `tenant-data`) is resumable: call it until it returns `complete: true`.

   - **Refusals** (`ArchivePurgeRefusedError`, nothing changed): `reason: legal_hold` while any `archive_legal_holds` row of the organization is `active` (release them through `POST /legal-holds/{id}/release` after legal approval); `reason: retention` while a live record's effective retention is in the future (stored `retain_until`, a running Object Lock `lock_until`, or the live policy's current days). Deletion of a customer within its contractual retention is a legal decision, not an operator one: escalate.
   - **Phase 1:** every remaining `active`/`expiry_review` record goes through the disposal decision exactly like an expiry (reason `organization_deleted`): the record's data key is destroyed in the same transaction (crypto-shredding: no copy can be decrypted any more), an `archive_disposals` row is written and an index `delete` op queued, in batches of 200; one `purge_org` op asks the index role to delete the organization's documents and its tenant alias. The archive-worker's lifecycle role then deletes every object version (also in the replica targets), waits for the index and hard-deletes the rows. The call returns `complete: false` while records or unfinished disposals remain.
   - **Phase 2** (no record and no unfinished disposal left): deletes, in RESTRICT-safe batches, `archive_capture_intents`, `archive_index_checks`, `archive_download_grants`, `ediscovery_search_hits`, `ediscovery_exports`, `ediscovery_searches`, `ediscovery_custodians`, released `archive_legal_holds`, `ediscovery_cases`, `archive_settings`, `archive_retention_policies`, then sets every `archive_encryption_keys` row `destroyed` with `wrapped_key = NULL`. `archive_disposals` (the per-record disposal log, compliance tier) and `audit_logs` stay. Export packages under `org/<org>/exports/` in the archive bucket carry the `eg-object=archive-export` tag and expire with the bucket lifecycle rule (≤ `ARCHIVE_EXPORT_TTL_HOURS` + 1 day); delete them earlier by prefix if required.

   ```sql
   SELECT status, COUNT(*) FROM email_archives WHERE organization_id = ? GROUP BY status;
   SELECT state, COUNT(*) FROM archive_disposals WHERE organization_id = ? GROUP BY state;
   SELECT COUNT(*) FROM archive_legal_holds WHERE organization_id = ? AND status = 'active';
   SELECT version, status, wrapped_key IS NULL AS destroyed FROM archive_encryption_keys WHERE organization_id = ?;
   ```

   **Journal intake (step 8.6, [§3.2](../plan/steps/27-journal-intake-and-archive-split.md#32-new-tables)).** `JournalIntakeTenantDataRepository.purgeOrganization(systemScope(org))` (api `tenant-data`, `JOURNAL_INTAKE_PURGE_ORDER`) deletes, in batches of 500 (`DELETE … WHERE organization_id = ? ORDER BY … LIMIT 500`, autocommit, resumable, idempotent: a re-run returns 0 everywhere), in this order: `journal_intake_counters` (daily counters per source), `journal_intake_messages` (partitioned by `received_at`, no foreign keys; on its `(organization_id, received_at)` index) and `journal_intake_sources` (`organization_id` `RESTRICT`). Run it **before the provider-connection purge below**: `journal_intake_sources.provider_connection_id` references `provider_connections` with `RESTRICT`, so the connections cannot go while a source names them. Run it after (or with) the message-graph tables and after the archive purge has disposed of the records (an intake message's archive record is a normal archive record). The rows hold kinds, statuses, CIDRs of the customer's sending servers, envelope addresses, proof codes, counters and the SHA-256 hashes of the intake addresses and header tokens; no message content (the EMLs are mail-bucket objects under `org/<org>/eml/`, deleted with the other mail objects) and no secret (an address cannot be derived without `JOURNAL_INTAKE_ADDRESS_SECRET`, which only the api holds). `archive_dedupe_keys` and `archive_record_sources` belong to archive records: the archive-worker removes them when it disposes of the organization's records (Phase 1 of the archive purge above), never this repository. It returns the count per table for the `organization.purged` audit row. Tell the customer to remove the journal rule / routing setting / BCC that sends to the intake addresses (they are refused with `550 5.1.1` once the sources are gone). Verify with:

   ```sql
   SELECT 'journal_intake_counters' t, COUNT(*) FROM journal_intake_counters WHERE organization_id = ?
   UNION ALL SELECT 'journal_intake_messages', COUNT(*) FROM journal_intake_messages WHERE organization_id = ?
   UNION ALL SELECT 'journal_intake_sources', COUNT(*) FROM journal_intake_sources WHERE organization_id = ?
   UNION ALL SELECT 'archive_dedupe_keys (archive-worker)', COUNT(*) FROM archive_dedupe_keys WHERE organization_id = ?
   UNION ALL SELECT 'archive_record_sources (archive-worker)', COUNT(*) FROM archive_record_sources WHERE organization_id = ?;
   ```

   **AI assistant (steps AI-1, AI-2 and AI-R, [§3](../plan/steps/28-ai-chat-management.md#3-data-model-migration-ai_assistant-ai-1-wp1), [AI-2 §3](../plan/steps/29-ai-chat-confirmations-mail-writes.md#3-data-model-migration-ai_assistant_confirmations-wp1), [AI-R §3 and D7](../plan/steps/31-ai-chat-reports.md#3-data-model-migration-ai_assistant_reports-wp1), ADR-0094, ADR-0093, ADR-0095).** `AssistantTenantDataRepository.purgeOrganization(systemScope(org))` (api `tenant-data`, `ASSISTANT_PURGE_ORDER`) deletes, in batches of 500 (`DELETE … WHERE organization_id = ? ORDER BY … LIMIT 500`, autocommit, resumable, idempotent: a re-run returns 0 everywhere), in this order: **first the report data of step AI-R**: `ai_chat_report_deliveries`, then `ai_chat_reports`, where each batch of report rows first deletes its **report objects** from the mail bucket (`S3_BUCKET_MAIL`, only keys under `org/<organizationId>/assistant/report/`; a missing object counts as deleted; an S3 error stops the purge before the rows go, so a re-run retries) and then the rows (count `reportObjects`); then `ai_chat_action_confirmations` (step AI-2), `ai_chat_tool_executions`, `ai_chat_messages`, `ai_chat_turns`, `ai_chat_conversations`, `ai_chat_usage_daily` and `ai_chat_settings` (all nine reference `organizations` with `RESTRICT`; the conversation children also cascade from their conversation, a backstop only). It has no ordering constraint against the other areas (no foreign key to or from them); run it with the other tenant-configuration purges. The rows hold the users' chat text, masked metadata cards as the API returned them, provider transcripts and execution metadata; no email body or attachment and no credential; the only S3 objects are the AI-R report HTML documents, deleted first as above (the mail bucket is versioned and no lifecycle rule covers these keys, so each report delete removes every version and delete marker of its key: nothing of the report HTML stays in the bucket). Copies of reports already emailed to recipients' mailboxes are outside the platform and cannot be purged. The `assistant.*` rows in `audit_logs` stay (append-only, audit retention). It returns the count per table for the `organization.purged` audit row. Verify with:

   ```sql
   SELECT 'ai_chat_report_deliveries' t, COUNT(*) FROM ai_chat_report_deliveries WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_reports', COUNT(*) FROM ai_chat_reports WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_action_confirmations', COUNT(*) FROM ai_chat_action_confirmations WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_tool_executions', COUNT(*) FROM ai_chat_tool_executions WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_messages', COUNT(*) FROM ai_chat_messages WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_turns', COUNT(*) FROM ai_chat_turns WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_conversations', COUNT(*) FROM ai_chat_conversations WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_usage_daily', COUNT(*) FROM ai_chat_usage_daily WHERE organization_id = ?
   UNION ALL SELECT 'ai_chat_settings', COUNT(*) FROM ai_chat_settings WHERE organization_id = ?;
   ```

   and that no report object is left: `mc ls --recursive <alias>/<S3_BUCKET_MAIL>/org/<organizationId>/assistant/report/` (MinIO) or `aws s3 ls s3://<S3_BUCKET_MAIL>/org/<organizationId>/assistant/report/ --recursive` lists nothing.

   **Microsoft 365 and Google Workspace connections (step 8.2, [§3.3](../plan/steps/25-m365-google-connectors.md#33-retention-maintenance-role)).** `ProviderTenantDataRepository.purgeOrganization(systemScope(org))` (api `tenant-data`, `PROVIDER_PURGE_ORDER`) deletes, per connection of the organization and in batches of 500 (`DELETE … WHERE connection_id = ? AND organization_id = ? ORDER BY id LIMIT 500`, resumable, idempotent), in this order: `provider_relay_counters`, `provider_probe_observations`, `provider_health_events`, `provider_health_checks`, `provider_validation_runs`, `provider_consent_states`, `provider_connection_domains`, `provider_connection_grants` (the encrypted customer credentials go with their rows; no key material is kept anywhere else); then it sets `smtp_connectors.provider_connection_id = NULL` on the organization's `provider_relay` connectors (that column is `RESTRICT`; the connectors themselves are deleted by the organization's connector purge) and finally deletes the `provider_connections` rows (`organization_id` `RESTRICT`). It returns the count per table plus `smtp_connectors_detached` for the `organization.purged` audit row. Run it **before** the domains and connectors are deleted (`provider_connection_domains.domain_id` cascades, but the explicit order keeps the statements short). The rows hold provider tenant ids and names, domain names, permission names, check results and counts; no message content and no S3 object. The gateway cannot remove its consent or delegation inside the customer's Microsoft 365 or Google Workspace tenant (step 8.2 I3): tell the customer to delete the enterprise application / domain-wide delegation entry (the disconnect response and the setup guide list the steps). `ProviderTenantDataRepository.exportOrganization` returns the tenant data export section `provider-tenant-export/1` (connections, grants **without** ciphertext, key id or credential, linked domains, validation runs without probe-token hashes, health transitions). Verify with:

   ```sql
   SELECT 'provider_relay_counters' t, COUNT(*) FROM provider_relay_counters WHERE organization_id = ?
   UNION ALL SELECT 'provider_probe_observations', COUNT(*) FROM provider_probe_observations WHERE organization_id = ?
   UNION ALL SELECT 'provider_health_events', COUNT(*) FROM provider_health_events WHERE organization_id = ?
   UNION ALL SELECT 'provider_health_checks', COUNT(*) FROM provider_health_checks WHERE organization_id = ?
   UNION ALL SELECT 'provider_validation_runs', COUNT(*) FROM provider_validation_runs WHERE organization_id = ?
   UNION ALL SELECT 'provider_consent_states', COUNT(*) FROM provider_consent_states WHERE organization_id = ?
   UNION ALL SELECT 'provider_connection_domains', COUNT(*) FROM provider_connection_domains WHERE organization_id = ?
   UNION ALL SELECT 'provider_connection_grants', COUNT(*) FROM provider_connection_grants WHERE organization_id = ?
   UNION ALL SELECT 'provider_connections', COUNT(*) FROM provider_connections WHERE organization_id = ?
   UNION ALL SELECT 'smtp_connectors (provider-linked)', COUNT(*) FROM smtp_connectors WHERE organization_id = ? AND provider_connection_id IS NOT NULL;
   ```

   **ATO identity-provider integrations (step 8.5, [§4.1 "Purge and export"](../plan/steps/26-ato-provider-adapters.md)).** `AtoProviderTenantDataRepository.purgeOrganization(systemScope(org))` (api `tenant-data`, `ATO_PROVIDER_PURGE_ORDER`) deletes, in batches of 500 (resumable, idempotent): per integration of the organization `ato_provider_mailbox_items` then `ato_provider_streams` (`DELETE … WHERE integration_id = ? AND organization_id = ? ORDER BY id LIMIT 500`), then the organization's `ato_account_identities` and finally its `ato_provider_integrations` rows (`organization_id` `RESTRICT`). Run it **before** the rest of the `ato_*` rows (accounts, signals, responses; still with the deferred 8.4 part of the purge) and **before** the step 8.2 connection purge above (the integrations reference connections only by public id, so either order works, but integrations first stops any provider poll of a dying organization). `ato_response_actions.integration_id` has no foreign key: action history goes with the 8.4 rows. It returns the count per table for the `organization.purged` audit row. The rows hold provider kinds, connection public ids, settings, health and probe results, permission names, the tenant's own directory domain names, stream cursors (opaque) and counters, hashed identities, mailbox item hashes, target **domains** and trait codes; never a provider token, credential, forwarding or delegate address, rule keyword or message content, and no S3 object. The gateway cannot remove the ATO apps' consent or domain-wide delegation inside the customer's Microsoft 365 or Google Workspace tenant: tell the customer to delete them (the step 8.2 disconnect steps cover the ATO profiles too). `AtoProviderTenantDataRepository.exportOrganization` returns the tenant data export section `ato-provider-tenant-export/1` (integrations with settings, health, permission names and directory domains; stream status rows without cursors; mailbox items with hashes, kinds, target domains and traits, without provider item ids). Verify with:

   ```sql
   SELECT 'ato_provider_mailbox_items' t, COUNT(*) FROM ato_provider_mailbox_items WHERE organization_id = ?
   UNION ALL SELECT 'ato_provider_streams', COUNT(*) FROM ato_provider_streams WHERE organization_id = ?
   UNION ALL SELECT 'ato_account_identities', COUNT(*) FROM ato_account_identities WHERE organization_id = ?
   UNION ALL SELECT 'ato_provider_integrations', COUNT(*) FROM ato_provider_integrations WHERE organization_id = ?;
   ```

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
