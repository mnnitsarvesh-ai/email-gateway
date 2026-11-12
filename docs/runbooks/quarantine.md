# Runbook: quarantine

Step 5.3 ([design](../plan/steps/17-quarantine.md), [ADR-0046](../architecture/adr/0046-quarantine-store-and-per-recipient-decisions.md), [ADR-0047](../architecture/adr/0047-quarantine-release-revalidation-and-approvals.md), [ADR-0048](../architecture/adr/0048-quarantine-preview-and-download-controls.md), [ADR-0049](../architecture/adr/0049-policy-copy-body-edits-banners-and-url-rewrite.md); deployment [quarantine.md](../deployment/quarantine.md); services [policy-engine](../../apps/policy-engine/README.md), [notification-worker](../../apps/notification-worker/README.md); notices [policy-notifications.md](policy-notifications.md)).

The quarantine store holds one **entry** (`quarantine_messages`) per message, lifecycle round and held recipient. Entries are written by the policy-engine in the same writer transaction as the policy decision (QUARANTINE → `held`, REQUIRE_APPROVAL → `pending_approval` with a `policy_review` approval request), by the api (manual quarantine) and by the sweeper (adoption of messages held before 5.3). Releases go through the **release executor** (policy-engine role `quarantine`, queue `email.quarantine`), which re-validates every release against the latest scan round and the **current** policy. Nothing in the quarantine ever releases mail on its own: expiry ends an entry as `expired`.

- Alerts: [QuarantineReleaseExecutorStalled](#quarantinereleaseexecutorstalled) · [QuarantineSweeperStalled](#quarantinesweeperstalled) · [QuarantinePurgeFailures](#quarantinepurgefailures) · [QuarantineApprovalBacklog](#quarantineapprovalbacklog) · [QuarantineNotificationFailures](#quarantinenotificationfailures) · [QuarantineDownloadRefusalSpike](#quarantinedownloadrefusalspike) · [QuarantineInconsistentReads](#quarantineinconsistentreads)
- Procedures: [reading an entry](#reading-an-entry-and-its-explanation) · [release outcomes](#release-outcomes) · [approvals and separation of duties](#approvals-and-separation-of-duties) · [legal hold and retention](#delete-refusals-legal-hold-and-retention) · [purge failures](#quarantinepurgefailures) · [digests not arriving](#digests-not-arriving) · [download refusals](#quarantinedownloadrefusalspike) · [tenant settings](#tenant-settings) · [boundaries](#what-53-does-not-do)

## States

| Entry state        | Meaning                                                                                        | Next                                                                                                        |
| ------------------ | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `held`             | quarantined; waits for a decision or expiry                                                    | `pending_approval`, `releasing`, `rejected`, `deleted`, `expired`                                           |
| `pending_approval` | an approval request (`policy_review`, `release_approval`, `release_request`) is open           | `releasing` (approved), `held` (denied/cancelled/expired), `rejected` (review denied), `deleted`, `expired` |
| `releasing`        | a release is queued for the executor                                                           | `released`, `held` (blocked), `pending_approval` (new reasons)                                              |
| terminal           | `released`, `rejected`, `deleted`, `expired`, `superseded` (a rescan re-decided the recipient) | `rejected`/`expired` → `deleted` (purge request) only                                                       |

Recipients follow their entry: a held recipient is `quarantined` in `email_recipients`; a rejected, deleted or expired one is `discarded`; a released one goes back to `pending` and is approved for delivery. The **message** state is the delivery view: a split message (some recipients allowed) is `approved` → `delivered` (`delivery_partial`) while the others stay held.

## Reading an entry and its explanation

- Api (WP4): `GET /api/v1/quarantine/entries/{id}` (explanation lines, hard blocks, floor reasons, decisive rule, approval request, release attempts, `allowedActions`), `GET …/{id}/history` (every action).
- SQL (writer or replica):

```sql
SELECT public_id, lifecycle_round, rcpt_seq, status, kind, origin, reason, primary_engine, risk_level,
       hard_blocks, floor_reasons, decision_source, decisive_policy_public_id, decisive_rule_id,
       explanation_text, quarantined_at, expires_at, approval_request_id, object_purged_at
FROM quarantine_messages WHERE message_id = <id> ORDER BY lifecycle_round, rcpt_seq;
SELECT action, actor_type, actor_id, result, details, created_at
FROM quarantine_actions WHERE quarantine_message_id = <entry id> ORDER BY id;
```

`reason` is the strictest cause (malware > phishing > bec > dlp > engine_unavailable > policy > spam > bulk > suspicious); `primary_engine` names the engine behind it. `explanation_text` comes from the policy evaluation (fixed templates, no content). The subject is never stored on the entry; the api reads it from `email_messages` only where allowed.

## Release outcomes

A release (`POST …/release`, a self-release, an approval) writes a `quarantine_release_logs` row per entry (`status = pending`), sets the entries to `releasing` and publishes `mail.quarantine.release_requested.v1`. The executor decides authoritatively, in one transaction:

| Release log `status` | What happened                                                                                                                                                                                                                           | What to do                                                                                                                                  |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `dispatched`         | Released: release copy (header `X-EG-Quarantine-Release: <release id>`), lifecycle edge (E14/E15/E28 or none), approval to delivery                                                                                                     | Track delivery (`delivery_seq`, `approval_event_ids`, `lifecycle_round_after`).                                                             |
| `approval_required`  | New approval reasons appeared (hard block, engine failure, DLP hold, policy now rejects, stale verdicts without rescan, …)                                                                                                              | A second authorized user approves the new `release_approval` request (`revalidation.approvalReasons`).                                      |
| `rescan_required`    | Verdicts are stale (`revalidation.staleness`: older than `QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS` with attachments/URLs, or ClamAV signatures newer by `QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS`) and the message can be rescanned | Rescan (`POST /api/v1/messages/{id}/rescan`); the new round re-decides and supersedes the entry; release the new entry if it is still held. |
| `refused`            | `blocked_reason`: `hard_block_release_disabled` (tenant setting), a self-release cause, `approval_not_valid` (the stored approval is not `approved` or violates SoD), `message_archived`                                                | Use the operator path, fix the approval, or accept the refusal.                                                                             |
| `message_busy`       | The message is being re-decided (scanning, policy_evaluated, …)                                                                                                                                                                         | Wait for the new round; its entries supersede these.                                                                                        |
| `stale`              | The event found the entries no longer `releasing` (superseded, already handled)                                                                                                                                                         | None.                                                                                                                                       |

Blocked releases put the entries back to `held` (or `pending_approval`) and notify the requesting user (`release_blocked`). A release copy that exceeds the copy bounds delivers the base object (rewritten copy of the latest round if it still exists, else the original EML) and the log records TAG/WARN/banner as `recorded`.

## Approvals and separation of duties

One table, `quarantine_approval_requests` (`policy_review` from REQUIRE_APPROVAL, `release_approval` from a release with approval reasons, `release_request` from a user request). The approver must hold `quarantine:approve`, must not be the requester, the entry's recipient, an end user or an API key; the api checks it at decision time and the executor re-checks the stored decision (`approved`, decider ≠ requester, decider ≠ the entry's user). A request made with an API key counts the key's creator (`api_keys.created_by_user_id`) as the requester (`403 quarantine_approval_forbidden`, `reason: requester`). When the executor finds new reasons after an approval, the new `release_approval` request names the original requester, not the approver. A rescan of a quarantined or held message needs `quarantine:release` as well as `message:rescan` (`403 quarantine_rescan_forbidden`). Pending requests expire at `expires_at` (sweeper): `release_*` → entry back to `held` and an `approval_decided (expired)` notice to a user requester; `policy_review` → the entry expires (never released).

## Delete refusals: legal hold and retention

A delete (`409 quarantine_legal_hold` / `409 quarantine_retention_active`) and every purge consult, on writer facts: an active `archive_legal_holds` row whose criteria match (5.3 understands `{ custodians, from, to }`; anything else matches everything, fail-safe), archive retention (`archive_settings` + the longest `archive_retention_policies.retention_days`, or an `email_archives` row with `retain_until` in the future or `legal_hold`), an ARCHIVE requested but not done (`archive_pending`), and the shared object rule (the EML stays while any entry is open or released, or any recipient is pending/deferred/delivered). The purge row (`quarantine_object_purges`) shows the decision: `retained` with `reason` and `purge_after` (re-evaluated then; one day later when no date is known), `pending`, `purged`, `failed`. Releasing a legal hold is step 8.1; the next sweeper pass after `purge_after` purges.

## Digests not arriving

1. Organization: `organization_settings.digest_enabled`, `digest_schedule` (5-field cron), `timezone`; tenant settings `endUser.enabled`, `digest.allowOptOut`; the user's `quarantine_user_preferences.digest_opt_out`.
2. Runs: `SELECT kind, scheduled_for, window_from, users_total, users_done, completed_at FROM quarantine_digest_runs WHERE organization_id = <org> ORDER BY scheduled_for DESC LIMIT 5;` (at most one per hour; an invalid schedule or time zone is logged and skipped). Entries held after the last instant wait for the next one. The scheduler visits `QUARANTINE_SWEEP_BATCH_SIZE` organizations per sweep in rotation (keyset cursor, wrap-around), so with many tenants an organization's digest can lag by up to ⌈organizations / batch⌉ sweep intervals; a large run that uses up `QUARANTINE_DIGEST_MAX_USERS_PER_RUN` continues first on the next sweep.
3. Digests: `quarantine_digests` (one per run and user; `event_id` = the outbox event). The user must be active, e-mail-verified and the entries addressed to their e-mail.
4. Delivery: notification-worker metrics `notification_quarantine_messages_total{kind="user_digest",result}` (`no_entries`: everything was released or expired before sending; `not_applicable`: opted out or end users disabled), relay ([policy-notifications.md](policy-notifications.md)).

## Tenant settings

`quarantine_settings.settings` (strict; invalid stored settings fall back to the defaults and count `quarantine_settings_invalid_total`): review days, approval TTL, `release.allowHardBlocks`, end-user flags, digest flags, alert flags and interval, sender notice on reject, downloads. Hold days come from `organization_settings.quarantine_retention_days` clamped to `QUARANTINE_MAX_HOLD_DAYS`; `expires_at` is fixed when an entry is created.

## Alerts

### QuarantineReleaseExecutorStalled

Releases are queued (api `quarantine_requests_total{operation="release",result="queued"}`) but `quarantine_releases_total` does not move. Entries stay `releasing`; events wait in `email.quarantine` (durable work queue). Check: the `quarantine-worker` Deployment (Kubernetes) or the `policy-engine` container with `POLICY_ENGINE_ROLES` containing `quarantine` (Compose); readiness (mysql, rabbitmq, redis, s3); `rabbitmqctl list_queues name messages consumers` for `email.quarantine`; dead letters of `email.quarantine` (replayable through the ops replay, `retry.email.quarantine.`). A `mail.policy.decided.v1` left over from the v9 dormant buffer is dead-lettered as `unknown_event_type`: it is firehose data, discard it.

### QuarantineSweeperStalled

No replica completed a sweeper pass for 15 minutes. `quarantine_sweeper_leader` shows which replica holds `GET_LOCK('eg:quarantine-sweeper')` (one per cluster; when the lock connection drops the server releases it and another replica takes over on its next tick). Logs `quarantine sweeper step failed` name the failing step (`expiry`, `approvals`, `purge`, `adoption`, `digests`, `retention`, `gauges`); the other steps still run. Expiries and purges are only late; nothing is released.

### QuarantinePurgeFailures

`SELECT message_id, status, attempts, last_error_code, purge_after FROM quarantine_object_purges WHERE status = 'failed' ORDER BY purge_after LIMIT 50;` — `key_prefix`: an object key outside `org/<org>/` was found (never deleted; investigate as a defect); S3 error names: check the policy-engine's S3 permissions (`s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:ListBucketVersions` on the purged prefixes) and MinIO/S3 health. Retries back off up to 6 hours.

### QuarantineApprovalBacklog

`SELECT organization_id, kind, COUNT(*) FROM quarantine_approval_requests WHERE status = 'pending' GROUP BY 1, 2 ORDER BY 3 DESC;` Approvers receive `approval_requested` notices and rate-bounded `admin_alert`s; check that the organization has users holding `quarantine:approve` with verified e-mail.

### QuarantineNotificationFailures

The relay refused or was unreachable; see [policy-notifications.md](policy-notifications.md#failures).

### QuarantineDownloadRefusalSpike

Many `reauth_failed` / `token_used` / `token_invalid` download refusals (api). Check `audit_logs` actions `quarantine.download_refused` / `quarantine.download_granted` per principal and the login lockouts; a burst from one user is a guessing or replay attempt (revoke sessions, disable `download.enabled` for the tenant).

### QuarantineInconsistentReads

`quarantine_inconsistent_reads_total{read}` above 10 in 15 minutes (api or policy-engine). Every occurrence is retried and nothing is decided from a wrong row; a sustained rate means the writer connection pool hands out wrong rows (step 4.2 §6) or concurrent writers fight over the same entries (compare-and-set conflicts on `entry_update`).

## What 5.3 does not do

- Admin-portal and end-user screens (7.x); webhooks, preference center (6.2); legal hold and retention management, journaling, archive copies (8.1); clawback of delivered mail (8.2); defanged-archive downloads; one-click release links; automatic rescan-and-release.
- Per-recipient TAG/WARN edits: one delivered copy per round (the merge of the allowed recipients' edits).
