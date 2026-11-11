# Runbook: policy engine

Step 5.2 ([design](../plan/steps/16-policy-engine.md), [ADR-0043](../architecture/adr/0043-policy-dsl-and-deterministic-evaluator.md), [ADR-0044](../architecture/adr/0044-policy-evaluation-placement-and-delivery-gating.md), [ADR-0045](../architecture/adr/0045-policy-action-semantics.md); DSL reference [policy-dsl.md](../architecture/policy-dsl.md); service [README](../../apps/policy-engine/README.md); deployment [policy-engine.md](../deployment/policy-engine.md)).

The policy-engine evaluates every scanned, scan-failed and parse-failed message round against the tenant's published policies plus the platform default (`pol-default/1`) and the mandatory **strictness floor**, and is the **only automatic producer of delivery approvals**. One evaluation per (message, lifecycle round), stored in `policy_execution_logs`, never updated.

- Alerts: [PolicyEvaluationsStalled](#policyevaluationsstalled) · [PolicyInputErrors](#policyinputerrors) · [PolicySnapshotInvalidVersion](#policysnapshotinvalidversion) · [PolicyInconsistentReads](#policyinconsistentreads) · [PolicyRiskMissing](#policyriskmissing) · [PolicyNotificationFailures](#policynotificationfailures)
- Procedures: [reading an evaluation](#reading-an-evaluation) · [dry-run and test](#dry-run-and-test) · [rollback](#rolling-back-a-policy) · [disabling a policy](#disabling-a-policy) · [held mail during an outage](#held-mail-during-an-outage-and-recovery) · [dead-lettered rounds](#dead-lettered-rounds) · [floor reasons](#floor-reasons) · [boundaries (5.3, 8.1)](#what-52-does-not-do)

## What it does, per message round

`email.policy.evaluate` delivers `mail.message.scanned.v1` (`outcome = scanned | scan_failed`) and `mail.message.parse_failed.v1`. In one writer transaction (ledger consumer `policy-engine.evaluate`):

1. First lifecycle edge (E8 / E9 / E5 → `policy_evaluated`). Not applicable (rescanned, released, expired, already decided, another tenant) → ledger only, `policy_lifecycle_skipped_total{result}`.
2. Facts of the round (echo-checked writer reads), the organization's policy generation and compiled snapshot (cached by `(organization, generation)`), departments/users referenced by the snapshot, input, evaluation.
3. ALLOW: delivered object = the round's URL-rewritten copy, else the original; with TAG/WARN header edits a **policy copy** `org/<org>/policy/…` (tag `eg-object=policy-copy`).
4. `policy_execution_logs` row, `email_messages.final_verdict / final_action / risk_score`, disposition edge (E10 `approved`, E11 `quarantined`, E12 `held_for_review`, E13 `rejected`).
5. Outbox: `mail.policy.decided.v1`; approvals (`source = policy`) for ALLOW; `mail.message.archive_requested.v1` for ARCHIVE; `mail.policy.notification_requested.v1` for ALERT and the outbound sender non-delivery notice.

| Disposition      | State                 | `final_action`                                                                         | Delivered?                                    |
| ---------------- | --------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------- |
| allow            | `approved` → delivery | `deliver` / `tag`                                                                      | yes (original, rewritten copy or policy copy) |
| require_approval | `held_for_review`     | `require_approval`                                                                     | no, until an operator release                 |
| quarantine       | `quarantined`         | `quarantine`                                                                           | no, until an operator release                 |
| reject           | `rejected`            | `discard` (inbound, no bounce) / `reject` (outbound/internal, sender notice requested) | never                                         |

Action statuses (ADR-0045) are stored per action: `enforced`, `requested`, `recorded`, `not_applicable`. TAG/WARN are `recorded` when headers are disabled or the message was too large for a copy (`policy_copy_total{result="too_large"|"header_too_large"}`).

## Reading an evaluation

- Api (WP4): `GET /api/v1/messages/{messageId}/policy-evaluations` (every round, `message:read`), the `policy` section of each round in `GET /api/v1/messages/{messageId}/scans`, history `GET /api/v1/policies/executions?from=…&to=…` (`policy:read`).
- SQL (writer or replica):

```sql
SELECT evaluation_seq, `trigger`, disposition, decision_source, decisive_policy_public_id, decisive_rule_id,
       action, delivered_object, object_key, policy_generation, reason_codes, explanation_text, evaluated_at
FROM policy_execution_logs WHERE message_id = <id> ORDER BY evaluation_seq;
```

`explanation_text` is built from fixed templates (ids, rule references, codes; never addresses or content). `reason_codes[0]` is the decisive reason: `policy.default.*` (platform default: the risk recommendation or the deterministic BEC rule D2), `policy.floor.*` (the floor raised it), `policy.decision.tenant_rule` / `policy.override.applied` (tenant rule), `policy.url_rewrite.required`; further codes such as `policy.clamp.*`, `policy.rule.excepted`, `policy.tag.platform_suppressed`, `policy.alert.disabled` explain the rest. `floor`, `recommendation`, `clamps` and `matched_rules` show the rest; `trace` shows which rules matched, did not match, were unknown or excepted. `policy_generation` + `snapshot_sha256` identify the exact policy set; `input_sha256` the facts.

## Dry-run and test

Both write nothing (WP4 routes, `policy:manage`):

- `POST /api/v1/policies/test` with synthetic facts and a target (`active`, `platform`, a version, or an inline draft): what would a policy decide.
- `POST /api/v1/messages/{messageId}/scans/{scanId}/policy/dry-run`: the stored round's facts against a target. `reproducible: true` (target `active`) means the same input and snapshot hashes as the stored evaluation; `false` after a policy or department membership change.

## Rolling back a policy

`POST /api/v1/policies/{policyId}/versions/{versionNo}/activate` with an earlier published version (`policy:publish`, audited). It increments the organization's generation: the **next** evaluation uses it. Messages already decided are never re-evaluated; release or rescan them if needed.

## Disabling a policy

`POST /api/v1/policies/{policyId}/disable` (`policy:publish`). The platform default and the floor still apply. To stop **every** tenant rule of an organization at once, disable its policies one by one (each is audited); there is no global switch, by design.

## Held mail during an outage and recovery

When the policy-engine is down (or cannot reach MySQL, RabbitMQ or S3), nothing is approved: messages stay `scanned` / `scan_failed` / `persisted` (held, never delivered unchecked). `email.policy.evaluate` buffers (work queue, reject-publish at 1 000 000). On recovery the backlog is evaluated with the generation current **at evaluation time**. The `scanned` lifecycle deadline (`LIFECYCLE_DEADLINE_SCANNED_HOURS`, 24 h) still expires messages that wait longer; expired ones need an administrative rescan.

1. `kubectl -n email-gateway get pods -l app.kubernetes.io/name=policy-engine`; readiness body names the failing check (mysql, rabbitmq, redis, s3).
2. Queue: `email.policy.evaluate` messages and consumers (management UI or `rabbitmq-messaging.md`).
3. Locally: `docker compose --profile apps up -d --wait policy-engine`.

### PolicyEvaluationsStalled

Critical. Scan rounds completed for 45 minutes with no `scanned`/`scan_failed` evaluation. Follow [held mail](#held-mail-during-an-outage-and-recovery). If the engine runs but evaluates nothing, look at its logs for `policy_input_invalid` (dead letters, below) or repeated inconsistent reads, and at `policy_lifecycle_skipped_total` (every event skipped means the messages are no longer in the expected state, e.g. after a rescan storm).

## Dead-lettered rounds

`PolicyInputError` (malformed stored facts: an enum outside the vocabulary, malformed JSON in a risk row, a scan without completion time) or an evaluator exception → `NonRetryableError('policy_input_invalid')`, `policy_input_errors_total`; the event goes to `email.dead-letter` (`dead-letter.email.policy.evaluate…`) and the message **stays held**. It is a defect, never a pass.

### PolicyInputErrors

1. Find the dead letters (`rabbitmq-messaging.md`, dead-letter inspection): `x-eg-failure-reason = policy_input_invalid`, the message id in the envelope.
2. Inspect the round's rows (scan, `message_risk_scores`, `dlp_scan_results`, `bec_scan_results`); the engine logs only ids and the error class.
3. Fix the producing stage (or the engine), deploy, then replay the dead letter (`POST /api/v1/dead-letters/…/replay`, ops) or rescan the message.

### PolicySnapshotInvalidVersion

A stored active version no longer validates (retired DSL version, hash mismatch, malformed reference): its rules are excluded (only the tenant's rules are dropped; the platform default and floor stay). `GET /api/v1/policies/{policyId}/versions/{versionNo}` shows the violations; publish a corrected version or roll back.

### PolicyInconsistentReads

Writer reads that did not echo their request (the Prisma wrong-read defect, step 4.2 §6). Each one rolls the evaluation back and retries. Sustained > 10 / 15 min: writer stalls, a too-short `POLICY_DB_TX_TIMEOUT_MS`, or a non-zero `DATABASE_SOCKET_TIMEOUT_SECONDS`. `policy_inconsistent_reads_total{read}` names the read.

### PolicyRiskMissing

A scanned round reached policy without its revision-0 risk row (written with `scanned.v1` since 5.1). The floor quarantines it (`policy.floor.risk_missing`). Check the email-worker scan replicas' version and `RiskScoreMissing` ([risk-scoring.md](risk-scoring.md#riskscoremissing)); release the quarantined messages after the fix if appropriate.

### PolicyNotificationFailures

The notification-worker could not send policy alerts or sender notices (SMTP failures retried, then dead-lettered). Check the relay (`NOTIFY_SMTP_*`, `postfix-notify` / SES), then replay the dead letters of `email.notifications`. Notifications are at-least-once (a duplicate keeps its `Message-ID`).

## Floor reasons

The floor is never overridable (tenant ALLOW, overrides and settings cannot weaken it):

| Code                                             | Meaning                                      | Minimum disposition                                       |
| ------------------------------------------------ | -------------------------------------------- | --------------------------------------------------------- |
| `policy.floor.hard_block`                        | a 5.1 hard block (malware, malicious URL, …) | the hard block's action (usually reject)                  |
| `policy.floor.risk_error`                        | the risk row is a scoring error              | its recommendation (quarantine)                           |
| `policy.floor.engine_failure` / `unknown_engine` | an engine failed or returned unknown         | the revision's recommendation (or a mandatory tag)        |
| `policy.floor.dlp_<action>`                      | the DLP binding (ADR-0037)                   | alert → tag, require_approval, quarantine, block → reject |
| `policy.floor.dlp_missing`                       | a definite DLP final without its row         | quarantine                                                |
| `policy.floor.risk_missing`                      | no revision-0 risk row                       | quarantine                                                |
| `policy.floor.scan_failed` / `not_scanned`       | scan failed / parse failed                   | quarantine                                                |

## What 5.2 does not do

- **Quarantine store, digests, end-user release, release re-validation: step 5.3.** 5.2 holds messages in `quarantined` / `held_for_review`; the only release is the operator release (`POST /api/v1/messages/{messageId}/release`, `quarantine:release`). `mail.policy.decided.v1` already reaches the dormant `email.quarantine` for 5.3.
- **Archiving: step 8.1.** ARCHIVE is `requested`: `mail.message.archive_requested.v1` waits in the dormant, bounded `email.archive`; 8.1 reconciles from `policy_execution_logs` rows whose actions contain ARCHIVE.
- WARN body banners (`bodyBanner: not_supported`), per-recipient dispositions, re-evaluation when a sandbox result arrives later.
- Policy copies change the Subject of inbound mail when a prefix is configured: DKIM signatures covering Subject no longer verify downstream (as with URL rewriting).
