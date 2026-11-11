# Runbook: risk scoring (scores, explanations, profiles, alerts)

Design: [15-risk-scoring.md](../plan/steps/15-risk-scoring.md) (decision ids R*n*: R2–R19),
ADRs [0041](../architecture/adr/0041-risk-scoring-model.md) (the model) and
[0042](../architecture/adr/0042-risk-scoring-placement-and-policy-handoff.md) (placement and the
hand-off to policy). Calibration: [risk-scoring-calibration.md](../performance/risk-scoring-calibration.md).
Code: `packages/risk-scoring` (the pure scorer), `apps/email-worker/src/scanning/risk/` (reads,
profile cache, row writes, metrics), `apps/api/src/modules/risk-scoring/` (profiles, dry-run).

Three facts frame every step below:

- **5.1 recommends; it never enforces.** A score row carries a `recommended_action`. Since step
  5.2 the policy-engine decides from it (platform default `pol-default/1` and the strictness floor,
  [policy-engine runbook](policy-engine.md)); the quarantine store (5.3) is not built yet. The
  development pass-through and `DELIVERY_DEV_PASSTHROUGH_RISK_HOLD` were removed in 5.2.
- **The defaults are not validated accuracy.** The weights and thresholds of the platform profile
  `rsk-default/1` are engineering defaults calibrated on a synthetic, self-constructed dataset. No
  detection accuracy, precision or recall is claimed. Tune per tenant within the bounds, with the
  dry-run, and never treat a score as proof.
- **Never clean by accident.** `unknown`, `timeout`, `error`, a missing engine result or child row
  and a scoring error are never `clean`: each has a reason code, failures (including a missing
  authentication, BEC or DLP row) have level and action floors (`medium`, `quarantine`), an
  `unknown` result has the floors `low` and `tag` (`failures.unknownAction`), and a scoring error
  writes a fail-safe error row (high, quarantine).

Data rules: rows, explanations, logs and metrics carry engine names, outcomes, reason codes,
signal ids, integers, versions and ids only. No addresses, domains, URLs, subjects, file names or
body text are ever stored in or derived into a risk row.

## Contents

- [Where scoring runs](#where-scoring-runs) · [Revisions 0 and 1](#revisions-0-and-1) ·
  [Reading a score](#reading-a-score) · [The dry-run](#the-dry-run) ·
  [Profiles: publish, activate, rollback, reset](#profiles-publish-activate-rollback-reset) ·
  [Error rows](#error-rows) · [Profile fallbacks](#profile-fallbacks)
- Alerts: [RiskScoringErrors](#riskscoringerrors) · [RiskProfileFallback](#riskprofilefallback) ·
  [RiskScoreMissing](#riskscoremissing) · [RiskUnmappedCodes](#riskunmappedcodes) (rules
  `infrastructure/monitoring/rules/risk-scoring.rules.yml`)
- [Metrics](#metrics) · [Configuration](#configuration) · [Checking the alert rules](#checking-the-alert-rules)

## Where scoring runs

```
round opens (ScanRepository.openRound)
  └─ email_scans.risk_profile_version_id = risk_scoring_profiles.active_version_id (snapshot)
round completes (last required final, or the deadline sweeper) — one transaction, row locks held
  └─ aggregateRound → email_scans status/scan_verdict
       └─ risk: read finals + email_auth_results + bec_scan_results + dlp_scan_results (echo-checked)
            ├─ resolve the snapshot profile (LRU of published versions; fallback = platform default)
            ├─ score (pure, integer arithmetic) → message_risk_scores revision 0
            ├─ email_scans.verdict, risk_score, scoring_version
            └─ (a non-skipped sandbox final already present → revision 1)
       └─ lifecycle transition E6/E7 → mail.message.scanned.v1 (outbox)
late sandbox final (sandbox-finalizer, under the email_scans row lock)
  └─ round no longer running → message_risk_scores revision 1
```

The score row commits in the same transaction as `scanned.v1`, so any consumer of that event finds
it. It is written whether or not the lifecycle transition applies (a superseded round keeps its
score). A database error rolls back the whole completion, which is retried like any scan
completion. A wrong read (Prisma defect, step 4.2 §6) throws `InconsistentRiskReadError` and is
retried (`scan_risk_inconsistent_reads_total{read}`). A round whose message row was purged while
it was open completes without a score (`scan_risk_skipped_total{reason="message_gone"}`).

## Revisions 0 and 1

| Revision | Written by                                                   | Inputs                                           | Also sets                                              |
| -------- | ------------------------------------------------------------ | ------------------------------------------------ | ------------------------------------------------------ |
| 0        | the round's completion (engine finalize or deadline sweeper) | every required engine's final, auth/bec/dlp rows | `email_scans.verdict`, `risk_score`, `scoring_version` |
| 1        | whichever comes second of completion and the sandbox final   | the same, plus the sandbox final (non-skipped)   | nothing (`email_scans` keeps revision 0)               |

- The sandbox never enters revision 0 (its arrival order would change it). Delivery, the
  pass-through and policy use revision 0; policy (5.2) may read revision 1 only to be stricter.
- One row per `(scan_id, revision)`: the unique key `(scan_id, revision, received_at)` makes a
  repeated attempt a no-op (`scan_risk_duplicates_total{revision}`).
- A rescan is a new round (new `scan_id`) with its own snapshot and its own rows. Old rows are never
  updated; they disappear only through retention (6 months, `core`) or organization purge.

## Reading a score

The scans read API returns each round with its scores (revisions ascending; `[]` before 5.1 or
while the round runs):

```
GET /api/v1/messages/{messageId}/scans          (permission message:read)
  rounds[].risk[] = { revision, status, score, level, verdict, recommendedAction, hardBlocks,
                      reasonCodes, contributions, groups, engines, failures, floors, trust,
                      evidence, explanation { lines, text }, versions, inputSha256, createdAt }
```

How to read it, in this order:

1. `status`: `scored`, or `error` (a fail-safe row, see [Error rows](#error-rows)).
2. `hardBlocks`: any entry (`hb.malware_attachment`, `hb.known_phishing`, `hb.dlp_block`, …) sets
   the level to `critical`, fixes the verdict and a non-delivery action, whatever the score, trust
   or profile weights say.
3. `score` (0–1000) and `level` (`none < low < medium < high < critical`; default thresholds 100,
   300, 550, 800). `recommendedAction` is the strictest of the level's action, the failure floor,
   the DLP binding (never weaker than the round's DLP action), every hard block and the AI-only tag.
4. `explanation.text`: fixed English templates over codes and integers, e.g.
   `Risk 720/1000 (high): recommended quarantine.` followed by hard blocks, engine failures, the top
   signals with the engines that asserted them, trust, floors and the profile used.
5. `contributions` (fired signals: weight, applied points, the `engine:code` assertions) and
   `groups` (`max` or `capped_sum`, multiplier, trust factor, cap, total) show where the points
   came from. Several engines asserting the same fact raise one signal once.
6. `failures` and `floors`: required engines that timed out, errored, were missing or returned
   `unknown` (and missing child rows), and the level floors they imposed (the action floors are
   `failures.action` and `failures.unknownAction` of the profile used).
7. `trust`: `applied` only for an authenticated trusted sender (BEC T1, DMARC pass, no auth
   failure); otherwise why it was not (`not_trusted`, `denied_unauthenticated`,
   `denied_auth_failure`, `off`).
8. `versions`: scorer, signal map, input version and the profile (`rsk-default/1` or
   `rsk-default/1+t:<version public id>#<n>`) with its SHA-256; `inputSha256` identifies the exact
   input. Together they make the result reproducible.

From the database (writer or replica), by message: `message_risk_scores` filtered by
`(message_id, received_at)` (indexed); never select by organization without a time range.

## The dry-run

```
POST /api/v1/messages/{messageId}/scans/{scanId}/risk/dry-run
     (permissions policy:manage and message:read; reads the replica; writes nothing)
body { "profile": "active" | "platform" | { "versionId": "<public id>" } | { "overrides": { … } },
       "revision": 0 | 1 }
```

It rebuilds the round's input from the stored rows, resolves the requested profile and returns
`{ result, stored, reproducible }`. `reproducible: true` with `profile: "active"` (or the version
the round used) proves the stored row is what the scorer computes today. Use it:

- before publishing a draft: dry-run a few recent rounds of the tenant against
  `{ "versionId": "<draft>" }` or the raw `{ "overrides": … }` and compare levels and actions;
- when a customer disputes a score: compare `result` with `stored` and read the explanation.

`409 scan_round_not_complete` means the round still runs or the replica has not caught up; retry
after a few seconds. `404` means another tenant's message or scan (never a hint that it exists).

## Profiles: publish, activate, rollback, reset

A tenant profile is a set of **bounded overrides** of the platform default (thresholds, actions
per level, group multipliers 0.5×–2×, hard-block switches where allowed, failure weights and floors
that may only be raised, trust mode and factor, the AI-only tag). Routes (tenant from the
authenticated scope; every change audited `risk_profile.*`):

| Task                                                         | Route                                                                            | Permission       |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------- | ---------------- |
| See the platform default, bounds, signal map and hard blocks | `GET /api/v1/risk-scoring/platform-profile`                                      | `policy:read`    |
| See the active profile                                       | `GET /api/v1/risk-scoring/profile`                                               | `policy:read`    |
| List / read versions                                         | `GET /api/v1/risk-scoring/profile/versions[/{versionId}]`                        | `policy:read`    |
| Create a draft (optionally from a version)                   | `POST /api/v1/risk-scoring/profile/versions`                                     | `policy:manage`  |
| Edit / delete a draft                                        | `PUT` / `DELETE /api/v1/risk-scoring/profile/versions/{versionId}`               | `policy:manage`  |
| Publish (and by default activate)                            | `POST …/profile/versions/{versionId}/publish` `{ activate, expectedRowVersion }` | `policy:publish` |
| Activate a published version (rollback)                      | `POST …/profile/versions/{versionId}/activate`                                   | `policy:publish` |
| Reset to the platform default                                | `POST /api/v1/risk-scoring/profile/reset`                                        | `policy:publish` |

- **Published versions are immutable** (`409 risk_profile_version_immutable` on edit or delete).
  The worker caches them by id for that reason; nothing needs to be flushed after a change.
- **A change applies to the next round only.** Each round stores the active version when it opens
  (`email_scans.risk_profile_version_id`); open rounds and stored scores never change. To re-score
  a message with the new profile, rescan it (`POST /api/v1/messages/{id}/rescan`): the new round
  gets new rows, the old ones stay.
- **Rollback** = activate the previous published version. **Reset** = pointer to NULL (platform
  default). Both are pointer changes with compare-and-set; both are audited with old and new ids.
- Validation errors name the override path (`400 risk_profile_invalid`); the version limit is
  `RISK_PROFILE_MAX_VERSIONS` (`409 risk_profile_limit_reached`).

## Error rows

A scoring failure never blocks a round. Instead the worker writes a row with `status = error`,
`score` = the platform `high` threshold (550), `level = high`, `verdict = unknown`,
`recommended_action = quarantine`, reason `risk.scoring_error` and the explanation
`Scoring failed; treated as high risk (fail-safe)`. Reasons (`scan_risk_errors_total{reason}`):

| Reason             | Meaning                                                             | Typical cause                                                                      |
| ------------------ | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `input_invalid`    | the input builder refused the round's rows (`RiskInputError`)       | malformed JSON in a child row, an engine name or outcome the release does not know |
| `scorer_exception` | the scorer threw, or its result failed its own schema               | a defect in `@email-gateway/risk-scoring`                                          |
| `profile_error`    | the snapshot's version row is malformed (public id, version number) | a defect or a manual edit of `risk_scoring_profile_versions`                       |

The email-worker logs `risk scoring failed; fail-safe error row written` at error with the ids
(organization, message, scan, round, revision) and the reason only. Find the rows with
`SELECT scan_id, revision, reason_codes FROM message_risk_scores WHERE status = 'error' AND
received_at >= NOW() - INTERVAL 1 DAY` (add the organization when known). An error row is final
for its round; after the cause is fixed, rescan the affected messages to get scored rows.

## Profile fallbacks

When a round's snapshot version cannot be used, the round is scored with the platform default and
the row carries `profile_source = platform`, `profile_version_id = NULL` and a reason code:

| Fallback (`scan_risk_profile_fallback_total{reason}`) | Code                            | Cause                                                                                                                    |
| ----------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `invalid`                                             | `risk.profile.invalid_fallback` | the version fails the current platform bounds (bounds tightened since publish) or names a base profile no longer shipped |
| `missing`                                             | `risk.profile.missing_fallback` | the version row is absent or is not published (a draft id in the pointer)                                                |
| `foreign`                                             | `risk.profile.foreign_fallback` | the version belongs to another organization (a corrupted pointer)                                                        |

The pointer never names a draft or a foreign version through the api; `missing` and `foreign`
mean a manual database change or a defect. Fix the pointer (activate a valid published version or
reset). `invalid` after a release that tightened bounds: the tenant republishes a corrected version
(the api's version detail shows the violations).

## RiskScoringErrors

Warning: error rows in the last 15 minutes (label `reason`); critical: the same for an hour.

1. Read the email-worker error logs `risk scoring failed` for the ids and the reason.
2. `input_invalid`: dry-run one affected round (`profile: "platform"`); a `RiskInputError` names
   the field. Check the release of every scan replica: a newer engine writing values an older
   scorer does not know is the common cause during a rollout (finish the rollout).
3. `scorer_exception`: a library defect. Roll back the email-worker release if it is systematic;
   collect the round ids for the fix.
4. `profile_error`: find the tenant (`email_scans.risk_profile_version_id` of the affected rounds)
   and reset or re-activate a valid version (`POST …/profile/reset`).
5. After the fix, rescan the affected messages.

## RiskProfileFallback

Warning: rounds scored with the platform default instead of their tenant version (label `reason`).
Scores are valid but ignore the tenant's settings. See [Profile fallbacks](#profile-fallbacks);
find the tenants with `SELECT DISTINCT organization_id FROM message_risk_scores WHERE received_at

> = NOW() - INTERVAL 1 HOUR AND JSON_CONTAINS(reason_codes, '"risk.profile.<reason>_fallback"')`.

## RiskScoreMissing

Critical: for 30 minutes more rounds completed (`scan_rounds_completed_total`) than revision-0 rows
were written (`scan_risk_scores_total{revision="0"}` plus rounds skipped because their message
was purged). Missing rows are holds for policy and the pass-through.

1. Mixed releases: a scan replica without step 5.1 completes rounds without scoring. Check the
   image of every email-worker Deployment that runs the scan role (`email-worker-scan`,
   `-attachment`, `-url`, `-bec`, `-dlp`, `-sandbox`); finish or roll back the rollout.
2. `scan_risk_duplicates_total{revision="0"}` rising: a round was completed twice (a defect);
   collect the scan ids from the logs.
3. Find the rounds: `SELECT s.id, s.received_at FROM email_scans s LEFT JOIN message_risk_scores r
   ON r.scan_id = s.id AND r.received_at = s.received_at AND r.revision = 0 WHERE s.completed_at
   > = NOW() - INTERVAL 1 HOUR AND s.status <> 'running' AND r.id IS NULL`; rescan those messages
   > once the cause is fixed.

## RiskUnmappedCodes

Info: an engine emitted reason codes the signal map `risk-signals/1` does not know (label
`engine`). They contribute 0 points, are listed in `evidence.unmappedCodes` and keep a round from
being `clean`. A newer engine release added codes: map them (or list them as informational) in a
new signal map version of `@email-gateway/risk-scoring`; never edit a released map.

## Metrics

email-worker (labels are bounded enums; never tenant ids):

| Series                                   | Labels                                                  | Meaning                                                |
| ---------------------------------------- | ------------------------------------------------------- | ------------------------------------------------------ |
| `scan_risk_scores_total`                 | revision, level, action, direction, status              | rows written                                           |
| `scan_risk_score` (histogram, 100…1000)  | revision                                                | score distribution                                     |
| `scan_risk_hard_blocks_total`            | indicator                                               | hard blocks fired                                      |
| `scan_risk_engine_failures_total`        | engine, status                                          | failures, unknowns, missing rows counted by the scorer |
| `scan_risk_trust_total`                  | status                                                  | trusted-sender decisions                               |
| `scan_risk_profile_fallback_total`       | reason (invalid, missing, foreign)                      | platform-default fallbacks                             |
| `scan_risk_errors_total`                 | reason (input_invalid, scorer_exception, profile_error) | error rows                                             |
| `scan_risk_unmapped_codes_total`         | engine                                                  | unknown engine codes                                   |
| `scan_risk_duplicates_total`             | revision                                                | no-op repeated inserts                                 |
| `scan_risk_duration_seconds` (histogram) | —                                                       | reads + profile + scoring inside the transaction       |
| `scan_risk_skipped_total`                | revision, reason (message_gone)                         | completed rounds without a row                         |
| `scan_risk_inconsistent_reads_total`     | read                                                    | wrong reads (retried)                                  |

api: `risk_dry_runs_total{result}`, `risk_profile_changes_total{operation}`. What policy does with
the score is counted by the policy-engine (`policy_evaluations_total`, `policy_floor_raises_total`,
step 5.2); the 5.1 pass-through series `delivery_risk_holds_total` and
`delivery_approvals_skipped_total` were removed with the pass-through.

Every metric is recorded after the transaction commits, so a rolled-back completion is never
counted. The measured cost (package integration, local stack) is a few milliseconds per round
(`scan_risk_duration_seconds`, `message_risk_scores.duration_us`).

## Configuration

| Key                              | Service           | Default         | Bounds                                  |
| -------------------------------- | ----------------- | --------------- | --------------------------------------- |
| `RISK_PLATFORM_PROFILE`          | email-worker, api | `rsk-default/1` | a shipped id (`RISK_PLATFORM_PROFILES`) |
| `RISK_PROFILE_CACHE_MAX_ENTRIES` | email-worker      | `10000`         | 100–100000                              |
| `RISK_PROFILE_MAX_VERSIONS`      | api               | `200`           | 10–1000                                 |

A changed platform default is a new id (`rsk-default/2`), never an edit; stored rows keep the
version they were scored with. Kubernetes sets the first two on every scan-role email-worker
Deployment and the api (`infrastructure/kubernetes/base/`).

## Checking the alert rules

```
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 check rules /m/rules/risk-scoring.rules.yml
docker run --rm -v "$PWD/infrastructure/monitoring:/m:ro" --entrypoint promtool \
  prom/prometheus:v3.6.0 test rules /m/tests/risk-scoring.rules.test.yml
```

Prometheus loads the file through `rule_files: rules/*.rules.yml` (no change to
`infrastructure/monitoring/prometheus.yml`).
