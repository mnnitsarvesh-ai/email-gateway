# Runbook: policy builder, policy management and DLP/BEC configuration

Operating the visual policy builder and the policy management pages of the admin portal (step 7.3; [design and verification record](../plan/steps/22-policy-builder.md), [ADR-0063](../architecture/adr/0063-policy-builder-dsl-driven-no-client-evaluation.md)). The builder is driven by the api's DSL catalogue (`GET /api/v1/policies/catalog`) and never evaluates policy logic in the browser: validation, test, dry-run, publish and execution are api calls, and the server's answer is what the page shows. Pages, routes and operations: [page inventory](../frontend/page-inventory.md) (pages 13 and 14). The portal itself: [admin-portal runbook](admin-portal.md). The DSL: [policy-dsl.md](../architecture/policy-dsl.md).

Contents: [roles](#who-can-do-what) · [validation](#validation-and-auto-validate-throttling) · [test](#test-targets) · [dry run](#sample-dry-run-bounds-and-429s) · [conflicts](#conflicts-and-the-dialog-choices) · [publish and rollback](#publish-activate-and-rollback) · [large policies](#large-policies-and-the-413-limitation) · [risk drafts](#risk-profile-drafts) · [settings](#policy-settings) · [DLP and BEC](#dlp-and-bec-configuration) · [audit](#where-the-audit-rows-are) · [troubleshooting](#troubleshooting)

## Who can do what

| Role (system)                                                            | Policy builder and management                                                                                                                                      | DLP / BEC                                                                                          |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| `organization_admin`, `super_admin`                                      | Everything: drafts, validate, test, dry run, publish, activate / roll back, enable / disable, delete, settings, risk-profile drafts                                | Edit (`dlp:manage`, `bec:manage`); the Aadhaar basis (`dlp:compliance_manage`) with an MFA session |
| `security_analyst`                                                       | Create and edit drafts, validate, test, dry run (`policy:manage`, dry run also `message:read`); no publish/activate/enable/disable/delete-policy/settings controls | Edit (no Aadhaar basis)                                                                            |
| `read_only_user`, `compliance_auditor`, `domain_admin`, `platform_admin` | View mode only (no inputs, no mutation or test controls)                                                                                                           | View only where the role holds `dlp:read` / `bec:read`                                             |

The portal hides what the session may not call (`x-eg-permissions` of the operation); the api stays authoritative (a direct call answers `403`). The organization is always the signed-in session's; another organization's policy, version, DLP or BEC id is `404` (the "not found" state).

## Validation and auto-validate throttling

- `POST /api/v1/policies/validate` (`policy:manage`, standard rate class) checks a document exactly as a draft save would and writes nothing. `valid` covers the DSL; `referenceViolations` (unknown department or user ids, checked on the replica) are warnings for a draft but block publish, activation and enable.
- The editor validates (a) on **Validate**, (b) automatically 2 s after the last edit when the document changed, **at most once per 10 s**, only while the tab is visible, and (c) before the publish dialog confirms. After a `429` it pauses for `Retry-After`.
- Violations carry a stable code and a JSON path (`rules[0].when.all[1].any[2]`); the editor shows them on that condition ("Problems reported by the server") and in an error summary whose items move focus to the node. Regular expressions, globs, CIDRs and time zones are only checked by the server (RE2). A draft must validate to be saved; until then the work exists only in the editor (an unsaved-changes guard warns before leaving; definitions are never stored in the browser).

## Test targets

`POST /api/v1/policies/test` (synthetic facts; writes nothing). Targets: **This draft** (`{ policyId, versionNo }`: the saved draft in place of the policy's active version; with unsaved edits the button reads **Save and test**), **This new policy (unsaved)** (`{ definition }`, before the policy exists), **Active policies**, **Platform default only**. Facts come from the form (vocabularies from the catalogue), five presets, or the Advanced (JSON) editor; invalid facts are `400 policy_test_facts_invalid`. The result is the server's `PolicyTestResponse` (disposition, decisive policy/rule, matched rules, actions, floor, trace with **Show in editor**). The platform floor always applies.

## Sample dry run: bounds and 429s

`POST /api/v1/policies/dry-run` re-evaluates the newest stored evaluation of each message in a window against a target and compares it with the stored decision. Writes nothing; returns message public ids, times, enums and rule ids only.

| Bound                                        | Default                                                   | Key                                        |
| -------------------------------------------- | --------------------------------------------------------- | ------------------------------------------ |
| Rounds per request (`sample.limit`)          | 25 (max 50)                                               | `POLICY_DRY_RUN_SAMPLE_MAX` (1–200)        |
| Wall-clock deadline (then `truncated: true`) | 10 000 ms                                                 | `POLICY_DRY_RUN_DEADLINE_MS`               |
| Sample dry runs per principal per minute     | 6                                                         | `POLICY_SAMPLE_DRY_RUNS_PER_MINUTE` (1–60) |
| Window                                       | last 7 days, at most `POLICY_HISTORY_MAX_RANGE_DAYS` (31) | —                                          |

It is also in the `expensive` rate class (`API_RATE_EXPENSIVE_PER_MINUTE`). A `429 rate_limited` with `scope: route` is the per-principal limit (wait `Retry-After`; the panel disables **Run** with a countdown); `scope: principal|tenant` is the class or tenant budget. A `503` means the rate-limit store (Redis) is unavailable (fail closed). **One message** uses the per-round dry run (`POST /messages/{id}/scans/{scanId}/policy/dry-run`) and shows `reproducible`. Production-scale timing of the sample is not measured (local data only; the deadline bounds it).

## Conflicts and the dialog choices

- Saving a draft sends `expectedRowVersion`. **`409 policy_conflict`** (someone saved first): **Reload theirs** (discard local edits), **Overwrite with mine** (re-PUT at the server's `currentRowVersion`, an explicit choice), **Download my definition** (a local JSON file only).
- **`409 policy_version_immutable`** (the draft was published meanwhile): **Save as a new draft** (`POST …/versions` with the local definition).
- `409 policy_name_taken` (new policy or rename) is shown on the name; `409 policy_limit_reached` names the limit.
- Activate/rollback sends the policy's `rowVersion`; a `409 policy_conflict` asks to reload and confirm again.

## Publish, activate and rollback

- **Publish** (`policy:publish`, Idempotency-Key reused on retry): the dialog re-runs validation and the reference check; **Activate now** (default on) makes the version active. Success shows the organization's new **policy generation**.
- **Next-evaluation rule:** a publish, activation, rollback, enable/disable or settings change increments the generation in the same transaction and applies to the **next evaluation only**; messages already evaluated keep their decision (quarantine release re-validates against the current policy).
- **Roll back** = activate an earlier published version (`POST …/versions/{n}/activate`): no version is changed or deleted; audited `policy.version_activated` with `versionNo` and `previousVersionNo`. A version the DSL no longer accepts, or one naming a deleted department, is refused (`400 policy_definition_invalid` with violations). **Restore as new draft** ("New draft from this version") is the alternative when you want to edit first.
- **Enable / disable** (switch with a confirmation; enable needs an active version), **Delete policy** (type the name; archives it), **Delete draft**.

## Large policies and the 413 limitation

The api's JSON body limit is Express's default 100 KiB, below the DSL's 256 KiB document limit. Measured in step 7.3 (§13 WP1): a larger body is answered **`500 internal_error`**, not `413` (body-parser's error is not mapped by the global exception filter). The editor shows the document size and treats `413`, or a `500` above about 100 KiB, as "too large to send — split it into several policies". Follow-up (no owning step yet): map `entity.too.large` to `413 payload_too_large` and/or raise the limit for the policy routes.

## Risk-profile drafts

Policy management → **Risk scoring**: **New draft** (from the active version or the platform profile) opens `/policies/risk-profile/{versionId}`, a form generated from `GET /risk-scoring/platform-profile` bounds (thresholds with their min/max and minimum gap, actions per level, group multipliers, hard blocks, failures, floors, trust). Only values that differ from the platform profile are stored. Save uses `expectedRowVersion` (`409 risk_profile_version_conflict` → reload); `400 risk_profile_invalid` is mapped to the inputs. Publish (activate default on), **Activate vN / Roll back to vN…** from the versions table, **Reset to the platform profile** — all confirmed, `policy:publish`, Idempotency-Key. There is no risk dry-run UI (the api exists).

## Policy settings

Policy management → **Policy settings**: editable switches (`allowRecommendationOverrides`, `recipientSplit`, sender non-delivery notices, policy alerts, platform tag header / outbound) with `expectedRowVersion`; only changed values are sent. Turning **Recommendation overrides** on needs a confirmation (audited `policy.settings_overrides_enabled`); the strictness floor still applies.

## DLP and BEC configuration

Decided by the product owner on 2026-11-16: configuration editing is part of 7.3 (dialogs/sheets inside the DLP and BEC tabs; no new routes; existing api).

- **DLP** (`dlp:manage`): policies (mode, priority, directions, enabled; delete requires typing the name and removes its rules), rules (categories, detectors, custom patterns, dictionaries, coverage reasons, thresholds, scope), exceptions (scope, target, filters, reason, expiry ≤ 365 days), custom patterns with **Test pattern** (`POST /dlp/patterns/test`, 30 per caller per minute; the server compiles the pattern with RE2 and returns masked matches; the portal never evaluates a pattern; use synthetic samples only), keyword dictionaries. Incidents stay read-only.
- **Aadhaar basis** (`dlp:compliance_manage`, organization admin / super admin, and an **MFA session**): record or withdraw with a confirmation and an Idempotency-Key. Without MFA the page shows the MFA-required state (`mfa_required`); sign in again with MFA.
- **BEC** (`bec:manage`): executives, vendors (free-mail domains refused, `vendor_domain_freemail`), trusted senders (registrable domain or address; free-mail refused), **Lift** a suppression. Feedback stays read-only.
- Changes apply after the engines' tenant-data cache refresh (30 s by default); finished scans keep their result. Updates send `version` (`409 version_conflict` → **Load the current version**); lists read the replica, so a just-created row can lag a moment.
- **Not in 7.3** (data operations, no owning step yet): BEC communication-history purge (`DELETE /bec/history`), BEC feedback recording and export, DLP evidence purge.

## Where the audit rows are

All rows are in `audit_logs` (append-only), visible on the Audit logs page (`audit:read`) and, for a policy, on its **Audit** tab (two reads: `resourceType=email_policy` and `policy_version`, `resourceId` = the policy's public id, last 90 days, merged by time). Metadata holds ids, numbers and hashes only (never the definition).

| Area         | Actions                                                                                                                                                                                                                                                                               |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Policies     | `policy.created`, `policy.updated`, `policy.deleted`, `policy.enabled`, `policy.disabled`, `policy.version_draft_created/updated/deleted`, `policy.version_published`, `policy.version_activated` (`versionNo`, `previousVersionNo`, `generation`), `policy.override_rules_published` |
| Settings     | `policy.settings_updated`, `policy.settings_overrides_enabled`                                                                                                                                                                                                                        |
| Risk profile | `risk_profile.draft_created/updated/deleted`, `risk_profile.published`, `risk_profile.activated`, `risk_profile.reset`                                                                                                                                                                |
| DLP          | `dlp_policy.*`, `dlp_rule.*`, `dlp_exception.*`, `dlp_pattern.*`, `dlp_dictionary.*` (`created/updated/deleted`), `dlp_compliance.aadhaar_enabled/aadhaar_disabled`                                                                                                                   |
| BEC          | `bec_executive.*`, `bec_vendor.*`, `bec_trusted_sender.*` (`created/updated/deleted`), `bec_suppression.deleted`                                                                                                                                                                      |

Validate, test and dry runs write nothing and are not audited. To read a rollback: filter the Audit logs page by action `policy.version_activated`; `previousVersionNo` greater than `versionNo` is a rollback.

## Troubleshooting

| Symptom                                                  | Cause and action                                                                                                                                            |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The builder shows a catalogue error state                | The api answered a catalogue shape the portal does not accept (`CatalogShapeError`): portal and api versions differ. Deploy the api first, then the portal. |
| A stored time zone is not in the picker                  | The catalogue lists the api runtime's zones (`Asia/Calcutta`, not `Asia/Kolkata`); the value round-trips and the server validates it.                       |
| Run in the dry-run panel stays disabled with a countdown | The per-principal sample limit (`429 scope: route`); wait or raise `POLICY_SAMPLE_DRY_RUNS_PER_MINUTE` deliberately.                                        |
| Publish refused with `department_unknown`                | A referenced department was deleted; edit the draft (directory picker) and publish again.                                                                   |
| Save fails with a "too large" message                    | See [large policies](#large-policies-and-the-413-limitation).                                                                                               |
| A DLP/BEC change has no effect on a message              | The engines' cache refresh (30 s) had not passed, or the message was scanned before; rescan the message from Email details.                                 |
