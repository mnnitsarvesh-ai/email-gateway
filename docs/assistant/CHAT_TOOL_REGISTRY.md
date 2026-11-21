# Chat tool registry

The registry is the list of operations the assistant may call. It is **generated** from the committed OpenAPI snapshot (`docs/api/openapi.json`) plus a small hand-written manifest, so a tool is always exactly one existing `/api/v1` operation with that operation's own permission, idempotency, rate class and cursor metadata. Design: [D3, D4](../plan/steps/28-ai-chat-management.md#d3-tool-registry-bound-to-openapi-adr-0091), [AI-2 D4, D5, §4.3](../plan/steps/29-ai-chat-confirmations-mail-writes.md#d4-confirmation-specs-package-packagesassistantsrcconfirmationsspecsts), [§4.4](../plan/steps/28-ai-chat-management.md#44-risk-and-confirmation-rules-the-generators-rules-overrides-in-the-manifest); [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md); record format in [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1).

## Files

| File                                                       | Role                                                                                                                                                                                                                                                                                                                                                         |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `packages/assistant/src/registry/manifest.ts`              | Hand-written: the program phase (`ASSISTANT_PROGRAM_PHASE = 'AI-2'` since step AI-2; `CONFIRMATION_SUPPORT_PHASE = 'AI-2'`), the classification rules (not-applicable tags and reasons, critical operations, risk verbs) and per-operation overrides (risk, phase, title, display hints, `untrustedFields`, portal route, bindings, limitations, `testedBy`) |
| `packages/assistant/scripts/generate-registry.ts`          | The generator (run with `tsx`)                                                                                                                                                                                                                                                                                                                               |
| `packages/assistant/src/registry/build.ts`                 | Classification and schema normalization used by the generator and the tests                                                                                                                                                                                                                                                                                  |
| `packages/assistant/src/registry/operations.generated.ts`  | Generated: one `OperationTool` record per classified operation and `REGISTRY_VERSION`                                                                                                                                                                                                                                                                        |
| `docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md`           | Generated: the UI-to-chat capability matrix (every operation, its portal pages, tool, permission, risk, confirmation, status, phase and test coverage)                                                                                                                                                                                                       |
| `packages/assistant/src/registry/registry.ts`, `render.ts` | Runtime: lookup by name, permission pre-filter (`enabledTools`), the catalogue index of the system prompt, `describe_tool`                                                                                                                                                                                                                                   |
| `packages/assistant/src/registry/consistency.ts`           | The AI-2 consistency rules (below), run by the generator (it refuses to write outputs that break them) and the registry tests                                                                                                                                                                                                                                |
| `packages/assistant/src/confirmations/specs.ts`            | One confirmation spec per enabled write (precondition read, state fields, CAS injection, definition validation)                                                                                                                                                                                                                                              |
| `packages/assistant/src/confirmations/impact.ts`           | One impact template per enabled write: the server-authored `assistant-confirmation/1` summary of the confirmation card                                                                                                                                                                                                                                       |

Inputs of the generator: the OpenAPI snapshot, the manifest, and the portal's operation usage (operation-id strings in `apps/admin-portal/src/features/**`, the app shell excluded), which fills the "Portal page" column.

## Regenerating

```bash
pnpm --filter @email-gateway/assistant registry:generate   # rewrites both generated files
pnpm --filter @email-gateway/assistant registry:check      # fails when either is stale
```

`registry:check` is part of the package's `test` script (and so of `pnpm test`). After an OpenAPI change, regenerate the snapshot first (`UPDATE_OPENAPI=1 pnpm --filter @email-gateway/api test:e2e`), then the registry.

## Record

Each record (`OperationTool`) has: `name`, `operationId`, `method`, `pathTemplate`, `module` (OpenAPI tag), `summary`, `description`, `inputSchema` (JSON Schema of path parameters, query parameters and, for writes, the body; `$ref`s inlined; `additionalProperties: false`; header parameters such as `Idempotency-Key` never included), `pathParams`, `queryParams`, `requirement` (copy of `x-eg-permissions`), `platformOnly`, `idempotency`, `rateClass`, `cursor`, `access` (`read`/`write`), `risk`, `confirm`, `phase`, `enabled`, `status`, `portalRoute`, `portalPages`, `display`, `untrustedFields`, `bind`, `limitations`, `testedBy`. `REGISTRY_VERSION` is the first 16 hex characters of the SHA-256 of the generated content and is stored on every turn.

## Naming

`snake(controller name without "Controller") + "_" + snake(method name)`, for example `PolicyManagementController_list_v1` → `policy_management_list`, `QuarantineEntriesController_search_v1` → `quarantine_entries_search`. Names match `^[a-z0-9_]{1,64}$` and are unique (test-enforced).

## Classification rules

| Class            | Operations                                                                                                                                                                                                                                                                        | Confirmation (from AI-2)                 |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `not_applicable` | tags `auth`, `mfa`, `sessions`, `meta`, `assistant`; operations with `x-eg-returns-secret`; previews, downloads, download grants, reveal, DLP evidence reads; provider credential upload and OAuth consent; platform override; BEC feedback export (file)                         | never a tool; the chat links to the page |
| `critical`       | organization status and deletion, legal-hold release, archive disposal, archive key rotation, DLP evidence purges, BEC history purge                                                                                                                                              | portal only (also `not_applicable`)      |
| `read`           | every other `GET`, and side-effect-free `POST`s (`…/test`, `…/validate`, `…/dry-run`, mail-flow preview, pattern test)                                                                                                                                                            | none                                     |
| `read_audited`   | archive record reads, eDiscovery hits, audit and login-event searches                                                                                                                                                                                                             | none                                     |
| `high`           | deletes, remove/purge/revoke/rotate/reset/rollback/bulk, role and user status/role/MFA/session changes, feature and limit overrides, DKIM rotation, exports, holds, mail-flow apply, ATO responses, platform threat intel, rescans, training, dead-letter replay, policy settings | confirm + impact + fresh re-auth         |
| `medium`         | enable/disable/publish/activate/approve/deny/release/reject/rescan/retry/replay/pause/resume/verify/settings and other `PUT`s                                                                                                                                                     | confirm + impact                         |
| `low`            | creates and updates of drafts and records (manifest overrides adjust single operations)                                                                                                                                                                                           | confirm                                  |

The confirmation is specified in [ADR-0093](../architecture/adr/0093-assistant-action-confirmation.md) (amended in AI-2) and built in AI-2.

**Enabled** = not `not_applicable`, `phase` ≤ the program phase, and either `access = read` or (the confirmation manager exists, `CONFIRMATION_SUPPORT_PHASE` ≤ the program phase, and the write has a `testedBy` suite). **Status** in the matrix: `IMPLEMENTED` (enabled and covered by a named suite: every enabled read by the tool sweep in `apps/api/integration/assistant-tools.test.ts`, every enabled write by its `testedBy` suite), `PARTIALLY_IMPLEMENTED` (enabled with `limitations`), `MISSING` (planned for the phase shown), `NOT_APPLICABLE` (with the reason).

## Checks (test-enforced)

`packages/assistant/src/registry/registry.test.ts` and `registry:check` fail the build when:

- either generated file is stale, or `REGISTRY_VERSION` is not the content hash;
- an OpenAPI operation is not classified exactly once (**completeness**: a new endpoint of any later step fails until it is classified);
- a `requirement` differs from the operation's `x-eg-permissions`; an `x-eg-returns-secret` operation or an `auth`/`mfa`/`sessions`/`meta`/`assistant` operation is a tool (**consistency**);
- an enabled tool is beyond the program phase, or a write is enabled before the confirmation manager exists (`CONFIRMATION_SUPPORT_PHASE`);
- an enabled write lacks a `testedBy` suite, a confirmation spec or an impact template, or has a non-confirmable risk (`critical` operations are never tools);
- a confirmation spec does not belong to exactly one enabled write; a precondition tool (or a `toolByAction` tool) is not an enabled read whose path parameters are exactly the mapped ones; a mapped argument path, an injected CAS field (with the spec's minimum) or the `validateDefinition` field does not exist in the write's input schema;
- a name is invalid, duplicated or not derived from the operation id;
- an enabled tool has no portal route, or an override, display hint or `untrustedFields` path names something that does not exist in the operation or its success (200/201) response schema;
- a free-form response path of a tool (object without declared properties, map, untyped value) is not covered by its `untrustedFields` (the generator adds them by default: `freeFormResponsePaths` in `src/registry/build.ts`);
- an input schema does not compile in Ajv strict mode.

`packages/assistant/src/dependency-boundary.test.ts` checks that no app other than the api depends on `@email-gateway/assistant` (the portal imports types only).

## How later steps add tools

Every step that adds or changes API operations (ATP-1 … ATP-9, 8.3, …) also:

1. classifies each new operation in the manifest (tool with phase, or `not_applicable` with a reason), adds display hints (`columns`, `resourceType`, link field) and `untrustedFields` for mail-derived or attacker-influenced typed strings (free-form objects are untrusted by default);
2. regenerates the OpenAPI snapshot and the registry, and commits both generated files;
3. relies on the tool sweep for new reads (it iterates every enabled read) and, for each write it enables, adds a confirmation spec, an impact template and a `testedBy` integration suite that proposes and confirms the write against the real api (the sweep's "no write without confirmation" check covers it automatically).

The registry check fails the build otherwise, which is how "each later step adds its own chat tools" is enforced.

## Confirmation specs (AI-2)

Every enabled write has exactly one spec (`CONFIRMATION_SPECS`); the executor uses it to build the proposal and the confirm uses it to re-check the target. A spec names:

- **precondition**: `null` (creates), `single` (one read tool with `params` mapping its path parameters to the write's argument paths) or `each` (quarantine bulk: one read per id of `body.ids`, the first 25, with a read tool per `body.action`);
- **stateFields**: the fields of the read whose change between the proposal and the confirm refuses the confirm (state digest), plus `rowVersionField` and the `displayFields` the impact template shows (sanitized, ≤ 300 characters each);
- **inject**: the CAS field set from the read's row version (`body.expectedRowVersion`, `query.expectedRowVersion` or `body.expectedVersion`; server-authoritative, overrides any model value; the schema minimum is the placeholder before the read);
- **validateDefinition**: `body.definition` for policy writes that carry a definition (validated through `POST /policies/validate` before the proposal).

| Write (operation)                                   | Risk   | Precondition read (`params`)                                                    | State fields                          | CAS injected                         |
| --------------------------------------------------- | ------ | ------------------------------------------------------------------------------- | ------------------------------------- | ------------------------------------ |
| `policy_management_create`                          | low    | none (definition validated)                                                     | —                                     | —                                    |
| `policy_management_update`                          | low    | `policy_management_get {policyId}`                                              | rowVersion, name, description, status | body `expectedRowVersion`            |
| `policy_management_enable`, `_disable`, `_activate` | medium | `policy_management_get {policyId}`                                              | rowVersion, status, activeVersionNo   | body `expectedRowVersion`            |
| `policy_management_remove`                          | high   | `policy_management_get {policyId}`                                              | rowVersion, status                    | query `expectedRowVersion`           |
| `policy_management_create_draft`                    | low    | `policy_management_get {policyId}` (definition validated when given)            | rowVersion, status, latestVersionNo   | —                                    |
| `policy_management_update_draft`                    | medium | `policy_management_get_version {policyId, versionNo}` (validated)               | rowVersion, status                    | body `expectedRowVersion`            |
| `policy_management_publish`                         | medium | `policy_management_get_version {policyId, versionNo}`                           | rowVersion, status                    | body `expectedRowVersion`            |
| `policy_management_delete_draft`                    | high   | `policy_management_get_version {policyId, versionNo}`                           | rowVersion, status                    | query `expectedRowVersion`           |
| `policy_settings_put`                               | high   | `policy_settings_get`                                                           | rowVersion, settingsSha256            | body `expectedRowVersion` (min 0)    |
| `quarantine_entries_release`, `_reject`             | medium | `quarantine_entries_detail {entryId}`                                           | rowVersion, state                     | body `expectedRowVersion`            |
| `quarantine_entries_delete`                         | high   | `quarantine_entries_detail {entryId}`                                           | rowVersion, state                     | body `expectedRowVersion`            |
| `quarantine_entries_request_release`                | medium | `quarantine_entries_detail {entryId}`                                           | rowVersion, state                     | —                                    |
| `quarantine_self_release`                           | medium | `quarantine_self_detail {entryId}`                                              | rowVersion, state                     | body `expectedRowVersion`            |
| `quarantine_self_request_release`                   | medium | `quarantine_self_detail {entryId}`                                              | rowVersion, state                     | —                                    |
| `quarantine_self_put_preferences`                   | low    | `quarantine_self_preferences`                                                   | digestOptOut                          | —                                    |
| `quarantine_tools_put_settings`                     | medium | `quarantine_tools_get_settings`                                                 | rowVersion                            | body `expectedRowVersion` (min 0)    |
| `quarantine_entries_manual`                         | low    | `messages_detail {messageId: body.messageId}`                                   | status, version, lifecycleRound       | —                                    |
| `quarantine_approvals_approve`, `_deny`, `_cancel`  | medium | `quarantine_approvals_get {approvalId}`                                         | status                                | —                                    |
| `quarantine_tools_bulk`                             | high   | each of the first 25 `body.ids`: entry detail, or approval for `approve`/`deny` | state / status, rowVersion per item   | — (the route revalidates every item) |
| `message_lifecycle_release`, `_rescan`              | medium | `messages_detail {messageId}`                                                   | status, version, lifecycleRound       | body `expectedVersion` (min 0)       |
| `recipient_suppressions_create`                     | low    | none                                                                            | —                                     | —                                    |
| `recipient_suppressions_delete`                     | high   | `recipient_suppressions_get {suppressionId}`                                    | active, expiresAt, reason             | —                                    |
| `saved_views_create`                                | low    | none                                                                            | —                                     | —                                    |
| `saved_views_update`                                | medium | `saved_views_get {viewId}`                                                      | rowVersion, name                      | body `expectedRowVersion`            |
| `saved_views_remove`                                | low    | `saved_views_get {viewId}`                                                      | rowVersion                            | —                                    |

## Impact templates (AI-2)

`IMPACT_TEMPLATES` holds one pure template per enabled write (31), keyed by operation id; `impactOf(operationId, { args, snapshot, validation })` builds the `assistant-confirmation/1` summary the card shows: title, one action sentence, target rows, field changes (before → after from the precondition snapshot), the policy rule summary (rule by rule: `when` flattened to a readable string ≤ 300 characters, actions with their parameters), impact lines, warnings, `reversible`, the portal route and the request (method and path, shown under "Technical details"). Rules (test-enforced by fixture snapshots per operation): `medium` has at least one impact line; `high` has impact lines and a warning (and the card asks for re-authentication); values from mail (subjects, senders, recipients, file names) are `untrusted: true` and sanitized; caps 20 targets, 40 changes, 50 rules, 10 impact lines, 5 warnings, 16 KiB. A generic fallback exists but no enabled tool may use it (registry check). The summary is never model text.

## testedBy rule

An enabled write needs a named integration suite that proposes it through a turn, confirms it and asserts the api's state change and audit: policy writes → `apps/api/integration/assistant-writes-policies.test.ts`; quarantine, message, recipient-suppression and saved-view writes → `apps/api/integration/assistant-writes-mail-ops.test.ts`. The tool sweep (`assistant-tools.test.ts`) additionally proposes every enabled write without confirming it and asserts that no request reaches the write route ("no write without confirmation").

## Current counts

From the generated matrix (registry version `0e75a5af832f11ce`, program phase AI-2):

| Measure                     | Count                                                                                                                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenAPI operations          | 421 (403 before AI-1, + 15 assistant routes of AI-1, + 3 confirmation routes of AI-2)                                                                                                    |
| Chat tools                  | 348, of which 209 enabled (178 reads, 31 writes)                                                                                                                                         |
| Not applicable              | 73 (18 assistant routes, 20 credential/session ceremony, 2 identity/override, 9 secret-returning, 12 content/preview/download/reveal, 2 consent, 1 file export, 9 critical)              |
| By status                   | `IMPLEMENTED` 209, `PARTIALLY_IMPLEMENTED` 0, `MISSING` 139 (4 side-effect-free reads, 135 writes), `NOT_APPLICABLE` 73                                                                  |
| By phase                    | AI-1 174, AI-2 35, AI-3 47, AI-4 66, AI-5 26                                                                                                                                             |
| By risk (tools)             | `read` 175, `read_audited` 7, `low` 50, `medium` 56, `high` 60 (enabled writes: low 8, medium 17, high 6)                                                                                |
| Confirmation specs          | 31 (one per enabled write); impact templates 31                                                                                                                                          |
| Platform-only enabled tools | 7 (`organization_deletion_get`, `attachment_rescans_list`, `attachment_rescans_get`, `platform_audit_logs_search`, `dead_letters_stats`, `threat_hashes_list`, `threat_indicators_list`) |

The four `MISSING` reads are side-effect-free `POST`s (risk dry run, DLP pattern test, webhook test, mail-flow preview), planned with their module's write phase.
