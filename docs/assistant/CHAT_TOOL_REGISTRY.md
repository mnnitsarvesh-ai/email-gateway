# Chat tool registry

The registry is the list of operations the assistant may call. It is **generated** from the committed OpenAPI snapshot (`docs/api/openapi.json`) plus a small hand-written manifest, so a tool is always exactly one existing `/api/v1` operation with that operation's own permission, idempotency, rate class and cursor metadata. Design: [D3, D4](../plan/steps/28-ai-chat-management.md#d3-tool-registry-bound-to-openapi-adr-0091), [§4.4](../plan/steps/28-ai-chat-management.md#44-risk-and-confirmation-rules-the-generators-rules-overrides-in-the-manifest); [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md); record format in [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1).

## Files

| File                                                       | Role                                                                                                                                                                                                                                                                                                  |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/assistant/src/registry/manifest.ts`              | Hand-written: the program phase (`ASSISTANT_PROGRAM_PHASE = 'AI-1'`), the classification rules (not-applicable tags and reasons, critical operations, risk verbs) and per-operation overrides (risk, phase, title, display hints, `untrustedFields`, portal route, bindings, limitations, `testedBy`) |
| `packages/assistant/scripts/generate-registry.ts`          | The generator (run with `tsx`)                                                                                                                                                                                                                                                                        |
| `packages/assistant/src/registry/build.ts`                 | Classification and schema normalization used by the generator and the tests                                                                                                                                                                                                                           |
| `packages/assistant/src/registry/operations.generated.ts`  | Generated: one `OperationTool` record per classified operation and `REGISTRY_VERSION`                                                                                                                                                                                                                 |
| `docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md`           | Generated: the UI-to-chat capability matrix (every operation, its portal pages, tool, permission, risk, confirmation, status, phase and test coverage)                                                                                                                                                |
| `packages/assistant/src/registry/registry.ts`, `render.ts` | Runtime: lookup by name, permission pre-filter (`enabledTools`), the catalogue index of the system prompt, `describe_tool`                                                                                                                                                                            |

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

The confirmation itself is specified in [ADR-0093](../architecture/adr/0093-assistant-action-confirmation.md) and built in AI-2; in AI-1 no write tool is enabled.

**Enabled** = not `not_applicable`, `phase` ≤ the program phase, and `access = read` (writes need the confirmation manager of AI-2 and a `testedBy` suite). **Status** in the matrix: `IMPLEMENTED` (enabled and covered by a named suite: every enabled read is covered by the tool sweep in `apps/api/integration/assistant-tools.test.ts`), `PARTIALLY_IMPLEMENTED` (enabled with `limitations`), `MISSING` (planned for the phase shown), `NOT_APPLICABLE` (with the reason).

## Checks (test-enforced)

`packages/assistant/src/registry/registry.test.ts` and `registry:check` fail the build when:

- either generated file is stale, or `REGISTRY_VERSION` is not the content hash;
- an OpenAPI operation is not classified exactly once (**completeness**: a new endpoint of any later step fails until it is classified);
- a `requirement` differs from the operation's `x-eg-permissions`; an `x-eg-returns-secret` operation or an `auth`/`mfa`/`sessions`/`meta`/`assistant` operation is a tool (**consistency**);
- a write is enabled in AI-1, an enabled tool is beyond the program phase, or an enabled write lacks `testedBy`;
- a name is invalid, duplicated or not derived from the operation id;
- an enabled tool has no portal route, or an override, display hint or `untrustedFields` path names something that does not exist in the operation or its success (200/201) response schema;
- a free-form response path of a tool (object without declared properties, map, untyped value) is not covered by its `untrustedFields` (the generator adds them by default: `freeFormResponsePaths` in `src/registry/build.ts`);
- an input schema does not compile in Ajv strict mode.

`packages/assistant/src/dependency-boundary.test.ts` checks that no app other than the api depends on `@email-gateway/assistant` (the portal imports types only).

## How later steps add tools

Every step that adds or changes API operations (ATP-1 … ATP-9, 8.3, …) also:

1. classifies each new operation in the manifest (tool with phase, or `not_applicable` with a reason), adds display hints (`columns`, `resourceType`, link field) and `untrustedFields` for mail-derived or attacker-influenced typed strings (free-form objects are untrusted by default);
2. regenerates the OpenAPI snapshot and the registry, and commits both generated files;
3. relies on the tool sweep for new reads (it iterates every enabled read) and, once AI-2 exists, adds a `testedBy` suite for each enabled write.

The registry check fails the build otherwise, which is how "each later step adds its own chat tools" is enforced.

## Current counts

From the generated matrix (registry version `30777563d395518a`, program phase AI-1):

| Measure                     | Count                                                                                                                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenAPI operations          | 418 (403 before AI-1 + the 15 assistant routes)                                                                                                                                          |
| Chat tools                  | 348, of which 174 enabled                                                                                                                                                                |
| Not applicable              | 70 (15 assistant routes, 20 credential/session ceremony, 2 identity/override, 9 secret-returning, 12 content/preview/download/reveal, 2 consent, 1 file export, 9 critical)              |
| By status                   | `IMPLEMENTED` 174, `PARTIALLY_IMPLEMENTED` 0, `MISSING` 174 (8 side-effect-free reads, 166 writes), `NOT_APPLICABLE` 70                                                                  |
| By phase                    | AI-1 174, AI-2 35, AI-3 47, AI-4 66, AI-5 26                                                                                                                                             |
| By risk (tools)             | `read` 175, `read_audited` 7, `low` 50, `medium` 56, `high` 60                                                                                                                           |
| Platform-only enabled tools | 7 (`organization_deletion_get`, `attachment_rescans_list`, `attachment_rescans_get`, `platform_audit_logs_search`, `dead_letters_stats`, `threat_hashes_list`, `threat_indicators_list`) |

The eight `MISSING` reads are side-effect-free `POST`s (policy validate, test and dry runs, risk dry run, DLP pattern test, webhook test, mail-flow preview), planned with their module's write phase.
