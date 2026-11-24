# @email-gateway/assistant

Pure package of the AI chat management assistant (step AI-1, design
[`docs/plan/steps/28-ai-chat-management.md`](../../docs/plan/steps/28-ai-chat-management.md), ADR-0091/0092). It holds no
business logic and touches no database: the api's `assistant` module (the only dependent, enforced by a test) runs turns
and executes tools through its own HTTP pipeline.

| Area      | Files                                                                                                             | What                                                                                                                                                                                                                                                                                                                                                              |
| --------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Providers | `src/providers/*`                                                                                                 | `LlmProvider` (D6): Anthropic (`@anthropic-ai/sdk` 1.1.0, streaming, strict meta tools, server-side refusal fallback, preserved thinking), OpenAI and Azure OpenAI (plain HTTPS, bounded SSE, zod), the deterministic `FakeProvider` (refused in production), factory, retry, breaker, prices                                                                     |
| Prompt    | `prompts/assistant-system-4.md`, `src/prompt/system.ts`                                                           | `assistant-system/4` (step AI-2: writes are proposals confirmed in a card; step AI-3: rule 12, no self-service of authority and no credentials in chat; step AI-R: rule 13, reports through `report_generate` / `report_send_email`; `assistant-system-1.md` to `-3.md` are kept for stored turns): prompt text, catalogue index, then the volatile context block |
| Confirm   | `src/confirmations/*`                                                                                             | Step AI-2 (design 29 D3–D6): canonical JSON, action/state digests and the single-use token, the confirmation spec of every enabled write, the server-authored impact summaries (`assistant-confirmation/1`) and the action-updates block; step AI-3 (design 30 D3–D7): proposal guards, risk escalation, selected-item preconditions                              |
| Context   | `src/context/window.ts`                                                                                           | Token estimate (chars / 3.5), segment window, deterministic recap (D7)                                                                                                                                                                                                                                                                                            |
| Results   | `src/results/*`                                                                                                   | Sanitizer, minimizer (`assistant-tool-result/1`, refs, `untrusted_text`), cards (`assistant-card/1`), stream events (`assistant-stream/1`)                                                                                                                                                                                                                        |
| Registry  | `src/registry/manifest.ts`, `operations.generated.ts`, `native.ts`, `registry.ts`, `scripts/generate-registry.ts` | Classification rules and overrides, the generated tool records, the native tools of step AI-R, `ALL_TOOLS`, `enabledTools`, `renderCatalogueIndex`, `describeTool`, `compileValidator` (Ajv 8 strict)                                                                                                                                                             |
| Reports   | `src/reports/*`                                                                                                   | Step AI-R (design [31](../../docs/plan/steps/31-ai-chat-reports.md) D2–D5, ADR-0095): the source plan and response parsers, `buildReportModel`, static SVG charts, the inert HTML renderer (`assistant-report/1`) and the recipient rule                                                                                                                          |

## Registry

`docs/api/openapi.json` + the manifest + the portal's operation usage produce
`src/registry/operations.generated.ts` and [`docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md`](../../docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md):

```sh
pnpm --filter @email-gateway/assistant registry:generate   # after an API or manifest change
pnpm --filter @email-gateway/assistant registry:check      # part of `test`; fails when stale or unclassified
```

A step that adds or changes API operations classifies them in `src/registry/manifest.ts` (a module needs a planned
phase in `MODULE_WRITE_PHASE`; mail-derived or attacker-influenced typed string fields go in `untrustedFields`; free-form objects, maps and untyped values are added by the generator) and regenerates.

## Program phase and confirmations (steps AI-2, AI-3)

`ASSISTANT_PROGRAM_PHASE` is `AI-R` (which adds only the native tools below): reads of every phase up to AI-3 and the 78 OpenAPI writes of AI-2 (policies, quarantine,
mail operations) and AI-3 (identity and tenant administration, design
[`30-ai-chat-identity-tenant-admin.md`](../../docs/plan/steps/30-ai-chat-identity-tenant-admin.md)) are enabled. A write is
enabled only with a `testedBy` integration suite, a confirmation spec (`src/confirmations/specs.ts`) and an impact
template (`src/confirmations/impact.ts`); the registry check enforces it. AI-3 adds three spec features, all pure
functions the api's executor, proposer and confirm route call:

- **Proposal guards** (`guards.ts`, `guardRefusal(spec, { args, principalUserPublicId, read }, phase)`): `not_self_user`
  (no change of the caller's own account, roles, status, MFA or sessions; case-insensitive UUID compare),
  `deny_values` (the assistant cannot change its own `ai_assistant` feature) and `deny_permission_change` (no role may
  gain or lose `assistant:configure`). `before_read` guards run before any request; `after_read` ones on the
  precondition target. Refusals carry fixed `GUARD_MESSAGES` (never argument values); the executor records them as
  decision `denied_guard`.
- **Conditional risk escalation** (`escalation.ts`, `effectiveRisk(tool, spec, finalArgs)`): the registry risk raised
  by the spec's `escalate` rules (a webhook URL, SMTP networks or TLS, a user's email, an initial administrator, a plan
  change, turning MFA off, the notification email) with their fixed warnings, which `impactOf` appends
  (`ImpactInput.escalationWarnings`). The stored confirmation risk is the effective one.
- **Selected-item preconditions** (`SinglePrecondition.select`, `selectTarget` / `targetOf`): the target is one item
  of a list read (a session, a feature, a limit, a scan engine); `stateDigest`, `rowVersionOf` and `buildSnapshot`
  apply to `targetOf(...)`. A missing required item is treated like a `404` read; a missing optional item is `{}`.

The registry check also refuses an enabled write whose input schema has a credential-pattern key (`isCredentialKey`;
named exceptions in `CREDENTIAL_KEY_EXCEPTIONS`: role keys) and an access override other than `'write'`.

## Reports and native tools (step AI-R)

Design [`31-ai-chat-reports.md`](../../docs/plan/steps/31-ai-chat-reports.md) (I15–I17, D1–D5, D10), ADR-0095.
`ASSISTANT_PROGRAM_PHASE` is `AI-R` (`PROGRAM_PHASES` = AI-1, AI-2, AI-3, AI-R, AI-4, AI-5, AI-6); AI-R adds no
OpenAPI tool.

- **Native tools** (`src/registry/native.ts`, `NATIVE_TOOLS`): `report_generate` (`AssistantNative_reportGenerate`,
  read, `read_audited`) and `report_send_email` (`AssistantNative_reportSendEmail`, write, `medium`,
  `confirm+impact`), both `report:read`. They are hand-written registry records with `native: true` and a
  `native:<name>` path (never an OpenAPI operation, never the loopback). `ALL_TOOLS = [...OPERATION_TOOLS,
...NATIVE_TOOLS]` backs `findTool`, `enabledTools`, the catalogue index and `describeTool`; the generator lists
  them in the matrix section "Native assistant tools" and hashes them into `REGISTRY_VERSION`. The registry check
  enforces unique names, `^AssistantNative_[A-Za-z]+$` ids absent from OpenAPI, `native:` paths, strict input
  schemas, `testedBy`, no credential-pattern key and a `native` confirmation spec with an impact template for every
  enabled native write.
- **Renderer** (`src/reports/*`, pure and deterministic): `REPORT_SOURCES` / `REPORT_SOURCE_DEFS` (per section the
  source tools, their arguments and zod parsers of the fields used), `resolveReportWindow` (range or explicit
  window, hourly up to 48 h, the ATO range covering the window), `buildReportModel(results, { window, generatedAt,
organizationName, sections })` (cards, 18 charts, tables, omitted sections with reasons, ≤ 8 summary figures) and
  `renderReportHtml(model, { maxBytes })` (one self-contained document: constant CSP meta and `<style>`, static SVG,
  data appendix, no script, link or external resource; every data string sanitized, capped and escaped; size cap
  fallback to 50 appendix rows per table, else `ReportTooLargeError`).
- **Recipient rule** (`src/reports/recipients.ts`): `normalizeRecipient` (one plain ASCII address) and
  `classifyRecipient(address, directory)` → `self` | `member` | `domain` | `null` (exact domain match); the api
  supplies the directory and evaluates it at proposal and confirm.
- **Confirmation and results**: the `report_send_email` spec (`native: 'report_send_email'`, no precondition read),
  its impact template (`ImpactInput.native` snapshot: report, recipient, remaining limits), `reportStateDigest`, the
  executed action-update line naming the queued recipient, the card kind `report` (`reportCard`) and the
  `report_generate` envelope (`reportEnvelope`, `reportRefs`). The fake provider has the report demo intents.

## Meta tools

The model sees two strict tools: `describe_tool { name }` and `call_tool { name, arguments }`. Strict tool use requires
fully declared objects, so `arguments` is a JSON object serialized to a string; `parseMetaToolInput` parses and checks
it before the executor validates it against the operation's input schema.

## Tests

`pnpm --filter @email-gateway/assistant test` (unit only). Providers run against injected `fetch` with synthetic
recorded fixtures; no test reaches an LLM API or the internet, and no API key is used anywhere. The report suites
(`src/reports/*.test.ts`, synthetic fixtures in `fixtures.test-support.ts`) include a byte-stable snapshot of a full
report, a `parse5` allow-list walk of every fixture report and a `fast-check` property test with hostile data strings.
