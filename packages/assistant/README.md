# @email-gateway/assistant

Pure package of the AI chat management assistant (step AI-1, design
[`docs/plan/steps/28-ai-chat-management.md`](../../docs/plan/steps/28-ai-chat-management.md), ADR-0091/0092). It holds no
business logic and touches no database: the api's `assistant` module (the only dependent, enforced by a test) runs turns
and executes tools through its own HTTP pipeline.

| Area      | Files                                                                                                             | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Providers | `src/providers/*`                                                                                                 | `LlmProvider` (D6): Anthropic (`@anthropic-ai/sdk` 1.1.0, streaming, strict meta tools, server-side refusal fallback, preserved thinking), OpenAI and Azure OpenAI (plain HTTPS, bounded SSE, zod), the deterministic `FakeProvider` (refused in production), factory, retry, breaker, prices                                                                                                                                                                             |
| Prompt    | `prompts/assistant-system-5.md`, `src/prompt/system.ts`                                                           | `assistant-system/5` (step AI-2: writes are proposals confirmed in a card; step AI-3: rule 12, no self-service of authority and no credentials in chat; step AI-R: rule 13, reports through `report_generate` / `report_send_email`; step AI-4: rule 14, ATO four eyes, re-authentication for weakening detection, platform-only operations; `assistant-system-1.md` to `-4.md` are kept for stored turns): prompt text, catalogue index, then the volatile context block |
| Confirm   | `src/confirmations/*`                                                                                             | Step AI-2 (design 29 D3–D6): canonical JSON, action/state digests and the single-use token, the confirmation spec of every enabled write, the server-authored impact summaries (`assistant-confirmation/1`) and the action-updates block; step AI-3 (design 30 D3–D7): proposal guards, risk escalation, selected-item preconditions; step AI-4 (design 32 D3–D6, D10): four-eyes guards, new CAS fields, queued-work lines                                               |
| Context   | `src/context/window.ts`                                                                                           | Token estimate (chars / 3.5), segment window, deterministic recap (D7)                                                                                                                                                                                                                                                                                                                                                                                                    |
| Results   | `src/results/*`                                                                                                   | Sanitizer, minimizer (`assistant-tool-result/1`, refs, `untrusted_text`), cards (`assistant-card/1`), stream events (`assistant-stream/1`)                                                                                                                                                                                                                                                                                                                                |
| Registry  | `src/registry/manifest.ts`, `operations.generated.ts`, `native.ts`, `registry.ts`, `scripts/generate-registry.ts` | Classification rules and overrides, the generated tool records, the native tools of step AI-R, `ALL_TOOLS`, `enabledTools`, `renderCatalogueIndex`, `describeTool`, `compileValidator` (Ajv 8 strict)                                                                                                                                                                                                                                                                     |
| Reports   | `src/reports/*`                                                                                                   | Step AI-R (design [31](../../docs/plan/steps/31-ai-chat-reports.md) D2–D5, ADR-0095): the source plan and response parsers, `buildReportModel`, static SVG charts, the inert HTML renderer (`assistant-report/1`) and the recipient rule                                                                                                                                                                                                                                  |

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

At AI-R (which added only the native tools below) reads of every phase up to AI-3 and the 78 OpenAPI writes of AI-2 (policies, quarantine,
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
named exceptions in `CREDENTIAL_KEY_EXCEPTIONS`: role keys and, step AI-4, the `require_password_reset` action
setting and BEC/incident reason codes) and an access override other than `'write'`.

## Security operations (step AI-4)

Design [`32-ai-chat-security-operations.md`](../../docs/plan/steps/32-ai-chat-security-operations.md) (I18–I21,
D1–D12). `ASSISTANT_PROGRAM_PHASE` is `AI-4`: 70 more tools are enabled (64 writes of DLP, BEC, risk scoring, incidents,
ATO triage, responses, settings and IdP integrations, the 8 platform operations; the reads `dlp_patterns_test`,
`risk_dry_run_dry_run` and the four single reads `bec_trusted_senders_get`, `bec_feedback_get_suppression`,
`dlp_exceptions_get`, `threat_indicators_get`). Their suites are `ATO_WRITES_TESTED_BY`,
`DETECTION_WRITES_TESTED_BY` and `PLATFORM_OPS_WRITES_TESTED_BY` (`AI4_WRITES_TESTED_BY`).

- **Four eyes (I18)**: the after-read guard kinds `not_self_field` (a user id of the target is not the caller, optionally
  gated by `when`) and `require_read_value` (a target field has the required value, fail closed) refuse an
  `ato_responses_approve` / `_reject` proposal by the requester, by the creator of the requesting API key or without MFA
  (`canDecide` false) with the message `ato_four_eyes`. The api's `ato_self_approval` stays the authority.
- **Weakening detection is high (I20)**: risk overrides for trust and exception creates, ATO settings and IdP settings;
  the escalations of D4 (`AI4_ESCALATION_WARNINGS`).
- **CAS fields**: `CasInjection.field` also takes `version`, `rowVersion` and `expectedProfileVersion`.
- **Redacted read inputs (D9)**: `OperationTool.redactParams` (`dlp_patterns_test`: `body.sample`, `body.pattern`);
  `redactToolArguments(tool, args)` gives the copy with `[redacted]` the api stores; only reads may have them.
- **Outcomes (D10)**: `QUEUED_202_TOOLS` (queued work answers "it was queued (HTTP 202)"); `ato_responses_request`
  answers "the response was requested (HTTP 201) …".
- **Fake provider**: plans "approve the pending response", "open an incident for the account <address>" and
  `add dlp dictionary "<name>" with terms …`.

## Reports and native tools (step AI-R)

Design [`31-ai-chat-reports.md`](../../docs/plan/steps/31-ai-chat-reports.md) (I15–I17, D1–D5, D10), ADR-0095.
`PROGRAM_PHASES` = AI-1, AI-2, AI-3, AI-R, AI-4, AI-5, AI-6; AI-R adds no OpenAPI tool.

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
