# @email-gateway/assistant

Pure package of the AI chat management assistant (step AI-1, design
[`docs/plan/steps/28-ai-chat-management.md`](../../docs/plan/steps/28-ai-chat-management.md), ADR-0091/0092). It holds no
business logic and touches no database: the api's `assistant` module (the only dependent, enforced by a test) runs turns
and executes tools through its own HTTP pipeline.

| Area      | Files                                                                                                | What                                                                                                                                                                                                                                                                                                                                 |
| --------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Providers | `src/providers/*`                                                                                    | `LlmProvider` (D6): Anthropic (`@anthropic-ai/sdk` 1.1.0, streaming, strict meta tools, server-side refusal fallback, preserved thinking), OpenAI and Azure OpenAI (plain HTTPS, bounded SSE, zod), the deterministic `FakeProvider` (refused in production), factory, retry, breaker, prices                                        |
| Prompt    | `prompts/assistant-system-3.md`, `src/prompt/system.ts`                                              | `assistant-system/3` (step AI-2: writes are proposals confirmed in a card; step AI-3: rule 12, no self-service of authority and no credentials in chat; `assistant-system-1.md` and `-2.md` are kept for stored turns): prompt text, catalogue index, then the volatile context block                                                |
| Confirm   | `src/confirmations/*`                                                                                | Step AI-2 (design 29 D3–D6): canonical JSON, action/state digests and the single-use token, the confirmation spec of every enabled write, the server-authored impact summaries (`assistant-confirmation/1`) and the action-updates block; step AI-3 (design 30 D3–D7): proposal guards, risk escalation, selected-item preconditions |
| Context   | `src/context/window.ts`                                                                              | Token estimate (chars / 3.5), segment window, deterministic recap (D7)                                                                                                                                                                                                                                                               |
| Results   | `src/results/*`                                                                                      | Sanitizer, minimizer (`assistant-tool-result/1`, refs, `untrusted_text`), cards (`assistant-card/1`), stream events (`assistant-stream/1`)                                                                                                                                                                                           |
| Registry  | `src/registry/manifest.ts`, `operations.generated.ts`, `registry.ts`, `scripts/generate-registry.ts` | Classification rules and overrides, the generated tool records, `enabledTools`, `renderCatalogueIndex`, `describeTool`, `compileValidator` (Ajv 8 strict)                                                                                                                                                                            |

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

`ASSISTANT_PROGRAM_PHASE` is `AI-3`: reads of every phase up to AI-3 and the 78 writes of AI-2 (policies, quarantine,
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

## Meta tools

The model sees two strict tools: `describe_tool { name }` and `call_tool { name, arguments }`. Strict tool use requires
fully declared objects, so `arguments` is a JSON object serialized to a string; `parseMetaToolInput` parses and checks
it before the executor validates it against the operation's input schema.

## Tests

`pnpm --filter @email-gateway/assistant test` (unit only). Providers run against injected `fetch` with synthetic
recorded fixtures; no test reaches an LLM API or the internet, and no API key is used anywhere.
