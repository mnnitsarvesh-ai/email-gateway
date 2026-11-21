# @email-gateway/assistant

Pure package of the AI chat management assistant (step AI-1, design
[`docs/plan/steps/28-ai-chat-management.md`](../../docs/plan/steps/28-ai-chat-management.md), ADR-0091/0092). It holds no
business logic and touches no database: the api's `assistant` module (the only dependent, enforced by a test) runs turns
and executes tools through its own HTTP pipeline.

| Area      | Files                                                                                                | What                                                                                                                                                                                                                                                                                          |
| --------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Providers | `src/providers/*`                                                                                    | `LlmProvider` (D6): Anthropic (`@anthropic-ai/sdk` 1.1.0, streaming, strict meta tools, server-side refusal fallback, preserved thinking), OpenAI and Azure OpenAI (plain HTTPS, bounded SSE, zod), the deterministic `FakeProvider` (refused in production), factory, retry, breaker, prices |
| Prompt    | `prompts/assistant-system-2.md`, `src/prompt/system.ts`                                              | `assistant-system/2` (step AI-2: writes are proposals confirmed in a card; `assistant-system-1.md` is kept for stored turns): prompt text, catalogue index, then the volatile context block                                                                                                   |
| Confirm   | `src/confirmations/*`                                                                                | Step AI-2 (design 29 D3–D6): canonical JSON, action/state digests and the single-use token, the confirmation spec of every enabled write, the server-authored impact summaries (`assistant-confirmation/1`) and the action-updates block                                                      |
| Context   | `src/context/window.ts`                                                                              | Token estimate (chars / 3.5), segment window, deterministic recap (D7)                                                                                                                                                                                                                        |
| Results   | `src/results/*`                                                                                      | Sanitizer, minimizer (`assistant-tool-result/1`, refs, `untrusted_text`), cards (`assistant-card/1`), stream events (`assistant-stream/1`)                                                                                                                                                    |
| Registry  | `src/registry/manifest.ts`, `operations.generated.ts`, `registry.ts`, `scripts/generate-registry.ts` | Classification rules and overrides, the generated tool records, `enabledTools`, `renderCatalogueIndex`, `describeTool`, `compileValidator` (Ajv 8 strict)                                                                                                                                     |

## Registry

`docs/api/openapi.json` + the manifest + the portal's operation usage produce
`src/registry/operations.generated.ts` and [`docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md`](../../docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md):

```sh
pnpm --filter @email-gateway/assistant registry:generate   # after an API or manifest change
pnpm --filter @email-gateway/assistant registry:check      # part of `test`; fails when stale or unclassified
```

A step that adds or changes API operations classifies them in `src/registry/manifest.ts` (a module needs a planned
phase in `MODULE_WRITE_PHASE`; mail-derived or attacker-influenced typed string fields go in `untrustedFields`; free-form objects, maps and untyped values are added by the generator) and regenerates.

## Meta tools

The model sees two strict tools: `describe_tool { name }` and `call_tool { name, arguments }`. Strict tool use requires
fully declared objects, so `arguments` is a JSON object serialized to a string; `parseMetaToolInput` parses and checks
it before the executor validates it against the operation's input schema.

## Tests

`pnpm --filter @email-gateway/assistant test` (unit only). Providers run against injected `fetch` with synthetic
recorded fixtures; no test reaches an LLM API or the internet, and no API key is used anywhere.
