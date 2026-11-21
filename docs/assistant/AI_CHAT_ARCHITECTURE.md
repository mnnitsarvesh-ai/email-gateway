# AI chat architecture

How the AI assistant is built (steps AI-1 and AI-2). Normative sources: [design D1–D14](../plan/steps/28-ai-chat-management.md#2-decisions), [AI-2 design D1–D11](../plan/steps/29-ai-chat-confirmations-mail-writes.md#2-decisions), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md), [ADR-0092](../architecture/adr/0092-llm-provider-abstraction-and-data-handling.md), [ADR-0094](../architecture/adr/0094-assistant-conversation-storage-retention-audit.md), [ADR-0093](../architecture/adr/0093-assistant-action-confirmation.md) (amended in AI-2), [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1) and [§35.1](../architecture/contracts.md#351-confirmations-step-ai-2). This page summarizes them; where they differ, they win.

## Principles (design §2.0)

| #   | Invariant                                                                                                                                                                                              |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| I1  | **No parallel business logic.** A tool is an existing `/api/v1` operation. The assistant never imports another module's services or repositories and runs no SQL beyond its own `ai_chat_*` tables.    |
| I2  | **The user's own authority, live.** Tools run only inside a live request of the user, with that request's bearer token. Nothing runs in the background on a user's behalf; no credential is stored.    |
| I3  | **The model is an untrusted client.** Tool names, arguments, ids and text from the model are validated like internet input; the model can never confirm, approve or change permissions.                |
| I4  | **Tenant from the principal** (`scopeFromPrincipal`), never from a tool argument; the api enforces it again on every call.                                                                             |
| I5  | **No message content to the model, none in MySQL.** No tool returns bodies or attachments; `ai_chat_*` stores user text, assistant text and masked metadata cards only, bounded and purged.            |
| I6  | **Every tool execution is recorded and audited**, allowed or denied.                                                                                                                                   |
| I7  | **Isolation from mail processing.** The assistant lives in the api only; no worker, smtp-adapter, policy-engine or RabbitMQ change.                                                                    |
| I8  | **Tests never reach an LLM or the internet** (deterministic fake provider, injected `fetch`).                                                                                                          |
| I9  | **No write without the user** (AI-2). A write runs only inside `POST /assistant/confirmations/{id}/confirm`, a live request of the same user and session family, carrying a token the model never saw. |
| I10 | **What the user confirms is what runs** (AI-2). The card is rendered from the stored, server-authored summary of the stored request; the confirm carries the card's digest; changed state refuses.     |
| I11 | **Existing controls stay the authority** (AI-2). The confirmed request passes the api's own pipeline (RBAC, MFA, tenant scope, rate limits, idempotency, CAS, approvals, audit).                       |

## Components

| Component                   | Where                                                                                                                                                                                                                            | Role                                                                                                                                                                                                                                                                                                                          |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chat panel and page         | `apps/admin-portal/src/features/assistant`                                                                                                                                                                                       | "Ask AI" header button (`Ctrl/Cmd+J`), right-side sheet (full screen below `md`), `/assistant` page with history, Settings → AI assistant tab; streams turns through the BFF; renders cards and a restricted Markdown subset (no raw HTML, internal links only); the confirmation card (`confirmation-card.tsx`, AI-2)        |
| BFF proxy                   | `apps/admin-portal/src/server/proxy.ts`                                                                                                                                                                                          | Session cookie → bearer, CSRF, client IP; passes `text/event-stream` through unbuffered (`cache-control: no-store, no-transform`, `x-accel-buffering: no`)                                                                                                                                                                    |
| Controllers (18 routes)     | `apps/api/src/modules/assistant/controllers`                                                                                                                                                                                     | Thin, `@UserOnly()`, tag `assistant` ([CHAT_API_DOCUMENTATION.md](CHAT_API_DOCUMENTATION.md))                                                                                                                                                                                                                                 |
| Turn engine                 | `services/turn-engine.service.ts`                                                                                                                                                                                                | Lock, budgets, context, model rounds, tool calls, persistence, SSE events, cancellation                                                                                                                                                                                                                                       |
| Tool executor               | `services/tool-executor.service.ts`                                                                                                                                                                                              | Registry lookup, permission pre-filter, bindings, refs, schema validation, loopback call, card + envelope, execution row + audit row; for an enabled write, hands over to the proposer instead of the loopback write                                                                                                          |
| Confirmations (AI-2)        | `services/confirmation-proposer.service.ts`, `confirmation.service.ts`, `confirmation-views.service.ts`, `repositories/confirmations.repository.ts`, `domain/confirmation-binding.ts`, `controllers/confirmations.controller.ts` | Proposal (pending cap, spec, definition validation, precondition read, CAS injection, summary, digest, token, rows), the confirm/cancel/get routes with their ordered checks, re-authentication, execution of the stored request, action updates for the next turn                                                            |
| Loopback client             | `services/loopback-client.ts`                                                                                                                                                                                                    | Sends the tool's HTTP request to the api itself with the caller's bearer                                                                                                                                                                                                                                                      |
| Availability, limits, usage | `services/assistant-availability.service.ts`, `assistant-limits.service.ts`, `assistant-usage.service.ts`                                                                                                                        | Switches (platform, feature, tenant), per-user turn window, concurrency, token budgets, usage rows                                                                                                                                                                                                                            |
| Settings, retention         | `services/assistant-settings.service.ts`, `assistant-retention.service.ts`                                                                                                                                                       | Tenant settings (CAS), content purge, metadata hard delete, stale-turn sweeper                                                                                                                                                                                                                                                |
| Provider service            | `services/assistant-provider.service.ts`                                                                                                                                                                                         | Builds the configured `LlmProvider`, retry policy, Redis-backed breaker, metrics                                                                                                                                                                                                                                              |
| `@email-gateway/assistant`  | `packages/assistant`                                                                                                                                                                                                             | Providers (Anthropic, OpenAI, Azure OpenAI, fake with multi-step plans), system prompt `assistant-system/2`, context window and recap, minimizer and sanitizer, card builder, stream contract, the generated tool registry and its generator, confirmations (canonical JSON, digest, specs, impact templates, action updates) |
| Tenant purge                | `apps/api/src/modules/tenant-data/assistant-tenant-data.repository.ts`                                                                                                                                                           | Organization deletion removes every `ai_chat_*` row                                                                                                                                                                                                                                                                           |
| Shared permission predicate | `apps/api/src/auth-contracts/authorization.ts`                                                                                                                                                                                   | `satisfiesRequirement`, used by both `PermissionsGuard` and the executor's pre-filter (one implementation)                                                                                                                                                                                                                    |

## Data flow

```mermaid
flowchart LR
  U["Browser: chat panel or /assistant"] -->|"POST /bff/api/v1/assistant/conversations/{id}/turns (SSE)"| BFF["Portal BFF (cookie → bearer, CSRF, client IP)"]
  BFF --> API["AssistantTurnsController (assistant:use, UserOnly, rate class expensive)"]
  API --> TE["Turn engine: lock, budgets, context, persistence"]
  TE <-->|"stream, describe_tool / call_tool"| LLM["LlmProvider: anthropic | openai | azure_openai | fake"]
  TE --> EX["Tool executor: registry, permission pre-filter, refs, schema"]
  EX -->|"loopback HTTP with the caller's bearer, x-correlation-id"| PIPE["api /api/v1 pipeline: AuthGuard → rate limit → PermissionsGuard → pipes → controller → service → audit"]
  PIPE --> DB[("MySQL writer / replica")]
  EX --> MIN["Minimizer: projection, refs, untrusted envelope"]
  MIN --> TE
  EX --> CARD["Result card (assistant-card/1)"]
  TE --> STORE[("ai_chat_* tables")]
  EX --> AUD["audit_logs: assistant.tool_executed / tool_denied"]
  TE -->|"assistant-stream/1 events"| U
```

One **turn** = one user message → up to `ASSISTANT_MAX_TOOL_ROUNDS` model calls → one assistant message:

1. Gates: platform switch, organization feature `ai_assistant`, tenant setting, permission `assistant:use`, per-user turn window, concurrency, tenant and platform token budgets, breaker (each with its coded error, [CHAT_API_DOCUMENTATION.md](CHAT_API_DOCUMENTATION.md#error-codes)).
2. A Redis lock per conversation (`as:turn:<id>`); `clientTurnId` makes a retried POST idempotent.
3. One writer transaction stores the running turn and the user message; the SSE headers and `turn.started` are flushed before the first model call.
4. The model gets the system prompt (versioned template + context block + catalogue index of the user's available tools) and the conversation's current segment; it may call `describe_tool` or `call_tool`.
5. Each `call_tool` goes through the executor (below); the model receives a minimized envelope, the browser a card.
6. A final transaction stores the assistant message, the provider transcript, token usage (`ai_chat_usage_daily`) and the turn status.

## Loopback execution (ADR-0091)

A tool is executed by sending **the same HTTP request the portal would send** to the api itself (`ASSISTANT_LOOPBACK_URL`, empty = `http://127.0.0.1:${HTTP_PORT}`), so the guards, rate limits, idempotency, masking, signed cursors, coded errors and audit of the operation apply unchanged. The request carries exactly: the turn request's `authorization` header, `x-correlation-id: <turn correlation id>.<execution seq>`, the end user's client IP through the trusted forwarder (`x-eg-client-ip` + `x-eg-forwarder-token` when `API_TRUSTED_FORWARDER_TOKEN` is set), `accept: application/json`, `user-agent: eg-assistant/1` and the informational `x-eg-assistant-execution`. From step AI-2, the precondition reads of a confirmation (GET only) also carry `x-eg-assistant-read-primary`: HMAC-SHA256 of `AUTH_TOKEN_PEPPER` (a server value, identical on every api replica, never from model output). `AssistantReadPrimaryMiddleware` removes the header and, only when it matches (constant time), runs the route inside `runReadsOnWriter`, so its `PrismaReadService` reads use the MySQL writer instead of a lagging replica; it grants nothing else (authentication, RBAC and tenant scope are unchanged). No header is ever set from model output; path parameters are validated and encoded; responses are capped at 1 MiB; each call times out after `ASSISTANT_TOOL_TIMEOUT_MS`. A `401` ends the turn (`assistant_session_expired`). The assistant's own routes are never tools.

Executor order per `call_tool` (each refusal is a recorded, audited execution): per-turn call cap → registry lookup → not applicable → not enabled → permission pre-filter → bindings (`self_organization`) → refs (`@r<seq>.<row>`) → JSON Schema validation (Ajv) → loopback → card and envelope; for an enabled write the loopback write is replaced by the proposal (below). The confirmed write's loopback request adds `idempotency-key` (the confirmation id, a server value) for operations with `required` or `legacy` idempotency. Up to four calls of one model response run in parallel.

## Confirmation flow (step AI-2, ADR-0093 amended)

A write tool never executes inside a turn. The model can only **propose**; the user decides in a confirmation card; the confirm request executes exactly the stored request through the same loopback.

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser (card)
  participant T as Turn engine + executor
  participant P as Confirmation proposer
  participant API as api /api/v1 pipeline (loopback, user's bearer)
  participant DB as MySQL (ai_chat_*)
  participant M as Model (provider)
  M->>T: call_tool policy_management_create {…}
  T->>T: budget, lookup, permission pre-filter, bindings, refs, Ajv (CAS placeholder)
  T->>P: enabled write → propose
  P->>DB: pending cap (≤ ASSISTANT_MAX_PENDING_CONFIRMATIONS)
  P->>API: POST /policies/validate (definitions) · GET precondition read
  API-->>P: valid / current state (rowVersion, state fields)
  P->>P: inject CAS, build request, impact summary, digest, token
  P->>DB: execution (pending_confirmation) + confirmation (pending, token hash) + audit
  T-->>B: tool.completed (pending_confirmation) + confirmation.required {confirmation, token}
  T-->>M: tool_result pending_confirmation (no token, no digest)
  B->>T: POST /assistant/confirmations/{id}/confirm {token, actionDigest, reauth?}
  T->>T: owner · session family · pending · expiry · token · digest · tool · availability · re-auth (high) · turn lock
  T->>DB: pending → executing (atomic)
  T->>API: precondition re-read (state digest must match)
  T->>API: stored request, Idempotency-Key = confirmation id, CAS from the snapshot
  API-->>T: 2xx / 202 / coded error (operation audit rows carry the correlation id)
  T->>DB: execution row + executed/failed + audit
  T-->>B: 200 {confirmation, execution}
  Note over T,M: next turn starts with "Action updates since your last message …" (server-authored)
```

- **Proposal** (inside the turn): nothing changes platform state but `ai_chat_*` and audit rows; the validate and read calls are side-effect free. A failed definition validation (`assistant_definition_invalid`, at most 20 violations) or a failed precondition read (its coded error) is an ordinary failed execution the model can explain or fix.
- **Confirm** (outside the turn, `POST /assistant/confirmations/{id}/confirm`): the checks run in a fixed order ([CHAT_API_DOCUMENTATION.md](CHAT_API_DOCUMENTATION.md#confirmations-step-ai-2)); the confirmed write is a new execution row (`parent_execution_id` = the proposal, `turn_id` NULL) under the conversation's turn lock, as "Load more".
- **Cancel** needs no token (works after a reload); **get** shows any own confirmation (never the token).
- **Outcome to the model:** at the start of the next turn, terminal confirmations not yet reported (≤ 20, oldest first) are rendered by `buildActionUpdates()` as a prefix of the new user entry and marked `reported_at`; they are never stored in `ai_chat_messages.content`.
- **Sweeps** (the retention job): `pending` past `expires_at` → `expired`; `executing` whose write started (`execution_started_at`) more than `ASSISTANT_TOOL_TIMEOUT_MS` + 60 s ago, or with no write started and `decided_at` older than 26 × `ASSISTANT_TOOL_TIMEOUT_MS` + 60 s (the precondition re-read: up to 25 sequential reads) → `failed` with `assistant_confirmation_outcome_unknown` (never re-executed); a confirm request still running then loses its write claim (`409`, nothing sent) or, if its write was already sent, replaces that outcome with the real one (audit metadata `reconciledFrom`).
- **Specs and summaries** come from `@email-gateway/assistant` (`src/confirmations`): one confirmation spec and one impact template per enabled write ([CHAT_TOOL_REGISTRY.md](CHAT_TOOL_REGISTRY.md#confirmation-specs-ai-2)).

## Provider abstraction (ADR-0092)

One interface, `LlmProvider.complete(request, signal, onDelta)` (`packages/assistant/src/providers/types.ts`), and four implementations:

| Provider       | Transport                                                                                                                                          | Notes                                                                                                                                                                       |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `anthropic`    | `@anthropic-ai/sdk` 1.1.0 (as the BEC layer), streaming, `cache_control` on the system block, `output_config.effort`, server-side refusal fallback | Default model `claude-opus-5-5`, effort `low`; no `thinking`, `temperature` or forced `tool_choice`; thinking blocks replayed unchanged; `maxRetries: 0` (own retry policy) |
| `openai`       | Plain HTTPS Chat Completions with `stream: true`, strict function tools, bounded SSE parser, zod-validated chunks                                  | `ASSISTANT_OPENAI_BASE_URL`                                                                                                                                                 |
| `azure_openai` | The same client against `{endpoint}/openai/deployments/{deployment}/chat/completions?api-version=…` with the `api-key` header                      | Region chosen by the operator                                                                                                                                               |
| `fake`         | In process, deterministic, no network                                                                                                              | Directives (`/tool`, `/describe`, `/text`), demo intents, templates, adversarial mode for tests; refused with `NODE_ENV=production`                                         |

Every provider sees exactly two meta tools, `describe_tool { name }` and `call_tool { name, arguments }`, not one tool per operation (token cost, provider limits). The catalogue index in the system prompt lists only the tools the user may call, one line each, in a fixed order (prompt caching). Retries: one retry on connection errors, `429` and `5xx` before any text was streamed. Breaker: `ASSISTANT_BREAKER_THRESHOLD` failures open it for `ASSISTANT_BREAKER_RESET_MS` across all api pods (`as:brk:<provider>`), then `503 assistant_provider_unavailable`. Costs: per-model prices in `prices.ts` or `ASSISTANT_MODEL_PRICES`; tokens are always recorded, cost is advisory (`null` when unknown). The model id reported by the provider is stored per turn.

## Context and segments (D7)

- **System prompt**: `packages/assistant/prompts/assistant-system-2.md` (`assistant-system/2` from AI-2: writes are proposals, never claim a change without an action update or result, never ask for a confirmation, password or code in chat, validate policy definitions first; turns keep their stored `prompt_version`) + a context block (organization name and id, user display name, roles, UTC time, the browser's time zone, registry version) + the catalogue index.
- **Transcript**: the provider-native transcripts of the previous turns of the current **segment**, replayed verbatim (append-only; required for preserved thinking), plus the new user message.
- **Window**: when system + segment exceed `ASSISTANT_CONTEXT_MAX_TOKENS`, a new segment starts with a deterministic recap (last user messages, tools used and the refs still valid). No model call is made for the recap and history inside a segment is never edited.
- **Refs**: results are numbered `r<seq>` (execution) and `r<seq>.<row>` (row) per conversation; the model can refer to "the second one" as `@r4.2`, which the server resolves to the stored public id of this conversation only.

## Results (D8, D9)

- **Card** (`assistant-card/1`) for the user: built from the real API response (table, key-value, series, message or error) with display hints and portal links; the UI renders numbers from the card, not from the model's text. "Load more" re-runs the stored cursor without a model call.
- **Envelope** (`assistant-tool-result/1`) for the model: at most `ASSISTANT_TOOL_RESULT_MAX_ROWS` rows and `ASSISTANT_TOOL_RESULT_MAX_BYTES` bytes, strings ≤ 300 characters, credential-like keys dropped, control/bidi/zero-width characters stripped, mail-derived and attacker-influenced values (manifest `untrustedFields`) plus every free-form response value (objects without declared properties, maps, untyped values: evidence, detail, metadata, criteria, params; added by the registry generator, `freeFormResponsePaths`) wrapped as `{ "untrusted_text": … }`, with a fixed note that data is never instructions.
- **Assistant text** is capped at 16 000 characters and rendered by an in-repo Markdown subset renderer (no HTML, links only to internal portal routes, images and external URLs as plain text).

## Isolation from the mail path (I7, D11)

The assistant is a module of the api process only. It publishes and consumes no RabbitMQ message (topology stays v14), adds nothing to workers, smtp-adapter or policy-engine, and its failures (provider outage, budget exhaustion, bugs) degrade only the chat: kill switches at platform (`ASSISTANT_ENABLED`), organization (feature `ai_assistant`) and tenant (settings) level, a per-process concurrency cap (`ASSISTANT_MAX_CONCURRENT_TURNS`), per-user turn limits and the api's existing rate limits on every loopback call. Production may later route `/api/v1/assistant` to a separate Deployment of the same api image with its own egress policy (AI-6); not done in AI-1.

## Configuration

Api only; section "AI assistant (step AI-1)" of `.env.example` (AI-2 appended `ASSISTANT_MAX_PENDING_CONFIRMATIONS`); validated at start-up by `assistantConfigShape` (`apps/api/src/config.ts`), errors name the key, never the value.

| Key                                                                                                          | Default                     | Meaning                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `ASSISTANT_ENABLED`                                                                                          | `false`                     | Platform switch (`503 assistant_disabled` when off)                                                                                  |
| `ASSISTANT_PROVIDER`                                                                                         | `fake`                      | `fake`, `anthropic`, `openai`, `azure_openai`; `fake` is refused with `NODE_ENV=production` while enabled                            |
| `ASSISTANT_MODEL`                                                                                            | `claude-opus-5-5`           | Model id (Anthropic, OpenAI); Azure uses the deployment                                                                              |
| `ASSISTANT_EFFORT`                                                                                           | `low`                       | Anthropic effort (`low`, `medium`, `high`)                                                                                           |
| `ASSISTANT_REFUSAL_FALLBACK`                                                                                 | `default`                   | Anthropic server-side refusal fallback (`default`) or plain requests (`off`)                                                         |
| `ASSISTANT_ANTHROPIC_API_KEY`, `ASSISTANT_OPENAI_API_KEY`, `ASSISTANT_AZURE_OPENAI_API_KEY`                  | unset                       | Provider credentials (external secrets, `_FILE` accepted); required for the selected provider while enabled                          |
| `ASSISTANT_ANTHROPIC_BASE_URL`                                                                               | SDK default                 | Optional Anthropic endpoint                                                                                                          |
| `ASSISTANT_OPENAI_BASE_URL`                                                                                  | `https://api.openai.com/v1` | OpenAI endpoint (https outside local/CI)                                                                                             |
| `ASSISTANT_AZURE_OPENAI_ENDPOINT`, `ASSISTANT_AZURE_OPENAI_DEPLOYMENT`, `ASSISTANT_AZURE_OPENAI_API_VERSION` | unset, unset, `2024-10-21`  | Azure OpenAI resource, deployment and API version                                                                                    |
| `ASSISTANT_TIMEOUT_MS`                                                                                       | `30000`                     | One provider call                                                                                                                    |
| `ASSISTANT_TURN_DEADLINE_MS`                                                                                 | `90000`                     | Whole turn                                                                                                                           |
| `ASSISTANT_MAX_OUTPUT_TOKENS`                                                                                | `4096`                      | Output tokens per model call                                                                                                         |
| `ASSISTANT_MAX_TOOL_ROUNDS`, `ASSISTANT_MAX_TOOL_CALLS_PER_TURN`                                             | `6`, `12`                   | Model rounds and tool calls per turn                                                                                                 |
| `ASSISTANT_TOOL_TIMEOUT_MS`                                                                                  | `15000`                     | One loopback tool call                                                                                                               |
| `ASSISTANT_TOOL_RESULT_MAX_BYTES`, `ASSISTANT_TOOL_RESULT_MAX_ROWS`                                          | `12288`, `25`               | Envelope size sent to the model                                                                                                      |
| `ASSISTANT_CONTEXT_MAX_TOKENS`                                                                               | `60000`                     | Segment window before a recap                                                                                                        |
| `ASSISTANT_USER_MESSAGE_MAX_CHARS`                                                                           | `4000`                      | Question length                                                                                                                      |
| `ASSISTANT_TURNS_PER_USER_PER_MINUTE`                                                                        | `6`                         | Per-user turn window                                                                                                                 |
| `ASSISTANT_MAX_CONCURRENT_TURNS`                                                                             | `20`                        | Per api process (`503 assistant_busy`)                                                                                               |
| `ASSISTANT_TENANT_DAILY_TOKENS_DEFAULT`, `ASSISTANT_TENANT_DAILY_TOKENS_MAX`                                 | `1000000`, `5000000`        | Tenant budget per UTC day when unset, and the most a tenant may set                                                                  |
| `ASSISTANT_PLATFORM_DAILY_TOKENS`                                                                            | `0`                         | Platform tokens per UTC day (0 = no cap)                                                                                             |
| `ASSISTANT_RETENTION_DEFAULT_DAYS`                                                                           | `30`                        | Content retention after the last turn when the tenant set none                                                                       |
| `ASSISTANT_EXECUTION_RETENTION_DAYS`                                                                         | `400`                       | Hard delete of conversation, turn and execution metadata                                                                             |
| `ASSISTANT_MAX_CONVERSATIONS_PER_USER`                                                                       | `500`                       | `409 assistant_conversation_limit` beyond                                                                                            |
| `ASSISTANT_LOOPBACK_URL`                                                                                     | empty                       | Base URL of tool calls (empty = the api's own port)                                                                                  |
| `ASSISTANT_BACKGROUND_JOBS_ENABLED`                                                                          | `true`                      | Retention purge and stale-turn sweeper in this process                                                                               |
| `ASSISTANT_BREAKER_THRESHOLD`, `ASSISTANT_BREAKER_RESET_MS`                                                  | `5`, `60000`                | Provider breaker                                                                                                                     |
| `ASSISTANT_MODEL_PRICES`                                                                                     | empty                       | JSON prices per model (micro-USD per million tokens)                                                                                 |
| `ASSISTANT_CONFIRMATION_TTL_SECONDS`                                                                         | `300`                       | Time to confirm a proposal (60–900 s)                                                                                                |
| `ASSISTANT_REAUTH_WINDOW_SECONDS`                                                                            | `300`                       | After a successful re-authentication at an assistant confirm, `high` confirms of the same session skip it (0–1800 s; 0 = always ask) |
| `ASSISTANT_MAX_PENDING_CONFIRMATIONS`                                                                        | `5`                         | Pending confirmations per conversation (1–20); a further proposal is `denied_budget` (AI-2)                                          |

The Docker Compose api service passes no `ASSISTANT_*` key, so the containerized api runs with the assistant off; see [README.md](README.md#enabling-it-locally).
