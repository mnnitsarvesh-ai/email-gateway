# Chat API

The assistant's HTTP interface: 15 routes under `/api/v1/assistant` (OpenAPI tag `assistant`), one Server-Sent Events stream, coded errors. The normative contract is [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1); request and response schemas with examples are in the OpenAPI snapshot [`docs/api/openapi.json`](../api/openapi.json) (tag `assistant`). Examples below use synthetic values.

## Conventions

- **User principals only** (`@UserOnly()`): API keys get `403` even with the permission. The portal reaches the routes through its BFF (`/bff/api/v1/assistant/…`, session cookie, CSRF header); direct clients send `Authorization: Bearer <access-token>`.
- **Tenant** always from the authenticated principal; a conversation, turn or execution of another user or organization answers `404`.
- Coded errors with `requestId` (ADR-0050), strict request validation (unknown fields → `400`), cursor v1 pagination on the two list routes.
- None of these routes is ever a chat tool (no recursion).

## Routes

| Method | Path                                                 | Permission            | Purpose                                                                                                                                                       |
| ------ | ---------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/assistant/status`                                  | `assistant:use`       | Whether the assistant is available to the caller and why not; provider, model, limits, today's budget                                                         |
| GET    | `/assistant/settings`                                | `assistant:configure` | The organization's `assistant-settings/1` document with `rowVersion`                                                                                          |
| PUT    | `/assistant/settings`                                | `assistant:configure` | Update with CAS (`expectedRowVersion`); enabling needs `externalProcessingAcknowledged: true` and the feature `ai_assistant`; rate class `sensitive`; audited |
| GET    | `/assistant/usage`                                   | `assistant:configure` | Tokens and advisory cost per UTC day and model (`from`/`to`, at most 92 days)                                                                                 |
| GET    | `/assistant/tools`                                   | `assistant:use`       | The caller's enabled tools after the permission pre-filter, with `registryVersion`                                                                            |
| GET    | `/assistant/conversations`                           | `assistant:use`       | Own conversations, newest first; `q` (title contains), `status` (`active`/`archived`), `limit`, `cursor`                                                      |
| POST   | `/assistant/conversations`                           | `assistant:use`       | Create (`{ title? }`) → `201`                                                                                                                                 |
| GET    | `/assistant/conversations/{conversationId}`          | `assistant:use`       | One own conversation                                                                                                                                          |
| PATCH  | `/assistant/conversations/{conversationId}`          | `assistant:use`       | Rename or archive/restore (`{ title?, status? }`)                                                                                                             |
| DELETE | `/assistant/conversations/{conversationId}`          | `assistant:use`       | Clear: soft delete and immediate content purge → `204`; audited                                                                                               |
| GET    | `/assistant/conversations/{conversationId}/messages` | `assistant:use`       | Messages oldest → newest, each with its turn and that turn's executions and cards                                                                             |
| POST   | `/assistant/conversations/{conversationId}/turns`    | `assistant:use`       | Ask: SSE with `accept: text/event-stream`, else JSON; rate class `expensive`                                                                                  |
| POST   | `/assistant/turns/{turnId}/cancel`                   | `assistant:use`       | Cancel an own running turn → `202`                                                                                                                            |
| GET    | `/assistant/executions/{executionId}`                | `assistant:use`       | One own tool execution: card and metadata                                                                                                                     |
| POST   | `/assistant/executions/{executionId}/more`           | `assistant:use`       | Next page of a list result, without a model call; returns a new execution; rate class `expensive`                                                             |

## Examples

Status (available):

```http
GET /api/v1/assistant/status
Authorization: Bearer <access-token>
```

```json
{
  "available": true,
  "provider": "anthropic",
  "model": "claude-opus-5-5",
  "limits": { "messageMaxChars": 4000, "turnsPerMinute": 6 },
  "budget": { "dailyTokens": 1000000, "usedToday": 18240 }
}
```

When not available, `available` is `false` and `reason` is one of `platform_disabled`, `feature_disabled`, `tenant_disabled`, `provider_unavailable`, `budget_exhausted`.

Enable for the organization (an organization admin):

```http
PUT /api/v1/assistant/settings
Content-Type: application/json

{
  "expectedRowVersion": 0,
  "enabled": true,
  "externalProcessingAcknowledged": true,
  "dailyTokenBudget": null,
  "retentionDays": 30
}
```

```json
{
  "version": "assistant-settings/1",
  "enabled": true,
  "externalProcessingAcknowledged": true,
  "externalProcessingAcknowledgedAt": "2026-11-20T09:15:02.114Z",
  "externalProcessingAcknowledgedBy": "0193a1c2-6f00-7a00-8c00-000000000001",
  "dailyTokenBudget": null,
  "effectiveDailyTokenBudget": 1000000,
  "retentionDays": 30,
  "dataSharing": "metadata",
  "featureEnabled": true,
  "rowVersion": 1,
  "updatedAt": "2026-11-20T09:15:02.114Z"
}
```

Ask as JSON (no `accept: text/event-stream`):

```http
POST /api/v1/assistant/conversations/0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01/turns
Content-Type: application/json

{
  "clientTurnId": "6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e",
  "message": "Which policies are active right now?",
  "timeZone": "Asia/Kolkata"
}
```

```json
{
  "turn": {
    "id": "0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02",
    "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
    "seq": 1,
    "status": "completed",
    "errorCode": null,
    "provider": "anthropic",
    "model": "claude-opus-5-5",
    "responseModel": "claude-opus-5-5",
    "rounds": 2,
    "toolCalls": 1,
    "usage": {
      "inputTokens": 5120,
      "outputTokens": 210,
      "cacheReadTokens": 4096,
      "cacheWriteTokens": 0
    },
    "latencyMs": 3810,
    "startedAt": "2026-11-20T09:16:00.000Z",
    "finishedAt": "2026-11-20T09:16:03.810Z"
  },
  "message": {
    "id": "0193a1c2-7c30-7e5a-9c73-4b2d8e3f6a03",
    "turnId": "0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02",
    "seq": 2,
    "role": "assistant",
    "content": "Two policies are active: Block executables and Tag external senders.",
    "createdAt": "2026-11-20T09:16:03.800Z"
  },
  "executions": [
    {
      "id": "0193a1c2-7b40-7f6b-8d84-5c3e9f4a7b04",
      "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
      "turnId": "0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02",
      "parentExecutionId": null,
      "seq": 1,
      "ref": "r1",
      "tool": "policy_management_list",
      "operationId": "PolicyManagementController_list_v1",
      "access": "read",
      "risk": "read",
      "decision": "allowed",
      "status": "succeeded",
      "httpStatus": 200,
      "errorCode": null,
      "hasMore": false,
      "card": {
        "executionId": "0193a1c2-7b40-7f6b-8d84-5c3e9f4a7b04",
        "tool": "policy_management_list",
        "title": "List policies",
        "status": "ok",
        "kind": "table",
        "columns": [
          { "key": "name", "label": "Name" },
          { "key": "status", "label": "Status" }
        ],
        "rows": [
          { "name": "Block executables", "status": "active", "ref": "r1.1" },
          { "name": "Tag external senders", "status": "active", "ref": "r1.2" }
        ],
        "nextCursor": false,
        "portalLinks": [
          {
            "label": "Block executables",
            "href": "/policies/0193a1c2-0000-7000-8000-00000000aa01",
            "ref": "r1.1"
          }
        ],
        "refs": ["r1.1", "r1.2"]
      },
      "latencyMs": 42,
      "createdAt": "2026-11-20T09:16:01.200Z"
    }
  ]
}
```

The card above is abbreviated (cards carry every column of the tool's display hints and a link per row). Sending the same `clientTurnId` again replays the stored result of a completed turn; while it runs the answer is `409 assistant_turn_in_progress`.

## Event stream `assistant-stream/1`

With `accept: text/event-stream` the turn route answers `200` with `content-type: text/event-stream` and flushes the headers with `turn.started` before the first model call. Each event is an `event:` name and one `data:` JSON line; a comment line (`: heartbeat`) is sent every 15 s. Order: `turn.started`, then any interleaving of text and tool events, then exactly one of `turn.completed` or `turn.failed`.

| Event            | Data                                                                    |
| ---------------- | ----------------------------------------------------------------------- |
| `turn.started`   | `{ turnId, conversationId, seq }`                                       |
| `text.delta`     | `{ text }` (zero or more)                                               |
| `tool.started`   | `{ executionId, tool, title }`                                          |
| `tool.completed` | `{ executionId, status, decision, card }` (`card` = `assistant-card/1`) |
| `tool.denied`    | `{ executionId, tool, decision, message }`                              |
| `turn.completed` | `{ turnId, status, usage: { inputTokens, outputTokens }, messageId }`   |
| `turn.failed`    | `{ turnId, code, message }`                                             |

```text
event: turn.started
data: {"turnId":"0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02","conversationId":"0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01","seq":1}

event: tool.started
data: {"executionId":"0193a1c2-7b40-7f6b-8d84-5c3e9f4a7b04","tool":"policy_management_list","title":"List policies"}

event: tool.completed
data: {"executionId":"0193a1c2-7b40-7f6b-8d84-5c3e9f4a7b04","status":"succeeded","decision":"allowed","card":{…}}

event: text.delta
data: {"text":"Two policies are active: "}

event: text.delta
data: {"text":"Block executables and Tag external senders."}

event: turn.completed
data: {"turnId":"0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02","status":"completed","usage":{"inputTokens":5120,"outputTokens":210},"messageId":"0193a1c2-7c30-7e5a-9c73-4b2d8e3f6a03"}
```

Refusals before the stream starts (switches, budgets, rate limits, validation) are ordinary JSON error responses. A client disconnect cancels the turn like `POST /assistant/turns/{turnId}/cancel`; the turn is stored as `cancelled` with the partial text. Behind a reverse proxy the stream must not be buffered: the portal BFF sets `cache-control: no-store, no-transform` and `x-accel-buffering: no` on it.

AI-2 adds `confirmation.required { confirmationId, token, summary, impact, risk, requiresReauth }` and the confirm/cancel routes ([ADR-0093](../architecture/adr/0093-assistant-action-confirmation.md)); they do not exist in AI-1.

## Error codes

| Code                               | HTTP | When                                                                                 |
| ---------------------------------- | ---- | ------------------------------------------------------------------------------------ |
| `assistant_disabled`               | 503  | Platform switch `ASSISTANT_ENABLED` is off                                           |
| `assistant_not_enabled`            | 403  | Organization feature `ai_assistant` is off                                           |
| `assistant_tenant_disabled`        | 403  | Tenant setting is off                                                                |
| `assistant_provider_unavailable`   | 503  | Provider breaker is open                                                             |
| `assistant_busy`                   | 503  | `ASSISTANT_MAX_CONCURRENT_TURNS` reached in this api process                         |
| `assistant_budget_exhausted`       | 429  | Tenant or platform daily token budget used up (`scope: tenant \| platform`)          |
| `assistant_turn_in_progress`       | 409  | A turn of this conversation is running (or the same `clientTurnId` is still running) |
| `assistant_conversation_limit`     | 409  | `ASSISTANT_MAX_CONVERSATIONS_PER_USER` reached                                       |
| `assistant_conversation_not_found` | 404  | Unknown, foreign or deleted conversation                                             |
| `assistant_execution_not_found`    | 404  | Unknown or foreign execution                                                         |
| `assistant_no_more_results`        | 409  | "More" on an execution without a stored cursor                                       |
| `assistant_settings_conflict`      | 409  | `expectedRowVersion` is stale                                                        |
| `rate_limited`                     | 429  | Turns per user per minute, or the api's rate classes (`expensive`, `sensitive`)      |
| `payload_too_large`                | 413  | Message longer than `ASSISTANT_USER_MESSAGE_MAX_CHARS`                               |

Turn failure codes (stream `turn.failed` and the stored turn's `errorCode`): `assistant_session_expired` (a loopback call answered `401`; sign in again and retry), `assistant_turn_limit` (rounds, tool calls or deadline), `assistant_refused` (the provider declined, with its category), `assistant_turn_abandoned` (the process stopped mid-turn; set by the sweeper), `assistant_provider_error`.

Executor decisions (per tool execution, never an HTTP error of the turn): `allowed`, `denied_budget`, `denied_unknown_tool`, `denied_not_applicable`, `denied_disabled`, `denied_permission`, `denied_ref`, `denied_schema`; a coded error of the called operation itself (for example `404` for an id of another organization) is a `failed` execution with that code.

## Rate limits and budgets

| Control                          | Default                                                                                     | Error                                       |
| -------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------- |
| Turns per user                   | 6 per minute (`ASSISTANT_TURNS_PER_USER_PER_MINUTE`) and the api rate class `expensive`     | `429 rate_limited`                          |
| Tool calls                       | Each loopback call counts against the user's ordinary api limits (principal, tenant, class) | the tool's own `429`, shown in its card     |
| Concurrent turns per api process | 20                                                                                          | `503 assistant_busy`                        |
| Tenant tokens per UTC day        | 1 000 000 (tenant may set 1 … 5 000 000)                                                    | `429 assistant_budget_exhausted` (tenant)   |
| Platform tokens per UTC day      | none (`ASSISTANT_PLATFORM_DAILY_TOKENS` = 0)                                                | `429 assistant_budget_exhausted` (platform) |
| Per turn                         | 6 model rounds, 12 tool calls, 4 096 output tokens per call, 90 s, 15 s per tool call       | `assistant_turn_limit`                      |
| Message length                   | 4 000 characters                                                                            | `413 payload_too_large`                     |
| Conversations per user           | 500                                                                                         | `409 assistant_conversation_limit`          |

Budgets are checked at turn start; a running turn may finish (overshoot of at most one turn). Usage is readable per day and model with `GET /assistant/usage` and in **Settings → AI assistant**.
