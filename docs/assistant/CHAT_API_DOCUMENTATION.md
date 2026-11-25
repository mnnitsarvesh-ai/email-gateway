# Chat API

The assistant's HTTP interface: 19 routes under (step AI-R added `GET /assistant/reports/{reportId}`) `/api/v1/assistant` (OpenAPI tag `assistant`), one Server-Sent Events stream, coded errors. The normative contract is [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1) and, for confirmations (step AI-2), [§35.1](../architecture/contracts.md#351-confirmations-step-ai-2) and, for the identity and tenant administration tools (step AI-3), [§35.2](../architecture/contracts.md#352-identity-and-tenant-administration-tools-step-ai-3); AI-3 added no assistant route; request and response schemas with examples are in the OpenAPI snapshot [`docs/api/openapi.json`](../api/openapi.json) (tag `assistant`). Examples below use synthetic values.

## Conventions

- **User principals only** (`@UserOnly()`): API keys get `403` even with the permission. The portal reaches the routes through its BFF (`/bff/api/v1/assistant/…`, session cookie, CSRF header); direct clients send `Authorization: Bearer <access-token>`.
- **Tenant** always from the authenticated principal; a conversation, turn, execution or confirmation of another user or organization answers `404`.
- Coded errors with `requestId` (ADR-0050), strict request validation (unknown fields → `400`), cursor v1 pagination on the two list routes.
- None of these routes is ever a chat tool (no recursion).

## Routes

| Method | Path                                                 | Permission            | Purpose                                                                                                                                                                 |
| ------ | ---------------------------------------------------- | --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/assistant/status`                                  | `assistant:use`       | Whether the assistant is available to the caller and why not; provider, model, limits, today's budget                                                                   |
| GET    | `/assistant/settings`                                | `assistant:configure` | The organization's `assistant-settings/1` document with `rowVersion`                                                                                                    |
| PUT    | `/assistant/settings`                                | `assistant:configure` | Update with CAS (`expectedRowVersion`); enabling needs `externalProcessingAcknowledged: true` and the feature `ai_assistant`; rate class `sensitive`; audited           |
| GET    | `/assistant/usage`                                   | `assistant:configure` | Tokens and advisory cost per UTC day and model (`from`/`to`, at most 92 days)                                                                                           |
| GET    | `/assistant/tools`                                   | `assistant:use`       | The caller's enabled tools after the permission pre-filter, with `registryVersion`                                                                                      |
| GET    | `/assistant/conversations`                           | `assistant:use`       | Own conversations, newest first; `q` (title contains), `status` (`active`/`archived`), `limit`, `cursor`                                                                |
| POST   | `/assistant/conversations`                           | `assistant:use`       | Create (`{ title? }`) → `201`                                                                                                                                           |
| GET    | `/assistant/conversations/{conversationId}`          | `assistant:use`       | One own conversation                                                                                                                                                    |
| PATCH  | `/assistant/conversations/{conversationId}`          | `assistant:use`       | Rename or archive/restore (`{ title?, status? }`)                                                                                                                       |
| DELETE | `/assistant/conversations/{conversationId}`          | `assistant:use`       | Clear: soft delete and immediate content purge → `204`; audited                                                                                                         |
| GET    | `/assistant/conversations/{conversationId}/messages` | `assistant:use`       | Messages oldest → newest, each with its turn and that turn's executions and cards                                                                                       |
| POST   | `/assistant/conversations/{conversationId}/turns`    | `assistant:use`       | Ask: SSE with `accept: text/event-stream`, else JSON; rate class `expensive`                                                                                            |
| POST   | `/assistant/turns/{turnId}/cancel`                   | `assistant:use`       | Cancel an own running turn → `202`                                                                                                                                      |
| GET    | `/assistant/executions/{executionId}`                | `assistant:use`       | One own tool execution: card and metadata                                                                                                                               |
| POST   | `/assistant/executions/{executionId}/more`           | `assistant:use`       | Next page of a list result, without a model call; returns a new execution; rate class `expensive`                                                                       |
| GET    | `/assistant/confirmations/{confirmationId}`          | `assistant:use`       | One own confirmation (`{ confirmation: ConfirmationView }`, any session, never the token); a `pending` row past its expiry is shown `expired` (AI-2)                    |
| POST   | `/assistant/confirmations/{confirmationId}/confirm`  | `assistant:use`       | Confirm a proposed write: `{ token, actionDigest, reauth? }` → `200 { confirmation, execution }`; same session family only; rate class `sensitive` (AI-2)               |
| POST   | `/assistant/confirmations/{confirmationId}/cancel`   | `assistant:use`       | Cancel a pending proposal (no body, no token; works after a reload) → `200 { confirmation }`; idempotent; rate class `sensitive` (AI-2)                                 |
| GET    | `/assistant/reports/{reportId}`                      | `assistant:use`       | One own report (AI-R): `200 { report: ReportView, html: string \| null }`; `html` only while `available`; owner only (else `404`); `Cache-Control: no-store`; JSON only |

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

| Event                   | Data                                                                                                                                                                                                                                                                     |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `turn.started`          | `{ turnId, conversationId, seq }`                                                                                                                                                                                                                                        |
| `text.delta`            | `{ text }` (zero or more)                                                                                                                                                                                                                                                |
| `tool.started`          | `{ executionId, tool, title }`                                                                                                                                                                                                                                           |
| `tool.completed`        | `{ executionId, status, decision, card }` (`card` = `assistant-card/1`; `status` `pending_confirmation` for a proposed write)                                                                                                                                            |
| `confirmation.required` | `{ confirmation: ConfirmationView, token }` right after the `tool.completed` of a proposed write (AI-2); the only place the token ever appears                                                                                                                           |
| `tool.denied`           | `{ executionId, tool, decision, message }`; since AI-3 `decision` can be `denied_guard` (a proposal guard refused the write; `message` is the fixed server text, for example "Changes to your own account, roles, status, MFA or sessions are not available in chat. …") |
| `turn.completed`        | `{ turnId, status, usage: { inputTokens, outputTokens }, messageId }`                                                                                                                                                                                                    |
| `turn.failed`           | `{ turnId, code, message }`                                                                                                                                                                                                                                              |

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

## Confirmations (step AI-2)

A write tool never runs inside a turn. The executor validates the call, reads the target's current state through the matching read operation (the user's own token), validates policy definitions with `POST /policies/validate`, builds a server-authored summary (`assistant-confirmation/1`) and stores a confirmation bound by `actionDigest` (SHA-256 of the canonical request, preconditions and identity) to a single-use token. The browser receives the token once, in `confirmation.required`; the model receives `pending_confirmation` without token or digest and learns the outcome at the start of its next turn ("Action updates since your last message …").

Proposal (stream excerpt; the token is shown as `<token>`):

```text
event: tool.completed
data: {"executionId":"0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05","status":"pending_confirmation","decision":"allowed","card":{…"kind":"message"…}}

event: confirmation.required
data: {"confirmation":{"id":"0193a1c2-7d60-7b7d-8fa6-7e5a1b6c9d06","executionId":"0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05","tool":"policy_management_create","risk":"low","requiresReauth":false,"reauthFresh":false,"status":"pending","summary":{…},"actionDigest":"<64 hex characters>","expiresAt":"2026-11-21T10:05:00.000Z",…},"token":"<token>"}
```

In JSON mode the turn result carries `confirmations: [{ confirmation, token }]` (`token` is `null` when a `clientTurnId` retry replays a stored result).

Confirm (from the card; the BFF adds the bearer and CSRF):

```http
POST /api/v1/assistant/confirmations/0193a1c2-7d60-7b7d-8fa6-7e5a1b6c9d06/confirm
Content-Type: application/json

{ "token": "<token>", "actionDigest": "<the digest the card showed>" }
```

A `high`-risk confirmation adds `"reauth": { "password": "<password>", "totpCode": "<6 digits>" }` (`totpCode` when the user has MFA) unless the same sign-in session re-authenticated at an assistant confirm within `ASSISTANT_REAUTH_WINDOW_SECONDS` (`reauthFresh: true`).

```json
{
  "confirmation": {
    "id": "0193a1c2-7d60-7b7d-8fa6-7e5a1b6c9d06",
    "executionId": "0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05",
    "resultExecutionId": "0193a1c2-7e70-7c8e-90b7-8f6b2c7d0e07",
    "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
    "tool": "policy_management_create",
    "operationId": "PolicyManagementController_create_v1",
    "risk": "low",
    "requiresReauth": false,
    "reauthFresh": false,
    "status": "executed",
    "summary": {
      "version": "assistant-confirmation/1",
      "title": "Create policy",
      "action": "Creates the policy \"Quarantine inbound executables\" as a draft (version 1). It does not evaluate mail until it is published and activated.",
      "target": [{ "label": "Name", "value": "Quarantine inbound executables" }],
      "changes": [{ "label": "Rules", "after": "1" }],
      "definition": {
        "direction": "inbound",
        "priority": 100,
        "rules": [{ "id": "quarantine-executables", "when": "…", "actions": "QUARANTINE" }]
      },
      "impact": ["Nothing changes for mail until the draft is published and activated."],
      "warnings": [],
      "reversible": true,
      "portalRoute": "/policies",
      "request": { "method": "POST", "path": "/api/v1/policies" }
    },
    "actionDigest": "<64 hex characters>",
    "expiresAt": "2026-11-21T10:05:00.000Z",
    "createdAt": "2026-11-21T10:00:00.000Z",
    "decidedAt": "2026-11-21T10:00:41.120Z",
    "executedAt": "2026-11-21T10:00:41.410Z",
    "result": { "httpStatus": 201, "error": null }
  },
  "execution": { "id": "0193a1c2-7e70-7c8e-90b7-8f6b2c7d0e07", "parentExecutionId": "0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05", "status": "succeeded", "httpStatus": 201, "card": {…}, "…": "…" }
}
```

The summary above is abbreviated. A write the operation itself refuses (for example `409 policy_conflict`) is still `200`, with `confirmation.status = "failed"`, `result: { httpStatus, error }` and the execution's error card: the confirm worked, the operation refused. A quarantine release that needs approval answers `202` and the confirmation is `executed` ("submitted for approval").

**Views.** `ConfirmationView` = `{ id, executionId, resultExecutionId, conversationId, tool, operationId, risk, requiresReauth, reauthFresh, status, summary, actionDigest, expiresAt, createdAt, decidedAt, executedAt, result }` with `status` `pending`, `executing`, `executed`, `failed`, `expired` or `cancelled` (`summary` is `null` after the conversation content was purged). `ExecutionView` gains `confirmation: ConfirmationView | null` (on proposal executions; the messages route and the JSON turn result include it, never the token) and the status `pending_confirmation`. Since AI-3 every `ExecutionView` also carries `title` (the tool's display title, as `tool.started` sends it) and `message` (`null` for an allowed call; for a refused one the fixed server text of its decision, for `denied_guard` the guard's own message, derived from the stored operation's confirmation spec; never an argument value), so a stored conversation (reload, refetch after the turn) shows the same denied card as the live `tool.denied` event.

**Confirm checks, in order:** owner (`404`), session family (`403`), status `pending` (`409`), expiry (`410`, the row becomes `expired`), token (`403`; the fifth wrong token cancels the row), digest (`409`), tool still enabled and permitted (`409` / `403`), availability, re-authentication for `high` (`401`), the conversation's turn lock (`409 assistant_turn_in_progress`), the atomic `pending → executing` transition, the precondition re-read (`409` when the target changed), then the stored request runs through the loopback with `Idempotency-Key` = the confirmation id (operations with `required`/`legacy` idempotency) and the precondition's row version as CAS. Every refusal except `404` is audited as `assistant.confirmation_refused`.

**Step AI-3 additions to the confirm checks** ([design note 30 D10](../plan/steps/30-ai-chat-identity-tenant-admin.md#d10-api-changes-assistant-module)): right after the tool check, the **effective risk** is recomputed from the stored arguments (registry risk raised by the spec's escalation rules, D4); a difference from the stored `risk` fails the row with `409 assistant_confirmation_tool_changed`. Then the **proposal guards** that need no read are evaluated with the confirming principal, and after the precondition re-read the guards on the fresh target (for example `roles_update` adding or removing `assistant:configure`); a refusal fails the row with `403 assistant_action_not_allowed` ("This change is not allowed in chat.") and is audited as `assistant.confirmation_refused` with `reason: guard`. The stored `risk` of an AI-3 confirmation is the effective risk, so `requiresReauth` is `true` for an escalated `low`/`medium` tool (for example `webhooks_update` with `body.url`) and the card's warnings include the escalation warning.

**A guard refusal at proposal** (AI-3) is not a confirmation at all: the execution is `refused` with decision `denied_guard`, the stream sends `tool.denied`, the model's envelope is `{ "status": "denied", "decision": "denied_guard", "message": "…" }`, no confirmation row is stored and no loopback request is sent (self guards are evaluated before the precondition read).

**New read target** (AI-3): `GET /api/v1/api-keys/{id}` (`ApiKeysController_get_v1`, tool `api_keys_get`, `apikey:read`) returns the list item's view (`id, name, prefix, scopes, createdBy, lastUsedAt, expiresAt, revokedAt, createdAt`; never the key or its hash; revoked keys included; another organization's or an unknown id `404`). It is the precondition read of `api_keys_revoke`, so the revocation card names the key, and an ordinary enabled read tool.

## Error codes

| Code                                      | HTTP | When                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assistant_disabled`                      | 503  | Platform switch `ASSISTANT_ENABLED` is off                                                                                                                                                                                                                                                                                                                  |
| `assistant_not_enabled`                   | 403  | Organization feature `ai_assistant` is off                                                                                                                                                                                                                                                                                                                  |
| `assistant_tenant_disabled`               | 403  | Tenant setting is off                                                                                                                                                                                                                                                                                                                                       |
| `assistant_provider_unavailable`          | 503  | Provider breaker is open                                                                                                                                                                                                                                                                                                                                    |
| `assistant_busy`                          | 503  | `ASSISTANT_MAX_CONCURRENT_TURNS` reached in this api process                                                                                                                                                                                                                                                                                                |
| `assistant_budget_exhausted`              | 429  | Tenant or platform daily token budget used up (`scope: tenant \| platform`)                                                                                                                                                                                                                                                                                 |
| `assistant_turn_in_progress`              | 409  | A turn of this conversation is running (or the same `clientTurnId` is still running)                                                                                                                                                                                                                                                                        |
| `assistant_conversation_limit`            | 409  | `ASSISTANT_MAX_CONVERSATIONS_PER_USER` reached                                                                                                                                                                                                                                                                                                              |
| `assistant_conversation_not_found`        | 404  | Unknown, foreign or deleted conversation                                                                                                                                                                                                                                                                                                                    |
| `assistant_execution_not_found`           | 404  | Unknown or foreign execution                                                                                                                                                                                                                                                                                                                                |
| `assistant_no_more_results`               | 409  | "More" on an execution without a stored cursor                                                                                                                                                                                                                                                                                                              |
| `assistant_settings_conflict`             | 409  | `expectedRowVersion` is stale                                                                                                                                                                                                                                                                                                                               |
| `rate_limited`                            | 429  | Turns per user per minute, or the api's rate classes (`expensive`, `sensitive`)                                                                                                                                                                                                                                                                             |
| `payload_too_large`                       | 413  | Message longer than `ASSISTANT_USER_MESSAGE_MAX_CHARS`                                                                                                                                                                                                                                                                                                      |
| `assistant_confirmation_not_found`        | 404  | Unknown confirmation, or one of another user or organization (AI-2)                                                                                                                                                                                                                                                                                         |
| `assistant_confirmation_session_mismatch` | 403  | The confirmation was proposed in another sign-in session of the user                                                                                                                                                                                                                                                                                        |
| `assistant_confirmation_not_pending`      | 409  | Already executing, executed, failed, expired or cancelled (`details.status`)                                                                                                                                                                                                                                                                                |
| `assistant_confirmation_expired`          | 410  | Past `expires_at` (`ASSISTANT_CONFIRMATION_TTL_SECONDS`, default 300 s); the row becomes `expired`                                                                                                                                                                                                                                                          |
| `assistant_confirmation_token_invalid`    | 403  | Wrong token; the fifth cancels the confirmation (`error_code` `assistant_confirmation_token_locked`)                                                                                                                                                                                                                                                        |
| `assistant_confirmation_digest_mismatch`  | 409  | `actionDigest` differs from the stored digest (or the stored row was tampered with)                                                                                                                                                                                                                                                                         |
| `assistant_confirmation_tool_changed`     | 409  | The tool is no longer enabled with the same method and path, or (AI-3) the effective risk recomputed from the stored arguments differs from the stored risk                                                                                                                                                                                                 |
| `assistant_action_not_allowed`            | 403  | (AI-3) A proposal guard refused the change at confirm (self-service of authority, the assistant's own feature or `assistant:configure`; since AI-4 also the ATO four-eyes guard: the confirming user requested the response, created the requesting API key, or the api's `canDecide` became false); the row is `failed` with this code and nothing is sent |
| `assistant_confirmation_state_changed`    | 409  | The target changed since the proposal (`details.httpStatus` when the re-read failed)                                                                                                                                                                                                                                                                        |
| `assistant_reauth_required`               | 401  | A `high`-risk confirm without `reauth` and without a fresh re-authentication window                                                                                                                                                                                                                                                                         |
| `assistant_reauth_failed`                 | 401  | Re-authentication failed (`details.reason`: `password`, `totp`, `totp_required`, `locked`, `inactive`; counts toward the sign-in lockout)                                                                                                                                                                                                                   |
| `assistant_report_not_found`              | 404  | (AI-R) The report is not the caller's (organization, user, override id), unknown, or (proposal of `report_send_email`) not in this conversation                                                                                                                                                                                                             |
| `assistant_report_purged`                 | 410  | (AI-R) The report was deleted with the conversation content (proposal of `report_send_email`; the route answers `200` with `html: null`)                                                                                                                                                                                                                    |
| `assistant_report_too_large`              | 413  | (AI-R) The rendered HTML exceeds `ASSISTANT_REPORT_MAX_HTML_BYTES` (generation, or a stored report too large to email)                                                                                                                                                                                                                                      |
| `assistant_report_generation_limit`       | 429  | (AI-R) `ASSISTANT_REPORTS_PER_USER_PER_DAY` reports today (UTC); executor decision `denied_budget`                                                                                                                                                                                                                                                          |
| `assistant_report_email_limit`            | 429  | (AI-R) Daily report emails of the user or organization used up (`scope: user \| tenant`); `denied_budget` at proposal, a failed confirmation (`429`, nothing written) at confirm                                                                                                                                                                            |
| `assistant_report_sources_unavailable`    | 503  | (AI-R) No report source answered (every requested section omitted)                                                                                                                                                                                                                                                                                          |
| `assistant_report_storage_failed`         | 502  | (AI-R) The report object could not be stored; the row becomes `failed`                                                                                                                                                                                                                                                                                      |
| `assistant_report_invalid_window`         | 400  | (AI-R) A window the server refuses (`denied_schema`: `to` in the future, `from ≥ to`, longer than `REPORTS_MAX_RANGE_DAYS`)                                                                                                                                                                                                                                 |

Turn failure codes (stream `turn.failed` and the stored turn's `errorCode`): `assistant_session_expired` (a loopback call answered `401`; sign in again and retry), `assistant_turn_limit` (rounds, tool calls or deadline), `assistant_refused` (the provider declined, with its category), `assistant_turn_abandoned` (the process stopped mid-turn; set by the sweeper), `assistant_provider_error`.

Proposal envelope codes (in the tool result of a write, never an HTTP error): `assistant_definition_invalid` (the policy definition failed validation; at most 20 violations `{ path, code, message }` so the model can fix and retry) and `assistant_precondition_unavailable` (the precondition read returned no usable row version). Confirmation row codes (`result.error`): `assistant_confirmation_token_locked`, `assistant_confirmation_outcome_unknown` (the api stopped while the write ran; never re-executed, check the target in the portal).

Executor decisions (per tool execution, never an HTTP error of the turn): `allowed`, `denied_budget` (also: more than `ASSISTANT_MAX_PENDING_CONFIRMATIONS` pending confirmations in the conversation), `denied_unknown_tool`, `denied_not_applicable`, `denied_disabled`, `denied_permission`, `denied_ref`, `denied_schema`, `denied_guard` (AI-3: a proposal guard refused the write before anything was stored or sent; the card says "Not allowed in chat"); a coded error of the called operation itself (for example `404` for an id of another organization) is a `failed` execution with that code.

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
| Pending confirmations            | 5 per conversation (`ASSISTANT_MAX_PENDING_CONFIRMATIONS`)                                  | the proposal is `denied_budget`             |
| Time to confirm                  | 300 s (`ASSISTANT_CONFIRMATION_TTL_SECONDS`)                                                | `410 assistant_confirmation_expired`        |
| Confirm and cancel requests      | the api rate class `sensitive`                                                              | `429 rate_limited`                          |

Budgets are checked at turn start; a running turn may finish (overshoot of at most one turn). Usage is readable per day and model with `GET /assistant/usage` and in **Settings → AI assistant**.

## Reports (step AI-R)

Contract: [contracts §35.3](../architecture/contracts.md), design [note 31](../plan/steps/31-ai-chat-reports.md) D2, D5, D6.

### Tools

| Tool                | Input                                                                                                                                                                                                                                                                            | Result                                                                                                                                                                                           |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `report_generate`   | `range?: '24h' \| '7d' \| '30d'` (default `7d`); `from?`, `to?` (ISO 8601, both or neither; replace `range`; at most `REPORTS_MAX_RANGE_DAYS`); `sections?`: unique, non-empty subset of `summary, traffic, threats, domains, delivery, processing, url_clicks, quarantine, ato` | `201`, card kind `report`, envelope `data = { ref, reportId, title, period, sections, omitted, figures }` (≤ 8 figures; never the HTML)                                                          |
| `report_send_email` | `reportId?`: UUID or ref `@r<seq>.1` (default the latest available report of this conversation); `to?`: one plain ASCII address (default the user's own)                                                                                                                         | A `medium` confirmation (`confirmation.required`); after confirm `202`, card kind `message` "Report email queued to <address>", envelope `data = { deliveryId, reportId, to, status: 'queued' }` |

Guard codes (decision `denied_guard`): `report_recipient_not_allowed` (the recipient rule, see [AI_SECURITY_STANDARDS.md](AI_SECURITY_STANDARDS.md#recipient-rule)) and `report_needs_organization` (a platform principal without an override).

### Card kind `report`

```json
{
  "version": "assistant-card/1",
  "executionId": "0193a0c4-0000-7000-8000-00000000c001",
  "tool": "report_generate",
  "title": "Security report: Last 7 days",
  "status": "ok",
  "kind": "report",
  "report": {
    "reportId": "0193a0c4-0000-7000-8000-00000000a001",
    "title": "Security report: Last 7 days",
    "period": {
      "from": "2026-11-16T09:00:00.000Z",
      "to": "2026-11-23T09:00:00.000Z",
      "granularity": "day",
      "atoRange": "7d",
      "label": "Last 7 days"
    },
    "generatedAt": "2026-11-23T09:00:00.000Z",
    "sizeBytes": 182344,
    "sections": [
      "summary",
      "traffic",
      "threats",
      "domains",
      "delivery",
      "processing",
      "url_clicks"
    ],
    "omitted": [
      { "section": "quarantine", "reason": "permission", "code": "quarantine:read" },
      { "section": "ato", "reason": "permission", "code": "ato:read" }
    ],
    "figures": [{ "label": "Messages", "value": "12,480" }]
  },
  "portalLinks": [
    { "label": "Open full size", "href": "/assistant/reports/0193a0c4-0000-7000-8000-00000000a001" }
  ],
  "refs": ["r1.1"]
}
```

Omission reasons: `permission` (the caller lacks the source's permission; the source is never requested), `not_enabled` (ATO feature off), `unavailable` (the source answered non-2xx; `code` is its error code, e.g. `report_timeout`), `unexpected_response` (the source's shape did not parse).

### `GET /assistant/reports/{reportId}`

`200 { report: ReportView, html: string | null }` (`assistant-report-view/1`): `{ id, conversationId, executionId, status: pending|available|failed|purged, title, period: { from, to, granularity, atoRange }, sections, omitted: [{ section, reason, code|null }], figures, sizeBytes, sha256, templateVersion, createdAt, deliveries: [{ id, to|null, recipientKind: self|member|domain, status: queued|sent|failed, errorCode, requestedAt, sentAt }] }` (deliveries newest first, at most 20). `html` is the stored document only while the report is `available` and its object reads back with the stored SHA-256; a purged report answers `200` with `html: null` and `to: null` on its deliveries. `400` for a non-UUID id, `404 assistant_report_not_found` for anything not the caller's. The HTML is never served as `text/html`.

## Security operations (step AI-4)

Design: [note 32](../plan/steps/32-ai-chat-security-operations.md) (D3, D9, D10, D11), contracts §35.4. No assistant route changed; AI-4 adds tools, guard kinds and outcome wording. Tools and risks: [CHAT_TOOL_REGISTRY.md](CHAT_TOOL_REGISTRY.md#security-operations-tools-ai-4) and the generated [matrix](UI_TO_CHAT_CAPABILITY_MATRIX.md).

### New guard kinds and message

`not_self_field` and `require_read_value` are after-read guards on the precondition target. Both guard `ato_responses_approve` and `ato_responses_reject` with the message key `ato_four_eyes`; a refusal at proposal is the usual `denied_guard` (`tool.denied`, no confirmation, only the precondition read `GET /ato/responses/{responseId}` was sent, never `/approve` or `/reject`):

```json
{
  "status": "denied",
  "decision": "denied_guard",
  "message": "This response needs a different person to decide it. The person who requested a response, or who created the API key that requested it, can never approve or reject it, and deciding needs a session signed in with MFA. Ask another responder to decide it in chat or on the Responses page."
}
```

At confirm the guards are evaluated again on the fresh read: a refusal fails the row with `403 assistant_action_not_allowed` (audit `assistant.confirmation_refused`, `reason: guard`, `guard: not_self_field | require_read_value`); a response that left `pending_approval` fails with `409 assistant_confirmation_state_changed` (its `status` is a state field). The api's own refusal when a request reaches it is `403 ato_approval_self`. The portal's denied card shows the message and an "Open Responses" link to `/ato/responses`.

### Outcome texts

| Tool                                                                                                                                                                                                                                                                              | HTTP | Line to the model (next turn)                                                                                                                  | Portal card                                                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `report_send_email`, `ato_providers_health_check`, `ato_providers_backfill`, `ato_account_mailbox_refresh`, `attachment_rescans_request`, `message_lifecycle_rescan`, `users_resend_invitation`, `webhooks_test`, `webhook_deliveries_replay`, `webhook_deliveries_create_replay` | 202  | "the user confirmed it; it was queued (HTTP 202)."                                                                                             | "Done: the action was applied."                                                                                                     |
| `ato_responses_request`                                                                                                                                                                                                                                                           | 201  | "the user confirmed it; the response was requested (HTTP 201). If it needs approval, another responder must approve it; the requester cannot." | "Requested. If this action needs approval, another responder must approve it before it runs (you cannot approve your own request)." |
| other `202` (quarantine and legacy releases)                                                                                                                                                                                                                                      | 202  | "(HTTP 202, accepted: waiting for approval by another person)"                                                                                 | "Submitted for approval: another person must approve it before it takes effect."                                                    |

The created response's status (`pending_approval`, or `succeeded` for a low-impact gateway action) is in the result envelope the model receives. A rescan dry run answers `200` and gets the plain success line.

### Redacted inputs

`dlp_patterns_test` (a side-effect-free `POST` read) stores `body.sample` and `body.pattern` as `"[redacted]"` in the execution's `params_redacted` and in its audit params (`exact: false`); the loopback request carries the real values and the result card shows the api's answer (matches, never the sample).

### New reads

| Tool                           | Route                                         | Permission                                                                  |
| ------------------------------ | --------------------------------------------- | --------------------------------------------------------------------------- |
| `bec_trusted_senders_get`      | `GET /api/v1/bec/trusted-senders/{id}`        | `bec:read` (API keys allowed)                                               |
| `bec_feedback_get_suppression` | `GET /api/v1/bec/suppressions/{id}`           | `bec:read` (API keys allowed)                                               |
| `dlp_exceptions_get`           | `GET /api/v1/dlp/exceptions/{id}`             | `dlp:read` (API keys allowed)                                               |
| `threat_indicators_get`        | `GET /api/v1/platform/threat-indicators/{id}` | `platform:threat_intel_manage` (platform users with MFA; the id is decimal) |

Another organization's or an unknown id is `404` with the module's not-found code (`bec_trusted_sender_not_found`, `bec_suppression_not_found`, `dlp_exception_not_found`, `threat_indicator_not_found`).

### Platform-only tools

The nine platform tools of AI-4 (threat hashes and indicators, attachment rescans, scan training, dead-letter replay, `threat_indicators_get`) never appear in `GET /assistant/tools` for customer users or for platform users under an override; a forced call is `denied_permission` with no loopback request.

## Compliance and integrations (step AI-5)

Design: [note 33](../plan/steps/33-ai-chat-compliance-integrations.md) (D3–D5, D7, D8, D11), contracts §35.5. No assistant route changed and no confirm code was added; AI-5 adds tools, read-relative escalation, three guards, a server-filled impact token and outcome wording. Tools and risks: [CHAT_TOOL_REGISTRY.md](CHAT_TOOL_REGISTRY.md#compliance-and-integrations-tools-ai-5) and the generated [matrix](UI_TO_CHAT_CAPABILITY_MATRIX.md).

### Confirm codes in AI-5

| Code                                   | HTTP | When (AI-5)                                                                                                                                                                                                 |
| -------------------------------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assistant_action_not_allowed`         | 403  | One of the three new guards refused at confirm on the fresh read (the policy became the default, the capture is no longer `failed`, the case got an active hold)                                            |
| `assistant_confirmation_state_changed` | 409  | A state field changed since the proposal; for mail-flow apply and disconnect also when the fresh preview's change set or warnings differ from the proposal's                                                |
| `assistant_confirmation_tool_changed`  | 409  | The effective risk recomputed from the stored arguments **and the stored snapshot** differs from the stored risk                                                                                            |
| route codes                            | 4xx  | A failed confirmed write keeps the route's code, e.g. `409 impact_changed` (the impact token expired or the connection changed), `422` of a first-time Google grant verify (no `subjectEmail` through chat) |

### New denial messages (`denied_guard`)

The proposal guards answer `denied_guard` with a fixed English message (no values), and nothing is stored but the refused execution; only the precondition read was sent:

| Tool                       | Message key                | Message                                                                                                                                                                                                      |
| -------------------------- | -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `archive_retention_delete` | `retention_default_policy` | "The default retention policy cannot be deleted. Choose another default in the archive settings first (Retention and lock in the portal)."                                                                   |
| `archive_admin_retry`      | `capture_not_retryable`    | "Only a failed capture can be retried. A lost capture cannot be recovered, and a pending one is still being retried by the archive."                                                                         |
| `ediscovery_cases_close`   | `case_active_holds`        | "This case still has active legal holds, so it cannot be closed. Legal holds are released only on the Legal holds page in the portal by a person with the legal-hold permission; close the case after that." |

The portal's "Not allowed in chat" card links to the page that resolves each refusal: Retention and lock (`/archive/retention`), Legal holds (`/legal-holds`) and the Capture issues tab (`/archive/retention?tab=capture`). A `denied_not_applicable` card ("Not available in chat; use the portal page") for `legal_holds_release` links to Legal holds, for `archive_messages_dispose` and `archive_admin_rotate` to Retention and lock (review queue, immutability and keys), and for provider grant creation, credentials, consent completion and validation runs to Provider connections. The api's own refusals (`409 archive_retention_policy_is_default`, `409 archive_capture_retry_not_allowed`, `409 ediscovery_case_has_active_holds`) stay the authority when a request reaches them.

### Server-filled impact token

`provider_mail_flow_apply` (pass only `id` and `body.change`) and `provider_connections_disconnect` (pass only `id`) never take an impact token from the model: the proposal sends the user's own `POST /api/v1/provider-connections/{id}/mail-flow/preview` (`{ change }`, or `{ change: { kind: "disable" } }` for disconnect), shows the preview's change set and warning codes in the card, and stores the returned token in the confirmation request only; confirm previews again and compares. A non-2xx preview fails the proposal with its own code (for example `409 outbound_active`); a 2xx preview without a usable token fails it with `502`. The token never appears in the stream, the confirmation view, the execution view or the audit params.

### Omitted inputs

`intake_sources_get` has no `reveal` input and `provider_grants_verify` no `body.subjectEmail` (`omitInputs`); a forced value is `denied_schema` with no loopback request.

### Outcome texts

| Tool                                                                     | HTTP | Line to the model (next turn)                                                                                    |
| ------------------------------------------------------------------------ | ---- | ---------------------------------------------------------------------------------------------------------------- |
| `ediscovery_exports_create`                                              | 202  | "the user confirmed it; the export was queued (HTTP 202). It is downloaded only on the case page in the portal." |
| `ediscovery_searches_create`                                             | 202  | "the user confirmed it; the search was queued (HTTP 202); follow it with `ediscovery_searches_get`."             |
| `provider_health_check_now` (and the ten queued tools listed under AI-4) | 202  | "the user confirmed it; it was queued (HTTP 202)."                                                               |

The portal card of an executed export says "Export queued. Download it on the case page when it is ready; downloads never go through chat." with the link "Open the case" (`/ediscovery/{caseId}`).

### New read

| Tool                          | Route                                            | Permission                                              |
| ----------------------------- | ------------------------------------------------ | ------------------------------------------------------- |
| `archive_admin_capture_issue` | `GET /api/v1/archive/capture-issues/{messageId}` | `journal:manage` or `archive:manage` (API keys allowed) |

The capture intent of the message in the capture-issue list's view, for any intent status; no intent, an unknown or another organization's message is `404 archive_capture_issue_not_found`, a non-uuid `400`. `provider_mail_flow_preview` (`POST …/mail-flow/preview`, `integration:manage`) is a side-effect-free read tool; its envelope and card never contain the impact token.
