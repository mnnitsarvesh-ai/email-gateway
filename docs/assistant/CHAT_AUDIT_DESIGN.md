# Chat audit design

Every tool the assistant runs, or refuses to run, leaves two records: an execution row in `ai_chat_tool_executions` (conversation context, kept with the conversation) and an `audit_logs` row (the organization's audit trail, append-only). The operation itself writes its own audit rows exactly as it does for the portal, and they share a correlation id with the execution. Normative sources: [design D12](../plan/steps/28-ai-chat-management.md#d12-storage-retention-and-audit-adr-0094), [ADR-0094](../architecture/adr/0094-assistant-conversation-storage-retention-audit.md), [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1) (Audit).

## Execution rows (`ai_chat_tool_executions`)

One row per `call_tool` and per "Load more", allowed or denied (I6), written in one writer transaction together with its audit row.

| Field                                               | Content                                                                                                                                           |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `public_id`                                         | Execution id (UUIDv7); the audit row's resource id                                                                                                |
| `organization_id`, `user_id`                        | Owner, from the principal (the override's target organization under a platform override)                                                          |
| `conversation_id`, `turn_id`, `parent_execution_id` | Context; `turn_id` is NULL and `parent_execution_id` set for a "more" page                                                                        |
| `seq`                                               | Conversation-wide sequence (`r<seq>` refs)                                                                                                        |
| `tool_name`, `operation_id`, `http_method`          | What was asked                                                                                                                                    |
| `access`, `risk`                                    | Registry classification at execution time                                                                                                         |
| `decision`                                          | `allowed`, `denied_permission`, `denied_unknown_tool`, `denied_disabled`, `denied_not_applicable`, `denied_schema`, `denied_ref`, `denied_budget` |
| `status`                                            | `succeeded`, `failed` (coded API error), `refused` (any denial), `timeout`                                                                        |
| `http_status`, `error_code`                         | Result of the loopback call (NULL when refused before it)                                                                                         |
| `correlation_id`                                    | `<turn correlation id>.<seq>`, sent as `x-correlation-id` on the loopback call                                                                    |
| `params_redacted`                                   | Validated arguments with credential-like keys removed (≤ 4 KiB)                                                                                   |
| `resource_ref`                                      | The single resource targeted (first path parameter, a public id), when there is one                                                               |
| `result_card`, `result_refs`, `next_cursor`         | Content: the card shown to the user, the ref map, the API cursor for "more"; purged with the conversation content                                 |
| `latency_ms`, `created_at`                          | Timing                                                                                                                                            |

## Audit rows (`audit_logs`)

| Action                           | Resource type              | Resource id            | Written when                                                                                                |
| -------------------------------- | -------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------- |
| `assistant.tool_executed`        | `assistant_tool_execution` | execution public id    | A tool call passed the executor's checks (any HTTP outcome)                                                 |
| `assistant.tool_denied`          | `assistant_tool_execution` | execution public id    | The executor refused the call (any `denied_*` decision)                                                     |
| `assistant.conversation_deleted` | `assistant_conversation`   | conversation public id | The user cleared a conversation (content purged at once)                                                    |
| `assistant.settings_updated`     | `assistant_settings`       | organization public id | An `assistant:configure` holder changed the tenant settings (incl. the external-processing acknowledgement) |

Tool-execution metadata (scrubbed by `AuditService` like every audit row):

```json
{
  "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
  "turnId": "0193a1c2-7b20-7d4f-8b62-3a1c7d2e5f02",
  "tool": "quarantine_entries_get",
  "operationId": "QuarantineEntriesController_get_v1",
  "access": "read",
  "risk": "read",
  "decision": "allowed",
  "status": "failed",
  "httpStatus": 404,
  "error": "quarantine_entry_not_found",
  "resourceRef": "0193a1c2-0000-7000-8000-00000000bb01",
  "params": { "entryId": "0193a1c2-0000-7000-8000-00000000bb01" },
  "correlationId": "5f0c9d1e-2b3a-4c5d-8e9f-0a1b2c3d4e5f.1"
}
```

`params` is the redacted argument object capped at 2 KiB. The error code is stored under `error` (not `errorCode`): the audit scrubber drops keys ending in `code` as credential-like, so the design's `errorCode` key would have been removed (deviation recorded in the design note §12). The actor, source IP (the end user's address forwarded by the BFF) and correlation id columns are filled as for any audited request.

Mapping to the brief's audit fields: user → actor; tenant → `organization_id`; conversation → `conversationId`; tool → `tool`; API operation → `operationId`; validated parameters (redacted) → `params`; permission decision → `decision`; confirmation → AI-2 (ADR-0093); execution status → `status`, `httpStatus`, `error`; resource → `resourceRef`; timestamp → `created_at`.

## Correlation with the operation's own audit rows

The loopback request carries `x-correlation-id: <turn correlation id>.<execution seq>`. The api's correlation middleware accepts it, so every audit row the operation writes itself (audited reads such as archive record reads and audit searches; from AI-2 every write) carries the same `correlation_id` as the `assistant.tool_executed` row. To answer "what did the assistant do, and what did it cause":

1. Search the audit log for `assistant.tool_executed` / `assistant.tool_denied` (audit page or `GET /audit/logs`, `audit:read`), optionally by user or time range.
2. Take the row's `correlationId` and search by correlation id: the operation's own rows appear next to it.
3. With the execution id, the owner can open the execution (`GET /assistant/executions/{id}`); administrators cannot read conversations (PO Q9).

Proven by `apps/api/integration/assistant.test.ts` ("records the execution correlation id on the audited operation's own audit row"). Denied calls produce no request and so no operation audit row (`assistant-tools.test.ts`).

## Retention

| Record                                                          | Retention                                                                                                                                                                                                            |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_logs` rows (`assistant.*`)                               | Audit retention: kept until an operator exports and drops old partitions deliberately ([retention.md](../database/retention.md)); never deleted by the assistant, not by conversation deletion or organization purge |
| Execution metadata (`ai_chat_tool_executions` row fields)       | Hard-deleted with the conversation after `ASSISTANT_EXECUTION_RETENTION_DAYS` (default 400 days)                                                                                                                     |
| Execution content (`result_card`, `result_refs`, `next_cursor`) | Set to NULL at the conversation's `purge_after` (tenant retention, default 30 days after the last turn) and when the user clears the conversation                                                                    |
| Organization deletion                                           | `AssistantTenantDataRepository` removes all `ai_chat_*` rows; audit rows stay                                                                                                                                        |

Logs and metrics are not an audit channel: logs carry ids and codes only (never prompts, responses, arguments or results); metrics have no organization or user labels.
