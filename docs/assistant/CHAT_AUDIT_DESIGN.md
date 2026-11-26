# Chat audit design

Every tool the assistant runs, or refuses to run, leaves two records: an execution row in `ai_chat_tool_executions` (conversation context, kept with the conversation) and an `audit_logs` row (the organization's audit trail, append-only). The operation itself writes its own audit rows exactly as it does for the portal, and they share a correlation id with the execution. Normative sources: [design D12](../plan/steps/28-ai-chat-management.md#d12-storage-retention-and-audit-adr-0094), [ADR-0094](../architecture/adr/0094-assistant-conversation-storage-retention-audit.md), [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1) (Audit); confirmations (step AI-2): [design note 29 D11](../plan/steps/29-ai-chat-confirmations-mail-writes.md#d11-metrics-logs-audit), [contracts §35.1](../architecture/contracts.md#351-confirmations-step-ai-2); identity and tenant administration (step AI-3): [design note 30 D10, D13](../plan/steps/30-ai-chat-identity-tenant-admin.md#d13-audit-and-data-handling-summary), [contracts §35.2](../architecture/contracts.md#352-identity-and-tenant-administration-tools-step-ai-3).

## Execution rows (`ai_chat_tool_executions`)

One row per `call_tool` and per "Load more", allowed or denied (I6), written in one writer transaction together with its audit row.

| Field                                               | Content                                                                                                                                                                                                                                                |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `public_id`                                         | Execution id (UUIDv7); the audit row's resource id                                                                                                                                                                                                     |
| `organization_id`, `user_id`                        | Owner, from the principal (the override's target organization under a platform override)                                                                                                                                                               |
| `conversation_id`, `turn_id`, `parent_execution_id` | Context; `turn_id` is NULL and `parent_execution_id` set for a "more" page and for a confirmed write (the parent is the proposal)                                                                                                                      |
| `seq`                                               | Conversation-wide sequence (`r<seq>` refs)                                                                                                                                                                                                             |
| `tool_name`, `operation_id`, `http_method`          | What was asked                                                                                                                                                                                                                                         |
| `access`, `risk`                                    | Registry classification at execution time                                                                                                                                                                                                              |
| `decision`                                          | `allowed`, `denied_permission`, `denied_unknown_tool`, `denied_disabled`, `denied_not_applicable`, `denied_schema`, `denied_ref`, `denied_budget`, `denied_guard` (AI-3: a proposal guard refused the write; no loopback request, no confirmation row) |
| `status`                                            | `succeeded`, `failed` (coded API error), `refused` (any denial), `timeout`, `pending_confirmation` (a write proposal, AI-2)                                                                                                                            |
| `http_status`, `error_code`                         | Result of the loopback call (NULL when refused before it)                                                                                                                                                                                              |
| `correlation_id`                                    | `<turn correlation id>.<seq>`, sent as `x-correlation-id` on the loopback call                                                                                                                                                                         |
| `params_redacted`                                   | Validated arguments with credential-like keys removed (≤ 4 KiB)                                                                                                                                                                                        |
| `resource_ref`                                      | The single resource targeted (first path parameter, a public id), when there is one                                                                                                                                                                    |
| `result_card`, `result_refs`, `next_cursor`         | Content: the card shown to the user, the ref map, the API cursor for "more"; purged with the conversation content                                                                                                                                      |
| `latency_ms`, `created_at`                          | Timing                                                                                                                                                                                                                                                 |

## Audit rows (`audit_logs`)

| Action                             | Resource type                   | Resource id            | Written when                                                                                                                                                                                                                                                                                                               |
| ---------------------------------- | ------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `assistant.tool_executed`          | `assistant_tool_execution`      | execution public id    | A tool call passed the executor's checks (any HTTP outcome)                                                                                                                                                                                                                                                                |
| `assistant.tool_denied`            | `assistant_tool_execution`      | execution public id    | The executor refused the call (any `denied_*` decision; for `denied_guard` the metadata adds `guard`: `not_self_user`, `deny_values` or `deny_permission_change`, AI-3; `not_self_field` or `require_read_value`, AI-4)                                                                                                    |
| `assistant.conversation_deleted`   | `assistant_conversation`        | conversation public id | The user cleared a conversation (content purged at once)                                                                                                                                                                                                                                                                   |
| `assistant.settings_updated`       | `assistant_settings`            | organization public id | An `assistant:configure` holder changed the tenant settings (incl. the external-processing acknowledgement)                                                                                                                                                                                                                |
| `assistant.confirmation_requested` | `assistant_action_confirmation` | confirmation public id | A write was proposed (with `assistant.tool_executed`, status `pending_confirmation`) (AI-2)                                                                                                                                                                                                                                |
| `assistant.confirmation_executed`  | `assistant_action_confirmation` | confirmation public id | The user confirmed and the operation answered 2xx (including `202` approval pending)                                                                                                                                                                                                                                       |
| `assistant.confirmation_failed`    | `assistant_action_confirmation` | confirmation public id | The confirmed operation refused (non-2xx), the state changed at confirm, a tampered row, the tool changed, or the sweeper found it stuck in `executing` (`outcome_unknown`)                                                                                                                                                |
| `assistant.confirmation_cancelled` | `assistant_action_confirmation` | confirmation public id | The user cancelled, the conversation was deleted, or the fifth wrong token cancelled it                                                                                                                                                                                                                                    |
| `assistant.confirmation_expired`   | `assistant_action_confirmation` | confirmation public id | A confirm after the expiry, or the sweeper expired a pending row                                                                                                                                                                                                                                                           |
| `assistant.confirmation_refused`   | `assistant_action_confirmation` | confirmation public id | A confirm or cancel was refused (metadata `reason`: session mismatch, not pending, token, digest, re-auth required or failed, turn in progress, …; AI-3: `guard` with the `guard` kind when a proposal guard refused at confirm, the row then `failed` with `assistant_action_not_allowed`); `404` answers are not audited |
| `assistant.report_generated`       | `assistant_report`              | report public id       | (AI-R) `report_generate` stored a report (in the execution's persist transaction, next to `assistant.tool_executed`)                                                                                                                                                                                                       |
| `assistant.report_email_requested` | `assistant_report_delivery`     | delivery public id     | (AI-R) A confirmed `report_send_email` queued a delivery (in the confirm's transaction, with the delivery row and its outbox event)                                                                                                                                                                                        |

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

Confirmation metadata (AI-2; keys chosen to survive the credential-key scrub, so never ending in `code`, `token` or `key`):

```json
{
  "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
  "executionId": "0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05",
  "resultExecutionId": "0193a1c2-7e70-7c8e-90b7-8f6b2c7d0e07",
  "tool": "policy_management_remove",
  "operationId": "PolicyManagementController_remove_v1",
  "risk": "high",
  "requiresReauth": true,
  "reauthUsed": true,
  "status": "executed",
  "httpStatus": 200,
  "error": null,
  "correlationId": "7c1d0e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f.4"
}
```

Since AI-3 `risk` is the **effective** risk (the registry risk raised by the spec's escalation rules on the final arguments) and `assistant.confirmation_requested` adds `baseRisk`, the registry risk; they differ only when an escalation matched (for example `webhooks_update` with a new URL: `risk: "high"`, `baseRisk: "low"`). Both keys, and `guard`, survive the credential-key scrub.

`reconciledFrom: "assistant_confirmation_outcome_unknown"` is added to the `assistant.confirmation_executed` / `_failed` row of a write that outlived the outcome-unknown sweep (step AI-2 review): the sweep's `assistant.confirmation_failed` (system actor) stays, and the real outcome replaces the row's `outcome_unknown`.

`assistant.confirmation_refused` adds `reason`. Neither the token, its hash, the digest input, the request body nor the password or code is ever written to an audit row or a log.

Mapping to the brief's audit fields: user → actor; tenant → `organization_id`; conversation → `conversationId`; tool → `tool`; API operation → `operationId`; validated parameters (redacted) → `params`; permission decision → `decision`; confirmation → the `assistant.confirmation_*` rows (AI-2, ADR-0093); execution status → `status`, `httpStatus`, `error`; resource → `resourceRef`; timestamp → `created_at`.

## Report audit (step AI-R)

Design [note 31](../plan/steps/31-ai-chat-reports.md) D11. Keys are chosen to survive the credential-key scrub (no key ends in `code`; error codes are stored under `error`).

`assistant.report_generated` (resource `assistant_report`):

```json
{
  "reportId": "0193a0c4-0000-7000-8000-00000000a001",
  "conversationId": "0193a1c2-7a10-7c3e-9a51-2f0b6c1d4e01",
  "executionId": "0193a1c2-7d50-7a6c-8e95-6d4f0a5b8c05",
  "period": {
    "from": "2026-11-16T09:00:00.000Z",
    "to": "2026-11-23T09:00:00.000Z",
    "granularity": "day",
    "atoRange": "7d"
  },
  "sections": ["summary", "traffic", "threats", "domains", "delivery", "processing", "url_clicks"],
  "omitted": [{ "section": "quarantine", "reason": "permission", "error": "quarantine:read" }],
  "sizeBytes": 182344,
  "sha256": "<64 hex of the stored HTML>",
  "templateVersion": "assistant-report/1",
  "sources": [{ "tool": "reports_traffic", "outcome": "ok", "httpStatus": 200, "error": null }]
}
```

`sources` lists every planned source with its outcome (`ok`, `omitted_permission`, `unavailable`, `unexpected`) and HTTP status; a source the principal may not read appears without a request. No figure, data string, display name or HTML is written to the audit row or the report row.

`assistant.report_email_requested` (resource `assistant_report_delivery`): `{ deliveryId, reportId, confirmationId, executionId, recipientKind: self|member|domain, recipientDomain, recipientSha256, correlationId }`. It sits next to the AI-2 rows of the same confirmation (`assistant.confirmation_requested`, `assistant.confirmation_executed`); the audit row's own `correlation_id` is the confirm request's, the metadata's `correlationId` the result execution's (the same value the delivery row and the outbox event carry).

Refusals: a refused recipient is audited only by `assistant.tool_denied` with `guard: report_recipient_not_allowed`, `recipientDomain` and `recipientSha256` (SHA-256 of the lower-cased address); the execution's stored `params` show `to: "[redacted]"`. The daily limits add `scope: user|tenant` to `assistant.tool_denied` (`denied_budget`, code `assistant_report_email_limit` or `assistant_report_generation_limit`); a platform principal without an override gets `guard: report_needs_organization`.

The notification-worker writes no audit row: the delivery's outcome is the row's `status` (`sent` with the SMTP Message-ID, or `failed` with a code), shown in the report card (R-6). Report and delivery rows follow the conversation (content purge clears `recipient_address`; hard delete with the conversation; organization purge first); the audit rows stay with the audit retention.

## Security operations audit (step AI-4)

Design: [note 32 D13](../plan/steps/32-ai-chat-security-operations.md#d13-audit-and-data-handling). No new audit action and no new table: every AI-4 proposal, guard denial, confirmation and confirmed operation is audited as in AI-2/AI-3.

- **Guard metadata values.** `guard` gains `not_self_field` (the requester of an ATO response tried to approve or reject it) and `require_read_value` (the api's `canDecide` was not `true` for the caller: the creator of the requesting API key, or a session without MFA), on `assistant.tool_denied` (proposal) and on `assistant.confirmation_refused` with `reason: guard` (confirm).
- **Effective risk.** An escalated AI-4 proposal stores `risk: "high"` with `baseRisk` the registry risk (for example `ato_accounts_set_override` with `verdict: "benign"`: `risk: "high"`, `baseRisk: "medium"`).
- **Redacted parameters.** For `dlp_patterns_test` the execution's `params_redacted` and the audit params of `assistant.tool_executed` / `assistant.tool_denied` hold `"[redacted]"` for `body.sample` and `body.pattern` (`exact: false`).
- **The operation's own rows**, correlated by the execution's correlation id (below): the `ato.response_*` rows of the request, decision and outcome, `ato.override_set` / `ato.override_cleared`, `ato.trusted_context_added` / `ato.trusted_context_removed`, `ato.account_protected` / `ato.account_unprotected`, `ato.mailbox_state.refresh_requested`, `ato.settings_updated`, the IdP integration rows `ato.provider.bound`, `.updated`, `.paused`, `.resumed`, `.unbound`, `.backfill_requested`, `.health_check_requested`; `dlp_*.created` / `.updated` / `.deleted` and the compliance rows; the `bec_*` rows; `incident.*`; `risk_profile.*`; and, for platform users, `threat_hash.*`, `threat_indicator.*`, `attachment_rescan.*`, `dead_letter.replayed`, `scan_training.*` (organization NULL or the named organization, as the operation writes them). The exact action names are those of each module (see [docs/security/rbac.md](../security/rbac.md) and the module docs); the assistant does not add or rename any.
- **Data.** No email content is involved; summaries hold account addresses, incident subjects and response reasons (already shown to the same user, marked untrusted where they come from another person or the mail path) and are purged with the conversation content.

## Compliance and integrations audit (step AI-5)

Design: [note 33 D12](../plan/steps/33-ai-chat-compliance-integrations.md#d12-audit-and-data-handling). No new audit action and no new table: every AI-5 proposal, guard denial, confirmation and confirmed operation is audited as in AI-2..AI-4.

- **Guard metadata values.** `guard: require_read_value` now also for the three AI-5 guards (message keys `retention_default_policy`, `capture_not_retryable`, `case_active_holds`), on `assistant.tool_denied` (proposal) and on `assistant.confirmation_refused` with `reason: guard` (confirm, re-evaluated on the fresh read).
- **Effective risk.** A proposal escalated by a read-relative condition stores `risk: "high"` with `baseRisk` the registry risk (for example `archive_retention_update` shortening 365 → 30 days: `risk: "high"`, `baseRisk: "medium"`); the confirm route recomputes it from the stored snapshot.
- **The preview is audited twice per mail-flow confirmation.** `provider_mail_flow_apply` and `provider_connections_disconnect` run `POST …/mail-flow/preview` once at proposal and once at confirm (step 12), so the api writes `integration.mail_flow_previewed` (kind and counts only) **twice** for one confirmed apply or disconnect, then `integration.mail_flow_applied` or `integration.connection_disconnected`. A read-only `provider_mail_flow_preview` call writes one. The impact token is never in `params_redacted`, an audit row's params or a log line.
- **Export audit chain** (asserted by `assistant-writes-compliance.test.ts`). `assistant.tool_executed` (the proposal, `pending_confirmation`) → `assistant.confirmation_requested` → (`assistant.confirmation_refused` when a confirm arrived without re-authentication) → `assistant.confirmation_executed` (`reauthUsed: true`, the result execution's correlation id) → `ediscovery.export_requested` (the operation's row, carrying the result execution's correlation id) → later `ediscovery.export_completed` or `ediscovery.export_failed` written by the archive-worker → a download grant and the download only through the portal (`ediscovery.download_granted`, `ediscovery.downloaded`; no assistant correlation, because `ediscovery_exports_grant` is not a chat tool).
- **Refused critical operations.** `legal_holds_release`, `archive_messages_dispose` and `archive_admin_rotate` are `denied_not_applicable` (`assistant.tool_denied`, no loopback request, no `legal_hold.released` row).
- **The operation's own rows**, correlated by the execution's correlation id: `archive.retention_policy_created` / `_updated` / `_deleted`, `archive.settings_updated`, `archive.capture_retried`, the journaling settings rows of step 8.6, `journal_intake.source_updated` / `_paused` / `_resumed` / `_disabled`, `journal_intake.attested`, `ediscovery.case_created` / `_updated` / `_closed`, `legal_hold.created`, `ediscovery.search_requested`, `ediscovery.review_tagged`, `ediscovery.export_requested`, and `integration.connection_created` / `_updated` / `_disconnected`, `integration.attestation_recorded`, `integration.domains_linked`, `integration.grant_revoked`, `integration.grant_verification_requested`, `integration.health_check_requested`, `integration.mail_flow_previewed`, `integration.mail_flow_applied`.
- **Data.** No message body, attachment, export content, intake address or impact token is stored in `ai_chat_*` rows, except the impact token inside the confirmation's stored request (`request`, valid ≤ 15 minutes, bound to the user and the change set; the confirmation view and summary never contain it). Summaries hold policy, case, hold, source and connection names (untrusted, already visible to the same user) and counts, and are purged with the conversation content.

## Hardening and operations audit (step AI-6)

Design: [note 34](../plan/steps/34-ai-chat-hardening-operations.md) D1–D7, [contracts §35.6](../architecture/contracts.md#356-hardening-and-operations-step-ai-6). New `assistant.*` actions (actor = the signed-in user unless noted; metadata never carries content, a key or a token):

| Action                               | Resource type (id)                                      | Metadata                                                                                 | When                                                                                              |
| ------------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `assistant.feedback_recorded`        | `assistant_feedback` (feedback public id)               | `{ messageId, conversationId, rating, reason }`, never the comment                       | `PUT /assistant/messages/{id}/feedback` (create or change)                                        |
| `assistant.feedback_removed`         | `assistant_feedback`                                    | as above                                                                                 | `DELETE …/feedback`                                                                               |
| `assistant.audit_viewed`             | `assistant_conversation` (conversation public id)       | `{ turns, executions, underPlatformOverride }` (counts)                                  | Every `GET /assistant/admin/conversations/{id}` (the audit detail of someone else's conversation) |
| `assistant.report_job_queued`        | `assistant_report_job` (job public id)                  | the report and execution ids, period, sections                                           | With `assistant.tool_executed` when `report_generate` queues a background report (D5)             |
| `assistant.report_generated`         | `assistant_report`                                      | AI-R metadata plus `{ async: true, jobId }`; actor = the user of the job                 | A background job finished the report (written by the api-assistant consumer)                      |
| `assistant.provider_key_set`         | `assistant_provider_key` (the organization's public id) | `{ provider, model, fingerprint, outcome }`                                              | A tenant key was probed and stored                                                                |
| `assistant.provider_key_removed`     | `assistant_provider_key`                                | `{ provider, model, fingerprint, outcome }`                                              | `DELETE /assistant/settings/provider-key`                                                         |
| `assistant.provider_key_validated`   | `assistant_provider_key`                                | `{ provider, model, fingerprint, outcome }`                                              | `POST …/provider-key/validate`                                                                    |
| `assistant.provider_key_invalidated` | `assistant_provider_key`                                | `{ provider, model, fingerprint, outcome }`; actor = the user whose turn met the refusal | A turn's model call with the tenant key answered `401/403` (the key becomes `invalid`)            |

`assistant.settings_updated` additionally records the new `dataSharing` and `useTenantKey` state (like `enabled`), never a key.

### Audit view (`audit:read`, I24)

Administrators with `audit:read` read assistant activity of their organization through three metadata-only routes ([API](CHAT_API_DOCUMENTATION.md#hardening-and-operations-step-ai-6)): the conversation list (owner, status, timestamps, turn and segment counts, content purged, platform override flag, totals of tokens, estimated cost, tool calls, denied calls, confirmations by status, reports and ratings; **no title**), the conversation detail (turns with provider, model, key source, data-sharing level, fallback-from, prompt and registry version, rounds, tokens, cost, latency and error code; executions with operation id, decision, risk, HTTP status, error code and `params_redacted` exactly as stored; confirmations; reports with sections, size, async flag, job status and deliveries showing the recipient **domain** only; ratings without comments) and the execution search over 92-day windows (by user, tool, module, decision, status, risk, access, correlation id or conversation). Every detail read writes `assistant.audit_viewed`. Message text, titles, provider transcripts, result cards, report HTML and feedback comments are never returned there (Q9 kept). The execution rows and the `assistant.tool_executed` audit rows are the same record seen from two places; the operation's own audit rows still join by correlation id (below).

### Background report jobs

A queued report produces, in order: `assistant.tool_executed` (the `report_generate` execution, HTTP 202) and `assistant.report_job_queued` in the turn's transaction; then, in the consumer, the loopback source reads with the job token (each audited by the source route as for any `GET`, correlation `<job correlation>.<n>`, the original execution id in `x-eg-assistant-execution`); finally `assistant.report_generated` with `{ async: true, jobId }`. A job that fails writes no `assistant.report_generated`; its `error_code` is on `ai_chat_report_jobs` and on the report row. Refused job tokens are not audit rows: they are counted (`api_assistant_job_token_refusals_total`) and logged (route template and job id) and alert as critical.

## Correlation with the operation's own audit rows

The loopback request carries `x-correlation-id: <turn correlation id>.<execution seq>`. The api's correlation middleware accepts it, so every audit row the operation writes itself (audited reads such as archive record reads and audit searches, and every confirmed write since AI-2) carries the same `correlation_id` as the `assistant.tool_executed` row. To answer "what did the assistant do, and what did it cause":

1. Search the audit log for `assistant.tool_executed` / `assistant.tool_denied` (audit page or `GET /audit/logs`, `audit:read`), optionally by user or time range.
2. Take the row's `correlationId` and search by correlation id: the operation's own rows appear next to it.
3. With the execution id, the owner can open the execution (`GET /assistant/executions/{id}`); administrators cannot read conversations (PO Q9).

Proven by `apps/api/integration/assistant.test.ts` ("records the execution correlation id on the audited operation's own audit row") and, for writes, `assistant-confirmations.test.ts` (the confirmed create's `policy.created` row carries the result execution's correlation id) and the AI-3 write suites (`assistant-writes-identity`, `-domains`, `-tenant-admin`: `user.invited`, `user.roles_changed`, `apikey.revoked`, `domain.*`, `webhook.*`, `organization.*`, `scan_settings.*` … rows carry the result execution's correlation id). The confirmed write's correlation id is `<confirm request correlation id>.<seq>`; the confirmation's own audit rows link the proposal (`executionId`) and the write (`resultExecutionId`). Denied calls produce no request and so no operation audit row (`assistant-tools.test.ts`).

## Retention

| Record                                                                                                                           | Retention                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit_logs` rows (`assistant.*`)                                                                                                | Audit retention: kept until an operator exports and drops old partitions deliberately ([retention.md](../database/retention.md)); never deleted by the assistant, not by conversation deletion or organization purge |
| Execution metadata (`ai_chat_tool_executions` row fields)                                                                        | Hard-deleted with the conversation after `ASSISTANT_EXECUTION_RETENTION_DAYS` (default 400 days)                                                                                                                     |
| Execution content (`result_card`, `result_refs`, `next_cursor`) and confirmation content (`request`, `preconditions`, `summary`) | Set to NULL at the conversation's `purge_after` (tenant retention, default 30 days after the last turn) and when the user clears the conversation                                                                    |
| Confirmation rows                                                                                                                | Hard-deleted with their proposal execution (FK cascade); pending rows expire after `ASSISTANT_CONFIRMATION_TTL_SECONDS`                                                                                              |
| Organization deletion                                                                                                            | `AssistantTenantDataRepository` removes all `ai_chat_*` rows (confirmations first); audit rows stay                                                                                                                  |

Logs and metrics are not an audit channel: logs carry ids and codes only (never prompts, responses, arguments or results; AI-3: never argument values of identity changes); metrics have no organization or user labels. AI-3 adds the label values `decision="denied_guard"` on `assistant_tool_calls_total` and `outcome="refused_guard"` on `assistant_confirmations_total` (a guard refusal at confirm; a recomputed risk that differs counts as `failed`).
