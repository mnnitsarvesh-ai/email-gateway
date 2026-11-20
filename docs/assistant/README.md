# AI assistant (chat-based management)

The AI assistant lets an authorized user manage the Email Security Gateway in natural language from the admin portal: a chat panel in the header ("Ask AI", `Ctrl/Cmd+J`) and the full-screen `/assistant` page. Every action the assistant takes is one existing `/api/v1` operation, executed with the user's own credential through the api's own HTTP pipeline, so permissions, tenant scope, MFA, rate limits, validation, masking and audit are exactly those of the portal.

**Status (step AI-1, 2026-11-20):** built and verified locally, not yet committed. AI-1 ships the foundation and every eligible **read** operation as a chat tool (174 tools). Writes (create, update, enable, release, …) come in AI-2 … AI-5 behind server-issued confirmations; see [CHAT_IMPLEMENTATION_STATUS.md](CHAT_IMPLEMENTATION_STATUS.md). Not verified: calls to a real LLM provider, Kubernetes, CI ([CHAT_TESTING_REPORT.md](CHAT_TESTING_REPORT.md)).

## Documents

| Document                                                           | Contents                                                                                                                                                  |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [AI_CHAT_ARCHITECTURE.md](AI_CHAT_ARCHITECTURE.md)                 | Components, data flow, loopback execution, provider abstraction, context and segments, isolation from the mail path, configuration keys                   |
| [CHAT_TOOL_REGISTRY.md](CHAT_TOOL_REGISTRY.md)                     | How tools are generated from OpenAPI, completeness and consistency checks, naming, risk and confirmation rules, how later steps add tools, current counts |
| [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) | Every API operation (= every portal action) with its chat tool, permission, risk, confirmation, status and test coverage (generated; do not edit by hand) |
| [CHAT_API_DOCUMENTATION.md](CHAT_API_DOCUMENTATION.md)             | The 15 assistant routes, examples, the `assistant-stream/1` event stream, error codes, rate limits and budgets                                            |
| [AI_SECURITY_STANDARDS.md](AI_SECURITY_STANDARDS.md)               | Threat model and controls (prompt injection, exfiltration, privilege escalation, IDOR, replay), data handling, what never reaches the model               |
| [CHAT_RBAC_MAPPING.md](CHAT_RBAC_MAPPING.md)                       | `assistant:use` / `assistant:configure` per system role, tool permissions, platform-only tools, platform override                                         |
| [CHAT_AUDIT_DESIGN.md](CHAT_AUDIT_DESIGN.md)                       | `ai_chat_tool_executions`, `assistant.*` audit rows, correlation with the operation's own audit rows, retention                                           |
| [CHAT_DATABASE_SCHEMA.md](CHAT_DATABASE_SCHEMA.md)                 | The six `ai_chat_*` tables, indexes, retention and purge, rollback, Redis keys                                                                            |
| [CHAT_TESTING_REPORT.md](CHAT_TESTING_REPORT.md)                   | What ran in AI-1 (unit, e2e, integration, Playwright) with numbers, and what could not be verified                                                        |
| [CHAT_IMPLEMENTATION_STATUS.md](CHAT_IMPLEMENTATION_STATUS.md)     | Per module: implemented reads, missing writes by phase, not-applicable operations with reasons; known limitations                                         |

## Sources of truth

- Design note: [docs/plan/steps/28-ai-chat-management.md](../plan/steps/28-ai-chat-management.md) (program AI-1 … AI-6, decisions D1–D14, data model, contracts, test plan, deviations §12, verification §13).
- Brief: [docs/plan/briefs/ai-chat-management.md](../plan/briefs/ai-chat-management.md).
- ADRs: [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md) (architecture, loopback tools, registry), [ADR-0092](../architecture/adr/0092-llm-provider-abstraction-and-data-handling.md) (providers, data handling), [ADR-0093](../architecture/adr/0093-assistant-action-confirmation.md) (confirmations, built in AI-2), [ADR-0094](../architecture/adr/0094-assistant-conversation-storage-retention-audit.md) (storage, retention, audit).
- Contracts: [contracts §35](../architecture/contracts.md#35-ai-assistant-step-ai-1) (routes, stream, documents, executor decisions, loopback request, risk rules, data, audit, Redis keys, configuration).
- Code: `packages/assistant` (`@email-gateway/assistant`: providers, prompt, context, results, registry), `apps/api/src/modules/assistant` (Nest module), `apps/admin-portal/src/features/assistant` (panel, page, settings tab).

## Enabling it locally

The local stack runs the deterministic **fake** provider: no LLM API key, no network call. Three switches must be on, plus the permission:

1. Platform: `ASSISTANT_ENABLED=true` and `ASSISTANT_PROVIDER=fake` in the repository `.env` for an api started on the host (`pnpm --filter @email-gateway/api dev`). The api **container** of Docker Compose receives no `ASSISTANT_*` key and runs `NODE_ENV=production`, where the fake is refused; for a container test stack add [tests/portal-e2e/assistant.override.yml](../../tests/portal-e2e/assistant.override.yml) when recreating the api.
2. Organization: a platform operator enables the feature `ai_assistant` (`PUT /api/v1/organizations/{id}/features/ai_assistant` `{ "enabled": true }`, or the organization page in the portal).
3. Tenant: an organization admin (`assistant:configure`) opens **Settings → AI assistant**, ticks the external-processing acknowledgement and turns it on.

Then ask, for example, "show active policies", "what was quarantined today", "journaling status", or use the fake's directives `/tool <tool name> <json arguments>`, `/describe <tool name>` and `/text <text>`. A real provider (`anthropic`, `openai`, `azure_openai`) needs its API key in the environment or a secret file; see [AI_CHAT_ARCHITECTURE.md](AI_CHAT_ARCHITECTURE.md#configuration) and [AI_SECURITY_STANDARDS.md](AI_SECURITY_STANDARDS.md#data-handling).
