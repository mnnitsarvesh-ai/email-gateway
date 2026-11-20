# Chat RBAC mapping

Who may use the assistant and which tools each user gets. Normative sources: [design D5, D13](../plan/steps/28-ai-chat-management.md#d13-tenant-settings-and-permissions), product-owner decision Q3 (2026-11-20), [docs/security/rbac.md § AI assistant](../security/rbac.md#ai-assistant-step-ai-1), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md).

## Two permissions

| Permission            | Grants                                                                                                                                                                         | Does not grant                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `assistant:use`       | The chat: status, tool list, own conversations, turns, executions, "more" pages                                                                                                | Any data access of its own: every tool still needs the operation's own permission |
| `assistant:configure` | `GET/PUT /assistant/settings` (enable with the external-processing acknowledgement, daily token budget, content retention) and `GET /assistant/usage`; Settings → AI assistant | `assistant:use`, other users' conversations                                       |

Both are tenant permissions (category `assistant`, not platform-only), catalog total 74. Custom roles get them only when an administrator adds them (`role:manage`; the caller must hold them).

## Grants per system role

From the seed catalog and the migration `20261120141509_ai_assistant` (grant-preserving `INSERT IGNORE`; nothing removed). "Enabled tools reachable" counts the 174 enabled AI-1 tools whose `x-eg-permissions` the role satisfies (`enabledTools` with the role's permission set; platform-only tools only for platform roles), computed from the catalog and the generated registry on 2026-11-20.

| System role           | `assistant:use` | `assistant:configure` | Enabled tools reachable (of 174) |
| --------------------- | :-------------: | :-------------------: | -------------------------------: |
| `super_admin`         |        ✓        |           ✓           |                              174 |
| `platform_admin`      |        ✓        |                       |                              131 |
| `organization_admin`  |        ✓        |           ✓           |                              154 |
| `domain_admin`        |        ✓        |                       |                               89 |
| `security_analyst`    |        ✓        |                       |                              139 |
| `quarantine_reviewer` |        ✓        |                       |                               43 |
| `compliance_auditor`  |        ✓        |                       |                              160 |
| `read_only_user`      |        ✓        |                       |                               97 |
| `mailbox_user`        |                 |                       |                      0 (no chat) |
| `compliance_officer`  |        ✓        |                       |                               57 |

`organization_admin` gets both through `TENANT_PERMISSIONS` (it holds every tenant permission except archive access, so archive record tools stay with archive roles, step 8.6). The end-user role `mailbox_user` does not chat in AI-1 (PO Q3); the portal shows it no entry point and `/assistant` is forbidden (Playwright `assistant.spec.ts`).

## Gates in order

1. Platform switch `ASSISTANT_ENABLED` (`503 assistant_disabled`).
2. Organization feature `ai_assistant`, operator-enabled, off in every plan (`403 assistant_not_enabled`); a platform operator turns it on with `PUT /organizations/{id}/features/ai_assistant` (`platform:organizations`).
3. Tenant setting `enabled` with the external-processing acknowledgement (`403 assistant_tenant_disabled`), set by an `assistant:configure` holder.
4. The route's permission (`assistant:use` or `assistant:configure`), user principals only (API keys `403 user_required`).
5. Per tool: the operation's own permission (below).

The portal shows the "Ask AI" button to `assistant:use` holders when the assistant is available; when it is not, only `assistant:configure` holders see the button, with the reason and a link to Settings → AI assistant.

## Tool permissions = the operation's `x-eg-permissions`

A tool's `requirement` is copied by the generator from the operation's `x-eg-permissions` in `docs/api/openapi.json` (never hand-written; a test fails if they differ). Before the model sees the catalogue, the executor's pre-filter applies `satisfiesRequirement(principal, requirement)` from `apps/api/src/auth-contracts/authorization.ts`, the predicate `PermissionsGuard` uses (one implementation; a unit test proves identical decisions). The effect:

- a tool the user may not call is not in the system prompt's catalogue index nor in `GET /assistant/tools`;
- a forced call (the model names it anyway) is refused as `denied_permission`, recorded and audited, **without** any request to the operation;
- an allowed call still passes `PermissionsGuard` (and MFA requirements) inside the loopback request with the user's own bearer token. The pre-filter is a convenience and a safety net, never the authority.

Requirements with `any` (`a | b`) and `all` (`a + b`) semantics are evaluated as for the route. The per-operation permission of every tool is listed in [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) (column "Permission").

## Platform-only tools

Tools whose requirement needs a `platform:*` permission (`all` mode: any of them is `platform:*`; `any` mode: all alternatives are) are `platformOnly` and are offered only to users of the platform organization. Seven are enabled in AI-1: `organization_deletion_get`, `attachment_rescans_list`, `attachment_rescans_get`, `platform_audit_logs_search`, `dead_letters_stats`, `threat_hashes_list`, `threat_indicators_list`. A customer user never sees them; a forced call is `denied_permission` (`assistant-tools.test.ts`, `assistant-injection.test.ts`).

## Platform override

A platform operator acting in a customer organization through an audited override (`platform:tenant_override`, ADR-0016) may chat (PO Q11). The conversation is stored under the override's **target** organization with the override id (`ai_chat_conversations.platform_override_id`; the API shows `underPlatformOverride: true`), the operator's effective permissions are the intersection the override grants, and the existing override audit interceptor logs every loopback call like any other request in the override (`tenant-isolation-assistant.test.ts`, "platform override (Q11)").

## Privacy between users

Conversations are private (PO Q9): only their owner can list, read, rename, archive, clear or continue them; any other user, administrators included, gets `404`. Administrators with `audit:read` see the **tool-execution audit trail** (`assistant.tool_executed` / `assistant.tool_denied` in the audit log), not the conversation content. See [CHAT_AUDIT_DESIGN.md](CHAT_AUDIT_DESIGN.md).
