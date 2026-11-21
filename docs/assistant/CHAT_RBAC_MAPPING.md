# Chat RBAC mapping

Who may use the assistant and which tools each user gets. Normative sources: [design D5, D13](../plan/steps/28-ai-chat-management.md#d13-tenant-settings-and-permissions), product-owner decision Q3 (2026-11-20), [docs/security/rbac.md § AI assistant](../security/rbac.md#ai-assistant-step-ai-1), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md).

## Two permissions

| Permission            | Grants                                                                                                                                                                         | Does not grant                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `assistant:use`       | The chat: status, tool list, own conversations, turns, executions, "more" pages                                                                                                | Any data access of its own: every tool still needs the operation's own permission |
| `assistant:configure` | `GET/PUT /assistant/settings` (enable with the external-processing acknowledgement, daily token budget, content retention) and `GET /assistant/usage`; Settings → AI assistant | `assistant:use`, other users' conversations                                       |

Both are tenant permissions (category `assistant`, not platform-only), catalog total 74. Custom roles get them only when an administrator adds them (`role:manage`; the caller must hold them).

## Grants per system role

From the seed catalog and the migration `20261120141509_ai_assistant` (grant-preserving `INSERT IGNORE`; nothing removed). "Enabled tools reachable" counts the 209 enabled tools of program phase AI-2 (178 reads, 31 writes) whose `x-eg-permissions` the role satisfies (`enabledTools` with the role's permission set from `packages/database/src/seed/catalog.ts`; platform-only tools only for platform roles), computed from the catalog and the generated registry (version `0e75a5af832f11ce`) on 2026-11-21. The write columns count the AI-2 write tools (each runs only after the user confirms it; `high` also needs re-authentication).

| System role           | `assistant:use` | `assistant:configure` | Enabled tools reachable (of 209) | of which writes (of 31) | Writes low / medium / high |
| --------------------- | :-------------: | :-------------------: | -------------------------------: | ----------------------: | -------------------------: |
| `super_admin`         |        ✓        |           ✓           |                              209 |                      31 |                 8 / 17 / 6 |
| `platform_admin`      |        ✓        |                       |                              134 |                       3 |                  2 / 1 / 0 |
| `organization_admin`  |        ✓        |           ✓           |                              189 |                      31 |                 8 / 17 / 6 |
| `domain_admin`        |        ✓        |                       |                               94 |                       5 |                  3 / 1 / 1 |
| `security_analyst`    |        ✓        |                       |                              161 |                      18 |                  6 / 9 / 3 |
| `quarantine_reviewer` |        ✓        |                       |                               55 |                      12 |                  2 / 8 / 2 |
| `compliance_auditor`  |        ✓        |                       |                              163 |                       3 |                  2 / 1 / 0 |
| `read_only_user`      |        ✓        |                       |                              100 |                       3 |                  2 / 1 / 0 |
| `mailbox_user`        |                 |                       |                      0 (no chat) |             0 (no chat) |                          — |
| `compliance_officer`  |        ✓        |                       |                               57 |                       0 |                          — |

The three writes of `platform_admin`, `compliance_auditor` and `read_only_user` are their own saved views (create, update, remove). AI-1 counts for comparison (174 enabled reads): `super_admin` 174, `platform_admin` 131, `organization_admin` 154, `domain_admin` 89, `security_analyst` 139, `quarantine_reviewer` 43, `compliance_auditor` 160, `read_only_user` 97, `compliance_officer` 57.

`organization_admin` gets both through `TENANT_PERMISSIONS` (it holds every tenant permission except archive access, so archive record tools stay with archive roles, step 8.6). The end-user role `mailbox_user` does not chat (PO Q3, unchanged in AI-2; the quarantine self-service write tools serve users whose role holds both the self-service permissions and `assistant:use`); the portal shows it no entry point and `/assistant` is forbidden (Playwright `assistant.spec.ts`).

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
- a write (AI-2) is first a proposal: the permission is checked at the proposal (pre-filter and the precondition read) and again at the confirm (the principal must still satisfy the tool's requirement, else `403 forbidden` and the confirmation fails) and once more by `PermissionsGuard` on the confirmed loopback request. Separation of duties (quarantine approvals, ADR-0047) stays in the api: a requester confirming their own approval through chat gets the api's refusal as a failed confirmation.
- confirmations are private to their owner and to the proposing sign-in session: another user or organization gets `404`, another session of the same user `403 assistant_confirmation_session_mismatch`.

Requirements with `any` (`a | b`) and `all` (`a + b`) semantics are evaluated as for the route. The per-operation permission of every tool is listed in [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) (column "Permission").

## Platform-only tools

Tools whose requirement needs a `platform:*` permission (`all` mode: any of them is `platform:*`; `any` mode: all alternatives are) are `platformOnly` and are offered only to users of the platform organization. Seven are enabled in AI-1: `organization_deletion_get`, `attachment_rescans_list`, `attachment_rescans_get`, `platform_audit_logs_search`, `dead_letters_stats`, `threat_hashes_list`, `threat_indicators_list`. A customer user never sees them; a forced call is `denied_permission` (`assistant-tools.test.ts`, `assistant-injection.test.ts`).

## Platform override

A platform operator acting in a customer organization through an audited override (`platform:tenant_override`, ADR-0016) may chat (PO Q11). The conversation is stored under the override's **target** organization with the override id (`ai_chat_conversations.platform_override_id`; the API shows `underPlatformOverride: true`), the operator's effective permissions are the intersection the override grants, and the existing override audit interceptor logs every loopback call like any other request in the override (`tenant-isolation-assistant.test.ts`, "platform override (Q11)").

## Privacy between users

Conversations are private (PO Q9): only their owner can list, read, rename, archive, clear or continue them; any other user, administrators included, gets `404`. Administrators with `audit:read` see the **tool-execution audit trail** (`assistant.tool_executed` / `assistant.tool_denied` in the audit log), not the conversation content. See [CHAT_AUDIT_DESIGN.md](CHAT_AUDIT_DESIGN.md).
