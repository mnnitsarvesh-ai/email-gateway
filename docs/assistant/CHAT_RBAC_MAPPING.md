# Chat RBAC mapping

Who may use the assistant and which tools each user gets. Normative sources: [design D5, D13](../plan/steps/28-ai-chat-management.md#d13-tenant-settings-and-permissions), product-owner decision Q3 (2026-11-20), [docs/security/rbac.md § AI assistant](../security/rbac.md#ai-assistant-step-ai-1), [ADR-0091](../architecture/adr/0091-assistant-architecture-loopback-tools.md).

## Two permissions

| Permission            | Grants                                                                                                                                                                         | Does not grant                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| `assistant:use`       | The chat: status, tool list, own conversations, turns, executions, "more" pages                                                                                                | Any data access of its own: every tool still needs the operation's own permission |
| `assistant:configure` | `GET/PUT /assistant/settings` (enable with the external-processing acknowledgement, daily token budget, content retention) and `GET /assistant/usage`; Settings → AI assistant | `assistant:use`, other users' conversations                                       |

Both are tenant permissions (category `assistant`, not platform-only), catalog total 74. Custom roles get them only when an administrator adds them (`role:manage`; the caller must hold them).

## Grants per system role

From the seed catalog and the migration `20261120141509_ai_assistant` (grant-preserving `INSERT IGNORE`; nothing removed; AI-2 and AI-3 changed no grant). "Enabled tools reachable" counts the 257 enabled tools of program phase AI-3 (179 reads, 78 writes) whose `x-eg-permissions` the role satisfies (`enabledTools` with the role's permission set from `packages/database/src/seed/catalog.ts`; platform-only tools only for platform roles), computed from the catalog and the generated registry (version `b031a24c9868f02c`) on 2026-11-22, the same method as the AI-2 table. The write columns count the AI-2 and AI-3 write tools by their **registry** risk (each runs only after the user confirms it; `high` also needs re-authentication; an escalation can raise a `low`/`medium` proposal to `high`, never lower one).

| System role           | `assistant:use` | `assistant:configure` | Enabled tools reachable (of 257) | of which writes (of 78) | Writes low / medium / high | of which AI-3 writes (of 47) |
| --------------------- | :-------------: | :-------------------: | -------------------------------: | ----------------------: | -------------------------: | ---------------------------: |
| `super_admin`         |        ✓        |           ✓           |                              257 |                      78 |               16 / 30 / 32 |                           47 |
| `platform_admin`      |        ✓        |                       |                              144 |                      12 |                  3 / 5 / 4 |                            9 |
| `organization_admin`  |        ✓        |           ✓           |                              231 |                      72 |               16 / 28 / 28 |                           41 |
| `domain_admin`        |        ✓        |                       |                              107 |                      18 |                  5 / 5 / 8 |                           13 |
| `security_analyst`    |        ✓        |                       |                              164 |                      21 |                  7 / 9 / 5 |                            3 |
| `quarantine_reviewer` |        ✓        |                       |                               56 |                      13 |                  3 / 8 / 2 |                            1 |
| `compliance_auditor`  |        ✓        |                       |                              165 |                       4 |                  3 / 1 / 0 |                            1 |
| `read_only_user`      |        ✓        |                       |                              102 |                       4 |                  3 / 1 / 0 |                            1 |
| `mailbox_user`        |                 |                       |                      0 (no chat) |             0 (no chat) |                          — |                            — |
| `compliance_officer`  |        ✓        |                       |                               58 |                       1 |                  1 / 0 / 0 |                            1 |

The AI-3 write every chatting role reaches is its own notification preferences (`notifications_put_preferences`, low). `platform_admin` adds the six platform-only organization writes (create, deletion cancel, feature and limit override and reset) and the two customer organization writes bound to its own (platform) organization; `organization_admin` reaches every AI-3 write except those six; `domain_admin` the ten domain writes and the two SMTP connector writes; `security_analyst` the two scan-settings writes. The remaining writes of `platform_admin`, `compliance_auditor` and `read_only_user` are their own saved views (create, update, remove). Counts of AI-2 for comparison (209 enabled tools, 31 writes): `super_admin` 209/31, `platform_admin` 134/3, `organization_admin` 189/31, `domain_admin` 94/5, `security_analyst` 161/18, `quarantine_reviewer` 55/12, `compliance_auditor` 163/3, `read_only_user` 100/3, `compliance_officer` 57/0; AI-1 (174 enabled reads): 174, 131, 154, 89, 139, 43, 160, 97, 57.

`organization_admin` gets both assistant permissions through `TENANT_PERMISSIONS` (it holds every tenant permission except archive access, so archive record tools stay with archive roles, step 8.6). The end-user role `mailbox_user` does not chat (PO Q3, unchanged in AI-2 and AI-3; the quarantine self-service write tools serve users whose role holds both the self-service permissions and `assistant:use`); the portal shows it no entry point and `/assistant` is forbidden (Playwright `assistant.spec.ts`).

## Separation of duties in chat (step AI-3)

Identity and permission changes through chat pass five layers ([design note 30 D3, §2.0 I12–I14](../plan/steps/30-ai-chat-identity-tenant-admin.md#d3-proposal-guards-separation-of-duties-package-confirmationsguardsts)); the first and the last two are added by the assistant, the middle ones are the api's and stay the authority.

1. **Self guards (I12).** Through chat nobody changes their own account, roles, status, MFA or sessions: `users_update`, `users_change_status`, `users_replace_roles`, `users_reset_mfa`, `users_remove`, `users_resend_invitation`, `users_revoke_all_sessions` and `users_revoke_session` refuse when `id` is the signed-in user (case-insensitive UUID compare). The refusal happens in the executor right after the schema check, before any loopback request (not even the precondition read): execution `refused` / `denied_guard`, `assistant.tool_denied` with metadata `guard: not_self_user`, the card "Not allowed in chat" with the fixed message. The portal's account pages keep their own rules; another administrator may make the change through chat.
2. **The api's no-escalation rules (I13).** Every confirmed identity change still passes `UsersService`'s `assertCanManageUser` (the caller holds every permission of the target's current roles), `assertNoEscalation` (every added **and removed** role), the last-administrator guard (`409`), "cannot disable/delete yourself" (`409`), MFA reset of self refused (`409`), role changes refused under a platform override (`403`) and the archive delegation rule (MFA-authenticated users only, never to themselves; step 8.6 D12); `RolesService` creates and updates roles only with permissions the caller holds and refuses system roles (`409`) and assigned roles on delete. A refusal surfaces as a **failed confirmation** with the api's code; the assistant never bypasses it (`assistant-separation-of-duties.test.ts`: the same user calling `PUT /users/{self}/roles` directly gets `403`, a `user:manage` holder confirming `organization_admin` for another user gets the api's `403`).
3. **Re-authentication on every role and permission change.** `users_invite`, `users_replace_roles`, `users_change_status`, `users_reset_mfa`, `users_remove`, both session revocations, `roles_create`, `roles_update`, `roles_remove`, `api_keys_revoke`, the feature and limit overrides are `high`: password and, with MFA, a fresh TOTP code (the 5-minute window of the session family applies, A2-2). Escalation (D4) adds `high` for user email changes, SMTP networks and `requireTls: false`, webhook URLs, organization creation with an initial admin, plan changes, `mfaRequired: false` and organization notification email changes; the stored risk is the effective one and the confirm recomputes it (`409 assistant_confirmation_tool_changed` on a difference).
4. **Assistant self-configuration guards (A3-4).** `organization_configuration_override_feature` / `_reset_feature` refuse `featureKey = ai_assistant` (the assistant cannot turn itself on or off); `roles_create` refuses a permission list containing `assistant:configure`, and `roles_update` refuses any addition or removal of `assistant:configure` compared with the role's current permissions (an after-read guard on the `roles_get` precondition; fail closed when the old set cannot be read). Assigning an existing role that includes `assistant:configure` (for example `organization_admin`) to **another** user stays allowed under rule 2, with re-authentication.
5. **Audit.** The proposal (`assistant.tool_executed` + `assistant.confirmation_requested` with `risk` and `baseRisk`), a guard denial (`assistant.tool_denied`, `guard`), a refused confirm (`assistant.confirmation_refused`, `reason: guard`), the confirmation outcome and the operation's own row (`user.roles_changed`, `user.invited`, `apikey.revoked`, …) share the execution correlation id ([CHAT_AUDIT_DESIGN.md](CHAT_AUDIT_DESIGN.md)).

Guards are evaluated again at confirm with the confirming principal and the fresh target; a refusal there fails the row `403 assistant_action_not_allowed`. There is **no four-eyes approval** for role changes (A3-5): one re-authenticated administrator can make a change the api's rules allow.

Escalation table (registry risk → stored risk when the condition holds):

| Tool                                         | Registry risk | Condition                                                       | Stored risk |
| -------------------------------------------- | ------------- | --------------------------------------------------------------- | ----------- |
| `users_update`                               | low           | `body.email` present                                            | high        |
| `smtp_connectors_update`                     | medium        | `body.networks` present, or `body.requireTls = false`           | high        |
| `webhooks_update`                            | low           | `body.url` present                                              | high        |
| `organizations_create`                       | medium        | `body.initialAdmin` present                                     | high        |
| `organizations_update`                       | medium        | `body.planCode` present                                         | high        |
| `organization_configuration_update_settings` | medium        | `body.mfaRequired = false`, or `body.notificationEmail` present | high        |

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
- a write (AI-2, AI-3) is first a proposal: the permission is checked at the proposal (pre-filter and the precondition read) and again at the confirm (the principal must still satisfy the tool's requirement, else `403 forbidden` and the confirmation fails) and once more by `PermissionsGuard` on the confirmed loopback request. Separation of duties (quarantine approvals, ADR-0047) stays in the api: a requester confirming their own approval through chat gets the api's refusal as a failed confirmation.
- confirmations are private to their owner and to the proposing sign-in session: another user or organization gets `404`, another session of the same user `403 assistant_confirmation_session_mismatch`.

Requirements with `any` (`a | b`) and `all` (`a + b`) semantics are evaluated as for the route. The per-operation permission of every tool is listed in [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) (column "Permission").

## Platform-only tools

Tools whose requirement needs a `platform:*` permission (`all` mode: any of them is `platform:*`; `any` mode: all alternatives are) are `platformOnly` and are offered only to users of the platform organization. Thirteen are enabled: the seven reads of AI-1 (`organization_deletion_get`, `attachment_rescans_list`, `attachment_rescans_get`, `platform_audit_logs_search`, `dead_letters_stats`, `threat_hashes_list`, `threat_indicators_list`) and six writes of AI-3 (`organizations_create`, `organization_deletion_cancel`, `organization_configuration_override_feature`, `_reset_feature`, `_override_limit`, `_reset_limit`; never bound to the caller's organization, so a platform user always names the target organization). A customer user never sees them; a forced call is `denied_permission` (`assistant-tools.test.ts`, `assistant-injection.test.ts`).

## Platform override

A platform operator acting in a customer organization through an audited override (`platform:tenant_override`, ADR-0016) may chat (PO Q11). The conversation is stored under the override's **target** organization with the override id (`ai_chat_conversations.platform_override_id`; the API shows `underPlatformOverride: true`), the operator's effective permissions are the intersection the override grants, and the existing override audit interceptor logs every loopback call like any other request in the override (`tenant-isolation-assistant.test.ts`, "platform override (Q11)").

## Privacy between users

Conversations are private (PO Q9): only their owner can list, read, rename, archive, clear or continue them; any other user, administrators included, gets `404`. Administrators with `audit:read` see the **tool-execution audit trail** (`assistant.tool_executed` / `assistant.tool_denied` in the audit log), not the conversation content. See [CHAT_AUDIT_DESIGN.md](CHAT_AUDIT_DESIGN.md).

## Reports (step AI-R)

Design [note 31](../plan/steps/31-ai-chat-reports.md) D1, D2, D5, R-11. No new permission.

| What                                         | Needs                                                                                    | Notes                                                                                                                                                                                                                                                                   |
| -------------------------------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `report_generate` (native read)              | `assistant:use` + `report:read`                                                          | Without `report:read` the tool is absent from the catalogue and a forced call is `denied_permission`                                                                                                                                                                    |
| Report sections                              | the permission of each source operation (`report:read`, `quarantine:read`, `ato:read`)   | A section whose source the user cannot read is **not requested** and listed under "Not included" with reason `permission` and the missing key (e.g. `quarantine:read`); the same predicate as the tool pre-filter. The ATO feature off gives `not_enabled`              |
| `report_send_email` (native write, `medium`) | `assistant:use` + `report:read`                                                          | Confirmation card, no re-authentication; the recipient rule (own address, active users of the organization, addresses of its verified domains) is the server's and does not depend on the user's `user:read` or `domain:read`                                           |
| `GET /assistant/reports/{reportId}`          | `assistant:use`, and being the report's owner (organization, user, platform override id) | No administrator can read another user's report (as conversations, Q9); API keys `403 user_required`                                                                                                                                                                    |
| Platform principals                          | an active platform override of the target organization                                   | Without an override `report_generate` is `denied_guard` (`report_needs_organization`); under an override the report is stored under the target organization with `platform_override_id`, private to the operator in that override; `self` is the operator's own address |

Every source read is the user's own loopback request: the reports module's, quarantine's and ATO's own guards, RBAC, tenant scope and rate limits apply exactly as for the portal's Reports and Dashboard pages.
