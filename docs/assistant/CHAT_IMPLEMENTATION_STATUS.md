# Chat implementation status

What the assistant can do today, per module, and what is planned or excluded. Generated numbers come from [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) (registry version `0e75a5af832f11ce`, program phase AI-2, 2026-11-21), which lists every operation; this page groups them. Design: [AI-1 §6 phase plan](../plan/steps/28-ai-chat-management.md#6-phase-plan-each-step-about-one-day-independently-shippable-and-testable), [AI-2 design note](../plan/steps/29-ai-chat-confirmations-mail-writes.md).

**Step AI-1:** committed (`cf4b9ca`, 2026-11-21): the foundation and every eligible read.

**Step AI-2 status: built and verified locally on 2026-11-21, not complete** (not committed; CI and a real-provider test pending). AI-2 adds action confirmations and the mail-operations write tools: policies, quarantine, held messages, recipient suppressions and saved views. See [CHAT_TESTING_REPORT.md](CHAT_TESTING_REPORT.md) and the [verification record](../plan/steps/29-ai-chat-confirmations-mail-writes.md#12-verification-record).

## Summary

| Status                  | Operations | Meaning                                                                                                                                                                                                                                                                                                      |
| ----------------------- | ---------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `IMPLEMENTED`           |        209 | Enabled tools: 178 reads, each called by the tool sweep (`apps/api/integration/assistant-tools.test.ts`), and 31 writes that run only after the user confirms them in a confirmation card, each covered by `assistant-writes-policies.test.ts` or `assistant-writes-mail-ops.test.ts` (its `testedBy` suite) |
| `PARTIALLY_IMPLEMENTED` |          0 | —                                                                                                                                                                                                                                                                                                            |
| `MISSING`               |        139 | Classified and planned: 135 writes (AI-3 46, AI-4 64, AI-5 25) and 4 side-effect-free `POST` reads (AI-3 1, AI-4 2, AI-5 1)                                                                                                                                                                                  |
| `NOT_APPLICABLE`        |         73 | Never a chat tool; the chat links to the portal page (reasons below)                                                                                                                                                                                                                                         |
| **Total**               |    **421** | Every operation of `docs/api/openapi.json` = every portal action (ADR-0063); AI-2 added the 3 confirmation routes (not applicable)                                                                                                                                                                           |

Phase totals of the tools: AI-1 174 (built), AI-2 35 (built: 31 writes and 4 side-effect-free policy `POST`s), AI-3 47, AI-4 66, AI-5 26. A portal user can therefore **read** everything they can read in the portal through chat (subject to the same permissions) and can **change** policies, quarantine, held messages, recipient suppressions and saved views through chat, each change only after confirming it in the card; every other change stays in the portal until its phase.

## Per module

| Module                 | IMPLEMENTED reads | IMPLEMENTED writes (AI-2) | MISSING reads (phase) | MISSING writes (phase) | NOT_APPLICABLE (reason)                                     |
| ---------------------- | ----------------: | ------------------------: | --------------------- | ---------------------- | ----------------------------------------------------------- |
| `api-keys`             |                 1 |                         — | —                     | AI-3 1                 | returns a secret 1                                          |
| `archive`              |                10 |                         — | —                     | AI-5 3                 | content/preview/download/reveal 4, critical (portal only) 2 |
| `archive,journaling`   |                 2 |                         — | —                     | AI-5 2                 | —                                                           |
| `assistant`            |                 0 |                         — | —                     | —                      | assistant route 18                                          |
| `ato`                  |                20 |                         — | —                     | AI-4 19                | —                                                           |
| `attachments`          |                 2 |                         — | —                     | —                      | —                                                           |
| `audit`                |                 2 |                         — | —                     | —                      | —                                                           |
| `auth`                 |                 0 |                         — | —                     | —                      | ceremony 13                                                 |
| `bec`                  |                 7 |                         — | —                     | AI-4 11                | critical (portal only) 1, file export 1                     |
| `billing`              |                 2 |                         — | —                     | —                      | —                                                           |
| `deliveries`           |                 3 |                         — | —                     | —                      | —                                                           |
| `departments`          |                 3 |                         — | —                     | AI-3 5                 | —                                                           |
| `dlp`                  |                 9 |                         — | AI-4 1                | AI-4 17                | content/preview/download/reveal 1, critical (portal only) 2 |
| `domains`              |                 8 |                         — | —                     | AI-3 10                | —                                                           |
| `ediscovery`           |                 9 |                         — | —                     | AI-5 7                 | content/preview/download/reveal 1, critical (portal only) 1 |
| `incidents`            |                 5 |                         — | —                     | AI-4 3                 | —                                                           |
| `journaling`           |                 6 |                         — | —                     | AI-5 4                 | returns a secret 2                                          |
| `messages`             |                 7 |                         2 | —                     | —                      | content/preview/download/reveal 2                           |
| `meta`                 |                 0 |                         — | —                     | —                      | ceremony 1                                                  |
| `mfa`                  |                 0 |                         — | —                     | —                      | ceremony 4                                                  |
| `notifications`        |                 2 |                         — | —                     | AI-3 2                 | —                                                           |
| `organizations`        |                 7 |                         — | —                     | AI-3 8                 | critical (portal only) 3                                    |
| `platform`             |                 6 |                         — | —                     | AI-4 8                 | identity/override 2                                         |
| `policies`             |                12 |                        11 | —                     | —                      | —                                                           |
| `provider-connections` |                10 |                         — | AI-5 1                | AI-5 9                 | credential/consent 2, returns a secret 2                    |
| `quarantine`           |                12 |                        13 | —                     | —                      | content/preview/download/reveal 4                           |
| `recipients`           |                 2 |                         2 | —                     | —                      | —                                                           |
| `reports`              |                 6 |                         — | —                     | —                      | —                                                           |
| `risk-scoring`         |                 4 |                         — | AI-4 1                | AI-4 6                 | —                                                           |
| `roles`                |                 3 |                         — | —                     | AI-3 3                 | —                                                           |
| `saved-views`          |                 2 |                         3 | —                     | —                      | —                                                           |
| `scan-settings`        |                 1 |                         — | —                     | AI-3 2                 | —                                                           |
| `sessions`             |                 0 |                         — | —                     | —                      | ceremony 2                                                  |
| `smtp-connectors`      |                 2 |                         — | —                     | AI-3 2                 | returns a secret 2                                          |
| `threat-intelligence`  |                 1 |                         — | —                     | —                      | —                                                           |
| `url-protection`       |                 2 |                         — | —                     | —                      | —                                                           |
| `usage`                |                 1 |                         — | —                     | —                      | —                                                           |
| `users`                |                 3 |                         — | —                     | AI-3 9                 | —                                                           |
| `webhooks`             |                 6 |                         — | AI-3 1                | AI-3 4                 | returns a secret 2                                          |
| **Total**              |           **178** |                    **31** | **4**                 | **135**                | **73**                                                      |

`MISSING` columns give the phase that will build them (AI-3 identity and tenant administration; AI-4 security operations; AI-5 compliance and integrations). The module `archive,journaling` holds the operations tagged with both.

## Write support per module (AI-2)

Every write below is a **proposal** first: the executor validates it, reads the target's current state, builds a server-authored summary and stores a confirmation; it runs only when the user confirms the card (risk `high` also asks for the password and, with MFA, the authenticator code). Risk classes and confirmation specs: [CHAT_TOOL_REGISTRY.md](CHAT_TOOL_REGISTRY.md#confirmation-specs-ai-2).

| Module          | Write tools (risk)                                                                                                                                                                                                                                                                                                                                                                                 | Side-effect-free reads added                                                                           |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| policies (11)   | `policy_management_create` (low), `_update` (low), `_create_draft` (low), `_enable` (medium), `_disable` (medium), `_update_draft` (medium), `_publish` (medium), `_activate` (medium), `_remove` (high), `_delete_draft` (high), `policy_settings_put` (high)                                                                                                                                     | `policy_tools_validate`, `policy_tools_test`, `policy_messages_dry_run`, `policy_tools_sample_dry_run` |
| quarantine (13) | `quarantine_entries_release`, `_reject`, `_request_release` (medium), `quarantine_entries_manual` (low), `quarantine_entries_delete` (high), `quarantine_self_release`, `quarantine_self_request_release` (medium), `quarantine_self_put_preferences` (low), `quarantine_tools_put_settings` (medium), `quarantine_approvals_approve`, `_deny`, `_cancel` (medium), `quarantine_tools_bulk` (high) | —                                                                                                      |
| messages (2)    | `message_lifecycle_release`, `message_lifecycle_rescan` (medium)                                                                                                                                                                                                                                                                                                                                   | —                                                                                                      |
| recipients (2)  | `recipient_suppressions_create` (low), `recipient_suppressions_delete` (high)                                                                                                                                                                                                                                                                                                                      | —                                                                                                      |
| saved-views (3) | `saved_views_create` (low), `saved_views_update` (medium), `saved_views_remove` (low)                                                                                                                                                                                                                                                                                                              | —                                                                                                      |

Quarantine releases that need an approval are answered `202` by the api: the confirmation is `executed` and the card says the release waits for another person's approval (separation of duties stays in the api, ADR-0047).

## Product-owner questions of AI-2 (defaults applied)

Built with the design defaults ([note 29 §6](../plan/steps/29-ai-chat-confirmations-mail-writes.md#6-product-owner-questions-defaults-applied-product-owner-may-revise-before-or-after-the-commit)); the product owner may revise them before or after the commit.

| #    | Question                                                                    | Default built                                                                                                                       |
| ---- | --------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| A2-1 | A policy created through chat: draft only, or also published and activated? | Draft only (one confirmation = one request); the assistant then offers "publish and activate" as a second, `medium` confirmation    |
| A2-2 | Scope of the 5-minute re-authentication window                              | Assistant confirmations of the same session family only; it does not satisfy other re-auth prompts (download grants) nor vice versa |
| A2-3 | Pending confirmations after a reload or in another tab                      | Cannot be confirmed (the token is only in the proposing tab); can be cancelled; the user asks again                                 |
| A2-4 | Changed-state rule                                                          | Any change of the target's state fields between proposal and confirm refuses, even when the route itself would accept the request   |
| A2-5 | Limits                                                                      | At most 5 pending confirmations per conversation; 5 wrong tokens cancel a confirmation; bulk previews read 25 items                 |
| A2-6 | Policy definitions                                                          | Always validated server-side before a proposal; testing with `policy_tools_test` is the model's (prompted) choice, not enforced     |
| A2-7 | Confirm during a running turn                                               | Refused with `409 assistant_turn_in_progress`; the card's Confirm button is disabled while the turn streams                         |

## Not applicable, with reasons

| Reason                                    | Count | Examples                                                                                                                        |
| ----------------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------- |
| The assistant's own routes (no recursion) |    18 | `/assistant/*` (AI-2 added the three confirmation routes)                                                                       |
| Credential or session ceremony            |    20 | login, MFA, password change and reset, invitations, logout, refresh, own sessions, `meta`                                       |
| Returns a secret                          |     9 | API key creation, webhook signing secrets, SMTP connector credentials, journal intake addresses, provider secrets               |
| Content, preview, download or unmasking   |    12 | quarantine and archive previews and downloads, download grants, reveal, DLP evidence (ADR-0048/0062)                            |
| Credential upload or OAuth consent        |     2 | provider connection credentials and consent                                                                                     |
| Changes the caller's identity or tenant   |     2 | platform override start and end                                                                                                 |
| File export stream                        |     1 | BEC feedback export                                                                                                             |
| Critical: portal only by policy           |     9 | organization status and deletion, legal-hold release, archive disposal and key rotation, DLP evidence purges, BEC history purge |

These stay in the portal permanently; when asked, the assistant says so and links to the page (`denied_not_applicable` with the reason).

## Brief §14 functional checklist (after AI-2)

| Capability (brief §14)                      | Status                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| List existing resources                     | Yes (every list operation the user may call)                                                                                                                                          |
| Search and filter resources                 | Yes (query parameters of the list and search operations; "Load more" pages)                                                                                                           |
| Create, update, enable or disable policies  | Yes (AI-2): create, rename, drafts, publish, activate, enable, disable, delete and policy settings, each confirmed in a card; definitions are validated server-side before a proposal |
| Quarantine and held-message operations      | Yes (AI-2): release, reject, delete, request release, manual quarantine, approvals, bulk actions, settings, self-service, message release and rescan                                  |
| Investigate ATP threats                     | Partly: existing threat-intelligence, URL, attachment and message reads; the ATP steps add their own tools                                                                            |
| Investigate ATO incidents                   | Yes, read-only (accounts, signals, auth events, incidents, responses); actions in AI-4                                                                                                |
| Manage journaling configuration             | Read-only (status, settings, intake sources); changes in AI-5                                                                                                                         |
| Search email and archive records            | Yes (message explorer and archive search within the user's permissions; no content)                                                                                                   |
| Generate reports                            | Reads of the existing report operations (series cards); asynchronous report generation is AI-6                                                                                        |
| View system status                          | Yes (journaling and archive status, dead-letter statistics for platform users, usage)                                                                                                 |
| Destructive operations require confirmation | Yes (AI-2): every write needs the card; `high` risk also re-authentication; `critical` operations stay portal only                                                                    |
| Every other supported operation             | Reads yes; writes by phase as in the table above                                                                                                                                      |

## Known limitations

- **Writes of AI-3 … AI-5 modules** (users, roles, domains, DLP, BEC, ATO, archive, eDiscovery, journaling, integrations, …) are not enabled: asking for them gets `denied_disabled` and a pointer to the portal page.
- **One change per confirmation.** "Create and publish" is two cards (A2-1); bulk quarantine actions are one card for the whole list (the first 25 items are previewed, the api revalidates every item).
- **The confirmation token lives in the proposing browser tab only.** After a reload or in another tab a pending card can be cancelled but not confirmed (A2-3): ask again.
- **Changed state refuses.** Any change of the target's state fields between the proposal and the confirm refuses the confirm (`409 assistant_confirmation_state_changed`), even when the route itself would accept the request (A2-4).
- **Limits.** At most 5 pending confirmations per conversation (`ASSISTANT_MAX_PENDING_CONFIRMATIONS`), 5 minutes to confirm (`ASSISTANT_CONFIRMATION_TTL_SECONDS`), 5 wrong tokens cancel a confirmation, a confirm is refused while a turn of the conversation runs (A2-5, A2-7).
- **Four side-effect-free `POST` reads** (risk dry run, DLP pattern test, webhook test, mail-flow preview) are deferred to their module's write phase.
- **Card columns named like credentials are withheld.** The credential-key pattern also matches harmless fields: the tool sweep reports `roles_list.key` and `incidents_list.titleCode` columns shown as empty; the audit metadata stores the error code under `error` for the same reason.
- **Coverage depth of the tool sweep.** Every enabled read is called once and every enabled write is proposed once (no confirm); the write suites confirm each write against the real api. The sweep proves reachability, validation, permission checks and "no write without confirmation"; it does not compare every tool's data with the portal.
- **Fake provider only.** Local stacks and all tests run the deterministic fake; the Anthropic, OpenAI and Azure OpenAI adapters are unit-tested against recorded fixtures but no real provider call was made. Whether a real model proposes sensible changes and explains confirmations well is not evaluated (AI-6, with the product owner's approval of spend).
- **Docker Compose api** receives no `ASSISTANT_*` key and runs `NODE_ENV=production`, so the containerized api has the assistant off; the Playwright run adds `tests/portal-e2e/assistant.override.yml`.
- **Not in AI-2** (design note 29 §8): writes of later phases, ATO second-analyst flows through chat (AI-4), confirmations by another user, asynchronous or background execution, re-issuing tokens, feedback, content search beyond titles, pseudonymized sharing, provider fallback, the `api-assistant` Deployment (AI-6).
- **Portal page column.** The generator attributes an operation to every portal feature folder whose source files (tests included) name it, so `/assistant` appears beside some non-assistant operations named in the assistant feature's tests. The chat tools and their links are unaffected.
