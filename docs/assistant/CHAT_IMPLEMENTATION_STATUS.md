# Chat implementation status

What the assistant can do today, per module, and what is planned or excluded. Generated numbers come from [UI_TO_CHAT_CAPABILITY_MATRIX.md](UI_TO_CHAT_CAPABILITY_MATRIX.md) (registry version `30777563d395518a`, 2026-11-21), which lists every operation; this page groups them. Design: [§6 phase plan](../plan/steps/28-ai-chat-management.md#6-phase-plan-each-step-about-one-day-independently-shippable-and-testable), [§10 not in scope of AI-1](../plan/steps/28-ai-chat-management.md#10-not-in-scope-of-ai-1).

**Step AI-1 status: built and verified locally on 2026-11-20, not complete** (not committed; CI and a real-provider test pending). See [CHAT_TESTING_REPORT.md](CHAT_TESTING_REPORT.md).

## Summary

| Status                  | Operations | Meaning                                                                                                                                            |
| ----------------------- | ---------: | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `IMPLEMENTED`           |        174 | Enabled read tools, each called by the AI-1 tool sweep (`apps/api/integration/assistant-tools.test.ts`)                                            |
| `PARTIALLY_IMPLEMENTED` |          0 | —                                                                                                                                                  |
| `MISSING`               |        174 | Classified and planned: 166 writes (AI-2 35, AI-3 47, AI-4 66, AI-5 26 including their side-effect-free reads) and 8 side-effect-free `POST` reads |
| `NOT_APPLICABLE`        |         70 | Never a chat tool; the chat links to the portal page (reasons below)                                                                               |
| **Total**               |    **418** | Every operation of `docs/api/openapi.json` = every portal action (ADR-0063)                                                                        |

Phase totals of the tools: AI-1 174 (built), AI-2 35, AI-3 47, AI-4 66, AI-5 26. A portal user can therefore **read** everything they can read in the portal through chat today (subject to the same permissions), and can **change** nothing through chat until AI-2.

## Per module

| Module                 | IMPLEMENTED (reads) | MISSING reads (phase) | MISSING writes (phase) | NOT_APPLICABLE (reason)                                     |
| ---------------------- | ------------------: | --------------------- | ---------------------- | ----------------------------------------------------------- |
| `api-keys`             |                   1 | —                     | AI-3 1                 | returns a secret 1                                          |
| `archive`              |                  10 | —                     | AI-5 3                 | content/preview/download/reveal 4, critical (portal only) 2 |
| `archive,journaling`   |                   2 | —                     | AI-5 2                 | —                                                           |
| `assistant`            |                   0 | —                     | —                      | assistant route 15                                          |
| `ato`                  |                  20 | —                     | AI-4 19                | —                                                           |
| `attachments`          |                   2 | —                     | —                      | —                                                           |
| `audit`                |                   2 | —                     | —                      | —                                                           |
| `auth`                 |                   0 | —                     | —                      | ceremony 13                                                 |
| `bec`                  |                   7 | —                     | AI-4 11                | critical (portal only) 1, file export 1                     |
| `billing`              |                   2 | —                     | —                      | —                                                           |
| `deliveries`           |                   3 | —                     | —                      | —                                                           |
| `departments`          |                   3 | —                     | AI-3 5                 | —                                                           |
| `dlp`                  |                   9 | AI-4 1                | AI-4 17                | content/preview/download/reveal 1, critical (portal only) 2 |
| `domains`              |                   8 | —                     | AI-3 10                | —                                                           |
| `ediscovery`           |                   9 | —                     | AI-5 7                 | content/preview/download/reveal 1, critical (portal only) 1 |
| `incidents`            |                   5 | —                     | AI-4 3                 | —                                                           |
| `journaling`           |                   6 | —                     | AI-5 4                 | returns a secret 2                                          |
| `messages`             |                   7 | —                     | AI-2 2                 | content/preview/download/reveal 2                           |
| `meta`                 |                   0 | —                     | —                      | ceremony 1                                                  |
| `mfa`                  |                   0 | —                     | —                      | ceremony 4                                                  |
| `notifications`        |                   2 | —                     | AI-3 2                 | —                                                           |
| `organizations`        |                   7 | —                     | AI-3 8                 | critical (portal only) 3                                    |
| `platform`             |                   6 | —                     | AI-4 8                 | identity/override 2                                         |
| `policies`             |                   8 | AI-2 4                | AI-2 11                | —                                                           |
| `provider-connections` |                  10 | AI-5 1                | AI-5 9                 | credential/consent 2, returns a secret 2                    |
| `quarantine`           |                  12 | —                     | AI-2 13                | content/preview/download/reveal 4                           |
| `recipients`           |                   2 | —                     | AI-2 2                 | —                                                           |
| `reports`              |                   6 | —                     | —                      | —                                                           |
| `risk-scoring`         |                   4 | AI-4 1                | AI-4 6                 | —                                                           |
| `roles`                |                   3 | —                     | AI-3 3                 | —                                                           |
| `saved-views`          |                   2 | —                     | AI-2 3                 | —                                                           |
| `scan-settings`        |                   1 | —                     | AI-3 2                 | —                                                           |
| `sessions`             |                   0 | —                     | —                      | ceremony 2                                                  |
| `smtp-connectors`      |                   2 | —                     | AI-3 2                 | returns a secret 2                                          |
| `threat-intelligence`  |                   1 | —                     | —                      | —                                                           |
| `url-protection`       |                   2 | —                     | —                      | —                                                           |
| `usage`                |                   1 | —                     | —                      | —                                                           |
| `users`                |                   3 | —                     | AI-3 9                 | —                                                           |
| `webhooks`             |                   6 | AI-3 1                | AI-3 4                 | returns a secret 2                                          |
| **Total**              |             **174** | **8**                 | **166**                | **70**                                                      |

`IMPLEMENTED` counts are reads; `MISSING` columns give the phase that will build them (AI-2 policies, quarantine, messages, recipient suppressions, saved views; AI-3 identity and tenant administration; AI-4 security operations; AI-5 compliance and integrations). The module `archive,journaling` holds the operations tagged with both.

## Not applicable, with reasons

| Reason                                    | Count | Examples                                                                                                                        |
| ----------------------------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------- |
| The assistant's own routes (no recursion) |    15 | `/assistant/*`                                                                                                                  |
| Credential or session ceremony            |    20 | login, MFA, password change and reset, invitations, logout, refresh, own sessions, `meta`                                       |
| Returns a secret                          |     9 | API key creation, webhook signing secrets, SMTP connector credentials, journal intake addresses, provider secrets               |
| Content, preview, download or unmasking   |    12 | quarantine and archive previews and downloads, download grants, reveal, DLP evidence (ADR-0048/0062)                            |
| Credential upload or OAuth consent        |     2 | provider connection credentials and consent                                                                                     |
| Changes the caller's identity or tenant   |     2 | platform override start and end                                                                                                 |
| File export stream                        |     1 | BEC feedback export                                                                                                             |
| Critical: portal only by policy           |     9 | organization status and deletion, legal-hold release, archive disposal and key rotation, DLP evidence purges, BEC history purge |

These stay in the portal permanently; when asked, the assistant says so and links to the page (`denied_not_applicable` with the reason).

## Brief §14 functional checklist (AI-1)

| Capability (brief §14)                     | AI-1                                                                                                       |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| List existing resources                    | Yes (every list operation the user may call)                                                               |
| Search and filter resources                | Yes (query parameters of the list and search operations; "Load more" pages)                                |
| Create, update, enable or disable policies | No: AI-2 (confirmations)                                                                                   |
| Investigate ATP threats                    | Partly: existing threat-intelligence, URL, attachment and message reads; the ATP steps add their own tools |
| Investigate ATO incidents                  | Yes, read-only (accounts, signals, auth events, incidents, responses); actions in AI-4                     |
| Manage journaling configuration            | Read-only (status, settings, intake sources); changes in AI-5                                              |
| Search email and archive records           | Yes (message explorer and archive search within the user's permissions; no content)                        |
| Generate reports                           | Reads of the existing report operations (series cards); asynchronous report generation is AI-6             |
| View system status                         | Yes (journaling and archive status, dead-letter statistics for platform users, usage)                      |
| Every other supported operation            | Reads yes; writes by phase as in the table above                                                           |

## Known limitations

- **Read-only.** No write tool is enabled; asking for a change gets `denied_disabled` and a pointer to the portal page. The confirmation design is fixed (ADR-0093) but not built.
- **Eight side-effect-free `POST` reads** (policy validate, test and dry runs, risk dry run, DLP pattern test, webhook test, mail-flow preview) are deferred to their module's write phase.
- **Card columns named like credentials are withheld.** The credential-key pattern also matches harmless fields: the tool sweep reports `roles_list.key` and `incidents_list.titleCode` columns shown as empty; the audit metadata stores the error code under `error` for the same reason.
- **Coverage depth of the tool sweep.** Every enabled tool is called once (174: 167 tenant tools through a turn, 7 platform tools through the executor); 89 returned data and the rest returned coded `404` (synthetic ids) or `400` (required arguments omitted). It proves that each tool is reachable, validated, permission-checked and safe; it does not compare every tool's data with the portal.
- **Fake provider only.** Local stacks and all tests run the deterministic fake; the Anthropic, OpenAI and Azure OpenAI adapters are unit-tested against recorded fixtures but no real provider call was made. Answer quality of a real model is not evaluated (AI-6, with the product owner's approval of spend).
- **Docker Compose api** receives no `ASSISTANT_*` key and runs `NODE_ENV=production`, so the containerized api has the assistant off; the Playwright run adds `tests/portal-e2e/assistant.override.yml`.
- **Not in AI-1** (design §10): write tools and confirmations, re-authentication, asynchronous reports and RabbitMQ use, feedback, conversation content search beyond titles, pseudonymized data sharing, tenant-supplied keys or providers, provider fallback chains, a separate Deployment and egress policy, chat for `mailbox_user`, file uploads or images, voice, exposing the registry over MCP, ATP tools (added by the ATP steps).
- **Portal page column.** The generator attributes an operation to every portal feature folder whose source files (tests included) name it, so `/assistant` appears beside four non-assistant operations named in the assistant feature's tests (policy list, organization get, organization settings, ATO attention). The chat tools and their links are unaffected.
