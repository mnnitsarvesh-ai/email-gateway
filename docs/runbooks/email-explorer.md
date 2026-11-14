# Runbook: Email Explorer and Email Details

Operating the message search, the masking and reveal of sensitive message metadata and the saved explorer views of step 7.2 ([design note](../plan/steps/21-email-explorer-details.md), [ADR-0061](../architecture/adr/0061-message-search-drivers-and-saved-views.md) search drivers and saved views, [ADR-0062](../architecture/adr/0062-sensitive-message-metadata-masking-and-reveal.md) masking and reveal). The pages are page 9 (`/messages`) and page 10 (`/messages/[messageId]`) of the admin portal ([page inventory](../frontend/page-inventory.md), [portal runbook](admin-portal.md)); the api contract is in the [API guide](../api/README.md#messages-messages-tag-steps-61-and-72).

Contents: [configuration](#configuration) · [search refusals (422 / 503)](#search-refusals-422-message_search_too_broad-and-503-message_search_timeout) · [short pages and slow searches](#short-pages-and-slow-searches) · [403 message_filter_forbidden](#403-message_filter_forbidden) · [reveal limits and audit](#reveal-limits-and-the-messagerevealed-audit-rows) · [masking rules](#masking-rules-summary) · [saved views](#saved-views) · [index rollout and write amplification](#index-rollout-and-write-amplification) · [cursor invalidation after a deploy](#cursor-invalidation-after-a-deploy) · [metrics](#metrics)

## Configuration

All keys belong to the api (`apps/api/src/config.ts`, `.env.example` section "Email explorer and details (step 7.2)", Compose `api.environment` as `${KEY:-default}`, Kubernetes `infrastructure/kubernetes/base/api.yaml`). None is a secret; the portal has no new key.

| Key                               | Default | Bounds       | Meaning                                                                                                       |
| --------------------------------- | ------- | ------------ | ------------------------------------------------------------------------------------------------------------- |
| `API_MESSAGES_SEARCH_MAX_MATCHES` | 5 000   | 500–50 000   | Most messages of the requested range a `subjectPrefix` search may match before `422 message_search_too_broad` |
| `API_MESSAGES_SEARCH_TIMEOUT_MS`  | 5 000   | 1 000–30 000 | `MAX_EXECUTION_TIME` of both subject-prefix statements; over it `503 message_search_timeout`                  |
| `API_MESSAGES_REVEAL_PER_MINUTE`  | 30      | 1–600        | Reveal calls per user or API key per minute (both reveal operations share it)                                 |
| `SAVED_VIEWS_MAX_PER_USER`        | 50      | 1–200        | Saved explorer views per user and kind                                                                        |

Unchanged and relevant: `API_MESSAGES_MAX_RANGE_DAYS` (31, the explorer's longest range), `API_LIST_SCAN_BUDGET_ROWS` (5 000 index entries per request for searches with residual filters), `API_CURSOR_TTL_SECONDS`, `API_AUDIT_MAX_RANGE_DAYS` (90, the audit history section). A changed value needs an api restart (`kubectl rollout restart deployment/api -n email-gateway`, Compose `docker compose up -d --no-deps api`).

## Search refusals: `422 message_search_too_broad` and `503 message_search_timeout`

Both concern the **subject-prefix** search only (`subjectPrefix`, "Subject starts with" in the explorer). The prefix is a range over the generated subject key, not an equality, so its matches are not in time order: the api first probes the index (`LIMIT 1 OFFSET cap`) and refuses when more than `API_MESSAGES_SEARCH_MAX_MATCHES` messages of the range match; otherwise it sorts at most that many rows. Every other search (exact sender, From address, recipient, subject, Message-ID, sender and recipient domain, one delivery or quarantine status, one verdict) reads its index in time order and is never refused.

| Symptom                                                           | Cause                                                                                                                                                                         | Action                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "The search matches too many messages" next to the search (`422`) | A common beginning (`Invoice`, `Your order`) in a long range of a large tenant                                                                                                | Users type more of the subject, use the exact **Subject** search (an equality, never refused) or narrow the range. Raising `API_MESSAGES_SEARCH_MAX_MATCHES` lets each such request sort more rows (the statement still reads only the index of the range, but the sort and the replica's CPU grow linearly with the cap); raise it in steps and watch `api_message_search_refused_total{reason}` and the replica's CPU |
| "The search took too long" next to the search (`503`)             | The probe or the page statement ran past `API_MESSAGES_SEARCH_TIMEOUT_MS`: index entries of the pruned partitions outside the window are filtered by index condition pushdown | Usually a 31-day range of a very large tenant or an overloaded replica. Check the replica first (lag, CPU, `SHOW PROCESSLIST` for long statements). Raise `API_MESSAGES_SEARCH_TIMEOUT_MS` only while `PORTAL_API_TIMEOUT_MS` (the portal's upstream timeout, 15 s) stays above it; the timeout is the backstop that keeps one search from occupying a replica connection                                               |
| Many refusals for one tenant                                      | A tenant's users search a frequent prefix all day                                                                                                                             | Explain the exact Subject search and saved views with a short range; the metric has no tenant label (by design), so find the tenant through the audit trail: subject searches are audited as `message.searched` (first page only, the normalized value as SHA-256)                                                                                                                                                      |

The refusal body carries `code`, the api's message (with `maxMatches` for `422`) and `requestId`; the portal shows them next to the search and does not retry.

## Short pages and slow searches

- **A short or empty page with "More results may exist further back":** the search combined a driver with residual filters (for example a sender domain and a risk band): each request examines at most `API_LIST_SCAN_BUDGET_ROWS` entries of the driver's index ([ADR-0061](../architecture/adr/0061-message-search-drivers-and-saved-views.md)). Following the cursor ("Load next page") continues; this is not an error.
- **Slow lists:** every driver statement names its index (`FORCE INDEX`); EXPLAIN plans at 50 000+ messages are recorded in [docs/database/indexing.md](../database/indexing.md) and verified by `apps/api/integration/messages-explain.test.ts`. Production-scale timing has **not** been measured (local volumes only). Check the replica lag (`/health/ready` reports it) and `api_message_list_plan_total{driver,budgeted}` to see which plans run.

## `403 message_filter_forbidden`

A filter needs a permission beyond `message:read`: `recipient` / `subject` / `subjectPrefix` → `message:reveal` (a subject search reveals subjects; an exact recipient search confirms an address that every read masks — `recipientDomain` stays open), `deliveryStatus` → `delivery:read`, `quarantineStatus` → `quarantine:read`. The body names the `filter` and the `permission`. The portal hides those controls and drops such filters from a shared link or an old saved view with a notice, so the code reaches the portal only from a stale tab; API clients must remove the filter or obtain the permission. Saving a view applies the same check (`403` on save).

## Reveal limits and the `message.revealed` audit rows

- **Who:** `message:reveal` holders only: `organization_admin`, `security_analyst`, `compliance_auditor`, `super_admin`, and API keys whose scope holds it. `platform_admin`, `domain_admin`, `quarantine_reviewer`, `read_only_user` and `mailbox_user` never reveal ([rbac.md](../security/rbac.md#sensitive-message-metadata-step-72)).
- **Operations:** `POST /messages/reveal` (subjects of up to 100 messages: the explorer's "Show subjects" switch, one call per loaded page) and `POST /messages/{id}/reveal` (subject, To/Cc/Subject header values and recipient addresses of one message: the details page's **Reveal**). Both answer with `Cache-Control: no-store`, take no Idempotency-Key and write their audit rows in one writer transaction **before** the response: if that write fails the caller gets `503 service_unavailable` and no value.
- **`429 rate_limited` (`scope: route`):** more than `API_MESSAGES_REVEAL_PER_MINUTE` reveal calls by one user or API key in a minute; the response carries `Retry-After` and the `RateLimit-*` headers of the reveal bucket, and the portal shows a countdown. A legitimate triage user paging quickly through the explorer with subjects shown can reach 30 pages a minute; raise the limit per deployment if analysts need it, never per user. `503` with the limiter store down (Redis): check Redis (`api_rate_limit_store_errors_total`).
- **Reading the audit rows:** one row per revealed message, action `message.revealed`, resource `message` / `<message public id>`, actor (user or API key), source IP, `requestId`, and for a platform override session `metadata.override`. `metadata` holds what was revealed, never the values: bulk `{ fields: ["subject"], bulk: true }`; single `{ fields, headerCount?, recipients?: { count, firstRcptSeq, lastRcptSeq } }`. Where to look: the message's **Audit history** section (Email Details, "Message events"), the Audit logs page (`/audit-logs?action=message.revealed`) or `GET /audit/logs?action=message.revealed` / `?resourceType=message&resourceId=<id>` (served by the resource index `audit_logs_org_resource_created_idx`).
- **Suspected misuse** (many reveals by one principal): list `message.revealed` by actor over the period, revoke the user's sessions (Users → sessions) or the API key, and remove `message:reveal` from a custom role. Values already revealed cannot be recalled; the audit trail shows exactly which messages and fields were revealed.

## Masking rules (summary)

Applied by the api's service layer for every caller ([ADR-0062](../architecture/adr/0062-sensitive-message-metadata-masking-and-reveal.md), [API guide](../api/README.md#sensitive-message-metadata-and-reveal-messages-tag-step-72)):

| Value                                                                                                                                             | Read                                                            | Clear only through                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------- |
| Subject (lists and details)                                                                                                                       | `null`, `subjectMasked: true`                                   | the reveal operations                                         |
| Recipient addresses (recipients, deliveries)                                                                                                      | `f***@example.com`, `addressMasked` / `recipientMasked`         | single reveal (`recipients`)                                  |
| Matched user of a recipient                                                                                                                       | `null`                                                          | single reveal (`recipients`)                                  |
| Header values of To, Cc, Subject and any name outside the safe subset                                                                             | `value: null`, `masked: true`                                   | single reveal (`headers`)                                     |
| Addresses inside SMTP replies, delivery event details and Rspamd symbol options                                                                   | local part masked                                               | never                                                         |
| Quarantine entry recipient (operator routes)                                                                                                      | clear for quarantine deciders and `message:reveal`, else masked | —                                                             |
| Sender addresses, the safe header subset (From, Sender, Reply-To, Return-Path, Date, Message-ID, In-Reply-To, References, Authentication-Results) | clear                                                           | —                                                             |
| DLP matches                                                                                                                                       | masked samples with `dlp:read` (step 4.5)                       | the audited evidence route (`dlp:evidence_read`, MFA session) |

Bodies and attachment content are never fetched by the explorer or the details sections; the only message text the details page can show is the sanitized preview of a quarantined copy, loaded after an explicit click and audited (step 5.3). The full header block stays in the EML in object storage and is never fetched. Attachment file names are **not** masked (open product-owner question, ADR-0062).

## `403 quarantine_filter_forbidden`

`GET /quarantine/entries?recipient=…` from a caller who reads quarantine recipients masked (no quarantine decision permission and no `message:reveal`: `read_only_user`, `domain_admin`, `platform_admin` under an override, an API key with `quarantine:read` only). The search would confirm the masked address, so it is refused before anything is read (no `quarantine.searched` row). The Quarantine page hides the "Recipient (exact)" filter for these users and ignores it in a shared link (with a notice); API clients drop the filter or obtain a decision permission or `message:reveal`.

## Quarantine entries of one message

The details page's quarantine and audit sections call `GET /quarantine/entries?messageId=<id>` **without** `from`/`to`: since the step 7.2 close the api then returns every entry of the message, any recipient and round, whenever it was quarantined (a manual quarantine or a rescan long after receipt included), read by the message-led unique key `(message_id, lifecycle_round, rcpt_seq)` — at most recipients × rounds rows. Without `messageId` the range stays required and bounded by `QUARANTINE_SEARCH_MAX_RANGE_DAYS`. An entry created in the last seconds may be missing for the replica lag.

## Saved views

- Stored server-side in `saved_views` (per organization, user and kind `message_explorer`; not partitioned), read from the writer. Limits: `SAVED_VIEWS_MAX_PER_USER` (50) per user → `409 saved_view_limit_reached`; names 1–80 characters, unique per user (case-insensitive) → `409 saved_view_name_taken`; definition ≤ 8 KiB JSON, ≤ 24 filters, validated with the `GET /messages` rules and filter permissions.
- `409 saved_view_conflict`: the view was changed in another tab or device (`expectedRowVersion`); the portal reloads the list and asks the user to apply the view again.
- Members only: API keys `403 user_required`, platform override sessions `403 saved_views_member_only`. Audited `saved_view.created|updated|deleted` with the view id and kind only (names and filters may contain addresses or subjects typed by the owner; they are never logged or audited).
- A view whose filters no longer apply (a parameter removed, a permission revoked, an absolute range now invalid) is applied partially and the portal lists what it left out.
- Deleting a user deletes their views (`ON DELETE CASCADE`); deleting an organization is restricted while views exist (organization purge is deferred, step 1.2).

## Index rollout and write amplification

The migration `20261113212017_email_explorer_search` adds four `VIRTUAL` generated columns (`email_messages.subject_key`, `sender_domain`, `message_id_key`, `email_recipients.address_domain`; `ALGORITHM=INSTANT`, metadata only) and nine secondary indexes (`ALGORITHM=INPLACE, LOCK=NONE`), plus the `saved_views` table ([schema reference](../database/schema-reference.md), [indexing](../database/indexing.md)).

- **Online build:** the index builds read every partition of `email_messages`, `email_recipients`, `email_deliveries`, `quarantine_messages` and `audit_logs`; ingestion keeps running (`LOCK=NONE`) but the writer does extra I/O and the replica applies each `ALTER` after the writer finished it (replica lag for the duration of the build on the replica). Apply in a quiet window, watch replica lag (the api's `/health/ready` reports it) and disk space (each index needs space for a copy of its keys plus the online log).
- **Write cost:** `email_messages` gains five secondary indexes, three of them on regex-computed keys evaluated on every insert and every update of `subject`. Measured locally with `pnpm db:perf` (200 000 messages, one connection): `email_messages` inserts about 15–20 % slower beyond laptop noise, `email_recipients` perhaps 5–10 % (design note §13 WP1). Production-scale write cost is **not** measured; compare the ingestion commit latency before and after the rollout.
- **Hostile subjects:** the subject-key expression uses possessive quantifiers because the designed pattern raised `ER_REGEXP_TIME_OUT` on a crafted subject (WP1 deviation 1); a failing insert would reject mail, so any change of the expression needs the parity and hostile-subject integration tests (`apps/api/integration/messages-search-keys.test.ts`).
- **Rollback** (forward-only policy; manual): drop the nine indexes, the four generated columns and `saved_views` with a new forward migration. The api of step 7.2 needs the indexes for its plans; roll the api back first.

## Cursor invalidation after a deploy

The signed message cursor also covers the search driver, so a deploy that changes driver selection answers every outstanding message cursor once with `400 cursor_invalid`. The portal restarts the list from the first page; API clients must do the same. The window is bounded by `API_CURSOR_TTL_SECONDS`. A burst of `cursor_invalid` right after a deploy is expected; a burst at any other time means a cursor key rotation without `API_CURSOR_KEY_PREVIOUS` ([API guide](../api/README.md#pagination-and-lists)).

## Metrics

| Metric                                                      | Meaning                                                                                    |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `api_message_list_plan_total{driver,budgeted}`              | Which search plan served each list request (driver name; `budgeted` with residual filters) |
| `api_message_search_refused_total{reason}`                  | Subject-prefix refusals: `too_broad` (`422`), `timeout` (`503`)                            |
| `api_list_scan_budget_exhausted_total{resource="messages"}` | Budgeted pages that hit `API_LIST_SCAN_BUDGET_ROWS` (short pages)                          |
| `api_message_reveal_total{kind}`                            | Reveal calls: `bulk` (explorer pages) and `message` (details)                              |
| `api_message_reveal_values_total{field}`                    | Values revealed per field (`subject`, `headers`, `recipients`)                             |

No metric carries a tenant, principal or message id; use the audit trail for attribution.
