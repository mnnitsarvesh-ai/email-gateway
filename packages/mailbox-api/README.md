# @email-gateway/mailbox-api

Provider mailbox clients and pure helpers of **API-mode protection** (step API-1,
[design note](../../docs/plan/steps/35-api-mode-protection.md) D9, D10, D11, §5;
[ADR-0100](../../docs/architecture/adr/0100-api-mode-intake-mailbox-worker.md)). The mailbox-worker
uses the clients for change feeds and the inventory; the api uses the notification schema and the
client-state hash. The library has **no database, no Prisma, no Nest**; it depends on
`@email-gateway/idp-adapters` (8.5 HTTPS client, budgets, errors, simulators) and
`@email-gateway/provider-integrations` (the `*.mailbox_remediation` profiles).

API-1 only **read** mailboxes (the only writes were Graph change-notification subscriptions).
Step API-2 ([design note 36](../../docs/plan/steps/36-api-mode-remediation.md) R2, R3, R5, R6, R14;
ADR-0101/0102) adds the **remediation** calls (move to the gateway's hidden quarantine folder or
label, Junk, tag, recoverable delete, hard delete where allowed, restore) and the pure remediation
policy, plan and key helpers below. The library still never decides _when_ to act on its own: the
mailbox-worker's `copies` role decides with `decideRemediation`, its `remediate` role executes with
these clients.

## Clients

Every client method goes through `guardedCall(context, family, signal, run)`:

1. **Throttle gate** (`ThrottleGate` port): while the connection-family is paused the call fails
   `throttle_paused` (retryable, `retryAfterMs` = remaining pause) without contacting the provider.
2. **Budget**: `takeMailboxBudget` → 8.5's `takeBudget` with `integrationId = 'mbx:<apiConnectionPublicId>'`
   and the family (`graph`, `gmail`, `google_directory`); exhausted for 1 s → `rate_budget`.
3. **Call** through 8.5's `ProviderHttpClient` (origin allow-list per family, provider links only
   same-origin and under the base path, `https` unless `allowHttpEndpoints`, no redirects, no proxy
   environment, timeouts, byte caps, zod per endpoint, `401` drops the token and retries once).
4. **Errors** are normalized into one `MailboxApiError` (`code`, `retryable`, `retryAfterMs`,
   `status`, sanitized `providerCode`; never a header, token, URL, delta link, address or body).
   A `429`, a Google rate-limit `403` (`throttled`), `quota_exhausted`, or a `503` **with**
   `Retry-After` calls `throttle.pause({ apiConnectionPublicId, family, retryAfterMs ≤ 600 000,
status, code })` before the error is thrown.

`MailboxClientContext = { http: ProviderHttpClient, apiConnectionPublicId, budget: RateBudget,
throttle: ThrottleGate, sleep?, metrics?, maxThrottlePauseMs? }`. Tokens come from 8.5's
`TokenSource` (`get(signal)`, `invalidate()`); the worker adapts 8.2's
`ProviderTokenService.getAccessToken(grant, signal, { resource, subject })` (Microsoft
`resource: 'graph'`; Google `resource: 'google'` with subject = the mailbox for Gmail and the
grant's delegated administrator for the Directory). Map token-service failures to
`ConnectionAccessError`/`ProviderCallError` so they classify.

| Class                                                    | Method                                                                                                                                                        | Provider call                                                                                                                                                                                                                                                               |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GraphMailClient(context, token)`                        | `listUsers(pageLink \| undefined, signal)` → `{ users, nextLink }`                                                                                            | `GET /v1.0/users?$select=id,mail,userPrincipalName,proxyAddresses,accountEnabled&$top=999`, then `@odata.nextLink`                                                                                                                                                          |
|                                                          | `inboxDelta(userId, link \| undefined, signal)` → `GraphDeltaPage`                                                                                            | `GET /v1.0/users/{id}/mailFolders('inbox')/messages/delta?$select=id,internetMessageId,receivedDateTime,isDraft&changeType=created`, `Prefer: odata.maxpagesize=50`; `{ messages, removed, nextLink, deltaLink }` (exactly one link); `410`/`syncState*` → `cursor_expired` |
|                                                          | `messageMime(userId, messageId, maxBytes, signal)` → `MailboxContentStream`                                                                                   | `GET /v1.0/users/{id}/messages/{mid}/$value`, streamed (`requestStream`), over `maxBytes` → `response_too_large`                                                                                                                                                            |
|                                                          | `createSubscription({ userId, notificationUrl, lifecycleNotificationUrl, expirationDateTime, clientState }, signal)` → `{ id, expirationDateTime }`           | `POST /v1.0/subscriptions` `{ changeType: 'created', notificationUrl, lifecycleNotificationUrl, resource: "users/{id}/mailFolders('inbox')/messages", expirationDateTime, clientState, latestSupportedTlsVersion: 'v1_2' }`                                                 |
|                                                          | `renewSubscription(id, expiry, signal)` / `deleteSubscription(id, signal)` → `'deleted' \| 'not_found'`                                                       | `PATCH` / `DELETE /v1.0/subscriptions/{id}` (`404` on delete = done)                                                                                                                                                                                                        |
| `GmailClient(context, tokens: (mailbox) => TokenSource)` | `profile(mailbox, signal)` → `{ historyId }`                                                                                                                  | `GET /gmail/v1/users/{u}/profile`                                                                                                                                                                                                                                           |
|                                                          | `history(mailbox, startHistoryId, pageToken \| undefined, signal)` → `{ added[{ id, threadId, labelIds, inInbox }], nextPageToken, historyId, lastRecordId }` | `GET …/history?startHistoryId=…&historyTypes=messageAdded&labelId=INBOX&maxResults=500`; `404` → `cursor_expired`                                                                                                                                                           |
|                                                          | `messageMetadata(mailbox, id, signal)` → `{ id, threadId, labelIds, messageId, internalDate, sizeEstimate, historyId }`                                       | `GET …/messages/{id}?format=metadata&metadataHeaders=Message-ID`                                                                                                                                                                                                            |
|                                                          | `messageRaw(mailbox, id, maxBytes, signal)` → `MailboxContentStream`                                                                                          | `GET …/messages/{id}?format=raw`, streamed through `GmailRawExtractor` (decoded bytes ≤ `maxBytes`)                                                                                                                                                                         |
| `GoogleDirectoryClient(context, token)`                  | `listUsers(pageToken \| undefined, signal)` → `{ users[{ id, primaryEmail, aliases, suspended, archived }], nextPageToken }`                                  | `GET /admin/directory/v1/users?customer=my_customer&projection=basic&maxResults=500`                                                                                                                                                                                        |

### Remediation calls (step API-2, R6.2/R6.3)

Same call discipline (gate, budget of the family, `401` retry, classified errors, `Retry-After`
pause ≤ 600 s, redaction). Path templates never contain an id (`/v1.0/users/{id}/messages/{mid}/move`,
`/gmail/v1/users/{userId}/messages/{id}/modify`, …). Inputs that would change a provider query
(empty, over-long or control-character ids and names, whitespace in a Gmail `rfc822msgid`) fail
`bad_request` before any call.

| Class             | Method                                                                                                   | Provider call                                                                                                                                                                     |
| ----------------- | -------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GraphMailClient` | `findMessagesByInternetMessageId(user, internetMessageId, signal)` → `[{ id, parentFolderId, isDraft }]` | `GET /v1.0/users/{u}/messages?$filter=internetMessageId eq '<id>'&$select=id,parentFolderId,isDraft&$top=10` (angle brackets added when missing, `'` doubled per OData)           |
|                   | `getMessageState(user, id, signal)` → `{ id, parentFolderId, categories }`                               | `GET …/messages/{id}?$select=id,parentFolderId,categories`                                                                                                                        |
|                   | `wellKnownFolderId(user, name, signal)`                                                                  | `GET …/mailFolders/{inbox\|junkemail\|sentitems\|recoverableitemsdeletions\|msgfolderroot}?$select=id`                                                                            |
|                   | `ensureChildFolder(user, parentWellKnown, displayName, hidden, signal)` → `{ id, created }`              | `GET …/mailFolders/{parent}/childFolders?includeHiddenFolders=true&$filter=displayName eq '<name>'`, else `POST …/childFolders { displayName, isHidden }` (`409` → look up again) |
|                   | `moveMessage(user, id, destinationId, signal)` → `{ id, parentFolderId }`                                | `POST …/messages/{id}/move { destinationId }` — the answer carries a **new id** (store it; the old id answers `404`)                                                              |
|                   | `setCategories(user, id, categories, signal)`                                                            | `PATCH …/messages/{id} { categories }` (whole list; compute it with `graphCategoriesWith`)                                                                                        |
|                   | `permanentDelete(user, id, signal)`                                                                      | `POST …/messages/{id}/permanentDelete` (`204`; irreversible)                                                                                                                      |
| `GmailClient`     | `findMessagesByRfc822Id(mailbox, messageId, signal)` → `[{ id, threadId }]`                              | `GET …/messages?q=rfc822msgid:<id without brackets>&includeSpamTrash=true&maxResults=10`                                                                                          |
|                   | `messageLabels(mailbox, id, signal)` → `{ id, threadId, labelIds }`                                      | `GET …/messages/{id}?format=minimal`                                                                                                                                              |
|                   | `listLabels(mailbox, signal)` / `ensureLabel(mailbox, name, hidden, signal)` → `{ id, created }`         | `GET …/labels`; create `POST …/labels { name, labelListVisibility: labelHide\|labelShow, messageListVisibility: hide\|show }` (name match case-insensitive; `409` → list again)   |
|                   | `modifyLabels(mailbox, id, add, remove, signal)`, `trash(…)`, `untrash(…)` → `{ id, labelIds }`          | `POST …/messages/{id}/modify { addLabelIds, removeLabelIds }`, `POST …/trash`, `POST …/untrash`                                                                                   |

There is deliberately **no Gmail `delete`**: `messages.delete` needs the full
`https://mail.google.com/` scope, which the `google.mailbox_remediation` grant (`gmail.modify`)
does not request; the simulator proves the refusal (`403 insufficientPermissions`).

`MailboxContentStream = { contentLength: number | undefined, body: AsyncIterable<Uint8Array> }`;
iteration failures are `MailboxApiError`s; breaking out of the loop cancels the transfer.

The HTTP client needs a `maxResponseBytes` that fits a page of 999 Graph users with their proxy
addresses (4 MiB is ample); MIME and raw bodies use their own per-call `maxBytes`.

## Budget and throttling

- `MAILBOX_API_FAMILIES`, `MailboxApiFamily`, `mailboxBudgetId(id)` (`mbx:<id>`),
  `parseMailboxBudgetId`, `takeMailboxBudget(...)`, `MAX_THROTTLE_PAUSE_MS` (600 000).
- `ThrottleGate { remainingMs(apiConnectionPublicId, family); pause(event: ThrottleEvent) }`: the
  worker implements it over Redis `mbx:throttle:<apiConnectionPublicId>:<family>` (TTL =
  `retryAfterMs`) and records `throttled_until` and the `throttled_429`/`throttled_503` counters in
  `pause`. `InMemoryThrottleGate` (tests, single process) and `OPEN_THROTTLE_GATE`.

## Pure helpers

| Export                                                                                                                                | Purpose                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GmailRawExtractor` (`push`, `end`, `static extract(source, { maxDecodedBytes, maxOtherBytes? })`)                                    | Incremental scanner of the top-level JSON string `raw` (any field order, escapes, nested `raw` keys ignored), base64url/base64 decoding chunk by chunk, bounded                                                                                                                                                       |
| `extractCopyHeaders(bytes \| string, { maxBytes? })` → `CopyHeaders`                                                                  | `messageId` (raw, ≤ 998), `from` (addr-spec), `date`, `subject` (raw, ≤ 998), `to[]`, `cc[]`, `topReceivedAt` (date of the topmost `Received:`), `complete`; folded headers, RFC 5322 and obsolete dates; also `parseRfc5322Date`, `parseAddressList`, `receivedHeaderDate`, `parseHeaderFields`, `normalizeAddrSpec` |
| `copyMessageIdHash(organizationId, messageId)`                                                                                        | SHA-256 hex of `api-copy/1\0<org>\0<Message-ID without angle brackets and surrounding whitespace>`, null without an id; `normalizeMessageId`                                                                                                                                                                          |
| `ingestKeyForCopy({ connectionPublicId, mailboxPublicId, providerMessageId })`                                                        | `v2:mbx:` + SHA-256 hex of `conn\|mailbox\|providerMessageId`                                                                                                                                                                                                                                                         |
| `objectRefForCopy({ …, organizationId })`, `emlObjectKeyForCopy(ref, at)`                                                             | First 32 hex of SHA-256 of `mbx\|conn\|mailbox\|providerMessageId\|org`; `org/<org>/eml/<yyyy>/<mm>/<dd>/<ref>.eml`                                                                                                                                                                                                   |
| `deriveClientState(secret, mailboxPublicId, version)`, `clientStateHash(value)`, `clientStateMatches(value, storedHash)`              | base64url(HMAC-SHA256(secret, `api-mode-graph-client-state/1\0<id>\0<version>`)) cut at 48 characters (= the 43-character digest); SHA-256 hex; constant-time compare                                                                                                                                                 |
| `graphNotificationSchema`, `graphNotificationItemSchema`, `GRAPH_LIFECYCLE_EVENTS`, `isGraphLifecycleEvent`, `isGraphValidationToken` | `{ value: [1..1000] of { subscriptionId, clientState?, changeType?, lifecycleEvent?, tenantId?, subscriptionExpirationDateTime? } }`, other keys dropped; nulls → undefined                                                                                                                                           |
| `classifyRecipientDirection(sender, recipient, orgDomains)`, `addressDomain`                                                          | `internal` when both sides are organization domains, else `inbound`                                                                                                                                                                                                                                                   |
| `lagBucket(ms)`, `LAG_BUCKETS`, `copyLagMs(deliveredAt, verdictAt)`, `lagPercentileSeconds(counts, q, maxMs?)`                        | Counter buckets `le_60s … gt_3600s`; bucket percentiles for the health check and the overview                                                                                                                                                                                                                         |
| `evaluateMailboxCoverage(mailbox, now, { feedPollIntervalSeconds, journalCoverageDays })`, `coveragePercent`                          | D11.2 `covered \| gap \| out_of_scope`                                                                                                                                                                                                                                                                                |
| `evaluateApiModeHealth(input, config)`, `apiModeHealthDocumentSchema`, `API_MODE_HEALTH_CHECK_CODES`                                  | D11.3 checks (`connection.active`, `intake.present`, `intake.journal_health`, `mailbox_access.grant`, `coverage.percent`, `lag.p95_1h`, `throttling.1h`, `feeds.errors`, `domains.api_mode_mx`), worst status, `api-mode-health/1` document, `failingChecks`                                                          |
| `MailboxApiError`, `toMailboxApiError`, `MAILBOX_API_ERROR_CODES`, `isGraphCursorExpired`                                             | The one error type (8.5 codes + `cursor_expired`, `throttle_paused`)                                                                                                                                                                                                                                                  |
| `M365_MAILBOX_REMEDIATION_PROFILE`, `GOOGLE_MAILBOX_REMEDIATION_PROFILE`, `MAILBOX_PROFILE_KEYS`, `MAILBOX_TOKEN_RESOURCES`           | Re-exported profiles and the token resource per family                                                                                                                                                                                                                                                                |

## Remediation (step API-2)

### Policy document `api-remediation-policy/1` (R2.1)

`remediationPolicySchema` (strict everywhere, unknown keys refused): `{ v: 1, rules: [1..16] of
{ id (1..48, [a-z0-9_-], unique), when: { verdicts (1..9, unique; clean/unknown refused), minLevel?,
maxLevel? (≥ minLevel; low|medium|high|critical), hardBlock?, minScore? (0..1000) }, action:
move_quarantine|move_junk|tag|soft_delete|hard_delete|none }, remediateScanFailures?: false }`.
`when.policyDispositions` is **reserved** for the later policy-evaluation step and refused with the
custom issue `unsupported_until_policy_evaluation` (message and `params.code`). The mode
(`detect_only`/`enforce`) is a column of `api_remediation_policies`, not part of the document.
`parseRemediationPolicy`, `hardDeleteRuleIds` (the api refuses them while
`API_MODE_HARD_DELETE_ENABLED` is off), `canonicalJson` / `canonicalPolicySha256` (sorted keys; the
`document_sha256` column and the decision provenance).

`DEFAULT_REMEDIATION_POLICY` = P1 in `enforce` (frozen): `p1-high-confidence-malware-phishing-hb`
(malware/phishing + any hard block → `move_quarantine`), `p1-high-confidence-malware-phishing`
(malware/phishing, level critical → `move_quarantine`), `p1-other-malware-phishing` (→ `tag`),
`p1-suspicious` (suspicious/BEC → `tag`); spam, bulk and DLP → nothing. `REMEDIATION_PRESETS`:
`p1`, `detectOnlyStart` (P1 rules, mode `detect_only`), `strict` (P1 + `strict-spam-junk`: spam →
`move_junk`). No default or preset contains `hard_delete`.

### Decision order (R2.2)

`decideRemediation(input, { mode, document }, { hardDeleteEnabled })` → `{ outcome: 'none' }` |
`{ outcome: 'skip', reason, ruleId, action }` | `{ outcome: 'act', action, ruleId, simulated, notes }`:

1. copy not `scanned`, or verdict `clean`/`unknown`/null → `none`;
2. first matching rule (verdict listed and every present bound holds: a null level fails
   `minLevel`/`maxLevel`, no hard block fails `hardBlock: true`, a null score fails `minScore`); no
   match or action `none` → `none`;
3. verdict authority `inline` (hybrid) → skip `inline_authority`;
4. domain effective mode not `api`/`hybrid`, or mailbox `disabled`/`deleted` → skip `out_of_scope`;
   4b. (step API-3, note 37 C8.5) copy `direction: 'internal'` while `context.internalMailEnabled`
   is `false` → skip `internal_mail_disabled` (both fields optional: absent = `inbound` / `true`);
5. `hard_delete` without the platform setting → skip `hard_delete_disabled`;
6. mode `detect_only` → `act` with `simulated: true` (no provider call);
7. connection paused → skip `remediation_paused`;
8. no active mailbox grant → skip `no_mailbox_access`;
9. `act`. A Google `hard_delete` carries the note `hard_delete_falls_back_to_trash`.

`resolveEffectivePolicy({ organization, domains }, domainId)` → `{ scope: platform_default |
organization | domain, policy, publicId, rowVersion }` (domain row → organization row → P1);
`buildDecisionRecord(effective, input, decision, provenance?)` → `api-remediation-decision/1` (`{ v, policy: {
scope, publicId, rowVersion, sha256 }, mode, ruleId, inputs: { verdict, riskScore, level,
hardBlocks ≤ 9, verdictAuthority }, policyOutcome: null, notes }`, schema
`remediationDecisionRecordSchema`). `remediationActionKey(copyPublicId, action, generation)` = hex
SHA-256 of `api-remediation/1\0<copyPublicId>\0<action>\0<generation>` (the unique `action_key`).
A clawback decision (step API-3 C3.2) passes `provenance = { source: 'clawback', clawbackId }`,
recorded as the notes `source:clawback` and `clawback:<clawbackId>` (the record schema is unchanged).

### Provider mappings (R3) and helpers

`REMEDIATION_PROVIDER_ACTIONS` is the R3 table as data (Graph steps, Gmail steps, reversal,
quarantine container):

| Action            | Graph (`Mail.ReadWrite`)                         | Gmail (`gmail.modify`)                                            | Reversal        | Entry container     |
| ----------------- | ------------------------------------------------ | ----------------------------------------------------------------- | --------------- | ------------------- |
| `move_quarantine` | ensure hidden folder under `msgfolderroot`, move | ensure hidden label, modify +label −`INBOX`                       | `restore_inbox` | `quarantine_folder` |
| `move_junk`       | move to `junkemail`                              | modify +`SPAM` −`INBOX`                                           | `restore_inbox` | `junk`              |
| `tag`             | add the tag category (no-op when present)        | ensure tag label, modify +label                                   | `remove_tag`    | —                   |
| `soft_delete`     | move to `recoverableitemsdeletions`              | `trash`                                                           | `restore_inbox` | `deleted_items`     |
| `hard_delete`     | `permanentDelete`                                | **falls back to `trash`** (`hard_delete_unsupported_provider`)    | —               | —                   |
| `restore_inbox`   | move to `inbox`, then remove the tag category    | `untrash` when trashed, modify +`INBOX` −`SPAM` −quarantine label | —               | releases the entry  |
| `remove_tag`      | remove the tag category                          | modify −tag label                                                 | —               | —                   |

Helpers: `isReversible`, `reversalOf`, `isReversal`, `containerOf`, `createsQuarantineEntry`,
`executedContainerOf(action, provider)` (`provider_refs.container`), `executionResultCode`,
`graphTargetReached` / `gmailTargetReached` (the "already in target" check over the state read
before acting), `graphCategoriesWith`, `gmailModifyFor` (only the label changes that still differ),
`graphLocateCandidates` / `gmailLocateCandidates` (drop drafts and Sent Items / sent-only matches,
at most 5), `verdictToQuarantineReason` and `hardBlockToPrimaryEngine` (R9.1 mappings of a mailbox
entry), `mailboxEntryExplanation(ruleId)` (content-free). `classifyRemediationError(error)` maps a
`MailboxApiError` onto `throttled` (429, Google rate-limit 403, quota, 503 **with** `Retry-After`,
paused gate, budget: wait, no attempt counted), `retryable` (other 5xx, timeouts: back-off),
`forbidden` (401 after the token retry, 403 → `provider_forbidden`), `not_found` (404 → re-ensure
the container once or run the locate step), `rejected` (400 and other non-retryable answers →
`provider_rejected`) and `access_revoked` (no token → `mailbox_access_revoked`).

Vocabularies (string unions mirroring the Prisma enums): `REMEDIATION_ACTIONS`,
`REVERSAL_ACTIONS`, `REMEDIATION_ACTION_KINDS`, `REMEDIATION_MODES`, `REMEDIATION_TRIGGERS`,
`REMEDIATION_STATUSES`, `COPY_REMEDIATION_STATES`, `REMEDIATION_MAILBOX_CONTAINERS`,
`REMEDIATION_SKIP_REASONS`, `REMEDIATION_RESULT_CODES`, `REMEDIATION_FAILURE_CODES`,
`MESSAGE_VERDICTS`, `RISK_LEVELS`.

**Hard delete** is off by default (`API_MODE_HARD_DELETE_ENABLED=false`), needs an explicit tenant
rule, is never in a default or preset, never manual and never from the assistant. On Graph it is
`permanentDelete` (irreversible); on Gmail it runs the Trash plan and records
`hard_delete_unsupported_provider`.

### Health (R14)

`API_MODE_HEALTH_CHECK_CODES` gains `remediation.failures_1h`, `remediation.backlog`,
`remediation.access` and `remediation.paused` (13 codes; the document cap stays 16).
`evaluateApiModeHealth` evaluates them only when the input has the optional `remediation` block
`{ succeeded1h, failed1h, oldestPendingAgeSeconds, enforceWithoutGrant, paused, thresholds: {
failureWarnPercent, failureFailPercent, backlogWarnMinutes, backlogFailMinutes } }`: failure rate
rated from 5 attempts (> warn % → warn, > fail % → fail), oldest pending age (> warn minutes → warn,

> fail minutes → fail), enforce without an active grant → warn, paused → warn
> (`evaluateRemediationHealth`). Evidence carries counts, percentages and ages only (≤ 512).

Thresholds are configuration of the caller (`API_MODE_*` keys, design D16), never constants here,
except the fixed ratios of D11.3 (`FEEDS_INTAKE_MIN_RATIO` 0.9, `FEEDS_ERROR_WARN_RATIO` 0.1).

## Clawback, search and purge (step API-3)

Pure helpers of retroactive clawback ([design note 37](../../docs/plan/steps/37-api-mode-clawback-reporting.md)
C2–C7, C17; ADR-0103). The api creates admin/campaign/report clawbacks and decides approvals; the
mailbox-worker's `clawback` role materializes, plans and queues targets as `api_remediation_actions`
rows (the `remediate` role stays the only action engine). Nothing here touches a database.

| Export                                                                                                                                                                                                                                        | Purpose                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CLAWBACK_TRIGGERS`, `CLAWBACK_STATUSES` (+ `ACTIVE_`, `CANCELLABLE_`, `RESTORABLE_CLAWBACK_STATUSES`), `CLAWBACK_DECISION_MODES`, `CLAWBACK_ACTIONS`, `CLAWBACK_RESTORE_STATUSES`, `CLAWBACK_APPROVAL_REASONS`, `CLAWBACK_APPROVAL_STATUSES` | Mirrors of the `api_clawbacks` enums                                                                                                                                                                                                                                                                                                                                                    |
| `CLAWBACK_TARGET_STATUSES`, `CLAWBACK_TARGET_RESTORE_STATUSES`, `CLAWBACK_MATCH_KEYS`, `CLAWBACK_TARGET_REASON_CODES`, `CLAWBACK_RESTORE_REASON_CODES`, `entryStateRestoreCode(state)`                                                        | Target enums and the §5 reason codes (policy outcomes, eligibility and planning skips, `internal_mail_disabled`, every R5 result code; restore `approval_required`, `refused`, `not_reversible`, `entry_<state>`)                                                                                                                                                                       |
| `CLAWBACK_SIGNAL_KINDS`, `CLAWBACK_HARD_BLOCKS` / `CLAWBACK_HARD_BLOCK_IDS`, `CLAWBACK_STRENGTH_ORDER`, `actionStrength`, `CLAWBACK_ACTION_TRIGGERS`, `API_MODE_ACTION_TRIGGERS`, `REMEDIATION_PURGE_PERMISSION`                              | Signal kinds; synthetic hard blocks `hb.clawback.url`, `hb.clawback.threat_intel`, `hb.clawback.analyst`; `tag < move_junk < move_quarantine < soft_delete < hard_delete`; action triggers `clawback`/`purge` (and the whole `ApiRemediationTrigger` enum); `remediation:purge`                                                                                                         |
| `clawbackCriteriaSchema`, `parseClawbackCriteria(value, { now, maxWindowDays, fromCampaignSeed? })`, `clawbackWindowIssues`, `normalizeClawbackCriteria`, `canonicalCriteriaSha256`                                                           | `api-clawback-criteria/1` (C4.1): strict; keys `messageIdHashes` ≤ 10, `attachmentSha256` ≤ 20, `urlSha256` ≤ 20, `urlDomains`/`senders`/`senderDomains` ≤ 5 (TI only), `senderSubject { sender, subjectKey ≤ 128 code points }`; ≥ 1 key (OR); window ≤ `maxWindowDays`, `from ≥ now − 186 d`, sender + subject ≤ 7 days unless from a campaign seed; errors carry codes, never values |
| `clawbackSignalSchema`, `clawbackSignalFactsSchema`, `UNSUPPORTED_UNTIL_ATP4`                                                                                                                                                                 | `api-clawback-signal/1` (§5); `refs.campaignRef` refused with `unsupported_until_atp4`                                                                                                                                                                                                                                                                                                  |
| `clawbackSignalKey(organizationId, { source: 'late', messageId, receivedAt, kind, revision, urlSha256 } \| { source: 'ti', table, rowId })`                                                                                                   | C2.5 `signal_key`: hex SHA-256 of `api-clawback-signal/1\0<org>\0late\0<messageId>\0<receivedAt ISO>\0<kind>\0<revision ?? urlSha256>` or `…\0ti\0<table>\0<rowId>`                                                                                                                                                                                                                     |
| `signalFacts(input)`, `tiEligible(indicator, minConfidence, now)`, `signatureEligible(signature, now)`                                                                                                                                        | The C3.1 table (`{ verdict, level, hardBlocks, score? }`); C2.2 eligibility (types `url`/`domain`/`file_sha256`/`email`, never `ip`; severity high/critical; confidence floor; not expired)                                                                                                                                                                                             |
| `targetEligibility(...)`, `clawbackRemediationInput(...)`, `clawbackPolicyOutcome(decision)`, `planClawbackTarget(...)`                                                                                                                       | C5.2 skips (`no_mailbox_access`, `out_of_scope`, `mailbox_inactive`, `report_mailbox`); the C3.2 `decideRemediation` input (copy authority, `max(score)`); decision → `skip`/`simulate`/`act`; C5.3 escalation-only planning                                                                                                                                                            |
| `requiresPurgeApproval({ mailboxesEligible, threshold, action, autoCap })`, `decidePurgeApproval({ approver, request, now })`                                                                                                                 | C6: reasons `mailbox_threshold`, `hard_delete`, `auto_cap`; Q14 rules (`api_mode_purge_approval_forbidden` `api_key`/`missing_permission`/`requester`, `api_mode_purge_approval_not_pending` `not_pending`/`expired`; no recipient rule)                                                                                                                                                |
| `subjectKeyOf(subject)`, `messageIdKeyOf(id)`                                                                                                                                                                                                 | Parity copy of the api's `normalizeSubjectKey` / `normalizeMessageIdKey` (C4.4; same vectors, drift-guard test)                                                                                                                                                                                                                                                                         |
| `ORG_SETTINGS_DEFAULTS`, `ORG_SETTINGS_BOUNDS`, `orgSettingsSchema`, `resolveOrgSettings(row \| null)`, `AUTO_CLAWBACK_MODES`                                                                                                                 | C17 defaults (internal mail on, `enforce`, cap 500, P2 50, lookback 14 d, TI confidence 80, ack and feedback on); C14 #19 bounds; row or defaults (clamped)                                                                                                                                                                                                                             |

**Planning (C5.3)**, in order: a `hard_delete` in policy mode → `hard_delete_not_allowed` (an explicit
one with the setting off → `hard_delete_disabled`); copy `pending` → `remediation_in_progress`; copy
`remediated` with an equal or stronger action (or an unknown one) → `already_remediated`, a weaker
one → act (escalation, the earlier tag stays); copy `restored` whose restore completed after
`signal_at` (or at an unknown time) → `restored_after_signal`; otherwise act.

**Signal facts (C3.1):** sandbox revision → its verdict, level (`none` read as `low`) and hard
blocks; URL dynamic malicious → `phishing`/`critical`/`hb.clawback.url`, suspicious →
`suspicious`/`high`; TI file hash → `malware`, URL/domain/email by category (`malware`/`c2` →
`malware`, `phishing`/`scam` → `phishing`, `spam` → `spam`, none/`other` → `suspicious`), level from
severity, `hb.clawback.threat_intel` when severity `critical` or confidence ≥ 90; malware signature
→ `malware`, level from severity, treated as confidence 100 (a confirmed hash); report analyst
`malicious` → the original's `malware`/`phishing`/`bec` else `phishing`, `critical`,
`hb.clawback.analyst`; admin/campaign → the chosen verdict and level (default `critical`, with
`hb.clawback.analyst`).

## Reported phishing (step API-3)

Pure helpers of the report mailbox (note 37 C10–C11; ADR-0104). The mailbox-worker's `reports`
role reads the report copy's EML from S3 and calls them; the per-reporter rate limit stays in the
worker.

| Export                                                                                                                                                                   | Purpose                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REPORT_STATUSES`, `REPORT_IDENTIFICATIONS`, `REPORT_REJECT_REASONS`, `REPORT_ASSESSMENTS`, `REPORT_ANALYST_VERDICTS`, `REPORT_FEEDBACK_STATES`, `REPORT_FEEDBACK_KINDS` | Mirrors of the `api_user_reports` enums and codes                                                                                                                                                                                                                                                                                  |
| `extractReportedMessage(bytes, { maxBytes, maxOriginalBytes, maxDepth?, maxParts? })`                                                                                    | Bounded MIME walker (depth ≤ 4, parts ≤ 200): `attachment` (first `message/rfc822`/`message/global`, or `application/octet-stream`/`application/eml` named `*.eml`; transfer-decoded; headers; `extraOriginals`; attachment hashes), `inline`, `unsupported` (`.msg`), `none`; failures `too_large` (with `limit`), `parse_failed` |
| `parseInlineForward(text)`, `INLINE_FORWARD_SEPARATORS`, `parseForwardDate`, `htmlToText`, `decodeEncodedWords`, `originalAttachmentHashes`, `reportEnvelopeHeaders`     | Inline forward separators (English, German, French, Spanish, Italian, Dutch, Portuguese; Outlook, Gmail, Apple Mail, Thunderbird and the Outlook rule line) followed within 20 lines by `From:`/`Subject:` (optional `Date:`/`Sent:`/`Message-ID:`); client date formats; linear HTML-to-text; RFC 2047                            |
| `reportOriginalSchema`, `buildReportOriginal({ organizationId, extraction, fallbackAttachmentSha256?, urlSha256? })`, `reportIdentificationOf`                           | `api-report-original/1`: `messageIdHash` (`copyMessageIdHash`), `sender` (lower case), `subjectKey` (`subjectKeyOf`), `date`, `attachmentSha256` ≤ 20, `urlSha256` ≤ 50 (caller fills), `extraOriginals`; never bodies                                                                                                             |
| `reportGroupKey(original)`, `assessReport(scan)`, `reporterCheck({ reporterAddress, orgDomains, reportMailboxAddresses, headers })`                                      | C11.3 group key (Message-ID hash, else SHA-256 of sender + subject key + date hour, else null); C11.2 hint (`malicious`, `suspicious`, `clean`, `unknown`); C10.1 `external_reporter`, `loop`, `auto_submitted`                                                                                                                    |

The attachment hashes of an attached original follow `@email-gateway/mime-parser`'s rule (every leaf
except the first `text/plain` and `text/html` bodies; leaves of nested messages included), so they
match `email_attachments.sha256`. The walker never renders or executes content; failures carry codes
only (no address, subject or body).

### Health (step API-3, C13)

`API_MODE_HEALTH_CHECK_CODES` gains `clawback.stalled` and `reports.backlog` (15 codes; cap 16),
evaluated only with the optional input blocks `clawback: { oldestActiveAgeSeconds, thresholds: {
stalledWarnMinutes, stalledFailMinutes } }` (> warn → warn, > fail → fail) and `reports: {
hasReportMailbox, oldestPendingTriageAgeSeconds, thresholds: { triageWarnHours } }` (> warn hours →
warn, never fail) (`evaluateClawbackHealth`, `evaluateReportsHealth`).

## Testing (`@email-gateway/mailbox-api/testing`)

`createMailboxTestbed(options?)` starts the in-process simulators of
`@email-gateway/idp-adapters/testing` (Graph mail delta, `$value`, subscriptions with the
validation handshake and notification push; Gmail profile, history, metadata and streamed raw;
Google Directory; step API-2: per-mailbox message location state, Graph folders/move/categories/
permanent delete, Gmail labels/modify/trash/untrash — assert with `messageLocation(script, user, id)`) on 127.0.0.1 and wires the three clients with `SimTokenSource`s for the two
`mailbox_remediation` grants, a `RecordingRateBudget` and an `InMemoryThrottleGate` on a
`TestClock`. Deliver messages with `tb.sims.deliver({ user, eml })` (`syntheticEml(...)`), script
failures with `tb.sims.script.inject(...)`, expire cursors with `expireCursors(script, user)` and
assert "no fetch" with `tb.sims.script.calls(...)`. `collectStream(body)` collects a stream.

```sh
pnpm --filter @email-gateway/mailbox-api build typecheck lint test
```

No suite contacts a real Microsoft or Google endpoint or the Internet.
