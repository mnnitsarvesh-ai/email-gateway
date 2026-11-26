# @email-gateway/mailbox-api

Provider mailbox clients and pure helpers of **API-mode protection** (step API-1,
[design note](../../docs/plan/steps/35-api-mode-protection.md) D9, D10, D11, §5;
[ADR-0100](../../docs/architecture/adr/0100-api-mode-intake-mailbox-worker.md)). The mailbox-worker
uses the clients for change feeds and the inventory; the api uses the notification schema and the
client-state hash. The library has **no database, no Prisma, no Nest**; it depends on
`@email-gateway/idp-adapters` (8.5 HTTPS client, budgets, errors, simulators) and
`@email-gateway/provider-integrations` (the `*.mailbox_remediation` profiles).

API-1 only **reads** mailboxes: the only `POST`/`PATCH`/`DELETE` calls are Graph change-notification
subscriptions. There is no client method that changes mailbox content.

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

Thresholds are configuration of the caller (`API_MODE_*` keys, design D16), never constants here,
except the fixed ratios of D11.3 (`FEEDS_INTAKE_MIN_RATIO` 0.9, `FEEDS_ERROR_WARN_RATIO` 0.1).

## Testing (`@email-gateway/mailbox-api/testing`)

`createMailboxTestbed(options?)` starts the in-process simulators of
`@email-gateway/idp-adapters/testing` (Graph mail delta, `$value`, subscriptions with the
validation handshake and notification push; Gmail profile, history, metadata and streamed raw;
Google Directory) on 127.0.0.1 and wires the three clients with `SimTokenSource`s for the two
`mailbox_remediation` grants, a `RecordingRateBudget` and an `InMemoryThrottleGate` on a
`TestClock`. Deliver messages with `tb.sims.deliver({ user, eml })` (`syntheticEml(...)`), script
failures with `tb.sims.script.inject(...)`, expire cursors with `expireCursors(script, user)` and
assert "no fetch" with `tb.sims.script.calls(...)`. `collectStream(body)` collects a stream.

```sh
pnpm --filter @email-gateway/mailbox-api build typecheck lint test
```

No suite contacts a real Microsoft or Google endpoint or the Internet.
