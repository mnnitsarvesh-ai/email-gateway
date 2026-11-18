# @email-gateway/archive

The pure library of step 8.1, journaling and compliance archiving. The binding design is
[docs/plan/steps/23-journaling-archiving.md](../../docs/plan/steps/23-journaling-archiving.md)
(A1, A3–A4, A8, A10–A13, A16–A18, A22, §4.1–§4.3) together with ADRs
[0064](../../docs/architecture/adr/0064-journal-capture-intents-and-archive-consumer.md) to
[0069](../../docs/architecture/adr/0069-ediscovery-cases-searches-and-exports.md).

It covers the archive crypto, the JSON documents, the capture decision, journal eligibility,
retention and expiry, legal-hold matching, the OpenSearch template and builders, the snapshot
codec, object keys, download tokens and export manifests. The archive-worker (capture, index,
lifecycle and ediscovery roles), the api (`archive` and `ediscovery` modules), the quarantine
disposal rules (`@email-gateway/quarantine`, A23) and the test suites all use it, so each of
these rules has one implementation.

## Invariants

- **No I/O, no clock, no logger.** Time is always a parameter (`now`). Callers read MySQL, S3
  and OpenSearch and pass the facts in. The OpenSearch HTTP client lives in
  `@email-gateway/common` (`OpenSearchModule`).
- **Errors carry no detail.** Crypto errors (`ArchiveCryptoError`) give only a reason
  (`malformed`, `unauthentic` or `integrity`). Configuration errors (`ArchiveKeyConfigError`)
  name the configuration key and never its value. Document, key, codec and query errors name
  the document, path or filter, never the content.
- **Tenant first.** Every AAD, object key, index name, alias and query is built from the
  internal organization id. `buildArchiveSearchQuery` always adds the organization term and a
  bounded `received_at` range. `assertKeyOfOrganization` checks every S3 key read or written.
- **Metadata only in the index.** `buildArchiveSearchDocument` emits exactly the fields of the
  `dynamic: strict` template (§4.3). It never emits a body, a header value other than the
  subject and the addresses, an attachment's content or a URL.
- **Extend-only retention.** `effectiveRetainUntil` and `decideExpiry` never move a date
  earlier.
- **Fail-safe holds.** Hold criteria that cannot be parsed match every message.

## Formats

| Id                                         | Where                                                                                       | Defined in                                  |
| ------------------------------------------ | ------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `archive-object/1`                         | every archive object (`.bin`)                                                               | `crypto/object-format.ts`, design A8        |
| SecretBox `v1.<kid>.<iv>.<tag>.<ct>`       | `archive_encryption_keys.wrapped_key` (kid = root key id), `wrapped_dek` (kid `k<version>`) | `crypto/secret-box.ts`, `crypto/keys.ts`    |
| `archive-settings/1`                       | `archive_settings.settings`                                                                 | `documents/settings.ts`, A22                |
| `archive-retention/1`                      | `archive_retention_policies.criteria`                                                       | `documents/criteria.ts`, A11                |
| `archive-hold/1` (+ the 5.3 legacy subset) | `archive_legal_holds.criteria`                                                              | `documents/criteria.ts`, `holds/matcher.ts` |
| `archive-parties/1`                        | `email_archives.parties`                                                                    | `documents/records.ts`                      |
| `objects`, `scan_rounds`                   | `email_archives.objects`, `email_archives.scan_rounds`                                      | `documents/records.ts`                      |
| `archive-journal/1`                        | the journal object                                                                          | `documents/records.ts`                      |
| `archive-scan/1`                           | scan snapshot objects (tagged codec rows)                                                   | `snapshot/scan-snapshot.ts`                 |
| `archive-search/1`                         | `ediscovery_searches.criteria`, `GET /archive/messages` filters                             | `documents/search.ts`                       |
| `archive-export-manifest/1`                | `manifest.json` of export packages (+ Ed25519 `manifest.sig`)                               | `documents/search.ts`, `export/manifest.ts` |
| Download token `v1.<payload>.<mac>`        | `GET /archive/downloads/{token}`                                                            | `tokens/download-token.ts`                  |

The `archive-object/1` layout is a 51-byte header: `EGARC1`, version `0x01`, kind (1 eml,
2 journal, 3 scan, 4 export), chunk size (u32 BE), a 32-byte salt and a 7-byte nonce prefix.
Chunks of `ARCHIVE_CHUNK_BYTES` (default 65 536) follow. Each chunk is AES-256-GCM with
nonce = prefix ‖ counter (u32 BE) ‖ final flag and AAD = the header, followed by its 16-byte
tag. The object key is HKDF-SHA256(DEK, salt,
`eg-archive-object/v1\0<kind>\0<organizationId>\0<subjectId>`). Truncation, reordering,
extension, tampering, a wrong kind or a wrong key all fail decryption. Both stream directions
keep memory bounded by one chunk.

## API

### `crypto/`

- `parseArchiveRootKeys(config)` parses `ARCHIVE_ROOT_KEY`, `ARCHIVE_ROOT_KEY_ID` (default `r1`)
  and the optional previous pair, with cross-checks. Errors name keys only.
- `ArchiveRootKeyProvider` (`currentKeyId`, `previousKeyId`, async `wrap` and `unwrap`) is the
  seam for a KMS provider. `LocalRootKeyProvider.fromConfig(config)` is the configuration-key
  implementation. `unwrap` returns `{ key, rootKeyId, usedPreviousKey }`.
- `wrapTenantKey` / `unwrapTenantKey(provider, …, { organizationId, version })` use the AAD
  `eg-archive-tenant-key/v1\0<org>\0<version>`.
- `wrapRecordKey` / `unwrapRecordKey(tenantKey, …, { organizationId, messagePublicId, captureId, keyVersion })`
  use the format `v1.k<version>.…`. `wrapExportKey` / `unwrapExportKey` do the same for exports.
  `keyVersionOfWrapped(wrapped)` returns the tenant key version a wrapped DEK names.
- `generateDataKey()` returns 32 random bytes. `deriveObjectKey(dek, salt, { kind, organizationId, subjectId })`
  derives an object key with HKDF.
- `createArchiveEncryptStream({ dek, kind, organizationId, subjectId, chunkBytes? })` returns a
  Transform. After the end, `.summary` (also the `summary` event) gives the plaintext and
  ciphertext byte counts and SHA-256s.
- `createArchiveDecryptStream({ dek, kind, organizationId, subjectId, expectedSha256? })` returns
  a Transform. It fails with `unauthentic` on any manipulation and with `integrity` when the
  plaintext hash differs.
- `encryptArchiveObject` / `decryptArchiveObject` are whole-buffer helpers that produce the
  same bytes. `parseArchiveObjectHeader` parses a header.
- `generateExportSigningKeyPair()`, `parseExportSigningPrivateKey`, `parseExportSigningPublicKey`,
  `parsePreviousSigningPublicKeys('id:key,…')`, `parseSigningKeyId`, `signManifest` and
  `verifyManifestSignature` handle Ed25519 (PKCS#8 / SPKI DER, base64url).

### `documents/`

- The zod schemas are strict and have exported types and examples: `archiveSettingsSchema`,
  `archiveRetentionCriteriaSchema`, `archiveHoldCriteriaSchema`, `legacyLegalHoldCriteriaSchema`,
  `archiveHoldCreateCriteriaSchema` (addresses, `from ≤ to`), `archivePartiesSchema`,
  `archiveJournalSchema`, `archiveRecordObjectsSchema`, `archiveScanRoundsSchema`,
  `archiveSearchCriteriaSchema` and `archiveExportManifestSchema`.
- `resolveArchiveSettings(raw | null)` applies the A22 defaults. `null` means every default.
  An invalid document throws `ArchiveDocumentError`.
- `validateArchiveSettingsChange(previous, next, { objectLockAvailable, entitled?, defaultRetentionLive? })`
  checks the A10/A22 rules. It returns `{ ok, enabling, applyLockPass, weakeningForNewCapturesOnly }`
  or `{ ok: false, code }`.
- `canonicalJson`, `canonicalJsonBytes`, `canonicalSha256` and `sha256Hex` produce sorted-key
  JSON for hashes and the manifest bytes.

### `capture/`

- `decideCapture(input)` implements the A3 table and returns `wait`, `capture(category)`,
  `skip(reason)` or `lost(reason)` with `recheckAt`. Skip reasons are `not_entitled`,
  `archiving_disabled`, `policy_archive_disabled`, `category_excluded` and `max_age`. Lost
  reasons are `message_missing` and `original_missing`.
- `categoryOf(message)`, `isFinalMessageStatus(status)`, `nextWaitCheckAt(now, waitsSoFar)`
  (1, 2, 5, 15, 30 min, then hourly) and `nextOutcomeCheckAt({ now, capturedAt, final, finalSince, outcomeWindowDays })`
  (+1 h, +24 h, hourly while non-final, `null` = close) cover the categories and schedules.
- `journalEligibility({ settings, journalEnabledAt, message, scope | matcher })` checks the
  enablement date, the direction (the message direction or any recipient direction) and the
  scope (`all`, `include` or `exclude` over org-side parties).
- Related helpers: `orgSideParties`, `directionEligible`, `createScopeMatcher(resolvedScope)`,
  `scopeEligible`, `normalizeAddress` and `domainOf`.

### `retention/`

- `retentionCriteriaMatch(criteria, facts)` tests one policy's criteria.
  `selectRetentionPolicy(policies, facts, defaultPolicyId)` returns the first live policy by
  priority, then id, whose criteria match, and otherwise falls back to the live default policy.
- `computeRetainUntil(receivedAt, days, daySeconds = 86 400)` computes a retention date.
  `effectiveRetainUntil({ storedRetainUntil, receivedAt, policy, daySeconds })` recomputes it
  lazily and extend-only.
- `decideExpiry({ now, mode, record, policy, holds, holdFacts, holdExtensionDays, reviewExtensionDays, daySeconds })`
  returns `policy_extended`, `held`, `review` or `disposed` (in A13 order) with the new
  `retainUntil` and an Object Lock extension target. A running object lock also keeps the
  record.

### `holds/`

- `legalHoldMatches(criteria, facts, { criteriaVersion })` applies the exact 5.3 semantics.
  Legacy rows (`criteria_version` NULL) use only `{ custodians, from, to }`; `archive-hold/1`
  adds `directions`. Unparsable criteria match everything.
- `parseHoldCriteria`, `firstMatchingHold` and `holdBound` support it.
  `holdToSearchCriteria(criteria, version)` builds the `holdId` filter of the search.

### `search/`

- Names: `indexTemplateName`, `indexPattern`, `yearlyIndexName`, `yearlyIndicesBetween` and
  `tenantAliasName` (`<prefix>-t<organizationId>`).
- Alias bodies: `tenantAliasActions`, `newIndexAliasActions`, `removeTenantAliasActions` and
  `aliasesForIndexCreation`.
- `buildIndexTemplate({ prefix, shards, replicas })` builds the template.
  `ARCHIVE_INDEX_MAPPING` and `ARCHIVE_INDEX_FIELDS` describe the mapping.
- `buildArchiveSearchDocument(record, { prefix, now, extra? })` returns `{ index, id, routing, document }`.
  `messageIdKey` normalizes a Message-ID.
- `buildArchiveSearchQuery({ organizationId, criteria, sort, limit, searchAfter, permissions: { reveal, holds }, hold?, caseCustodians?, timeoutMs? })`
  builds a search. It throws `ArchiveSearchQueryError` with code `archive_filter_forbidden`,
  `archive_search_range_invalid`, `hold_unresolved`, `case_custodians_unresolved` or
  `cursor_invalid`.
- Cursor and audit helpers: `parseSearchAfter`, `encodeSearchAfter`, `decodeSearchAfter`,
  `searchAfterOfHit`, `searchFilterHash` and `searchFilterNames`.
- `buildDayCountQuery` (reconciliation) and `buildOrganizationPurgeQuery` build the other
  queries.

### `snapshot/`

- `encodeTagged` / `decodeTagged` and `encodeRows` / `decodeRows` implement the tagged codec:
  BigInt becomes `{"$b":…}` and Date becomes `{"$d":…}`. Buffers, Decimals, class instances,
  functions, symbols, `undefined` inside arrays and non-finite numbers are refused.
- `buildScanSnapshot(input)` returns `{ document, bytes }`. `parseScanSnapshot(bytes)` decodes
  the rows.

### `keys/`

- `archiveObjectKey({ organizationId, receivedAt, messagePublicId, captureId, kind, round?, revision? })`,
  `exportObjectKey`, `archivePrefixOf`, `archiveDayPrefixOf` and `EXPORT_OBJECT_TAG` build the
  object keys.
- `assertKeyOfOrganization(key, organizationId, area)` and `isKeyOfOrganization` check them.

### `tokens/`

- `signArchiveDownloadToken(payload, key)` and `verifyArchiveDownloadToken(token, key, { now, expected })`
  handle the token, with payload `{ jti, org, usr, kind, tgt, exp }`. The MAC is HMAC-SHA256
  over `eg-archive-download/v1\0` ‖ payload and is compared in constant time.
  `parseDownloadTokenKey` reads the key.

### `export/`

- `buildExportManifest(input)` returns `{ manifest, bytes, sha256 }`. `buildSignedExportManifest`
  and `verifySignedExportManifest` add and check the signature.
- `exportEntryPath` gives `messages/<yyyymmddThhmmss.mmmZ>_<messageId>.eml` or `malicious/…`.
  `exportTimestamp` formats the timestamp.
- The text constants are `EXPORT_README_TEXT` and `EXPORT_MALICIOUS_README_TEXT`.

### `versions` and `vocabulary`

- `versions` holds every document and format id: `ARCHIVE_*_VERSION`, `ARCHIVE_OBJECT_FORMAT`
  and `ARCHIVE_TENANT_KEY_ALGORITHM`.
- `vocabulary` holds the enums that mirror Prisma (directions, statuses, categories, lock modes,
  review tags and so on).

## How services use it

- **archive-worker, capture role:**
  1. Run `journalEligibility` for each swept message.
  2. Run `decideCapture` on writer facts.
  3. Select the policy with `selectRetentionPolicy` and compute `computeRetainUntil`.
  4. Take the tenant key (`unwrapTenantKey`, or `generateDataKey` + `wrapTenantKey` on first use).
  5. Create the record DEK (`generateDataKey` + `wrapRecordKey`).
  6. Encrypt with `createArchiveEncryptStream` (the EML, with the plaintext SHA-256 compared to
     `eml_sha256`) and `encryptArchiveObject` (the journal and `buildScanSnapshot`).
  7. Build the object paths with `archiveObjectKey`.
- **archive-worker, index role:** `buildIndexTemplate`, the alias builders and
  `buildArchiveSearchDocument` with `OpenSearchService.bulk`.
- **archive-worker, lifecycle role:** `decideExpiry` and `legalHoldMatches`.
- **archive-worker, ediscovery role:** `buildArchiveSearchQuery` and `buildSignedExportManifest`.
- **api:** `resolveArchiveSettings` and `validateArchiveSettingsChange` for settings; the
  schemas for request bodies; `buildArchiveSearchQuery` through the tenant alias; the decrypt
  streams for content routes; `signArchiveDownloadToken` / `verifyArchiveDownloadToken` for
  downloads.
- **quarantine (5.3 Q17 under 8.1):** `legalHoldMatches` with the row's `criteria_version`.

## Tests

`pnpm --filter @email-gateway/archive test` runs the unit suites only, with no infrastructure.
They cover crypto round trips (0 B, 1 B, chunk−1, chunk, chunk+1, a property over sizes and a
50 MiB stream), every tamper case, AAD binding, previous-key unwrap, Ed25519, every schema
with its examples and unknown keys, the A3 table, scope, retention, expiry order, holds
(legacy and unparsable), the query and document builders, the codec, keys, tokens and the
manifest.
