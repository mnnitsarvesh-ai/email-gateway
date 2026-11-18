# Runbook: eDiscovery (cases, legal holds, searches, review, exports)

Step 8.1 ([design](../plan/steps/23-journaling-archiving.md) A12, A17, A18, §4.4 #24–#41; [ADR-0067](../architecture/adr/0067-retention-legal-hold-and-disposal-consistency.md), [ADR-0068](../architecture/adr/0068-archive-search-opensearch-and-authorization.md), [ADR-0069](../architecture/adr/0069-ediscovery-cases-searches-and-exports.md)). The api records cases, holds, search and export requests and every review decision; the archive-worker's `ediscovery` role runs the searches and builds the export packages; its `lifecycle` role enforces holds at disposal time. The archive itself (capture, index, disposal, keys) is in [archive.md](archive.md). API reference: [docs/api/README.md](../api/README.md#legal-holds-and-ediscovery-ediscovery-tag-step-81).

## Who may do what

`ediscovery:manage` (organization admins, compliance auditors) sees **every** case of the organization (per-case access lists are not offered) and manages custodians, searches, review and exports. Placing a hold needs `archive:legal_hold` **and** `ediscovery:manage` (organization admins); releasing one `archive:legal_hold`. Export requests and their downloads also need `archive:export`. Holds, case close, review and every download grant are user-only; holds, case close and grants also need an MFA session; grants re-ask the password (+ TOTP). Platform operators never get archived content, even under an override ([rbac.md](../security/rbac.md#archive-and-ediscovery-step-81)).

## Cases and custodians

1. `POST /api/v1/ediscovery/cases` `{ name, description?, matterReference?, custodians? }` (Idempotency-Key). Names are unique per organization; at most `ARCHIVE_CASES_MAX_OPEN_PER_ORG` open cases and `ARCHIVE_CASE_MAX_CUSTODIANS` custodians per case. Custodian addresses are lower-cased and linked to the organization user with that address when one exists.
2. `PATCH /api/v1/ediscovery/cases/{caseId}` with `expectedRowVersion` replaces the custodian list (holds keep the custodians they snapshotted).
3. `POST …/close` (MFA) once the matter ends — refused while the case has active holds (`409 ediscovery_case_has_active_holds`). A closed case is read-only; its searches, hits and exports stay readable until the organization is purged.

## Legal holds

- Place: `POST /api/v1/ediscovery/cases/{caseId}/holds` `{ name, reason, criteria?, useCaseCustodians? }` (MFA, Idempotency-Key). Criteria `archive-hold/1`: `custodians` (addresses; envelope sender, header From or any envelope recipient matches), `from`/`to` (dates cover whole UTC days), `directions`. **Empty criteria hold every record of the organization.** `useCaseCustodians: true` snapshots the case's custodians (`422 legal_hold_criteria_invalid`, `reason: no_case_custodians` for a case without any). Explicit custodian addresses need `message:reveal` (`403 archive_filter_forbidden`, `filter: criteria.custodians`).
- Effect: a matching active hold blocks every disposal — retention expiry (the record is extended by `ARCHIVE_HOLD_EXTENSION_DAYS` and flagged `legal_hold`), the review disposal, quarantine deletion and purge of the mail-bucket object, and the organization purge. Nothing is applied per record when the hold is created; it is evaluated authoritatively whenever a disposal is decided. Criteria that cannot be read hold everything (fail-safe).
- Which records a hold covers (informational): `GET /api/v1/archive/messages?from=…&to=…&holdId=<id>` (needs a hold permission).
- Change a hold: create a new one, then release the old one (holds are immutable).
- Release: `POST /api/v1/legal-holds/{holdId}/release` `{ reason }` (MFA). Records become eligible at their next expiry evaluation, never at once.

## Searches and completeness

`POST …/cases/{caseId}/searches` `{ criteria }` (`archive-search/1`; class `expensive`) returns `202` with `status: queued`. `custodians: "case"` uses the case's custodians at run time (a case without custodians matches nothing). Only holders of `message:reveal` can write the case's custodian addresses (case create or `PATCH` with a non-empty list: `403 archive_filter_forbidden`, `filter: custodians`; clearing the list is allowed), so a custodian search never confirms an address its caller chose without that permission. Criteria on recipients, the subject or explicit custodian addresses need `message:reveal`; the range is at most `ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS`; at most `ARCHIVE_CASE_MAX_ACTIVE_SEARCHES` searches per case may be queued or running.

Follow it with `GET …/searches/{searchId}`:

| Field              | Meaning                                                                                                                                                                        |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `status`           | `queued` → `running` → `completed` or `failed` (`errorCode`)                                                                                                                   |
| `hitCount`         | verified hits (every OpenSearch hit is re-checked against MySQL: same organization, live record)                                                                               |
| `truncated`        | `ARCHIVE_CASE_SEARCH_MAX_HITS` reached: narrow the criteria                                                                                                                    |
| `indexComplete`    | `true` only when the organization's index had no change older than 60 s at completion **and** every UTC day of the range has a successful reconciliation check                 |
| `incompleteReason` | `index_lag` (changes were not yet indexed), `unverified_days` (days not reconciled yet), `mismatched_days` (a reconciliation found differences and is repairing): re-run later |

A search is a point-in-time result. For a defensible collection, re-run it after `indexComplete` turns true and the reconciliation is green (archive runbook).

## Review

`GET …/searches/{searchId}/hits` lists the hits with the masked record (the first page is audited `ediscovery.hits_viewed`; reveal subjects or recipients through `POST /api/v1/archive/messages/{id}/reveal`). `POST …/review` `{ tag, messageIds }` sets `untagged`, `relevant`, `not_relevant` or `privileged` on up to `ARCHIVE_REVIEW_MAX_ITEMS` hits of a completed search (users only; audited with the message ids and counts).

## Exports

1. `POST …/cases/{caseId}/exports` `{ searchId, reviewTags?, acknowledgeMalicious? }` (class `expensive`): default tags are every tag except `not_relevant`. The api checks the bounds on the live records first (`ARCHIVE_EXPORT_MAX_ITEMS`, `ARCHIVE_EXPORT_MAX_BYTES`: `422 ediscovery_export_too_large`); malicious records need `acknowledgeMalicious: true` (`409 ediscovery_export_malicious_ack_required`) and go under `malicious/` with a warning README. Split larger selections into several searches (by range or custodian).
2. The archive-worker builds a ZIP: `messages/<receivedAt>_<messageId>.eml` (the decrypted originals, each re-verified against the SHA-256 recorded at capture), `manifest.json` (`archive-export-manifest/1`: ids, times, Message-IDs, paths, SHA-256, sizes, verdicts, counts, the review tags, the generator and the signing key id), `manifest.sig` and `README.txt`. The package is encrypted at rest under an export key of the tenant and expires after `ARCHIVE_EXPORT_TTL_HOURS` (`status: expired`). Follow `GET …/exports/{exportId}` until `completed` (`packageSha256`, `manifestSha256`, `signingKeyId`).
3. Download: `POST …/exports/{exportId}/download-grants` `{ password, totpCode? }` (MFA; `ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR` per user) → a single-use token valid `ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS`; then `GET /api/v1/archive/downloads/{token}` streams the ZIP (`application/octet-stream`, `attachment`). A second use is `410`; the portal's BFF streams it to the browser.

## Verifying a package (chain of custody)

```bash
# 1. The whole package: its SHA-256 equals packageSha256 of GET …/exports/{exportId}.
sha256sum ediscovery-export-<exportId>.zip
unzip ediscovery-export-<exportId>.zip -d export && cd export
# 2. The manifest signature with the published public key of manifest.json's signingKeyId.
curl -sS -H "Authorization: Bearer $TOKEN" "$API/api/v1/archive/export-signing-keys" \
  | jq -r '.data[] | select(.id == "es1") | .publicKey' \
  | tr '_-' '/+' | base64 -d > signing.der            # base64url → DER (pad with = if needed)
openssl pkey -pubin -inform DER -in signing.der -out signing.pem
tr '_-' '/+' < manifest.sig | base64 -d > manifest.sig.bin
openssl pkeyutl -verify -pubin -inkey signing.pem -rawin -in manifest.json -sigfile manifest.sig.bin
# → Signature Verified Successfully
# 3. Every message: its SHA-256 equals the manifest entry (and the original at capture).
jq -r '.items[] | "\(.sha256)  \(.path)"' manifest.json | sha256sum -c -
```

`signingKeyId` names the key: after a rotation the previous public key stays listed (`current: false`) for packages signed before.

## Limits (defaults)

| Key                                  | Default | Applies to                                 |
| ------------------------------------ | ------: | ------------------------------------------ |
| `ARCHIVE_CASES_MAX_OPEN_PER_ORG`     |     200 | open cases per organization                |
| `ARCHIVE_CASE_MAX_CUSTODIANS`        |   1 000 | custodians per case                        |
| `ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG`   |     100 | active holds per organization              |
| `ARCHIVE_CASE_MAX_ACTIVE_SEARCHES`   |       3 | queued/running searches per case           |
| `ARCHIVE_CASE_SEARCH_MAX_RANGE_DAYS` |   3 650 | range of a case search                     |
| `ARCHIVE_CASE_SEARCH_MAX_HITS`       | 100 000 | hits per search (`truncated`; worker)      |
| `ARCHIVE_REVIEW_MAX_ITEMS`           |     500 | hits per review request                    |
| `ARCHIVE_EXPORT_MAX_ITEMS`           |  10 000 | messages per export                        |
| `ARCHIVE_EXPORT_MAX_BYTES`           |   2 GiB | original bytes per export                  |
| `ARCHIVE_EXPORT_TTL_HOURS`           |     168 | export availability                        |
| `ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR`   |      20 | grants (and downloads) per user, all kinds |
| `ARCHIVE_DOWNLOAD_TOKEN_TTL_SECONDS` |      60 | token validity                             |

## Audit

Everything is in `audit_logs` (`GET /api/v1/audit/logs?actionPrefix=ediscovery.` and `?actionPrefix=legal_hold.`): `legal_hold.created|released`, `ediscovery.case_created|updated|closed`, `ediscovery.search_requested`, `ediscovery.hits_viewed`, `ediscovery.review_tagged`, `ediscovery.export_requested|download_granted|downloaded`, and the worker's `ediscovery.search_completed|failed`, `ediscovery.export_completed|failed`. Rows carry ids, counts and hashes, never custodian addresses or message content.

## Troubleshooting

- **Search stays `queued`**: the archive-worker's `ediscovery` role is down or OpenSearch is unavailable (archive runbook); nothing is lost, the search runs when it is back.
- **`indexComplete: false`**: see the reason above; `GET /api/v1/archive/status` shows the index lag.
- **Export `failed`** (`errorCode`): an integrity mismatch (`integrity_mismatch`, alerted) or a bound exceeded at build time; re-request after the cause is fixed.
- **`409 ediscovery_case_has_active_holds`** on close: list them with `GET /api/v1/legal-holds?status=active&caseId=<id>`.
