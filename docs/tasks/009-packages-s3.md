# 009: packages/s3 — streaming put/get, per-tenant key layout, tenant key assertion

Owner agent: backend-engineer
Depends on: 002, 003, 006
Status: draft
Branch: feat/009-packages-s3
Phase: 0

## User story

Story: _to be written by product-owner_

As a pipeline service author, I want to stream EML to and from S3 or MinIO with bounded memory under a per-tenant key layout so that ingest can persist mail of any allowed size and workers can't be tricked into reading another tenant's object.

## Acceptance criteria

AC-1 Given local MinIO and a generated 100 MiB body, when `putStream` runs, then growth in heap plus `arrayBuffers` stays under 64 MiB, and the returned `sizeBytes` and `sha256` equal an independent hash of the body.
AC-2 Given a successful `putStream`, when `head` is called, then it returns the same size and SHA-256, and the promise resolved only after the object was readable (a read right after resolve never returns 404).
AC-3 Given MinIO stopped mid-upload, when `putStream` is running, then it rejects (an error surfaces to the caller, never a resolve), no completed object exists at the key, and `ListMultipartUploads` shows no leftover upload (aborted).
AC-4 Given a source stream that errors midway, when `putStream` runs, then it rejects with that error and no object exists.
AC-5 Given an existing object, when `putStream` with `ifNoneMatch: true` uploads an identical body, then it resolves `alreadyExisted: true` (412 handled, SHA matches); with a different body under the same key, it rejects.
AC-6 Given `ifNoneMatch` unset or false, when `putStream` runs on a new key, then it writes with `ChecksumAlgorithm SHA256` and the SDK request carries no `If-None-Match` (spy on the client).
AC-7 Given `getStream` with a key under `org/{id}/` and a matching `expectedOrganizationId`, when called, then it returns a stream whose bytes equal the stored object and `sizeBytes` is correct.
AC-8 Given `getStream` with a mismatched `expectedOrganizationId`, when called, then it throws `CrossTenantKeyError` and the S3 client is never called (spy count 0); a key with no `org/` prefix also throws.
AC-9 Given a missing key, when `getStream` runs, then it rejects with a not-found error (no empty stream) and `head` returns `null`.
AC-10 Given `getStream` on a large object, when consumed with a slow reader, then memory stays bounded (no full buffering) with the same 64 MiB limit as AC-1.
AC-11 Given the key builders, when called with fixed inputs, then golden strings match: `org/{org}/eml/{yyyy}/{mm}/{dd}/{message_uuid}.eml`, `org/{org}/part/.../{message_uuid}/{part_index}.bin` and `org/{org}/archive/.../{message_uuid}.eml`, with dates from `received_at` in UTC (a test uses a timestamp near midnight UTC+5:30).
AC-12 Given any built key, when `parseKey` runs, then it returns the original `{ organizationId, kind, messageUuid, receivedDate }`; a malformed key or non-v7 id throws.
AC-13 Given the repo, when searched, then keys are built only in `@esg/s3/keys` (a lint or grep check finds no other `org/` template string in `services/` or `packages/`).
AC-14 Given config with SSE `aws:kms`, when `putStream` runs against a mocked client, then the request carries the SSE and key id (assumes default for NEEDS SARVESH #9-1: per-environment key, Bucket Keys on); with no SSE configured (MinIO), it sends none.
AC-15 Given S3 credentials, when logs and thrown errors are captured, then they contain no secret value (credentials come from `Secret` config).

## Out of scope

- Bucket creation, lifecycle rules, KMS keys, Object Lock and bucket policies. Those are Terraform (010, and later the infra track) and the local `minio-init` (003).
- MIME parsing and attachment extraction. Phase 2, in the workers. This task only defines the key builder for extracted parts.
- Archive write logic (Phase 5). This task only defines `archiveKey`.

## Design notes

**Package name.** The package is `packages/s3` (`@esg/s3`), as listed in CLAUDE.md. It is the "storage" package from your brief. See the naming item in 002's NEEDS SARVESH.

### API

```ts
export function createObjectStore(cfg: S3Config, log: Logger): ObjectStore;  // endpoint override + forcePathStyle for MinIO
interface ObjectStore {
  putStream(p: { bucket: string; key: string; body: Readable; contentType?: string; ifNoneMatch?: boolean })
    : Promise<{ bucket: string; key: string; etag: string; versionId?: string; sizeBytes: number; sha256: string; alreadyExisted: boolean }>;
  getStream(p: { bucket: string; key: string; expectedOrganizationId: OrganizationId })
    : Promise<{ body: Readable; sizeBytes: number; contentType?: string }>;
  head(p: { bucket: string; key: string }): Promise<{ sizeBytes: number; sha256?: string } | null>;
}
```

- **`putStream`** uses `@aws-sdk/lib-storage` `Upload` with `partSize = 8 MiB` and `queueSize = 2`. Peak buffered memory is about 16 MiB per upload, whatever the message size.
  - A pass-through `Transform` computes the SHA-256 and byte count while streaming.
  - `ChecksumAlgorithm: 'SHA256'`, so S3 checks integrity.
  - SSE comes from config (`aws:kms` with a key id in AWS, none in MinIO).
  - It resolves **only after** S3 has completed the upload (CompleteMultipartUpload, or the single PUT, succeeded). That is the durability point ingest relies on (hard rule 1).
  - On any error or abort it aborts the multipart upload and rejects.
  - With `ifNoneMatch: true` it sends `If-None-Match: *` (a conditional write). A `412` means the object already exists. The call then does a `head` and resolves `{ alreadyExisted: true }` if the SHA-256 matches, or rejects if it doesn't. This makes LMTP-retry ingest idempotent at the storage level.
- **`getStream`** first calls `assertKeyBelongsTo(key, expectedOrganizationId)`. If the key's `org/{id}/` prefix doesn't match the payload's `organization_id`, it throws `CrossTenantKeyError` before any network call. A forged or buggy queue payload can't make a worker read another tenant's EML.

### Key layout (`@esg/s3/keys`; Proposed ADR-027)

All keys are built here and nowhere else.

| Object | Bucket | Key |
|---|---|---|
| EML | mail bucket (`esg-mail-<env>`) | `org/{organization_id}/eml/{yyyy}/{mm}/{dd}/{message_uuid}.eml` |
| Extracted part (Phase 2) | mail bucket | `org/{organization_id}/part/{yyyy}/{mm}/{dd}/{message_uuid}/{part_index}.bin` |
| Archive copy (Phase 5) | archive bucket (`esg-archive-<env>`) | `org/{organization_id}/archive/{yyyy}/{mm}/{dd}/{message_uuid}.eml` |

- Dates come from `received_at` in UTC. Ids are canonical lowercase UUIDv7 strings.
- Tenant-first prefixes support per-tenant lifecycle, export and deletion, and IAM `s3:prefix` conditions. At 300 msg/s the PUT rate is far below S3's per-prefix limits.
- Quarantine doesn't copy: it references the EML key. `parseKey(key)` returns `{ organizationId, kind, messageUuid, receivedDate }`, or throws.

### Tests

These run against local MinIO.
- **Bounded memory.** Stream a generated 100 MiB body. The growth in `process.memoryUsage().arrayBuffers` and heap stays under 64 MiB. The SHA-256 returned matches an independent hash.
- With MinIO stopped mid-upload, `putStream` rejects, no completed object exists, and the multipart upload is aborted.
- Conditional put of an identical body resolves `alreadyExisted`. A different body under the same key rejects.
- `getStream` with a mismatched `expectedOrganizationId` throws without a network call (spy on the client).
- Golden tests for every key builder, and `parseKey` round-trips.

## Hard rules at risk

- **1 (250 only after persist).** `putStream` resolves only on completed upload. Partial uploads are aborted and reject.
- **3 (no EML in queues).** Workers get the key from the payload and stream from S3. This package is the only S3 path.
- **4 and 7 (tenant isolation).** Tenant-first keys, plus `assertKeyBelongsTo` on every read.
- **9.** Credentials come from config `Secret`s (006), or the IAM role in AWS. Never hard-coded.

## NEEDS SARVESH

1. **KMS key granularity** (cost and security posture). Options:
   - (a) one customer-managed KMS key per environment and bucket;
   - (b) a per-tenant KMS key in SaaS (about $1 per key per month, plus a request cost per object unless S3 Bucket Keys are on);
   - (c) (a) by default, with per-tenant keys as an enterprise add-on.

   *Recommendation:* (c). Dedicated deployments get their own keys anyway, because they're separate deployments. Use S3 Bucket Keys in every case to keep KMS request costs down.
