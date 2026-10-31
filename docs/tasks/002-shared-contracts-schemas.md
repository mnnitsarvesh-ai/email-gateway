# 002: Shared contracts — ids, event envelope, scan contract, idempotency key

Owner agent: backend-engineer
Depends on: 001
Status: draft
Branch: feat/002-shared-contracts-schemas
Phase: 0

**Contracts-first task.** Every pipeline task from Phase 1 on depends on this one. It defines the shapes that services exchange. It defines no behaviour.

## User story

Story: _to be written by product-owner_

As a pipeline service author, I want one zod-validated definition of message ids, engine states, scan requests and results, the event envelope and the idempotency key so that every service speaks the same contract and a fail-open "clean" can't be expressed.

## Acceptance criteria

AC-1 Given `packages/schemas` and `packages/idempotency`, when `pnpm turbo run build typecheck test --filter=@esg/schemas --filter=@esg/idempotency` runs, then it exits 0 with no infrastructure running (assumes default for NEEDS SARVESH #1: package names `schemas`, `idempotency`).
AC-2 Given `OrganizationId` and `MessageUuid`, when parsing a canonical lowercase UUIDv7, then it succeeds; an uppercase UUID, a v4 UUID, a non-UUID string or an empty string fails with a zod error.
AC-3 Given a value typed `OrganizationId`, when passed where `MessageUuid` is expected, then `expectTypeOf` / `tsc` fails; `newMessageUuid()` returns a v7 UUID and 1,000 sequential calls are strictly non-decreasing as strings.
AC-4 Given `EngineState`, when its options are listed, then they are exactly `clean, suspicious, malicious, unknown, timeout, error, not_scanned` (a snapshot test fails if one is added or removed).
AC-5 Given a `ScanResult` with `state` in `timeout|error|not_scanned` and no `reason_code`, when parsed, then it fails (one case per state).
AC-6 Given a `ScanResult` with `state = clean` and a `reason_code`, or with a non-empty `findings` array, when parsed, then it fails; a `clean` result with no reason and empty findings passes.
AC-7 Given `{}`, or a `ScanResult` with no `state`, when parsed, then it fails; a grep/test confirms no schema has a `.default('clean')`.
AC-8 Given a `ScanResult` with `reason_code` outside the closed list (the 12 listed values), when parsed, then it fails.
AC-9 Given a `ScanRequest` or `ScanResult` with an extra key (`body`, `eml`, `content`, `attachment`), when parsed, then it fails (`.strict()`); `eml` accepts only `bucket`, `key`, `size_bytes`, `sha256`.
AC-10 Given a `ScanResult` with more than 50 findings, or a finding containing a matched-content field, when parsed, then it fails.
AC-11 Given a `ScanRequest`/`ScanResult` whose `idempotency_key` differs from `buildIdempotencyKey(org, uuid, stage, stage_version)`, when parsed, then it fails the cross-field refine.
AC-12 Given the golden fixtures in `test/fixtures/*.json`, when each is parsed, then every file labelled valid passes and every file labelled invalid fails.
AC-13 Given `buildIdempotencyKey`, when called, then the result equals `${organization_id}:${message_uuid}:${stage}:${stage_version}`; a stage not matching `^[a-z][a-z0-9_-]{0,31}$` (for example containing `:`) throws; a key over 128 characters is rejected.
AC-14 Given fast-check, when 1,000+ random valid inputs are built then parsed, then `parseIdempotencyKey(buildIdempotencyKey(x))` equals `x`; a malformed key (wrong segment count) makes `parseIdempotencyKey` throw.
AC-15 Given `EventEnvelope(payloadSchema)`, when parsed, then a payload missing `event_id`, `type`, `schema_version`, `occurred_at` or `organization_id` fails, an invalid payload under a valid envelope fails, and a valid one passes.
AC-16 Given `topology.ts`, when imported, then it exports `esg.scan`, `esg.dlx`, `esg.scan.request.<stage>`, `esg.scan.result` and the `<q>.dlq` names; a snapshot test pins them.
AC-17 Given the repo, when `@esg/schemas` is searched, then no schema field derives tenancy from a header (no `from`, `to`, `x_*` tenancy fields), checked by a test over the exported schema keys.

### Open questions for Sarvesh

- NEEDS SARVESH #2: ADR-027 (UUIDv7) must be Accepted before this task is `ready`; AC-2/AC-3 are written against UUIDv7.

## Out of scope

- The idempotency **store** (a MySQL table plus a helper that records the key in the side-effect transaction). The table ships in 005. The helper ships in Phase 1, together with the first consumer.
- Phase 1 event payloads beyond the envelope (`message.ingested`, `policy.decided`, `delivery.requested`). These are added by the Phase 1 contracts task, using the conventions set here.
- RabbitMQ client code (008) and S3 key builders (009).
- Tenant policy schema (Phase 2).

## Design notes

### Package layout

The scan contract lives in `packages/schemas`, matching the CLAUDE.md layout. See the naming item under NEEDS SARVESH.

```
packages/schemas/            @esg/schemas
  src/ids.ts                 OrganizationId, MessageUuid, newMessageUuid()
  src/direction.ts           Direction = 'inbound' | 'outbound' | 'internal'
  src/engine-state.ts        EngineState, ReasonCode
  src/stages.ts              Stage, StageVersion
  src/scan.ts                ScanRequest, ScanResult, Finding
  src/envelope.ts            EventEnvelope(payloadSchema)
  src/topology.ts            exchange, queue and routing-key name constants for scan traffic
  src/index.ts
  test/fixtures/*.json       golden valid and invalid payloads
packages/idempotency/        @esg/idempotency
  src/key.ts                 IdempotencyKey schema, buildIdempotencyKey(), parseIdempotencyKey()
```

### Identifiers (Proposed ADR-027)

- `OrganizationId` and `MessageUuid` are **UUIDv7**, in canonical lowercase string form in payloads and logs and `BINARY(16)` in MySQL. In zod they are a UUID string matching the v7 version nibble, then `.brand<'OrganizationId'>()` or `.brand<'MessageUuid'>()`. The brands keep the two ids from being swapped at compile time.
- `newMessageUuid()` uses a vetted UUIDv7 implementation (the `uuid` package v10 or later). Never write a hand-rolled one.

### Engine states (hard rule 5)

- `EngineState = z.enum(['clean','suspicious','malicious','unknown','timeout','error','not_scanned'])`. There are exactly these seven values.
- `ReasonCode` is a closed enum, extended only by changing this package. Initial values:
  - `deadline_exceeded`
  - `engine_unavailable`
  - `engine_crash`
  - `size_limit`
  - `part_count_limit`
  - `mime_depth_limit`
  - `archive_limit`
  - `encrypted_content`
  - `unsupported_type`
  - `parse_error`
  - `stage_not_enabled` (used in Phase 1)
  - `fetch_failed`
- `ScanResult` uses `.superRefine` to enforce:
  - `state ∈ {timeout, error, not_scanned}` ⇒ `reason_code` is **required**;
  - `state = clean` ⇒ `reason_code` is **absent** and `findings` is empty.

  So "clean, but skipped" cannot be expressed.
- No schema has a default of `clean` anywhere. A test asserts that parsing `{}` or a result with no `state` fails.

### Scan request and result

All schemas are `.strict()`, so unknown keys such as `body`, `eml`, `content` or `attachment` fail validation.

```ts
ScanRequest = {
  schema_version: 1,
  organization_id: OrganizationId,
  message_uuid: MessageUuid,
  received_at: ISO-8601 UTC string,   // partition key; consumers need it (ADR-026)
  direction: Direction,
  stage: Stage,                       // 'clamav' | 'yara' | 'rspamd' (+ later 'url' | 'dlp')
  stage_version: positive int,
  eml: { bucket: string, key: string, size_bytes: int >= 0, sha256: hex(64) },
  idempotency_key: IdempotencyKey,    // must equal buildIdempotencyKey(org, uuid, stage, stage_version)
  deadline_at: ISO-8601 UTC string,
}

ScanResult = {
  schema_version: 1,
  organization_id, message_uuid, received_at, stage, stage_version, idempotency_key,
  engine: { name: string, version: string, signatures_version?: string },
  state: EngineState,
  reason_code?: ReasonCode,
  findings: Finding[] (max 50),       // Finding = { rule_id, category, severity } — ids only, never matched content
  score?: number,                     // engine-native score (e.g. Rspamd); scorer normalises later
  started_at, finished_at: ISO-8601 UTC strings,
}
```

A cross-field refine checks that `idempotency_key` matches the other fields. The `eml.key` org-prefix check (the key must sit under `org/{organization_id}/`) is done by `@esg/s3` in 009, not here, so this package doesn't depend on the S3 key layout.

### Event envelope

`EventEnvelope(payload)` is:

```
{
  event_id: uuidv7,
  type: string,
  schema_version: int,
  occurred_at,
  organization_id,
  message_uuid?,
  payload,
}
```

Event types are dot-namespaced (`scan.requested`, `scan.completed`). Outbox rows (005) store exactly this envelope as JSON.

### Topology names (`topology.ts`)

Constants only. Declaration is done by `@esg/mq` (008).

- Exchange `esg.scan` (topic).
- Queue per stage: `esg.scan.request.<stage>`, routing key `scan.request.<stage>`.
- Result queue: `esg.scan.result`.
- Every queue `<q>` has a DLQ `<q>.dlq` through the exchange `esg.dlx`.

### Idempotency key (hard rule 6)

- Format: `${organization_id}:${message_uuid}:${stage}:${stage_version}`.
- Stage tokens match `^[a-z][a-z0-9_-]{0,31}$`, so `:` is never ambiguous. The total length is at most 128 characters.
- `parseIdempotencyKey` round-trips the key. Property tests use fast-check: build, then parse, gives the identity.
- `tenant_id` in CLAUDE.md is the `organization_id` value. The code only ever uses the name `organization_id`.

### Tests

These are vitest unit tests only. No infrastructure is needed.
- Golden fixtures pass or fail as labelled.
- Every non-`clean` state without a `reason_code` is rejected.
- `clean` with a `reason_code` or with findings is rejected.
- Extra keys are rejected.
- Swapping an `OrganizationId` for a `MessageUuid` fails type checking, tested with `expectTypeOf`.

## Hard rules at risk

- **5 (no clean on failure).** It is enforced in the schema, so an engine bug that returns `clean` with a reason fails validation at the boundary.
- **3 (no EML in queues).** `.strict()` schemas only carry `eml.{bucket,key,size_bytes,sha256}`. `@esg/mq` (008) adds a size cap.
- **6 (idempotency key).** A single builder and parser. The refine stops a payload from carrying a key that doesn't match its fields.
- **4 (tenant not from headers).** `organization_id` is a required, branded field set by the producer from resolved tenancy. No schema has header-derived tenancy fields.

## NEEDS SARVESH

1. **Package names.** Your brief says `scan-contract` and `storage`. CLAUDE.md lists `schemas` and `s3` (along with `idempotency`). *Recommendation:* keep the CLAUDE.md names (`packages/schemas` holds the scan contract, and `packages/s3` is the storage package, task 009). That way no layout change is needed in CLAUDE.md. If you'd rather use `scan-contract` and `storage`, then CLAUDE.md's repo layout must be updated in this task.
2. **Proposed ADR-027 (UUIDv7 ids, `BINARY(16)` storage, S3 key layout).** It must be Accepted before this task is marked `ready`.
