# 006: packages/config (zod-validated env) and packages/logger (pino, bindings, redaction)

Owner agent: backend-engineer
Depends on: 001
Status: draft
Branch: feat/006-packages-config-logger
Phase: 0

## User story

Story: _to be written by product-owner_

As a service author, I want typed, fail-fast configuration and a logger that always carries tenant and message context and can't leak secrets or message content so that every service starts safely and logs consistently.

## Acceptance criteria

AC-1 Given a zod schema with required keys, when `loadConfig(schema, env)` is called with all keys valid, then it returns a deeply frozen object (assigning to a nested property throws in strict mode).
AC-2 Given an env missing a required key or holding an invalid value, when `loadConfig` runs, then it throws `ConfigError` listing the key names and issue codes, and the error message and stack contain none of the supplied values (a test uses a distinctive secret value and asserts it is absent).
AC-3 Given a service entrypoint using `loadConfig` with a bad env, when started, then the process exits non-zero before opening any listener (port stays closed).
AC-4 Given a `secret()` field, when the value is passed to `String()`, `JSON.stringify`, template literals, `util.inspect` and pino output, then each yields `[redacted]`, and `.reveal()` returns the original; a schema using `secret()` with a default fails type or runtime check (no defaults).
AC-5 Given `secretFile()` and an env var `X_FILE` pointing to a file, when loaded, then the file content (trailing newline trimmed) is the secret; a missing file throws `ConfigError` naming the key, not the path content.
AC-6 Given `mysqlWriterEnv`, when `MYSQL_WRITER_URL` is set, then it parses as a secret; the `@esg/config` root export does not contain `mysqlReaderEnv`; `@esg/config/control-plane` does (an `exports` map test).
AC-7 Given a data-plane config schema built from the root fragments and an env that also holds `MYSQL_READER_URL`, when loaded, then the key is absent from the result (unknown keys stripped).
AC-8 Given the repo, when `grep` runs, then `dotenv` is not a dependency and no deployment-mode key (`DEPLOYMENT_MODE`) is read by `@esg/config` for branching.
AC-9 Given `createLogger({ service, level })`, when it logs, then output is one JSON line on stdout with ISO `time`, `service`, `version` and `deployment`.
AC-10 Given `forMessage(logger, { organization_id, message_uuid, stage })`, when a line is logged, then the JSON contains all three fields; omitting `stage` fails type checking (`expectTypeOf`), and an invalid id fails at runtime in test/dev mode.
AC-11 Given a payload containing each sensitive key (`password, secret, token, authorization, cookie, headers.*, body, eml, content, attachment*, subject, err.sql, err.sqlMessage, dlp_match*`, plus nested `*.x` forms), when logged, then each value is `[redacted]` (snapshot test).
AC-12 Given a logged URL `mysql://user:pass@host/db`, when serialized, then it becomes `mysql://[redacted]@host/db`; a logged mysql2-style error has `type`, `code`, `message`, `stack` and no `sql`.
AC-13 Given `logAddress(addr)` (assumes default for NEEDS SARVESH #1: HMAC-SHA-256 keyed hash plus clear domain), when called with `a@tenant-a.test` and a key, then it returns `{ hash, domain: 'tenant-a.test' }`, the local part is absent from the output, the same input and key give the same hash, a different key gives a different hash, and a missing key throws.
AC-14 Given the package builds, when `pnpm turbo run build lint typecheck test --filter=@esg/config --filter=@esg/logger` runs, then it exits 0.

### Open questions for Sarvesh

- NEEDS SARVESH #1 (address logging policy) is assumed as option (b) in AC-13; qa-engineer must re-check if Sarvesh picks (a) or (c).

## Out of scope

- Reading secrets from AWS Secrets Manager or SSM at runtime. In the cluster, secrets reach containers as env vars or mounted files through External Secrets (devops-engineer, Phase 1 and later). This package only reads env and files.
- Metrics (Prometheus client) and tracing (OpenTelemetry). Phase 1, as a separate package if needed.
- Log shipping and sinks. Services log to stdout only.

## Design notes

### `packages/config` (`@esg/config`)

- `loadConfig<S extends z.ZodTypeAny>(schema: S, env = process.env): Readonly<z.infer<S>>`.
  - Parses, then deep-freezes the result.
  - On failure, throws a `ConfigError` that lists the **key names** and issue codes only, never the values. The process exits non-zero before it opens any listener.
- **Secrets.** `secret()` is a zod transform that wraps the value in a `Secret` class.
  - `toString()`, `toJSON()` and `util.inspect.custom` all return `"[redacted]"`.
  - `.reveal()` is the only way to read the value.
  - `secretFile()` reads a `*_FILE` path, for Kubernetes secret mounts.
  - Secrets never have defaults.
- **Reusable fragments.**
  - `mysqlWriterEnv`: `MYSQL_WRITER_URL` as a secret, plus pool sizes.
  - `rabbitEnv`, `s3Env`, `redisEnv`, `logEnv`.
- **`@esg/config/control-plane`** is a separate subpath that exports `mysqlReaderEnv` (`MYSQL_READER_URL`). The lint rule from 001 forbids importing it outside `services/api`. A data-plane service's config schema therefore *cannot* include a reader DSN, and an extra `MYSQL_READER_URL` in its environment is simply ignored. The schema is `.strip()` for unknown env keys.
- Local dev uses Node 24's native `--env-file=.env.local`, which is gitignored. Don't add `dotenv`.
- Deployment mode is **not** a config key that business logic branches on (ADR-018). Differences between modes are expressed as plain values, such as limits and endpoints.

### `packages/logger` (`@esg/logger`)

- `createLogger({ service, level }): Logger` is pino JSON on stdout, with base fields `service`, `version` and `deployment` (an env label used only for log routing). `timestamp` is ISO.
- **Pipeline bindings.**
  - `forMessage(logger, { organization_id, message_uuid, stage }): PipelineLogger` returns a child logger.
  - All three fields are required at compile time (a TypeScript type) and checked at runtime with a zod check of `@esg/schemas` ids, in dev and test only, to avoid a hot-path cost.
  - Pipeline code takes `PipelineLogger` in its signatures, so a log line without these fields doesn't type-check.
- **Redaction** (pino `redact` with `censor: '[redacted]'`), covering at least:
  - `password`, `*.password`, `secret`, `*.secret`, `token`, `*.token`, `authorization`, `*.authorization`, `cookie`, `headers.*`;
  - `body`, `*.body`, `eml`, `*.eml`, `content`, `*.content`, `attachment*`, `subject`, `*.subject`;
  - `err.sql` and `err.sqlMessage`, because mysql2 errors can include bound values;
  - `dlp_match*`.
- **Serializers.**
  - The URL serializer strips userinfo (`mysql://user:pass@…` becomes `mysql://[redacted]@…`).
  - The error serializer keeps `type`, `code`, `message` and `stack`, and drops `sql`.
  - `Secret` instances serialize as `[redacted]`.
- Email addresses: see NEEDS SARVESH. The package exports `logAddress(addr)`, which applies the chosen policy, so the policy lives in one place.

### Tests

- A config with a missing key throws, listing the key name, and the error text contains no values.
- `Secret` never appears in `JSON.stringify`, `util.inspect` or pino output.
- Every redaction path is censored. A snapshot test feeds pino a payload with each sensitive key and checks the output.
- `forMessage` without `stage` fails type checking, tested with `expectTypeOf`.
- A log line from `forMessage` contains all three bindings.

## Hard rules at risk

- **9 (no secrets).** The `Secret` wrapper, file-based secrets, no defaults, and redaction of DSNs.
- **Logging convention.** Bindings are required by type. Bodies, attachments and credentials are never logged.
- **2 (writer-only data plane).** The reader DSN schema can only be imported through the control-plane subpath, which lint blocks for data-plane services.

## NEEDS SARVESH

1. **Email addresses in logs.** The security-reviewer rules forbid full addresses "unless the spec allows". Options:
   - (a) never log addresses, only `rcpt_hash`;
   - (b) a keyed hash (HMAC-SHA-256 with a per-environment key from Secrets Manager), so support staff can correlate without seeing the address;
   - (c) a masked form (`a***@tenant-a.test`).

   *Recommendation:* (b) for recipients and senders, plus the domain in clear (`rcpt_domain`), which is needed for operations. Full addresses stay available through the portal's tenant-scoped trace, never in logs.
