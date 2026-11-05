# @email-gateway/clamav

clamd transport of the attachment engine (step 4.2 A7, [design](../../docs/plan/steps/10-attachment-scanning.md), [ADR-0028](../../docs/architecture/adr/0028-attachment-scanning-engine.md)). Used by the email-worker's `attachment` engine (scans, readiness `PING`) and its signature watcher (`VERSION`). TCP only: no local socket, no `clamdscan` binary. It decides **no** platform verdict (the A6 mapping lives in the email-worker) and never logs. No runtime dependencies (Node's `net`).

## API

- `new ClamdClient({ host, port, timeoutMs, maxConnections? = 4, chunkBytes? = 65536 })` (`CLAMAV_HOST`, `CLAMAV_PORT`, `CLAMAV_TIMEOUT_MS`, `CLAMAV_MAX_CONNECTIONS` ≤ 64, `CLAMAV_CHUNK_BYTES` 1 KiB–8 MiB; invalid options throw `RangeError`).
  - `ping(signal?)`: `zPING\0` → `PONG`.
  - `version(signal?)` → `{ engine: '1.4.6', dbVersion: 28173, dbTime: Date }` from `ClamAV 1.4.6/28173/Tue Nov  3 06:27:52 2026` (ctime parsed as UTC; an engine-only reply without a database is a protocol error).
  - `scan(input: Buffer | Uint8Array | Readable, signal?)` → `{ status: 'clean' } | { status: 'found', signature }` plus `{ engine, dbVersion, dbTime, bytes, durationMs }`. One connection, one **IDSESSION**: `zIDSESSION\0` `zVERSION\0` `zINSTREAM\0`, chunks `[uint32 BE length][bytes]` of at most `chunkBytes`, the zero-length terminator, `zEND\0`. Replies are matched by their request number (`1: ClamAV …`, `2: stream: OK` / `2: stream: <signature> FOUND`), in whatever order clamd sends them, so the version of a result is the version of the clamd instance that scanned it (several clamd pods behind one Service may differ during a database update). A `Readable` is re-chunked and streamed with back-pressure (header and payload are separate writes; a full socket buffer waits for `drain`); a buffer is sent as views, without copies.
  - `connections` → `{ active, waiting }` (metrics, tests).
- Bounds: every call (including the wait for a connection slot) ends after `timeoutMs`; at most `maxConnections` sockets per client (FIFO `ConnectionLimiter`); replies are read into a bounded buffer (4 KiB per reply, 8 replies); the caller's `AbortSignal` destroys the socket. Signature names must match `^[\x21-\x7e]{1,128}$` (`CLAMD_SIGNATURE_PATTERN`).
- Errors (`ClamdError` subclasses: `kind`, `retryable`, `operation`; messages carry fixed text, codes and numbers only, never bytes or reply text):
  - `ClamdUnavailableError` (`causeCode`: `ECONNREFUSED`, `ECONNRESET`, `EPIPE`, `ENOTFOUND`, …, `CLOSED` for a close before any reply), retryable.
  - `ClamdTimeoutError` (`timeoutMs`; `null` when the caller's signal aborted with a `TimeoutError`), retryable.
  - `ClamdProtocolError` (`reason`: `unexpected_reply`, `reply_too_large`, `invalid_signature`, `invalid_version`, `server_error` for any `… ERROR` other than the size limit), retryable.
  - `ClamdSizeLimitError` (`INSTREAM size limit exceeded. ERROR`: the stream is longer than clamd's `StreamMaxLength`), **not** retryable, with `version` (from the same session) and `bytesSent`. The attachment engine maps it to `limit.clamav` (suspicious) and logs it at warn: `StreamMaxLength` (30M) is kept above `ATTACHMENT_MAX_BYTES` (25 MiB), so it means a misconfiguration.
  - An error of a `Readable` input (e.g. an S3 body) is rethrown unchanged; a caller abort rethrows the abort reason.
- Parsers (pure): `parseVersion`, `parseCtime`, `parseScanReply`, `splitSessionReply`, `ReplyReader`, `isValidSignatureName`.

```ts
const clamd = new ClamdClient({ host: 'clamav', port: 3310, timeoutMs: 60_000, maxConnections: 4 });
const result = await clamd.scan(buffer, signal);
if (result.status === 'found') {
  // result.signature, e.g. 'Eicar-Test-Signature'; result.engine / result.dbVersion of this clamd
}
```

## clamd behaviour verified against `clamav/clamav-debian:1.4` (ClamAV 1.4.6)

- `IDSESSION` with `VERSION` + `INSTREAM` + `END` works on one connection; both replies are numbered (`1:`, `2:`), each terminated by NUL; clamd closes the connection after `END`. The design's fallback (VERSION on its own connection before each scan) is not needed.
- Above `StreamMaxLength` clamd answers `2: INSTREAM size limit exceeded. ERROR` and closes while the client is still writing; the reply arrives before the reset and is reported as `ClamdSizeLimitError` (verified repeatedly with 31 MiB and 40 MiB inputs).
- EICAR is reported as `Eicar-Test-Signature`, also inside zip, nested zip, gzip and tgz. An encrypted zip is `OK` (`AlertEncrypted no` in `infrastructure/clamav/clamd.conf`: the inspector reports encryption).

## Tests

- `pnpm --filter @email-gateway/clamav test`: reply parsers, limiter, and the client against a fake clamd (`net.Server` speaking the null-terminated protocol): OK, FOUND, out-of-order replies, chunking and back-pressure (8 MiB through a slow reader), Readable errors, size limit, `… ERROR`, invalid signature, garbage, unnumbered reply, reset, close, timeout (silent and slow server), abort (reason rethrown, socket destroyed), concurrency cap, slot wait counted against the timeout.
- `pnpm --filter @email-gateway/clamav test:integration`: the real clamd on `127.0.0.1:${CLAMAV_HOST_PORT}` (`.env`): `PING`, `VERSION`, clean buffer, EICAR plain / streamed / in zip (yazl) / nested zip / gzip / tgz, a clean 25 MiB − 1 file, the 30M `StreamMaxLength` refusal, encrypted zip clean, concurrent scans, a closed port. Test files come from `@email-gateway/attachment-corpus` (EICAR assembled from fragments at test time). Needs `docker compose up -d --wait clamav`; the suite fails with that instruction otherwise. Part of the root `pnpm test:integration`.
