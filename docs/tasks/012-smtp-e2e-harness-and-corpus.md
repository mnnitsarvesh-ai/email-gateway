# 012: SMTP e2e test harness (swaks + vitest) and labelled test corpus layout

Owner agent: qa-engineer
Depends on: 001, 003, 004, 005, 007, 009
Status: draft
Branch: feat/012-smtp-e2e-harness-and-corpus
Phase: 0

**Why qa-engineer owns this.**
- Every file this task creates lives inside qa-engineer's permitted write scope: `test/e2e/**`, `test/corpus/**`, swaks scripts and fixtures. No product code, config, migrations or infra change.
- qa-engineer is the main long-term user of the harness. Owning it means it can extend the harness in every later phase without waiting on an implementer.
- The things the harness needs from outside `test/` are already delivered by tasks it depends on: the `test/e2e` workspace glob, the `test:e2e` turbo task and the `.gitignore` entry for artifacts (001); the `swaks` tool container and ports (003); the Postfix configs (004).
- If the harness turns out to need a product-side change, such as a compose port, it goes back to the owning task. qa-engineer doesn't make that change.
- **Independence.** Because qa-engineer writes the harness, the usual "QA tests the implementer" split doesn't apply. Instead:
  - the harness ships with self-tests (below);
  - code-reviewer reviews it as code;
  - product-owner accepts it against its ACs.

  qa-engineer isn't in architect's list of implementer agents, so this ownership is an explicit, test-only exception.

## User story

Story: _to be written by product-owner_

As qa-engineer, I want a reusable harness that sends real SMTP with swaks and asserts SMTP codes, DB rows, S3 objects and downstream receipt, plus a labelled corpus layout, so that every later AC and the zero-loss check can be tested end to end against deploy/local.

## Acceptance criteria

AC-1 Given `test/e2e`, when `pnpm install` runs, then `@esg/e2e` is a workspace package with `vitest.config.ts` (`testTimeout` 60 s, file parallelism off) and `pnpm turbo run test:e2e --filter=@esg/e2e` is defined and uncached.
AC-2 Given recorded swaks transcripts for a 250 accept, a 4xx deferral, a 5xx reject, a multi-recipient send and a STARTTLS session, when `lib/smtp-parse.ts` parses them, then `exitCode`, `finalCode`, `enhancedCode` and per-command reply codes match the expected values in each case (unit test, no stack).
AC-3 Given `lib/swaks.ts`, when it runs, then it invokes swaks through `execFile` without a shell (a test passes an argument containing `;` and `$()` and confirms it is not interpreted), and saves the transcript under `.artifacts/` which is gitignored.
AC-4 Given `lib/wait.ts`, when a condition never becomes true, then the call rejects after its deadline with a message containing the last error; when it becomes true early it returns immediately (no fixed sleep).
AC-5 Given `lib/db.ts` helpers, when `countRows` or `findMessageByTag` is called without `organization_id`, then it fails type checking; queries use the writer (`@esg/db/writer`), not the replica.
AC-6 Given `lib/s3.ts` `expectObject`, when the object is absent, then it throws a not-found error; when present it returns size and SHA-256 using the `@esg/s3` key builder.
AC-7 Given a lost-message scenario, when a test sends N messages with unique tags (`e2e-<runId>-<n>`) and the verification expects all N downstream in Mailpit, but the stand-in drops one, then the harness reports FAIL naming the missing tag; with all N present it reports PASS (self-test with a stubbed receiver, no stack needed). This is the zero-loss detector.
AC-8 Given a duplicated delivery in the stubbed receiver (tag seen twice), when the check runs, then the harness reports a duplicate for that tag.
AC-9 Given `lib/corpus.ts` and a manifest, when validated, then a wrong `category` versus directory, a missing `license` on `public-corpus`, a `source` outside `synthetic|consented|public-corpus`, a file over 256 KiB, and a corpus over 20 MiB each fail with a distinct error.
AC-10 Given the EICAR materialiser, when run, then the output string's SHA-256 equals the known EICAR hash (68 bytes), it is written to a temp directory, and `git ls-files` plus a repo-wide hash scan find no file with that hash (hard rule 12).
AC-11 Given `test/corpus/`, when listed, then it has the six directories, `manifest.json` and `README.md` with the corpus rules; `malware-eicar/` contains `.eml` templates only and no other malware sample; `dlp/` values are synthetic (Verhoeff-valid Aadhaar-format, PAN-format, test card numbers).
AC-12 Given the stack up with `--profile mta`, when `smoke/stack.e2e.test.ts` runs, then it passes only if every service is healthy and the replica reports both threads running; with `rabbitmq` stopped it fails naming the service.
AC-13 Given `smoke/inbound-deferred-no-ingest.e2e.test.ts`, when run, then swaks to port 2525 for `user@tenant-a.test` gets 250, `postqueue -j` shows the message deferred with an LMTP connection error, and `email_messages` has zero rows for the test tag.
AC-14 Given `smoke/outbound-reinject.e2e.test.ts`, when run, then the message sent from the `reinject` network arrives in `mailpit-tenant` within 10 s; if delivery does not happen, the test fails with the timeout and last error.
AC-15 Given `smoke/open-relay.e2e.test.ts`, when run, then it executes `postfix/test/open-relay.sh` and fails if the script exits non-zero; its output appears in the same vitest report.
AC-16 Given `lib/stack.ts`, when a service is stopped, started and waited on, then `waitHealthy` returns only once the service reports healthy and rejects on timeout.
AC-17 Given the repo, when scanned, then no credentials are hard-coded in `test/e2e` (gitleaks passes; values read from `deploy/local/.env.local`), and the only file changes outside `test/` are none (diff check, since qa-engineer may not alter product code).
AC-18 Given the default `pnpm turbo run build lint typecheck test`, when run without the stack, then the self-tests pass and the `smoke/` e2e specs are not executed.

### Open questions for Sarvesh

- NEEDS SARVESH #1 (public corpora) is assumed as synthetic only; AC-9 and AC-11 allow `public-corpus` only with a license, but no such samples may be committed until approved.

## Out of scope

- Pipeline e2e specs (ingest, scanning, policy). Each is written in its own Phase 1+ task. This task builds the harness and **Phase 0 smoke specs** only.
- Load-testing tools (Phase 6) and chaos tooling beyond restarting compose services.
- Real or harvested spam, phishing or malware samples. Synthetic or consented only, and EICAR only for malware (hard rule 12).

## Design notes

### Layout

```
test/e2e/                      workspace package @esg/e2e
  package.json  vitest.config.ts  (testTimeout 60s, fileParallelism false by default; specs isolate by unique run tag)
  lib/swaks.ts                 run swaks via child_process.execFile (no shell) — either `docker compose exec swaks …`
                               (needed for reinjection on the internal `reinject` network) or host swaks for inbound 2525;
                               returns { exitCode, finalCode, enhancedCode, transcript }; saves transcript to .artifacts/
  lib/smtp-parse.ts            parse swaks transcript → per-command reply codes (unit-tested on recorded transcripts)
  lib/mailpit.ts               Mailpit REST API: waitForMessage({ instance: 'tenant'|'ext', tag, timeoutMs }), getRaw(id), purge()
  lib/db.ts                    assertions via @esg/db/writer (writer, not replica, so tests don't flake on lag):
                               findMessageByTag, countRows(table, { organization_id, message_uuid }) — every query tenant-scoped
  lib/s3.ts                    via @esg/s3: expectObject({ organizationId, messageUuid, receivedAt }) → size + sha256; uses keys builder
  lib/postfix.ts               queue inspection: `docker compose exec postfix-<role> postqueue -j` → parsed JSON; flush/hold helpers
  lib/stack.ts                 stop/start/restart a compose service (for failure tests); waitHealthy(service)
  lib/wait.ts                  poll-until with deadline and last-error reporting (no fixed sleeps)
  lib/tags.ts                  unique run/message tag: `e2e-<runId>-<n>`, carried in Subject and an `X-E2E-Tag` header
                               (test correlation only; the gateway never uses it for any decision)
  lib/corpus.ts                load + zod-validate test/corpus/manifest.json; materialise fixtures (incl. runtime EICAR)
  smoke/stack.e2e.test.ts                       every service healthy; replica running
  smoke/outbound-reinject.e2e.test.ts           swaks → postfix-outbound:10025 (from the `reinject` network) → mailpit-tenant receives within 10 s
  smoke/inbound-deferred-no-ingest.e2e.test.ts  swaks → 2525 for user@tenant-a.test → Postfix 250; postqueue shows it deferred
                                                (LMTP to ingest-service unreachable); zero email_messages rows. Phase 0 only:
                                                replaced by the real ingest spec in Phase 1.
  smoke/open-relay.e2e.test.ts                  wraps postfix/test/open-relay.sh (004) so it runs in the same report
  self-test/*.test.ts                           harness self-tests (below)
  .artifacts/                                   gitignored transcripts and logs
test/corpus/
  manifest.json                 [{ id, path, category, direction, expected: { min_state?, decision? }, source, license, notes }]
  ham/  spam/  phish/  malware-eicar/  malformed/  dlp/
  README.md                     rules for adding samples (below)
```

### Corpus rules

These go in `test/corpus/README.md` and are enforced by the `corpus.ts` validation test.

- `category` must match the directory. `source` is one of `synthetic`, `consented` or `public-corpus` (with `license` required). Each file is at most 256 KiB, and the whole corpus is at most 20 MiB. Large and malformed cases are **generated** at test time (deep MIME nesting, huge header counts, oversize bodies), not committed.
- **`malware-eicar/`** holds `.eml` *templates* only. The EICAR string is assembled at runtime from split constants and written to a temp directory, never committed as a plain file. That keeps developer-laptop antivirus from quarantining repo files, and keeps the repo free of anything that could be mistaken for a sample. Variants include a plain attachment, inside a zip, inside a nested zip, and base64 inline. **No other malware, ever** (hard rule 12).
- **`phish/`** uses only reserved domains (`.test`, `example.com/net/org`) and URLs that don't resolve to live sites.
- **`dlp/`** uses synthetic identifiers only: generated Aadhaar-format numbers that pass Verhoeff, PAN-format strings, and well-known test card numbers (for example 4111 1111 1111 1111). No real personal data.
- **`ham/`** and **`spam/`** are synthetic, unless Sarvesh approves a public corpus (see NEEDS SARVESH).

### Harness self-tests

These run under `pnpm turbo run test`, with no stack needed.
- The swaks transcript parser handles recorded transcripts for 250, 4xx, 5xx, multi-recipient and STARTTLS.
- `wait` reports the last error on timeout.
- Manifest validation catches a wrong category, a missing license and an oversized file.
- The EICAR materialiser produces the standard 68-byte EICAR string (checked by a known hash), and the repo contains no file with that hash.

### How to run

1. `docker compose -f deploy/local/compose.yaml --profile mta up -d && deploy/local/scripts/wait-healthy.sh`
2. `pnpm turbo run test:e2e --filter=@esg/e2e`

Credentials come from `deploy/local/.env.local` and are never hard-coded.

## Hard rules at risk

- **12 (EICAR only).** Runtime-materialised EICAR, a no-sample corpus policy, and the hash check.
- **9 (no secrets).** Credentials come from `.env.local`. Transcripts in `.artifacts/` are gitignored, because SMTP AUTH transcripts in later phases could contain credentials.
- **4 (tenant not from headers).** `X-E2E-Tag` is for test correlation only. From Phase 1 the specs include a negative test: a header claiming tenant B on mail sent to tenant A doesn't change tenancy.
- **7.** Harness DB helpers always filter by `organization_id`, as an example for the rest of the codebase.

## NEEDS SARVESH

1. **Public corpora for ham and spam** (licensing and PII). Options: (a) synthetic only; (b) add the Apache SpamAssassin public corpus (check its licence and redistribution terms); (c) add the Enron dataset. *Recommendation:* (a) now and (b) in Phase 2 after a licence check. Avoid (c), because it contains real people's PII and doesn't fit DPDP well.
