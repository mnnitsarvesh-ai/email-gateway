# @email-gateway/sandbox-controller

The isolated **sandbox-controller** of step 4.6 ([design](../../docs/plan/steps/14-sandbox.md),
[ADR-0039](../../docs/architecture/adr/0039-sandbox-security-boundary-and-backends.md),
[ADR-0040](../../docs/architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md),
[threat model](../../docs/security/sandbox-threat-model.md),
[runbook](../../docs/runbooks/sandbox-controller.md),
[deployment](../../docs/deployment/sandbox.md)): it consumes `mail.sandbox.task_requested.v1`
from `scan.sandbox` (broker user `eg-sandbox`), fetches the sealed sample from the restricted
sandbox bucket (its own MinIO/IAM user: `samples/` read, `artifacts/` write), runs the configured
isolation backend, seals artifacts to the artifact **public** key and publishes
`mail.sandbox.task_completed.v1` with confirms. It has no database and refuses every database,
Redis, main-S3, MinIO root, token, auth, DLP, BEC LLM, click and other broker key, and the
artifact private key (exit 1, keys named, values never).

**Execution of unknown files is disabled.** `SANDBOX_BACKEND` defaults to `disabled`;
production accepts `disabled` or `static` only; `hardened-container` is a local/CI test harness
(shared kernel, **not a VM boundary**); `vm` refuses to start in 4.6 (its runner is not
implemented). The controller produces no verdict: `sandbox-map/1` runs in the email-worker, and
no path of the controller can yield `clean`.

## Structure

| Path                               | What                                                                                                                                                                                                           |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/main.ts`                      | Startup order (X1): config (refusals) → backend factory → self-test (a failing `vm`/`hardened-container` exits 1: `sandbox backend refused: <code>`) → Nest.                                                   |
| `src/app.module.ts`                | Broker (`AmqpModule`), metrics, health, the controller module and its lifecycle: reaper `startup` pass → timers → consumer; graceful shutdown (wait ≤ task timeout, abort, close).                             |
| `src/config.ts`                    | zod config of §5 with bounds, `FORBIDDEN_KEYS` / `FORBIDDEN_PREFIXES` (+ `_FILE`), backend rules, `CONTROLLER_ENV_KEYS` (the dev allow-list).                                                                  |
| `src/backends/backend.ts`          | The X2 interface (WP1).                                                                                                                                                                                        |
| `src/backends/disabled.backend.ts` | `not_executed` / `backend_disabled`, no bucket, no scratch.                                                                                                                                                    |
| `src/backends/static/`             | The static backend: `analyzer-child.ts` (child entry), `child-runner.ts` (spawn, permission flags, `/proc` sampling, `prlimit`, handshake, kill), `analyzers/` (pure parsers).                                 |
| `src/backends/vm/`                 | Preflight contract + a minimal in-cluster Kubernetes HTTPS client (one `GET`).                                                                                                                                 |
| `src/backends/composite.ts`        | `withStaticAnalysis(static, executor \| null)`: static first, merged observations, caps re-applied.                                                                                                            |
| `src/backends/factory.ts`          | Builds `disabled` / `static` / `hardened-container` (`withStaticAnalysis(static, HardenedContainerBackend)`, re-checking APP_ENV local/ci, no Kubernetes, the opt-in and the sinkhole token) / `vm` (refuses). |
| `src/runner/`                      | The `hardened-container` runner (WP4, local/CI only).                                                                                                                                                          |
| `src/task/`                        | `task-state.ts` (pure X7 transition table + invariants), `task-handler.ts`, `task-consumer.ts` (pause/resume), `result-builder.ts`, `errors.ts`.                                                               |
| `src/storage/sandbox-s3.ts`        | The only S3 access: `GetObject samples/…`, `PutObject artifacts/…` (other keys refused locally), failure classification, readiness probe.                                                                      |
| `src/artifacts/`                   | Caps, kind/content-type and PNG checks, `sandbox-artifact/1` sealing, key layout.                                                                                                                              |
| `src/scratch/`, `src/reaper/`      | Per-task 0700 scratch (`<taskId>-<n>`), path-safe removal, startup/periodic reaping (+ `backend.reap()`).                                                                                                      |
| `src/health/`, `src/metrics/`      | `sandbox-backend` / `sandbox-s3` readiness; exactly the X20 `sandbox_*` series.                                                                                                                                |
| `scripts/dev-env.mjs`              | Host run: allow-listed keys from `../../.env` only, Compose hosts → `127.0.0.1` + published ports, `dist/main.js`.                                                                                             |
| `integration/`                     | Host-run suites against the Compose broker and MinIO; `support/backend-conformance.ts` is the shared X2 conformance suite (also for WP5's runner).                                                             |

## Backends and isolation

- **disabled** — isolation `none`; answers every task `not_executed` / `backend_disabled`.
- **static** — isolation `process`, never executes. ONE analyzer child per task (never reused):
  `env: {}`, `--permission` with `--allow-fs-read` of its compiled directory and
  `<scratch>/in`, `--allow-fs-write` of `<scratch>/out` (no child processes, workers or
  addons), `--max-old-space-size`, RSS/CPU sampled (`/proc` on Linux, `ps` elsewhere) and killed
  above the limits, wall timeout, `prlimit --cpu --core=0` on Linux. The sample is written
  `0400`. The child's reply is untrusted and re-validated with a strict bounded schema.
  Analyzers (`sandbox-static/1`): PE (headers, sections/entropy, imports, overlay), ELF (header
  sanity, UPX), OLE (CFB walk, VBA `dir`, MS-OVBA decompression; `office_auto_exec_shell` for
  auto-exec + shell in one project), OOXML (bounded zip, `vbaProject.bin`, external
  template/oleObject/frame relationships, DDE fields, embedded objects), PDF (names with `#xx`
  decoding, Flate object streams, actions, URI hosts), HTML/SVG (smuggling, password and
  external forms, meta refresh, obfuscated script — nothing rendered), scripts (encoded
  PowerShell, download cradles, LOLBins, shell execution, obfuscation), LNK (target and
  arguments), generic (EICAR assembled at runtime, URL hosts, IPv4, entropy). One bounded
  `static_report` JSON artifact per task (codes, counts, facts, indicators, dictionary tokens —
  no sample text).
- **vm** — preflight only (X9); refuses with `not_in_kubernetes`, `runtime_class_missing`,
  `rbac_denied`, `handler_not_allowed`, `preflight_failed` or, when every proof passes,
  `vm_runner_not_implemented`.
- **hardened-container** — WP4 (`src/runner/`), wired in the factory by WP5 (static analysis first); local/CI only, NOT a VM boundary.

## What is NOT provided

- Execution of unknown files in production or anywhere outside the local/CI harness; a VM
  runner (self-test pod, runner pods, out-of-guest collection) — the `vm` backend only refuses.
- A verdict (the email-worker maps results with `sandbox-map/1`), an artifact download or
  viewing API, decryption of artifacts in any service (ops script and tests only).
- Archive unpacking, Office rendering, OCR, YARA, JavaScript evaluation, disassembly, external
  tools in the static analyzers.
- Network isolation of the static analyzer child beyond the controller's own (Node 22's
  permission model does not restrict sockets; the child holds no credential and the controller's
  network reaches only the broker and the bucket).
- RLIMIT_AS for the analyzer child (V8 reserves address space far beyond its RSS; RSS and heap
  are enforced by the sampler and `--max-old-space-size`).

## Scripts

- `pnpm --filter @email-gateway/sandbox-controller typecheck | lint | test | build`
- `dev`: builds and runs `scripts/dev-env.mjs` (e.g. `SANDBOX_BACKEND=static pnpm --filter
@email-gateway/sandbox-controller dev`).
- `test`: unit tests; the static backend tests spawn the real analyzer child (compiled from source
  with swc into a temporary directory).
- `test:integration` (after `build`): `integration/controller.test.ts`,
  `integration/least-privilege.test.ts` against the Compose broker and MinIO (the MinIO pause
  test runs `docker compose pause minio` and always unpauses); part of the root
  `pnpm test:integration` chain since WP5.
- `test:integration:runner` (local/CI with Docker, the runner images and the exec override's
  sinkhole, which each file starts and stops): `integration/runner/**` — the escape-resistance,
  cleanup, browser, self-test and conformance suites of WP4 plus `factory.test.ts` (the
  factory-built `withStaticAnalysis(static, runner)` against the real daemon). NOT a VM boundary.
