# Runbook: sandbox-controller (isolated sandbox orchestration)

Step 4.6 ([design](../plan/steps/14-sandbox.md) X1–X9, X19, X20; [ADR-0039](../architecture/adr/0039-sandbox-security-boundary-and-backends.md), [ADR-0040](../architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md); [threat model](../security/sandbox-threat-model.md); deployment: [sandbox.md](../deployment/sandbox.md); related runbook: [sandbox-engine.md](sandbox-engine.md) — the email-worker side: dispatch, dedup, results, expiry, purge). The **sandbox-controller** consumes `mail.sandbox.task_requested.v1` from `scan.sandbox` (broker user `eg-sandbox`), reads the sealed sample from the restricted sandbox bucket (`samples/` only), runs the configured isolation backend, seals artifacts to the artifact **public** key (`artifacts/` only) and publishes `mail.sandbox.task_completed.v1` with confirms. It has no database and produces no verdict (`sandbox-map/1` runs in the email-worker).

**Execution of unknown files is disabled.** Every environment runs `SANDBOX_BACKEND=disabled` by default; production accepts `disabled` or `static` (no execution) only. `hardened-container` is a local/CI test harness (shared kernel, **not a VM boundary**) that the configuration refuses outside `APP_ENV` local/ci, inside Kubernetes and without `SANDBOX_ALLOW_NON_VM_EXECUTION=true`. The `vm` backend is a preflight contract that **refuses to start** in step 4.6. Nothing in this runbook enables execution in production; that needs every precondition of the threat model §8 and a new ADR.

**Rules that hold in every procedure below:**

- **Never give the controller more credentials** to "debug" it. It refuses to start (exit 1, names the key, never the value) with any `DATABASE_*`, `MYSQL_*`, `REDIS_*`, `S3_*`, `MINIO_*`, `URL_TOKEN_*`, `AUTH_*`, `DLP_*`, `BEC_LLM_*`, `CLICK_*` key, `DATA_ENCRYPTION_KEY(_PREVIOUS)`, `ATTACHMENT_CACHE_HMAC_KEY`, `URL_CACHE_HMAC_KEY`, `URL_EGRESS_PROXY_TOKEN`, `ANTHROPIC_API_KEY`, `SANDBOX_ARTIFACT_PRIVATE_KEY`, `RABBITMQ_URL`, `RABBITMQ_ADMIN_URL`, `RABBITMQ_DEFAULT_USER/PASS`, `RABBITMQ_PASSWORD`, `RABBITMQ_CLUSTER_ERLANG_COOKIE` or any other `RABBITMQ_*_URL` / `RABBITMQ_*_PASSWORD` (also as `<KEY>_FILE`). Host runs go through `scripts/dev-env.mjs` (allow-listed keys only), never `--env-file=../../.env`.
- **Never open a sample or an artifact on a workstation.** Artifacts are sealed to the artifact public key; only the documented ops script opens them, on an ops host that holds the private key (`pnpm --filter @email-gateway/sandbox artifact:open`).
- **Never download or commit real malware** to test anything. Tests use synthetic benign samples written for them and the EICAR string assembled at runtime.
- The controller is **optional**: `scan.sandbox` is a bounded lossy work queue (10 000, drop-head); analyses nobody answers expire at their deadline (verdict `timeout`, never `clean`); mail delivery never waits for the sandbox.

## Contents

- [Backends](#backends) · [Readiness and self-test](#readiness-and-self-test) · [Series](#series)
- Alerts: [SandboxControllerDown](#sandboxcontrollerdown) · [SandboxBackendNotReady](#sandboxbackendnotready) · [SandboxCleanupFailures](#sandboxcleanupfailures) · [SandboxTaskFailuresHigh](#sandboxtaskfailureshigh) · [SandboxExecutingBackendOutsideTest](#sandboxexecutingbackendoutsidetest)
- Procedures: [enabling static](#enabling-the-static-backend) · [refusing execution](#refusing-execution) · [reaper and leftovers](#reaper-and-leftover-runners-or-scratch) · [suspected escape](#suspected-escape) · [key rotation](#key-rotation) · [v8 rollout purge](#topology-v8-rollout-purge-of-the-dormant-scansandbox) · [failure classes](#failure-classes) · [host run and tests](#host-run-and-the-focused-suites)

## Backends

| `SANDBOX_BACKEND`    | Isolation   | Executes | Allowed in                                       | What a task gets                                                                                                                                              |
| -------------------- | ----------- | -------- | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `disabled` (default) | `none`      | no       | everywhere                                       | `not_executed` / `backend_disabled`; no bucket read, no scratch.                                                                                              |
| `static`             | `process`   | no       | everywhere (production-eligible)                 | `completed` with static findings and indicators, `executed: false`, one sealed `static_report`; `not_executed` / `type_not_supported` for archives, images, … |
| `hardened-container` | `container` | yes      | `APP_ENV` local/ci, outside Kubernetes, opted in | Static analysis, then one disposable runner per task (WP4; wired in the factory by WP5). **Not a VM boundary.**                                               |
| `vm`                 | `vm`        | (yes)    | refuses everywhere in 4.6                        | The controller exits 1: `not_in_kubernetes` (here), else `runtime_class_missing` / `rbac_denied` / `handler_not_allowed` / `vm_runner_not_implemented`.       |

The `static` backend runs ONE analyzer child per task (`dist/backends/static/analyzer-child.js`): empty environment, Node's permission model (reads of its own directory and `<scratch>/in`, writes to `<scratch>/out`, no child processes, workers or addons), `--max-old-space-size=SANDBOX_STATIC_HEAP_MB`, RSS/CPU sampled from `/proc` and killed above `SANDBOX_STATIC_MAX_RSS_MB` / `SANDBOX_STATIC_CPU_SECONDS`, wall timeout `SANDBOX_STATIC_TIMEOUT_MS`, `prlimit --cpu --core=0` on Linux. The sample is written `0400` (never executable) and is never evaluated: analyzers pe, elf, ole (CFB + MS-OVBA), ooxml, pdf, html/svg, script, lnk, generic (EICAR, hosts, IPv4, entropy) are pure pattern/structure parsers (`sandbox-static/1`). A resource kill is a finding (`limit.analyzer_resources`, the file is hostile to parsers); a wall-timeout kill is `failed`/`analyzer_timeout`, a crash `failed`/`analyzer_crashed`.

## Readiness and self-test

Startup order (X1): configuration (refusals) → backend factory → `backend.selfTest()` (a failing `vm` / `hardened-container` self-test exits 1 with `sandbox backend refused: <code>`) → reaper `startup` pass → consumer. `/health/ready` checks:

- `rabbitmq` — connected, `scan.sandbox`, `email.security`, `email.events` verified passively;
- `sandbox-backend` — the last self-test (startup, then every `SANDBOX_SELF_TEST_INTERVAL_MS`), details `backend`, `backendVersion`, `isolation`, `executes`, `boundary` (`no-execution`, `analyzer-process-no-execution`, `container-not-a-vm-boundary`, `vm`), `selfTest`, `lastSelfTestAt` and the backend's own details (static: `analyzerVersion`, `permissionModel`, `rlimit`);
- `sandbox-s3` (static / hardened-container only) — a `GetObject` of a sample key that never exists: `NoSuchKey` (or `AccessDenied`) proves endpoint, bucket and credentials; the controller's user may not `HeadBucket` (no bucket-level permission, by design).

While the self-test fails the consumer is **cancelled** (no nack loop) and resumes when it passes again.

## Series

`sandbox_tasks_total{backend,status}` (`completed`, `not_executed`, `failed`, `rejected`, `retried`), `sandbox_task_duration_seconds{backend,profile}`, `sandbox_backend_ready{backend}`, `sandbox_backend_info{backend,isolation,executes}`, `sandbox_runners_active`, `sandbox_reaped_total{kind,mode}`, `sandbox_cleanup_failures_total{kind}`, `sandbox_limit_hits_total{limit}`, `sandbox_findings_total{severity}`, `sandbox_artifacts_total{kind}`, `sandbox_artifact_bytes_total`, `sandbox_s3_errors_total{op}` (`get_sample`, `put_artifact`), `sandbox_publish_failures_total`, plus `amqp_*`. No tenant, hash, host or task label. Logs carry task id, analysis id, organization id, backend, status, codes and durations only.

## SandboxControllerDown

`up{job="sandbox-controller"} == 0` for 5 minutes. Tasks wait in `scan.sandbox` (bounded, lossy) and analyses expire at their deadline (`timeout`); delivery is unaffected.

1. Kubernetes: `kubectl -n email-gateway get pods -l app.kubernetes.io/name=sandbox-controller`; `kubectl logs` — a refusal at start is one fatal line: `sandbox-controller configuration refused` (issues name the keys) or `sandbox backend refused: <code>`. Fix the configuration; never add credentials.
2. Compose: `docker compose --profile apps ps sandbox-controller`; `docker compose logs --tail 50 sandbox-controller`. Locally the Prometheus job is 0 unless Prometheus is attached to the internal `sandbox-control` network (expected).
3. After the restart the startup reaper removes anything the previous process left; redelivered tasks run again (their results are deduplicated downstream).

## SandboxBackendNotReady

`sandbox_backend_ready == 0` for 10 minutes; the consumer is paused.

1. `curl -s http://<controller>:3092/health/ready | jq '.checks[] | select(.name=="sandbox-backend")'` — the error names the self-test code.
2. `static`, `self_test_failed`: the analyzer child could not spawn, handshake or analyze the built-in benign sample, or the scratch is not writable. Check `SANDBOX_SCRATCH_DIR` (emptyDir/tmpfs full or read-only?), the image (is `dist/backends/static/analyzer-child.js` present?), memory limits (`SANDBOX_STATIC_HEAP_MB` < `SANDBOX_STATIC_MAX_RSS_MB` < container limit).
3. `hardened-container` (local/CI): see WP4's [escape-testing doc](../security/sandbox-escape-testing.md) — `docker_unreachable`, `spec_not_enforced` (a probe runner did not prove its restrictions).
4. When it passes again (next interval or a restart) the consumer resumes on its own.

## SandboxCleanupFailures

**Critical.** A runner or scratch directory could not be removed (per task or by the reaper): it may hold sample bytes or a still-running sample.

1. Logs: `sandbox scratch directory could not be removed` / `sandbox runner could not be removed` / `sandbox reaper removed leftovers` with `failures > 0` (ids and counts only).
2. Scratch: `kubectl exec deploy/sandbox-controller -- ls -la /scratch` (Compose: `docker compose exec sandbox-controller ls -la /scratch`). Entries are `<taskId>-<n>` or `selftest-<hex>`. A restart empties the emptyDir/tmpfs and the startup reaper removes the rest.
3. Runners (local/CI only): `docker ps -a --filter label=eg.sandbox.runner=1 --format '{{.ID}} {{.Labels}}'`; remove with `docker rm -f -v <id>`. A runner that survives forced removal or keeps running after its `eg.sandbox.expires` label → [suspected escape](#suspected-escape).

## SandboxTaskFailuresHigh

More than 10 % of the results of 15 minutes are `failed`. Read the codes: `sum by (status) (rate(sandbox_tasks_total[15m]))` and the controller logs (`errorCode`).

- `sample_unavailable` — the sample object is gone (lifecycle expiry, an analysis older than `SANDBOX_SAMPLE_RETENTION_HOURS`, or the dispatcher's put failed). See [sandbox-engine.md](sandbox-engine.md).
- `sample_integrity` — the sealed object does not open with `SANDBOX_SAMPLE_KEY` (+previous) or its SHA-256 differs: a key mismatch between email-worker and controller (rotation done on one side only) or tampering. Compare the key ids/rotation state; never print keys.
- `storage_unavailable` — the bucket was unreachable for the whole retry budget (`sandbox_s3_errors_total`); see the S3 endpoint and the controller NetworkPolicy.
- `analyzer_crashed` / `analyzer_timeout` — parser failures on hostile input (the sample is not analysable statically; its analysis ends `error`). A sudden rise after an image change is a regression: roll back.
- `backend_not_ready` — a refusal during a run (should coincide with SandboxBackendNotReady).

## SandboxExecutingBackendOutsideTest

**Critical.** `sandbox_backend_info{executes="true"}` reported by a target whose `environment` label is not `local`/`ci` (or missing). The configuration refusal should make this impossible; treat it as a configuration breach.

1. Stop the controller now: `kubectl -n email-gateway scale deploy/sandbox-controller --replicas=0` (Compose: `docker compose stop sandbox-controller`).
2. Restore `SANDBOX_BACKEND=disabled`, `SANDBOX_ALLOW_NON_VM_EXECUTION=false`; verify `APP_ENV=production` and that the Deployment does not mount a Docker socket.
3. If samples ran, follow [suspected escape](#suspected-escape). Open an incident; the change that enabled it needs the threat model §8 review it skipped.

## Enabling the static backend

`static` executes nothing and is production-eligible.

1. Prerequisites: the sandbox bucket and the `eg-sandbox-controller` IAM user/policy exist (deployment doc); the Secrets `email-gateway-sandbox-s3` and `email-gateway-sandbox-keys` are populated (`sample-key`, `result-key`, `artifact-public-key`); the email-worker holds the same sample and result keys.
2. Set `SANDBOX_BACKEND=static` on the Deployment (Compose: `SANDBOX_BACKEND=static` in `.env`, then `docker compose --profile apps up -d --no-deps sandbox-controller`). Optionally set `SANDBOX_EXPECTED_BACKEND=static` for the api (informational: the portal says "static analysis only").
3. Verify: `/health/ready` shows `sandbox-backend` `backend: static`, `executes: false`, and `sandbox-s3` ok; `sandbox_backend_info{backend="static",executes="false"} 1`.
4. Roll back by setting `disabled` again (no state to migrate).

## Refusing execution

Execution is refused by configuration in every production environment: `SANDBOX_ALLOW_NON_VM_EXECUTION=true` is refused outside `APP_ENV` local/ci; `hardened-container` additionally needs no `KUBERNETES_SERVICE_HOST`; `vm` refuses at preflight. Never set `APP_ENV` to `local`/`ci` in a cluster to get around it. The local exec override (Compose file of WP4, Docker socket) is for focused local/CI suites only and never deployed.

## Reaper and leftover runners or scratch

- `startup` (before the consumer starts): removes every scratch entry (`<taskId>-<n>`, `selftest-<hex>`) and asks the backend to remove every runner labelled with this controller's `SANDBOX_CONTROLLER_NAME` (pod name in Kubernetes; fixed in Compose).
- `periodic` (every `SANDBOX_REAPER_INTERVAL_MS`): scratch older than `SANDBOX_TASK_TIMEOUT_MS + 60 s` and runners past their `eg.sandbox.expires` label, never those of a task in flight.
- Paths are safe: only direct, well-named children of the real scratch root; symbolic links are unlinked, never followed.
- `sandbox_reaped_total{kind,mode}` > 0 after a crash is expected; a steady periodic count means tasks are leaving things behind — read `sandbox_cleanup_failures_total` and the task logs.

## Suspected escape

Threat model §8 item 7. Applies to the local/CI harness today (production executes nothing):

1. **Contain:** stop the controller (`docker compose stop sandbox-controller`, or scale to 0); stop and keep (do not remove) any runner still alive: `docker pause <id>`; disconnect the host from shared networks if a host-level compromise is possible.
2. **Preserve:** `docker inspect <id>` and `docker export <id>` to an evidence location; copy the controller logs (ids only) and the sinkhole records (`GET /records` with the admin token) before they age out (15 min ring).
3. **Rotate** what the controller held: the `eg-sandbox` broker password (`RABBITMQ_SANDBOX_PASSWORD`, `pnpm rabbitmq:init`), the `eg-sandbox-controller` S3 secret (MinIO user / IAM key), `SANDBOX_SAMPLE_KEY` and `SANDBOX_RESULT_KEY` ([key rotation](#key-rotation)); the artifact private key never was on the controller.
4. **Rebuild** the runner image and the host/VM from known-good sources; re-run the escape-resistance suite before any further execution.
5. In a future production VM pool: cordon and drain the runner pool, keep the node for forensics, rotate as above.

## Key rotation

Never print a key. All three are 32 random bytes as 64 hex (`SANDBOX_SAMPLE_KEY`, `SANDBOX_RESULT_KEY`) or an X25519 pair (artifacts).

- **`SANDBOX_SAMPLE_KEY`** (email-worker seals, controller opens): set the new key as `SANDBOX_SAMPLE_KEY` and the old as `SANDBOX_SAMPLE_KEY_PREVIOUS` on **both** the controller and email-worker-sandbox (controller first, so it can open samples sealed with either), wait `SANDBOX_SAMPLE_RETENTION_HOURS` (samples are short-lived), then drop `_PREVIOUS`.
- **`SANDBOX_RESULT_KEY`** (controller signs, email-worker verifies; no previous-key support): deploy both sides together during a quiet window; results signed with the old key in flight are rejected (`bad_mac`), queued tasks whose result token was sealed under the old key are rejected by the controller (dead-letter `invalid_task`, no run), and their analyses expire (`timeout`) — re-dispatch by rescanning if needed.
- **Artifact key pair**: generate a new pair (`scripts/init-env.mjs` directives `__X25519_PRIVATE__` / `__X25519_PUBLIC_OF_PREVIOUS__`, or `generateArtifactKeyPair()`); store the private key in the secret store (offline/ops only, never on a service); deploy the new public key to the controller. Older artifacts keep their `kid` (`x1.<kid>…`, first 8 hex of the public key's SHA-256): keep the previous private key until their retention (`SANDBOX_ARTIFACT_RETENTION_DAYS`) has passed.

## Topology v8 rollout purge of the dormant scan.sandbox

Topology v8 rebinds `scan.sandbox` from `mail.attachment.sandbox_requested.v1` (v4–v7, dormant, nobody consumed it) to `mail.sandbox.task_requested.v1`. Before the first controller consumes it, the old dormant buffer must be empty — it holds submission events, not tasks, and the controller would dead-letter each as an unaccepted type:

1. `pnpm rabbitmq:init` (removes the stale bindings).
2. Check: `docker compose exec rabbitmq rabbitmqctl list_queues -p email-gateway name messages | grep '^scan.sandbox\s'` (Kubernetes: the management API).
3. If not empty: `rabbitmqctl purge_queue -p email-gateway scan.sandbox` **once**, before deploying the controller. The pending submissions behind them expire through the sweeper (`timeout`), see [sandbox-engine.md](sandbox-engine.md).

## Failure classes

| Failure                                  | Behaviour                                                                                                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Unknown type / schema / tenant mismatch  | Dead-lettered at once (`sandbox_tasks_total{status="rejected"}`).                                                                                                                 |
| Deadline passed                          | `not_executed` / `deadline_passed` without a run.                                                                                                                                 |
| Bucket outage (sample GET, artifact PUT) | Transient: hold retry (5 s…60 s), no result, attempt not consumed — until the next hold would pass the task deadline or the 1 h retry age; then `failed` / `storage_unavailable`. |
| Sample missing / not authentic           | `failed` / `sample_unavailable` / `sample_integrity` (no retry).                                                                                                                  |
| Backend infrastructure outage            | Transient as above; then `failed` / `backend_not_ready`.                                                                                                                          |
| Broker outage while publishing           | The task is not acked; the consumer retries; the common client reconnects.                                                                                                        |
| Shutdown during a task                   | Aborted, scratch removed, requeued (retried by the next process).                                                                                                                 |
| Duplicate delivery in flight             | Waits for the first and is acked without a second run; cross-process duplicates are absorbed downstream.                                                                          |

## Host run and the focused suites

- `pnpm --filter @email-gateway/sandbox-controller dev` — builds, then `scripts/dev-env.mjs` copies only the allow-listed keys from `../../.env`, maps `minio:9000` to `127.0.0.1:${MINIO_HOST_PORT}`, uses `$TMPDIR/eg-sandbox-controller-scratch` and spawns `dist/main.js` (`SANDBOX_BACKEND=static pnpm … dev` to try static).
- `pnpm --filter @email-gateway/sandbox-controller build && pnpm --filter @email-gateway/sandbox-controller test:integration` — the WP2 suites (`integration/controller.test.ts`, `integration/least-privilege.test.ts`) against the Compose broker and MinIO: disabled and static results, the sealed `static_report` opened with the private key from `.env`, the non-execution probe, least privilege of both users, MinIO paused (`docker compose pause minio`, always unpaused in `finally`) → transient retry → result, and the `vm` refusal (spawned `node dist/main.js` exits 1). Every message and object they create is removed.
