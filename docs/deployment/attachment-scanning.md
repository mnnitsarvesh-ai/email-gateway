# Attachment scanning deployment (step 4.2)

How the attachment engine and clamd are deployed and sized: the `email-worker-attachment` Deployment, the clamd Deployment and Service, production clamd configuration (`ConcurrentDatabaseReload yes`), the scaling formula, a KEDA example, the YARA rule bundle feed and the rlimit requirement. Design and decision ids (A*n*): [docs/plan/steps/10-attachment-scanning.md](../plan/steps/10-attachment-scanning.md). Decision record: [ADR-0028](../architecture/adr/0028-attachment-scanning-engine.md). Operations: [runbook](../runbooks/attachment-scanning.md). Local numbers: [performance/attachment-scanning.md](../performance/attachment-scanning.md).

## Topology

```
 scan.attachment ──▶ email-worker-attachment (SCAN_CONSUMERS=attachment, user eg-scanner)
                       ├─ S3 GetObject org/<id>/part/…            (part bytes, in memory only)
                       ├─ MySQL writer                            (parse/attachment rows, malware_signatures,
                       │                                           attachment_scan_results, sandbox_submissions, outbox)
                       ├─ Redis eg:scan:att:v2:*                  (tenant-independent content cache, HMAC)
                       ├─ clamav Service :3310 ──▶ clamd pods      (INSTREAM inside IDSESSION, TCP only)
                       └─ inspector children (same pod)           (YARA-X, type detection, archive walk;
                                                                   prlimit, empty env, permission model)
 email-worker-scan (SCAN_CONSUMERS=rspamd) ──▶ rspamd                (unchanged, step 4.1)
```

Manifests (base, rendered with `kubectl kustomize infrastructure/kubernetes/base`): `email-worker-attachment.yaml` (Deployment, ServiceAccount without token, Service, HPA, PDB), `clamav.yaml` (ConfigMap with the production `clamd.conf` / `freshclam.conf`, Deployment, Service `clamav`, HPA, PDB), the attachment platform settings and `SCAN_ENGINES=rspamd,attachment` in `config.yaml` (shared with the api, which validates tenant overrides against them). `email-worker-scan` keeps the Rspamd consumers (`SCAN_CONSUMERS=rspamd`). `SCAN_ENGINES` (the required engines of every round) must be identical on every scan replica.

## email-worker-attachment

- Same image as every email-worker role; `MIME_INGESTION_ENABLED=false`, `SCAN_CONSUMERS=attachment`.
- Requests 1 CPU / 1 GiB, limits 2 CPU / 2 GiB. Memory budget: Node heap of the worker + `ATTACHMENT_MEMORY_BUDGET_BYTES` (128 MiB of attachment bytes in flight) + `ATTACHMENT_INSPECTOR_POOL_SIZE × ATTACHMENT_INSPECT_MAX_RSS_MB` (2 × 384 MiB worst case; a well-behaved child stays far below, its heap is capped at `ATTACHMENT_INSPECTOR_HEAP_MB` = 192). Raise the limit before raising the pool size or the budget.
- `readOnlyRootFilesystem: true`, all capabilities dropped, no privilege escalation, `runAsNonRoot`, seccomp `RuntimeDefault`, no service-account token. `/tmp` is a 64 Mi `emptyDir` (`ATTACHMENT_INSPECTOR_TMPDIR=/tmp`): the children's private 0700 working directories live there; nothing is written into them (buffers only), the size limit bounds any accident.
- Readiness includes `clamav` (PING) and `attachment-inspector` (pool ready, rlimit mode, bundle id): a pod that cannot reach clamd or has no ready child leaves the Service; held deliveries stay in the broker.
- The watcher (`scan:attachment-signatures`) and the rescan runner (`scan:attachment-rescans`) run on every replica, one leader each through MySQL advisory locks.
- Content cache MAC key: `ATTACHMENT_CACHE_HMAC_KEY_FILE=/var/run/secrets/attachment-cache/hmac-key` from its **own** Secret `email-gateway-attachment-cache-key` (key `hmac-key`, ≥ 32 random characters), mounted by this Deployment only. It must not go into `email-gateway-secrets`, which every Deployment (including the internet-facing api) mounts: the key is what stops another client of the shared Redis from planting a cache entry (A10). Every attachment replica needs the same value; rotating it only causes cache misses.

### rlimit requirement

`ATTACHMENT_INSPECTOR_RLIMITS=required` (default, and the only value accepted with `NODE_ENV=production`) starts every inspector child as `prlimit --cpu=<soft:hard> --core=0 -- node …` and refuses to start the pool when `prlimit` (util-linux, present in `node:22-bookworm-slim`) is missing. The CPU rlimit is a per-process backstop (soft = `ATTACHMENT_INSPECT_CPU_SECONDS × ATTACHMENT_INSPECTOR_MAX_JOBS`, hard = soft + 5 s); the per-file CPU limit is enforced by the worker's 100 ms sampler (`/proc/<pid>/stat`). Verified in the container by the stack suite `tests/integration/attachment-inspector-container.test.ts` (the `/proc` sampler's CPU and RSS kills, the wall clock and a crash under `prlimit`, and a CPU kill by the `prlimit` backstop alone). `RLIMIT_AS`/`RLIMIT_DATA` are not used (V8 reserves large virtual ranges); memory is enforced by the RSS watchdog (`/proc/<pid>/status`) and the V8 heap cap. Compiled children additionally run under Node's permission model (`--permission --allow-addons --allow-fs-read=<app>,<rules>`): no child processes, no worker threads, no file writes. `best_effort` exists for the macOS development host only.

## clamd

- Image `clamav/clamav-debian:1.4` (clamd + freshclam in one container; pin by digest per environment), TCP 3310 behind Service `clamav`, readiness/liveness `clamdcheck.sh` (PING), a long startup probe (the first database download and load takes minutes).
- Production `clamd.conf` (ConfigMap `clamav-config`): the local limits (`StreamMaxLength 30M` > `ATTACHMENT_MAX_BYTES` 25 MiB, `MaxScanSize 150M`, `MaxFileSize 30M`, `MaxRecursion 10`, `MaxFiles 2000`, `AlertExceedsMax yes`, `AlertOLE2Macros yes`, `AlertEncrypted no`, `HeuristicScanPrecedence no`) with **`ConcurrentDatabaseReload yes`** and `MaxThreads 8`, `MaxQueue 64`. With concurrent reloads clamd loads the new database next to the old one and switches atomically: scans are never blocked by a reload, but memory doubles during it.
- **Sizing:** measured locally (design §12 WP2): ~0.95 GiB RSS idle with the full database, ~1.06 GiB during a non-concurrent `RELOAD`, 1.36 GiB peak at start (freshclam tests a new daily database next to clamd's first load). With `ConcurrentDatabaseReload yes` budget two engines: requests 1.5 GiB, limit 3 GiB per pod. Never co-locate two clamd pods on a node smaller than 8 GiB.
- **Database distribution:** every pod downloads the databases at start (emptyDir). Use a private mirror (`DatabaseMirror` / `PrivateMirror` in `freshclam.conf`) to stay below the public CDN rate limits and to roll updates in a controlled way; alternatively pre-seed a read-only database volume and run freshclam as a separate CronJob. `ClamavSignaturesStale` fires after 48 h without an update.

## Scaling

- Messages in flight per worker: `SCAN_ATTACHMENT_CONCURRENCY` (= prefetch, default 4); attachments in flight: `× ATTACHMENT_PER_MESSAGE_PARALLELISM` (2) = 8, bounded by `ATTACHMENT_MEMORY_BUDGET_BYTES`; children: `ATTACHMENT_INSPECTOR_POOL_SIZE` (2, ≤ 16); clamd connections: `CLAMAV_MAX_CONNECTIONS` (4, ≤ 64). Keep `concurrency × parallelism ≥ pool size` (the worker warns otherwise).
- **clamd capacity:** `CLAMAV_MAX_CONNECTIONS × email-worker-attachment replicas ≤ clamd MaxThreads × clamd replicas` (with the defaults: 4 × N ≤ 8 × M, i.e. one clamd pod per two attachment workers). clamd `MaxQueue` absorbs short bursts; beyond it clamd refuses connections (attempt failures, breaker).
- **Throughput per worker** is bounded by clamd for most files (see the local benchmark): scale clamd on CPU together with the workers.

### KEDA example (queue-driven autoscaling)

Replace the base CPU HPA of `email-worker-attachment` with a ScaledObject (KEDA RabbitMQ scaler) per environment; target 200 ready messages per replica:

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: email-worker-attachment
spec:
  scaleTargetRef: { name: email-worker-attachment }
  minReplicaCount: 2
  maxReplicaCount: 20
  triggers:
    - type: rabbitmq
      metadata:
        protocol: amqp
        queueName: scan.attachment
        vhostName: email-gateway
        mode: QueueLength
        value: '200'
      authenticationRef: { name: rabbitmq-monitoring } # a read-only monitoring user, not eg-scanner
    - type: cpu
      metricType: Utilization
      metadata: { value: '65' }
```

Scale `clamav` on CPU (base HPA, 60 %) and keep the capacity inequality above when raising `maxReplicaCount`.

## YARA rule bundle feed

The image ships the platform bundle `apps/email-worker/yara` (`eg-platform`). A production feed is a directory with the same layout (`bundle.json` + `rules/*.yar`, every rule with `meta: id` and `meta: severity`) mounted read-only and selected with `ATTACHMENT_YARA_RULES_DIR`. Validate it before rollout with `node yara/bundle.mjs --check --dir <dir>` (compiles every rule, refuses warnings, unlisted files and missing metadata). The worker computes the bundle id at start (`yara-<version>-<12 hex>`, A9); every inspector child computes it again from the files it compiled and is refused if it differs. A new bundle changes the content version (every cache key) and is reported by the signature watcher (`yara_bundle`), creating a rescan job row per `ATTACHMENT_SIGNATURE_RESCAN`.

## Local (Compose)

`docker compose` runs one clamd (`mem_limit 2048m`, `infrastructure/clamav/clamd.conf` with `ConcurrentDatabaseReload no` for the 8 GB VM; restart the container after a change, no rebuild) and the email-worker with every role and engine in one process (`ATTACHMENT_INSPECTOR_RLIMITS=required` in the container; host runs use `best_effort` from `.env`). Never run two clamd instances, and never start the analytics/observability profiles together with the apps profile on the 8 GB VM.
