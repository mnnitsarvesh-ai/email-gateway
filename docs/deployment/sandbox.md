# Sandbox deployment (step 4.6)

Design: [14-sandbox.md](../plan/steps/14-sandbox.md) (X1, X3, X5, X8, X9, X11, X12, X20), [ADR-0039](../architecture/adr/0039-sandbox-security-boundary-and-backends.md), [ADR-0040](../architecture/adr/0040-sandbox-engine-dispatch-results-artifacts.md), [threat model](../security/sandbox-threat-model.md). Runbooks: [sandbox-controller.md](../runbooks/sandbox-controller.md), [sandbox-engine.md](../runbooks/sandbox-engine.md). Local runner internals and escape-resistance results: [sandbox-escape-testing.md](../security/sandbox-escape-testing.md) (WP4).

## Execution of unknown files is disabled

Stated plainly, for every environment this repository deploys:

- **The default backend everywhere is `disabled`**: every sandbox task is answered `not_executed` / `backend_disabled`; the analysis maps to `unknown` (never `clean`); nothing is read from the bucket.
- **Production accepts `SANDBOX_BACKEND=disabled` or `static` only.** `static` runs bounded static analyzers in a limited child process and **executes nothing**.
- **`hardened-container` is a local/CI test harness**: one hardened Docker container per task on an internal network with a recording sinkhole. It shares the host kernel and is **not a VM boundary**. The controller refuses it unless `APP_ENV` is `local` or `ci`, it runs outside Kubernetes and `SANDBOX_ALLOW_NON_VM_EXECUTION=true`; the alert `SandboxExecutingBackendOutsideTest` (critical) watches for it anywhere else.
- **`vm` refuses to start.** Its preflight checks Kubernetes, the RuntimeClass and its handler and then always refuses (`vm_runner_not_implemented`): the VM runner, its self-test pod and out-of-guest collection are not implemented in step 4.6. On a workstation it refuses with `not_in_kubernetes`.
- Only synthetic benign samples written for the tests and the EICAR test string (assembled at runtime) are ever executed or stored. No real malware is downloaded or committed.

## Topology

| Component                | Where                                                                                                 | Credentials                                                                                                                                                                                                        |
| ------------------------ | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **sandbox-controller**   | Compose profile `apps` (since step 4.6 WP5); `infrastructure/kubernetes/base/sandbox-controller.yaml` | broker user `eg-sandbox`; sandbox-bucket user `eg-sandbox-controller` (`samples/` read, `artifacts/` write); `SANDBOX_SAMPLE_KEY`, `SANDBOX_RESULT_KEY`, artifact **public** key. Nothing else (refused at start). |
| **email-worker sandbox** | Compose `email-worker` (`SANDBOX_ENABLED`); `email-worker-sandbox.yaml`                               | the scan role (`eg-scanner`), the email-worker's S3 credentials (sandbox bucket: put/get/delete `samples/*`, get/delete `artifacts/*`), the sample and result keys                                                 |
| **api**                  | existing                                                                                              | platform settings only (`SANDBOX_EXPECTED_BACKEND` is informational)                                                                                                                                               |
| **event-relay**          | existing                                                                                              | `RECONCILE_QUEUES` includes `scan.sandbox.submissions`                                                                                                                                                             |

Queues (topology v8): `scan.sandbox.submissions` (email-worker dispatcher), `scan.sandbox` (controller; bounded lossy, stateless), `scan.sandbox.results` (email-worker results consumer). The controller publishes results directly with publisher confirms (no outbox: it has no database).

## Compose (local)

1. Keys: `node scripts/init-env.mjs` generates `SANDBOX_SAMPLE_KEY`, `SANDBOX_RESULT_KEY`, the X25519 pair (`SANDBOX_ARTIFACT_PRIVATE_KEY` for tests/ops only, `SANDBOX_ARTIFACT_PUBLIC_KEY` for the controller), `RABBITMQ_SANDBOX_PASSWORD` and `SANDBOX_S3_SECRET_ACCESS_KEY` (existing secrets untouched).
2. `pnpm rabbitmq:init` (role user `eg-sandbox`, topology v8) and `docker compose run --rm --no-deps minio-init` (bucket `email-gateway-sandbox`, versioning off, lifecycle, user/policy `eg-sandbox-controller`). Before the first controller start: the [v8 purge](../runbooks/sandbox-controller.md#topology-v8-rollout-purge-of-the-dormant-scansandbox) of the dormant `scan.sandbox`.
3. Controller (profile `apps` since WP5): `docker compose --profile apps up -d sandbox-controller` — read-only root, tmpfs `/scratch` (256 MiB, 0700) and `/tmp`, `cap_drop: ALL`, `no-new-privileges`, user 1000, 384 MiB, pids 128, 1 CPU, network `sandbox-control` only (internal: RabbitMQ, MinIO), health on port 3092 inside that network (Docker does not publish ports of a container whose only network is internal: use `docker compose exec sandbox-controller node -e "fetch('http://127.0.0.1:3092/health/ready').then(async r=>console.log(await r.text()))"`). Build its image alone (never in parallel with another build on the 8 GB VM) and never start it together with the analytics/observability profiles.
4. Host run instead of the container: `pnpm --filter @email-gateway/sandbox-controller dev` (`scripts/dev-env.mjs` loads only the allow-listed keys, maps MinIO to its published port, uses a temporary scratch). Switch backends with `SANDBOX_BACKEND=static`.
5. **Local exec override (local/CI only):** `infrastructure/sandbox/compose.exec.yml` adds the recording sinkhole on the internal `sandbox-detonation` network and gives the controller the Docker socket with `SANDBOX_BACKEND=hardened-container`, `SANDBOX_ALLOW_NON_VM_EXECUTION=true`. Mounting the socket gives the controller control of the Docker VM: acceptable for focused local/CI suites only (threat model R3), never deployed. Its internals (runner image, hardened spec, protocol, sinkhole) and the escape-resistance results are documented by WP4 in [sandbox-escape-testing.md](../security/sandbox-escape-testing.md). In this wave the factory refuses `hardened-container` with `backend_not_wired`; WP5 wires the runner (wave 3).

## Kubernetes

Rendered only (`kubectl kustomize infrastructure/kubernetes/base`, overlays `saas` / `dedicated`); not applied by this repository.

- **`sandbox-controller`**: `replicas: 1`, `strategy: Recreate`, `SANDBOX_BACKEND=disabled`, `SANDBOX_ALLOW_NON_VM_EXECUTION=false`, `APP_ENV=production`, `SANDBOX_CONTROLLER_NAME` from the pod name (downward API), `automountServiceAccountToken: false` (its own ServiceAccount, no RBAC), restricted security context (non-root 1000, `RuntimeDefault` seccomp, no privilege escalation, all capabilities dropped, read-only root), `emptyDir` `/scratch` with `sizeLimit: 256Mi`, memory `/tmp`, probes on 3092, requests 250m / 256 MiB, limits 1 CPU / 768 MiB, `terminationGracePeriodSeconds: 200` (in-flight tasks awaited up to `SANDBOX_TASK_TIMEOUT_MS`). Explicit environment — it does **not** read `email-gateway-config` (which carries `S3_*`).
- **Secrets** (External Secrets, mounted as files via the `<KEY>_FILE` convention): `email-gateway-rabbitmq-sandbox` (`url`), `email-gateway-sandbox-s3` (`access-key-id`, `secret-access-key`), `email-gateway-sandbox-keys` (`sample-key`, `result-key`, `artifact-public-key`, optional `sample-key-previous`). Never mount `email-gateway-secrets`, the database, Redis, main-S3, DLP, BEC or other broker secrets, nor the artifact private key: the controller refuses to start with any of them.
- **`email-worker-sandbox`**: the email-worker image with `SCAN_ENABLED=true`, `SCAN_CONSUMERS=sandbox`, `SANDBOX_ENABLED=true` and the engine keys; it shares `email-gateway-sandbox-keys` (`sample-key`, `result-key`) with the controller.
- **`email-gateway-config`** gains the shared platform keys (`SANDBOX_TENANT_DEFAULT_ENABLED`, `SANDBOX_FILE_TYPES`, `SANDBOX_MAX_SAMPLE_BYTES`, `SANDBOX_BROWSER_ANALYSIS`, `SANDBOX_EXPECTED_BACKEND=disabled`, `SANDBOX_S3_BUCKET`, the artifact caps and retention keys) read by the api and email-worker-sandbox.
- **event-relay** `RECONCILE_QUEUES` adds `scan.sandbox.submissions`.
- **Prometheus** scrapes `sandbox-controller:3092` (job `sandbox-controller`) with a target label `environment` (`production`/`staging`): `SandboxExecutingBackendOutsideTest` fires for an executing backend in any other environment, and for a target without the label (fail-safe).

## Network policies

- **Controller egress** only: the broker subnet (5671/5672), cluster DNS (53) and HTTPS (443) to the subnet of an **S3 interface VPC endpoint** (PrivateLink; enable its private DNS or set `SANDBOX_S3_ENDPOINT` to the endpoint's DNS name). The base carries placeholder private CIDRs (`10.0.64.0/20` broker, `10.0.80.0/24` S3 endpoint) that every overlay replaces. **Fail-closed:** no public range — never `0.0.0.0/0`/`::/0` — because the controller parses attacker files and holds `SANDBOX_SAMPLE_KEY`; a gateway endpoint (a prefix list of public IPs) cannot be expressed in a NetworkPolicy. `pnpm test` (sandbox-controller `src/deployment/network-policy.test.ts`) refuses any non-private CIDR, any `except` list and any egress rule without destinations in the controller's NetworkPolicy, in the base and in every overlay file. **Ingress** only from Prometheus on 3092. The kubelet probes are not subject to NetworkPolicies.
- The analyzer child of the `static` backend shares the controller's network namespace (Node 22's permission model restricts files, child processes, workers and addons, not sockets); it holds no credential (empty environment) and can reach only what the controller's policy allows.
- `email-worker-sandbox` egress as the other scan replicas (MySQL, Redis, broker, DNS, OTLP, S3 over HTTPS).

## Production S3 bucket and IAM

- **Bucket** (Terraform): dedicated, e.g. `email-gateway-<env>-sandbox`; **versioning off** (a purge is a real delete), Block Public Access on, SSE-S3 or SSE-KMS, TLS-only bucket policy (`aws:SecureTransport`), lifecycle `samples/` expire after `ceil(SANDBOX_SAMPLE_RETENTION_HOURS / 24)` days (≥ 1) and `artifacts/` after `SANDBOX_ARTIFACT_RETENTION_DAYS + 1` days (the email-worker sweeper crypto-shreds and deletes earlier).
- **`eg-sandbox-controller`** (IAM user or role; the controller has no service-account token, so static credentials from the Secret, rotated like other keys):

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::<bucket>/samples/*"
      },
      {
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::<bucket>/artifacts/*"
      }
    ]
  }
  ```

  Nothing else: no `ListBucket` (it cannot enumerate other tasks' samples; the readiness probe tolerates the resulting `AccessDenied` for a missing key), no delete, no other bucket. Verified locally against MinIO by `integration/least-privilege.test.ts`.

- **`email-worker-sandbox` role**: `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on `<bucket>/samples/*`; `s3:GetObject`, `s3:DeleteObject` on `<bucket>/artifacts/*`; its existing mail-bucket permissions.
- **Artifact private key**: in the secret store, readable only by the ops role that runs `pnpm --filter @email-gateway/sandbox artifact:open` on an ops host. No service holds it.

## Rollout (upgrading from step 4.5)

1. `pnpm db:migrate` (`sandbox_engine`), `pnpm rabbitmq:init` (topology v8, `eg-sandbox`), bucket and IAM (above), the three Secrets.
2. Purge the dormant `scan.sandbox` once ([runbook](../runbooks/sandbox-controller.md#topology-v8-rollout-purge-of-the-dormant-scansandbox)).
3. Deploy the sandbox-controller (`disabled`) and verify readiness; deploy `email-worker-sandbox`; event-relay with the new `RECONCILE_QUEUES`.
4. Tenants opt in (plan feature `attachment_sandbox` + their `scan_engine_settings`); results are `unknown` (`sandbox.not_executed.backend_disabled`) until `static` is enabled ([runbook](../runbooks/sandbox-controller.md#enabling-the-static-backend)).

## Production preconditions for execution (threat model §8)

None of these is met in step 4.6, so **execution stays disabled**. All must be true, verified and recorded (step record and change ticket) before any executing backend runs outside local/CI:

1. **VM-class isolation proven at startup and continuously**: the `vm` backend runs in Kubernetes, the configured RuntimeClass exists with an allowed handler (`runsc`, `kata*`, `kata-fc`), and a self-test pod under it proves it is not on the node's kernel and cannot reach the metadata address, the node IP or the cluster DNS. Readiness fails when the self-test fails; the controller refuses to start when the preflight fails.
2. **A VM runner that collects from outside the guest** (host-side or trusted-agent telemetry the sample cannot modify) — not implemented.
3. **A dedicated, tainted node pool** for runner pods, nodes without useful instance-role credentials, IMDSv2 with hop limit 1, metadata blocked by NetworkPolicy and node firewall.
4. **Network**: runner namespace default-deny; only the recording sinkhole reachable; no Internet egress without a separately reviewed design.
5. **The controller's Kubernetes identity** limited to create/get/delete pods in the runner namespace with the fixed security context, enforced by an admission policy (RuntimeClass, non-root, no host namespaces, only a size-limited `emptyDir`); no secrets in that namespace.
6. **The escape-resistance suite**, extended for the VM runner, green against the production configuration in a staging cluster, plus an external penetration test of the runner pool.
7. **Monitoring and response**: `SandboxCleanupFailures`, `SandboxBackendNotReady`, `SandboxResultsRejected` routed to on-call; the suspected-escape runbook exercised.
8. **Update cadence**: gVisor/Kata/Firecracker and node kernels patched on a documented cadence; the runner image rebuilt weekly.
9. **The threat model re-reviewed** with the VM design and an ADR enabling execution accepted.

Until then: `SANDBOX_BACKEND ∈ {disabled, static}` in production; `hardened-container` is refused; `vm` refuses at preflight.
