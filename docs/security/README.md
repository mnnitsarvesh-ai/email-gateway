# Security baseline

This document lists the controls in place from Phase 0. A full threat model (STRIDE across the mail path, portal and tenant boundaries) is a dedicated follow-up task.

## Secrets

- No credentials in the repository. `.env` is git-ignored. `.env.example` contains only placeholders (`__GENERATE__`).
- `pnpm env:init` generates random 192-bit secrets locally and writes `.env` with mode 600.
- Clusters use AWS Secrets Manager → External Secrets → file mounts, read through `<KEY>_FILE`.
- Config errors name keys, never values. The logger redacts `password`, `secret`, `token`, `authorization` and `cookie` fields.

## Least privilege

- Separate DB accounts for runtime (DML) and migrations (DDL). The integration tests check this.
- Redis requires a password. RabbitMQ's default `guest` user is limited to loopback.
- MinIO and S3 buckets deny anonymous access. Production buckets are TLS-only with SSE-KMS (Terraform module).
- Containers run as non-root (`node` user). Kubernetes pods use the `restricted` Pod Security level, a read-only root filesystem, all capabilities dropped and no service-account token.
- Local ports bind to `127.0.0.1` only.

## Mail-path controls

- Not an open relay: unknown recipient domains get a permanent `554 Relay access denied`.
- The in-session policy service and the Rspamd milter **fail closed** (4xx tempfail).
- `VRFY` is disabled, HELO is required, connection/rate/recipient limits are set and messages are capped at 50 MB.
- Post-queue processing never bounces, which prevents backscatter. `discard` is always audited.
- Opportunistic inbound TLS (TLS 1.2+). Outbound TLS policy (MTA-STS/DANE) comes in the delivery phase.

## Application controls

- Input validation with zod at every boundary: configuration, events and (as endpoints are added) request bodies.
- Event payloads must carry tenant-prefixed S3 keys, which are checked against the envelope tenant.
- The policy protocol parser bounds request size (16 KiB), rejects malformed lines and refuses response splitting.
- Correlation ids are validated to prevent log injection.
- `helmet` security headers on the API. The portal sets `X-Frame-Options: DENY`, `nosniff`, a referrer policy and a permissions policy, and omits `X-Powered-By`.
- Generic 500 responses that never leak internal details.

## Supply chain

- `pnpm-lock.yaml` is committed, and CI installs with `--frozen-lockfile`.
- `minimumReleaseAge` (7 days) refuses freshly published packages. `onlyBuiltDependencies` allow-lists install scripts.
- Third-party images are pinned by tag (and by digest for MinIO).
- **Follow-ups:** pin GitHub Actions by commit SHA, add secret scanning (gitleaks), dependency audit and image scanning (Trivy) to CI, and generate SBOMs.

## Testing artefacts

Malware tests use only the EICAR test string, which is assembled at runtime and never stored in the repository.
