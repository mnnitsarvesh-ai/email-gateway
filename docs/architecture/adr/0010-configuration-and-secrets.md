# ADR-0010: Validated configuration, file-mounted secrets, least-privilege DB accounts

**Status:** Accepted

**Decision.**

- Each service declares a zod schema composed from `packages/config`, which is validated **once at startup**. An invalid config exits immediately, and the error names the keys but never echoes values.
- Environment-specific values come from the environment. The same image runs in every environment.
- **Secrets**: never committed. Locally, `pnpm env:init` generates random secrets into a git-ignored `.env` (mode 600). In clusters, External Secrets syncs AWS Secrets Manager into Kubernetes Secrets mounted as files and read through the `<KEY>_FILE` convention, so secrets don't appear in `env` dumps.
- **Least privilege**: the runtime DB account has DML only, and migrations use a separate DDL account. The integration tests check that the runtime account cannot run DDL. Redis requires auth. Every local port binds to `127.0.0.1`.

**Consequences.** Adding a config key means updating the schema, `.env.example` and the Compose or Kubernetes config together.
