# ADR-0001: pnpm workspaces + Turborepo monorepo

**Status:** Accepted

**Context.** There are eight deployables and seven shared libraries. Event contracts, configuration schemas and domain types must stay in lockstep across all of them. Separate repositories would need versioned package publishing for every contract change.

**Decision.** Use a single repository with pnpm workspaces (`apps/*`, `packages/*`, `tests`) and Turborepo for task orchestration and caching. Shared code lives only in `packages/*`, and apps never import each other (enforced by ESLint). pnpm's `minimumReleaseAge` refuses dependencies published less than 7 days ago.

**Alternatives.** Nx gives more features but more framework to learn and maintain. npm/yarn workspaces have weaker isolation; pnpm's strict `node_modules` catches undeclared dependencies.

**Consequences.** Atomic changes across contracts and consumers. CI builds only what changed (via the Turborepo cache). Docker images are produced with `pnpm deploy`, so each image contains only its app's production dependency closure.
