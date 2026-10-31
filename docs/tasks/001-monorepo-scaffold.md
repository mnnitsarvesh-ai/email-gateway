# 001: Monorepo scaffold, lint boundaries and CI pipeline

Owner agent: devops-engineer
Depends on: none
Status: ready
Branch: task/001
Phase: 0

**Why devops-engineer owns this.** The task is build and CI tooling: workspace layout, Turborepo pipeline, TypeScript and ESLint config, and the CI workflow. devops-engineer owns CI and the build. No service or package code is written here, apart from a fixture package used to prove the toolchain works. backend-engineer owns the packages that land on top of this, from task 002 onwards.

## User story

Story: _to be written by product-owner_

As a developer agent on this repo, I want a strict, enforced monorepo skeleton with CI so that every later task builds on the same rules and cross-service imports are impossible to merge.

## Acceptance criteria

Decided defaults (Sarvesh, via architect recommendation): CI is GitHub Actions; pnpm is the latest 10.x and Turborepo the latest 2.x at implementation time.

AC-1 Given a fresh clone with Node 24 and pnpm, when `pnpm install --frozen-lockfile && pnpm turbo run build lint typecheck test` runs, then it exits 0, and an immediate second run exits 0 with every task reported as a cache hit (turbo output shows `FULL TURBO` and no task is executed uncached).
AC-2 Given a Node version outside `>=24 <25`, when `pnpm install` runs, then it exits non-zero with an engines error. `package.json` has `"engines": { "node": ">=24 <25" }`, `.npmrc` sets `engine-strict=true`, and `.node-version` contains `24`.
AC-3 Given the repo root, when `tsconfig.base.json` is inspected, then `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `verbatimModuleSyntax`, `target` `ES2024`, and `module`/`moduleResolution` `NodeNext` are all set; and a check (script or test) confirms every workspace `tsconfig*.json` extends it, directly or through another config that does.
AC-4 Given a fixture with an implicit `any` parameter, and another with an unchecked `undefined` index access, when `tsc` is run on each through the fixture test, then each exits non-zero with the expected TS error code (TS7006; TS2532 or TS18048). The bad fixtures are excluded from the normal `pnpm turbo run typecheck`, which exits 0.
AC-5 Given a fixture using an explicit `any`, and another using an object-literal type assertion (`{} as Foo`), when ESLint runs on each, then the first reports `@typescript-eslint/no-explicit-any` and the second `@typescript-eslint/consistent-type-assertions`, each at severity error.
AC-6 Given a fixture in `services/a` importing from `services/b`, once by package name and once by relative path (`../../services/b/src/x`), when ESLint runs, then both fail with the boundary rule id; a vitest test in `tooling/lint-fixtures/test/` asserts the exact rule id for each case.
AC-7 Given a fixture in `packages/x` importing from `services/*`, another importing a relative path that leaves its own workspace, and another in `test/e2e` importing from `services/*`, when ESLint runs, then each fails with the boundary or `no-restricted-imports` rule id; the vitest test asserts the exact rule id per case.
AC-8 Given a data-plane fixture under `services/ingest-like/` importing `@esg/db/control-plane`, another importing `@esg/config/control-plane`, and a fixture under `services/portal` importing either, when ESLint runs, then each fails with the `no-restricted-imports` rule id; the same imports in a fixture under `services/api/` pass. The allow-list is the single constant `CONTROL_PLANE_DB_CONSUMERS = ['services/api']`, defined in exactly one place in the ESLint config (hard rule 2).
AC-9 Given a fixture `package.json` where one service depends on another service, when the workspace guard (turbo `boundaries` or `tooling/workspace-guard`) runs, then it exits non-zero with output naming both workspaces; on the real workspace it exits 0 and is wired into `pnpm turbo run lint` or `typecheck` (so CI runs it).
AC-10 Given the normal `pnpm turbo run lint`, when it runs, then the deliberately bad fixtures are excluded and lint exits 0, while the lint-fixture vitest tests (AC-4 to AC-9) run under `pnpm turbo run test`. Negative control: if the boundary rule is removed from the ESLint config, the fixture test fails.
AC-11 Given `.github/workflows/ci.yml`, when parsed (YAML parse plus `actionlint` clean), then it defines jobs `verify` (frozen-lockfile install, `build lint typecheck test`), `secrets` (gitleaks with committed `.gitleaks.toml`, fails on any finding) and `terraform` (`terraform fmt -check -recursive infra/terraform`, path-filtered on `infra/**`); Node (24) and pnpm (the `packageManager` version, via corepack) are pinned; and the pnpm store and `.turbo` are cached.
AC-12 Given a temporary directory outside version control containing a generated fake secret (an AWS-access-key-shaped string that is not a gitleaks-allowlisted `EXAMPLE` value), when `gitleaks detect --no-git --source <dir> --config .gitleaks.toml` runs, then it exits non-zero; on the repo working tree it exits 0. The fake secret is generated at test time and never committed.
AC-13 Given `.github/workflows/ci.yml`, when searched, then it has no cloud credentials, no `aws-actions/configure-aws-credentials`, no OIDC role assumption (no `id-token: write`), no `secrets.*` reference other than `GITHUB_TOKEN`, no deploy step, no `git push`, no `terraform apply`/`destroy`, no `kubectl`, and no `aws` CLI call; workflow `permissions` is `contents: read` (hard rule 10).
AC-14 Given `.gitignore`, when `git check-ignore` is run on `.env`, `.env.local`, `x.pem`, `x.key`, `a.tfstate`, `a.tfstate.backup`, `.terraform/x`, `x.tfvars` and `test/e2e/.artifacts/x`, then each is ignored; and `x.tfvars.example` and `.env.example` are not ignored.
AC-15 Given the repo, when verified without reading `.env.example`, then (a) `git ls-files .env.example` lists it, (b) `git ls-files` lists no `.env`, `.env.local`, `*.pem`, `*.key` or `*.tfstate*` file, (c) the AC-12 gitleaks scan of the working tree, which includes `.env.example`, exits 0, and (d) with `DATABASE_URL` unset and no `.env` file in the working directory, `pnpm dbmate up` exits non-zero with an error naming `DATABASE_URL`, and does not attempt a connection to any default host.
AC-16 Given `turbo.json` and a no-op `test:e2e` script in the fixture workspace, when `pnpm turbo run build lint typecheck test` runs, then no `test:e2e` task executes; and `pnpm turbo run test:e2e --dry=json` shows the task with caching disabled (`cache: false` in `turbo.json`).
AC-17 Given `CLAUDE.md` "Commands", when compared with root `package.json` scripts, then every `pnpm`/`turbo` command listed resolves to an existing script or turbo task; `CLAUDE.md` is updated where any differs. Commands that name a not-yet-existing service (`--filter=ingest-service`) are exempt and listed as such in the task.
AC-18 Given `package.json` and the lockfile, when inspected, then `packageManager` is `pnpm@10.x.y` with an exact version, `turbo` is a root devDependency with an exact `2.x.y` version (no range), and `pnpm-lock.yaml` is committed.
AC-19 Given every `package.json` script and every file under `.github/`, `tooling/` and `scripts/`, when searched, then none invokes `terraform apply`/`destroy`, `kubectl`, the `aws` CLI or `git push` (hard rule 10); a grep check records the result.
AC-20 Given `CLAUDE.md` "Repo layout", when inspected, then it lists `tooling/` (including `lint-fixtures` and `workspace-guard` if present) and `test/e2e`.

### Open questions for Sarvesh

- Resolved: NEEDS SARVESH #1 (GitHub Actions) and #3 (latest pnpm 10.x, Turborepo 2.x), per Sarvesh's instruction. Exact versions are asserted only as pinned (AC-18), not by number.
- NEEDS SARVESH #2 (agents cannot read `.env.example`) no longer blocks verification: AC-15 is checkable by `git ls-files`, gitleaks and the dbmate check without reading the file. It can stay open for later tasks that need agents to read the file.
- For architect: AC-16 assumes the fixture workspace carries a no-op `test:e2e` script, because turbo fails on a task no workspace defines. Confirm or propose an alternative.

## Out of scope

- Any service under `services/`. Any real package code beyond the fixtures. Those start in 002.
- Dockerfiles and image scanning. They arrive with the first deployable service in Phase 1.
- The Terraform CI job's contents. Add the job stub here; task 010 fills it in.
- Helm, ArgoCD, release pipelines and deploy jobs.

## Design notes

**How to work.** Implement in a git worktree on branch `task/001`. Commit locally; never push, never merge (CLAUDE.md hard rule 10 and workflow step 6). The decisions below are final for this task. The implementer may deviate only when a decision does not work with the pinned versions, and must state the deviation and the reason in the Implementation summary.

**Root files**
- `package.json`: `"private": true`. `"packageManager": "pnpm@<latest 10.x at implementation time, exact version>"`; `turbo` as an exact-pinned devDependency at the latest 2.x (NEEDS SARVESH #3 default). `"engines": { "node": ">=24 <25" }`. Scripts `build`, `lint`, `typecheck`, `test` and `test:e2e` delegate to `turbo run …`. Script `dbmate` runs a pinned dbmate (the npm `dbmate` package) with `--migrations-dir db/migrations`. It reads `DATABASE_URL` from the environment and has no default.
- `.node-version` set to `24`.
- `pnpm-workspace.yaml` with globs `services/*`, `packages/*`, `db`, `test/e2e` and `tooling/*`. `db` and `test/e2e` become workspace packages in tasks 005 and 012, so their globs exist from day one.
- `turbo.json`:
  - `build` depends on `^build`, outputs `dist/**`.
  - `typecheck` depends on `^build`.
  - `lint` has no dependencies.
  - `test` depends on `^build`.
  - `test:e2e` has `cache: false`, is **not** part of the default `pnpm turbo run build lint typecheck test`, and runs only on request or in a separate CI job that needs `deploy/local`.
- `tsconfig.base.json`: `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `noImplicitOverride`, `module`/`moduleResolution` `NodeNext`, `target` `ES2024`, `verbatimModuleSyntax`, `declaration`, `sourceMap`. Each package extends it.
- **Vitest: per-workspace configs, run by Turborepo.** Each workspace with tests has its own `vitest.config.ts` and a `test` script `vitest run`; Turborepo orchestrates and caches them. Do **not** create `vitest.workspace.ts` (deprecated in Vitest 3.2 and removed in 4). A root `vitest.config.ts` with `test.projects: ['packages/*', 'services/*', 'tooling/*']` is optional, for IDE and ad-hoc runs only; CI does not use it.
- `.gitignore` covers `node_modules`, `dist`, `.turbo`, `coverage`, `.env`, `.env.local`, `*.pem`, `*.key`, `**/*.tfstate*`, `**/.terraform/`, `*.tfvars` (but not `*.tfvars.example`), and `test/e2e/.artifacts/`.
- `.env.example` at the root with placeholder keys only. Create it with the Write tool. Nobody (implementer, qa-engineer, code-reviewer) reads it back with Read or with a shell command (`cat`, `grep`, `head`, editors, and so on): the deny rule stands and must not be worked around (NEEDS SARVESH #2). Verification is `gitleaks` over the working tree, which covers the file without an agent reading it.

**ESLint (flat config)**
- The config lives in a workspace package `tooling/eslint-config` (`@esg/eslint-config`), written as plain `index.mjs` with `// @ts-check`. It exports a factory `createConfig({ root })` that returns the flat-config array. Root `eslint.config.mjs` is `export default createConfig({ root: import.meta.dirname })` and adds `ignores: ['tooling/lint-fixtures/fixtures/**', '**/dist/**', '**/.turbo/**', '**/coverage/**']`. The root depends on `@esg/eslint-config` as `workspace:*`. The factory exists so the lint-fixture test can apply the exact same rules to a fixture tree.
- Typed linting via `parserOptions.projectService: true`.
- `typescript-eslint` `strictTypeChecked`. Make `no-explicit-any` an error, and make `consistent-type-assertions` an error with `assertionStyle: 'as'` and `objectLiteralTypeAssertions: 'never'`. Unexplained `as` casts can't be fully detected by lint; code-reviewer checks those.
- **Cross-service import boundary (hard rule 8): use core `no-restricted-imports`, not `eslint-plugin-boundaries`.** Reason: it is built into ESLint, needs no import resolver (`eslint-plugin-boundaries` must resolve each specifier to a file, which needs `eslint-import-resolver-typescript` and installed workspace links, and silently skips unresolvable imports, so a bad import can pass). The element types are:
  - `service`: `services/*`
  - `package`: `packages/*`
  - `migrations`: `db`
  - `e2e`: `test/e2e`
  - `tooling`: `tooling/*`

  The allowed imports are:
  - `service` → `package` only.
  - `package` → `package` only.
  - `e2e` → `package` only.
  - Nothing → `service`.

  Also block relative imports that leave the current workspace (`../../services/…`, `../../packages/…`): workspaces must use the package name (`@esg/<name>`).

  How to build it in `createConfig({ root })`:
  - At config load, read `<root>/services/*/package.json` and collect the service package names. For files matching `services/**`, `packages/**`, `db/**` and `test/e2e/**`, add `no-restricted-imports` `paths` entries for each service name and `patterns` entries `<name>/*`, so a service is unimportable by package name (the importing service's own name is excluded from its own block). New services are picked up automatically; there is no hand-kept list.
  - Relative escapes, for the same file globs: a `patterns` entry using the `regex` option (ESLint 9) with the regular expression `^(\.\./)+(.*/)?(services|packages|tooling|db|test/e2e)/` and a message telling the author to import `@esg/<name>`. Note the trade-off in a comment: a workspace may not name an internal folder `services/` or `packages/` and reach it with `../`.
  - All boundary messages start with `[boundary]` so the fixture test can assert rule id `no-restricted-imports` plus the message prefix.
  - ESLint merges `no-restricted-imports` per matching config object by replacement, not union. Build **one** `no-restricted-imports` entry per file group that already contains the boundary, relative-escape and control-plane restrictions, rather than several overlapping objects.
- **Writer-only data plane (hard rule 2).** Add a `no-restricted-imports` entry that forbids `@esg/db/control-plane` and `@esg/config/control-plane` everywhere except `services/api/**`. That covers all data-plane services and `services/portal`, which must talk only to `api`. The subpaths themselves are delivered in tasks 006 and 007; the rule is set up now so it's in place before any service exists. The allow-list lives in one constant, `CONTROL_PLANE_DB_CONSUMERS = ['services/api']`, so the exceptions are visible in review.
  Implementation: the control-plane restriction applies to `services/**` with `ignores` built by appending `/**` to each entry of `CONTROL_PLANE_DB_CONSUMERS`, folded into the single per-group `no-restricted-imports` entry described above. `services/api/**` gets the boundary restrictions without the control-plane ones. Messages start with `[control-plane]`.
- **Second enforcement layer: `tooling/workspace-guard/` (`@esg/workspace-guard`), not Turborepo `boundaries`.** Reason: `turbo boundaries` is still experimental in 2.x, needs per-package `turbo.json` tags, and its output and exit behaviour are not a stable contract to assert against. The guard is a small TypeScript module plus CLI, run directly by Node 24 type stripping (no build step; use erasable syntax only and set `erasableSyntaxOnly` in its tsconfig).
  - Input: a root directory (defaults to the repo root). It reads `pnpm-workspace.yaml` globs, loads every workspace `package.json`, and classifies each by path (`service`, `package`, `migrations`, `e2e`, `tooling`).
  - Rule: no workspace may list a `service` in `dependencies`, `devDependencies`, `peerDependencies` or `optionalDependencies`. `package` may depend only on `package`. On violation, print `<dependent> (<path>) depends on service <dependency> (<path>)` for each, and exit 1.
  - Wiring: the guard's vitest suite (a) runs it against `tooling/workspace-guard/fixtures/bad-repo/` and asserts exit 1 and both workspace names in the output (AC-9), and (b) runs it against the real repo root and asserts exit 0. So `pnpm turbo run test` always checks the real repo.
  - Caching: add a package-specific task `@esg/workspace-guard#test` in `turbo.json` whose `inputs` include `$TURBO_DEFAULT$`, `$TURBO_ROOT$/pnpm-workspace.yaml` and `$TURBO_ROOT$/{services,packages,tooling}/*/package.json`, `$TURBO_ROOT$/db/package.json`, `$TURBO_ROOT$/test/e2e/package.json`. Without these, a new bad dependency in another workspace would be served from cache as a pass.
- **Proof the rules work.** `tooling/lint-fixtures/` (`@esg/lint-fixtures`) holds a deliberately bad mini-repo under `fixtures/` (`fixtures/services/a`, `fixtures/services/b`, `fixtures/services/ingest-like`, `fixtures/services/api`, `fixtures/services/portal`, `fixtures/packages/x`, each with a minimal `package.json`, plus a `fixtures/tsconfig.json` for typed linting). A vitest test in `tooling/lint-fixtures/test/` runs `new ESLint({ cwd: fixturesRoot, overrideConfigFile: true, overrideConfig: createConfig({ root: fixturesRoot }) })` and asserts, for each bad file, the rule id and message prefix; and that the `services/api` control-plane import produces no `no-restricted-imports` message. Strict-TS fixtures (AC-4) live in `fixtures/ts-strict/` with their own tsconfig extending the base; the test runs `tsc -p fixtures/ts-strict --noEmit` via `execFile` and asserts the TS error codes. The package's own `lint` and `typecheck` scripts exclude `fixtures/`, so the normal run stays green.

**Package naming.** All workspaces use the npm scope `@esg/` (`@esg/config`, `@esg/db`, and so on). Packages publish ESM only, with an `exports` map. Deep imports outside the `exports` map are blocked by Node resolution, and that is part of how the boundaries are enforced.

**CI** (`.github/workflows/ci.yml`, GitHub Actions per the NEEDS SARVESH #1 default)
- Pin third-party actions to a full commit SHA with the version in a trailing comment.
- Job `verify`: Node from `.node-version` via `actions/setup-node`, pnpm via `pnpm/action-setup` reading `packageManager` (not corepack, which is no longer bundled from Node 25 and is optional on 24), `pnpm install --frozen-lockfile`, `pnpm turbo run build lint typecheck test`.
- Job `secrets`: gitleaks with a committed `.gitleaks.toml`. Fail on any finding.
- Job `terraform` (stub): `terraform fmt -check -recursive infra/terraform`, path-filtered on `infra/**`. Task 010 extends it.
- No cloud credentials, no deploy steps, no `git push` from CI, and no OIDC role assumption in this task.
- Cache the pnpm store and `.turbo`.

**Commands.** Update the "Commands" section of `CLAUDE.md` if anything differs from the target commands, per the definition of done.

## Hard rules at risk

- **8 (no cross-service imports).** The boundary rule must actually fail. The lint-fixture tests prove it, so a misconfigured glob that silently passes is caught.
- **2 (writer-only data plane).** A lint rule blocks the control-plane DB entry point outside `services/api`. Task 007 adds runtime and config layers on top.
- **9 (no secrets).** `.gitignore` coverage, the gitleaks job, and a placeholder-only `.env.example`.
- **10 (no push or apply).** CI must not have cloud credentials or deploy jobs.

## NEEDS SARVESH

1. **CI platform.** There is no git remote yet. Options: GitHub Actions, GitLab CI or Bitbucket Pipelines. *Recommendation:* GitHub Actions. It has the widest tooling support, gitleaks, terraform and helm actions, and OIDC to AWS later.
   **Proceeding with default — pending Sarvesh confirmation.** Sarvesh said to proceed with the recommended defaults. If he later picks another platform, only `.github/workflows/ci.yml` is rewritten; nothing else in this task depends on it.
2. **Agents can't read `.env.example`.** `.claude/settings.json` denies `Read(**/.env.*)`, which also matches `.env.example`. That file is committed and contains placeholders only. *Options:* add an allow rule for `Read(**/.env.example)`, or rename the file to `env.example`. Only Sarvesh can change the settings. **Still open.** Until it is resolved:
   - No agent works around the deny rule. The implementer creates `.env.example` with the Write tool only. Nobody reads it back with Read or with any shell command (`cat`, `grep`, `head`, `sed`, editors, and so on).
   - Verification of "placeholders only" is `gitleaks` over the working tree (AC-12 and the `secrets` job), which scans the file without an agent reading it.
   - This item does not block implementation, so the task is marked `ready`; it only limits how AC-15 is verified.
3. **Pinned versions.** *Recommendation:* the latest pnpm 10.x and Turborepo 2.x at implementation time, recorded as exact versions in `package.json` and upgraded through Renovate or Dependabot later.
   **Proceeding with default — pending Sarvesh confirmation.** The implementer records the exact versions chosen in the Implementation summary.

## Implementation summary

Implemented by devops-engineer on branch `task/001` (local commits only).

**Versions chosen (exact pins).** pnpm 10.34.9 (`packageManager`; pnpm 12 exists but the task requires 10.x), turbo 2.11.10, dbmate 2.37.0, Node 24 (verified with 24.22.2), eslint 10.14.0, @eslint/js 10.0.1, typescript-eslint 8.72.1, typescript 6.0.3, vitest 4.1.12, @types/node 24.19.2, yaml 2.8.1. Dev-tool versions are single-sourced in the `catalog:` block of `pnpm-workspace.yaml`. TypeScript is 6.0.3, not 7.x, because typescript-eslint 8.72.1 peers on `typescript <6.1.0`.

**Files.**
- Root: `package.json`, `.npmrc`, `.node-version`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `turbo.json`, `tsconfig.base.json`, `.gitignore`, `.gitleaks.toml`, `.env.example` (Write tool only, never read back), `eslint.config.mjs`, `db/migrations/.gitkeep`, `.github/workflows/ci.yml`.
- `tooling/eslint-config` (`@esg/eslint-config`): `createConfig({ root })`, `CONTROL_PLANE_DB_CONSUMERS` (single definition), `index.d.mts`.
- `tooling/workspace-guard` (`@esg/workspace-guard`): `src/guard.ts`, `src/cli.ts` (Node 24 type stripping), `fixtures/bad-repo`, vitest suite. Its `lint` script also runs the guard on the real repo.
- `tooling/lint-fixtures` (`@esg/lint-fixtures`): bad mini-repo in `fixtures/`, `src/index.ts` (fixture package so `build` exists), no-op `test:e2e` script, vitest tests for AC-4..AC-8 and AC-10 negative control.
- `tooling/repo-checks` (`@esg/repo-checks`, added beyond the design notes): vitest tests for AC-2, 3, 11-20.
- `CLAUDE.md`: "Repo layout" lists `tooling/` (+ its four workspaces) and `test/e2e/`; "Commands" updated.

**Deviations from design notes.**
1. Added the `tooling/repo-checks` workspace to host repo-level AC tests (AC-2/3/11-20). Reason: they need a home that runs under `pnpm turbo run test`. It has a package-specific `#test` task with explicit `inputs` so changes to CI, CLAUDE.md, .gitignore and so on invalidate the cache.
2. `secrets` job runs the pinned gitleaks Docker image (`ghcr.io/gitleaks/gitleaks:v8.23.1`) instead of `gitleaks/gitleaks-action`. Reason: the action needs a licence secret for organisations, which would violate AC-13 (no `secrets.*` other than `GITHUB_TOKEN`).
3. `terraform` job path filter is a step-level `git diff` check on `infra/` (job-level filtering is not available with workflow `paths`, which would also skip the other jobs).
4. `.gitleaks.toml` allowlists only the gitignored `node_modules`, `.turbo`, `dist` and `coverage` directories, so a `--no-git` working-tree scan stays meaningful and fast. Tracked files have no allowlist.
5. Control-plane exclusion is built as one config object per service directory (api gets no control-plane restriction) plus a base `services/**` group, rather than `ignores` with `/**` appended to the constant. The constant is still the only list and is consumed as `services/<dir>` membership.
6. `tooling/eslint-config/index.d.mts` is hand-written so typed test code can import the `.mjs` factory.
7. The relative-escape regex follows the design note exactly. Known limitation (as the note says): `../../b/src/x` between sibling services is only caught when the path contains a `services|packages|tooling|db|test/e2e` segment.
8. Root `lint` and the other root scripts delegate to `turbo run`; each workspace runs `eslint .` itself, which finds the root `eslint.config.mjs`.

**How to run.** Needs Node 24 and pnpm 10.34.9 (pnpm auto-selects it from `packageManager`).
```sh
pnpm install --frozen-lockfile
pnpm turbo run build lint typecheck test
pnpm turbo run test --filter=@esg/lint-fixtures     # boundary / strictness fixtures
pnpm test:e2e                                       # no-op placeholder, uncached
```

**Local results.** `pnpm turbo run build lint typecheck test`: 12 tasks successful. Tests: workspace-guard 2 passed, lint-fixtures 16 passed, repo-checks 26 passed and 3 skipped. A second run reports 12/12 cached, `FULL TURBO`. AC-2: `pnpm install` under Node 22 fails with `ERR_PNPM_UNSUPPORTED_ENGINE` (expected `>=24 <25`). AC-15d: `pnpm dbmate up` without `DATABASE_URL` exits non-zero naming `DATABASE_URL` (tested).

**ACs that need CI to verify (binary not installed locally, nothing installed system-wide).**
- AC-11 `actionlint` clean: test skips locally; YAML structure, SHA pins, jobs and caching are asserted locally.
- AC-12 gitleaks fake-secret detection and clean working tree (also covers `.env.example` placeholders-only, AC-15c): both tests skip locally when `gitleaks` is missing.
- The `terraform fmt` step itself (AC-11 `terraform` job), since `terraform` is not installed.
- Action SHAs and the `gitleaks:v8.23.1` and `terraform_version: 1.9.8` pins were chosen from `git ls-remote` and memory, and have not been run on GitHub.

**AC-17 exemption.** `pnpm turbo run test --filter=ingest-service` names a not-yet-existing service and is exempt from the command-resolution test.

**AC-19 grep result.** No script, `.github/`, `tooling/` or `scripts/` file invokes the forbidden commands. The only files that name them are the detection test sources in `tooling/repo-checks/test/`, which are excluded from their own scan.

## QA report

[docs/qa/001-report.md](../qa/001-report.md): PASS WITH ISSUES (1 high: sibling-service relative import not blocked; AC-11/12/15c partly CI-only).
