# QA report: 001 (monorepo scaffold, lint boundaries, CI)
Verdict: PASS WITH ISSUES (re-tested after round 1, see the end of this report; issue 1 below is closed)

Environment: Node 24.22.2, pnpm 10.34.9, turbo 2.11.10. `gitleaks`, `actionlint` and `terraform` are not installed locally, so ACs that need them are marked CI only, not PASS.

Clean-state run: `node_modules`, `.turbo` and `dist` removed, then `pnpm install --frozen-lockfile && pnpm turbo run build lint typecheck test`. Turbo shares its cache across git worktrees ("using shared worktree cache"), so a plain re-run is a false cache hit. The cold run used an empty `TURBO_CACHE_DIR`: exit 0, 12 successful, 0 cached. The second run: exit 0, 12/12 cached, `FULL TURBO`.

| AC | Test | Result | Evidence |
|----|------|--------|----------|
| AC-1 | No automated test (running turbo inside turbo test is circular). Manual run. | PASS | Cold run 12 executed, rc 0; second run 12/12 cached, `FULL TURBO`, rc 0 |
| AC-2 | `repo.test.ts` "AC-2: pnpm install fails with an engines error..." (new: runs real root package.json and .npmrc through pnpm with node-version 22, 23, 25) and "AC-2: pins node >=24 <25 ..." | PASS | Also ran real `pnpm install --frozen-lockfile` under nvm Node 22.22.1: `ERR_PNPM_UNSUPPORTED_ENGINE`, expected `>=24 <25`. Mutations (engine-strict=false, range `>=24`, .node-version 22) are caught |
| AC-3 | `repo.test.ts` "AC-3: base has the strict options", "AC-3: every workspace tsconfig*.json ... extends the base" | PASS | Mutations (target ES2022) caught |
| AC-4 | `lint-fixtures.test.ts` "AC-4: implicit any fails with TS7006", "AC-4: unchecked index access fails with TS2532 or TS18048" | PASS | Temporary `a[0].toFixed()` in a service gave TS2532 from tsc. Mutation: base `noUncheckedIndexedAccess=false` fails the test. Normal typecheck is green |
| AC-5 | `lint-fixtures.test.ts` "AC-5: explicit any ...", "AC-5: object-literal type assertion ..." | PASS | Temporary `any` in a service gave `no-explicit-any`. Mutations (rule off, `objectLiteralTypeAssertions: allow`) are caught |
| AC-6 | `lint-fixtures.test.ts` "AC-6: %s fails the boundary rule" (by name, by relative). Added an `it.fails` gap test, see issue 1 | PASS (with gap) | Temporary services a/b: `@esg/b`, `@esg/b/src/x` and `../../services/b/..` all fail with `no-restricted-imports` `[boundary]`. `../../b/src/x.js` is NOT caught (issue 1) |
| AC-7 | `lint-fixtures.test.ts` "AC-7: %s fails the boundary rule" (x3) | PASS | Temporary `packages/x` and `test/e2e` importing a service were both flagged |
| AC-8 | `lint-fixtures.test.ts` "AC-8: ... is blocked" (x4) and "AC-8: api/... passes" (x2) | PASS | Temporary portal import of `@esg/db/control-plane` is flagged `[control-plane]`; api passes. Mutations (empty constant, portal added to the constant) are caught. Constant defined once, at `tooling/eslint-config/index.mjs:16` |
| AC-9 | `guard.test.ts` "fails on the bad fixture ... (AC-9)", "passes on the real repo root (AC-9)"; new `repo.test.ts` "AC-9: the workspace guard is wired into the root-run lint" | PASS | Temporary service-depends-on-service (dependencies and optionalDependencies), package-depends-on-service and package-depends-on-tooling each exit 1 naming both workspaces. `pnpm turbo run lint` failed with the violation printed, and the turbo cache was correctly invalidated by the package.json change. Mutation (ignore services) is caught |
| AC-10 | `lint-fixtures.test.ts` "AC-10: negative control ..."; new `repo.test.ts` "AC-10: bad fixtures are excluded from the normal lint and typecheck" | PASS | Dropping blocked services or the relative regex made 3 and 2 fixture tests fail. Normal lint exit 0 |
| AC-11 | `repo.test.ts` "AC-11: defines verify, secrets, terraform ..." (strengthened to structural checks), "AC-11: pins third-party actions ...", "AC-11: workflow is actionlint clean" | PARTIAL: structure PASS; actionlint and `terraform fmt` unverified locally, CI only | Strengthening: the old test passed with `cache: pnpm` removed and with `continue-on-error: true` on gitleaks. Both now fail |
| AC-12 | `repo.test.ts` "AC-12: detects a generated fake secret ...", "AC-12: the working tree is clean" | unverified locally, CI only | Both tests skip without the `gitleaks` binary |
| AC-13 | `repo.test.ts` "AC-13: has no credentials, deploy, or forbidden commands" | PASS | Mutations (`id-token: write`, `secrets.FOO`, `git push`, `aws s3`, `permissions: write`) are caught |
| AC-14 | `repo.test.ts` "AC-14: %s is ignored" (x9), "AC-14: %s is not ignored" (x2) | PASS | Mutation (drop `*.pem`) caught |
| AC-15 | `repo.test.ts` "AC-15a/b: ...", "AC-15d: dbmate (direct) ...", "AC-15d: pnpm dbmate up ..."; (c) is the AC-12 gitleaks working-tree test | PARTIAL: a, b, d PASS; c unverified locally, CI only | Manual `env -u DATABASE_URL pnpm dbmate up` exits non-zero: "invalid url, have you set your --url flag or DATABASE_URL environment variable?". `.env.example` was not read |
| AC-16 | `repo.test.ts` "AC-16: default pipeline has no test:e2e task", "AC-16: test:e2e has cache disabled" | PASS | Mutation (`cache: true`) caught |
| AC-17 | `repo.test.ts` "AC-17: every pnpm/turbo command in Commands resolves" | PASS | Mutation (`pnpm test:e2f`) caught. `--filter=ingest-service` is exempt, as the task says |
| AC-18 | `repo.test.ts` "AC-18: exact pnpm 10.x.y and turbo 2.x.y, lockfile present" | PASS | Mutations (`^2.11.10`, `pnpm@11.0.0`) caught |
| AC-19 | `repo.test.ts` "AC-19: no script or tooling file invokes ..." | PASS | Pattern coverage confirmed by the CI mutations (`git push`, `aws s3`) |
| AC-20 | `repo.test.ts` "AC-20: Repo layout lists tooling/ and test/e2e" | PASS | Mutation (remove the tooling line) caught |

Test suite after this QA pass: workspace-guard 2 passed; lint-fixtures 16 passed and 1 expected fail (the gap test); repo-checks 29 passed and 3 skipped (actionlint, gitleaks x2).

## Test changes made by QA
- Every test title now carries its AC id. Repo-checks tests that previously carried it only in the `describe` title were renamed.
- AC-2: added a behavioural engines test.
- AC-11: strengthened. It now checks the setup-node `cache: pnpm` and `node-version-file`, the `.turbo` cache path, that gitleaks cannot be neutered (`continue-on-error`, `--exit-code 0`, `|| true`), and that the terraform fmt step is conditional on an infra/ diff.
- AC-9 and AC-10: added wiring checks (guard in the `lint` script and its turbo inputs; fixtures excluded from lint and typecheck).
- AC-6/7/8: also assert severity 2 and the right message prefix.
- Added fixture `tooling/lint-fixtures/fixtures/services/a/src/by-sibling-relative.ts` and an `it.fails` test for issue 1.

## Failure and chaos scenarios
Not in scope (no runtime services). Toolchain break-attempts, all reverted (`git status` clean before the test edits):
- cross-service import by name, deep name and relative, in `services/`, `packages/` and `test/e2e`: caught, except the sibling relative path (issue 1)
- temporary explicit `any` and unchecked index: caught
- service-depends-on-service package.json: caught
- control-plane import from `services/portal`: caught; from `services/api`: allowed
- 8 ESLint, guard and tsconfig mutations and about 20 repo-level mutations: each caught by a test

## Zero-loss check
Not applicable.

## Load results
Not applicable.

## Issues found
1. **High. Sibling-service relative import is not blocked (hard rule 8).** Repro: create `services/a/src/i.ts` containing `import { x } from '../../b/src/x.js';` with `services/b/src/x.ts` present, then run `eslint services`. There is no error. The relative-escape regex `^(\.\./)+(.*/)?(services|packages|tooling|db|test/e2e)/` needs one of those directory names in the path, and a real sibling path has none. `workspace-guard` only reads package.json, so it does not catch it either, and TypeScript NodeNext resolves the path happily. The AC-6 fixture passes only because it uses `../../../services/b/...`, which is how a path would look from the repo root and not from a service. The known limitation is acknowledged in Implementation summary deviation 7 and in `tooling/eslint-config/index.mjs:23-27`, but it leaves the main bypass open. Suggested fix, for the implementer: block any relative import that leaves the workspace. Either use `eslint-plugin-import`-style resolution, or a small local rule that resolves the specifier against the importing file's workspace root (`services/<dir>`). Documented by `it.fails` in `tooling/lint-fixtures/test/lint-fixtures.test.ts` (AC-6 gap); remove `.fails` when fixed.
2. **Low. Turbo cache is shared across git worktrees.** A "clean" cold run in this worktree reports 12/12 cache hits from the main checkout's cache. AC-1's cold-run check therefore needs an isolated cache (`TURBO_CACHE_DIR`) or `--force`. This is not a product bug, but anyone verifying AC-1 locally should know.
3. **Low. AC-1 has no automated test.** It is verified manually (above). Running turbo from inside a turbo task would be circular; CI's `verify` job is the permanent check.
4. **Low. CI is untested on GitHub.** Action SHAs, `ghcr.io/gitleaks/gitleaks:v8.23.1` and `terraform_version: 1.9.8` were chosen without running them, as the implementation summary says. The first CI run must be watched.
5. **Info. The sibling gap also applies to `services/api`, `services/portal` and `ingest-like`.** Same cause as issue 1.

## CI-only (unverified locally)
- AC-11: actionlint clean; the `terraform fmt` step.
- AC-12: gitleaks detects a fake secret; the working tree is clean.
- AC-15c: gitleaks over the working tree, which includes `.env.example`.

---

# Round 1 re-test (commits 869ef83..e24e7fd)
Verdict: PASS WITH ISSUES. All 20 ACs are met locally, except those marked CI only. The sibling-import gap (issue 1) is closed. No high-severity issue remains. Four medium/low gaps remain; each is recorded as an `it.fails` test, so it turns red when fixed.

Cold run (empty `TURBO_CACHE_DIR`, `node_modules`/`.turbo`/`dist` removed, Node 24.22.2): `pnpm install --frozen-lockfile && pnpm turbo run build lint typecheck test` gave 12 successful, 0 cached. Warm run: 12/12 cached, `FULL TURBO`. Tests: workspace-guard 4, lint-fixtures 32, repo-checks 60 passed (3 skipped: gitleaks x2, actionlint, CI only). After my additions: lint-fixtures 32 passed + 2 expected fail, repo-checks 60 passed + 12 expected fail.

## Earlier break attempts, re-run (temporary workspaces, all reverted)
Sibling `../../b/src/x.js`, `import()` literal, `require('@esg/b')`, `require.resolve`, `createRequire(...)(...)`, `export * from` (relative and by name), `export {..} from`, `import b = require(...)` (relative and by name), `typeof import()`, `.tsx`, `.jsx`, `.mjs`, `.mts`, side-effect `import '../..'`: all caught by `esg/import-boundaries` or `no-restricted-imports`. Control-plane via `@esg/db/dist/control-plane/...`, `@esg/config/control-plane/x`, `import('@esg/db/control-plane')`: caught. Inline disables (`/* eslint-disable */`, `-next-line` naming both rules, `-line`): do not hide anything. Temporary `any`, unchecked index, service-to-service package.json: all still caught.

## Attempts to defeat `esg/import-boundaries`
| Attempt | Result |
|---|---|
| `import(\`../../b/src/x.js\`)` (template, no expressions) | caught |
| `import(\`../../b/src/${'x'}.js\`)`, `import(variable)`, `import('../../b/' + 'src/x.js')`, `import('@esg/db/' + 'control-plane')` | NOT caught (issue 2) |
| `const r = createRequire(import.meta.url); r('../../b/src/x.js')` | NOT caught (issue 3) |
| Symlink `services/a/src/link -> ../../b/src`, then `import './link/x.js'` | NOT caught (issue 4) |
| `.cjs` file with ESM syntax | parse error, so not a bypass |

## workspace-guard
Fixtures `bad-repo`, `alias-repo` (`npm:`, `workspace:<name>@`, `link:`, `file:`) and `root-repo` each exit 1 naming both workspaces. My own temporary repo: `workspace:../b`, `file:../b`, `link:./../b`, `npm:@x/b`, range `*`, root devDependency, package-to-service by `link:`: all exit 1. Not caught: `pnpm.overrides` / `overrides` entries pointing at a service by `link:` or alias, in a workspace or root package.json (issue 5).

## dbmate wrapper (fake URLs only; the only network attempt was a `.invalid` host)
Allowed: localhost, 127.0.0.1, `[::1]`, `mysql`, `LOCALHOST`. Refused: `db.example.com`, `10.0.0.5`, `localhost.evil.com`, `localhost@evil.com`, `0.0.0.0`, `2130706433`, `127.1`, invalid URL, unset URL. `--url`, `--url=`, `-u`, `-e` refused; `--env-file` fails closed (Node errors out). Bypasses:
- `-url`, `-url=...`, `-env`, `-env-file=...` (single dash) pass the wrapper. Confirmed that dbmate honours them: `dbmate -url mysql://u:p@qa-fake-host.invalid:1/db status` with a localhost DATABASE_URL set tried to resolve `qa-fake-host.invalid` (issue 6).
- `?host=` query parameter in DATABASE_URL passes the host check (issue 6).
- Any single-label host passes, including real internal names such as `prod-rds-cluster-abc`; this is by design but worth knowing.
- `scripts/dbmate.mjs:3,27` and the round 1 table say `.env.local` is loaded; the wrapper does not load it. Documentation mismatch only (issue 7).

## .gitignore
Ignored as required: `.env`, `.env.*` and nested ones, `.envrc`, pem, key, p12, pfx, jks, `id_rsa*`, kubeconfig, tfstate variants, `.terraform/`, tfvars, tfvars.json, `*.tfplan`, `test/e2e/.artifacts/`. Not ignored: `.env.example`, `x.tfvars.example`. Not ignored but arguably should be (issue 8): bare `tfplan` (the round 1 table says it was added; only `*.tfplan` is), `id_ed25519`, `.aws/credentials`, `.kube/config`, `.pgpass`, `.netrc`, `*.keystore`.

## Issues found in round 1 re-test
2. **Medium. Non-literal dynamic imports are not checked** (hard rule 8, and 2). Repro: `const p='../../b/src/x.js'; export const q = import(p);` in `services/a/src`. No error. Also `import(\`../../b/${n}\`)`, string concatenation, and `import('@esg/db/' + 'control-plane')`. Suggested fix: forbid non-literal `import()` / `require()` arguments with `no-restricted-syntax` in governed workspaces. Rule: `tooling/eslint-config/import-boundaries.mjs:41-47` (`literal()` returns undefined). Test: RT1-1.
3. **Low. Aliased `createRequire` result.** `const r = createRequire(import.meta.url); r('../../b/src/x.js')` is not flagged; only the direct `createRequire(...)(...)` form is (`import-boundaries.mjs:52-66`). Test: RT1-2.
4. **Low. Symlinks.** `workspaceOf` and the escape check work on path strings, not realpaths (`import-boundaries.mjs:21-29,95-98`), so a symlink inside a workspace that points at another workspace is invisible. Unlikely in practice; git can track symlinks, so a code-review item.
5. **Low. workspace-guard ignores `overrides` / `pnpm.overrides`.** Repro: service `a` with `"pnpm":{"overrides":{"foo":"link:../b"}}` gives exit 0. `tooling/workspace-guard/src/guard.ts:48-60` reads only the four dependency fields.
6. **Medium. dbmate wrapper bypasses.** Repro: `DATABASE_URL=mysql://u:p@localhost/d node scripts/dbmate.mjs --check-only -url mysql://u@prod.invalid/d` exits 0 (and the real `pnpm dbmate -url ...` passes through to dbmate, which uses it). Same for `-env`, `-env-file=` and `?host=` in the URL. Defeats the "local only" guard at `scripts/dbmate.mjs:10,18-21`. Fix: also reject single-dash forms (normalise leading dashes and case before comparing), reject any query parameter named `host`/`socket`, and consider an allow-list of dbmate commands and flags. Tests: RT1-3, RT1-4.
7. **Info. `.env.local` is documented but never loaded** by `scripts/dbmate.mjs:3,27`.
8. **Low. `.gitignore` gaps** listed above (gitleaks is the backstop). Test: RT1-5.

## Test changes in this round
Added fixtures `fixtures/services/a/src/dynamic-nonliteral.ts` and `create-require-alias.ts`; `it.fails` tests RT1-1 to RT1-5 (cannot be fixed by QA; they are red-when-fixed markers). The earlier AC-6 sibling `it.fails` is gone; the implementer turned it into a normal passing test.

## CI only (unchanged)
AC-11 actionlint and `terraform fmt`; AC-12 gitleaks (both tests); AC-15c. The new gitleaks image digest pin, `:ro` mount and `persist-credentials: false` have not run on GitHub.
