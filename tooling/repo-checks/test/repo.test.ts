import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { FORBIDDEN, cleanDbEnv, git, read, readJson, repoRoot, rootFiles, walk, which } from './helpers.ts';

interface PkgJson {
  scripts?: Record<string, string>;
  engines?: Record<string, string>;
  devDependencies?: Record<string, string>;
  packageManager?: string;
}

interface WfStep {
  uses?: string;
  run?: string;
  if?: string;
  with?: Record<string, unknown>;
  'continue-on-error'?: unknown;
}

const rootPkg = readJson('package.json') as PkgJson;

function workspaceDirs(): string[] {
  const dirs: string[] = [];
  for (const base of ['services', 'packages', 'tooling']) {
    const abs = path.join(repoRoot, base);
    if (!fs.existsSync(abs)) continue;
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      if (e.isDirectory() && fs.existsSync(path.join(abs, e.name, 'package.json'))) dirs.push(`${base}/${e.name}`);
    }
  }
  for (const d of ['db', 'test/e2e']) if (fs.existsSync(path.join(repoRoot, d, 'package.json'))) dirs.push(d);
  return dirs;
}

describe('AC-2 engines', () => {
  it('AC-2: pnpm install fails with an engines error on a Node outside >=24 <25', () => {
    // pnpm's `node-version` setting overrides the Node version used for the engines check, so this
    // is deterministic on any host Node. Real root package.json and .npmrc, copied to a scratch dir.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eng-'));
    try {
      fs.copyFileSync(path.join(repoRoot, 'package.json'), path.join(dir, 'package.json'));
      fs.copyFileSync(path.join(repoRoot, '.npmrc'), path.join(dir, '.npmrc'));
      for (const v of ['22.0.0', '25.0.0', '23.9.0']) {
        const r = spawnSync('pnpm', ['install', '--offline', `--config.node-version=${v}`], { cwd: dir, encoding: 'utf8' });
        expect(r.status, `node ${v}`).not.toBe(0);
        expect(r.stdout + r.stderr, `node ${v}`).toContain('ERR_PNPM_UNSUPPORTED_ENGINE');
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it('AC-2: pins node >=24 <25 with engine-strict', () => {
    expect(rootPkg.engines?.['node']).toBe('>=24 <25');
    expect(read('.npmrc')).toMatch(/^engine-strict=true$/m);
    expect(read('.node-version').trim()).toBe('24');
  });
});

describe('AC-3 tsconfig', () => {
  const base = (readJson('tsconfig.base.json') as { compilerOptions: Record<string, unknown> }).compilerOptions;
  it('AC-3: base has the strict options', () => {
    expect(base).toMatchObject({
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
      noImplicitOverride: true,
      verbatimModuleSyntax: true,
      target: 'ES2024',
      module: 'NodeNext',
      moduleResolution: 'NodeNext',
    });
  });
  it('AC-3: every workspace tsconfig*.json (and fixtures) extends the base', () => {
    const files = [
      ...workspaceDirs().flatMap((d) => walk(d)),
    ].filter((f) => /(^|\/)tsconfig[^/]*\.json$/.test(f));
    expect(files.length).toBeGreaterThan(0);
    const reachesBase = (file: string, seen = new Set<string>()): boolean => {
      const abs = path.join(repoRoot, file);
      if (seen.has(abs)) return false;
      seen.add(abs);
      const cfg = JSON.parse(fs.readFileSync(abs, 'utf8')) as { extends?: string | string[] };
      const exts = typeof cfg.extends === 'string' ? [cfg.extends] : (cfg.extends ?? []);
      return exts.some((e) => {
        const target = path.resolve(path.dirname(abs), e);
        if (target === path.join(repoRoot, 'tsconfig.base.json')) return true;
        return e.startsWith('.') && fs.existsSync(target) && reachesBase(path.relative(repoRoot, target), seen);
      });
    };
    const missing = files.filter((f) => !reachesBase(f));
    expect(missing).toEqual([]);
  });
});

describe('workspace tsconfig confinement (hard rule 8, second layer)', () => {
  it('every workspace tsconfig sets rootDir inside its own workspace and an include', () => {
    const files = workspaceDirs()
      .flatMap((d) => walk(d))
      .filter((f) => /(^|\/)tsconfig[^/]*\.json$/.test(f) && !f.includes('/fixtures/'));
    expect(files.length).toBeGreaterThan(0);
    const problems: string[] = [];
    for (const f of files) {
      const ws = workspaceDirs().find((d) => f.startsWith(`${d}/`)) ?? '';
      const cfg = JSON.parse(read(f)) as { compilerOptions?: { rootDir?: string }; include?: string[]; files?: string[] };
      const rootDir = cfg.compilerOptions?.rootDir;
      if (rootDir === undefined) {
        problems.push(`${f}: no rootDir`);
        continue;
      }
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(f), rootDir));
      if (resolved !== ws && !resolved.startsWith(`${ws}/`)) problems.push(`${f}: rootDir escapes ${ws}`);
      if (!cfg.include && !cfg.files) problems.push(`${f}: no include/files`);
    }
    expect(problems).toEqual([]);
  });
});

describe('ESLint config integrity', () => {
  it('the root eslint.config.mjs is the only ESLint config (no nested override)', () => {
    const all = walk('.')
      .filter((f) => /(^|\/)(eslint\.config\.[cm]?[jt]s|\.eslintrc[^/]*)$/.test(f))
      .filter((f) => !f.includes('/fixtures/'));
    expect(all).toEqual(['eslint.config.mjs']);
    const tracked = git('ls-files').stdout.split('\n').filter((f) => /(^|\/)(eslint\.config\.[cm]?[jt]s|\.eslintrc[^/]*)$/.test(f));
    expect(tracked.filter((f) => f !== 'eslint.config.mjs')).toEqual([]);
  });
  it('no source file disables lint rules inline in governed workspaces', () => {
    // noInlineConfig is set in the shared config; this guards the setting itself.
    expect(read('tooling/eslint-config/index.mjs')).toContain('noInlineConfig: true');
    expect(read('tooling/eslint-config/index.mjs')).toContain("reportUnusedDisableDirectives: 'error'");
  });
});

describe('AC-11 / AC-13 CI workflow', () => {
  const raw = read('.github/workflows/ci.yml');
  const wf = parse(raw) as {
    permissions?: Record<string, string>;
    jobs: Record<string, { steps: WfStep[]; permissions?: unknown }>;
  };
  it('AC-11: defines verify, secrets, terraform with pinned Node/pnpm and cached store and .turbo', () => {
    const steps = (job: string): WfStep[] => wf.jobs[job]?.steps ?? [];
    expect(Object.keys(wf.jobs)).toEqual(expect.arrayContaining(['verify', 'secrets', 'terraform']));
    expect(JSON.stringify(wf.jobs['secrets'])).toContain('.gitleaks.toml');
    const setupNode = steps('verify').find((s) => s.uses?.startsWith('actions/setup-node@'));
    expect(setupNode?.with?.['node-version-file']).toBe('.node-version');
    expect(setupNode?.with?.['cache']).toBe('pnpm');
    expect(steps('verify').some((s) => s.uses?.startsWith('pnpm/action-setup@'))).toBe(true);
    const turboCache = steps('verify').find((s) => s.uses?.startsWith('actions/cache@'));
    expect(turboCache?.with?.['path']).toBe('.turbo');
    const runs = steps('verify').map((s) => s.run);
    expect(runs).toContain('pnpm install --frozen-lockfile');
    expect(runs).toContain('pnpm turbo run build lint typecheck test');
    // gitleaks job must fail on any finding: no continue-on-error anywhere, no zero exit-code override.
    const gl = JSON.stringify(wf.jobs['secrets']);
    expect(gl).not.toMatch(/continue-on-error|--exit-code[ =]0|\|\|\s*true/);
    expect(gl).toMatch(/gitleaks[^"]*detect/);
    for (const j of Object.values(wf.jobs)) for (const s of j.steps) expect(s['continue-on-error']).toBeUndefined();
    // terraform job: fmt step is conditional on an infra/ change check.
    const fmt = steps('terraform').find((s) => s.run?.includes('terraform fmt -check -recursive infra/terraform'));
    expect(fmt?.if ?? '').toContain('infra');
    expect(JSON.stringify(steps('terraform'))).toContain('git diff --name-only');
  });
  it('CI hardening: checkouts drop credentials, gitleaks image pinned by digest and mounted read-only', () => {
    for (const j of Object.values(wf.jobs)) {
      for (const st of j.steps.filter((x) => x.uses?.startsWith('actions/checkout@'))) {
        expect(st.with?.['persist-credentials']).toBe(false);
      }
    }
    const gl = JSON.stringify(wf.jobs['secrets']);
    expect(gl).toMatch(/ghcr\.io\/gitleaks\/gitleaks@sha256:[0-9a-f]{64}/);
    expect(gl).toContain(':/repo:ro');
    expect(gl).toContain('--user');
    expect(raw).toContain("cancel-in-progress: ${{ github.event_name == 'pull_request' }}");
  });
  it('AC-11: pins third-party actions to a commit SHA (design note)', () => {
    const uses = [...raw.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1] ?? '');
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/@[0-9a-f]{40}$/);
  });
  it('AC-11: workflow is actionlint clean (CI only: actionlint not installed locally)', (ctx) => {
    if (!which('actionlint')) ctx.skip();
    const r = spawnSync('actionlint', [path.join(repoRoot, '.github/workflows/ci.yml')], { encoding: 'utf8' });
    expect(r.stdout + r.stderr).toBe('');
    expect(r.status).toBe(0);
  });
  it('AC-13: has no credentials, deploy, or forbidden commands', () => {
    expect(wf.permissions).toEqual({ contents: 'read' });
    for (const job of Object.values(wf.jobs)) expect(job.permissions).toBeUndefined();
    expect(raw).not.toContain('id-token');
    expect(raw).not.toContain(['configure-', 'aws-credentials'].join(''));
    expect(raw).not.toMatch(/deploy/i);
    const secretRefs = [...raw.matchAll(/secrets\.(\w+)/g)].map((m) => m[1]);
    expect(secretRefs.filter((s) => s !== 'GITHUB_TOKEN')).toEqual([]);
    for (const f of FORBIDDEN) expect(raw, f.label).not.toMatch(f.re);
  });
});

describe('AC-12 gitleaks', () => {
  const fake = (): string => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let s = '';
    for (let i = 0; i < 16; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)] ?? 'A';
    return `AKIA${s.replace(/EXAMPLE/g, 'ZZZZZZZ')}`;
  };
  it('AC-12: detects a generated fake secret outside version control (CI only: gitleaks not installed locally)', (ctx) => {
    if (!which('gitleaks')) ctx.skip();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-'));
    try {
      fs.writeFileSync(path.join(dir, 'leak.txt'), `aws_access_key_id = "${fake()}"\n`);
      const r = spawnSync('gitleaks', ['detect', '--no-git', '--source', dir, '--config', path.join(repoRoot, '.gitleaks.toml')]);
      expect(r.status).not.toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it('AC-12: the working tree (incl. .env.example) is clean (CI only: gitleaks not installed locally)', (ctx) => {
    if (!which('gitleaks')) ctx.skip();
    // Scan a copy of tracked + untracked-not-ignored files, so gitignored node_modules/dist are never
    // scanned and the config needs no allowlist.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-tree-'));
    try {
      for (const f of git('ls-files', '-co', '--exclude-standard').stdout.split('\n').filter(Boolean)) {
        const src = path.join(repoRoot, f);
        if (!fs.existsSync(src)) continue;
        fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
        fs.copyFileSync(src, path.join(dir, f));
      }
      const r = spawnSync('gitleaks', ['detect', '--no-git', '--source', dir, '--config', path.join(repoRoot, '.gitleaks.toml')], {
        encoding: 'utf8',
      });
      expect(r.status, r.stdout + r.stderr).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  it('the gitleaks config has no allowlist', () => {
    expect(read('.gitleaks.toml')).not.toMatch(/^\s*\[+allowlists?\]/m);
  });
});

describe('AC-14 / AC-15 ignore rules and tracked files', () => {
  const ignored = [
    '.env', '.env.local', '.env.production', 'x.pem', 'x.key', 'a.tfstate', 'a.tfstate.backup', '.terraform/x', 'x.tfvars',
    'test/e2e/.artifacts/x', 'x.tfvars.json', 'x.tfplan', 'x.p12', 'x.pfx', 'x.jks', 'id_rsa', 'id_rsa.pub', 'kubeconfig',
    'services/a/.env.local',
  ];
  it.each(ignored)('AC-14: %s is ignored', (p) => {
    expect(git('check-ignore', '-q', p).status).toBe(0);
  });
  it.each(['x.tfvars.example', '.env.example'])('AC-14: %s is not ignored', (p) => {
    expect(git('check-ignore', '-q', p).status).toBe(1);
  });
  it('no dependency or build output is tracked', () => {
    const tracked = git('ls-files').stdout.split('\n').filter(Boolean);
    expect(tracked.filter((f) => /(^|\/)(node_modules|dist|coverage|\.turbo)\//.test(f))).toEqual([]);
  });
  it('AC-15a/b: .env.example is tracked, and no secrets files are tracked', () => {
    expect(git('ls-files', '.env.example').stdout.trim()).toBe('.env.example');
    const tracked = git('ls-files').stdout.split('\n').filter(Boolean);
    const bad = tracked.filter((f) => /(^|\/)\.env(\.(?!example$).*)?$|\.pem$|\.key$|\.tfstate|\.p12$|\.pfx$|\.jks$|(^|\/)id_rsa|(^|\/)kubeconfig$/.test(f));
    expect(bad).toEqual([]);
  });
  it('AC-15d: dbmate (direct) fails naming DATABASE_URL without a default host', () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'dbm-'));
    try {
      const r = spawnSync(path.join(repoRoot, 'node_modules', '.bin', 'dbmate'), ['--migrations-dir', 'db/migrations', 'up'], {
        cwd,
        env: cleanDbEnv(),
        encoding: 'utf8',
      });
      expect(r.status).not.toBe(0);
      expect(r.stdout + r.stderr).toContain('DATABASE_URL');
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
  it('AC-15d: pnpm dbmate up fails naming DATABASE_URL', (ctx) => {
    if (fs.existsSync(path.join(repoRoot, '.env')) || fs.existsSync(path.join(repoRoot, '.env.local'))) ctx.skip();
    const r = spawnSync('pnpm', ['dbmate', 'up'], { cwd: repoRoot, env: cleanDbEnv(), encoding: 'utf8' });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).toContain('DATABASE_URL');
  });
});

describe('guarded dbmate wrapper', () => {
  const wrapper = path.join(repoRoot, 'scripts', 'dbmate.mjs');
  const run = (url: string | undefined, ...args: string[]) => {
    const env = cleanDbEnv();
    if (url !== undefined) env['DATABASE_URL'] = url;
    return spawnSync(process.execPath, [wrapper, '--check-only', ...args], { env, encoding: 'utf8', cwd: os.tmpdir() });
  };
  // QA round 1 known gaps: dbmate (Go flag parsing) accepts single-dash flags, so these override DATABASE_URL.
  it.fails.each([['-url', 'mysql://u@prod.invalid/d'], ['-url=mysql://u@prod.invalid/d'], ['-env', 'OTHER'], ['-env-file=x']])(
    'RT1-3 (gap): wrapper refuses single-dash override %s',
    (...args) => {
      expect(run('mysql://u:p@localhost/d', ...args).status).not.toBe(0);
    },
  );
  it.fails('RT1-4 (gap): wrapper refuses a ?host= override in DATABASE_URL', () => {
    expect(run('postgres://u:p@localhost/d?host=prod.invalid').status).not.toBe(0);
  });
  it.fails.each(['tfplan', 'id_ed25519', '.aws/credentials', '.kube/config', '.pgpass', '.netrc', 'x.keystore'])(
    'RT1-5 (gap): .gitignore covers %s',
    (p) => {
      expect(git('check-ignore', '-q', p).status).toBe(0);
    },
  );
  it.each(['mysql://u:p@localhost:3306/d', 'mysql://u:p@127.0.0.1/d', 'mysql://u:p@[::1]:3306/d', 'mysql://u:p@mysql:3306/d'])(
    'allows %s',
    (u) => {
      expect(run(u).status).toBe(0);
    },
  );
  it.each([
    'mysql://u:p@db.example.com/d',
    'mysql://u:p@10.0.0.5/d',
    'mysql://u:p@writer.cluster-abc.ap-south-1.rds.amazonaws.com/d',
  ])('refuses %s', (u) => {
    const r = run(u);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('refusing host');
    expect(r.stderr).not.toContain(':p@');
  });
  it('refuses when DATABASE_URL is unset, naming it', () => {
    const r = run(undefined);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain('DATABASE_URL');
  });
  it.each(['--url=mysql://u:p@localhost/d', '-u', '--env-file=.env', '--env'])('refuses the %s override flag', (flag) => {
    const r = run('mysql://u:p@localhost/d', flag);
    expect(r.status).not.toBe(0);
  });
  it('the root script uses the wrapper', () => {
    expect(rootPkg.scripts?.['dbmate']).toContain('scripts/dbmate.mjs');
  });
});

describe('pnpm install hardening', () => {
  it('strictDepBuilds is on with an explicit onlyBuiltDependencies list', () => {
    const ws = parse(read('pnpm-workspace.yaml')) as { strictDepBuilds?: boolean; onlyBuiltDependencies?: string[] };
    expect(ws.strictDepBuilds).toBe(true);
    expect(Array.isArray(ws.onlyBuiltDependencies)).toBe(true);
  });
});

describe('AC-16 test:e2e is opt-in and uncached', () => {
  function dry(args: string[]): { tasks: { taskId: string; command: string; resolvedTaskDefinition: { cache: boolean } }[] } {
    const r = spawnSync('pnpm', ['turbo', 'run', ...args, '--dry=json'], { cwd: repoRoot, encoding: 'utf8', env: { ...process.env, TURBO_UI: 'false' } });
    expect(r.status, r.stderr).toBe(0);
    return JSON.parse(r.stdout) as ReturnType<typeof dry>;
  }
  it('AC-16: default pipeline has no test:e2e task', () => {
    const ids = dry(['build', 'lint', 'typecheck', 'test']).tasks.map((t) => t.taskId);
    expect(ids.filter((i) => i.endsWith('#test:e2e'))).toEqual([]);
  });
  it('AC-16: test:e2e has cache disabled', () => {
    const tasks = dry(['test:e2e']).tasks;
    expect(tasks.length).toBeGreaterThan(0);
    for (const t of tasks) expect(t.resolvedTaskDefinition.cache).toBe(false);
  });
});

describe('AC-17 / AC-20 CLAUDE.md', () => {
  const md = read('CLAUDE.md');
  // Exempt: names a service that does not exist yet.
  const EXEMPT = /--filter=ingest-service/;
  it('AC-17: every pnpm/turbo command in "Commands" resolves', () => {
    const section = /## Commands[\s\S]*?```sh\n([\s\S]*?)```/.exec(md)?.[1] ?? '';
    const lines = section.split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter((l) => /^pnpm\b/.test(l));
    expect(lines.length).toBeGreaterThan(0);
    const turboTasks = new Set(Object.keys((readJson('turbo.json') as { tasks: object }).tasks).filter((t) => !t.includes('#')));
    for (const line of lines) {
      if (EXEMPT.test(line)) continue;
      const tokens = line.split(/\s+/);
      if (tokens[1] === 'install') continue;
      if (tokens[1] === 'turbo') {
        expect(tokens[2]).toBe('run');
        const tasks = tokens.slice(3).filter((t) => !t.startsWith('-'));
        for (const t of tasks) expect(turboTasks.has(t), `${line}: ${t}`).toBe(true);
      } else {
        expect(Object.keys(rootPkg.scripts ?? {}), line).toContain(tokens[1]);
      }
    }
  });
  it('AC-20: Repo layout lists tooling/ and test/e2e', () => {
    const layout = /## Repo layout[\s\S]*?(?=\n## )/.exec(md)?.[0] ?? '';
    expect(layout).toContain('tooling/');
    expect(layout).toContain('lint-fixtures');
    expect(layout).toContain('workspace-guard');
    expect(layout).toContain('test/e2e');
  });
});

describe('AC-18 pins', () => {
  it('AC-18: exact pnpm 10.x.y and turbo 2.x.y, lockfile present', () => {
    expect(rootPkg.packageManager).toMatch(/^pnpm@10\.\d+\.\d+$/);
    expect(rootPkg.devDependencies?.['turbo']).toMatch(/^2\.\d+\.\d+$/);
    expect(fs.existsSync(path.join(repoRoot, 'pnpm-lock.yaml'))).toBe(true);
    expect(git('ls-files', 'pnpm-lock.yaml').stdout.trim()).toBe('pnpm-lock.yaml');
  });
});

describe('AC-19 forbidden commands', () => {
  it('AC-19: nothing in scripts, CI, tooling, services, packages, infra, deploy, db or the root runs a forbidden command', () => {
    const scanned = ['.github', 'tooling', 'scripts', 'services', 'packages', 'infra', 'deploy', 'db', 'test'].flatMap(walk);
    const files = [...scanned, ...rootFiles()]
      .filter((f) => !/\.(png|jpg|lock)$/.test(f))
      // helpers.ts necessarily names the forbidden commands in order to detect them.
      .filter((f) => f !== 'tooling/repo-checks/test/helpers.ts');
    const hits: string[] = [];
    for (const f of files) {
      const text = read(f);
      for (const { label, re } of FORBIDDEN) if (re.test(text)) hits.push(`${f}: ${label}`);
    }
    const pkgs = ['package.json', ...workspaceDirs().map((d) => `${d}/package.json`)];
    for (const p of pkgs) {
      const scripts = Object.values((readJson(p) as PkgJson).scripts ?? {}).join('\n');
      for (const { label, re } of FORBIDDEN) if (re.test(scripts)) hits.push(`${p}: ${label}`);
    }
    expect(hits).toEqual([]);
  });
  it('detects flags placed before the subcommand', () => {
    const tf = FORBIDDEN[0]?.re;
    const cmd = ['terra', 'form -chdir=x app', 'ly'].join('');
    expect(tf?.test(cmd)).toBe(true);
    const gp = FORBIDDEN[2]?.re;
    expect(gp?.test(['git -C x pu', 'sh origin'].join(''))).toBe(true);
  });
});

describe('AC-9 / AC-4 / AC-10 wiring', () => {
  it('AC-9: the workspace guard is wired into the root-run lint (so CI runs it)', () => {
    const guardPkg = readJson('tooling/workspace-guard/package.json') as PkgJson;
    expect(guardPkg.scripts?.['lint']).toMatch(/src\/cli\.ts/);
    const turbo = readJson('turbo.json') as { tasks: Record<string, { inputs?: string[] }> };
    expect(turbo.tasks['@esg/workspace-guard#lint']?.inputs).toEqual(
      expect.arrayContaining(['$TURBO_ROOT$/pnpm-workspace.yaml', '$TURBO_ROOT$/{services,packages,tooling}/*/package.json']),
    );
  });
  it('AC-10: bad fixtures are excluded from the normal lint and typecheck', () => {
    expect(read('eslint.config.mjs')).toContain('tooling/lint-fixtures/fixtures/**');
    expect(read('eslint.config.mjs')).toContain('tooling/workspace-guard/fixtures/**');
    const tsconfig = JSON.parse(read('tooling/lint-fixtures/tsconfig.json')) as { exclude?: string[]; include?: string[] };
    expect(JSON.stringify([tsconfig.exclude, tsconfig.include])).toContain('fixtures');
  });
});
