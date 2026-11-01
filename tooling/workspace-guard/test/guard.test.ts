import { execFileSync, spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const cli = path.join(import.meta.dirname, '..', 'src', 'cli.ts');
const repoRoot = path.join(import.meta.dirname, '..', '..', '..');
const badRepo = path.join(import.meta.dirname, '..', 'fixtures', 'bad-repo');

describe('workspace-guard', () => {
  it('fails on the bad fixture and names both workspaces (AC-9)', () => {
    const r = spawnSync(process.execPath, [cli, badRepo], { encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('@bad/svc-a (services/svc-a) depends on service @bad/svc-b (services/svc-b)');
    expect(r.stderr).toContain('@bad/pkg-a (packages/pkg-a) depends on service @bad/svc-b');
  });

  it('passes on the real repo root (AC-9)', () => {
    const out = execFileSync(process.execPath, [cli, repoRoot], { encoding: 'utf8' });
    expect(out).toContain('ok');
  });

  it('resolves npm:/workspace: aliases and link:/file: paths to their real target', () => {
    const alias = path.join(import.meta.dirname, '..', 'fixtures', 'alias-repo');
    const r = spawnSync(process.execPath, [cli, alias], { encoding: 'utf8' });
    expect(r.status).toBe(1);
    for (const dependent of ['@bad/p1 (packages/p1)', '@bad/p2 (packages/p2)', '@bad/t1 (tooling/t1)', '@bad/t2 (tooling/t2)']) {
      expect(r.stderr).toContain(`${dependent} depends on service @bad/svc-b (services/svc-b)`);
    }
  });

  it('checks the root package.json too', () => {
    const rootRepo = path.join(import.meta.dirname, '..', 'fixtures', 'root-repo');
    const r = spawnSync(process.execPath, [cli, rootRepo], { encoding: 'utf8' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('root-bad (.) depends on service @bad/svc-b (services/svc-b)');
  });
});
