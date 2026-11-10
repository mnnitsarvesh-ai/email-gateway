import { randomUUID } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { ScratchArea, ScratchPathError } from './scratch';

const base = mkdtempSync(join(tmpdir(), 'eg-sbx-scratch-'));
afterAll(() => rmSync(base, { recursive: true, force: true }));

async function area(): Promise<ScratchArea> {
  const s = new ScratchArea(join(base, randomUUID()));
  await s.init();
  return s;
}

describe('ScratchArea (X7, X8)', () => {
  it('creates 0700 task directories with increasing attempt numbers and removes them', async () => {
    const s = await area();
    const taskId = randomUUID();
    const first = await s.create(taskId);
    const second = await s.create(taskId);
    expect(first.endsWith(`${taskId}-1`)).toBe(true);
    expect(second.endsWith(`${taskId}-2`)).toBe(true);
    expect(statSync(first).mode & 0o777).toBe(0o700);
    writeFileSync(join(first, 'file'), 'x');
    expect(await s.remove(first)).toBe(true);
    expect(existsSync(first)).toBe(false);
    expect(await s.remove(first)).toBe(true);
  });

  it('refuses paths outside the root or with foreign names', async () => {
    const s = await area();
    await expect(s.remove('/etc')).rejects.toBeInstanceOf(ScratchPathError);
    await expect(s.remove(join(s.root, '..', 'x'))).rejects.toBeInstanceOf(ScratchPathError);
    await expect(s.remove(join(s.root, 'not-a-task'))).rejects.toBeInstanceOf(ScratchPathError);
    await expect(s.remove(join(s.root, `${randomUUID()}-1`, 'nested'))).rejects.toBeInstanceOf(
      ScratchPathError,
    );
    expect(() => new ScratchArea('/')).toThrow();
    expect(() => new ScratchArea('relative')).toThrow();
  });

  it('startup reap removes every task and self-test entry, never foreign files', async () => {
    const s = await area();
    const a = await s.create(randomUUID());
    const b = await s.createSelfTest('0123456789abcdef');
    mkdirSync(join(s.root, 'keep-me'));
    // A symbolic link named like a task is unlinked, its target untouched.
    const target = join(base, `target-${randomUUID()}`);
    mkdirSync(target);
    writeFileSync(join(target, 'precious'), 'x');
    symlinkSync(target, join(s.root, `${randomUUID()}-3`));
    const result = await s.reap(new Set(), 'startup', 0);
    expect(result).toEqual({ removed: 3, failures: 0 });
    expect(existsSync(a) || existsSync(b)).toBe(false);
    expect(existsSync(join(s.root, 'keep-me'))).toBe(true);
    expect(existsSync(join(target, 'precious'))).toBe(true);
  });

  it('periodic reap removes only old entries outside the active set', async () => {
    const s = await area();
    const activeId = randomUUID();
    const oldActive = await s.create(activeId);
    const oldOrphan = await s.create(randomUUID());
    const fresh = await s.create(randomUUID());
    const past = new Date(Date.now() - 600_000);
    utimesSync(oldActive, past, past);
    utimesSync(oldOrphan, past, past);
    const result = await s.reap(new Set([activeId]), 'periodic', 240_000);
    expect(result).toEqual({ removed: 1, failures: 0 });
    expect(existsSync(oldOrphan)).toBe(false);
    expect(existsSync(oldActive)).toBe(true);
    expect(existsSync(fresh)).toBe(true);
  });
});
