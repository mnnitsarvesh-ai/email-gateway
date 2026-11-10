import { lstat, mkdir, readdir, realpath, rm, stat } from 'node:fs/promises';
import { isAbsolute, join, relative, sep } from 'node:path';

/**
 * Per-task scratch directories under `SANDBOX_SCRATCH_DIR` (step 4.6 X7, X8): `<taskId>-<n>`
 * (0700), created before `backend.run`, removed right after it (before anything is stored or
 * published), and reaped at startup / on a timer when a crash left one behind. The static
 * backend's self-test uses `selftest-<hex>`.
 *
 * Path safety: only direct children of the (real) root whose name matches one of the two
 * patterns are ever removed; a symbolic link is unlinked, never followed; `rm` refuses any path
 * that resolves outside the root.
 */

const TASK_ID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
export const TASK_SCRATCH_PATTERN = new RegExp(`^(${TASK_ID})-([1-9][0-9]{0,5})$`);
export const SELFTEST_SCRATCH_PATTERN = /^selftest-[0-9a-f]{16}$/;

export class ScratchPathError extends Error {
  override readonly name = 'ScratchPathError';
  constructor() {
    super('scratch path outside the scratch root');
  }
}

export interface ScratchReapResult {
  removed: number;
  failures: number;
}

export class ScratchArea {
  private realRoot: string | undefined;
  private readonly attempts = new Map<string, number>();

  constructor(readonly root: string) {
    if (!isAbsolute(root) || root === '/' || root === sep) {
      throw new Error('SANDBOX_SCRATCH_DIR must be an absolute directory other than /');
    }
  }

  /** Creates the root (0700) when missing and resolves its real path. */
  async init(): Promise<void> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const info = await stat(this.root);
    if (!info.isDirectory()) throw new Error('SANDBOX_SCRATCH_DIR is not a directory');
    this.realRoot = await realpath(this.root);
  }

  private async rootPath(): Promise<string> {
    if (!this.realRoot) await this.init();
    return this.realRoot as string;
  }

  /** Creates `<root>/<taskId>-<n>` (0700) with the next free attempt number of this process. */
  async create(taskId: string): Promise<string> {
    const root = await this.rootPath();
    for (let tries = 0; tries < 50; tries += 1) {
      const attempt = (this.attempts.get(taskId) ?? 0) + 1;
      this.attempts.set(taskId, attempt);
      if (this.attempts.size > 10_000)
        this.attempts.delete(this.attempts.keys().next().value as string);
      const name = `${taskId}-${String(attempt)}`;
      if (!TASK_SCRATCH_PATTERN.test(name)) throw new ScratchPathError();
      const dir = join(root, name);
      try {
        await mkdir(dir, { mode: 0o700 });
        return dir;
      } catch (error) {
        if ((error as { code?: unknown }).code !== 'EEXIST') throw error;
      }
    }
    throw new Error('could not create a scratch directory');
  }

  /** Creates `<root>/selftest-<hex>` (0700) for a backend self-test. */
  async createSelfTest(hex: string): Promise<string> {
    const name = `selftest-${hex}`;
    if (!SELFTEST_SCRATCH_PATTERN.test(name)) throw new ScratchPathError();
    const dir = join(await this.rootPath(), name);
    await mkdir(dir, { mode: 0o700 });
    return dir;
  }

  /** Is `dir` a direct, well-named child of the root? */
  private async check(dir: string): Promise<string> {
    const root = await this.rootPath();
    const rel = relative(root, dir);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel) || rel.includes(sep)) {
      throw new ScratchPathError();
    }
    if (!TASK_SCRATCH_PATTERN.test(rel) && !SELFTEST_SCRATCH_PATTERN.test(rel)) {
      throw new ScratchPathError();
    }
    return join(root, rel);
  }

  /**
   * Removes one scratch directory (`rm -rf` of that directory only). Resolves true when it is
   * gone (also when it never existed); false when removal failed. Throws `ScratchPathError` for
   * a path outside the root.
   */
  async remove(dir: string): Promise<boolean> {
    const path = await this.check(dir);
    try {
      await rm(path, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Reaper pass (X8): `startup` removes every task/self-test entry (nothing of this process runs
   * yet); `periodic` removes entries older than `maxAgeMs` whose task id is not `active`.
   */
  async reap(
    active: ReadonlySet<string>,
    mode: 'startup' | 'periodic',
    maxAgeMs: number,
    now = Date.now(),
  ): Promise<ScratchReapResult> {
    const root = await this.rootPath();
    let names: string[];
    try {
      names = await readdir(root);
    } catch {
      return { removed: 0, failures: 1 };
    }
    let removed = 0;
    let failures = 0;
    for (const name of names) {
      const task = TASK_SCRATCH_PATTERN.exec(name);
      const selftest = SELFTEST_SCRATCH_PATTERN.test(name);
      if (!task && !selftest) continue;
      if (task && active.has(task[1] as string)) continue;
      const path = join(root, name);
      try {
        const info = await lstat(path);
        if (mode === 'periodic' && now - info.mtimeMs < maxAgeMs) continue;
        await rm(path, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
        removed += 1;
      } catch (error) {
        if ((error as { code?: unknown }).code === 'ENOENT') continue;
        failures += 1;
      }
    }
    return { removed, failures };
  }
}
