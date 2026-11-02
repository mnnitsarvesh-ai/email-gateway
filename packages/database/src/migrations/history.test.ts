import { describe, expect, it } from 'vitest';
import { checkMigrationHistory } from './history';

const LOCAL = ['20261101000000_baseline', '20261102000000_tenant_scoped_uniques'];

describe('checkMigrationHistory', () => {
  it('accepts an empty database and one that is behind or up to date', () => {
    expect(checkMigrationHistory([], LOCAL)).toMatchObject({ ok: true, retired: [], unknown: [] });
    expect(checkMigrationHistory(LOCAL.slice(0, 1), LOCAL).ok).toBe(true);
    expect(checkMigrationHistory(LOCAL, LOCAL).ok).toBe(true);
  });

  it('fails on the retired phase-0 init migration and explains the one-time reset', () => {
    const result = checkMigrationHistory(['20261101000000_init'], LOCAL);
    expect(result.ok).toBe(false);
    expect(result.retired).toEqual(['20261101000000_init']);
    expect(result.message).toContain('pnpm db:reset:local');
    expect(result.message).toContain('not the Docker volume');
  });

  it('only warns about unknown, non-retired migrations (a newer release ran here)', () => {
    const result = checkMigrationHistory([...LOCAL, '20270101000000_future'], LOCAL);
    expect(result).toMatchObject({ ok: true, unknown: ['20270101000000_future'] });
    expect(result.message).toContain('newer release');
  });
});
