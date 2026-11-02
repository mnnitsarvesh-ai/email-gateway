import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { InMemoryKeyValueStore } from '../../../../test/support/in-memory-key-value-store';
import type { LoginAuditRepository } from '../repositories/login-audit.repository';
import type { SessionsRepository } from '../repositories/sessions.repository';
import type { UserTokensRepository } from '../repositories/user-tokens.repository';
import { purgeInBatches, SessionPurgeService } from './session-purge.service';

/** A table with `rows` deletable rows; each call deletes up to the limit. */
function table(rows: number) {
  let left = rows;
  return vi.fn((_before: Date, limit: number) => {
    const n = Math.min(left, limit);
    left -= n;
    return Promise.resolve(n);
  });
}

describe('purgeInBatches', () => {
  it('deletes batch by batch until a short batch', async () => {
    const batches: number[] = [];
    let left = 2500;
    const total = await purgeInBatches((limit) => {
      const n = Math.min(left, limit);
      left -= n;
      batches.push(n);
      return Promise.resolve(n);
    }, 1000);
    expect(total).toBe(2500);
    expect(batches).toEqual([1000, 1000, 500]);
  });

  it('does one query when nothing is left', async () => {
    const fn = vi.fn(() => Promise.resolve(0));
    expect(await purgeInBatches(fn)).toBe(0);
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe('SessionPurgeService', () => {
  let kv: InMemoryKeyValueStore;
  beforeEach(() => {
    kv = new InMemoryKeyValueStore();
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });
  afterEach(() => vi.restoreAllMocks());

  function service(enabled: boolean, rows = { sessions: 1200, tokens: 3, audit: 0 }) {
    const repos = {
      sessions: { purgeExpired: table(rows.sessions) },
      tokens: { purgeExpired: table(rows.tokens) },
      audit: { purgeOlderThan: table(rows.audit) },
    };
    const svc = new SessionPurgeService(
      { AUTH_BACKGROUND_JOBS_ENABLED: enabled, AUTH_LOGIN_AUDIT_RETENTION_DAYS: 365 },
      kv,
      repos.sessions as unknown as SessionsRepository,
      repos.tokens as unknown as UserTokensRepository,
      repos.audit as unknown as LoginAuditRepository,
    );
    return { svc, repos };
  }

  it('purges with the D5 cut-offs under the lock, once per lock period', async () => {
    const { svc, repos } = service(true);
    const now = new Date('2026-11-02T12:00:00Z');
    expect(await svc.runOnce(now)).toEqual({ sessions: 1200, tokens: 3, loginAudit: 0 });
    expect(repos.sessions.purgeExpired).toHaveBeenCalledWith(
      new Date('2026-11-01T12:00:00Z'),
      1000,
    );
    expect(repos.tokens.purgeExpired).toHaveBeenCalledWith(new Date('2026-10-26T12:00:00Z'), 1000);
    expect(repos.audit.purgeOlderThan).toHaveBeenCalledWith(new Date('2025-11-02T12:00:00Z'), 1000);
    expect(await kv.ttl('jobs:auth-purge')).toBe(55 * 60);
    expect(await svc.runOnce(now)).toBeNull();
  });

  it('schedules an unref’d timer only when enabled and clears it on destroy', async () => {
    const disabled = service(false).svc;
    disabled.onApplicationBootstrap();
    expect(disabled.scheduled).toBe(false);

    const enabled = service(true).svc;
    enabled.onApplicationBootstrap();
    expect(enabled.scheduled).toBe(true);
    await enabled.onModuleDestroy();
    expect(enabled.scheduled).toBe(false);
  });
});
