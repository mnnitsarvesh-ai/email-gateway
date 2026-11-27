import { describe, expect, it, vi } from 'vitest';
import {
  alertScopeKey,
  approvalReasonCodes,
  failingApiModeChecks,
  SecurityAlertReads,
} from './alert-reads';

const CONNECTION = '0192f0c4-cccc-7ddd-8eee-0000000000a1';

describe('failingApiModeChecks (api-mode-health/1, step API-1 D11.3)', () => {
  it('returns the warn and fail codes in stored order, deduplicated', () => {
    expect(
      failingApiModeChecks({
        v: 1,
        checks: [
          { code: 'connection.active', status: 'pass' },
          { code: 'coverage.percent', status: 'warn', evidence: '82% covered' },
          { code: 'mailbox_access.grant', status: 'fail' },
          { code: 'coverage.percent', status: 'fail' },
        ],
      }),
    ).toEqual(['coverage.percent', 'mailbox_access.grant']);
  });

  it.each([
    null,
    undefined,
    'x',
    {},
    { checks: 'x' },
    { checks: [null, 1, { code: 'Bad Code', status: 'fail' }] },
  ])('ignores malformed documents and entries (%j)', (document) => {
    expect(failingApiModeChecks(document)).toEqual([]);
  });

  it('reads at most 16 stored checks', () => {
    const checks = Array.from({ length: 20 }, (_, i) => ({ code: `c.n${i}`, status: 'fail' }));
    expect(failingApiModeChecks({ v: 1, checks })).toHaveLength(16);
  });
});

describe('SecurityAlertReads.apiModeConnection', () => {
  const row = {
    publicId: CONNECTION,
    organizationId: 7n,
    provider: 'microsoft_365',
    healthStatus: 'failing',
    healthChecks: { v: 1, checks: [{ code: 'mailbox_access.grant', status: 'fail' }] },
    providerConnection: { organizationId: 7n, displayName: 'Contoso tenant' },
  };
  const txOf = (result: unknown) => {
    const findFirst = vi.fn(() => Promise.resolve(result));
    return { tx: { apiModeConnection: { findFirst } } as never, findFirst };
  };

  it('scopes the read to the organization and returns display and health fields only', async () => {
    const { tx, findFirst } = txOf(row);
    expect(await new SecurityAlertReads().apiModeConnection(tx, 7n, CONNECTION)).toEqual({
      publicId: CONNECTION,
      provider: 'microsoft_365',
      healthStatus: 'failing',
      displayName: 'Contoso tenant',
      failingChecks: ['mailbox_access.grant'],
    });
    expect(findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { publicId: CONNECTION, organizationId: 7n } }),
    );
  });

  it('null when absent; a foreign echo is an inconsistent read', async () => {
    expect(await new SecurityAlertReads().apiModeConnection(txOf(null).tx, 7n, CONNECTION)).toBe(
      null,
    );
    await expect(
      new SecurityAlertReads().apiModeConnection(
        txOf({ ...row, providerConnection: { organizationId: 8n, displayName: 'x' } }).tx,
        7n,
        CONNECTION,
      ),
    ).rejects.toThrow();
  });

  it('one throttle window per API-mode connection', () => {
    expect(alertScopeKey('api_mode_unhealthy', { apiModeConnectionPublicId: CONNECTION })).toBe(
      CONNECTION,
    );
  });
});

describe('SecurityAlertReads.clawback (step API-3 C6)', () => {
  const CLAWBACK = '0192f0c4-dddd-7eee-8fff-0000000000c1';
  const row = {
    publicId: CLAWBACK,
    organizationId: 7n,
    trigger: 'admin',
    status: 'pending_approval',
    action: 'move_quarantine',
    mailboxesEligible: 60,
    targetsEligible: 61,
    approvalStatus: 'pending',
    approvalReasons: ['mailbox_threshold', 'bogus', 'mailbox_threshold'],
    approvalExpiresAt: new Date('2026-11-16T09:00:00.000Z'),
  };
  const txOf = (result: unknown) => {
    const findFirst = vi.fn(() => Promise.resolve(result));
    return { tx: { apiClawback: { findFirst } } as never, findFirst };
  };

  it('scopes the read to the organization and keeps known approval reasons only', async () => {
    const { tx, findFirst } = txOf(row);
    expect(await new SecurityAlertReads().clawback(tx, 7n, CLAWBACK)).toEqual({
      ...row,
      organizationId: undefined,
      approvalReasons: ['mailbox_threshold'],
    } as never);
    expect(findFirst).toHaveBeenCalledWith(
      expect.objectContaining({ where: { publicId: CLAWBACK, organizationId: 7n } }),
    );
  });

  it('null when absent; a foreign echo is an inconsistent read', async () => {
    expect(await new SecurityAlertReads().clawback(txOf(null).tx, 7n, CLAWBACK)).toBeNull();
    await expect(
      new SecurityAlertReads().clawback(txOf({ ...row, organizationId: 8n }).tx, 7n, CLAWBACK),
    ).rejects.toThrow();
  });

  it('approval reasons from a JSON string or garbage', () => {
    expect(approvalReasonCodes('["hard_delete","auto_cap"]')).toEqual(['hard_delete', 'auto_cap']);
    expect(approvalReasonCodes('not json')).toEqual([]);
    expect(approvalReasonCodes({ a: 1 })).toEqual([]);
  });

  it('one throttle window per clawback; one per organization for reports', () => {
    expect(alertScopeKey('api_mode_purge_approval', { clawbackPublicId: CLAWBACK })).toBe(CLAWBACK);
    expect(alertScopeKey('api_mode_report_received', { clawbackPublicId: CLAWBACK })).toBe('-');
  });
});

describe('SecurityAlertReads.reportCounts (step API-3 C13)', () => {
  it('bounded counts scoped to the organization and the oldest waiting report', async () => {
    const count = vi.fn((args: { where: Record<string, unknown> }) =>
      Promise.resolve(args.where.status === 'pending_triage' ? 4 : args.where.status ? 1 : 3),
    );
    const findFirst = vi.fn(() =>
      Promise.resolve({
        organizationId: 7n,
        status: 'pending_triage',
        reportedAt: new Date('2026-11-13T07:00:00.000Z'),
      }),
    );
    const since = new Date('2026-11-13T09:00:00.000Z');
    const tx = { apiUserReport: { count, findFirst } } as never;
    expect(await new SecurityAlertReads().reportCounts(tx, 7n, since)).toEqual({
      pendingTriage: 4,
      inReview: 1,
      receivedInWindow: 3,
      oldestPendingAt: '2026-11-13T07:00:00.000Z',
    });
    for (const call of count.mock.calls) {
      expect(call[0]).toMatchObject({ where: { organizationId: 7n }, take: 10_000 });
    }
    expect(count).toHaveBeenCalledWith({
      where: { organizationId: 7n, reportedAt: { gte: since } },
      take: 10_000,
    });
  });

  it('a foreign oldest row is an inconsistent read; none waiting → null', async () => {
    const count = vi.fn(() => Promise.resolve(0));
    const foreign = {
      apiUserReport: {
        count,
        findFirst: vi.fn(() =>
          Promise.resolve({ organizationId: 8n, status: 'pending_triage', reportedAt: new Date() }),
        ),
      },
    } as never;
    await expect(new SecurityAlertReads().reportCounts(foreign, 7n, new Date())).rejects.toThrow();
    const empty = {
      apiUserReport: { count, findFirst: vi.fn(() => Promise.resolve(null)) },
    } as never;
    expect(
      (await new SecurityAlertReads().reportCounts(empty, 7n, new Date())).oldestPendingAt,
    ).toBeNull();
  });
});
