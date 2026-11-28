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

describe('step API-4 alert reads (A9.2, B7)', () => {
  const POLICY = '0192f0c4-eeee-7fff-8000-0000000000d1';

  it('scope keys: dlp_detected has none; api_mode_detect_only_ended one per remediation policy', () => {
    expect(alertScopeKey('dlp_detected', {})).toBe('-');
    expect(alertScopeKey('api_mode_detect_only_ended', { remediationPolicyPublicId: POLICY })).toBe(
      POLICY,
    );
  });

  it('messageIngestSource: scoped, echo-checked; null when the row is gone', async () => {
    const findFirst = vi.fn(() =>
      Promise.resolve({
        id: 501n,
        organizationId: 7n,
        receivedAt: new Date('2026-11-13T09:00:00.000Z'),
        ingestSource: 'journal_intake',
      }),
    );
    const tx = { emailMessage: { findFirst } } as never;
    const reads = new SecurityAlertReads();
    expect(
      await reads.messageIngestSource(tx, 7n, 501n, new Date('2026-11-13T09:00:00.000Z')),
    ).toBe('journal_intake');
    expect(findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: 501n, receivedAt: new Date('2026-11-13T09:00:00.000Z'), organizationId: 7n },
      }),
    );
    await expect(
      reads.messageIngestSource(tx, 8n, 501n, new Date('2026-11-13T09:00:00.000Z')),
    ).rejects.toThrow('inconsistent read');
    findFirst.mockResolvedValueOnce(null as never);
    expect(
      await reads.messageIngestSource(tx, 7n, 501n, new Date('2026-11-13T09:00:00.000Z')),
    ).toBeNull();
  });

  it('remediationPolicy: period columns and the domain name; never the document', async () => {
    const findFirst = vi.fn((args: { select: Record<string, boolean> }) => {
      expect(args.select).not.toHaveProperty('document');
      return Promise.resolve({
        publicId: POLICY,
        organizationId: 7n,
        domainId: 31n,
        mode: 'detect_only',
        detectOnlyUntil: new Date('2026-11-20T09:00:00.000Z'),
        detectOnlyThen: 'remind',
        detectOnlyStartedAt: new Date('2026-11-13T09:00:00.000Z'),
        detectOnlyNotifiedAt: null,
      });
    });
    const domain = vi.fn(() =>
      Promise.resolve({
        id: 31n,
        organizationId: 7n,
        publicId: 'd',
        name: 'acme.example',
        status: 'active',
      }),
    );
    const tx = { apiRemediationPolicy: { findFirst }, domain: { findFirst: domain } } as never;
    const policy = await new SecurityAlertReads().remediationPolicy(tx, 7n, POLICY);
    expect(policy).toMatchObject({
      domainId: 31n,
      domainName: 'acme.example',
      mode: 'detect_only',
    });
    await expect(new SecurityAlertReads().remediationPolicy(tx, 8n, POLICY)).rejects.toThrow(
      'inconsistent read',
    );
  });

  it('simulatedActions: bounded count of the scope; a foreign row is an inconsistent read', async () => {
    const queryRaw = vi.fn(() => Promise.resolve([{ n: 3n, org_min: 7n, org_max: 7n }]));
    const tx = { $queryRaw: queryRaw } as never;
    const reads = new SecurityAlertReads();
    expect(await reads.simulatedActions(tx, 7n, 31n, new Date(0))).toEqual({
      count: 3,
      capped: false,
    });
    queryRaw.mockResolvedValueOnce([{ n: 10_000n, org_min: 7n, org_max: 7n }]);
    expect(await reads.simulatedActions(tx, 7n, null, new Date(0))).toEqual({
      count: 10_000,
      capped: true,
    });
    queryRaw.mockResolvedValueOnce([{ n: 2n, org_min: 7n, org_max: 9n }]);
    await expect(reads.simulatedActions(tx, 7n, null, new Date(0))).rejects.toThrow(
      'inconsistent read',
    );
    queryRaw.mockResolvedValueOnce([{ n: 0n, org_min: null, org_max: null }] as never);
    expect(await reads.simulatedActions(tx, 7n, null, new Date(0))).toEqual({
      count: 0,
      capped: false,
    });
  });
});
