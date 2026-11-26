import { describe, expect, it, vi } from 'vitest';
import { alertScopeKey, failingApiModeChecks, SecurityAlertReads } from './alert-reads';

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
