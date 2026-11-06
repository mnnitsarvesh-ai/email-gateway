import { describe, expect, it } from 'vitest';
import { scanRow } from './click.test-support';
import { parseCodes, parseDynamic, parseStoredLookalike, storedFetch } from './stored-result';

describe('stored-result readers', () => {
  it('parseCodes keeps dotted codes only', () => {
    expect(parseCodes(['url.userinfo', 'BAD', 1, 'x', 'url.idn'])).toEqual([
      'url.userinfo',
      'url.idn',
    ]);
    expect(parseCodes(null)).toEqual([]);
  });

  it('parseStoredLookalike: findings, L4/L6 entries or codes, high confidence', () => {
    const result = parseStoredLookalike(
      [
        { rule: 'L2', targetKind: 'brand', targetDomain: 'paypal.com', score: 0.9, distance: 1 },
        { rule: 'L4' },
        { rule: 'L9', targetKind: 'brand' },
      ],
      ['url.idn'],
      0.85,
    );
    expect(result).toMatchObject({ mixedScript: true, idn: true, highConfidence: true });
    expect(result.findings).toHaveLength(1);
    expect(
      parseStoredLookalike(
        [{ rule: 'L2', targetKind: 'brand', targetDomain: 'a.b', score: 0.5, distance: 2 }],
        [],
        0.85,
      ).highConfidence,
    ).toBe(false);
    expect(parseStoredLookalike('garbage', [], 0.85).findings).toEqual([]);
  });

  it('storedFetch maps statuses, errors and blocked reasons', () => {
    expect(storedFetch(scanRow())).toBeNull();
    expect(storedFetch(scanRow({ fetchStatus: 'error', fetchError: 'timeout' }))?.error).toBe(
      'timeout',
    );
    expect(storedFetch(scanRow({ fetchStatus: 'error', fetchError: 'weird' }))?.error).toBe(
      'connection_error',
    );
    expect(
      storedFetch(scanRow({ fetchStatus: 'blocked', fetchError: 'metadata' }))?.blockedReason,
    ).toBe('metadata');
    expect(
      storedFetch(
        scanRow({
          fetchStatus: 'blocked',
          redirectChain: [
            { host: 'a.test', port: null, status: 302, kind: 'initial', blocked: null },
            { host: '127.0.0.1', port: null, status: null, kind: 'http', blocked: 'loopback' },
          ],
        }),
      )?.blockedReason,
    ).toBe('loopback');
    const completed = storedFetch(
      scanRow({
        fetchStatus: 'completed',
        landing: {
          passwordFields: 1,
          forms: 1,
          crossOriginFormAction: false,
          formActionHosts: [],
          titleBrandMatches: [],
        },
      }),
    );
    expect(completed?.landing?.passwordFields).toBe(1);
  });

  it('parseDynamic validates known signal keys only', () => {
    expect(parseDynamic(null)).toBeNull();
    expect(parseDynamic({ scanId: 1n, urlSha256: '', status: 'failed', signals: null })).toEqual({
      status: 'failed',
      signals: null,
    });
    expect(
      parseDynamic({
        scanId: 1n,
        urlSha256: '',
        status: 'completed',
        signals: { passwordFields: -1 },
      }),
    ).toBeNull();
  });
});
