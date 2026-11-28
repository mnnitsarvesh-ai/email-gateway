import { describe, expect, it } from 'vitest';
import {
  chooseConnection,
  ownershipView,
  type ProviderVerificationState,
  providerResultAction,
} from './provider-ownership';

const A = { id: 1n, publicId: '0192f3a0-3333-7000-8000-00000000000a' };
const B = { id: 2n, publicId: '0192f3a0-3333-7000-8000-00000000000b' };
const NOW = new Date('2026-11-27T12:00:00.000Z');

const row = (patch: Partial<ProviderVerificationState> = {}): ProviderVerificationState => ({
  status: 'pending',
  providerResult: null,
  providerErrorCode: null,
  expiresAt: new Date(NOW.getTime() + 60_000),
  ...patch,
});

describe('provider ownership rules (step API-4 B3)', () => {
  it('chooses the requested, the previous or the only capable connection', () => {
    expect(chooseConnection([A, B], B.publicId.toUpperCase(), null)).toEqual({
      ok: true,
      connection: B,
    });
    expect(chooseConnection([A], B.publicId, null)).toEqual({
      ok: false,
      reason: 'not_capable',
      candidates: [],
    });
    expect(chooseConnection([], undefined, null)).toEqual({
      ok: false,
      reason: 'none',
      candidates: [],
    });
    expect(chooseConnection([A], undefined, null)).toEqual({ ok: true, connection: A });
    expect(chooseConnection([A, B], undefined, 2n)).toEqual({ ok: true, connection: B });
    expect(chooseConnection([A, B], undefined, 9n)).toEqual({
      ok: false,
      reason: 'connection_required',
      candidates: [A.publicId, B.publicId],
    });
  });

  it.each([
    [
      'verified result claims',
      'pending_verification',
      row({ providerResult: 'verified' }),
      { kind: 'claim' },
    ],
    [
      'unverified fails with the code',
      'pending_verification',
      row({ providerResult: 'unverified' }),
      { kind: 'fail', lastError: 'unverified' },
    ],
    [
      'absent fails',
      'pending_verification',
      row({ providerResult: 'absent' }),
      { kind: 'fail', lastError: 'absent' },
    ],
    [
      'alias fails',
      'pending_verification',
      row({ providerResult: 'alias' }),
      { kind: 'fail', lastError: 'alias' },
    ],
    [
      'error carries the provider code',
      'pending_verification',
      row({ providerResult: 'error', providerErrorCode: 'throttled' }),
      { kind: 'fail', lastError: 'error:throttled' },
    ],
    ['no result yet waits', 'pending_verification', row(), { kind: 'wait' }],
    [
      'no result by expiry expires',
      'pending_verification',
      row({ expiresAt: NOW }),
      { kind: 'expire' },
    ],
    [
      'a TXT win meanwhile fails the row',
      'verified',
      row({ providerResult: 'verified' }),
      { kind: 'fail', lastError: 'domain_not_pending' },
    ],
    [
      'a deleted domain fails the row',
      null,
      row(),
      { kind: 'fail', lastError: 'domain_not_pending' },
    ],
    [
      'a finished row is done',
      'pending_verification',
      row({ status: 'expired' }),
      { kind: 'done' },
    ],
  ] as const)('%s', (_name, status, state, expected) => {
    expect(providerResultAction(status, state, NOW)).toEqual(expected);
  });

  it('the ownership view: available only while waiting with a capable connection', () => {
    expect(
      ownershipView({
        domainStatus: 'pending_verification',
        method: null,
        latest: null,
        capableConnections: 1,
      }),
    ).toEqual({ method: null, providerCheck: null, providerCheckAvailable: true });
    expect(
      ownershipView({ domainStatus: 'failed', method: null, latest: null, capableConnections: 0 })
        .providerCheckAvailable,
    ).toBe(false);
    const view = ownershipView({
      domainStatus: 'verified',
      method: 'provider_tenant',
      latest: {
        id: 42n,
        status: 'verified',
        providerResult: 'verified',
        connectionPublicId: A.publicId,
        createdAt: NOW,
        providerCheckedAt: NOW,
        expiresAt: NOW,
      },
      capableConnections: 2,
    });
    expect(view).toEqual({
      method: 'provider_tenant',
      providerCheck: {
        id: '42',
        status: 'verified',
        result: 'verified',
        connectionId: A.publicId,
        requestedAt: NOW.toISOString(),
        checkedAt: NOW.toISOString(),
        expiresAt: NOW.toISOString(),
      },
      providerCheckAvailable: false,
    });
  });
});
