import { clientStateHash, graphNotificationSchema } from '@email-gateway/mailbox-api';
import { describe, expect, it } from 'vitest';
import { decideNotification, mergeEffects, type SubscribedMailbox } from './notifications';

const STATE = 'example-client-state-for-tests-only-000000';
const TENANT = '11111111-2222-3333-4444-555555555555';

const mailbox = (patch: Partial<SubscribedMailbox> = {}): SubscribedMailbox => ({
  id: 7n,
  feedStatus: 'active',
  clientStateHash: clientStateHash(STATE),
  boundTenantId: TENANT,
  ...patch,
});

const item = (patch: Record<string, unknown> = {}) =>
  graphNotificationSchema.parse({
    value: [{ subscriptionId: 'sub-1', clientState: STATE, changeType: 'created', ...patch }],
  }).value[0]!;

const SYNC = { requestSync: true, expireSubscription: false, clearSubscription: false };

describe('decideNotification (step API-1 D12.4, N3)', () => {
  it('a matching change notification only requests a sync', () => {
    expect(decideNotification('change', item({ tenantId: TENANT }), mailbox())).toEqual({
      result: 'accepted',
      mailboxId: 7n,
      effect: SYNC,
    });
    // tenantId is optional; the GUID compares case-insensitively.
    expect(decideNotification('change', item(), mailbox()).result).toBe('accepted');
    expect(
      decideNotification('change', item({ tenantId: TENANT.toUpperCase() }), mailbox()).result,
    ).toBe('accepted');
  });

  it.each([
    ['an unknown subscription', item(), null, 'unknown_subscription'],
    ['no client state', item({ clientState: undefined }), mailbox(), 'client_state_mismatch'],
    [
      'a wrong client state',
      item({ clientState: 'x'.repeat(43) }),
      mailbox(),
      'client_state_mismatch',
    ],
    [
      'a mailbox without a stored hash',
      item(),
      mailbox({ clientStateHash: null }),
      'client_state_mismatch',
    ],
    [
      'another tenant',
      item({ tenantId: '99999999-2222-3333-4444-555555555555' }),
      mailbox(),
      'tenant_mismatch',
    ],
    [
      'an unbound connection',
      item({ tenantId: TENANT }),
      mailbox({ boundTenantId: null }),
      'tenant_mismatch',
    ],
    ['feeds off', item(), mailbox({ feedStatus: 'off' }), 'feed_inactive'],
    ['a revoked feed', item(), mailbox({ feedStatus: 'revoked' }), 'feed_inactive'],
    ['an unknown lifecycle event', item({ lifecycleEvent: 'somethingElse' }), mailbox(), 'invalid'],
  ] as const)('%s is not accepted', (_n, i, m, result) => {
    expect(decideNotification('change', i, m)).toEqual({ result });
  });

  it('lifecycle events: renew, forget, catch up (each also requests a sync)', () => {
    expect(
      decideNotification(
        'lifecycle',
        item({ lifecycleEvent: 'reauthorizationRequired' }),
        mailbox(),
      ),
    ).toEqual({
      result: 'accepted',
      mailboxId: 7n,
      effect: { requestSync: true, expireSubscription: true, clearSubscription: false },
    });
    expect(
      decideNotification('lifecycle', item({ lifecycleEvent: 'subscriptionRemoved' }), mailbox()),
    ).toEqual({
      result: 'accepted',
      mailboxId: 7n,
      effect: { requestSync: true, expireSubscription: false, clearSubscription: true },
    });
    expect(decideNotification('lifecycle', item({ lifecycleEvent: 'missed' }), mailbox())).toEqual({
      result: 'accepted',
      mailboxId: 7n,
      effect: SYNC,
    });
  });

  it('a lifecycle route item with neither event nor change type is invalid', () => {
    expect(decideNotification('lifecycle', item({ changeType: undefined }), mailbox()).result).toBe(
      'invalid',
    );
  });

  it('pending, error and throttled feeds still accept the hint', () => {
    for (const feedStatus of ['pending', 'error', 'throttled'] as const) {
      expect(decideNotification('change', item(), mailbox({ feedStatus })).result).toBe('accepted');
    }
  });
});

describe('mergeEffects (one coalescing UPDATE per mailbox)', () => {
  it('ORs the effects of a mailbox and ignores refusals', () => {
    const merged = mergeEffects([
      { result: 'accepted', mailboxId: 7n, effect: SYNC },
      {
        result: 'accepted',
        mailboxId: 7n,
        effect: { requestSync: true, expireSubscription: true, clearSubscription: false },
      },
      { result: 'accepted', mailboxId: 8n, effect: SYNC },
      { result: 'unknown_subscription' },
    ]);
    expect([...merged.entries()]).toEqual([
      [7n, { requestSync: true, expireSubscription: true, clearSubscription: false }],
      [8n, SYNC],
    ]);
  });
});
