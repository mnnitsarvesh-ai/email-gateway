import { describe, expect, it } from 'vitest';
import {
  addressDomain,
  classifyRecipientDirection,
  copyLagMs,
  lagBucket,
  lagPercentileSeconds,
} from './classify';
import {
  clientStateHash,
  clientStateMatches,
  CLIENT_STATE_LENGTH,
  copyMessageIdHash,
  deriveClientState,
  emlObjectKeyForCopy,
  ingestKeyForCopy,
  normalizeMessageId,
  objectRefForCopy,
} from './identifiers';
import {
  graphNotificationSchema,
  isGraphLifecycleEvent,
  isGraphValidationToken,
} from './notifications';

const REF = {
  connectionPublicId: '0190dddd-0000-7000-8000-000000000001',
  mailboxPublicId: '0190eeee-0000-7000-8000-000000000001',
  providerMessageId: 'AAMkEXAMPLE1',
};
// Synthetic, test-only secret (not secret-shaped).
const SECRET = 'EXAMPLE-notification-secret-for-tests-only';

describe('identifiers (design §5)', () => {
  it('dedupe hash: fixed vector, angle brackets and whitespace removed, null without an id', () => {
    const expected = 'c70fe7b7061d751b616a60456d72be9dd04c119d6b1afda126499491fe4896a1';
    expect(copyMessageIdHash(1001n, '<abc.123@mail.example>')).toBe(expected);
    expect(copyMessageIdHash('1001', '  <abc.123@mail.example>  ')).toBe(expected);
    expect(copyMessageIdHash(1001, 'abc.123@mail.example')).toBe(expected);
    expect(copyMessageIdHash(1001, '< abc.123@mail.example >')).toBe(expected);
    // Organization-scoped and case-sensitive.
    expect(copyMessageIdHash(1002, '<abc.123@mail.example>')).not.toBe(expected);
    expect(copyMessageIdHash(1001, '<ABC.123@mail.example>')).not.toBe(expected);
    for (const empty of [null, undefined, '', '   ', '<>', '< >']) {
      expect(copyMessageIdHash(1001, empty)).toBeNull();
    }
    expect(normalizeMessageId('<a@b>')).toBe('a@b');
    expect(normalizeMessageId('<a@b')).toBe('<a@b');
  });

  it('ingest key and object ref: fixed vectors; object key layout', () => {
    expect(ingestKeyForCopy(REF)).toBe(
      'v2:mbx:9ea256a43f5cd29aef334b96cf1f0b137e91347ee27e02e2518ec711e067e0c5',
    );
    expect(ingestKeyForCopy(REF).length).toBeLessThanOrEqual(128);
    expect(objectRefForCopy({ ...REF, organizationId: 1001n })).toBe(
      '5615f4d58271503607f4f15a9d5c1ae3',
    );
    expect(
      emlObjectKeyForCopy({ ...REF, organizationId: 1001n }, new Date('2026-11-09T23:59:59.999Z')),
    ).toBe('org/1001/eml/2026/11/09/5615f4d58271503607f4f15a9d5c1ae3.eml');
  });

  it('client state: fixed vector, version-bound, 43 characters, hash and constant-time match', () => {
    const value = deriveClientState(SECRET, REF.mailboxPublicId, 3);
    expect(value).toBe('n5qzUyaoiMVYxPr6rpC9I6xp228pcfLrmJTMAdGLHo0');
    expect(value).toHaveLength(CLIENT_STATE_LENGTH);
    expect(value).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(deriveClientState(SECRET, REF.mailboxPublicId, 4)).not.toBe(value);
    expect(deriveClientState(`${SECRET}x`, REF.mailboxPublicId, 3)).not.toBe(value);
    const hash = clientStateHash(value);
    expect(hash).toBe('06111c4d70ccdb16fcfe2801fb2a51329213fa38e1fb7016c28b62b0ab8a12d1');
    expect(clientStateMatches(value, hash)).toBe(true);
    expect(clientStateMatches(`${value}x`, hash)).toBe(false);
    expect(clientStateMatches(undefined, hash)).toBe(false);
    expect(clientStateMatches(value, null)).toBe(false);
    expect(clientStateMatches(value, 'not-a-hash')).toBe(false);
    expect(() => deriveClientState('', REF.mailboxPublicId, 1)).toThrow(
      'client_state_secret_required',
    );
    expect(() => deriveClientState(SECRET, REF.mailboxPublicId, -1)).toThrow();
  });
});

describe('direction and lag (D7.4, D7.8)', () => {
  const org = ['example.com', 'Example.NET'];
  it.each([
    ['colleague@example.com', 'user@example.com', 'internal'],
    ['Colleague@EXAMPLE.net', 'user@example.com', 'internal'],
    ['partner@other.example', 'user@example.com', 'inbound'],
    ['someone@sub.example.com', 'user@example.com', 'inbound'],
    [null, 'user@example.com', 'inbound'],
    ['', 'user@example.com', 'inbound'],
    ['colleague@example.com', 'external@other.example', 'inbound'],
  ] as const)('%s → %s is %s', (sender, recipient, direction) => {
    expect(classifyRecipientDirection(sender, recipient, org)).toBe(direction);
  });

  it('extracts domains', () => {
    expect(addressDomain('a@Example.COM.')).toBe('example.com');
    expect(addressDomain('no-at')).toBeNull();
    expect(addressDomain('@x')).toBeNull();
  });

  it.each([
    [-5, 'le_60s'],
    [0, 'le_60s'],
    [60_000, 'le_60s'],
    [60_001, 'le_300s'],
    [300_000, 'le_300s'],
    [900_000, 'le_900s'],
    [3_600_000, 'le_3600s'],
    [3_600_001, 'gt_3600s'],
  ] as const)('lagBucket(%i) = %s', (ms, bucket) => {
    expect(lagBucket(ms)).toBe(bucket);
  });

  it('computes the copy lag and bucket percentiles', () => {
    const t = new Date('2026-11-10T12:00:00Z');
    expect(copyLagMs(t, new Date(t.getTime() + 1234))).toBe(1234);
    expect(copyLagMs(new Date(t.getTime() + 1000), t)).toBe(0);
    const zero = { le_60s: 0, le_300s: 0, le_900s: 0, le_3600s: 0, gt_3600s: 0 };
    expect(lagPercentileSeconds(zero, 0.95)).toBeNull();
    const counts = { le_60s: 90, le_300s: 5, le_900s: 4, le_3600s: 1, gt_3600s: 0 };
    expect(lagPercentileSeconds(counts, 0.5)).toBe(60);
    expect(lagPercentileSeconds(counts, 0.95)).toBe(300);
    expect(lagPercentileSeconds(counts, 0.99)).toBe(900);
    expect(lagPercentileSeconds({ ...zero, gt_3600s: 3 }, 0.95, 7_200_000)).toBe(7200);
    expect(lagPercentileSeconds({ ...zero, gt_3600s: 3 }, 0.95)).toBe(3601);
  });
});

describe('graphNotificationSchema (D12.4)', () => {
  const item = {
    subscriptionId: '7f105c7d-2dc5-4530-97cd-4e7ae6534c07',
    subscriptionExpirationDateTime: '2026-11-13T10:00:00.000Z',
    changeType: 'created',
    resource: 'Users/x/Messages/y',
    resourceData: { id: 'y', '@odata.type': '#Microsoft.Graph.Message' },
    clientState: 'EXAMPLE-state',
    tenantId: '11111111-2222-3333-4444-555555555555',
  };

  it('keeps the fields it reads and drops everything else', () => {
    const parsed = graphNotificationSchema.parse({ value: [item], validationTokens: ['x'] });
    expect(parsed).toEqual({
      value: [
        {
          subscriptionId: item.subscriptionId,
          subscriptionExpirationDateTime: item.subscriptionExpirationDateTime,
          changeType: 'created',
          clientState: 'EXAMPLE-state',
          tenantId: item.tenantId,
        },
      ],
    });
    expect(JSON.stringify(parsed)).not.toContain('Messages');
  });

  it('accepts lifecycle items and nulls; rejects missing ids, wrong types and sizes', () => {
    const lifecycle = graphNotificationSchema.parse({
      value: [{ subscriptionId: 's1', lifecycleEvent: 'missed', clientState: null }],
    });
    expect(lifecycle.value[0]).toEqual({ subscriptionId: 's1', lifecycleEvent: 'missed' });
    for (const bad of [
      {},
      { value: [] },
      { value: [{ changeType: 'created' }] },
      { value: [{ subscriptionId: '' }] },
      { value: [{ subscriptionId: 's', clientState: 5 }] },
      { value: [{ subscriptionId: 's', clientState: 'x'.repeat(256) }] },
      { value: [{ subscriptionId: 'x'.repeat(129) }] },
      { value: Array.from({ length: 1001 }, () => ({ subscriptionId: 's' })) },
      { value: 'nope' },
    ]) {
      expect(graphNotificationSchema.safeParse(bad).success, JSON.stringify(bad).slice(0, 60)).toBe(
        false,
      );
    }
    expect(
      graphNotificationSchema.safeParse({
        value: Array.from({ length: 1000 }, () => ({ subscriptionId: 's' })),
      }).success,
    ).toBe(true);
  });

  it('recognizes lifecycle events and validation tokens', () => {
    expect(isGraphLifecycleEvent('reauthorizationRequired')).toBe(true);
    expect(isGraphLifecycleEvent('other')).toBe(false);
    expect(isGraphLifecycleEvent(undefined)).toBe(false);
    expect(isGraphValidationToken('Validation: Testing client application')).toBe(true);
    expect(isGraphValidationToken('x'.repeat(1024))).toBe(true);
    expect(isGraphValidationToken('x'.repeat(1025))).toBe(false);
    expect(isGraphValidationToken('')).toBe(false);
    expect(isGraphValidationToken('a\nb')).toBe(false);
    expect(isGraphValidationToken(null)).toBe(false);
  });
});
