import { describe, expect, it } from 'vitest';
import { IncidentCategoryRegistry } from '@email-gateway/security-incidents';
import { fakeCategoryHandler } from '@email-gateway/security-incidents/testing';
import { atoIncidentFeedbackSchema, atoIncidentHandler } from './incident-handler';

const handler = atoIncidentHandler({
  store: () => {
    throw new Error('the store is not needed by these assertions');
  },
});

describe('atoIncidentHandler (D12, D24)', () => {
  it('declares category account_takeover, subject ato_account and ato:read / ato:manage', () => {
    expect(handler.category).toBe('account_takeover');
    expect(handler.subjectTypes).toEqual(['ato_account']);
    expect(handler.permissions).toEqual({ read: 'ato:read', manage: 'ato:manage' });
    expect(handler.feedbackSchema).toBe(atoIncidentFeedbackSchema);
    expect(typeof handler.onTransition).toBe('function');
  });

  it('registers next to another category; permissions isolate the categories', () => {
    const other = fakeCategoryHandler();
    const registry = new IncidentCategoryRegistry([handler, other]);
    expect(registry.get('account_takeover')).toBe(handler);
    expect(registry.readPermissions()).toContain('ato:read');
    expect(registry.managePermissions()).toContain('ato:manage');
    expect(registry.categoriesReadableBy(['ato:read'])).toEqual(['account_takeover']);
    expect(registry.categoriesReadableBy([other.permissions.read])).not.toContain(
      'account_takeover',
    );
    expect(() => new IncidentCategoryRegistry([handler, handler])).toThrow(/already registered/);
  });

  it('resolveSubject refuses another subject type without touching the database', async () => {
    const tx = {} as never;
    expect(await handler.resolveSubject(tx, 1n, { type: 'message', publicId: 'x' })).toBeNull();
  });

  it('a non-terminal transition does not use the store', async () => {
    const tx = {} as never;
    const lazy = atoIncidentHandler({
      store: () => {
        throw new Error('store must not be called');
      },
    });
    await expect(
      lazy.onTransition!(
        tx,
        {} as never,
        'open',
        'investigating',
        { type: 'system', id: null },
        undefined,
      ),
    ).resolves.toBeUndefined();
  });
});

describe('atoIncidentFeedbackSchema (§5.2 categoryFeedback)', () => {
  it('defaults to dismissing signals with no trusted contexts', () => {
    expect(atoIncidentFeedbackSchema.parse({})).toEqual({
      trustedContexts: [],
      dismissSignals: true,
    });
  });

  it('accepts up to 20 trusted contexts of the four kinds with expiry 1-365 days', () => {
    const parsed = atoIncidentFeedbackSchema.parse({
      trustedContexts: [
        { kind: 'ip_cidr', value: '198.51.100.0/24', expiresInDays: 30, reason: 'office VPN' },
        { kind: 'asn', value: '64501', expiresInDays: 365, reason: 'ISP' },
        { kind: 'country', value: 'GB', expiresInDays: 1, reason: 'travel' },
        { kind: 'device', value: '0123456789abcdef', expiresInDays: 90, reason: 'laptop' },
      ],
      dismissSignals: false,
    });
    expect(parsed.trustedContexts).toHaveLength(4);
    expect(parsed.dismissSignals).toBe(false);
  });

  it('is strict and bounded', () => {
    const ctx = { kind: 'country', value: 'GB', expiresInDays: 30, reason: 'travel' };
    expect(atoIncidentFeedbackSchema.safeParse({ extra: true }).success).toBe(false);
    expect(
      atoIncidentFeedbackSchema.safeParse({ trustedContexts: [{ ...ctx, kind: 'user' }] }).success,
    ).toBe(false);
    expect(
      atoIncidentFeedbackSchema.safeParse({ trustedContexts: [{ ...ctx, expiresInDays: 366 }] })
        .success,
    ).toBe(false);
    expect(
      atoIncidentFeedbackSchema.safeParse({ trustedContexts: [{ ...ctx, reason: '  ' }] }).success,
    ).toBe(false);
    expect(
      atoIncidentFeedbackSchema.safeParse({ trustedContexts: Array(21).fill(ctx) }).success,
    ).toBe(false);
  });
});
