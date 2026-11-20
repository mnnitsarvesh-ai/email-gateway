import { describe, expect, it } from 'vitest';
import { looksSecretShaped, providerEventSchema, type ProviderEvent } from './ato-port';
import { validateActionState } from './state-ports';

const event: ProviderEvent = {
  provider: 'microsoft_entra',
  eventId: 'entra:1',
  stream: 'sign_ins',
  occurredAt: '2026-11-10T11:50:00.000Z',
  identity: {
    provider: 'microsoft_entra',
    externalId: 'u-1',
    primaryEmail: 'alex@contoso-it.example',
  },
  outcome: 'success',
  ip: '192.0.2.10',
  deviceIdHash: '0123456789abcdef',
  deviceLabel: 'Edge 120.0 · Windows 10',
};

describe('8.4 providerEventSchema through the port (§0.2, M1, invariant 6)', () => {
  it('accepts a normalized event including PX1 deviceLabel', () => {
    expect(providerEventSchema.safeParse(event).success).toBe(true);
  });

  it('bounds strings and lists', () => {
    expect(providerEventSchema.safeParse({ ...event, eventId: 'x'.repeat(129) }).success).toBe(
      false,
    );
    expect(providerEventSchema.safeParse({ ...event, deviceLabel: 'x'.repeat(97) }).success).toBe(
      false,
    );
    expect(
      providerEventSchema.safeParse({
        ...event,
        oauth: { appIdHash: 'h', scopes: Array(51).fill('s'), consentType: 'user' },
      }).success,
    ).toBe(false);
    expect(
      providerEventSchema.safeParse({
        ...event,
        mailbox: { change: 'access', ruleTraits: Array(17).fill('t') },
      }).success,
    ).toBe(false);
    expect(providerEventSchema.safeParse({ ...event, raw: {} }).success).toBe(false);
    expect(providerEventSchema.safeParse({ ...event, ip: 'not-an-ip' }).success).toBe(false);
  });

  it('refuses secret-shaped values anywhere', () => {
    // Assembled at runtime so no JWT- or PEM-shaped text sits in the repository.
    const jwtLike = ['ey', 'J', 'EXAMPLEheader', '.', 'ey', 'J', 'EXAMPLEpayload'].join('');
    const pemLike = ['-----BEGIN', 'EXAMPLE', 'KEY-----'].join(' ');
    for (const value of [
      'Bearer abc.def',
      jwtLike,
      'EXAMPLE-sim-token-12',
      pemLike,
      'access_token=abc',
    ]) {
      expect(looksSecretShaped(value)).toBe(true);
      expect(
        providerEventSchema.safeParse({ ...event, failureCode: value.slice(0, 64) }).success,
      ).toBe(false);
    }
    expect(looksSecretShaped('entra_50126')).toBe(false);
  });
});

describe('provider action state (§5.2)', () => {
  it('validates and bounds the state at 2 KiB', () => {
    expect(() =>
      validateActionState({
        v: 1,
        phase: 'pre',
        pre: { uid: 'u-1', enabled: true },
        at: '2026-11-10T12:00:00.000Z',
      }),
    ).not.toThrow();
    expect(() =>
      validateActionState({
        v: 1,
        phase: 'pre',
        pre: { a: 'x'.repeat(600) },
        at: '2026-11-10T12:00:00.000Z',
      }),
    ).toThrow();
    const big = Object.fromEntries(
      Array.from({ length: 10 }, (_, i) => [`k${i}`, 'x'.repeat(300)]),
    );
    expect(() =>
      validateActionState({ v: 1, phase: 'pre', pre: big, at: '2026-11-10T12:00:00.000Z' }),
    ).toThrow('provider_state_too_large');
  });
});
