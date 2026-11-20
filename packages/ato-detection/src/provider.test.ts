import { describe, expect, it } from 'vitest';
import {
  adapterSupports,
  normalizeProviderEvent,
  providerEventKey,
  providerEventSchema,
  ProviderRegistry,
  type IdentityProviderAdapter,
  type ProviderEvent,
  type ProviderIdentityRef,
  type ProviderStream,
} from './provider';
import {
  describeProviderAdapterContract,
  FAKE_PROVIDER_CAPABILITIES,
  FakeIdentityProviderAdapter,
} from './testing';

const identity: ProviderIdentityRef = {
  provider: 'fake',
  externalId: 'fake-user-0001',
  primaryEmail: 'user@tenant.example',
};

const T = '2026-11-18T10:00:00.000Z';

function event(
  stream: ProviderStream,
  n: number,
  extra: Partial<ProviderEvent> = {},
): ProviderEvent {
  const base: ProviderEvent = {
    provider: 'fake',
    eventId: `fake-${stream}-${n}`,
    stream,
    occurredAt: T,
    identity,
  };
  switch (stream) {
    case 'sign_ins':
      return {
        ...base,
        outcome: 'success',
        ip: '198.51.100.7',
        userAgent: 'Mozilla/5.0',
        ...extra,
      };
    case 'oauth_consents':
      return {
        ...base,
        oauth: { appIdHash: 'ab'.repeat(16), scopes: ['mail.read'], consentType: 'user' },
        ...extra,
      };
    case 'mailbox_audit':
    case 'forwarding_changes':
    case 'delegation_changes':
      return {
        ...base,
        mailbox: { change: 'forwarding_added', targetDomain: 'drop.example' },
        ...extra,
      };
    case 'risk_events':
      return { ...base, riskLevel: 'high', riskDetail: 'unfamiliar_features', ...extra };
    default:
      return { ...base, ...extra };
  }
}

function scripted(): FakeIdentityProviderAdapter {
  const adapter = new FakeIdentityProviderAdapter({ pollsUntilConfirmed: 2 });
  adapter.addIdentity('user@tenant.example', identity);
  for (const stream of ['sign_ins', 'mailbox_audit', 'oauth_consents'] as const) {
    adapter.script(
      stream,
      [1, 2, 3, 4, 5].map((n) => event(stream, n)),
    );
  }
  return adapter;
}

describeProviderAdapterContract('FakeIdentityProviderAdapter', scripted, {
  identity,
  address: 'USER@tenant.example',
  streamsWithEvents: ['sign_ins', 'mailbox_audit', 'oauth_consents'],
  injectIngestFailure: (a) =>
    (a as FakeIdentityProviderAdapter).failNext('ingest', { code: 'auth_error', retryable: false }),
  injectThrottle: (a, stream) => (a as FakeIdentityProviderAdapter).throttleNext(stream, 2500),
  effects: (a) => (a as FakeIdentityProviderAdapter).effects,
  maxPolls: 3,
});

describeProviderAdapterContract(
  'FakeIdentityProviderAdapter without rollback capabilities',
  () => {
    const adapter = new FakeIdentityProviderAdapter({
      capabilities: {
        streams: { sign_ins: { supported: true } },
        actions: {
          revoke_sessions: { supported: true, rollback: false, confirmation: 'synchronous' },
        },
      },
    });
    adapter.addIdentity('user@tenant.example', identity);
    adapter.script(
      'sign_ins',
      [1, 2, 3].map((n) => event('sign_ins', n)),
    );
    return adapter;
  },
  { identity, address: 'user@tenant.example', streamsWithEvents: ['sign_ins'] },
);

describe('providerEventSchema (strict, D15)', () => {
  it('accepts every scripted stream shape', () => {
    for (const stream of [
      'sign_ins',
      'risk_events',
      'oauth_consents',
      'mailbox_audit',
      'forwarding_changes',
      'delegation_changes',
      'session_events',
    ] as const) {
      expect(providerEventSchema.safeParse(event(stream, 1)).success, stream).toBe(true);
    }
  });

  it('refuses unknown keys, provider mismatch and missing stream-specific parts', () => {
    expect(providerEventSchema.safeParse({ ...event('sign_ins', 1), raw: {} }).success).toBe(false);
    expect(
      providerEventSchema.safeParse({ ...event('sign_ins', 1), provider: 'google_workspace' })
        .success,
    ).toBe(false);
    const { outcome: _o, ...noOutcome } = event('sign_ins', 1);
    expect(providerEventSchema.safeParse(noOutcome).success).toBe(false);
    const { oauth: _a, ...noOauth } = event('oauth_consents', 1);
    expect(providerEventSchema.safeParse(noOauth).success).toBe(false);
    const { mailbox: _m, ...noMailbox } = event('mailbox_audit', 1);
    expect(providerEventSchema.safeParse(noMailbox).success).toBe(false);
  });

  it('refuses token- or secret-shaped values and non-IP literals', () => {
    const jwtLike = ['eyJ', 'a'.repeat(12), '.', 'b'.repeat(12)].join('');
    const longRun = 'Q'.repeat(48);
    expect(providerEventSchema.safeParse(event('sign_ins', 1, { eventId: jwtLike })).success).toBe(
      false,
    );
    expect(
      providerEventSchema.safeParse({
        ...event('sign_ins', 1),
        identity: { ...identity, externalId: longRun },
      }).success,
    ).toBe(false);
    expect(
      providerEventSchema.safeParse(event('sign_ins', 1, { ip: 'host.example' })).success,
    ).toBe(false);
    expect(
      providerEventSchema.safeParse(event('sign_ins', 1, { eventId: 'line\nbreak' })).success,
    ).toBe(false);
  });
});

describe('ProviderRegistry (D15)', () => {
  const realLike = (kind: 'microsoft_entra' | 'google_workspace') =>
    ({ ...new FakeIdentityProviderAdapter(), kind }) as unknown as IdentityProviderAdapter;

  it('is empty by default and registers the fake only when enabled in local/ci', () => {
    const r = new ProviderRegistry();
    expect(r.size).toBe(0);
    r.registerFake(new FakeIdentityProviderAdapter(), { enabled: false, appEnv: 'local' });
    expect(r.size).toBe(0);
    expect(() =>
      r.registerFake(new FakeIdentityProviderAdapter(), { enabled: true, appEnv: 'production' }),
    ).toThrow(/only in local and ci/);
    r.registerFake(new FakeIdentityProviderAdapter(), { enabled: true, appEnv: 'ci' });
    expect(r.kinds()).toEqual(['fake']);
  });

  it('refuses the fake through register and duplicate kinds', () => {
    const r = new ProviderRegistry();
    expect(() => r.register(new FakeIdentityProviderAdapter())).toThrow(/registerFake/);
    r.register(realLike('microsoft_entra'));
    expect(() => r.register(realLike('microsoft_entra'))).toThrow(/already registered/);
    expect(r.get('microsoft_entra')).toBeDefined();
    expect(r.get('google_workspace')).toBeUndefined();
  });

  it('adapterSupports reads the declared capabilities', () => {
    const a = new FakeIdentityProviderAdapter();
    expect(adapterSupports(a, 'revoke_sessions')).toBe(true);
    expect(adapterSupports(a, 'require_password_reset')).toBe(
      FAKE_PROVIDER_CAPABILITIES.actions.require_password_reset?.supported === true,
    );
    expect(adapterSupports(a, 'suspend_account')).toBe(false);
  });
});

describe('normalizeProviderEvent', () => {
  it('a sign-in becomes an auth observation of source idp_sign_in with a device label', () => {
    const o = normalizeProviderEvent(
      event('sign_ins', 1, {
        outcome: 'success',
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      }),
    );
    expect(o).toMatchObject({
      type: 'auth',
      source: 'idp_sign_in',
      channel: 'idp',
      outcome: 'success',
      ip: '198.51.100.7',
      ipPrefix: '198.51.100.0/24',
      geo: null,
    });
    if (o.type !== 'auth') throw new Error('auth expected');
    expect(o.device?.hash).toMatch(/^[0-9a-f]{16}$/);
    expect(o.key).toBe(providerEventKey(event('sign_ins', 1)));
  });

  it('PX1: a provider device without a user agent keeps its hash and structured label', () => {
    const base = event('sign_ins', 4);
    delete base.userAgent;
    const o = normalizeProviderEvent({
      ...base,
      deviceIdHash: '0123456789abcdef',
      deviceLabel: 'Edge · Windows 10',
    });
    expect(o.type === 'auth' && o.device).toEqual({
      hash: '0123456789abcdef',
      label: 'Edge · Windows 10',
    });
    const unlabelled = normalizeProviderEvent({ ...base, deviceIdHash: '0123456789abcdef' });
    expect(unlabelled.type === 'auth' && unlabelled.device?.label).toBe('Provider device');
    expect(providerEventSchema.safeParse({ ...base, deviceLabel: 'x'.repeat(97) }).success).toBe(
      false,
    );
  });

  it('interrupted maps to mfa_required, failure to failure', () => {
    const a = normalizeProviderEvent(event('sign_ins', 2, { outcome: 'interrupted' }));
    const b = normalizeProviderEvent(
      event('sign_ins', 3, { outcome: 'failure', failureCode: 'bad_password' }),
    );
    expect(a.type === 'auth' && a.outcome).toBe('mfa_required');
    expect(b.type === 'auth' && b.outcome).toBe('failure');
  });

  it('a forwarding change becomes a provider observation with domain novelty from context', () => {
    const fresh = normalizeProviderEvent(event('forwarding_changes', 1));
    const known = normalizeProviderEvent(event('forwarding_changes', 1), {
      knownDomains: new Set(['drop.example']),
    });
    expect(fresh).toMatchObject({
      type: 'provider',
      stream: 'forwarding_changes',
      mailbox: {
        change: 'forwarding_added',
        targetDomain: 'drop.example',
        targetDomainKnown: false,
      },
    });
    expect(known.type === 'provider' && known.mailbox?.targetDomainKnown).toBe(true);
  });

  it('duplicate deliveries of one event id share the same source key (dedupe)', () => {
    const a = providerEventKey(event('risk_events', 9));
    const redelivered: ProviderEvent = {
      ...event('risk_events', 9),
      occurredAt: '2026-11-18T11:00:00.000Z',
    };
    const b = providerEventKey(redelivered);
    expect(a).toBe(b);
    expect(a).not.toBe(providerEventKey(event('risk_events', 10)));
    expect(a.length).toBeLessThanOrEqual(64);
  });

  it('refuses an invalid event instead of normalizing it', () => {
    expect(() => normalizeProviderEvent({ ...event('sign_ins', 1), ip: 'not-an-ip' })).toThrow();
  });
});
