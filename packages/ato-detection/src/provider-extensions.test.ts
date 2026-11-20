/**
 * Step 8.5 port extensions of the 8.4 package (design note §0.2, merge notes M2/M3): PX2
 * (per-integration adapter factories in `ProviderRegistry`) and PX3 (`RuleContext.historical`).
 * PX1 (`deviceLabel`) is covered in `provider.test.ts`.
 */
import { describe, expect, it } from 'vitest';
import {
  ProviderRegistry,
  type IdentityProviderAdapter,
  type ProviderIntegrationRef,
} from './provider';
import { capabilitySet } from './rules/catalogue';
import { evaluateRules } from './rules/evaluate';
import type { RuleInput } from './rules/types';
import { mergeAtoSettings } from './settings';
import { FakeIdentityProviderAdapter } from './testing/fake-provider';
import {
  accountSnapshot,
  authObservation,
  matureBaselineView,
  providerObservation,
  ruleContext,
  ruleInput,
  windowSnapshot,
} from './testing/builders';

const ALL_CAPS = capabilitySet(
  {
    geoip_city: true,
    geoip_asn: true,
    geoip_anonymous: true,
    dnsbl: true,
    breach_intel: true,
    bec_observations: true,
  },
  ['sign_ins', 'risk_events', 'oauth_consents', 'mailbox_audit', 'forwarding_changes'],
);

const run = (input: Partial<RuleInput>) =>
  evaluateRules(ruleInput(input), mergeAtoSettings({}), ALL_CAPS);

interface Row extends ProviderIntegrationRef {
  publicId: string;
}

describe('PX2: per-integration adapter factories', () => {
  const bound = (row: Row): IdentityProviderAdapter =>
    ({
      ...new FakeIdentityProviderAdapter(),
      kind: 'microsoft_entra',
      version: `bound:${row.publicId}`,
    }) as unknown as IdentityProviderAdapter;

  it('builds one adapter per integration through the kind factory', () => {
    const r = new ProviderRegistry<Row>();
    const calls: string[] = [];
    r.registerFactory('microsoft_entra', (row) => {
      calls.push(row.publicId);
      return bound(row);
    });
    const a = r.adapterFor({
      id: 1n,
      organizationId: 7n,
      provider: 'microsoft_entra',
      publicId: 'a',
    });
    const b = r.adapterFor({
      id: 2n,
      organizationId: 8n,
      provider: 'microsoft_entra',
      publicId: 'b',
    });
    expect(a?.version).toBe('bound:a');
    expect(b?.version).toBe('bound:b');
    expect(calls).toEqual(['a', 'b']);
    expect(r.hasFactory('microsoft_entra')).toBe(true);
    expect(r.get('microsoft_entra')).toBeUndefined();
    expect(r.kinds()).toEqual(['microsoft_entra']);
    expect(r.size).toBe(1);
    expect(r.singletonKinds()).toEqual([]);
    expect(
      r.adapterFor({ id: 3n, organizationId: 7n, provider: 'google_workspace', publicId: 'c' }),
    ).toBeUndefined();
  });

  it('the fake adapter keeps working: its factory is its single instance', () => {
    const fake = new FakeIdentityProviderAdapter();
    const r = new ProviderRegistry<Row>().registerFake(fake, { enabled: true, appEnv: 'local' });
    expect(r.adapterFor({ id: 1n, organizationId: 7n, provider: 'fake', publicId: 'x' })).toBe(
      fake,
    );
    expect(r.adapterFor({ id: 2n, organizationId: 9n, provider: 'fake', publicId: 'y' })).toBe(
      fake,
    );
    expect(r.get('fake')).toBe(fake);
    expect(r.singletonKinds()).toEqual(['fake']);
    expect(r.hasFactory('fake')).toBe(false);
  });

  it('refuses a fake factory and a kind registered twice', () => {
    const r = new ProviderRegistry<Row>();
    expect(() => r.registerFactory('fake', bound)).toThrow(/registerFake/);
    r.registerFactory('google_workspace', bound);
    expect(() => r.registerFactory('google_workspace', bound)).toThrow(/already registered/);
    const google = {
      ...new FakeIdentityProviderAdapter(),
      kind: 'google_workspace',
    } as unknown as IdentityProviderAdapter;
    expect(() => r.register(google)).toThrow(/already registered/);
    expect(r.kinds()).toEqual(['google_workspace']);
  });
});

describe('PX3: historical rule context', () => {
  const mailbox = accountSnapshot({ kind: 'mailbox' });
  const failure = authObservation({ outcome: 'failure', failureCode: 'bad_password' });

  it('records every signal informational, also rules that are not baseline-relative', () => {
    const live = run({
      account: mailbox,
      observation: failure,
      windows: windowSnapshot({ minutes: { af: [10] } }),
    });
    expect(live.map((c) => c.code)).toContain('ato.auth.bruteforce');
    expect(live.find((c) => c.code === 'ato.auth.bruteforce')!.informational).toBe(false);
    const historical = run({
      account: mailbox,
      observation: failure,
      windows: windowSnapshot({ minutes: { af: [10] } }),
      context: ruleContext({ historical: true }),
    });
    expect(historical.map((c) => c.code)).toEqual(live.map((c) => c.code));
    expect(historical.every((c) => c.informational)).toBe(true);
  });

  it('provider observations (M1 external forwarding) are informational when historical', () => {
    const forwarding = providerObservation({
      stream: 'forwarding_changes',
      mailbox: {
        change: 'forwarding_added',
        targetDomain: 'exfil.example',
        targetDomainKnown: false,
        ruleHash: null,
        ruleTraits: [],
        clientType: null,
        clientTypeKnown: true,
      },
    });
    const live = run({ account: mailbox, observation: forwarding, baseline: matureBaselineView() });
    expect(live.length).toBeGreaterThan(0);
    expect(live.some((c) => !c.informational)).toBe(true);
    const historical = run({
      account: mailbox,
      observation: forwarding,
      baseline: matureBaselineView(),
      context: ruleContext({ historical: true }),
    });
    expect(historical.map((c) => c.code)).toEqual(live.map((c) => c.code));
    expect(historical.every((c) => c.informational)).toBe(true);
  });

  it('defaults to live (historical omitted or false)', () => {
    const c = run({
      account: mailbox,
      observation: failure,
      windows: windowSnapshot({ minutes: { af: [10] } }),
      context: ruleContext({ historical: false }),
    });
    expect(c.find((x) => x.code === 'ato.auth.bruteforce')!.informational).toBe(false);
  });
});

describe('M3: provider inbox-rule traits reach M2', () => {
  it("maps the adapters' trait vocabulary onto the 8.4 codes (evidence in 8.4 codes)", () => {
    const rule = (ruleTraits: string[]) =>
      run({
        account: accountSnapshot({ kind: 'mailbox' }),
        observation: providerObservation({
          stream: 'mailbox_audit',
          mailbox: {
            change: 'inbox_rule_added',
            targetDomain: null,
            targetDomainKnown: false,
            ruleHash: 'abcdef0123456789',
            ruleTraits,
            clientType: null,
            clientTypeKnown: true,
          },
        }),
      }).find((c) => c.code === 'ato.mailbox.suspicious_inbox_rule');
    const hit = rule([
      'forwards_external',
      'moves_to_rarely_used_folder',
      'marks_read',
      'matches_finance_keywords',
    ]);
    expect(hit?.evidence.codes).toEqual([
      'forward',
      'move_rare_folder',
      'mark_read',
      'finance_keywords',
    ]);
    // The 8.4 vocabulary still works unchanged; non-suspicious traits alone do not fire.
    expect(rule(['delete'])?.evidence.codes).toEqual(['delete']);
    expect(rule(['moves_to_folder', 'stops_processing'])).toBeUndefined();
  });
});
