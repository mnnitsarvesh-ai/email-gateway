import { describe, expect, it } from 'vitest';
import { capabilitySet, type CapabilitySet } from './rules/catalogue';
import { ATO_ACCOUNT_CHANGE_ACTIONS } from '@email-gateway/event-contracts';
import { DATA_ACCESS_ACTIONS, evaluateRules } from './rules/evaluate';
import type { RuleInput, SignalCandidate } from './rules/types';
import { mergeAtoSettings, type AtoSettingsInput } from './settings';
import {
  accountChangeObservation,
  accountSnapshot,
  authObservation,
  geoView,
  matureBaselineView,
  outboundObservation,
  providerObservation,
  ruleContext,
  ruleInput,
  seenToday,
  submissionObservation,
  T0,
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
  [
    'sign_ins',
    'risk_events',
    'oauth_consents',
    'mailbox_audit',
    'forwarding_changes',
    'delegation_changes',
    'session_events',
  ],
);

function run(
  input: Partial<RuleInput>,
  settings: AtoSettingsInput = {},
  caps: CapabilitySet = ALL_CAPS,
): SignalCandidate[] {
  return evaluateRules(ruleInput(input), mergeAtoSettings(settings), caps);
}
const codes = (c: SignalCandidate[]) => c.map((x) => x.code).sort();
const one = (c: SignalCandidate[], code: string) => {
  const found = c.find((x) => x.code === code);
  if (!found) throw new Error(`${code} did not fire; got ${codes(c).join(', ')}`);
  return found;
};

const mailbox = accountSnapshot({ kind: 'mailbox' });
const connector = accountSnapshot({ kind: 'smtp_connector' });
const mature = matureBaselineView();
const failure = authObservation({ outcome: 'failure', failureCode: 'bad_password' });

describe('authentication rules', () => {
  it('A1 fires at 10 failures in 15 minutes, not at 9', () => {
    expect(
      codes(run({ observation: failure, windows: windowSnapshot({ minutes: { af: [10] } }) })),
    ).toContain('ato.auth.bruteforce');
    expect(
      codes(run({ observation: failure, windows: windowSnapshot({ minutes: { af: [9] } }) })),
    ).not.toContain('ato.auth.bruteforce');
    // Failures older than the window do not count.
    const old = Array<number>(20).fill(0);
    old[16] = 10;
    expect(
      codes(run({ observation: failure, windows: windowSnapshot({ minutes: { af: old } }) })),
    ).not.toContain('ato.auth.bruteforce');
    const a1 = one(
      run({ observation: failure, windows: windowSnapshot({ minutes: { af: [12] } }) }),
      'ato.auth.bruteforce',
    );
    expect(a1.evidence).toEqual({ failures: 12, windowMinutes: 15, threshold: 10 });
    expect(a1.dedupeWindowMinutes).toBe(60);
    expect(a1.sourceKind).toBe('auth_event');
  });

  it('A1 thresholds are tenant-tunable and rules can be disabled', () => {
    const w = windowSnapshot({ minutes: { af: [5] } });
    expect(
      codes(
        run(
          { observation: failure, windows: w },
          { rules: { 'ato.auth.bruteforce': { params: { failures: 5 } } } },
        ),
      ),
    ).toContain('ato.auth.bruteforce');
    expect(
      codes(
        run(
          { observation: failure, windows: windowSnapshot({ minutes: { af: [50] } }) },
          { rules: { 'ato.auth.bruteforce': { enabled: false } } },
        ),
      ),
    ).not.toContain('ato.auth.bruteforce');
  });

  it('A2 success after ≥ 5 failures; strong with ≥ 3 failure IPs or a flagged IP', () => {
    const w = windowSnapshot({ minutes: { af: [5] }, distinctFailureIps30m: 1 });
    const a2 = one(run({ windows: w }), 'ato.auth.success_after_failures');
    expect(a2.strength).toBe('moderate');
    expect(a2.weight).toBe(30);
    expect(codes(run({ windows: windowSnapshot({ minutes: { af: [4] } }) }))).not.toContain(
      'ato.auth.success_after_failures',
    );
    const strong = one(
      run({ windows: windowSnapshot({ minutes: { af: [5] }, distinctFailureIps30m: 3 }) }),
      'ato.auth.success_after_failures',
    );
    expect(strong.strength).toBe('strong');
    expect(strong.weight).toBe(40);
    const flagged = one(
      run({
        observation: authObservation({ ipFlag: { flagged: true, distinctAccounts: 12 } }),
        windows: w,
      }),
      'ato.auth.success_after_failures',
    );
    expect(flagged.strength).toBe('strong');
    // Dedupe per success event.
    const other = one(
      run({ observation: authObservation({ key: 'evt-auth-2' }), windows: w }),
      'ato.auth.success_after_failures',
    );
    expect(other.dedupeKey).not.toBe(a2.dedupeKey);
  });

  it('A3 MFA failures (users only) and A4 lockout', () => {
    const mfa = authObservation({ outcome: 'mfa_failure', source: 'portal_mfa' });
    expect(
      codes(run({ observation: mfa, windows: windowSnapshot({ minutes: { mf: [3] } }) })),
    ).toContain('ato.auth.mfa_failures');
    expect(
      codes(run({ observation: mfa, windows: windowSnapshot({ minutes: { mf: [2] } }) })),
    ).not.toContain('ato.auth.mfa_failures');
    expect(
      codes(
        run({
          observation: mfa,
          account: mailbox,
          windows: windowSnapshot({ minutes: { mf: [3] } }),
        }),
      ),
    ).not.toContain('ato.auth.mfa_failures');
    expect(codes(run({ observation: authObservation({ outcome: 'locked' }) }))).toContain(
      'ato.auth.lockout',
    );
    expect(codes(run({ observation: { ...failure, lockedByThrottle: true } }))).toContain(
      'ato.auth.lockout',
    );
    expect(
      codes(run({ observation: authObservation({ outcome: 'locked' }), account: connector })),
    ).not.toContain('ato.auth.lockout');
  });
});

describe('access context rules (baseline-relative)', () => {
  const newIp = authObservation({
    ip: '203.0.113.5',
    ipPrefix: '203.0.113.0/24',
    geo: geoView({ country: 'BR', asn: 64502 }),
  });

  it('C1/C2/G1 fire for a new prefix, ASN and country of a mature account', () => {
    const c = run({ observation: newIp, baseline: mature });
    expect(codes(c)).toEqual(
      expect.arrayContaining([
        'ato.access.new_ip_prefix',
        'ato.access.new_asn',
        'ato.geo.new_country',
      ]),
    );
    expect(one(c, 'ato.access.new_ip_prefix').seen).toEqual({
      kind: 'prefixes',
      value: '203.0.113.0/24',
    });
    expect(one(c, 'ato.geo.new_country').evidence).toEqual({ country: 'BR' });
  });

  it('nothing baseline-relative for immature accounts or known values', () => {
    expect(
      codes(run({ observation: newIp, baseline: matureBaselineView({ mature: false }) })),
    ).toEqual([]);
    expect(codes(run({ observation: newIp, baseline: null }))).toEqual([]);
    expect(codes(run({ observation: authObservation(), baseline: mature }))).toEqual([]);
  });

  it('seen today, trusted networks and trusted contexts suppress novelty', () => {
    const seen = seenToday({ prefixes: ['203.0.113.0/24'], countries: ['BR'], asns: ['64502'] });
    expect(codes(run({ observation: newIp, baseline: mature, seen }))).toEqual([]);
    const trusted = ruleContext({ trustedNetworks: ['203.0.113.0/24'] });
    expect(codes(run({ observation: newIp, baseline: mature, context: trusted }))).toEqual([]);
    const ctx = ruleContext({
      trustedContexts: [{ kind: 'country', value: 'BR', expiresAt: new Date(T0.getTime() + 1000) }],
    });
    expect(codes(run({ observation: newIp, baseline: mature, context: ctx }))).not.toContain(
      'ato.geo.new_country',
    );
    const expired = ruleContext({
      trustedContexts: [{ kind: 'country', value: 'BR', expiresAt: new Date(T0.getTime() - 1) }],
    });
    expect(codes(run({ observation: newIp, baseline: mature, context: expired }))).toContain(
      'ato.geo.new_country',
    );
  });

  it('learning period records informational candidates', () => {
    const c = run({
      observation: newIp,
      baseline: mature,
      context: ruleContext({ learning: true }),
    });
    expect(c.length).toBeGreaterThan(0);
    expect(c.every((x) => x.informational)).toBe(true);
  });

  it('capabilities: no GeoIP → G1 and C2 unavailable, C1 still fires', () => {
    const c = run({ observation: newIp, baseline: mature }, {}, capabilitySet({}));
    expect(codes(c)).toEqual(['ato.access.new_ip_prefix']);
  });

  it('C3 new device and C4 unusual hour', () => {
    const device = authObservation({
      device: { hash: 'ffffffffffffffff', label: 'Firefox 130 · Linux · desktop' },
    });
    expect(
      one(run({ observation: device, baseline: mature }), 'ato.access.new_device').evidence,
    ).toEqual({ deviceLabel: 'Firefox 130 · Linux · desktop' });
    const night = authObservation({ occurredAt: new Date('2026-11-18T03:00:00.000Z') });
    const c4 = one(run({ observation: night, baseline: mature }), 'ato.access.unusual_hour');
    expect(c4.evidence).toEqual({ permille: 0, baseline: 110 });
    // 08:00 is within ±1 hour of the busy hours (hour 7..9 sum 20 of 110 = 181 ‰).
    expect(
      codes(
        run({
          observation: authObservation({ occurredAt: new Date('2026-11-18T08:00:00.000Z') }),
          baseline: mature,
        }),
      ),
    ).not.toContain('ato.access.unusual_hour');
    const thin = matureBaselineView({ hourHistogram: Array<number>(24).fill(1) });
    expect(codes(run({ observation: night, baseline: thin }))).not.toContain(
      'ato.access.unusual_hour',
    );
  });

  it('C5 first direct API login of a portal-only user', () => {
    expect(
      codes(run({ observation: authObservation({ channel: 'api' }), baseline: mature })),
    ).toContain('ato.access.channel_change');
    expect(
      codes(
        run({
          observation: authObservation({ channel: 'api' }),
          baseline: matureBaselineView({ channels: ['portal', 'api'] }),
        }),
      ),
    ).not.toContain('ato.access.channel_change');
  });

  it('C6 concurrent prefixes for connectors above the usual maximum', () => {
    const smtp = authObservation({ source: 'smtp_auth', channel: 'smtp' });
    expect(
      codes(
        run({
          observation: smtp,
          account: connector,
          windows: windowSnapshot({ distinctSuccessPrefixes60m: 4 }),
        }),
      ),
    ).toContain('ato.access.concurrent_ips');
    expect(
      codes(
        run({
          observation: smtp,
          account: connector,
          windows: windowSnapshot({ distinctSuccessPrefixes60m: 3 }),
        }),
      ),
    ).not.toContain('ato.access.concurrent_ips');
    expect(
      codes(
        run({
          observation: smtp,
          account: connector,
          baseline: matureBaselineView({ maxHourlyPrefixes: 5 }),
          windows: windowSnapshot({ distinctSuccessPrefixes60m: 5 }),
        }),
      ),
    ).not.toContain('ato.access.concurrent_ips');
  });
});

describe('geography rules', () => {
  const london = authObservation({
    ip: '198.51.100.7',
    ipPrefix: '198.51.100.0/24',
    geo: geoView({
      country: 'GB',
      latitude: 51.5074,
      longitude: -0.1278,
      accuracyKm: 10,
      asn: 64501,
    }),
    occurredAt: new Date(T0.getTime() + 30 * 60_000),
  });
  const prevMumbai = {
    at: T0,
    country: 'IN',
    latitude: 19.076,
    longitude: 72.8777,
    accuracyKm: 20,
    anonymizerFlags: 0,
    trusted: false,
  };

  it('G2 impossible travel, downgraded through an anonymizer, suppressed when trusted', () => {
    const g2 = one(
      run({ observation: london, account: accountSnapshot({ lastSuccess: prevMumbai }) }),
      'ato.geo.impossible_travel',
    );
    expect(g2.strength).toBe('moderate');
    expect(g2.weight).toBe(30);
    expect(g2.evidence).toMatchObject({ fromCountry: 'IN', toCountry: 'GB', elapsedMinutes: 30 });
    const anon = one(
      run({
        observation: { ...london, geo: geoView({ ...london.geo!, anonymizerFlags: 1 }) },
        account: accountSnapshot({ lastSuccess: prevMumbai }),
      }),
      'ato.geo.impossible_travel',
    );
    expect(anon.strength).toBe('weak');
    expect(anon.weight).toBe(10);
    expect(
      codes(
        run({
          observation: { ...london, trustedNetwork: true },
          account: accountSnapshot({ lastSuccess: prevMumbai }),
        }),
      ),
    ).not.toContain('ato.geo.impossible_travel');
    expect(
      codes(
        run({
          observation: london,
          account: accountSnapshot({ lastSuccess: { ...prevMumbai, accuracyKm: 1000 } }),
        }),
      ),
    ).not.toContain('ato.geo.impossible_travel');
    expect(
      codes(
        run(
          { observation: london, account: accountSnapshot({ lastSuccess: prevMumbai }) },
          {},
          capabilitySet({}),
        ),
      ),
    ).not.toContain('ato.geo.impossible_travel');
  });

  it('G3 inconsistent sessions within 60 minutes', () => {
    const obs = {
      ...london,
      concurrentLocations: [
        { country: 'IN', latitude: 19.076, longitude: 72.8777, accuracyKm: 20, at: T0 },
      ],
    };
    expect(one(run({ observation: obs }), 'ato.geo.inconsistent_sessions').evidence).toMatchObject({
      count: 2,
      windowMinutes: 60,
    });
    const stale = {
      ...london,
      concurrentLocations: [
        {
          country: 'IN',
          latitude: 19.076,
          longitude: 72.8777,
          accuracyKm: 20,
          at: new Date(T0.getTime() - 3_600_000),
        },
      ],
    };
    expect(codes(run({ observation: stale }))).not.toContain('ato.geo.inconsistent_sessions');
  });

  it('G4 anonymizer only with the Anonymous IP capability', () => {
    const vpn = authObservation({ geo: geoView({ anonymizerFlags: 1 }) });
    expect(codes(run({ observation: vpn }))).toContain('ato.geo.anonymizer');
    expect(codes(run({ observation: vpn }, {}, capabilitySet({ geoip_city: true })))).not.toContain(
      'ato.geo.anonymizer',
    );
  });
});

describe('threat intelligence rules', () => {
  const listed = (
    severity: 'low' | 'medium' | 'high' | 'critical',
    confidence: 'high' | 'medium' | 'low' | null = null,
  ) =>
    authObservation({
      reputation: {
        status: 'listed',
        severity,
        category: 'c2',
        confidence,
        providers: ['local_feed'],
      },
    });

  it('T1 strong for high/critical severity, moderate 25 otherwise; confidence wins when present', () => {
    expect(
      one(run({ observation: listed('critical') }), 'ato.ti.malicious_ip_success').strength,
    ).toBe('strong');
    const med = one(run({ observation: listed('medium') }), 'ato.ti.malicious_ip_success');
    expect(med.strength).toBe('moderate');
    expect(med.weight).toBe(25);
    expect(
      one(run({ observation: listed('critical', 'medium') }), 'ato.ti.malicious_ip_success')
        .strength,
    ).toBe('moderate');
    expect(
      one(run({ observation: listed('low', 'high') }), 'ato.ti.malicious_ip_success').strength,
    ).toBe('strong');
    expect(
      one(
        run({ observation: authObservation({ blockedNetwork: true }) }),
        'ato.ti.malicious_ip_success',
      ).strength,
    ).toBe('strong');
    expect(
      codes(
        run({
          observation: authObservation({
            reputation: {
              status: 'error',
              severity: null,
              category: null,
              confidence: null,
              providers: [],
            },
          }),
        }),
      ),
    ).toEqual([]);
  });

  it('T2 DNSBL, T3 attack source, T4 breach, T5 campaign target, T6 failed from listed', () => {
    expect(codes(run({ observation: authObservation({ dnsblListed: true }) }))).toContain(
      'ato.ti.dnsbl_listed_success',
    );
    expect(
      codes(run({ observation: authObservation({ dnsblListed: true }) }, {}, capabilitySet({}))),
    ).not.toContain('ato.ti.dnsbl_listed_success');
    expect(
      one(
        run({ observation: authObservation({ ipFlag: { flagged: true, distinctAccounts: 14 } }) }),
        'ato.ti.attack_source_success',
      ).evidence,
    ).toMatchObject({ distinctAccounts: 14 });
    expect(codes(run({ observation: authObservation({ breachListed: true }) }))).toContain(
      'ato.ti.breach_listed',
    );
    expect(
      codes(run({ observation: { ...failure, ipFlag: { flagged: true, distinctAccounts: 11 } } })),
    ).toContain('ato.ti.targeted_by_campaign');
    expect(codes(run({ observation: { ...failure, blockedNetwork: true } }))).toContain(
      'ato.ti.malicious_ip_attempt',
    );
  });
});

describe('account change rules', () => {
  it.each([
    ['auth.refresh_token_reused', 'ato.account.refresh_token_reuse'],
    ['auth.mfa_disabled', 'ato.account.mfa_disabled'],
    ['auth.password_changed', 'ato.account.credentials_changed'],
    ['user.mfa_reset', 'ato.account.credentials_changed'],
    ['apikey.created', 'ato.account.persistence_created'],
    ['smtp_connector.secret_rotated', 'ato.account.persistence_created'],
    ['user.roles_changed', 'ato.account.privilege_change'],
    ['platform.override_started', 'ato.account.privilege_change'],
  ])('%s → %s', (action, code) => {
    const c = run({ observation: accountChangeObservation({ action }) });
    expect(codes(c)).toEqual([code]);
    expect(c[0]!.evidence).toEqual({ action });
    expect(c[0]!.sourceKind).toBe('audit');
  });

  it('K6 bulk data access at 20 in 60 minutes; session.revoked_all fires nothing', () => {
    const reveal = accountChangeObservation({ action: 'message.revealed' });
    expect(
      codes(run({ observation: reveal, windows: windowSnapshot({ minutes: { data: [20] } }) })),
    ).toEqual(['ato.account.bulk_data_access']);
    expect(
      codes(run({ observation: reveal, windows: windowSnapshot({ minutes: { data: [19] } }) })),
    ).toEqual([]);
    expect(
      codes(run({ observation: accountChangeObservation({ action: 'session.revoked_all' }) })),
    ).toEqual([]);
  });

  it('K6 counts operator and self releases (the audited release actions, WP3 deviation 1)', () => {
    expect([...DATA_ACCESS_ACTIONS].sort()).toEqual([
      'message.revealed',
      'quarantine.downloaded',
      'quarantine.release_requested',
      'quarantine.self_released',
    ]);
    for (const action of DATA_ACCESS_ACTIONS) {
      // Every data-access action is one the api actually emits as auth.account.changed.v1.
      expect(ATO_ACCOUNT_CHANGE_ACTIONS as readonly string[]).toContain(action);
      expect(
        codes(
          run({
            observation: accountChangeObservation({ action }),
            windows: windowSnapshot({ minutes: { data: [20] } }),
          }),
        ),
      ).toEqual(['ato.account.bulk_data_access']);
    }
    expect(ATO_ACCOUNT_CHANGE_ACTIONS as readonly string[]).not.toContain(
      'quarantine.entry_released',
    );
  });
});

describe('outbound rules', () => {
  const msg = outboundObservation();
  const base = { account: mailbox, observation: msg };

  it('O1 immature absolute thresholds (200/h, 1000/day), strong at 3× and ≥ 200', () => {
    expect(codes(run({ ...base, windows: windowSnapshot({ minutes: { msg: [201] } }) }))).toContain(
      'ato.outbound.volume_spike',
    );
    expect(
      codes(run({ ...base, windows: windowSnapshot({ minutes: { msg: [200] } }) })),
    ).not.toContain('ato.outbound.volume_spike');
    const day = Array<number>(24).fill(0);
    day[3] = 1001;
    const daily = one(
      run({ ...base, windows: windowSnapshot({ hourlyMessages: day }) }),
      'ato.outbound.volume_spike',
    );
    expect(daily.evidence).toEqual({ count: 1001, threshold: 1000, windowMinutes: 1440 });
    expect(daily.informational).toBe(false);
    const strong = one(
      run({ ...base, windows: windowSnapshot({ minutes: { msg: [600] } }) }),
      'ato.outbound.volume_spike',
    );
    expect(strong.strength).toBe('strong');
    expect(strong.weight).toBe(40);
    // Absolute (immature) thresholds are not informational in the learning period.
    expect(
      one(
        run({
          ...base,
          windows: windowSnapshot({ minutes: { msg: [201] } }),
          context: ruleContext({ learning: true }),
        }),
        'ato.outbound.volume_spike',
      ).informational,
    ).toBe(false);
  });

  it('O1 mature robust thresholds', () => {
    // max hourly 5 × 3000 ‰ = 15 < absMinPerHour 20 → threshold 20.
    expect(
      one(
        run({ ...base, baseline: mature, windows: windowSnapshot({ minutes: { msg: [21] } }) }),
        'ato.outbound.volume_spike',
      ).evidence,
    ).toEqual({ count: 21, threshold: 20, windowMinutes: 60 });
    expect(
      codes(
        run({ ...base, baseline: mature, windows: windowSnapshot({ minutes: { msg: [20] } }) }),
      ),
    ).not.toContain('ato.outbound.volume_spike');
    expect(
      one(
        run({
          ...base,
          baseline: mature,
          windows: windowSnapshot({ minutes: { msg: [21] } }),
          context: ruleContext({ learning: true }),
        }),
        'ato.outbound.volume_spike',
      ).informational,
    ).toBe(true);
  });

  it('O2 fan-out, O3 new domains, O6 unusual hour, O7 new client IP, O10 mismatch (mature only)', () => {
    expect(
      codes(
        run({
          ...base,
          baseline: mature,
          windows: windowSnapshot({ distinctExternalDomains60m: 20 }),
        }),
      ),
    ).toContain('ato.outbound.recipient_fanout');
    expect(
      codes(
        run({
          ...base,
          baseline: mature,
          windows: windowSnapshot({ distinctExternalDomains60m: 19 }),
        }),
      ),
    ).not.toContain('ato.outbound.recipient_fanout');
    expect(
      codes(
        run({
          ...base,
          baseline: matureBaselineView({ maxHourlyExternalDomains: 10 }),
          windows: windowSnapshot({ distinctExternalDomains60m: 25 }),
        }),
      ),
    ).not.toContain('ato.outbound.recipient_fanout');
    expect(
      one(
        run({
          ...base,
          baseline: mature,
          windows: windowSnapshot({ minutes: { ext: [20], newdom: [16] } }),
        }),
        'ato.outbound.new_recipient_domains',
      ).evidence,
    ).toEqual({ permille: 800, count: 20 });
    expect(
      codes(
        run({
          ...base,
          baseline: mature,
          windows: windowSnapshot({ minutes: { ext: [20], newdom: [15] } }),
        }),
      ),
    ).not.toContain('ato.outbound.new_recipient_domains');
    const hours = Array<number>(24).fill(0);
    hours[0] = 10;
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ occurredAt: new Date('2026-11-18T02:00:00.000Z') }),
          baseline: mature,
          windows: windowSnapshot({ hourlyMessages: hours }),
        }),
      ),
    ).toContain('ato.outbound.unusual_hour');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ clientIpPrefix: '203.0.113.0/24' }),
          baseline: mature,
        }),
      ),
    ).toContain('ato.outbound.new_client_ip');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ clientIpPrefix: '203.0.113.0/24' }),
          baseline: null,
        }),
      ),
    ).not.toContain('ato.outbound.new_client_ip');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ headerFromMatches: false }),
          baseline: mature,
          windows: windowSnapshot({ minutes: { hfm: [10] } }),
        }),
      ),
    ).toContain('ato.outbound.sender_identity_mismatch');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ headerFromMatches: false }),
          baseline: matureBaselineView({
            content: {
              becCategories: [],
              financial: 0,
              phishing: 0,
              spam: 0,
              fromMismatch: 3,
              massSubject: 0,
            },
          }),
          windows: windowSnapshot({ minutes: { hfm: [10] } }),
        }),
      ),
    ).not.toContain('ato.outbound.sender_identity_mismatch');
  });

  it('O4 attachment spread, O5 mass subject, O9 replies without parent', () => {
    const spread = { sha256: 'a'.repeat(64), type: 'application/zip', recipients: 20, domains: 5 };
    expect(
      one(
        run({ ...base, windows: windowSnapshot({ attachmentSpread: spread }) }),
        'ato.outbound.attachment_spread',
      ).evidence,
    ).toEqual({ count: 20, domainCount: 5, attachmentType: 'application_zip' });
    expect(
      codes(
        run({ ...base, windows: windowSnapshot({ attachmentSpread: { ...spread, domains: 4 } }) }),
      ),
    ).not.toContain('ato.outbound.attachment_spread');
    expect(
      codes(
        run({
          ...base,
          baseline: matureBaselineView({ attachmentTypes: [{ t: 'application/zip', n: 1 }] }),
          windows: windowSnapshot({ attachmentSpread: spread }),
        }),
      ),
    ).not.toContain('ato.outbound.attachment_spread');
    expect(codes(run({ ...base, windows: windowSnapshot({ subjectMessages60m: 30 }) }))).toContain(
      'ato.outbound.mass_subject',
    );
    expect(
      codes(run({ ...base, windows: windowSnapshot({ subjectMessages60m: 29 }) })),
    ).not.toContain('ato.outbound.mass_subject');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ replyWithoutParent: true }),
          windows: windowSnapshot({ minutes: { rnp: [5] } }),
        }),
      ),
    ).toContain('ato.outbound.reply_without_parent');
    expect(
      codes(
        run({
          account: mailbox,
          observation: outboundObservation({ replyWithoutParent: true }),
          windows: windowSnapshot({ minutes: { rnp: [4] } }),
        }),
      ),
    ).not.toContain('ato.outbound.reply_without_parent');
  });

  it('O8 connector sender spread on submissions', () => {
    const sub = submissionObservation();
    expect(
      codes(
        run({
          account: connector,
          observation: sub,
          windows: windowSnapshot({ distinctSenders60m: 20 }),
        }),
      ),
    ).toContain('ato.outbound.connector_sender_spread');
    expect(
      codes(
        run({
          account: connector,
          observation: sub,
          windows: windowSnapshot({ distinctSenders60m: 19 }),
        }),
      ),
    ).not.toContain('ato.outbound.connector_sender_spread');
    expect(
      codes(
        run({
          account: connector,
          observation: sub,
          baseline: matureBaselineView({ maxHourlySenders: 10 }),
          windows: windowSnapshot({ distinctSenders60m: 25 }),
        }),
      ),
    ).not.toContain('ato.outbound.connector_sender_spread');
  });

  it('connectors get outbound signals only for attributed messages', () => {
    const phishing = outboundObservation({
      findings: {
        phishing: true,
        phishingCodes: ['url.phishing_known'],
        malware: false,
        spam: false,
        becCategories: [],
        financial: false,
      },
    });
    expect(codes(run({ account: connector, observation: phishing }))).toEqual([]);
    expect(
      codes(run({ account: connector, observation: { ...phishing, connectorAttributed: true } })),
    ).toEqual(['ato.content.phishing_sent']);
  });
});

describe('outbound content rules', () => {
  const findings = {
    phishing: false,
    phishingCodes: [] as string[],
    malware: false,
    spam: false,
    becCategories: [] as string[],
    financial: false,
  };
  const mb = { account: mailbox };

  it('P1 phishing and P2 malware dedupe per message', () => {
    const p1 = one(
      run({
        ...mb,
        observation: outboundObservation({
          findings: {
            ...findings,
            phishing: true,
            phishingCodes: ['url.phishing_known', 'RSPAMD.PHISHING'],
          },
        }),
      }),
      'ato.content.phishing_sent',
    );
    expect(p1.strength).toBe('strong');
    expect(p1.evidence).toEqual({
      messageId: '101',
      codes: ['url.phishing_known', 'rspamd.phishing'],
    });
    expect(p1.messageRef).toEqual({ id: 101n, receivedAt: T0 });
    const other = one(
      run({
        ...mb,
        observation: outboundObservation({
          message: { id: 102n, receivedAt: T0 },
          findings: { ...findings, phishing: true },
        }),
      }),
      'ato.content.phishing_sent',
    );
    expect(other.dedupeKey).not.toBe(p1.dedupeKey);
    expect(
      codes(
        run({
          ...mb,
          observation: outboundObservation({ findings: { ...findings, malware: true } }),
        }),
      ),
    ).toEqual(['ato.content.malware_sent']);
  });

  it('P3 spam at 3 in 60 minutes', () => {
    const spam = outboundObservation({ findings: { ...findings, spam: true } });
    expect(
      codes(run({ ...mb, observation: spam, windows: windowSnapshot({ minutes: { spam: [3] } }) })),
    ).toContain('ato.content.spam_sent');
    expect(
      codes(run({ ...mb, observation: spam, windows: windowSnapshot({ minutes: { spam: [2] } }) })),
    ).not.toContain('ato.content.spam_sent');
  });

  it('P4 BEC language per new category; P5 financial identifiers; need a mature baseline', () => {
    const bec = outboundObservation({
      findings: { ...findings, becCategories: ['bank_change', 'urgency', 'gift_card'] },
    });
    const p4 = run({ ...mb, observation: bec, baseline: mature }).filter(
      (c) => c.code === 'ato.content.bec_language',
    );
    expect(p4.map((c) => c.evidence.categories)).toEqual([['bank_change'], ['gift_card']]);
    expect(
      run({
        ...mb,
        observation: bec,
        baseline: matureBaselineView({
          content: {
            becCategories: ['bank_change', 'gift_card'],
            financial: 0,
            phishing: 0,
            spam: 0,
            fromMismatch: 0,
            massSubject: 0,
          },
        }),
      }).filter((c) => c.code === 'ato.content.bec_language'),
    ).toEqual([]);
    expect(
      run({ ...mb, observation: bec, baseline: mature }, {}, capabilitySet({})).filter(
        (c) => c.code === 'ato.content.bec_language',
      ),
    ).toEqual([]);
    expect(
      run({
        ...mb,
        observation: outboundObservation({ findings: { ...findings, becCategories: null } }),
        baseline: mature,
      }).filter((c) => c.code === 'ato.content.bec_language'),
    ).toEqual([]);
    expect(
      codes(
        run({
          ...mb,
          observation: outboundObservation({ findings: { ...findings, financial: true } }),
          baseline: mature,
        }),
      ),
    ).toContain('ato.content.financial_identifiers');
    expect(
      codes(
        run({
          ...mb,
          observation: outboundObservation({ findings: { ...findings, financial: true } }),
          baseline: null,
        }),
      ),
    ).not.toContain('ato.content.financial_identifiers');
  });
});

describe('provider rules (fake adapter streams)', () => {
  const mb = { account: mailbox };
  const box = (change: string, extra: Record<string, unknown> = {}) =>
    providerObservation({
      mailbox: {
        change,
        targetDomain: null,
        targetDomainKnown: false,
        ruleHash: null,
        ruleTraits: [],
        clientType: null,
        clientTypeKnown: true,
        ...extra,
      },
    });

  it('M1 external forwarding to a never-contacted domain', () => {
    expect(
      one(
        run({ ...mb, observation: box('forwarding_added', { targetDomain: 'evil.example' }) }),
        'ato.mailbox.external_forwarding',
      ).evidence,
    ).toEqual({ domain: 'evil.example' });
    expect(
      codes(
        run({
          ...mb,
          observation: box('forwarding_added', {
            targetDomain: 'partner.example',
            targetDomainKnown: true,
          }),
        }),
      ),
    ).toEqual([]);
    expect(
      codes(
        run(
          { ...mb, observation: box('forwarding_added', { targetDomain: 'evil.example' }) },
          {},
          capabilitySet({}),
        ),
      ),
    ).toEqual([]);
  });

  it('M2 suspicious rule, M3 delegation, M4 unusual access', () => {
    expect(
      codes(
        run({
          ...mb,
          observation: box('inbox_rule_added', {
            ruleTraits: ['delete'],
            ruleHash: 'b'.repeat(64),
          }),
        }),
      ),
    ).toEqual(['ato.mailbox.suspicious_inbox_rule']);
    expect(
      codes(run({ ...mb, observation: box('inbox_rule_added', { ruleTraits: ['flag'] }) })),
    ).toEqual([]);
    expect(codes(run({ ...mb, observation: box('delegate_added') }))).toEqual([
      'ato.mailbox.delegation_added',
    ]);
    expect(
      codes(
        run({ ...mb, observation: box('access', { clientType: 'ews', clientTypeKnown: false }) }),
      ),
    ).toEqual(['ato.mailbox.unusual_access']);
    expect(
      codes(
        run({ ...mb, observation: box('access', { clientType: 'owa', clientTypeKnown: true }) }),
      ),
    ).toEqual([]);
  });

  it('Q1 consent (strong for user consent to mail scopes of an unverified app), Q2 token anomaly, R1 risk levels', () => {
    const consent = (
      scopes: string[],
      consentType: 'user' | 'admin',
      publisherVerified: boolean | null,
    ) =>
      providerObservation({
        stream: 'oauth_consents',
        oauth: { appIdHash: 'c'.repeat(32), scopes, consentType, publisherVerified },
      });
    expect(
      one(
        run({ ...mb, observation: consent(['mail_read'], 'user', false) }),
        'ato.oauth.risky_consent',
      ).strength,
    ).toBe('strong');
    expect(
      one(
        run({ ...mb, observation: consent(['mail_read'], 'user', false) }),
        'ato.oauth.risky_consent',
      ).weight,
    ).toBe(40);
    expect(
      one(
        run({ ...mb, observation: consent(['mail_read'], 'admin', false) }),
        'ato.oauth.risky_consent',
      ).strength,
    ).toBe('moderate');
    expect(
      one(
        run({ ...mb, observation: consent(['mail_read'], 'user', true) }),
        'ato.oauth.risky_consent',
      ).strength,
    ).toBe('moderate');
    expect(
      codes(
        run({
          ...mb,
          observation: providerObservation({ stream: 'session_events', tokenAnomaly: true }),
        }),
      ),
    ).toEqual(['ato.oauth.token_anomaly']);
    const risk = (level: 'low' | 'medium' | 'high') =>
      one(
        run({
          ...mb,
          observation: providerObservation({ stream: 'risk_events', riskLevel: level }),
        }),
        'ato.provider.risk_event',
      );
    expect([risk('high').strength, risk('high').weight]).toEqual(['strong', 40]);
    expect([risk('medium').strength, risk('medium').weight]).toEqual(['moderate', 25]);
    expect([risk('low').strength, risk('low').weight]).toEqual(['weak', 10]);
  });

  it('provider rules never apply to gateway users', () => {
    expect(codes(run({ observation: box('delegate_added') }))).toEqual([]);
  });
});

describe('dedupe keys', () => {
  it('bucket by hour or day and differ per account', () => {
    const w = windowSnapshot({ minutes: { af: [10] } });
    const a = one(run({ observation: failure, windows: w }), 'ato.auth.bruteforce');
    const sameHour = one(
      run({
        observation: { ...failure, occurredAt: new Date(T0.getTime() + 10 * 60_000) },
        windows: w,
      }),
      'ato.auth.bruteforce',
    );
    const nextHour = one(
      run({
        observation: { ...failure, occurredAt: new Date(T0.getTime() + 60 * 60_000) },
        windows: w,
      }),
      'ato.auth.bruteforce',
    );
    const otherAccount = one(
      run({ observation: failure, windows: w, account: accountSnapshot({ id: 43n }) }),
      'ato.auth.bruteforce',
    );
    expect(sameHour.dedupeKey).toBe(a.dedupeKey);
    expect(nextHour.dedupeKey).not.toBe(a.dedupeKey);
    expect(otherAccount.dedupeKey).not.toBe(a.dedupeKey);
  });
});
