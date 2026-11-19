import { describe, expect, it } from 'vitest';
import { assertEvidenceSafe, renderExplanation } from './explain';
import { ruleByCode } from './rules/catalogue';
import { CORRELATION_RULE_CODES, evaluateCorrelation } from './rules/evaluate';
import type { CorrelationInput, PersistedSignal, SignalCandidate } from './rules/types';
import { mergeAtoSettings, type AtoSettingsInput } from './settings';
import type { AtoAccountKind } from '@email-gateway/security-contracts';

const NOW = new Date('2026-11-18T12:00:00.000Z');
const minutesAgo = (m: number) => new Date(NOW.getTime() - m * 60_000);
const ACCOUNT_ID = 41n;

/** A persisted signal of the catalogue (category, strength and weight from the rule). */
function persisted(
  code: string,
  at: Date,
  overrides: Partial<PersistedSignal> = {},
): PersistedSignal {
  const rule = ruleByCode(code)!;
  return {
    accountId: ACCOUNT_ID,
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    status: 'active',
    firstOccurredAt: at,
    lastOccurredAt: at,
    ...overrides,
  };
}

/** A fresh candidate of this observation. */
function fresh(
  code: string,
  at: Date = NOW,
  overrides: Partial<SignalCandidate> = {},
): SignalCandidate & { occurredAt: Date } {
  const rule = ruleByCode(code)!;
  return {
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    dedupeKey: `dk-${code}`,
    dedupeWindowMinutes: 60,
    evidence: {},
    sourceKind: 'auth_event',
    sourceRef: null,
    messageRef: null,
    authEventRef: null,
    informational: false,
    seen: null,
    occurredAt: at,
    ...overrides,
  };
}

function correlate(
  kind: AtoAccountKind,
  input: Partial<Omit<CorrelationInput, 'account'>>,
  settings: AtoSettingsInput = {},
): SignalCandidate[] {
  return evaluateCorrelation(
    {
      account: { id: ACCOUNT_ID, kind },
      recent: [],
      fresh: [],
      successTimes: [],
      now: NOW,
      ...input,
    },
    mergeAtoSettings(settings),
  );
}
const codes = (c: SignalCandidate[]) => c.map((x) => x.code).sort();

describe('evaluateCorrelation (D10 X1–X5)', () => {
  it('the catalogue has exactly the five correlation rules', () => {
    expect([...CORRELATION_RULE_CODES].sort()).toEqual([
      'ato.correlation.attack_then_change',
      'ato.correlation.config_change_after_login',
      'ato.correlation.connector_compromise',
      'ato.correlation.login_then_outbound',
      'ato.correlation.multi_category',
    ]);
  });

  it('returns nothing without a fresh signal (old evidence alone never correlates)', () => {
    const recent = [
      persisted('ato.geo.impossible_travel', minutesAgo(120)),
      persisted('ato.outbound.volume_spike', minutesAgo(60)),
    ];
    expect(correlate('mailbox', { recent })).toEqual([]);
  });

  describe('X1 login_then_outbound (mailbox, 24 h)', () => {
    it('fires for a moderate geography signal before a fresh outbound signal', () => {
      const out = correlate('mailbox', {
        recent: [persisted('ato.geo.impossible_travel', minutesAgo(90))],
        fresh: [fresh('ato.outbound.volume_spike')],
      });
      const x1 = out.find((c) => c.code === 'ato.correlation.login_then_outbound');
      expect(x1).toBeDefined();
      expect(x1).toMatchObject({
        category: 'correlation',
        strength: 'strong',
        weight: 40,
        sourceKind: 'correlation',
        dedupeWindowMinutes: 1440,
        informational: false,
      });
      expect(x1!.evidence).toEqual({
        codes: ['ato.geo.impossible_travel', 'ato.outbound.volume_spike'],
        windowMinutes: 90,
      });
      expect(() => assertEvidenceSafe(x1!.evidence)).not.toThrow();
      expect(renderExplanation(x1!.code, x1!.evidence)).toContain('90 minutes');
    });

    it('also fires when the outbound signal is old and the access signal is fresh but earlier', () => {
      const out = correlate('mailbox', {
        recent: [persisted('ato.content.phishing_sent', minutesAgo(1))],
        fresh: [fresh('ato.ti.malicious_ip_success', minutesAgo(30))],
      });
      expect(codes(out)).toContain('ato.correlation.login_then_outbound');
    });

    it('does not fire for weak access signals, after 24 h, or when the order is reversed', () => {
      const weakOnly = correlate('mailbox', {
        recent: [persisted('ato.access.new_ip_prefix', minutesAgo(30))],
        fresh: [fresh('ato.outbound.volume_spike')],
      });
      expect(codes(weakOnly)).not.toContain('ato.correlation.login_then_outbound');
      const tooOld = correlate('mailbox', {
        recent: [persisted('ato.geo.impossible_travel', minutesAgo(24 * 60 + 1))],
        fresh: [fresh('ato.outbound.volume_spike')],
      });
      expect(codes(tooOld)).not.toContain('ato.correlation.login_then_outbound');
      const atBoundary = correlate('mailbox', {
        recent: [persisted('ato.geo.impossible_travel', minutesAgo(24 * 60))],
        fresh: [fresh('ato.outbound.volume_spike')],
      });
      expect(codes(atBoundary)).toContain('ato.correlation.login_then_outbound');
      const reversed = correlate('mailbox', {
        recent: [persisted('ato.outbound.volume_spike', minutesAgo(30))],
        fresh: [fresh('ato.geo.impossible_travel')],
      });
      expect(codes(reversed)).not.toContain('ato.correlation.login_then_outbound');
    });

    it('counts linked-account signals passed in recent (gateway user with the same address)', () => {
      const out = correlate('mailbox', {
        recent: [persisted('ato.ti.attack_source_success', minutesAgo(10), { accountId: 99n })],
        fresh: [fresh('ato.outbound.recipient_fanout')],
      });
      expect(codes(out)).toContain('ato.correlation.login_then_outbound');
    });

    it('applies only to mailboxes and honours the tunable window and disabling', () => {
      const input = {
        recent: [persisted('ato.geo.impossible_travel', minutesAgo(180))],
        fresh: [fresh('ato.outbound.volume_spike')],
      };
      expect(codes(correlate('gateway_user', input))).not.toContain(
        'ato.correlation.login_then_outbound',
      );
      expect(
        codes(
          correlate('mailbox', input, {
            rules: { 'ato.correlation.login_then_outbound': { params: { windowHours: 2 } } },
          }),
        ),
      ).not.toContain('ato.correlation.login_then_outbound');
      expect(
        codes(
          correlate('mailbox', input, {
            rules: { 'ato.correlation.login_then_outbound': { enabled: false } },
          }),
        ),
      ).not.toContain('ato.correlation.login_then_outbound');
    });
  });

  describe('X2 attack_then_change (user, connector, 2 h)', () => {
    const attack = persisted('ato.auth.bruteforce', minutesAgo(60));

    it('fires for an authentication signal, then a success, then a fresh account change', () => {
      const out = correlate('gateway_user', {
        recent: [attack],
        fresh: [fresh('ato.account.mfa_disabled')],
        successTimes: [minutesAgo(30)],
      });
      const x2 = out.find((c) => c.code === 'ato.correlation.attack_then_change');
      expect(x2).toMatchObject({ strength: 'strong', weight: 45 });
      expect(x2!.evidence).toEqual({
        codes: ['ato.auth.bruteforce', 'ato.account.mfa_disabled'],
        windowMinutes: 120,
      });
    });

    it('takes the success from a success-type signal when no success time is given', () => {
      const out = correlate('gateway_user', {
        recent: [attack, persisted('ato.auth.success_after_failures', minutesAgo(40))],
        fresh: [fresh('ato.account.credentials_changed')],
      });
      expect(codes(out)).toContain('ato.correlation.attack_then_change');
    });

    it('does not fire without a success in between, beyond 2 h, or for a mailbox', () => {
      expect(
        codes(
          correlate('gateway_user', {
            recent: [attack],
            fresh: [fresh('ato.account.mfa_disabled')],
          }),
        ),
      ).not.toContain('ato.correlation.attack_then_change');
      expect(
        codes(
          correlate('gateway_user', {
            recent: [attack],
            fresh: [fresh('ato.account.mfa_disabled')],
            // The success precedes the attack: not the X2 order.
            successTimes: [minutesAgo(90)],
          }),
        ),
      ).not.toContain('ato.correlation.attack_then_change');
      expect(
        codes(
          correlate('gateway_user', {
            recent: [persisted('ato.auth.bruteforce', minutesAgo(121))],
            fresh: [fresh('ato.account.mfa_disabled')],
            successTimes: [minutesAgo(30)],
          }),
        ),
      ).not.toContain('ato.correlation.attack_then_change');
      expect(
        codes(
          correlate('gateway_user', {
            recent: [attack],
            // The success follows the change: not the X2 order either.
            fresh: [fresh('ato.account.mfa_disabled', minutesAgo(20))],
            successTimes: [minutesAgo(10)],
          }),
        ),
      ).not.toContain('ato.correlation.attack_then_change');
      expect(
        codes(
          correlate('mailbox', {
            recent: [attack],
            fresh: [fresh('ato.account.mfa_disabled')],
            successTimes: [minutesAgo(30)],
          }),
        ),
      ).not.toContain('ato.correlation.attack_then_change');
    });
  });

  describe('X3 connector_compromise (connector, 2 h)', () => {
    it('fires for a connector authentication anomaly then a fresh attributed outbound signal', () => {
      const out = correlate('smtp_connector', {
        recent: [persisted('ato.access.new_ip_prefix', minutesAgo(45))],
        fresh: [fresh('ato.outbound.connector_sender_spread')],
      });
      const x3 = out.find((c) => c.code === 'ato.correlation.connector_compromise');
      expect(x3).toMatchObject({ strength: 'strong', weight: 45 });
      expect(x3!.evidence).toEqual({
        codes: ['ato.access.new_ip_prefix', 'ato.outbound.connector_sender_spread'],
        windowMinutes: 120,
      });
    });

    it('does not fire for a non-anomaly code, beyond the window, or for mailboxes', () => {
      expect(
        codes(
          correlate('smtp_connector', {
            recent: [persisted('ato.access.unusual_hour', minutesAgo(45))],
            fresh: [fresh('ato.outbound.volume_spike')],
          }),
        ),
      ).not.toContain('ato.correlation.connector_compromise');
      expect(
        codes(
          correlate('smtp_connector', {
            recent: [persisted('ato.geo.new_country', minutesAgo(121))],
            fresh: [fresh('ato.outbound.volume_spike')],
          }),
        ),
      ).not.toContain('ato.correlation.connector_compromise');
      expect(
        codes(
          correlate('mailbox', {
            recent: [persisted('ato.geo.new_country', minutesAgo(45))],
            fresh: [fresh('ato.outbound.volume_spike')],
          }),
        ),
      ).not.toContain('ato.correlation.connector_compromise');
    });
  });

  describe('X4 multi_category (all kinds, ≥ 3 categories in 24 h)', () => {
    it('fires for moderate or strong signals in three categories', () => {
      const out = correlate('gateway_user', {
        recent: [
          persisted('ato.auth.bruteforce', minutesAgo(300)),
          persisted('ato.geo.impossible_travel', minutesAgo(200)),
        ],
        fresh: [fresh('ato.account.bulk_data_access')],
      });
      const x4 = out.find((c) => c.code === 'ato.correlation.multi_category');
      expect(x4).toMatchObject({ strength: 'moderate', weight: 20 });
      expect(x4!.evidence).toMatchObject({
        count: 3,
        categories: ['account_change', 'authentication', 'geography'],
      });
    });

    it('ignores weak signals, signals older than 24 h, and honours minCategories', () => {
      const base = {
        recent: [
          persisted('ato.auth.bruteforce', minutesAgo(300)),
          persisted('ato.access.new_device', minutesAgo(200)),
        ],
        fresh: [fresh('ato.account.bulk_data_access')],
      };
      expect(codes(correlate('gateway_user', base))).not.toContain(
        'ato.correlation.multi_category',
      );
      expect(
        codes(
          correlate('gateway_user', {
            recent: [
              persisted('ato.auth.bruteforce', minutesAgo(24 * 60 + 5)),
              persisted('ato.geo.impossible_travel', minutesAgo(200)),
            ],
            fresh: [fresh('ato.account.bulk_data_access')],
          }),
        ),
      ).not.toContain('ato.correlation.multi_category');
      expect(
        codes(
          correlate('gateway_user', base, {
            rules: { 'ato.correlation.multi_category': { params: { minCategories: 2 } } },
          }),
        ),
      ).toContain('ato.correlation.multi_category');
    });
  });

  describe('X5 config_change_after_login (mailbox, 24 h)', () => {
    it('fires for M1–M3 or Q1 after an access, geography or threat-intel signal', () => {
      for (const config of [
        'ato.mailbox.external_forwarding',
        'ato.mailbox.suspicious_inbox_rule',
        'ato.mailbox.delegation_added',
        'ato.oauth.risky_consent',
      ]) {
        const out = correlate('mailbox', {
          recent: [persisted('ato.access.new_device', minutesAgo(120))],
          fresh: [fresh(config, NOW, { sourceKind: 'provider' })],
        });
        const x5 = out.find((c) => c.code === 'ato.correlation.config_change_after_login');
        expect(x5, config).toMatchObject({ strength: 'strong', weight: 40 });
        expect(x5!.evidence).toEqual({ codes: ['ato.access.new_device', config] });
      }
    });

    it('does not fire for M4 or Q2, beyond 24 h, or without a preceding access signal', () => {
      for (const config of ['ato.mailbox.unusual_access', 'ato.oauth.token_anomaly']) {
        expect(
          codes(
            correlate('mailbox', {
              recent: [persisted('ato.access.new_device', minutesAgo(120))],
              fresh: [fresh(config)],
            }),
          ),
        ).not.toContain('ato.correlation.config_change_after_login');
      }
      expect(
        codes(
          correlate('mailbox', {
            recent: [persisted('ato.access.new_device', minutesAgo(24 * 60 + 1))],
            fresh: [fresh('ato.mailbox.external_forwarding')],
          }),
        ),
      ).not.toContain('ato.correlation.config_change_after_login');
      expect(
        codes(
          correlate('mailbox', {
            recent: [persisted('ato.outbound.volume_spike', minutesAgo(30))],
            fresh: [fresh('ato.mailbox.external_forwarding')],
          }),
        ),
      ).not.toContain('ato.correlation.config_change_after_login');
    });
  });

  it('ignores dismissed and informational signals and existing correlation signals', () => {
    const out = correlate('mailbox', {
      recent: [
        persisted('ato.geo.impossible_travel', minutesAgo(30), { status: 'dismissed' }),
        persisted('ato.ti.malicious_ip_success', minutesAgo(20), { status: 'informational' }),
        persisted('ato.correlation.multi_category', minutesAgo(10)),
      ],
      fresh: [
        fresh('ato.outbound.volume_spike'),
        fresh('ato.geo.inconsistent_sessions', minutesAgo(5), { informational: true }),
      ],
    });
    expect(out).toEqual([]);
  });

  it('dedupes per account and day and is deterministic', () => {
    const input = {
      recent: [persisted('ato.geo.impossible_travel', minutesAgo(90))],
      fresh: [fresh('ato.outbound.volume_spike')],
    };
    const a = correlate('mailbox', input);
    const b = correlate('mailbox', input);
    expect(a).toEqual(b);
    const later = evaluateCorrelation(
      {
        account: { id: ACCOUNT_ID, kind: 'mailbox' },
        ...input,
        successTimes: [],
        now: new Date(NOW.getTime() + 60_000),
      },
      mergeAtoSettings({}),
    );
    expect(later[0]!.dedupeKey).toBe(a[0]!.dedupeKey);
    const other = evaluateCorrelation(
      { account: { id: 42n, kind: 'mailbox' }, ...input, successTimes: [], now: NOW },
      mergeAtoSettings({}),
    );
    expect(other[0]!.dedupeKey).not.toBe(a[0]!.dedupeKey);
  });
});
