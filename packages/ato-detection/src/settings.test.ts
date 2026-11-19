import { describe, expect, it } from 'vitest';
import { ATO_RULES } from './rules/catalogue';
import {
  ATO_SETTINGS_BOUNDS,
  atoSettingsSchema,
  canonicalSettingsJson,
  DEFAULT_ATO_SETTINGS,
  isLearning,
  mergeAtoSettings,
  normalizeAtoSettings,
  resolveAtoSettings,
  settingsDiffPaths,
  settingsSha256,
} from './settings';

const issues = (input: unknown): string[] => {
  const r = atoSettingsSchema.safeParse(input);
  return r.success ? [] : r.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`);
};

describe('DEFAULT_ATO_SETTINGS (§4.3)', () => {
  it('has the brief defaults', () => {
    expect(DEFAULT_ATO_SETTINGS.mode).toBe('monitor');
    expect(DEFAULT_ATO_SETTINGS.learningDays).toBe(14);
    expect(DEFAULT_ATO_SETTINGS.scoring.bands).toEqual({ medium: 30, high: 50, critical: 75 });
    expect(DEFAULT_ATO_SETTINGS.scoring.incidentThreshold).toBe(50);
    expect(DEFAULT_ATO_SETTINGS.scoring.weakOnlyCap).toBe(45);
    expect(DEFAULT_ATO_SETTINGS.scoring.strongFloor).toBe(60);
    expect(DEFAULT_ATO_SETTINGS.scoring.incidentReopenCooldownMinutes).toBe(60);
    expect(DEFAULT_ATO_SETTINGS.scoring.halfLifeMinutes.authentication).toBe(360);
    expect(DEFAULT_ATO_SETTINGS.scoring.halfLifeMinutes.mailbox_configuration).toBe(10080);
    expect(DEFAULT_ATO_SETTINGS.baselines).toEqual({
      windowDays: 28,
      minActiveDays: 7,
      minEvents: 30,
      volumeK: 6,
    });
    expect(DEFAULT_ATO_SETTINGS.geo).toEqual({
      impossibleTravelKmh: 900,
      minDistanceKm: 500,
      maxAccuracyRadiusKm: 500,
    });
    expect(DEFAULT_ATO_SETTINGS.notifications.digest).toEqual({
      daily: true,
      weekly: true,
      hourLocal: 8,
    });
    expect(DEFAULT_ATO_SETTINGS.restrictions).toEqual({
      defaultMode: 'reject',
      defaultDurationMinutes: 240,
    });
    expect(DEFAULT_ATO_SETTINGS.automation.maxAutomaticPerHour).toBe(10);
  });

  it('automates the three low-impact gateway actions only by default', () => {
    expect(DEFAULT_ATO_SETTINGS.automation.alert_tenant_admins.mode).toBe('automatic');
    expect(DEFAULT_ATO_SETTINGS.automation.notify_soc.mode).toBe('automatic');
    expect(DEFAULT_ATO_SETTINGS.automation.escalate_investigation.mode).toBe('automatic');
    expect(DEFAULT_ATO_SETTINGS.automation.restrict_smtp_sending).toEqual({
      mode: 'recommend',
      minLevel: 'critical',
      durationMinutes: 240,
    });
    expect(DEFAULT_ATO_SETTINGS.automation.revoke_sessions.mode).toBe('recommend');
    expect('record_manual_action' in DEFAULT_ATO_SETTINGS.automation).toBe(false);
  });

  it('has every rule enabled with its default weight', () => {
    for (const r of ATO_RULES) {
      expect(DEFAULT_ATO_SETTINGS.rules[r.code]).toMatchObject({
        enabled: true,
        weight: r.defaultWeight,
      });
    }
  });

  it('is frozen', () => {
    expect(Object.isFrozen(DEFAULT_ATO_SETTINGS.scoring.bands)).toBe(true);
  });
});

describe('atoSettingsSchema validation', () => {
  it('accepts an empty object and every documented key', () => {
    expect(issues({})).toEqual([]);
    expect(
      issues({
        mode: 'enforce',
        learningDays: 0,
        scoring: {
          bands: { medium: 25, high: 50, critical: 80 },
          incidentThreshold: 50,
          weakOnlyCap: 40,
          strongFloor: 65,
          categoryMultipliers: { geography: 1500 },
          halfLifeMinutes: { authentication: 60 },
        },
        rules: { 'ato.auth.bruteforce': { enabled: false, weight: 30, params: { failures: 20 } } },
        ipReputation: {
          trustedNetworks: ['192.0.2.0/24', '2001:db8::/32'],
          blockedNetworks: ['198.51.100.7/32'],
        },
        notifications: { socEmails: ['SOC@Example.test'], throttleMinutes: 30 },
        automation: {
          maxAutomaticPerHour: 5,
          restrict_smtp_sending: { mode: 'automatic', minLevel: 'high', durationMinutes: 60 },
        },
        restrictions: { defaultMode: 'defer' },
      }),
    ).toEqual([]);
  });

  it('is strict and bounded', () => {
    expect(issues({ unknown: 1 })).not.toEqual([]);
    expect(issues({ learningDays: 61 })).not.toEqual([]);
    expect(issues({ scoring: { categoryMultipliers: { geography: 499 } } })).not.toEqual([]);
    expect(issues({ scoring: { halfLifeMinutes: { geography: 43201 } } })).not.toEqual([]);
    expect(issues({ rules: { 'ato.auth.bruteforce': { weight: 101 } } })).not.toEqual([]);
    expect(issues({ automation: { maxAutomaticPerHour: 101 } })).not.toEqual([]);
    expect(issues({ automation: { record_manual_action: { mode: 'automatic' } } })).not.toEqual([]);
    expect(issues({ automation: { restrict_smtp_sending: { minLevel: 'medium' } } })).not.toEqual(
      [],
    );
    expect(issues({ restrictions: { defaultDurationMinutes: 14 } })).not.toEqual([]);
    expect(ATO_SETTINGS_BOUNDS.durationMinutes).toEqual({ min: 15, max: 10080 });
  });

  it('enforces bands, threshold, weak-only cap and strong floor relations', () => {
    expect(issues({ scoring: { bands: { medium: 50, high: 50 } } })).toContain(
      'scoring.bands: Bands must satisfy medium < high < critical',
    );
    expect(issues({ scoring: { bands: { medium: 40 }, incidentThreshold: 35 } })).toContain(
      'scoring.incidentThreshold: The incident threshold must be at least the medium band',
    );
    expect(issues({ scoring: { weakOnlyCap: 50 } })).toContain(
      'scoring: Must satisfy weakOnlyCap < incidentThreshold <= strongFloor',
    );
    expect(issues({ scoring: { strongFloor: 45 } })).toContain(
      'scoring: Must satisfy weakOnlyCap < incidentThreshold <= strongFloor',
    );
  });

  it('validates CIDRs (IPv4 ≥ /8, IPv6 ≥ /32, unique) and SOC e-mails', () => {
    expect(issues({ ipReputation: { trustedNetworks: ['10.0.0.0/7'] } })).not.toEqual([]);
    expect(issues({ ipReputation: { trustedNetworks: ['2001:db8::/31'] } })).not.toEqual([]);
    expect(
      issues({ ipReputation: { trustedNetworks: ['192.0.2.0/24', '192.0.2.9/24'] } }),
    ).not.toEqual([]);
    expect(issues({ ipReputation: { trustedNetworks: ['not-a-cidr'] } })).not.toEqual([]);
    expect(
      issues({
        ipReputation: { blockedNetworks: Array.from({ length: 101 }, (_, i) => `10.${i}.0.0/16`) },
      }),
    ).not.toEqual([]);
    expect(issues({ notifications: { socEmails: ['nope'] } })).not.toEqual([]);
    expect(issues({ notifications: { socEmails: ['a@x.test', 'A@x.test'] } })).not.toEqual([]);
    expect(
      issues({
        notifications: {
          socEmails: ['1@x.test', '2@x.test', '3@x.test', '4@x.test', '5@x.test', '6@x.test'],
        },
      }),
    ).not.toEqual([]);
  });

  it('validates rule codes and per-rule params', () => {
    expect(issues({ rules: { 'ato.unknown.rule': { enabled: false } } })).toContain(
      'rules.ato.unknown.rule: Unknown rule code',
    );
    expect(issues({ rules: { 'ato.auth.bruteforce': { params: { failures: 2 } } } })).not.toEqual(
      [],
    );
    expect(issues({ rules: { 'ato.auth.bruteforce': { params: { bogus: 1 } } } })).not.toEqual([]);
    expect(issues({ rules: { 'ato.auth.bruteforce': { params: { failures: 3 } } } })).toEqual([]);
  });
});

describe('resolve, normalize, diff, hash', () => {
  it('resolves valid settings over the defaults and invalid ones to the defaults', () => {
    const r = resolveAtoSettings({
      mode: 'enforce',
      rules: { 'ato.auth.bruteforce': { params: { failures: 20 } } },
    });
    expect(r.invalid).toBe(false);
    expect(r.settings.mode).toBe('enforce');
    expect(r.settings.rules['ato.auth.bruteforce']!.params).toEqual({
      failures: 20,
      windowMinutes: 15,
    });
    expect(r.settings.rules['ato.auth.bruteforce']!.weight).toBe(20);
    const bad = resolveAtoSettings({ mode: 'nope' });
    expect(bad.invalid).toBe(true);
    expect(bad.settings.mode).toBe('monitor');
    expect(resolveAtoSettings(null).invalid).toBe(false);
  });

  it('normalizes CIDRs and e-mails and always stores the mode', () => {
    const n = normalizeAtoSettings({
      ipReputation: { trustedNetworks: ['192.0.2.7/24'] },
      notifications: { socEmails: ['SOC@Example.TEST'] },
    });
    expect(n.mode).toBe('monitor');
    expect(n.ipReputation?.trustedNetworks).toEqual(['192.0.2.0/24']);
    expect(n.notifications?.socEmails).toEqual(['soc@example.test']);
    expect(Object.keys(n)).toEqual([...Object.keys(n)].sort());
  });

  it('canonical JSON and SHA-256 ignore key order', () => {
    expect(canonicalSettingsJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(settingsSha256({ b: 1, a: 2 })).toBe(settingsSha256({ a: 2, b: 1 }));
    expect(settingsSha256({ a: 1 })).toMatch(/^[0-9a-f]{64}$/);
  });

  it('lists changed paths', () => {
    const a = mergeAtoSettings({});
    const b = mergeAtoSettings({
      mode: 'enforce',
      scoring: { bands: { critical: 80 } },
      ipReputation: { trustedNetworks: ['192.0.2.0/24'] },
    });
    expect(settingsDiffPaths(a, b)).toEqual([
      'ipReputation.trustedNetworks',
      'mode',
      'scoring.bands.critical',
    ]);
    expect(settingsDiffPaths(a, a)).toEqual([]);
  });

  it('learning period lasts learningDays after enablement', () => {
    const start = new Date('2026-11-01T00:00:00.000Z');
    expect(isLearning({ learningDays: 14 }, start, new Date('2026-11-14T23:59:59.000Z'))).toBe(
      true,
    );
    expect(isLearning({ learningDays: 14 }, start, new Date('2026-11-15T00:00:00.000Z'))).toBe(
      false,
    );
    expect(isLearning({ learningDays: 0 }, start, start)).toBe(false);
  });
});
