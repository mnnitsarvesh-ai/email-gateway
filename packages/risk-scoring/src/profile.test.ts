import { describe, expect, it } from 'vitest';
import {
  canonicalJson,
  effectiveProfileSchema,
  isPlatformProfileId,
  platformProfile,
  RISK_DEFAULT_PLATFORM_PROFILE_ID,
  RISK_HARD_BLOCKS,
  RISK_PLATFORM_PROFILES,
  RISK_SIGNAL_GROUPS,
  RISK_LOCKED_GROUPS,
  resolveProfile,
  RiskProfileError,
  sha256Hex,
  validateEffectiveProfile,
  validateOverrides,
} from './index';

const P = RISK_PLATFORM_PROFILES['rsk-default/1'];
const PUBLIC_ID = '0190a6f2-7b3c-7def-8abc-0123456789ab';
const paths = (doc: unknown) => validateOverrides(doc).map((v) => v.path);

describe('platform default rsk-default/1 (R4–R10)', () => {
  it('has the documented defaults', () => {
    expect(RISK_DEFAULT_PLATFORM_PROFILE_ID).toBe('rsk-default/1');
    expect(P.thresholds).toEqual({ low: 100, medium: 300, high: 550, critical: 800 });
    expect(P.actions).toEqual({
      none: 'deliver',
      low: 'deliver',
      medium: 'tag',
      high: 'quarantine',
      critical: 'quarantine',
    });
    for (const g of RISK_SIGNAL_GROUPS) expect(P.groupMultipliersPermille[g]).toBe(1000);
    expect(P.failures).toEqual({
      engineFailureWeight: 300,
      groupCap: 600,
      unknownWeight: 60,
      minLevel: 'medium',
      unknownMinLevel: 'low',
      action: 'quarantine',
      unknownAction: 'tag',
    });
    expect(P.floors).toEqual({ engineMalicious: 'high', becSuspicious: 'low' });
    expect(P.trust).toEqual({ mode: 'reduce_content', contentFactorPermille: 500 });
    expect(P.ai).toEqual({ tagOnAiOnlyRaise: true });
    for (const h of RISK_HARD_BLOCKS) {
      expect(P.hardBlocks[h.id]).toEqual({ enabled: h.defaultEnabled, action: h.defaultAction });
    }
    expect(P.hardBlocks['hb.dmarc_reject'].enabled).toBe(false);
  });

  it('is valid against its own bounds, frozen and schema-valid', () => {
    expect(validateEffectiveProfile(P, P)).toEqual([]);
    expect(effectiveProfileSchema.parse(P)).toEqual(P);
    expect(Object.isFrozen(P.thresholds)).toBe(true);
    expect(isPlatformProfileId('rsk-default/1')).toBe(true);
    expect(isPlatformProfileId('rsk-default/2')).toBe(false);
  });

  it('platformProfile hashes the canonical profile', () => {
    const r = platformProfile('rsk-default/1');
    expect(r).toMatchObject({
      source: 'platform',
      id: 'rsk-default/1',
      versionNo: null,
      fallback: null,
    });
    expect(r.sha256).toBe(sha256Hex(canonicalJson(P)));
    expect(platformProfile('rsk-default/1', 'foreign').fallback).toBe('foreign');
    expect(() => platformProfile('rsk-default/9')).toThrow(RiskProfileError);
  });
});

describe('validateOverrides (R10 bounds)', () => {
  it('accepts an empty document', () => {
    expect(validateOverrides({})).toEqual([]);
  });

  it('refuses unknown keys and wrong types', () => {
    expect(paths({ weights: {} })).toEqual(['weights']);
    expect(paths({ thresholds: { extreme: 900 } })).toEqual(['thresholds.extreme']);
    expect(paths({ thresholds: { low: 'high' } })).toEqual(['thresholds.low']);
    expect(paths({ thresholds: { low: 100.5 } })).toEqual(['thresholds.low']);
    expect(paths({ hardBlocks: { 'hb.something': { enabled: true } } })).toEqual([
      'hardBlocks.hb.something',
    ]);
    expect(paths(null)).toEqual(['$']);
  });

  const thresholdCases: [string, number, number, number][] = [
    ['low', 50, 250, 100],
    ['medium', 200, 450, 300],
    ['high', 400, 700, 550],
    ['critical', 650, 950, 800],
  ];
  it.each(thresholdCases)('thresholds.%s bounds %i–%i', (key, min, max) => {
    // at the bounds (neighbours adjusted to keep the order valid)
    const fit = (value: number) => {
      const t = { low: 100, medium: 300, high: 550, critical: 800, [key]: value };
      if (t.medium - t.low < 50) t.medium = Math.min(450, t.low + 50);
      if (t.high - t.medium < 50) t.high = Math.min(700, t.medium + 50);
      if (t.critical - t.high < 50) t.critical = Math.min(950, t.high + 50);
      if (t.medium - t.low < 50) t.low = t.medium - 50;
      if (t.high - t.medium < 50) t.medium = t.high - 50;
      if (t.low > t.medium - 50) t.low = t.medium - 50;
      return { thresholds: t };
    };
    expect(validateOverrides(fit(min))).toEqual([]);
    expect(validateOverrides(fit(max))).toEqual([]);
    expect(paths({ thresholds: { [key]: min - 1 } })).toContain(`thresholds.${key}`);
    expect(paths({ thresholds: { [key]: max + 1 } })).toContain(`thresholds.${key}`);
  });

  it('thresholds must increase with gaps of at least 50 after the merge', () => {
    expect(paths({ thresholds: { medium: 200, low: 160 } })).toEqual(['thresholds.medium']);
    expect(validateOverrides({ thresholds: { low: 150, medium: 200 } })).toEqual([]);
    expect(paths({ thresholds: { high: 700, critical: 700 } })).toContain('thresholds.critical');
  });

  it('level actions within the allowed sets and non-decreasing', () => {
    expect(
      validateOverrides({
        actions: { low: 'tag', medium: 'require_approval', high: 'block', critical: 'block' },
      }),
    ).toEqual([]);
    expect(paths({ actions: { none: 'tag' } })).toContain('actions.none');
    expect(paths({ actions: { low: 'quarantine' } })).toContain('actions.low');
    expect(paths({ actions: { medium: 'deliver' } })).toContain('actions.medium');
    expect(paths({ actions: { high: 'tag' } })).toContain('actions.high');
    expect(paths({ actions: { critical: 'require_approval' } })).toContain('actions.critical');
    // monotone: medium quarantine with high require_approval
    expect(paths({ actions: { medium: 'quarantine', high: 'require_approval' } })).toEqual([
      'actions.high',
    ]);
  });

  it('group multipliers 500–2000; locked groups refused', () => {
    expect(
      validateOverrides({ groupMultipliersPermille: { spam: 500, bec_intent: 2000 } }),
    ).toEqual([]);
    expect(paths({ groupMultipliersPermille: { spam: 499 } })).toEqual([
      'groupMultipliersPermille.spam',
    ]);
    expect(paths({ groupMultipliersPermille: { spam: 2001 } })).toEqual([
      'groupMultipliersPermille.spam',
    ]);
    for (const g of RISK_LOCKED_GROUPS) {
      expect(paths({ groupMultipliersPermille: { [g]: 1000 } })).toEqual([
        `groupMultipliersPermille.${g}`,
      ]);
    }
  });

  it('locked hard blocks cannot be disabled; actions within the allowed set', () => {
    for (const id of [
      'hb.malware_attachment',
      'hb.malware_url',
      'hb.malware_sandbox',
      'hb.dlp_block',
    ]) {
      expect(paths({ hardBlocks: { [id]: { enabled: false } } })).toEqual([
        `hardBlocks.${id}.enabled`,
      ]);
    }
    expect(paths({ hardBlocks: { 'hb.dlp_block': { action: 'quarantine' } } })).toEqual([
      'hardBlocks.hb.dlp_block.action',
    ]);
    expect(
      validateOverrides({ hardBlocks: { 'hb.malware_url': { action: 'quarantine' } } }),
    ).toEqual([]);
    expect(paths({ hardBlocks: { 'hb.malware_url': { action: 'tag' } } })).toEqual([
      'hardBlocks.hb.malware_url.action',
    ]);
    expect(
      validateOverrides({
        hardBlocks: {
          'hb.known_phishing': { enabled: false },
          'hb.dmarc_reject': { enabled: true, action: 'block' },
        },
      }),
    ).toEqual([]);
    expect(paths({ hardBlocks: { 'hb.bec_malicious': { action: 'deliver' } } })).toEqual([
      'hardBlocks.hb.bec_malicious.action',
    ]);
  });

  it('failures: weights within bounds, floors never below the platform default', () => {
    expect(
      validateOverrides({
        failures: { engineFailureWeight: 200, groupCap: 300, unknownWeight: 30 },
      }),
    ).toEqual([]);
    expect(
      validateOverrides({
        failures: { engineFailureWeight: 600, groupCap: 1000, unknownWeight: 200 },
      }),
    ).toEqual([]);
    expect(paths({ failures: { engineFailureWeight: 199 } })).toEqual([
      'failures.engineFailureWeight',
    ]);
    expect(paths({ failures: { engineFailureWeight: 601 } })).toEqual([
      'failures.engineFailureWeight',
    ]);
    expect(paths({ failures: { groupCap: 299 } })).toEqual(['failures.groupCap']);
    expect(paths({ failures: { groupCap: 1001 } })).toEqual(['failures.groupCap']);
    expect(paths({ failures: { unknownWeight: 29 } })).toEqual(['failures.unknownWeight']);
    expect(paths({ failures: { unknownWeight: 201 } })).toEqual(['failures.unknownWeight']);
    expect(
      validateOverrides({ failures: { minLevel: 'critical', unknownMinLevel: 'high' } }),
    ).toEqual([]);
    expect(paths({ failures: { minLevel: 'low' } })).toEqual(['failures.minLevel']);
    expect(paths({ failures: { unknownMinLevel: 'none' } })).toEqual(['failures.unknownMinLevel']);
    expect(paths({ failures: { unknownMinLevel: 'critical' } })).toEqual([
      'failures.unknownMinLevel',
    ]);
    expect(paths({ failures: { action: 'require_approval' } })).toEqual(['failures.action']);
    expect(paths({ failures: { action: 'block' } })).toEqual(['failures.action']);
    for (const unknownAction of ['tag', 'require_approval', 'quarantine'] as const) {
      expect(validateOverrides({ failures: { unknownAction } })).toEqual([]);
    }
    // Never weaker than the platform default `tag`: an unknown result never recommends deliver.
    expect(paths({ failures: { unknownAction: 'deliver' } })).toEqual(['failures.unknownAction']);
    expect(paths({ failures: { unknownAction: 'block' } })).toEqual(['failures.unknownAction']);
  });

  it('floors are raise-only', () => {
    expect(
      validateOverrides({ floors: { engineMalicious: 'critical', becSuspicious: 'high' } }),
    ).toEqual([]);
    expect(paths({ floors: { engineMalicious: 'medium' } })).toEqual(['floors.engineMalicious']);
    expect(paths({ floors: { becSuspicious: 'none' } })).toEqual(['floors.becSuspicious']);
    expect(paths({ floors: { becSuspicious: 'critical' } })).toEqual(['floors.becSuspicious']);
  });

  it('trust mode and factor 250–1000; ai switch boolean', () => {
    expect(
      validateOverrides({
        trust: { mode: 'off', contentFactorPermille: 250 },
        ai: { tagOnAiOnlyRaise: false },
      }),
    ).toEqual([]);
    expect(validateOverrides({ trust: { contentFactorPermille: 1000 } })).toEqual([]);
    expect(paths({ trust: { contentFactorPermille: 249 } })).toEqual([
      'trust.contentFactorPermille',
    ]);
    expect(paths({ trust: { contentFactorPermille: 1001 } })).toEqual([
      'trust.contentFactorPermille',
    ]);
    expect(paths({ trust: { mode: 'all' } })).toEqual(['trust.mode']);
    expect(paths({ ai: { tagOnAiOnlyRaise: 'yes' } })).toEqual(['ai.tagOnAiOnlyRaise']);
  });
});

describe('resolveProfile (R10)', () => {
  const version = (overrides: unknown, baseProfile = 'rsk-default/1') => ({
    publicId: PUBLIC_ID,
    versionNo: 4,
    baseProfile,
    overrides,
  });

  it('null → the platform default', () => {
    expect(resolveProfile('rsk-default/1', null)).toEqual(platformProfile('rsk-default/1'));
  });

  it('a valid version → tenant source, id with public id and number, merged profile', () => {
    const r = resolveProfile(
      'rsk-default/1',
      version({ thresholds: { high: 600 }, ai: { tagOnAiOnlyRaise: false } }),
    );
    expect(r.source).toBe('tenant');
    expect(r.id).toBe(`rsk-default/1+t:${PUBLIC_ID}#4`);
    expect(r.id.length).toBeLessThanOrEqual(96);
    expect(r.versionNo).toBe(4);
    expect(r.fallback).toBeNull();
    expect(r.profile.thresholds).toEqual({ low: 100, medium: 300, high: 600, critical: 800 });
    expect(r.profile.ai.tagOnAiOnlyRaise).toBe(false);
    expect(r.sha256).toBe(sha256Hex(canonicalJson(r.profile)));
    expect(r.sha256).not.toBe(platformProfile('rsk-default/1').sha256);
  });

  it('violations → the platform default with fallback invalid', () => {
    const r = resolveProfile('rsk-default/1', version({ thresholds: { low: 10 } }));
    expect(r).toMatchObject({
      source: 'platform',
      id: 'rsk-default/1',
      versionNo: null,
      fallback: 'invalid',
    });
    expect(r.violations.map((v) => v.path)).toEqual(['thresholds.low']);
    expect(r.profile).toEqual(P);
  });

  it('a retired base → platform default with base_profile_retired', () => {
    const r = resolveProfile('rsk-default/1', version({}, 'rsk-default/0'));
    expect(r.fallback).toBe('base_profile_retired');
    expect(r.violations).toEqual([{ path: 'baseProfile', message: 'base_profile_retired' }]);
  });

  it('refuses an unknown platform id and malformed version identity', () => {
    expect(() => resolveProfile('rsk-default/7', null)).toThrow(RiskProfileError);
    expect(() =>
      resolveProfile('rsk-default/1', { ...version({}), publicId: 'not-a-uuid' }),
    ).toThrow(RiskProfileError);
    expect(() => resolveProfile('rsk-default/1', { ...version({}), versionNo: 0 })).toThrow(
      RiskProfileError,
    );
  });

  it('same overrides in a different key order → same sha256', () => {
    const a = resolveProfile(
      'rsk-default/1',
      version({ thresholds: { high: 600, low: 120 }, trust: { mode: 'off' } }),
    );
    const b = resolveProfile(
      'rsk-default/1',
      version({ trust: { mode: 'off' }, thresholds: { low: 120, high: 600 } }),
    );
    expect(a.sha256).toBe(b.sha256);
  });
});
