import { describe, expect, it } from 'vitest';
import { ruleByCode } from './rules/catalogue';
import {
  DECAY_PERMILLE,
  decayStep,
  levelFor,
  overrideActive,
  scoreAccount,
  scoreExplanation,
  signalContribution,
  type ScoreOverride,
  type ScoreSignal,
} from './scoring';
import { mergeAtoSettings } from './settings';
import { T0 } from './testing/builders';

const settings = mergeAtoSettings({});

/** A fresh active signal of a catalogue rule (its category, strength and default weight). */
function sig(code: string, overrides: Partial<ScoreSignal> = {}): ScoreSignal {
  const rule = ruleByCode(code)!;
  return {
    code,
    category: rule.category,
    strength: rule.strength,
    weight: rule.defaultWeight,
    status: 'active',
    lastOccurredAt: T0,
    ...overrides,
  };
}

const score = (signals: ScoreSignal[], override: ScoreOverride | null = null, now = T0) =>
  scoreAccount(signals, settings, override, now);

describe('DECAY_PERMILLE (161 literal integers)', () => {
  it('equals round(1000 × 2^(−k/16)) with DECAY[160] = 0', () => {
    expect(DECAY_PERMILLE).toHaveLength(161);
    for (let k = 0; k < 160; k++) expect(DECAY_PERMILLE[k]).toBe(Math.round(1000 * 2 ** (-k / 16)));
    expect(DECAY_PERMILLE[160]).toBe(0);
    expect(DECAY_PERMILLE[0]).toBe(1000);
    expect(DECAY_PERMILLE[16]).toBe(500);
    expect(DECAY_PERMILLE[32]).toBe(250);
  });

  it('decay step is ⌊16 × age / halfLife⌋ capped at 160', () => {
    expect(decayStep(0, 60)).toBe(0);
    expect(decayStep(60 * 60_000, 60)).toBe(16);
    expect(decayStep(30 * 60_000, 60)).toBe(8);
    expect(decayStep(-5, 60)).toBe(0);
    expect(decayStep(1e12, 60)).toBe(160);
  });

  it('contribution is integer arithmetic', () => {
    expect(signalContribution(45, 1000, 1000)).toBe(45);
    expect(signalContribution(45, 1500, 500)).toBe(33);
    expect(signalContribution(7, 1000, 958)).toBe(6);
  });
});

describe('worked examples of D11 (defaults, fresh signals)', () => {
  it('VPN sign-in alone: G4 10 + C1 8 → weak only → 18 low', () => {
    const r = score([sig('ato.geo.anonymizer'), sig('ato.access.new_ip_prefix')]);
    expect(r.score).toBe(18);
    expect(r.level).toBe('low');
    expect(r.gates.weakOnly).toBe(true);
  });

  it('new country + new device + new IP → 24 low', () => {
    const r = score([
      sig('ato.geo.new_country'),
      sig('ato.access.new_device'),
      sig('ato.access.new_ip_prefix'),
    ]);
    expect(r.groups.access_context?.total).toBe(12);
    expect(r.groups.geography?.total).toBe(12);
    expect(r.score).toBe(24);
    expect(r.level).toBe('low');
  });

  it('impossible travel G2 30 + G1 12 + C3 10 → 43 medium (no incident)', () => {
    const r = score([
      sig('ato.geo.impossible_travel'),
      sig('ato.geo.new_country'),
      sig('ato.access.new_device'),
    ]);
    expect(r.groups.geography?.total).toBe(33);
    expect(r.score).toBe(43);
    expect(r.level).toBe('medium');
    expect(r.score).toBeLessThan(settings.scoring.incidentThreshold);
  });

  it('password spraying success T3 45 + C1 8 + G1 12 → 65 high', () => {
    const r = score([
      sig('ato.ti.attack_source_success'),
      sig('ato.access.new_ip_prefix'),
      sig('ato.geo.new_country'),
    ]);
    expect(r.score).toBe(65);
    expect(r.level).toBe('high');
    expect(r.gates.strongFloorApplied).toBe(false);
  });

  it('brute force + success + MFA disabled + X2 → 90 critical', () => {
    const r = score([
      sig('ato.auth.bruteforce'),
      sig('ato.auth.success_after_failures'),
      sig('ato.account.mfa_disabled'),
      sig('ato.correlation.attack_then_change'),
    ]);
    expect(r.groups.authentication?.total).toBe(35);
    expect(r.score).toBe(90);
    expect(r.level).toBe('critical');
  });

  it('phishing sent P1 45 → floor 60 high; + O1 25 → 70; + X1 40 → 100 critical', () => {
    const p1 = sig('ato.content.phishing_sent');
    const first = score([p1]);
    expect(first.raw).toBe(45);
    expect(first.score).toBe(60);
    expect(first.gates.strongFloorApplied).toBe(true);
    expect(first.level).toBe('high');
    expect(score([p1, sig('ato.outbound.volume_spike')]).score).toBe(70);
    const all = score([
      p1,
      sig('ato.outbound.volume_spike'),
      sig('ato.correlation.login_then_outbound'),
    ]);
    expect(all.score).toBe(100);
    expect(all.level).toBe('critical');
  });

  it('refresh-token reuse K1 50 → 60 high', () => {
    const r = score([sig('ato.account.refresh_token_reuse')]);
    expect(r.score).toBe(60);
    expect(r.level).toBe('high');
  });
});

describe('groups, caps and gates', () => {
  it('stacks only the 2nd–4th contribution at 250 ‰ and caps the group', () => {
    const many = Array.from({ length: 6 }, (_, i) =>
      sig('ato.access.new_ip_prefix', { id: BigInt(i), weight: 20 }),
    );
    const r = score(many);
    // 20 + ⌊(20+20+20) × 0.25⌋ = 35 → capped at 30
    expect(r.groups.access_context).toEqual({ total: 30, cap: 30, capped: true });
    expect(r.contributions.filter((c) => c.counted)).toHaveLength(4);
  });

  it('the weak-only cap holds a flood of weak signals below the incident threshold', () => {
    const weak = [
      sig('ato.geo.new_country', { weight: 40 }),
      sig('ato.access.new_ip_prefix', { weight: 30 }),
      sig('ato.geo.anonymizer', { weight: 40, category: 'threat_intel' }),
    ];
    const r = score(weak);
    expect(r.raw).toBeGreaterThan(45);
    expect(r.score).toBe(45);
    expect(r.gates.weakOnlyCapApplied).toBe(true);
  });

  it('the strong floor applies only while the strong signal is younger than one half-life', () => {
    const halfLife = settings.scoring.halfLifeMinutes.outbound_content;
    const fresh = score([sig('ato.content.phishing_sent')]);
    expect(fresh.score).toBe(60);
    const later = new Date(T0.getTime() + halfLife * 60_000);
    const old = scoreAccount([sig('ato.content.phishing_sent')], settings, null, later);
    expect(old.gates.strongFloorApplied).toBe(false);
    expect(old.score).toBe(22);
  });

  it('decays by category half-life and drops signals older than ten half-lives', () => {
    const halfLife = settings.scoring.halfLifeMinutes.authentication;
    const s = sig('ato.auth.success_after_failures');
    expect(
      scoreAccount([s], settings, null, new Date(T0.getTime() + halfLife * 60_000)).score,
    ).toBe(15);
    expect(
      scoreAccount([s], settings, null, new Date(T0.getTime() + 11 * halfLife * 60_000)).score,
    ).toBe(0);
  });

  it('ignores dismissed and informational signals', () => {
    const r = score([
      sig('ato.content.phishing_sent', { status: 'dismissed' }),
      sig('ato.auth.bruteforce', { status: 'informational' }),
    ]);
    expect(r.score).toBe(0);
    expect(r.level).toBe('low');
  });

  it('applies category multipliers', () => {
    const s = mergeAtoSettings({ scoring: { categoryMultipliers: { geography: 2000 } } });
    expect(scoreAccount([sig('ato.geo.new_country')], s, null, T0).score).toBe(24);
  });

  it('is deterministic regardless of input order', () => {
    const a = [
      sig('ato.geo.new_country', { id: 1n }),
      sig('ato.access.new_device', { id: 2n }),
      sig('ato.auth.bruteforce', { id: 3n }),
    ];
    expect(score([...a].reverse())).toEqual(score(a));
  });
});

describe('overrides', () => {
  const base: ScoreOverride = {
    verdict: 'compromised',
    createdAt: new Date(T0.getTime() - 60_000),
    expiresAt: new Date(T0.getTime() + 86_400_000),
    clearedAt: null,
    contradictedAt: null,
  };

  it('compromised raises to at least 90', () => {
    const r = score([sig('ato.access.new_device')], base);
    expect(r.score).toBe(90);
    expect(r.override).toEqual({ verdict: 'compromised', outcome: 'applied' });
  });

  it('benign caps below the medium band', () => {
    const r = score([sig('ato.auth.bruteforce'), sig('ato.auth.success_after_failures')], {
      ...base,
      verdict: 'benign',
      createdAt: new Date(T0.getTime() + 1),
    });
    expect(r.score).toBe(29);
    expect(r.override.outcome).toBe('applied');
  });

  it('a strong signal after a benign override contradicts it (not applied)', () => {
    const r = score([sig('ato.ti.attack_source_success')], { ...base, verdict: 'benign' });
    expect(r.override).toEqual({ verdict: 'benign', outcome: 'contradicted' });
    expect(r.score).toBe(60);
  });

  it('expired, cleared or contradicted overrides do not apply', () => {
    const expired = { ...base, expiresAt: new Date(T0.getTime() - 1) };
    expect(score([sig('ato.access.new_device')], expired).override.outcome).toBe('expired');
    expect(score([sig('ato.access.new_device')], { ...base, clearedAt: T0 }).override.outcome).toBe(
      'none',
    );
    expect(overrideActive(expired, T0)).toBe(false);
    expect(overrideActive(base, T0)).toBe(true);
  });
});

describe('levels and explanation', () => {
  it('uses the tenant bands', () => {
    const bands = { medium: 30, high: 50, critical: 75 };
    expect(levelFor(29, bands)).toBe('low');
    expect(levelFor(30, bands)).toBe('medium');
    expect(levelFor(49, bands)).toBe('medium');
    expect(levelFor(50, bands)).toBe('high');
    expect(levelFor(74, bands)).toBe('high');
    expect(levelFor(75, bands)).toBe('critical');
    expect(levelFor(40, { medium: 20, high: 40, critical: 60 })).toBe('high');
  });

  it('explanation keeps the top 10 counted contributions and versions', () => {
    const r = score([
      sig('ato.ti.attack_source_success'),
      sig('ato.access.new_ip_prefix'),
      sig('ato.geo.new_country'),
    ]);
    const e = scoreExplanation(r, 3);
    expect(e.version).toBe('ato-score/1');
    expect(e.rulesVersion).toBe('ato-rules/1');
    expect(e.settingsVersion).toBe(3);
    expect(e.top.map((c) => c.code)).toEqual([
      'ato.ti.attack_source_success',
      'ato.geo.new_country',
      'ato.access.new_ip_prefix',
    ]);
    expect(e.top[0]).not.toHaveProperty('counted');
  });
});
