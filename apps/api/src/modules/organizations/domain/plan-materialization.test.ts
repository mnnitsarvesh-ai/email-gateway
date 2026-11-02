import { FEATURE_KEYS, LIMIT_KEYS, PLANS } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { isFeatureKey, isLimitKey, parsePlanDefaults, planChanges } from './plan-materialization';

describe('parsePlanDefaults', () => {
  it('reads every catalog plan completely', () => {
    for (const plan of PLANS) {
      const defaults = parsePlanDefaults(plan.limits, plan.features);
      expect([...defaults.limits.keys()].sort()).toEqual([...LIMIT_KEYS].sort());
      expect([...defaults.features.keys()].sort()).toEqual([...FEATURE_KEYS].sort());
      expect(defaults.limits.get('max_users')).toBe(BigInt(plan.limits.max_users));
      expect(defaults.features.get('api_access')).toBe(plan.features.api_access);
    }
  });

  it('ignores unknown keys and malformed values', () => {
    const defaults = parsePlanDefaults(
      {
        max_users: 10,
        bogus: 5,
        max_domains: -1,
        messages_per_day: 1.5,
        archive_retention_days: '9',
      },
      { api_access: true, sso: 'yes', made_up: true },
    );
    expect([...defaults.limits]).toEqual([['max_users', 10n]]);
    expect([...defaults.features]).toEqual([['api_access', true]]);
  });

  it('tolerates non-object JSON', () => {
    expect(parsePlanDefaults(null, [1, 2]).limits.size).toBe(0);
    expect(parsePlanDefaults('x', 3).features.size).toBe(0);
  });
});

describe('planChanges', () => {
  const plan = new Map<string, bigint>([
    ['max_users', 250n],
    ['max_domains', 10n],
  ]);

  it('writes plan values and keeps overrides', () => {
    const changes = planChanges(
      [
        { key: 'max_users', source: 'override' },
        { key: 'max_domains', source: 'plan' },
      ],
      plan,
    );
    expect(changes.set).toEqual([{ key: 'max_domains', value: 10n }]);
    expect(changes.remove).toEqual([]);
  });

  it('adds keys the organization does not have yet', () => {
    expect(planChanges([], plan).set.map((s) => s.key)).toEqual(['max_users', 'max_domains']);
  });

  it('removes plan-sourced keys the new plan drops, never overrides', () => {
    const changes = planChanges(
      [
        { key: 'max_users', source: 'plan' },
        { key: 'webhooks_per_org', source: 'plan' },
        { key: 'legacy_override', source: 'override' },
      ],
      plan,
    );
    expect(changes.remove).toEqual(['webhooks_per_org']);
  });
});

describe('key guards', () => {
  it('accepts catalog keys only', () => {
    expect(isLimitKey('max_users')).toBe(true);
    expect(isLimitKey('max_planets')).toBe(false);
    expect(isFeatureKey('api_access')).toBe(true);
    expect(isFeatureKey('teleport')).toBe(false);
  });
});
