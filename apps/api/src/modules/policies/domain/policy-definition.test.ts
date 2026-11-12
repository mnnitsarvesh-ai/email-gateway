import { canonicalJson, POLICY_LIMITS, sha256Hex } from '@email-gateway/policy-dsl';
import { describe, expect, it } from 'vitest';
import {
  departmentExceptionDefinition,
  overrideDefinition,
  quarantineDomainDefinition,
  tagAllDefinition,
} from '../../../../test/support/policy-fixtures';
import {
  catalogView,
  changedSettingsPaths,
  checkDefinition,
  checkSettings,
  EMPTY_SETTINGS_SHA256,
  overrideRuleIds,
  referencesOf,
  settingsView,
  unknownReferenceViolations,
} from './policy-definition';

const DEPT = '0190f0f0-0000-7000-8000-00000000d001';
const bounds = {
  POLICY_PLATFORM_DEFAULT: 'pol-default/1',
  POLICY_MAX_POLICIES: 20,
  POLICY_MAX_VERSIONS_PER_POLICY: 50,
  POLICY_MAX_ACTIVE_RULES: 300,
  POLICY_HISTORY_MAX_RANGE_DAYS: 31,
};

describe('checkDefinition (P2–P6, P17)', () => {
  it('stores the canonical hash, references, rule count, override flag and DSL version', () => {
    for (const doc of [
      quarantineDomainDefinition(),
      tagAllDefinition(),
      departmentExceptionDefinition(DEPT),
      overrideDefinition(),
    ]) {
      const check = checkDefinition(doc);
      expect(check.ok, JSON.stringify(doc)).toBe(true);
      if (!check.ok) continue;
      expect(check.content.definitionSha256).toBe(
        sha256Hex(canonicalJson(check.content.definition)),
      );
      expect(check.content.dslVersion).toBe('policy-dsl/1');
      expect(check.content.ruleCount).toBe(1);
    }
    const dept = checkDefinition(departmentExceptionDefinition(DEPT));
    expect(dept.ok && dept.content.references).toEqual({ departmentIds: [DEPT], userIds: [] });
    const override = checkDefinition(overrideDefinition());
    expect(override.ok && override.content.hasOverrideRules).toBe(true);
  });

  it('refuses an invalid document with every violation by path', () => {
    const doc = {
      ...quarantineDomainDefinition(),
      rules: [
        {
          id: 'Bad Id',
          priority: 1,
          when: { field: 'no.such.field', op: 'equals', value: 'x' },
          actions: [{ type: 'QUARANTINE' }],
        },
      ],
      extra: true,
    };
    const check = checkDefinition(doc);
    expect(check.ok).toBe(false);
    if (check.ok) return;
    const paths = check.violations.map((v) => v.path);
    expect(paths).toContain('rules[0].id');
    expect(paths).toContain('rules[0].when.field');
    expect(paths.some((p) => p === 'extra')).toBe(true);
  });

  it('refuses a raw-sender exception and an override on spoofable identity (P6)', () => {
    const doc = {
      ...overrideDefinition(),
      rules: [
        {
          ...overrideDefinition().rules[0]!,
          when: { field: 'sender.envelope.domain', op: 'equals', value: 'partner.example' },
        },
      ],
    };
    const check = checkDefinition(doc);
    expect(check.ok).toBe(false);
    expect(!check.ok && check.violations.map((v) => v.code)).toContain('identity_unauthenticated');
  });
});

describe('directory references (P5)', () => {
  it('reports unknown departments and users at the leaf value path', () => {
    const doc = departmentExceptionDefinition(DEPT);
    const none = unknownReferenceViolations(doc, { departmentIds: new Set(), userIds: new Set() });
    expect(none).toEqual([
      {
        path: 'rules[0].unless[0].value[0]',
        code: 'department_unknown',
        message: 'Unknown department of the organization',
      },
    ]);
    expect(
      unknownReferenceViolations(doc, { departmentIds: new Set([DEPT]), userIds: new Set() }),
    ).toEqual([]);
    expect(referencesOf(null)).toEqual({ departmentIds: [], userIds: [] });
    expect(referencesOf({ departmentIds: [DEPT, 3], userIds: 'x' })).toEqual({
      departmentIds: [DEPT],
      userIds: [],
    });
  });

  it('lists the ids of override rules (audit metadata)', () => {
    expect(overrideRuleIds(overrideDefinition())).toEqual(['trusted-partner']);
    expect(overrideRuleIds(tagAllDefinition())).toEqual([]);
    expect(overrideRuleIds(null)).toEqual([]);
  });
});

describe('settings (P11)', () => {
  it('accepts the strict document and hashes it canonically', () => {
    const check = checkSettings({ tagging: { platformTagOutbound: true } });
    expect(check.ok).toBe(true);
    expect(check.ok && check.sha256).toBe(
      sha256Hex(canonicalJson({ tagging: { platformTagOutbound: true } })),
    );
    expect(EMPTY_SETTINGS_SHA256).toBe(sha256Hex(canonicalJson({})));
  });

  it('refuses unknown keys and wrong types by path', () => {
    const check = checkSettings({ unknown: 1, alerts: { enabled: 'yes' } });
    expect(check.ok).toBe(false);
    expect(!check.ok && check.violations.map((v) => v.path).sort()).toEqual([
      'alerts.enabled',
      'unknown',
    ]);
  });

  it('lists the effective paths that changed', () => {
    expect(changedSettingsPaths({}, { allowRecommendationOverrides: true })).toEqual([
      'allowRecommendationOverrides',
    ]);
    expect(changedSettingsPaths({}, { notices: { senderNonDelivery: true } })).toEqual([]);
    expect(
      changedSettingsPaths(
        { alerts: { enabled: false } },
        { tagging: { platformTagHeader: false } },
      ),
    ).toEqual(['alerts.enabled', 'tagging.platformTagHeader']);
  });

  it('shows defaults and generation 0 before the row exists', () => {
    const view = settingsView(null);
    expect(view).toMatchObject({
      settings: {},
      generation: '0',
      rowVersion: 0,
      settingsSha256: null,
      effective: { allowRecommendationOverrides: false, alerts: { enabled: true } },
    });
  });
});

describe('catalogView', () => {
  it('lists every field and applies the organization bounds to the DSL limits', () => {
    const catalog = catalogView(bounds);
    expect(catalog.versions).toEqual({
      dsl: 'policy-dsl/1',
      input: 'policy-input/1',
      evaluator: 'policy-eval/2',
    });
    expect(catalog.settingsDefaults.recipientSplit).toBe(true);
    expect(catalog.fields.find((f) => f.name === 'recipient.department')).toMatchObject({
      type: 'id',
      scope: 'recipients',
      quantified: true,
    });
    expect(catalog.limits.activeRulesPerOrganization).toBe(300);
    expect(catalog.limits.activePoliciesPerOrganization).toBe(20);
    expect(catalog.limits.rulesPerPolicy).toBe(POLICY_LIMITS.rulesPerPolicy);
    expect(catalog.limits.versionsPerPolicy).toBe(50);
    expect(catalog.dispositions).toEqual(['allow', 'require_approval', 'quarantine', 'reject']);
    expect(catalog.platformDefault.id).toBe('pol-default/1');
    expect(catalog.enforcement).toContain('step 5.3');
  });
});
