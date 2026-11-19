import { canonicalJson, sha256Hex } from '@email-gateway/policy-dsl';
import { describe, expect, it, vi } from 'vitest';
import {
  departmentExceptionDefinition,
  quarantineDomainDefinition,
} from '../../../../test/support/policy-fixtures';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import { PolicyValidateSchema } from '../dto/policies.schemas';
import type { PolicyFactsRepository } from '../repositories/policy-facts.repository';
import type { PolicyMetrics } from './policy-writer';
import { PolicyValidationService } from './policy-validation.service';

const SCOPE = systemScope(1n);
const KNOWN = '0190f0f0-0000-7000-8000-00000000d001';
const UNKNOWN = '0190f0f0-0000-7000-8000-00000000d0ff';

function setup() {
  const existingDirectoryIds = vi.fn(
    (_scope: unknown, refs: { departmentIds: readonly string[]; userIds: readonly string[] }) =>
      Promise.resolve({
        departmentIds: new Set(refs.departmentIds.filter((id) => id === KNOWN)),
        userIds: new Set<string>(),
      }),
  );
  // Every other repository method would be a read of something else: none may be called.
  const facts = new Proxy(
    { existingDirectoryIds },
    {
      get: (target, key: string) => {
        if (key in target) return target[key as keyof typeof target];
        if (key === 'then') return undefined;
        throw new Error(`unexpected repository call ${key}`);
      },
    },
  ) as unknown as PolicyFactsRepository;
  const metrics = { validations: { inc: vi.fn() } };
  const service = new PolicyValidationService(facts, metrics as unknown as PolicyMetrics);
  return { service, existingDirectoryIds, metrics };
}

const body = (definition: unknown) => PolicyValidateSchema.parse({ definition });

describe('PolicyValidationService.validate (step 7.3 §4.2)', () => {
  it('answers a valid definition with the columns a save would store, without a directory read', async () => {
    const ctx = setup();
    const definition = quarantineDomainDefinition();
    const res = await ctx.service.validate(SCOPE, body(definition));
    expect(res).toEqual({
      dslVersion: 'policy-dsl/1',
      valid: true,
      violations: [],
      referenceViolations: [],
      ruleCount: 1,
      hasOverrideRules: false,
      references: { departmentIds: [], userIds: [] },
      definitionSha256: sha256Hex(canonicalJson(definition)),
    });
    expect(ctx.existingDirectoryIds).not.toHaveBeenCalled();
    expect(ctx.metrics.validations.inc).toHaveBeenCalledWith({ result: 'valid' });
  });

  it('answers an invalid definition with every violation by path and null columns (200, not an error)', async () => {
    const ctx = setup();
    const definition = {
      ...quarantineDomainDefinition(),
      rules: [
        {
          id: 'Bad Id',
          priority: 10,
          when: { field: 'attachment.filename', op: 'regex', value: ['(a)\\1'] },
          actions: [{ type: 'QUARANTINE' }, { type: 'TAG' }],
        },
      ],
    };
    const res = await ctx.service.validate(SCOPE, body(definition));
    expect(res.valid).toBe(false);
    expect(res.violations.map((v) => [v.path, v.code])).toEqual([
      ['rules[0].actions[1].label', 'value_required'],
      ['rules[0].id', 'value_invalid'],
      ['rules[0].when.value[0]', 'regex_invalid'],
    ]);
    expect(res).toMatchObject({
      referenceViolations: [],
      ruleCount: null,
      hasOverrideRules: null,
      references: null,
      definitionSha256: null,
    });
    expect(ctx.existingDirectoryIds).not.toHaveBeenCalled();
    expect(ctx.metrics.validations.inc).toHaveBeenCalledWith({ result: 'invalid' });
  });

  it('reports field_strict_only for an ATO field in an ALLOW rule or an exception (step 8.4 D23)', async () => {
    const ctx = setup();
    const ato = { field: 'ato.risk_level', op: 'lte', value: 'low' };
    const definition = {
      dslVersion: 'policy-dsl/1',
      direction: 'outbound',
      priority: 100,
      rules: [
        { id: 'allow-low-risk', priority: 10, when: ato, actions: [{ type: 'ALLOW' }] },
        {
          id: 'hold',
          priority: 20,
          when: { field: 'direction', op: 'equals', value: 'outbound' },
          unless: [ato],
          actions: [{ type: 'QUARANTINE' }],
        },
      ],
    };
    const res = await ctx.service.validate(SCOPE, body(definition));
    expect(res.valid).toBe(false);
    expect(res.violations.map((v) => [v.path, v.code])).toEqual([
      ['rules[0].when.field', 'field_strict_only'],
      ['rules[1].unless[0].field', 'field_strict_only'],
    ]);
    // The same field in a hold rule's when is valid.
    const hold = await ctx.service.validate(
      SCOPE,
      body({
        ...definition,
        rules: [{ id: 'hold', priority: 10, when: ato, actions: [{ type: 'QUARANTINE' }] }],
      }),
    );
    expect(hold.valid).toBe(true);
  });

  it('lists at most 100 violations', async () => {
    const ctx = setup();
    const rules = Array.from({ length: 60 }, (_, i) => ({
      id: `r${i}`,
      priority: i,
      when: { field: 'nope', op: 'equals', value: 'x' },
      actions: [{ type: 'NOPE' }],
    }));
    const res = await ctx.service.validate(SCOPE, body({ ...quarantineDomainDefinition(), rules }));
    expect(res.violations).toHaveLength(100);
  });

  it('reports unknown departments of the organization separately; the definition stays valid', async () => {
    const ctx = setup();
    const definition = departmentExceptionDefinition(UNKNOWN);
    const res = await ctx.service.validate(SCOPE, body(definition));
    expect(res.valid).toBe(true);
    expect(res.references).toEqual({ departmentIds: [UNKNOWN], userIds: [] });
    expect(res.referenceViolations).toEqual([
      {
        path: 'rules[0].unless[0].value[0]',
        code: 'department_unknown',
        message: 'Unknown department of the organization',
      },
    ]);
    expect(ctx.existingDirectoryIds).toHaveBeenCalledWith(SCOPE, {
      departmentIds: [UNKNOWN],
      userIds: [],
    });
    const known = await ctx.service.validate(SCOPE, body(departmentExceptionDefinition(KNOWN)));
    expect(known.referenceViolations).toEqual([]);
  });

  it('refuses a body that is not { definition: object } (strict schema)', () => {
    expect(PolicyValidateSchema.safeParse({}).success).toBe(false);
    expect(PolicyValidateSchema.safeParse({ definition: [] }).success).toBe(false);
    expect(PolicyValidateSchema.safeParse({ definition: {}, extra: 1 }).success).toBe(false);
    expect(PolicyValidateSchema.safeParse({ definition: {} }).success).toBe(true);
  });
});
