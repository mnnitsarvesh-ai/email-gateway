/**
 * Step 7.3 policy builder routes (docs/plan/steps/22-policy-builder.md §4.2, §4.3, §9.2) over HTTP
 * with MySQL, Redis and S3 stubbed: the real controllers, guards (authentication, RBAC, the
 * `expensive` class, the sample dry-run's per-principal limit), validation pipes, services and the
 * shared policy evaluation run against the in-memory policy store and fakes of the replica reads
 * (test/support/policy-app.ts). Covered: both routes with their documented examples, strict
 * bodies, 401/403 (policy:manage; and message:read for the sample), the reference check against
 * the organization's departments, inline `400 policy_definition_invalid`, a foreign or unknown
 * version `404`, the sample bounds, `429` with `RateLimit-*` and `Retry-After` on the route
 * bucket, an Idempotency-Key accepted and nothing stored, and that neither route writes. The same
 * routes run against the real MySQL writer and replica in integration/policy-builder.test.ts.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/policy-builder.ts) ----
// @covers post /api/v1/policies/dry-run
// @covers post /api/v1/policies/validate
// ---- end of route coverage ----
import { randomUUID } from 'node:crypto';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicyPerRecipient,
  POLICY_LIMITS,
  validatePolicyDefinition,
} from '@email-gateway/policy-dsl';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { POLICY_JSON_BODY_LIMIT_BYTES } from '../src/http/policy-body-limit';
import { policyRoundRowsOf, snapshotSource } from '../src/modules/policies/domain/policy-round';
import {
  PolicySampleDryRunResponseSchema,
  PolicyValidateResponseSchema,
} from '../src/modules/policies/dto/policies.schemas';
import { POLICY_BUILDER_EXAMPLES } from '../src/modules/policies/dto/policy-builder.examples';
import type { InMemoryIdempotencyStore } from './support/api-test-app';
import { idem, installIdempotencyStore } from './legacy-idempotency-support';
import { createPolicyApp, MESSAGE_ID, type PolicyApp, roleOf } from './support/policy-app';
import {
  quarantineDomainDefinition,
  departmentExceptionDefinition,
} from './support/policy-fixtures';

const READ_ONLY = roleOf('read_only_user');
const ANALYST = roleOf('security_analyst');
const ADMIN = roleOf('organization_admin');
const P = '/api/v1/policies';
const VALIDATE = `${P}/validate`;
const SAMPLE = `${P}/dry-run`;

describe('step 7.3 policy builder routes (e2e, dependencies stubbed)', () => {
  let ctx: PolicyApp;
  let idempotency: InMemoryIdempotencyStore;
  const http = () => ctx.http();

  beforeAll(async () => {
    ctx = await createPolicyApp({
      POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: '2',
      POLICY_DRY_RUN_SAMPLE_MAX: '30',
      POLICY_HISTORY_MAX_RANGE_DAYS: '14',
    });
    idempotency = installIdempotencyStore(ctx.app);
  });
  afterAll(async () => {
    await ctx?.close();
  });
  beforeEach(() => {
    ctx.reset();
    idempotency.rows.clear();
  });

  const writes = () =>
    ctx.store().calls.filter((c) => /create|update|publish|delete|bump/i.test(c));

  /** Publishes a policy of organization A (as the admin) and returns its id. */
  async function publish(definition: object, name = 'p'): Promise<string> {
    const created = await http()
      .post(P)
      .set(await ctx.as(ADMIN))
      .send({ name, definition })
      .expect(201);
    const id = created.body.policy.id as string;
    await http()
      .post(`${P}/${id}/versions/1/publish`)
      .set(idem())
      .set(await ctx.as(ADMIN))
      .send({ expectedRowVersion: 1 })
      .expect(200);
    return id;
  }

  /**
   * The stored round of the harness's message (77, scan 900) as the policy-engine decided it under
   * the active snapshot, plus a round whose message registry row is gone (not_found).
   */
  async function storedRounds() {
    const store = ctx.store();
    const snapshot = compileSnapshot(
      snapshotSource(await store.facts.snapshot({ organizationId: 1n } as never), 'pol-default/1', {
        kind: 'active',
      }),
    );
    const decided = evaluatePolicyPerRecipient(
      buildPolicyInput(
        policyRoundRowsOf(
          { ...ctx.round.message, publicId: MESSAGE_ID },
          ctx.round.scan as never,
          ctx.round.rows,
          { departmentsByAddress: {}, usersByAddress: {} },
        ),
      ),
      snapshot,
    ).message;
    const row = {
      id: 5001n,
      receivedAt: ctx.round.message.receivedAt,
      messageId: 77n,
      evaluationSeq: 0,
      scanId: 900n,
      trigger: 'scanned',
      direction: 'inbound',
      disposition: decided.disposition,
      decisionSource: decided.decisive.source,
      decisivePolicyPublicId: decided.decisive.policyPublicId,
      decisiveRuleId: decided.decisive.ruleId,
      policyVersions: decided.versions.policies,
      evaluatedAt: new Date(ctx.round.message.receivedAt.getTime() + 6_000),
    };
    const gone = {
      ...row,
      id: 5000n,
      messageId: 78n,
      scanId: 899n,
      receivedAt: new Date(ctx.round.message.receivedAt.getTime() - 60_000),
    };
    ctx.executions.sampleRounds.mockResolvedValue([row, gone]);
    ctx.executions.messagePublicIds.mockResolvedValue(new Map([[77n, MESSAGE_ID]]));
    return decided;
  }

  it('answers 401 without credentials on both routes', async () => {
    await http().post(VALIDATE).send({ definition: {} }).expect(401);
    await http().post(SAMPLE).send({}).expect(401);
  });

  describe('POST /policies/validate', () => {
    it('validates the documented example without saving (policy:manage), references on the directory', async () => {
      const res = await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .send(POLICY_BUILDER_EXAMPLES.validateBody)
        .expect(200);
      expect(PolicyValidateResponseSchema.parse(res.body)).toEqual(res.body);
      // The example's Finance department does not exist in this organization.
      expect(res.body).toMatchObject({
        valid: true,
        ruleCount: 1,
        referenceViolations: [{ path: 'rules[0].unless[0].value[0]', code: 'department_unknown' }],
        definitionSha256: POLICY_BUILDER_EXAMPLES.validated.definitionSha256,
      });
      const invalid = await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .send(POLICY_BUILDER_EXAMPLES.validateInvalidBody)
        .expect(200);
      expect(invalid.body).toMatchObject({
        valid: false,
        violations: [{ path: 'rules[0].when.value[0]', code: 'regex_invalid' }],
        referenceViolations: [],
        ruleCount: null,
        hasOverrideRules: null,
        references: null,
        definitionSha256: null,
      });
    });

    it('checks references against the caller’s organization only', async () => {
      const admin = await ctx.as(ADMIN);
      const finance = await http()
        .post('/api/v1/departments')
        .set(admin)
        .send({ name: 'Finance' })
        .expect(201);
      const own = await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .send({ definition: departmentExceptionDefinition(finance.body.id as string) })
        .expect(200);
      expect(own.body.referenceViolations).toEqual([]);
      // The same department id from organization B is unknown there.
      const foreign = await http()
        .post(VALIDATE)
        .set(await ctx.as(ADMIN, 'B'))
        .send({ definition: departmentExceptionDefinition(finance.body.id as string) })
        .expect(200);
      expect(foreign.body.referenceViolations).toMatchObject([{ code: 'department_unknown' }]);
    });

    it('refuses bodies that are not { definition: object } and callers without policy:manage', async () => {
      const auth = await ctx.as(ANALYST);
      for (const body of [{}, { definition: [] }, { definition: 'x' }, { definition: {}, x: 1 }]) {
        const res = await http().post(VALIDATE).set(auth).send(body).expect(400);
        expect(res.body.code, JSON.stringify(body)).toBe('validation_failed');
      }
      for (const permissions of [READ_ONLY, ['policy:read', 'message:read']]) {
        await http()
          .post(VALIDATE)
          .set(await ctx.as(permissions))
          .send({ definition: quarantineDomainDefinition() })
          .expect(403);
      }
      await http()
        .post(VALIDATE)
        .set(await ctx.as(ADMIN))
        .send({ definition: quarantineDomainDefinition() })
        .expect(200);
    });

    it('writes nothing; an Idempotency-Key is accepted and nothing is stored', async () => {
      const auth = await ctx.as(ANALYST);
      const before = { writes: writes().length, audit: ctx.audit.record.mock.calls.length };
      const key = idem();
      for (let i = 0; i < 2; i += 1) {
        const res = await http()
          .post(VALIDATE)
          .set(auth)
          .set(key)
          .send({ definition: quarantineDomainDefinition() })
          .expect(200);
        expect(res.headers['idempotency-replayed']).toBeUndefined();
      }
      expect(idempotency.rows.size).toBe(0);
      expect(writes().length).toBe(before.writes);
      expect(ctx.audit.record.mock.calls.length).toBe(before.audit);
    });

    it('B16: definitions up to the DSL document limit are accepted; a larger body is 413 (§14.8)', async () => {
      const bigDefinition = (values: number, length: number) => ({
        ...quarantineDomainDefinition(),
        rules: Array.from({ length: 100 }, (_, i) => ({
          id: `r${i}`,
          priority: i,
          description: 'x'.repeat(250),
          when: {
            field: 'recipient.local_part',
            op: 'in',
            value: Array.from(
              { length: values },
              (_x, j) => `user-${i}-${j}-${'y'.repeat(length)}`,
            ),
          },
          actions: [{ type: 'TAG', label: `t${i}` }],
        })),
      });
      // A valid document of about 150 KiB on the wire: above Express's default 100 KiB.
      const medium = bigDefinition(5, 225);
      expect(validatePolicyDefinition(medium).ok).toBe(true);
      const mediumBody = JSON.stringify({ definition: medium });
      expect(Buffer.byteLength(mediumBody, 'utf8')).toBeGreaterThan(145 * 1024);
      const accepted = await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .set('Content-Type', 'application/json')
        .send(mediumBody)
        .expect(200);
      expect(accepted.body).toMatchObject({ valid: true });
      // A valid document just below the DSL's 262 144-byte limit.
      const large = bigDefinition(8, 260);
      expect(validatePolicyDefinition(large).ok).toBe(true);
      const largeBody = JSON.stringify({ definition: large });
      expect(Buffer.byteLength(largeBody, 'utf8')).toBeGreaterThan(245 * 1024);
      expect(Buffer.byteLength(largeBody, 'utf8')).toBeLessThan(POLICY_LIMITS.documentBytes);
      await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .set('Content-Type', 'application/json')
        .send(largeBody)
        .expect(200);
      // Above the route's limit (document limit + wrapper): 413 payload_too_large, not 500.
      const tooLarge = JSON.stringify({
        definition: {
          ...quarantineDomainDefinition(),
          pad: 'z'.repeat(POLICY_JSON_BODY_LIMIT_BYTES),
        },
      });
      const refused = await http()
        .post(VALIDATE)
        .set(await ctx.as(ANALYST))
        .set('Content-Type', 'application/json')
        .send(tooLarge);
      expect([refused.status, refused.body.code]).toEqual([413, 'payload_too_large']);
      expect(refused.body.message).toBe(
        `Request body is larger than the ${POLICY_JSON_BODY_LIMIT_BYTES}-byte limit of this route`,
      );
      expect(refused.headers['x-request-id']).toBeDefined();
    });
  });

  describe('POST /policies/dry-run', () => {
    it('re-evaluates the newest stored rounds against the active policies (examples, no change)', async () => {
      await publish(quarantineDomainDefinition('partner.example'));
      const decided = await storedRounds();
      expect(decided.disposition).toBe('quarantine');
      const res = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .send(POLICY_BUILDER_EXAMPLES.sampleBody)
        .expect(200);
      expect(PolicySampleDryRunResponseSchema.parse(res.body)).toEqual(res.body);
      expect(res.body).toMatchObject({
        target: { kind: 'active', policyId: null, versionNo: null },
        limit: 25,
        evaluated: 1,
        skipped: 1,
        truncated: false,
        exhausted: true,
        summary: { changed: 0, unchanged: 1, transitions: [] },
      });
      expect(res.body.items).toMatchObject([
        {
          messageId: MESSAGE_ID,
          scanId: '900',
          outcome: 'evaluated',
          stored: { disposition: 'quarantine', source: 'tenant_rule', versionNo: 1 },
          dryRun: { disposition: 'quarantine', source: 'tenant_rule', versionNo: 1 },
          dispositionChanged: false,
          decisiveChanged: false,
        },
        { messageId: null, scanId: '899', outcome: 'not_found', dryRun: null },
      ]);
      // The default window: the last 7 days before the request; at most limit × 4 rows read.
      const [, filter] = ctx.executions.sampleRounds.mock.calls[0] as [
        unknown,
        { from: Date; to: Date; take: number },
      ];
      expect(filter.take).toBe(100);
      expect(filter.to.getTime() - filter.from.getTime()).toBe(7 * 86_400_000);
      expect(JSON.stringify(res.body)).not.toContain('@');
    });

    it('shows the change of another target (platform), with transitions', async () => {
      await publish(quarantineDomainDefinition('partner.example'));
      await storedRounds();
      const res = await http()
        .post(SAMPLE)
        .set(await ctx.as(ADMIN))
        .send({ target: 'platform', sample: { direction: 'inbound', limit: 5 } })
        .expect(200);
      expect(res.body.items[0]).toMatchObject({
        stored: { disposition: 'quarantine' },
        dryRun: { disposition: 'allow', source: 'platform_default' },
        dispositionChanged: true,
        decisiveChanged: true,
      });
      expect(res.body.summary.transitions).toEqual([{ from: 'quarantine', to: 'allow', count: 1 }]);
      expect(ctx.executions.sampleRounds).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ direction: 'inbound', take: 20 }),
      );
    });

    it('refuses strict-body, limit and range violations with 400 validation_failed', async () => {
      const cases: object[] = [
        { unknown: 1 },
        { sample: { limit: 0 } },
        { sample: { limit: 201 } },
        { sample: { limit: 1.5 } },
        { sample: { extra: true } },
        { sample: { from: 'yesterday' } },
        { target: 'everything' },
        // Above POLICY_DRY_RUN_SAMPLE_MAX (30 in this suite).
        { sample: { limit: 31 } },
        // Longer than POLICY_HISTORY_MAX_RANGE_DAYS (14 in this suite).
        { sample: { from: '2026-10-01T00:00:00.000Z', to: '2026-10-15T00:00:00.001Z' } },
        // from not before to.
        { sample: { from: '2026-10-02T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z' } },
      ];
      for (const body of cases) {
        const res = await http()
          .post(SAMPLE)
          .set(await ctx.as(ANALYST))
          .send(body)
          .expect(400);
        expect(res.body.code, JSON.stringify(body)).toBe('validation_failed');
      }
      const limit = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .send({ sample: { limit: 31 } })
        .expect(400);
      expect(JSON.stringify(limit.body.message)).toContain('POLICY_DRY_RUN_SAMPLE_MAX');
      expect(ctx.executions.sampleRounds).not.toHaveBeenCalled();
    });

    it('answers 400 policy_definition_invalid for an invalid inline target and 404 for a foreign version', async () => {
      const inline = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .send({ target: { definition: { dslVersion: 'policy-dsl/0' } } })
        .expect(400);
      expect(inline.body.code).toBe('policy_definition_invalid');
      expect(inline.body.violations.length).toBeGreaterThan(0);
      // A policy of organization B: its version is not visible to organization A.
      const created = await http()
        .post(P)
        .set(await ctx.as(ADMIN, 'B'))
        .send({ name: 'b', definition: quarantineDomainDefinition() })
        .expect(201);
      const foreign = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .send({ target: { policyId: created.body.policy.id as string, versionNo: 1 } })
        .expect(404);
      expect(foreign.body.code).toBe('policy_version_not_found');
      const unknown = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .send({ target: { policyId: randomUUID(), versionNo: 1 } })
        .expect(404);
      expect(unknown.body.code).toBe('policy_version_not_found');
      expect(ctx.executions.sampleRounds).not.toHaveBeenCalled();
    });

    it('requires policy:manage and message:read', async () => {
      await storedRounds();
      for (const permissions of [READ_ONLY, ['policy:manage'], ['message:read']]) {
        await http()
          .post(SAMPLE)
          .set(await ctx.as(permissions))
          .send({})
          .expect(403);
      }
      await http()
        .post(SAMPLE)
        .set(await ctx.as(['policy:manage', 'message:read']))
        .send({})
        .expect(200);
    });

    it('limits each principal to POLICY_SAMPLE_DRY_RUNS_PER_MINUTE (429 route, RateLimit-*, Retry-After)', async () => {
      await storedRounds();
      const auth = await ctx.as(ANALYST);
      const first = await http().post(SAMPLE).set(auth).send({}).expect(200);
      expect(first.headers['ratelimit-limit']).toBe('2');
      expect(first.headers['ratelimit-remaining']).toBe('1');
      await http().post(SAMPLE).set(auth).send({}).expect(200);
      const third = await http().post(SAMPLE).set(auth).send({}).expect(429);
      expect(third.body).toMatchObject({ code: 'rate_limited', scope: 'route' });
      expect(Number(third.headers['retry-after'])).toBeGreaterThan(0);
      expect(third.headers['ratelimit-limit']).toBe('2');
      expect(third.headers['ratelimit-remaining']).toBe('0');
      // Validation does not share the bucket.
      await http()
        .post(VALIDATE)
        .set(auth)
        .send({ definition: quarantineDomainDefinition() })
        .expect(200);
    });

    it('writes nothing; an Idempotency-Key is accepted and nothing is stored', async () => {
      await publish(quarantineDomainDefinition('partner.example'));
      await storedRounds();
      // The publish above stored its own key; the dry-run must add none.
      const before = {
        writes: writes().length,
        audit: ctx.audit.record.mock.calls.length,
        keys: idempotency.rows.size,
      };
      const res = await http()
        .post(SAMPLE)
        .set(await ctx.as(ANALYST))
        .set(idem())
        .send({ target: { definition: quarantineDomainDefinition('other.example') } })
        .expect(200);
      expect(res.body.target).toEqual({
        kind: 'inline',
        policyId: '00000000-0000-7000-8000-000000000000',
        versionNo: 1,
      });
      expect(res.headers['idempotency-replayed']).toBeUndefined();
      expect(idempotency.rows.size).toBe(before.keys);
      expect(writes().length).toBe(before.writes);
      expect(ctx.audit.record.mock.calls.length).toBe(before.audit);
    });
  });
});
