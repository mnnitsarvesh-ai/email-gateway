/**
 * Step 7.3 policy builder api against the real MySQL writer and replica
 * (docs/plan/steps/22-policy-builder.md §4.2, §4.3, §9.2): `POST /policies/validate` checks the
 * DSL and the directory references against the organization's real departments on the replica;
 * `POST /policies/dry-run` samples the newest stored evaluation per message of the caller's
 * organization only (two organizations seeded), reproduces unchanged decisions for the active
 * target, shows the expected changes for a published (not active) QUARANTINE version, refuses
 * another organization's version with 404, and neither route writes anything (checksums of the
 * policy tables, `policy_execution_logs`, `audit_logs`, `api_idempotency_keys` and the outbox
 * count). B16: a valid ~150 KiB definition is accepted and a body above the policy routes' JSON
 * limit is `413 payload_too_large`; a direction-filtered sample is planned on the direction index.
 */
// ---- Route coverage (step 6.1 §3.8, test/route-coverage/policy-builder.ts) ----
// @covers post /api/v1/policies/dry-run
// @covers post /api/v1/policies/validate
// ---- end of route coverage ----
import { PrismaReadService } from '@email-gateway/common';
import { validatePolicyDefinition } from '@email-gateway/policy-dsl';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { POLICY_JSON_BODY_LIMIT_BYTES } from '../src/http/policy-body-limit';
import { PolicyTenantDataRepository } from '../src/modules/tenant-data/policy-tenant-data.repository';
import {
  departmentExceptionDefinition,
  quarantineDomainDefinition,
  tagAllDefinition,
} from '../test/support/policy-fixtures';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { bearer, idem, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';
import { insertCleanRound, policyChecksums, storeEvaluation } from './support/policy-rounds';

const POLL = { timeout: 20_000, interval: 250 };
const P = '/api/v1/policies';

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let analystA: Record<string, string>;
let readOnlyA: Record<string, string>;
let adminB: Record<string, string>;

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

async function purge(orgIds: bigint[]): Promise<void> {
  const repo = ctx.get(PolicyTenantDataRepository);
  for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  const where = { organizationId: { in: orgIds } };
  await ctx.prisma.messageRiskScore.deleteMany({ where });
  await ctx.prisma.emailAuthResult.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
}

/** Creates a policy and publishes version 1 (activated unless `activate: false`). */
async function publishPolicy(
  auth: Record<string, string>,
  name: string,
  definition: object,
): Promise<string> {
  const created = await ctx.http.post(P).set(headers(auth)).send({ name, definition }).expect(201);
  const id = created.body.policy.id as string;
  await ctx.http
    .post(`${P}/${id}/versions/1/publish`)
    .set(idem())
    .set(headers(auth))
    .send({ expectedRowVersion: 1 })
    .expect(200);
  return id;
}

/** Reads until `done` (or the timeout) and returns the last value. */
async function waitFor<T>(
  read: () => Promise<T>,
  done: (value: T) => boolean,
  timeoutMs = 20_000,
): Promise<T> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const value = await read();
    if (done(value) || Date.now() > until) return value;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
}

/** A message of `org` from `sender` received `minutesAgo` minutes ago. */
async function message(
  org: FixtureOrganization,
  sender: string,
  minutesAgo: number,
): Promise<LifecycleMessage> {
  const msg = await insertLifecycleMessage(ctx, org, {
    state: 'delivered',
    receivedAt: new Date(Date.now() - minutesAgo * 60_000),
    recipients: [{ address: 'alice@acme.example', status: 'delivered' }],
  });
  await ctx.prisma.emailMessage.update({
    where: { id_receivedAt: { id: msg.id, receivedAt: msg.receivedAt } },
    data: { envelopeFrom: sender, headerFrom: sender },
  });
  return msg;
}

beforeAll(async () => {
  ctx = await createIntegrationApp({
    POLICY_HISTORY_MAX_RANGE_DAYS: '7',
    POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: '60',
  });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => purge([orgA.id, orgB.id]));
  adminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true }));
  analystA = await tokenOf(await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true }));
  readOnlyA = await tokenOf(await fx.createUser(orgA, { roles: ['read_only_user'], mfa: true }));
  adminB = await tokenOf(await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true }));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('POST /policies/validate on the replica (§4.2)', () => {
  it('checks references against the organization’s real departments and writes nothing', async () => {
    const created = await ctx.http
      .post('/api/v1/departments')
      .set(headers(adminA))
      .send({ name: 'Finance' })
      .expect(201);
    const finance = created.body.id as string;
    const other = await ctx.http
      .post('/api/v1/departments')
      .set(headers(adminB))
      .send({ name: 'Finance' })
      .expect(201);
    const before = await policyChecksums(ctx, orgA);
    // The department is visible on the replica once replicated.
    await expect
      .poll(async () => {
        const res = await ctx.http
          .post(`${P}/validate`)
          .set(headers(analystA))
          .send({ definition: departmentExceptionDefinition(finance) });
        return res.status === 200 ? (res.body.referenceViolations as unknown[]).length : -1;
      }, POLL)
      .toBe(0);
    // Organization B's department is unknown in organization A.
    const foreign = await ctx.http
      .post(`${P}/validate`)
      .set(headers(analystA))
      .send({ definition: departmentExceptionDefinition(other.body.id as string) })
      .expect(200);
    expect(foreign.body).toMatchObject({
      valid: true,
      ruleCount: 1,
      references: { departmentIds: [other.body.id], userIds: [] },
      referenceViolations: [{ path: 'rules[0].unless[0].value[0]', code: 'department_unknown' }],
    });
    const invalid = await ctx.http
      .post(`${P}/validate`)
      .set(headers(adminA))
      .set(idem())
      .send({
        definition: {
          ...quarantineDomainDefinition(),
          rules: [{ id: 'x', priority: 1, when: { field: 'nope', op: 'is', value: true } }],
        },
      })
      .expect(200);
    expect(invalid.body.valid).toBe(false);
    expect(invalid.body.violations.map((v: { code: string }) => v.code)).toEqual([
      'value_required',
      'unknown_field',
    ]);
    await ctx.http
      .post(`${P}/validate`)
      .set(headers(readOnlyA))
      .send({ definition: tagAllDefinition() })
      .expect(403);
    expect(await policyChecksums(ctx, orgA)).toEqual(before);
  });

  it('B16: accepts a valid ~150 KiB definition; a body above the route limit is 413 (§14.8)', async () => {
    const rules = Array.from({ length: 100 }, (_, i) => ({
      id: `r${i}`,
      priority: i,
      description: 'x'.repeat(250),
      when: {
        field: 'recipient.local_part',
        op: 'in',
        value: Array.from({ length: 5 }, (_x, j) => `user-${i}-${j}-${'y'.repeat(225)}`),
      },
      actions: [{ type: 'TAG', label: `t${i}` }],
    }));
    const definition = { ...quarantineDomainDefinition(), rules };
    expect(validatePolicyDefinition(definition).ok).toBe(true);
    const body = JSON.stringify({ definition });
    expect(Buffer.byteLength(body, 'utf8')).toBeGreaterThan(145 * 1024);
    const res = await ctx.http
      .post(`${P}/validate`)
      .set(headers(analystA))
      .set('Content-Type', 'application/json')
      .send(body);
    // The policy routes accept the DSL's document limit plus the request wrapper (B16).
    expect([res.status, res.body.valid]).toEqual([200, true]);
    const tooLarge = JSON.stringify({
      definition: { ...definition, pad: 'z'.repeat(POLICY_JSON_BODY_LIMIT_BYTES) },
    });
    const refused = await ctx.http
      .post(`${P}/validate`)
      .set(headers(analystA))
      .set('Content-Type', 'application/json')
      .send(tooLarge);
    expect([refused.status, refused.body.code]).toEqual([413, 'payload_too_large']);
  });
});

describe('POST /policies/dry-run over stored evaluations of two organizations (§4.3)', () => {
  let policyA: string;
  let bad1: LifecycleMessage;
  let bad2: LifecycleMessage;
  let clean: LifecycleMessage;
  let messageB: LifecycleMessage;

  beforeAll(async () => {
    // Organization A: an active TAG policy decided the stored evaluations; then a QUARANTINE
    // version is published without being activated.
    policyA = await publishPolicy(adminA, 'Tag external', tagAllDefinition('external'));
    bad1 = await message(orgA, 'ceo@bad.example', 30);
    clean = await message(orgA, 'someone@partner.example', 20);
    bad2 = await message(orgA, 'billing@bad.example', 10);
    const r0 = await insertCleanRound(ctx, bad1, 0);
    await storeEvaluation(ctx, orgA, bad1, r0);
    const r1 = await insertCleanRound(ctx, bad1, 1);
    await storeEvaluation(ctx, orgA, bad1, r1);
    await storeEvaluation(ctx, orgA, clean, await insertCleanRound(ctx, clean, 0));
    await storeEvaluation(ctx, orgA, bad2, await insertCleanRound(ctx, bad2, 0));
    await ctx.http
      .post(`${P}/${policyA}/versions`)
      .set(headers(analystA))
      .send({ definition: quarantineDomainDefinition('bad.example') })
      .expect(201);
    await ctx.http
      .post(`${P}/${policyA}/versions/2/publish`)
      .set(idem())
      .set(headers(adminA))
      .send({ expectedRowVersion: 1, activate: false })
      .expect(200);
    // Organization B: one stored evaluation of its own.
    messageB = await message(orgB, 'ceo@bad.example', 5);
    await storeEvaluation(ctx, orgB, messageB, await insertCleanRound(ctx, messageB, 0));
    // Wait until the replica holds the rows the sample reads (expect.poll is test-only).
    const reader = ctx.get(PrismaReadService).client;
    const replicated = await waitFor(
      () =>
        Promise.all([
          reader.policyExecutionLog.count({
            where: { organizationId: { in: [orgA.id, orgB.id] } },
          }),
          reader.policyVersion.count({ where: { organizationId: orgA.id, status: 'published' } }),
        ]),
      ([logs, versions]) => logs === 5 && versions === 2,
    );
    expect(replicated).toEqual([5, 2]);
  }, 120_000);

  it('samples only the caller’s rounds, the newest round per message; the active target changes nothing', async () => {
    const before = await policyChecksums(ctx, orgA);
    const res = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(analystA))
      .set(idem())
      .send({})
      .expect(200);
    expect(res.body.target).toEqual({ kind: 'active', policyId: null, versionNo: null });
    expect(
      res.body.items.map((i: { messageId: string; lifecycleRound: number }) => [
        i.messageId,
        i.lifecycleRound,
      ]),
    ).toEqual([
      [bad2.publicId, 0],
      [clean.publicId, 0],
      [bad1.publicId, 1],
    ]);
    expect(JSON.stringify(res.body)).not.toContain(messageB.publicId);
    expect(res.body).toMatchObject({
      evaluated: 3,
      skipped: 0,
      truncated: false,
      exhausted: true,
      summary: { changed: 0, unchanged: 3, transitions: [] },
    });
    for (const item of res.body.items as Array<Record<string, unknown>>) {
      expect(item).toMatchObject({
        outcome: 'evaluated',
        trigger: 'scanned',
        stored: { disposition: 'allow' },
        dryRun: { disposition: 'allow', actionTypes: ['ALLOW', 'TAG'] },
        dispositionChanged: false,
        decisiveChanged: false,
      });
    }
    expect(JSON.stringify(res.body)).not.toContain('@');
    expect(await policyChecksums(ctx, orgA)).toEqual(before);
  });

  it('shows the expected changes of a published QUARANTINE version, and writes nothing', async () => {
    const before = await policyChecksums(ctx, orgA);
    const res = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(adminA))
      .send({ target: { policyId: policyA, versionNo: 2 }, sample: { direction: 'inbound' } })
      .expect(200);
    expect(res.body.target).toEqual({ kind: 'version', policyId: policyA, versionNo: 2 });
    const byMessage = new Map(
      (res.body.items as Array<{ messageId: string }>).map((i) => [i.messageId, i]),
    );
    for (const changed of [bad1, bad2]) {
      expect(byMessage.get(changed.publicId)).toMatchObject({
        stored: { disposition: 'allow' },
        dryRun: {
          disposition: 'quarantine',
          source: 'tenant_rule',
          policyId: policyA,
          versionNo: 2,
          ruleId: 'quarantine-domain',
        },
        dispositionChanged: true,
        decisiveChanged: true,
      });
    }
    expect(byMessage.get(clean.publicId)).toMatchObject({ dispositionChanged: false });
    expect(res.body.summary).toMatchObject({
      changed: 2,
      unchanged: 1,
      transitions: [{ from: 'allow', to: 'quarantine', count: 2 }],
    });
    // The window bound: a window with no stored round of this organization.
    const empty = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(adminA))
      .send({
        sample: {
          from: new Date(Date.now() - 6 * 86_400_000).toISOString(),
          to: new Date(Date.now() - 5 * 86_400_000).toISOString(),
        },
      })
      .expect(200);
    expect(empty.body).toMatchObject({ items: [], evaluated: 0, exhausted: true });
    expect(await policyChecksums(ctx, orgA)).toEqual(before);
  });

  it('isolates organizations: B sees only its round, A cannot target B’s version (404)', async () => {
    const own = await ctx.http.post(`${P}/dry-run`).set(headers(adminB)).send({}).expect(200);
    expect(own.body.items.map((i: { messageId: string }) => i.messageId)).toEqual([
      messageB.publicId,
    ]);
    const policyB = await publishPolicy(adminB, 'b', quarantineDomainDefinition('bad.example'));
    const foreign = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(analystA))
      .send({ target: { policyId: policyB, versionNo: 1 } })
      .expect(404);
    expect(foreign.body.code).toBe('policy_version_not_found');
    await ctx.http.post(`${P}/dry-run`).set(headers(readOnlyA)).send({}).expect(403);
    const tooWide = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(analystA))
      .send({ sample: { from: new Date(Date.now() - 8 * 86_400_000).toISOString() } })
      .expect(400);
    expect(tooWide.body.code).toBe('validation_failed');
  });

  it('bounds a direction-filtered sample by the direction index, not a walk of the window (§14.8)', async () => {
    // Organization A stored inbound rounds only: an outbound sample finds nothing.
    const none = await ctx.http
      .post(`${P}/dry-run`)
      .set(headers(analystA))
      .send({ sample: { direction: 'outbound' } })
      .expect(200);
    expect(none.body).toMatchObject({ items: [], evaluated: 0, exhausted: true });
    // The selection the repository issues (sampleRounds): the replica plans it on the
    // (organization_id, direction, received_at) index, so the LIMIT bounds the entries read.
    const reader = ctx.get(PrismaReadService).client;
    const to = new Date();
    const from = new Date(to.getTime() - 7 * 86_400_000);
    const INDEX = 'policy_execution_logs_organization_id_direction_received_at_idx';
    for (const direction of ['outbound', 'inbound']) {
      // Prisma returns EXPLAIN's columns positionally (f0…): MySQL 8.4's order is id,
      // select_type, table, partitions, type, possible_keys, key, key_len, ref, rows, filtered,
      // Extra.
      const plan = await reader.$queryRaw<Array<Record<string, unknown>>>`
        EXPLAIN SELECT id, received_at FROM policy_execution_logs
         WHERE organization_id = ${orgA.id} AND received_at >= ${from} AND received_at < ${to}
           AND scan_id IS NOT NULL AND direction = ${direction}
         ORDER BY received_at DESC, id DESC LIMIT 200`;
      expect(plan).toHaveLength(1);
      const [, , table, , , possibleKeys, key] = Object.values(plan[0] ?? {});
      expect(table).toBe('policy_execution_logs');
      expect(String(possibleKeys).split(',')).toContain(INDEX);
      if (direction === 'outbound') expect(key).toBe(INDEX);
    }
  });
});
