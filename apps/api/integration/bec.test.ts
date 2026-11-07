/**
 * Step 4.4 api routes against the real MySQL writer and replica (docs/plan/steps/
 * 12-phishing-bec.md B11–B15, B18, §9 "api"): executive and vendor profiles, trusted senders
 * (permissions, normalization, uniqueness and version 409s, per-tenant caps, another tenant's id
 * 404, audit rows with before-images), feedback on a scan's bec result (writer reads, suppression
 * bounds, idempotency, the active-rule cap), the NDJSON retraining export (MFA, no addresses or
 * notes, rate limit), suppressions, the history purge (MFA, batched, only the tenant's rows), the
 * `bec` scan settings, the `bec` section of the scans read API (replica, tenant-scoped, no span
 * text or hashes) and the organization purge of the seven BEC tables. Result rows are inserted
 * as the email-worker writes them (fixtures).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import {
  BEC_PURGE_ORDER,
  BecTenantDataRepository,
} from '../src/modules/tenant-data/bec-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(4).toString('hex');
const MARKER = `MARKER${run}`;

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let adminB: Record<string, string>;
let analystA: Record<string, string>;
let noMfaA: Record<string, string>;
let readerKeyA: Record<string, string>;

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

async function purgeBec(orgIds: bigint[]): Promise<void> {
  const repo = ctx.get(BecTenantDataRepository);
  for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  const where = { organizationId: { in: orgIds } };
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
}

const RULES = [
  {
    id: 'R2',
    code: 'bec.reply_to.freemail',
    category: 'identity',
    severity: 'medium',
    weight: 20,
    suppressed: null,
    evidence: [{ header: 'Reply-To', address: `pay.${run}@gmail.com`, domain: 'gmail.com' }],
  },
  {
    id: 'R1',
    code: 'bec.reply_to.domain_mismatch',
    category: 'identity',
    severity: 'medium',
    weight: 15,
    suppressed: null,
    evidence: [{ header: 'Reply-To', domain: 'gmail.com' }],
  },
  {
    id: 'C7',
    code: 'bec.content.urgency',
    category: 'intent',
    severity: 'low',
    weight: 10,
    suppressed: null,
    evidence: [
      {
        keywords: {
          category: 'urgency',
          language: 'en',
          lexiconIds: ['en.urgency.001'],
          spans: [{ source: 'text', start: 0, end: 6, text: MARKER }],
        },
      },
      {
        keywords: {
          category: 'urgency',
          language: 'hi-Latn',
          lexiconIds: ['hi-Latn.urgency.001'],
          spans: [{ source: 'subject', start: 2, end: 8 }],
        },
      },
    ],
  },
];

/** A completed round with a bec final and its `bec_scan_results` row (as the email-worker writes). */
async function insertBecRound(
  message: LifecycleMessage,
  from: { address: string; registrableDomain: string },
): Promise<bigint> {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const completedAt = new Date(startedAt.getTime() + 1_234);
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'suspicious',
      requiredEngines: ['rspamd', 'url', 'bec'],
      reasonCodes: RULES.map((r) => r.code),
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'bec',
      engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
      outcome: 'suspicious',
      score: 45,
      requiredScore: 40,
      durationMs: 321,
      attempt: 1,
      isFinal: true,
      reasonCodes: [...RULES.map((r) => r.code), 'bec.ai.unavailable'],
      settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
      evidence: { signals: [], thresholds: { suspicious: 40, malicious: 80 } },
      completedAt,
    },
  });
  await ctx.prisma.becScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      engineVersion: 'bec/1;lex=2876a3ab;fm=35f13669;br=fb362bf9',
      rulesVersion: 'bec-map/1',
      settingsVersion: 'bec-map/1;p=0123456789ab;t=none',
      lexiconVersion: '2876a3ab',
      textVersion: 'bec-text/1',
      deterministicScore: 45,
      score: 45,
      deterministicVerdict: 'suspicious',
      verdict: 'suspicious',
      inputs: { auth: 'available', url: 'available', text: 'complete', history: 'disabled' },
      rules: RULES,
      features: { rule_r1: 1, rule_r2: 1, rule_c7: 1, fromFreemail: false, [MARKER]: 1 },
      identity: {
        from: {
          displayName: `Billing ${MARKER}`,
          address: from.address,
          domain: from.registrableDomain,
          registrableDomain: from.registrableDomain,
          kind: 'external',
        },
        fromCount: 1,
        replyTo: [],
        sender: null,
        returnPath: null,
        envelopeFrom: from.address,
        isReply: false,
        flags: [],
      },
      ai: [],
      aiShadow: [
        {
          layer: 'local',
          mode: 'shadow',
          provider: 'local',
          modelId: 'bec-lr',
          modelVersion: 'bec-lr/1@0a0f071f7a91',
          promptTemplateVersion: null,
          status: 'ok',
          labels: [{ label: 'bec', confidence: 0.71 }],
          confidence: 0.71,
          indicators: ['urgency'],
          citedFeatures: [{ feature: 'rule_c7', contribution: 0.4 }],
          spans: [],
          responseSha256: 'e'.repeat(64),
          durationMs: 4,
        },
      ],
      durationMs: 321,
    },
  });
  return scan.id;
}

beforeAll(async () => {
  ctx = await createIntegrationApp({
    BEC_MAX_EXECUTIVES: '2',
    BEC_MAX_TRUSTED_SENDERS: '2',
    BEC_SUPPRESSIONS_MAX_PER_TENANT: '2',
  });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => purgeBec([orgA.id, orgB.id]));
  adminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true }));
  adminB = await tokenOf(await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true }));
  analystA = await tokenOf(await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true }));
  noMfaA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  readerKeyA = apiKeyHeader(await fx.createApiKey(orgA, ['bec:read', 'message:read']));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const auditOf = (action: string, resourceId: string) =>
  ctx.prisma.auditLog.findFirst({
    where: { organizationId: orgA.id, action, resourceId },
    orderBy: { id: 'desc' },
  });

describe('executive profiles (B18)', () => {
  it('creates, normalizes, refuses duplicates, caps, updates with versions and deletes, audited', async () => {
    const created = await ctx.http
      .post('/api/v1/bec/executives')
      .set(headers(adminA))
      .send({
        displayName: 'Anita Sharma',
        aliases: ['A. Sharma'],
        knownAddresses: ['Anita.Sharma@Acme.Example', 'anita.sharma@acme.example'],
        title: 'CEO',
      })
      .expect(201);
    expect(created.body).toMatchObject({
      displayName: 'Anita Sharma',
      normalizedName: 'anita sharma',
      knownAddresses: ['anita.sharma@acme.example'],
      version: 1,
      enabled: true,
    });
    const id = created.body.id as string;
    expect(await auditOf('bec_executive.created', id)).toBeTruthy();

    const dup = await ctx.http
      .post('/api/v1/bec/executives')
      .set(headers(adminA))
      .send({ displayName: 'ANITA  sharma!' })
      .expect(409);
    expect(dup.body).toMatchObject({ code: 'executive_exists', id });
    // The same name in another organization is independent.
    await ctx.http
      .post('/api/v1/bec/executives')
      .set(headers(adminB))
      .send({ displayName: 'Anita Sharma' })
      .expect(201);
    // Cap of 2 per organization (BEC_MAX_EXECUTIVES).
    await ctx.http
      .post('/api/v1/bec/executives')
      .set(headers(adminA))
      .send({ displayName: 'Ravi Kumar' })
      .expect(201);
    const capped = await ctx.http
      .post('/api/v1/bec/executives')
      .set(headers(adminA))
      .send({ displayName: 'Third Person' })
      .expect(409);
    expect(capped.body).toMatchObject({ code: 'bec_limit_reached', limit: 2 });

    // Another tenant's id is a 404 for every route.
    await ctx.http.get(`/api/v1/bec/executives/${id}`).set(headers(adminB)).expect(404);
    await ctx.http
      .patch(`/api/v1/bec/executives/${id}`)
      .set(headers(adminB))
      .send({ version: 1, enabled: false })
      .expect(404);
    await ctx.http.delete(`/api/v1/bec/executives/${id}`).set(headers(adminB)).expect(404);

    const stale = await ctx.http
      .patch(`/api/v1/bec/executives/${id}`)
      .set(headers(adminA))
      .send({ version: 7, enabled: false })
      .expect(409);
    expect(stale.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    const updated = await ctx.http
      .patch(`/api/v1/bec/executives/${id}`)
      .set(headers(adminA))
      .send({ version: 1, displayName: 'Anita R. Sharma', enabled: false })
      .expect(200);
    expect(updated.body).toMatchObject({
      version: 2,
      enabled: false,
      normalizedName: 'anita r sharma',
    });
    expect((await auditOf('bec_executive.updated', id))?.metadata).toMatchObject({
      before: { displayName: 'Anita Sharma', enabled: true, version: 1 },
      after: { displayName: 'Anita R. Sharma', enabled: false, version: 2 },
    });

    // Reads: API key with bec:read (replica), enabled filter.
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get('/api/v1/bec/executives?enabled=false')
          .set(headers(readerKeyA));
        return (res.body.data as { id: string }[] | undefined)?.map((e) => e.id);
      }, POLL)
      .toEqual([id]);
    await ctx.http.post('/api/v1/bec/executives').set(headers(readerKeyA)).send({}).expect(403);

    await ctx.http
      .delete(`/api/v1/bec/executives/${id}?version=1`)
      .set(headers(adminA))
      .expect(409);
    await ctx.http.delete(`/api/v1/bec/executives/${id}`).set(headers(adminA)).expect(204);
    expect((await auditOf('bec_executive.deleted', id))?.metadata).toMatchObject({
      before: { displayName: 'Anita R. Sharma', version: 2 },
    });
    expect(await ctx.prisma.becExecutiveProfile.count({ where: { publicId: id } })).toBe(0);
  });
});

describe('vendor profiles and trusted senders (B7, B18)', () => {
  it('normalizes vendor domains; refuses public suffixes (400) and free-mail domains (422)', async () => {
    const res = await ctx.http
      .post('/api/v1/bec/vendors')
      .set(headers(adminA))
      .send({
        name: 'Globex Supplies',
        domains: ['Billing.Globex-Supplies.Example', 'globex-supplies.example'],
        knownSenders: ['AR@globex-supplies.example'],
      })
      .expect(201);
    expect(res.body).toMatchObject({
      domains: ['globex-supplies.example'],
      knownSenders: ['ar@globex-supplies.example'],
      paymentChangeSensitive: true,
    });
    await ctx.http
      .post('/api/v1/bec/vendors')
      .set(headers(adminA))
      .send({ name: 'Bad', domains: ['co.uk'] })
      .expect(400);
    const freemail = await ctx.http
      .post('/api/v1/bec/vendors')
      .set(headers(adminA))
      .send({ name: 'Bad Two', domains: ['hotmail.com'] })
      .expect(422);
    expect(freemail.body.code).toBe('vendor_domain_freemail');
    const patched = await ctx.http
      .patch(`/api/v1/bec/vendors/${res.body.id as string}`)
      .set(headers(adminA))
      .send({ version: 1, paymentChangeSensitive: false })
      .expect(200);
    expect(patched.body).toMatchObject({ version: 2, paymentChangeSensitive: false });
    await ctx.http
      .get(`/api/v1/bec/vendors/${res.body.id as string}`)
      .set(headers(adminB))
      .expect(404);
  });

  it('trusted senders: normalized, unique per (kind, value), free-mail refused, capped, audited', async () => {
    const address = await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({ kind: 'address', value: 'Ops@Partner.Example', reason: 'Payroll partner' })
      .expect(201);
    expect(address.body).toMatchObject({ value: 'ops@partner.example', expired: false });
    const dup = await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({ kind: 'address', value: 'ops@partner.example', reason: 'again' })
      .expect(409);
    expect(dup.body.code).toBe('trusted_sender_exists');
    const free = await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({ kind: 'domain', value: 'gmail.com', reason: 'no' })
      .expect(422);
    expect(free.body.code).toBe('trusted_domain_freemail');
    await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({
        kind: 'domain',
        value: 'partner.example',
        reason: 'Partner',
        expiresAt: new Date(Date.now() + 400 * 86_400_000).toISOString(),
      })
      .expect(400);
    const domain = await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({ kind: 'domain', value: 'partner.example', reason: 'Partner' })
      .expect(201);
    const capped = await ctx.http
      .post('/api/v1/bec/trusted-senders')
      .set(headers(analystA))
      .send({ kind: 'domain', value: 'other.example', reason: 'x' })
      .expect(409);
    expect(capped.body.code).toBe('bec_limit_reached');
    const id = domain.body.id as string;
    await ctx.http
      .patch(`/api/v1/bec/trusted-senders/${id}`)
      .set(headers(analystA))
      .send({ version: 1, reason: 'Partner (renewed)' })
      .expect(200);
    await ctx.http.delete(`/api/v1/bec/trusted-senders/${id}`).set(headers(adminB)).expect(404);
    await ctx.http.delete(`/api/v1/bec/trusted-senders/${id}`).set(headers(analystA)).expect(204);
    expect((await auditOf('bec_trusted_sender.deleted', id))?.metadata).toMatchObject({
      before: { kind: 'domain', value: 'partner.example', reason: 'Partner (renewed)', version: 2 },
    });
  });
});

describe('feedback, suppressions, export and the scans read API (B11, B15)', () => {
  let message: LifecycleMessage;
  let scanId: bigint;
  let feedbackUrl: string;

  beforeAll(async () => {
    message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    scanId = await insertBecRound(message, {
      address: 'billing@partner-co.example',
      registrableDomain: 'partner-co.example',
    });
    feedbackUrl = `/api/v1/messages/${message.publicId}/scans/${scanId.toString()}/bec-feedback`;
  });

  it('records a false positive with a domain suppression; refuses repeats and out-of-bounds blocks', async () => {
    const res = await ctx.http
      .post(feedbackUrl)
      .set(headers(adminA))
      .send({
        kind: 'false_positive',
        reasonCodes: ['bec.reply_to.freemail', 'bec.ai.unavailable'],
        note: `Known partner ${MARKER}`,
        suppress: { codes: ['bec.reply_to.freemail'], scope: 'domain', days: 30 },
      })
      .expect(201);
    expect(res.body).toMatchObject({
      kind: 'false_positive',
      messageId: message.publicId,
      scanId: scanId.toString(),
      suppressions: [
        {
          reasonCode: 'bec.reply_to.freemail',
          senderScope: 'domain',
          senderValue: 'partner-co.example',
        },
      ],
    });
    const rule = await ctx.prisma.becSuppressionRule.findFirstOrThrow({
      where: { organizationId: orgA.id, reasonCode: 'bec.reply_to.freemail' },
    });
    const days = (rule.expiresAt.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(29.9);
    expect(days).toBeLessThanOrEqual(30);
    expect((await auditOf('bec_feedback.recorded', res.body.id as string))?.metadata).toMatchObject(
      {
        kind: 'false_positive',
        disputed: ['bec.reply_to.freemail', 'bec.ai.unavailable'],
        suppressions: [{ rule: 'bec.reply_to.freemail', senderScope: 'domain' }],
      },
    );

    const again = await ctx.http
      .post(feedbackUrl)
      .set(headers(adminA))
      .send({ kind: 'false_positive' })
      .expect(409);
    expect(again.body.code).toBe('feedback_exists');
    // Another kind by the same user, and the same kind by another user, are separate feedback.
    await ctx.http
      .post(feedbackUrl)
      .set(headers(adminA))
      .send({ kind: 'false_negative' })
      .expect(201);

    const notInResult = await ctx.http
      .post(feedbackUrl)
      .set(headers(analystA))
      .send({
        kind: 'false_positive',
        suppress: { codes: ['bec.content.payment_request'], scope: 'address', days: 5 },
      })
      .expect(422);
    expect(notInResult.body).toMatchObject({
      code: 'suppression_not_allowed',
      reason: 'code_not_in_result',
    });
    await ctx.http
      .post(feedbackUrl)
      .set(headers(analystA))
      .send({
        kind: 'false_positive',
        suppress: { codes: ['bec.auth.dmarc_fail'], scope: 'address', days: 5 },
      })
      .expect(400);
    const badCodes = await ctx.http
      .post(feedbackUrl)
      .set(headers(analystA))
      .send({ kind: 'false_positive', reasonCodes: ['bec.content.gift_card'] })
      .expect(422);
    expect(badCodes.body.code).toBe('feedback_codes_invalid');
    // Active-rule cap of 2: one rule exists, two more would make three.
    const capped = await ctx.http
      .post(feedbackUrl)
      .set(headers(analystA))
      .send({
        kind: 'false_positive',
        suppress: {
          codes: ['bec.reply_to.domain_mismatch', 'bec.content.urgency'],
          scope: 'address',
          days: 10,
        },
      })
      .expect(409);
    expect(capped.body.code).toBe('bec_limit_reached');
    expect(await ctx.prisma.becFeedback.count({ where: { organizationId: orgA.id } })).toBe(2);

    // Ids of another tenant, unknown scans, scans without a bec result.
    const foreign = await ctx.http
      .post(feedbackUrl)
      .set(headers(adminB))
      .send({ kind: 'false_negative' })
      .expect(404);
    expect(foreign.body.code).toBe('message_not_found');
    const unknownScan = await ctx.http
      .post(`/api/v1/messages/${message.publicId}/scans/987654321/bec-feedback`)
      .set(headers(adminA))
      .send({ kind: 'false_negative' })
      .expect(404);
    expect(unknownScan.body.code).toBe('scan_not_found');
    const plain = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const plainScan = await ctx.prisma.emailScan.create({
      data: {
        receivedAt: plain.receivedAt,
        messageId: plain.id,
        organizationId: orgA.id,
        lifecycleRound: 0,
        status: 'running',
      },
      select: { id: true },
    });
    const noResult = await ctx.http
      .post(`/api/v1/messages/${plain.publicId}/scans/${plainScan.id.toString()}/bec-feedback`)
      .set(headers(adminA))
      .send({ kind: 'false_negative' })
      .expect(404);
    expect(noResult.body.code).toBe('bec_result_not_found');
    await ctx.http
      .post(feedbackUrl)
      .set(headers(readerKeyA))
      .send({ kind: 'false_negative' })
      .expect(403);
  });

  it('refuses a domain suppression for a free-mail From domain', async () => {
    const freeMessage = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const freeScan = await insertBecRound(freeMessage, {
      address: `boss.${run}@gmail.com`,
      registrableDomain: 'gmail.com',
    });
    const res = await ctx.http
      .post(`/api/v1/messages/${freeMessage.publicId}/scans/${freeScan.toString()}/bec-feedback`)
      .set(headers(analystA))
      .send({
        kind: 'false_positive',
        suppress: { codes: ['bec.content.urgency'], scope: 'domain', days: 5 },
      })
      .expect(422);
    expect(res.body).toMatchObject({ code: 'suppression_not_allowed', reason: 'freemail_domain' });
  });

  it('lists feedback and suppressions (replica); deletes a suppression, audited', async () => {
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/bec/feedback').set(headers(readerKeyA));
        return (res.body.data as unknown[] | undefined)?.length;
      }, POLL)
      .toBe(2);
    const list = await ctx.http
      .get('/api/v1/bec/feedback?kind=false_positive')
      .set(headers(readerKeyA))
      .expect(200);
    expect(list.body.data).toEqual([
      expect.objectContaining({ kind: 'false_positive', messageId: message.publicId }),
    ]);
    expect((await ctx.http.get('/api/v1/bec/feedback').set(headers(adminB))).body.data).toEqual([]);
    const suppressions = await ctx.http
      .get('/api/v1/bec/suppressions?active=true')
      .set(headers(readerKeyA))
      .expect(200);
    expect(suppressions.body.data).toHaveLength(1);
    const id = suppressions.body.data[0].id as string;
    expect(suppressions.body.data[0].feedbackId).toBe(list.body.data[0].id);
    await ctx.http.delete(`/api/v1/bec/suppressions/${id}`).set(headers(adminB)).expect(404);
    await ctx.http.delete(`/api/v1/bec/suppressions/${id}`).set(headers(analystA)).expect(204);
    expect((await auditOf('bec_suppression.deleted', id))?.metadata).toMatchObject({
      before: { rule: 'bec.reply_to.freemail', senderValue: 'partner-co.example' },
    });
  });

  it('exports the B11 fields as NDJSON (MFA, never addresses, notes or markers), 10 per minute', async () => {
    await ctx.http.get('/api/v1/bec/feedback/export').set(headers(noMfaA)).expect(403);
    await ctx.http.get('/api/v1/bec/feedback/export').set(headers(analystA)).expect(403);
    const res = await ctx.http
      .get('/api/v1/bec/feedback/export?limit=1')
      .set(headers(adminA))
      .expect(200);
    expect(res.headers['content-type']).toContain('application/x-ndjson');
    expect(res.headers['x-next-cursor']).toBeTruthy();
    const next = await ctx.http
      .get(`/api/v1/bec/feedback/export?cursor=${res.headers['x-next-cursor'] as string}`)
      .set(headers(adminA))
      .expect(200);
    expect(next.headers['x-next-cursor']).toBeUndefined();
    const lines = [...res.text.trim().split('\n'), ...next.text.trim().split('\n')].map(
      (line) => JSON.parse(line) as Record<string, unknown>,
    );
    expect(lines.map((l) => l.kind).sort()).toEqual(['false_negative', 'false_positive']);
    expect(Object.keys(lines[0]!).sort()).toEqual(
      [
        'aiLabels',
        'createdAt',
        'deterministicScore',
        'deterministicVerdict',
        'engineVersion',
        'features',
        'feedbackId',
        'firedCodes',
        'kind',
        'llm',
        'localModel',
        'rulesVersion',
        'score',
        'verdict',
      ].sort(),
    );
    expect(lines[0]).toMatchObject({
      firedCodes: ['bec.reply_to.freemail', 'bec.reply_to.domain_mismatch', 'bec.content.urgency'],
      localModel: { id: 'bec-lr', version: 'bec-lr/1@0a0f071f7a91' },
      features: { rule_r1: 1, rule_r2: 1, rule_c7: 1, fromFreemail: false },
    });
    for (const forbidden of [
      MARKER,
      'partner-co.example',
      'gmail.com',
      message.publicId,
      'Known partner',
    ]) {
      expect(res.text + next.text).not.toContain(forbidden);
    }
    const audit = await ctx.prisma.auditLog.findFirst({
      where: { organizationId: orgA.id, action: 'bec_feedback.exported' },
    });
    expect(audit).toBeTruthy();
    // 10 per caller per minute (two used above).
    for (let i = 0; i < 8; i += 1) {
      await ctx.http.get('/api/v1/bec/feedback/export').set(headers(adminA)).expect(200);
    }
    await ctx.http.get('/api/v1/bec/feedback/export').set(headers(adminA)).expect(429);
  });

  it('shows the bec section in the scans read API (replica), tenant-scoped, without text or hashes', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const path = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => {
        const res = await ctx.http.get(path).set(headers(readerKeyA));
        const bec = (
          res.body.data?.[0]?.engines as
            { engine: string; bec?: { feedback: unknown[] } }[] | undefined
        )?.find((e) => e.engine === 'bec');
        return bec?.bec?.feedback.length;
      }, POLL)
      .toBe(2);
    const res = await ctx.http.get(path).set(headers(readerKeyA)).expect(200);
    expect(res.body.data[0].scanId).toBe(scanId.toString());
    const engine = res.body.data[0].engines.find((e: { engine: string }) => e.engine === 'bec');
    expect(engine).toMatchObject({
      outcome: 'suspicious',
      durationMs: null,
      bec: {
        verdict: 'suspicious',
        deterministicVerdict: 'suspicious',
        score: 45,
        thresholds: { suspicious: 40, malicious: 80 },
        inputs: { auth: 'available', history: 'disabled' },
        rules: [
          { id: 'R2', evidence: [{ header: 'Reply-To', domain: 'gmail.com' }] },
          { id: 'R1' },
          { id: 'C7', evidence: [{ keywords: { language: 'hi-Latn' } }] },
        ],
        aiShadow: [{ layer: 'local', mode: 'shadow', confidence: 0.71 }],
      },
    });
    expect(engine.completedAt).toMatch(/\.000Z$/);
    const text = JSON.stringify(res.body);
    for (const forbidden of [MARKER, 'responseSha256', 'eeeeeeee', 'textVersion']) {
      expect(text).not.toContain(forbidden);
    }
    await ctx.http.get(path).set(headers(adminB)).expect(404);
  });
});

describe('concurrent feedback (B11: the organization lock)', () => {
  it('serializes suppressions of one tenant: no deadlock on a new key, the cap is exact', async () => {
    const orgC = await fx.createOrganization();
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgC.id]));
    fx.registerCleanup(() => purgeBec([orgC.id]));
    const analysts = [];
    for (let i = 0; i < 4; i += 1) {
      analysts.push(
        await tokenOf(await fx.createUser(orgC, { roles: ['security_analyst'], mfa: true })),
      );
    }
    const from = { address: 'billing@race-co.example', registrableDomain: 'race-co.example' };
    const urls: string[] = [];
    for (let i = 0; i < 2; i += 1) {
      const m = await insertLifecycleMessage(ctx, orgC, { state: 'scanned' });
      const scan = await insertBecRound(m, from);
      urls.push(`/api/v1/messages/${m.publicId}/scans/${scan.toString()}/bec-feedback`);
    }
    const dispute = (url: string, auth: Record<string, string>, code: string) =>
      ctx.http
        .post(url)
        .set(headers(auth))
        .send({
          kind: 'false_positive',
          reasonCodes: [code],
          suppress: { codes: [code], scope: 'domain', days: 7 },
        });

    // Two analysts dispute the same code for the same sender on two scans at the same time: the
    // absent (organization, code, scope, sender) key must not deadlock (gap locks) or 409.
    for (let round = 0; round < 3; round += 1) {
      await ctx.prisma.becSuppressionRule.deleteMany({ where: { organizationId: orgC.id } });
      await ctx.prisma.becFeedback.deleteMany({ where: { organizationId: orgC.id } });
      const same = await Promise.all([
        dispute(urls[0]!, analysts[0]!, 'bec.reply_to.freemail'),
        dispute(urls[1]!, analysts[1]!, 'bec.reply_to.freemail'),
      ]);
      expect(same.map((r) => r.status)).toEqual([201, 201]);
      expect(
        await ctx.prisma.becSuppressionRule.count({ where: { organizationId: orgC.id } }),
      ).toBe(1);
    }

    // Cap 2 with one active rule: two concurrent new rules → exactly one is created.
    const capped = await Promise.all([
      dispute(urls[0]!, analysts[2]!, 'bec.reply_to.domain_mismatch'),
      dispute(urls[1]!, analysts[3]!, 'bec.content.urgency'),
    ]);
    expect(capped.map((r) => r.status).sort()).toEqual([201, 409]);
    expect(capped.find((r) => r.status === 409)!.body.code).toBe('bec_limit_reached');
    expect(await ctx.prisma.becSuppressionRule.count({ where: { organizationId: orgC.id } })).toBe(
      2,
    );
  });
});

describe('history purge, bec settings and the organization purge (B12, B13, B18)', () => {
  const historyRow = (organizationId: bigint) => ({
    organizationId,
    scope: 'sender' as const,
    keyHash: randomBytes(32).toString('hex'),
    messageCount: 3,
    inboundCount: 3,
    firstSeenAt: new Date(Date.now() - 86_400_000),
    lastSeenAt: new Date(),
  });

  it('purges only the tenant’s history rows (MFA, 202 with the count, audited)', async () => {
    await ctx.prisma.becContactHistory.createMany({
      data: [historyRow(orgA.id), historyRow(orgA.id), historyRow(orgA.id), historyRow(orgB.id)],
    });
    await ctx.http.delete('/api/v1/bec/history').set(headers(noMfaA)).expect(403);
    const res = await ctx.http.delete('/api/v1/bec/history').set(headers(adminA)).expect(202);
    expect(res.body).toEqual({ deleted: 3 });
    expect(await ctx.prisma.becContactHistory.count({ where: { organizationId: orgA.id } })).toBe(
      0,
    );
    expect(await ctx.prisma.becContactHistory.count({ where: { organizationId: orgB.id } })).toBe(
      1,
    );
    const audit = await ctx.prisma.auditLog.findFirst({
      where: { organizationId: orgA.id, action: 'bec_history.purged' },
      orderBy: { id: 'desc' },
    });
    expect(audit?.metadata).toMatchObject({ deleted: 3, batches: 1 });
  });

  it('stores a bec settings override with normalized free-mail domains, audited; refuses caps', async () => {
    const bad = await ctx.http
      .put('/api/v1/scan-settings/bec')
      .set(headers(adminA))
      .send({
        expectedVersion: 0,
        settings: { ai: { llm: 'active' }, freemailExtraDomains: ['co.uk'] },
      })
      .expect(422);
    expect(bad.body.violations.map((v: { path: string }) => v.path)).toEqual([
      'freemailExtraDomains.0',
    ]);
    const res = await ctx.http
      .put('/api/v1/scan-settings/bec')
      .set(headers(adminA))
      .send({
        expectedVersion: 0,
        settings: { freemailExtraDomains: ['Mail.Corp-Free.Example'], history: { enabled: true } },
      })
      .expect(200);
    expect(res.body).toMatchObject({
      engine: 'bec',
      version: 1,
      overrideApplied: true,
      effective: { freemailExtraDomains: ['mail.corp-free.example'], history: { enabled: true } },
    });
    const audit = await ctx.prisma.auditLog.findFirst({
      where: { organizationId: orgA.id, action: 'scan_settings.updated', resourceId: 'bec' },
    });
    expect(audit?.metadata).toMatchObject({
      after: { freemailExtraDomains: ['mail.corp-free.example'] },
    });
  });

  it('deletes every BEC row of one organization in the purge order, leaving others', async () => {
    const orgC = await fx.createOrganization();
    const message = await insertLifecycleMessage(ctx, orgC, { state: 'scanned' });
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgC.id]));
    fx.registerCleanup(() => purgeBec([orgC.id]));
    const scan = await insertBecRound(message, {
      address: 'a@c.example',
      registrableDomain: 'c.example',
    });
    const now = new Date();
    const base = { organizationId: orgC.id };
    await ctx.prisma.becExecutiveProfile.create({
      data: {
        ...base,
        publicId: randomUUID(),
        displayName: 'C Exec',
        normalizedName: 'c exec',
        aliases: [],
        knownAddresses: [],
      },
    });
    await ctx.prisma.becVendorProfile.create({
      data: {
        ...base,
        publicId: randomUUID(),
        name: 'C Vendor',
        normalizedName: 'c vendor',
        aliases: [],
        domains: ['c-vendor.example'],
        knownSenders: [],
      },
    });
    await ctx.prisma.becTrustedSender.create({
      data: {
        ...base,
        publicId: randomUUID(),
        kind: 'domain',
        value: 'c-trusted.example',
        reason: 'x',
      },
    });
    const result = await ctx.prisma.becScanResult.findFirstOrThrow({ where: { scanId: scan } });
    const fb = await ctx.prisma.becFeedback.create({
      data: {
        ...base,
        publicId: randomUUID(),
        messageId: message.id,
        messageReceivedAt: message.receivedAt,
        scanId: scan,
        becResultId: result.id,
        kind: 'false_positive',
      },
    });
    await ctx.prisma.becSuppressionRule.create({
      data: {
        ...base,
        publicId: randomUUID(),
        reasonCode: 'bec.content.urgency',
        senderScope: 'domain',
        senderValue: 'c.example',
        feedbackId: fb.id,
        expiresAt: new Date(now.getTime() + 86_400_000),
      },
    });
    await ctx.prisma.becContactHistory.create({ data: historyRow(orgC.id) });
    const before = await ctx.prisma.becContactHistory.count({ where: { organizationId: orgB.id } });

    const counts = await ctx
      .get(BecTenantDataRepository)
      .purgeOrganization(systemScope(orgC.id), 1);
    expect(Object.keys(counts)).toEqual([...BEC_PURGE_ORDER]);
    expect(counts).toEqual({
      bec_suppression_rules: 1,
      bec_feedback: 1,
      bec_trusted_senders: 1,
      bec_vendor_profiles: 1,
      bec_executive_profiles: 1,
      bec_contact_history: 1,
      bec_scan_results: 1,
    });
    const where = { organizationId: orgC.id };
    expect(
      await Promise.all([
        ctx.prisma.becSuppressionRule.count({ where }),
        ctx.prisma.becFeedback.count({ where }),
        ctx.prisma.becTrustedSender.count({ where }),
        ctx.prisma.becVendorProfile.count({ where }),
        ctx.prisma.becExecutiveProfile.count({ where }),
        ctx.prisma.becContactHistory.count({ where }),
        ctx.prisma.becScanResult.count({ where }),
      ]),
    ).toEqual([0, 0, 0, 0, 0, 0, 0]);
    expect(await ctx.prisma.becContactHistory.count({ where: { organizationId: orgB.id } })).toBe(
      before,
    );
    // Re-running is a no-op (resumable).
    expect(
      Object.values(await ctx.get(BecTenantDataRepository).purgeOrganization(systemScope(orgC.id))),
    ).toEqual([0, 0, 0, 0, 0, 0, 0]);
  });
});
