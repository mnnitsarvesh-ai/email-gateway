/**
 * Step 4.1 scan routes (S13, S16) against the real MySQL writer and replica, Redis, MinIO and the
 * Compose Rspamd: the scan results read (replica, tenant isolation), the scan settings (bounds,
 * raise-only severities, compare-and-set, RBAC, audit) and the platform training (permission and
 * MFA required, tenant admins refused, real Bayes learning and fuzzy hashes with per-run random
 * tokens, audit and timeline rows, 409 without the EML, 503 with an unreachable controller).
 * Scan rows are inserted as the email-worker writes them (fixtures, L8.6); the worker itself is
 * tested in apps/email-worker.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
import { mailBucketClient, s3Commands } from './support/probe-cleanup';

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(5).toString('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let readerA: Record<string, string>;
let readerB: Record<string, string>;
const uploaded: string[] = [];
const s3 = mailBucketClient();

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });

async function tokenOf(user: FixtureUser): Promise<Record<string, string>> {
  return bearer((await loginWithMfa(ctx, fx, user)).accessToken);
}

/** One completed round as the scan stage writes it (S5): scan row, attempts, final, auth. */
async function insertRound(
  message: LifecycleMessage,
  round: number,
  options: { failedAttempts?: number; verdict?: 'clean' | 'spam' } = {},
): Promise<bigint> {
  const startedAt = new Date(message.receivedAt.getTime() + 1_000 + round * 10_000);
  const scan = await ctx.prisma.emailScan.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanKind: round === 0 ? 'initial' : 'rescan',
      status: 'completed',
      lifecycleRound: round,
      scanVerdict: options.verdict ?? 'spam',
      requiredEngines: ['rspamd'],
      reasonCodes: ['spam.score', 'auth.spf_fail'],
      startedAt,
      completedAt: new Date(startedAt.getTime() + 5_000),
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  const failed = options.failedAttempts ?? 0;
  for (let attempt = 1; attempt <= failed; attempt += 1) {
    await ctx.prisma.scanEngineResult.create({
      data: {
        receivedAt: message.receivedAt,
        scanId: scan.id,
        messageId: message.id,
        organizationId: message.organizationId,
        engine: 'rspamd',
        outcome: 'timeout',
        durationMs: 20_000,
        attempt,
        isFinal: false,
        reasonCodes: ['engine.timeout'],
        errorCode: 'timeout',
        completedAt: new Date(startedAt.getTime() + attempt * 1_000),
      },
    });
  }
  await ctx.prisma.scanEngineResult.create({
    data: {
      receivedAt: message.receivedAt,
      scanId: scan.id,
      messageId: message.id,
      organizationId: message.organizationId,
      engine: 'rspamd',
      engineVersion: '3.12.1',
      outcome: options.verdict ?? 'spam',
      score: new Prisma.Decimal('8.250'),
      requiredScore: new Prisma.Decimal('15'),
      action: 'no action',
      durationMs: 812,
      attempt: failed + 1,
      isFinal: true,
      reasonCodes: ['spam.score', 'auth.spf_fail'],
      settingsVersion: 'rspamd-map/1;p=0123456789ab;t=none',
      evidence: {
        signals: [
          { name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] },
          { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
        ],
      },
      completedAt: new Date(startedAt.getTime() + 5_000),
    },
  });
  await ctx.prisma.emailAuthResult.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanId: scan.id,
      engine: 'rspamd',
      spf: 'fail',
      spfDomain: 'spoof.scan.test',
      dkim: 'none',
      dkimSignatures: [],
      dmarc: 'fail',
      dmarcPolicy: 'reject',
      dmarcDomain: 'spoof.scan.test',
      arc: 'none',
    },
  });
  return scan.id;
}

async function deleteScanFixtures(organizationIds: bigint[]): Promise<void> {
  const where = { organizationId: { in: organizationIds } };
  await ctx.prisma.emailAuthResult.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
}

/** Per-run text over a small vocabulary, long enough for Rspamd's fuzzy hashes. */
function eml(tag: string): string {
  const words = Array.from({ length: 160 }, (_, i) => `t${run}${tag}w${(i * 7) % 23}`);
  return [
    // Every Bayes token is per run (body words, From, Subject): the statfiles are shared and
    // persist, and a fixed header vocabulary learned as spam on every run makes Rspamd skip the
    // learn (204, already >= 95 % spam) after enough runs (step 4.2 §13).
    `From: Trainer ${run} <trainer-${run}@spam-sender.scan.test>`,
    'To: bob@customer.scan.test',
    `Subject: ${run}${tag} ${tag}${run}`,
    'Date: Thu, 05 Nov 2026 10:00:00 +0000',
    `Message-ID: <${run}.${tag}@spam-sender.scan.test>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    words.join(' ').replace(/(.{1,72})(\s|$)/g, '$1\r\n'),
  ].join('\r\n');
}

async function uploadEml(org: FixtureOrganization, tag: string): Promise<string> {
  const key = `org/${org.id.toString()}/eml/it-scan-training/${run}-${tag}.eml`;
  const { PutObjectCommand } = s3Commands();
  await s3.s3.send(new PutObjectCommand({ Bucket: s3.bucket, Key: key, Body: eml(tag) }));
  uploaded.push(key);
  return key;
}

let resumeCleanup: (() => Promise<void>) | undefined;

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => deleteScanFixtures([orgA.id, orgB.id]));
  readerA = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
  readerB = apiKeyHeader(await fx.createApiKey(orgB, ['message:read', 'policy:read']));
  resumeCleanup = async () => {
    const { DeleteObjectCommand } = s3Commands();
    for (const key of uploaded) {
      await s3.s3.send(new DeleteObjectCommand({ Bucket: s3.bucket, Key: key }));
    }
    s3.s3.destroy();
  };
}, 180_000);

afterAll(async () => {
  try {
    await fx?.cleanup();
    await ctx?.close();
  } finally {
    await resumeCleanup?.();
  }
}, 180_000);

describe('GET /messages/{messageId}/scans (S16)', () => {
  it('reads the rounds through the replica, newest first, with attempts, symbols and auth', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    await insertRound(message, 0, { failedAttempts: 2 });
    await insertRound(message, 1, { verdict: 'clean' });
    const url = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => {
        const page = (await ctx.http.get(url).set(headers(readerA))).body as {
          data?: unknown[];
        };
        return page.data?.length;
      }, POLL)
      .toBe(2);
    const res = await ctx.http.get(url).set(headers(readerA)).expect(200);
    expect(res.body.messageId).toBe(message.publicId);
    expect(res.body.data.map((r: { round: number }) => r.round)).toEqual([1, 0]);
    const initial = res.body.data[1];
    expect(initial).toMatchObject({
      round: 0,
      scanKind: 'initial',
      status: 'completed',
      verdict: 'spam',
      reasonCodes: ['spam.score', 'auth.spf_fail'],
      requiredEngines: ['rspamd'],
      auth: { spf: 'fail', dmarc: 'fail', dmarcPolicy: 'reject', spfDomain: 'spoof.scan.test' },
    });
    expect(initial.engines).toHaveLength(1);
    expect(initial.engines[0]).toMatchObject({
      engine: 'rspamd',
      final: true,
      outcome: 'spam',
      score: 8.25,
      requiredScore: 15,
      engineVersion: '3.12.1',
      symbols: [
        { name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] },
        { name: 'R_SPF_FAIL', score: 1, options: ['-all'] },
      ],
    });
    expect(
      initial.engines[0].attempts.map((a: { attempt: number; outcome: string }) => [
        a.attempt,
        a.outcome,
      ]),
    ).toEqual([
      [1, 'timeout'],
      [2, 'timeout'],
      [3, 'spam'],
    ]);

    // Pagination: one round per page, cursor to the older round.
    const first = await ctx.http.get(`${url}?limit=1`).set(headers(readerA)).expect(200);
    expect(first.body.data.map((r: { round: number }) => r.round)).toEqual([1]);
    const second = await ctx.http
      .get(`${url}?limit=1&cursor=${first.body.nextCursor as string}`)
      .set(headers(readerA))
      .expect(200);
    expect(second.body.data.map((r: { round: number }) => r.round)).toEqual([0]);
    expect(second.body.nextCursor).toBeNull();
  });

  it('isolates tenants: another organization’s message is 404 message_not_found', async () => {
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    await insertRound(message, 0);
    const url = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => (await ctx.http.get(url).set(headers(readerA))).status, POLL)
      .toBe(200);
    const foreign = await ctx.http.get(url).set(headers(readerB)).expect(404);
    expect(foreign.body).toMatchObject({ code: 'message_not_found' });
    expect(JSON.stringify(foreign.body)).not.toContain('rspamd');
    // A message without rounds yet (not scanned) lists nothing.
    const fresh = await insertLifecycleMessage(ctx, orgA, { state: 'persisted' });
    await expect
      .poll(
        async () =>
          (await ctx.http.get(`/api/v1/messages/${fresh.publicId}/scans`).set(headers(readerA)))
            .status,
        POLL,
      )
      .toBe(200);
    const none = await ctx.http
      .get(`/api/v1/messages/${fresh.publicId}/scans`)
      .set(headers(readerA))
      .expect(200);
    expect(none.body).toEqual({ messageId: fresh.publicId, data: [], nextCursor: null });
  });
});

describe('scan settings (S8, S16)', () => {
  const url = '/api/v1/scan-settings/rspamd';

  async function audits(org: FixtureOrganization, action: string) {
    return ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action, resourceType: 'scan_engine_settings' },
      orderBy: { id: 'asc' },
    });
  }

  it('lets organization_admin and security_analyst change them; read_only_user only reads', async () => {
    const org = await fx.createOrganization();
    fx.registerCleanup(() => deleteScanFixtures([org.id]));
    const admin = await tokenOf(await fx.createUser(org, { roles: ['organization_admin'] }));
    const analyst = await tokenOf(await fx.createUser(org, { roles: ['security_analyst'] }));
    const readOnly = await tokenOf(await fx.createUser(org, { roles: ['read_only_user'] }));

    const listed = await ctx.http.get('/api/v1/scan-settings').set(headers(readOnly)).expect(200);
    expect(listed.body.data[0]).toMatchObject({
      engine: 'rspamd',
      version: 0,
      override: null,
      platform: { spamScore: 6, suspiciousScore: 4, scoreMin: 1, scoreMax: 15 },
    });
    await ctx.http
      .put(url)
      .set(headers(readOnly))
      .send({ expectedVersion: 0, settings: { spamScore: 8 } })
      .expect(403);
    await ctx.http.delete(`${url}?expectedVersion=0`).set(headers(readOnly)).expect(403);

    const created = await ctx.http
      .put(url)
      .set(headers(admin))
      .send({ expectedVersion: 0, settings: { spamScore: 8, phishingVerdict: 'malicious' } })
      .expect(200);
    expect(created.body).toMatchObject({
      version: 1,
      override: { spamScore: 8, phishingVerdict: 'malicious' },
      effective: { spamScore: 8, suspiciousScore: 4, phishingVerdict: 'malicious' },
      overrideApplied: true,
    });
    const changed = await ctx.http
      .put(url)
      .set(headers(analyst))
      .send({ expectedVersion: 1, settings: { suspiciousScore: 2.5 } })
      .expect(200);
    expect(changed.body).toMatchObject({ version: 2, override: { suspiciousScore: 2.5 } });

    const rows = await audits(org, 'scan_settings.updated');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ actorType: 'user', resourceId: 'rspamd' });
    expect(rows[0]!.metadata).toMatchObject({
      engine: 'rspamd',
      fromVersion: 0,
      toVersion: 1,
      before: null,
      after: { spamScore: 8, phishingVerdict: 'malicious' },
    });
    expect(rows[1]!.metadata).toMatchObject({
      fromVersion: 1,
      toVersion: 2,
      before: { spamScore: 8, phishingVerdict: 'malicious' },
      after: { suspiciousScore: 2.5 },
    });
    const row = await ctx.prisma.scanEngineSetting.findFirstOrThrow({
      where: { organizationId: org.id, engine: 'rspamd' },
    });
    expect(row).toMatchObject({ version: 2, settings: { suspiciousScore: 2.5 } });
  });

  it('enforces the bounds, the threshold order, raise-only severities and unknown keys (422)', async () => {
    const org = await fx.createOrganization();
    fx.registerCleanup(() => deleteScanFixtures([org.id]));
    const admin = await tokenOf(await fx.createUser(org, { roles: ['organization_admin'] }));
    for (const [settings, code] of [
      [{ spamScore: 15.5 }, 'out_of_bounds'],
      [{ suspiciousScore: 0.5 }, 'out_of_bounds'],
      [{ spamScore: 3 }, 'threshold_order'],
      [{ suspiciousScore: 6 }, 'threshold_order'],
      [{ dmarcRejectVerdict: 'reason_only' }, 'invalid'],
      [{ disableRspamd: true }, 'unknown_key'],
      [{ spamScore: 7.125 }, 'invalid'],
    ] as const) {
      const res = await ctx.http
        .put(url)
        .set(headers(admin))
        .send({ expectedVersion: 0, settings })
        .expect(422);
      expect(res.body.code).toBe('scan_settings_invalid');
      expect(res.body.violations.map((v: { code: string }) => v.code)).toContain(code);
    }
    expect(await ctx.prisma.scanEngineSetting.count({ where: { organizationId: org.id } })).toBe(0);
    expect(await audits(org, 'scan_settings.updated')).toHaveLength(0);
    await ctx.http
      .put('/api/v1/scan-settings/clamav')
      .set(headers(admin))
      .send({ expectedVersion: 0, settings: {} })
      .expect(404);
  });

  it('compare-and-set: concurrent writers, stale versions and the reset (API key with the permission)', async () => {
    const org = await fx.createOrganization();
    fx.registerCleanup(() => deleteScanFixtures([org.id]));
    const key = apiKeyHeader(await fx.createApiKey(org, ['policy:read', 'scan:settings_manage']));
    const results = await Promise.all(
      [7, 8, 9, 10].map((spamScore) =>
        ctx.http.put(url).set(headers(key)).send({ expectedVersion: 0, settings: { spamScore } }),
      ),
    );
    expect(results.map((r) => r.status).sort()).toEqual([200, 409, 409, 409]);
    for (const lost of results.filter((r) => r.status === 409)) {
      expect(lost.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    }
    expect(await audits(org, 'scan_settings.updated')).toHaveLength(1);
    expect((await audits(org, 'scan_settings.updated'))[0]).toMatchObject({ actorType: 'api_key' });

    await ctx.http.delete(`${url}?expectedVersion=0`).set(headers(key)).expect(409);
    const reset = await ctx.http.delete(`${url}?expectedVersion=1`).set(headers(key)).expect(200);
    expect(reset.body).toMatchObject({ version: 2, override: null, overrideApplied: false });
    expect(reset.body.effective.spamScore).toBe(6);
    const resets = await audits(org, 'scan_settings.reset');
    expect(resets).toHaveLength(1);
    expect(resets[0]!.metadata).toMatchObject({ fromVersion: 1, toVersion: 2, after: null });
    // A writer still holding version 1 cannot overwrite after the reset.
    await ctx.http
      .put(url)
      .set(headers(key))
      .send({ expectedVersion: 1, settings: { spamScore: 12 } })
      .expect(409);
    // Tenant isolation: another organization still has no override.
    const other = await ctx.http.get('/api/v1/scan-settings').set(headers(readerB)).expect(200);
    expect(other.body.data[0]).toMatchObject({ version: 0, override: null });
  });
});

describe('POST /platform/organizations/{organizationId}/messages/{messageId}/scan-training (S13)', () => {
  const trainUrl = (org: FixtureOrganization, message: LifecycleMessage) =>
    `/api/v1/platform/organizations/${org.publicId}/messages/${message.publicId}/scan-training`;
  let platformAdmin: Record<string, string>;

  beforeAll(async () => {
    platformAdmin = await tokenOf(await fx.createPlatformUser(['platform_admin']));
  });

  async function trainingRows(org: FixtureOrganization, message: LifecycleMessage) {
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, resourceType: 'message', resourceId: message.publicId },
      orderBy: { id: 'asc' },
    });
    const events = await ctx.prisma.emailEvent.findMany({
      where: { messageId: message.id, receivedAt: message.receivedAt, eventType: 'scan.training' },
      orderBy: { id: 'asc' },
    });
    return { audit, events };
  }

  it('learns spam on the real Rspamd (then already_learned), audited, with a timeline event', async () => {
    const emlObjectKey = await uploadEml(orgA, 'bayes');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned', emlObjectKey });
    const body = { operation: 'learn_spam', reason: 'confirmed spam campaign' };
    const first = await ctx.http
      .post(trainUrl(orgA, message))
      .set(headers(platformAdmin))
      .send(body)
      .expect(200);
    expect(first.body).toEqual({
      operation: 'learn_spam',
      result: 'learned',
      engineVersion: expect.stringMatching(/^3\./),
    });
    const again = await ctx.http
      .post(trainUrl(orgA, message))
      .set(headers(platformAdmin))
      .send(body)
      .expect(200);
    expect(again.body.result).toBe('already_learned');

    const { audit, events } = await trainingRows(orgA, message);
    expect(audit.map((a) => a.action)).toEqual([
      'scan_training.learn_spam',
      'scan_training.learn_spam',
    ]);
    expect(audit[0]).toMatchObject({ actorType: 'user' });
    expect(audit[0]!.metadata).toMatchObject({
      operation: 'learn_spam',
      outcome: 'learned',
      reason: 'confirmed spam campaign',
    });
    expect(events.map((e) => e.details)).toEqual([
      { operation: 'learn_spam', result: 'learned' },
      { operation: 'learn_spam', result: 'already_learned' },
    ]);
    // Codes only: no content of the message in the audit or the timeline.
    const recorded = JSON.stringify([audit.map((a) => a.metadata), events.map((e) => e.details)]);
    expect(recorded).not.toContain(`t${run}`);
    expect(recorded).not.toContain('Trainer');
  });

  it('adds and deletes fuzzy hashes (spam flag) on the real Rspamd', async () => {
    const emlObjectKey = await uploadEml(orgA, 'fuzzy');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned', emlObjectKey });
    const add = await ctx.http
      .post(trainUrl(orgA, message))
      .set(headers(platformAdmin))
      .send({ operation: 'fuzzy_add', fuzzyFlag: 'spam', reason: 'campaign template' })
      .expect(200);
    expect(add.body.result).toBe('added');
    const del = await ctx.http
      .post(trainUrl(orgA, message))
      .set(headers(platformAdmin))
      .send({ operation: 'fuzzy_delete', fuzzyFlag: 'spam', reason: 'false positive' })
      .expect(200);
    expect(del.body.result).toBe('deleted');
    const { audit } = await trainingRows(orgA, message);
    expect(audit.map((a) => a.action)).toEqual([
      'scan_training.fuzzy_add',
      'scan_training.fuzzy_delete',
    ]);
    expect(audit[0]!.metadata).toMatchObject({ fuzzyFlag: 'spam', fuzzyFlagNumber: 11 });
  });

  it('requires the platform permission and an MFA session; tenant admins and API keys are refused', async () => {
    const emlObjectKey = await uploadEml(orgA, 'rbac');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned', emlObjectKey });
    const body = { operation: 'learn_ham', reason: 'not spam' };
    const tenantAdmin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    await ctx.http.post(trainUrl(orgA, message)).set(headers(tenantAdmin)).send(body).expect(403);
    const adminKey = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'message:rescan']));
    await ctx.http.post(trainUrl(orgA, message)).set(headers(adminKey)).send(body).expect(403);
    const noMfa = await tokenOf(await fx.createPlatformUser(['platform_admin'], { mfa: false }));
    await ctx.http.post(trainUrl(orgA, message)).set(headers(noMfa)).send(body).expect(403);
    expect((await trainingRows(orgA, message)).audit).toHaveLength(0);
  });

  it('looks the message up within the named organization only (404), 409 without the EML', async () => {
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const body = { operation: 'learn_spam', reason: 'x' };
    const wrongOrg = await ctx.http
      .post(trainUrl(orgB, message))
      .set(headers(platformAdmin))
      .send(body)
      .expect(404);
    expect(wrongOrg.body.code).toBe('message_not_found');
    const missing = await ctx.http
      .post(trainUrl(orgA, message))
      .set(headers(platformAdmin))
      .send(body)
      .expect(409);
    expect(missing.body.code).toBe('content_unavailable');
    const { audit, events } = await trainingRows(orgA, message);
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ outcome: 'content_unavailable' });
    expect(events).toHaveLength(0);
    await ctx.http
      .post(
        `/api/v1/platform/organizations/${randomUUID()}/messages/${message.publicId}/scan-training`,
      )
      .set(headers(platformAdmin))
      .send(body)
      .expect(404);
  });

  it('answers 503 rspamd_unavailable when the controller is unreachable (audited)', async () => {
    const unreachable = await createIntegrationApp({ RSPAMD_CONTROLLER_URL: 'http://127.0.0.1:1' });
    try {
      const emlObjectKey = await uploadEml(orgA, 'down');
      const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned', emlObjectKey });
      const res = await unreachable.http
        .post(trainUrl(orgA, message))
        .set(headers(platformAdmin))
        .send({ operation: 'learn_spam', reason: 'outage test' })
        .expect(503);
      expect(res.body.code).toBe('rspamd_unavailable');
      const { audit, events } = await trainingRows(orgA, message);
      expect(audit[0]!.metadata).toMatchObject({ outcome: 'rspamd_unavailable' });
      expect(events).toHaveLength(0);
      expect(unreachable.logs.join('\n')).not.toContain(
        process.env.RSPAMD_CONTROLLER_ENABLE_PASSWORD!,
      );
    } finally {
      await unreachable.close();
    }
  });
});
