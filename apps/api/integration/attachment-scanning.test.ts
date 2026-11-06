/**
 * Step 4.2 api routes against the real MySQL writer and replica (docs/plan/steps/
 * 10-attachment-scanning.md A8, A13, A16, A17): the per-attachment results of the scans read
 * (replica, every query filtered by the scope organization: rows of another organization with the
 * same message id are never shown, another organization's message is 404), the attachment
 * settings through the existing settings routes (bounds, audit), the platform known-threat hash
 * catalog (permission, MFA, API keys and tenants refused, 409/404, audit rows with the
 * before-image) and the bulk rescan jobs (dry-run estimate with the runner's candidate
 * predicate, a job row and its audit row, list/get on the replica, cancel and 409). Scan rows are
 * inserted as the email-worker writes them (fixtures, L8.6).
 *
 * The live email-worker may run the rescan runner: real (non-dry-run) jobs are only created for an
 * organization without candidates and cancelled at once, and every row is removed afterwards.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { PrismaReadService } from '@email-gateway/common';
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

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(6).toString('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let readerA: Record<string, string>;
let readerB: Record<string, string>;
let platformAdmin: Record<string, string>;
let platformAdminUser: FixtureUser;
const hashes = new Set<string>();
const jobIds = new Set<string>();

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);

/** A per-run SHA-256 (never a real file's hash). */
const runHash = (label: string): string => {
  const value = `${run}${Buffer.from(label).toString('hex')}`.padEnd(64, '0').slice(0, 64);
  hashes.add(value);
  return value;
};

async function deleteAttachmentFixtures(organizationIds: bigint[]): Promise<void> {
  const where = { organizationId: { in: organizationIds } };
  await ctx.prisma.sandboxSubmission.deleteMany({ where });
  await ctx.prisma.attachmentScanResult.deleteMany({ where });
  await ctx.prisma.emailAttachment.deleteMany({ where });
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
}

/** One email_attachments row of the message (as MIME ingestion writes it). */
async function insertAttachment(
  message: LifecycleMessage,
  partIndex: number,
  filename: string,
): Promise<bigint> {
  const row = await ctx.prisma.emailAttachment.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      partIndex,
      filename,
      declaredContentType: 'application/pdf',
      detectedContentType: 'application/x-dosexec',
      sizeBytes: 2048,
      sha256: runHash(`part${partIndex}${message.id.toString()}`),
      objectKey: `org/${message.organizationId.toString()}/part/2026/11/05/${message.id.toString()}/${partIndex}.att`,
    },
    select: { id: true },
  });
  return row.id;
}

/**
 * A completed round with an attachment engine final (as the email-worker finalizes it, A12):
 * scan row, final row, one attachment_scan_results row per attachment and, optionally, a
 * sandbox submission.
 */
async function insertAttachmentRound(
  message: LifecycleMessage,
  attachmentIds: { id: bigint; partIndex: number }[],
  options: { outcome?: 'suspicious' | 'malicious'; round?: number; sandbox?: boolean } = {},
): Promise<bigint> {
  const outcome = options.outcome ?? 'suspicious';
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const scan = await ctx.prisma.emailScan.create({
    data: {
      receivedAt: message.receivedAt,
      messageId: message.id,
      organizationId: message.organizationId,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: options.round ?? 0,
      scanVerdict: outcome,
      requiredEngines: ['rspamd', 'attachment'],
      reasonCodes: ['type.executable_disguised'],
      startedAt,
      completedAt: new Date(startedAt.getTime() + 2_000),
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      receivedAt: message.receivedAt,
      scanId: scan.id,
      messageId: message.id,
      organizationId: message.organizationId,
      engine: 'attachment',
      engineVersion: 'clamav/1.4.6/28173;yara-x/0.10.0/462fab6e5cc4',
      outcome,
      durationMs: 40,
      attempt: 1,
      isFinal: true,
      reasonCodes: ['type.executable_disguised'],
      settingsVersion: 'attachment-map/1;p=0123456789ab;t=none',
      evidence: { signals: [] },
      completedAt: new Date(startedAt.getTime() + 2_000),
    },
  });
  for (const attachment of attachmentIds) {
    await ctx.prisma.attachmentScanResult.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: message.organizationId,
        scanId: scan.id,
        attachmentId: attachment.id,
        partIndex: attachment.partIndex,
        sha256: runHash(`res${attachment.id.toString()}`),
        sizeBytes: 2048,
        detectedType: 'pe_executable',
        typeFamily: 'executable',
        typeMismatch: true,
        verdict: outcome,
        reasonCodes: ['type.executable_disguised', 'type.denied'],
        clamavEngineVersion: '1.4.6',
        clamavDbVersion: 28173,
        yaraBundleId: 'yara-1-462fab6e5cc4',
        yaraMatches: [],
        cacheResult: 'miss',
        contentVersion: '0123456789abcdef',
        durationMs: 12,
      },
    });
    if (options.sandbox) {
      await ctx.prisma.sandboxSubmission.create({
        data: {
          receivedAt: message.receivedAt,
          messageId: message.id,
          organizationId: message.organizationId,
          scanId: scan.id,
          attachmentId: attachment.id,
          partIndex: attachment.partIndex,
          sha256: runHash(`sbx${attachment.id.toString()}`),
          sizeBytes: 2048,
          detectedType: 'pe_executable',
          objectKey: `org/${message.organizationId.toString()}/part/x/${attachment.partIndex}.att`,
          attachmentVerdict: 'suspicious',
          reasonCodes: ['type.executable_disguised'],
          requestedEventId: randomUUID(),
        },
      });
    }
  }
  return scan.id;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => deleteAttachmentFixtures([orgA.id, orgB.id]));
  readerA = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
  readerB = apiKeyHeader(await fx.createApiKey(orgB, ['message:read', 'policy:read']));
  platformAdminUser = await fx.createPlatformUser(['platform_admin']);
  platformAdmin = await tokenOf(platformAdminUser);
  // Registered last, so it runs first (cleanups run in reverse): jobs reference organizations.
  fx.registerCleanup(async () => {
    await ctx.prisma.attachmentRescanJob.deleteMany({ where: { publicId: { in: [...jobIds] } } });
    await ctx.prisma.malwareSignature.deleteMany({ where: { sha256: { in: [...hashes] } } });
    await ctx.prisma.auditLog.deleteMany({
      where: {
        OR: [
          { resourceType: 'malware_signature', resourceId: { in: [...hashes] } },
          { resourceType: 'attachment_rescan_job', resourceId: { in: [...jobIds] } },
        ],
      },
    });
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('GET /messages/{messageId}/scans: per-attachment results (A16)', () => {
  it('reads them through the replica with filename and sandbox; never another organization’s rows', async () => {
    expect(ctx.get(PrismaReadService).status().mode).toBe('reader');
    const message = await insertLifecycleMessage(ctx, orgA, { state: 'scanned' });
    const first = await insertAttachment(message, 1, 'invoice.pdf');
    const second = await insertAttachment(message, 2, 'notes.txt');
    const scanId = await insertAttachmentRound(
      message,
      [
        { id: second, partIndex: 2 },
        { id: first, partIndex: 1 },
      ],
      { sandbox: true },
    );
    // A row of organization B with the same message id, round and receivedAt: never shown.
    await ctx.prisma.attachmentScanResult.create({
      data: {
        receivedAt: message.receivedAt,
        messageId: message.id,
        organizationId: orgB.id,
        scanId,
        attachmentId: 999_999_999n,
        partIndex: 7,
        sha256: runHash('foreign'),
        sizeBytes: 1,
        detectedType: 'text',
        typeFamily: 'text',
        typeMismatch: false,
        verdict: 'clean',
        reasonCodes: ['clean.no_findings'],
        cacheResult: 'miss',
        durationMs: 1,
      },
    });
    const url = `/api/v1/messages/${message.publicId}/scans`;
    await expect
      .poll(async () => {
        const body = (await ctx.http.get(url).set(headers(readerA))).body as {
          data?: { engines: { attachments?: unknown[] }[] }[];
        };
        return body.data?.[0]?.engines[0]?.attachments?.length;
      }, POLL)
      .toBe(2);
    const res = await ctx.http.get(url).set(headers(readerA)).expect(200);
    const engine = res.body.data[0].engines[0];
    expect(engine).toMatchObject({ engine: 'attachment', final: true, outcome: 'suspicious' });
    expect(engine.attachments.map((a: { partIndex: number }) => a.partIndex)).toEqual([1, 2]);
    expect(engine.attachments[0]).toMatchObject({
      partIndex: 1,
      filename: 'invoice.pdf',
      declaredContentType: 'application/pdf',
      detectedType: 'pe_executable',
      typeFamily: 'executable',
      verdict: 'suspicious',
      reasonCodes: ['type.executable_disguised', 'type.denied'],
      clamav: { signature: null, engineVersion: '1.4.6', dbVersion: 28173 },
      yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [] },
      sandbox: { status: 'pending' },
    });
    // Never shown to a tenant: the cross-tenant content cache outcome and timing (A10).
    expect(engine.attachments[0]).not.toHaveProperty('cache');
    expect(engine.attachments[0]).not.toHaveProperty('durationMs');
    expect(engine.durationMs).toBeNull();
    expect(engine.attempts.every((a: { durationMs: unknown }) => a.durationMs === null)).toBe(true);
    expect(JSON.stringify(res.body)).not.toContain('"partIndex":7');

    const foreign = await ctx.http.get(url).set(headers(readerB)).expect(404);
    expect(foreign.body).toMatchObject({ code: 'message_not_found' });
  });
});

describe('attachment settings through /scan-settings/attachment (A8)', () => {
  it('lists the attachment engine, enforces the platform bounds and audits a change', async () => {
    const admin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    const listed = await ctx.http.get('/api/v1/scan-settings').set(headers(admin)).expect(200);
    expect(listed.body.data.map((v: { engine: string }) => v.engine)).toEqual([
      'rspamd',
      'attachment',
      'url',
    ]);
    const url = '/api/v1/scan-settings/attachment';
    const invalid = await ctx.http
      .put(url)
      .set(headers(admin))
      .send({ expectedVersion: 0, settings: { allowedTypes: ['pdf', 'pe_executable'] } })
      .expect(422);
    expect(invalid.body.violations).toEqual([
      expect.objectContaining({ path: 'allowedTypes', code: 'out_of_bounds' }),
    ]);
    const saved = await ctx.http
      .put(url)
      .set(headers(admin))
      .send({
        expectedVersion: 0,
        settings: {
          deniedTypes: ['zip'],
          typeMismatchVerdict: 'malicious',
          maxAttachmentBytes: 5_242_880,
        },
      })
      .expect(200);
    expect(saved.body).toMatchObject({
      engine: 'attachment',
      version: 1,
      overrideApplied: true,
      effective: { typeMismatchVerdict: 'malicious', maxAttachmentBytes: 5_242_880 },
    });
    const row = await ctx.prisma.scanEngineSetting.findFirst({
      where: { organizationId: orgA.id, engine: 'attachment' },
    });
    expect(row?.settings).toEqual({
      deniedTypes: ['zip'],
      typeMismatchVerdict: 'malicious',
      maxAttachmentBytes: 5_242_880,
    });
    const audits = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, action: 'scan_settings.updated', resourceId: 'attachment' },
    });
    expect(audits).toHaveLength(1);
  });
});

describe('platform known-threat hashes (A16, A17)', () => {
  const url = '/api/v1/platform/threat-hashes';

  it('adds (201) as source analyst with its audit row, refuses a listed hash (409)', async () => {
    const sha256 = runHash('add');
    const res = await ctx.http
      .post(url)
      .set(headers(platformAdmin))
      .send({ sha256, severity: 'critical', family: 'Win.Test.Run', reason: 'integration run' })
      .expect(201);
    expect(res.body).toMatchObject({
      sha256,
      severity: 'critical',
      source: 'analyst',
      addedByUserId: platformAdminUser.publicId,
    });
    const row = await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } });
    expect(row).toMatchObject({
      source: 'analyst',
      addedByUserId: platformAdminUser.id,
      reason: 'integration run',
    });
    expect(row!.firstSeenAt.getTime()).toBe(row!.lastSeenAt.getTime());
    const audit = await ctx.prisma.auditLog.findMany({
      where: { action: 'threat_hash.added', resourceId: sha256 },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({ organizationId: null, actorId: platformAdminUser.publicId });
    expect(audit[0]!.metadata).toMatchObject({ sha256, severity: 'critical' });

    const again = await ctx.http
      .post(url)
      .set(headers(platformAdmin))
      .send({ sha256, severity: 'low', reason: 'twice' })
      .expect(409);
    expect(again.body.code).toBe('hash_exists');
  });

  it('lists through the replica and removes with the before-image (204, then 404)', async () => {
    const sha256 = runHash('remove');
    await ctx.http
      .post(url)
      .set(headers(platformAdmin))
      .send({ sha256, severity: 'medium', reason: 'to be removed' })
      .expect(201);
    await expect
      .poll(
        async () =>
          (
            (await ctx.http.get(`${url}?sha256=${sha256}`).set(headers(platformAdmin))).body as {
              data?: unknown[];
            }
          ).data?.length,
        POLL,
      )
      .toBe(1);
    await ctx.http
      .delete(`${url}/${sha256}?reason=false%20positive`)
      .set(headers(platformAdmin))
      .expect(204);
    expect(await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } })).toBeNull();
    const removed = await ctx.prisma.auditLog.findFirst({
      where: { action: 'threat_hash.removed', resourceId: sha256 },
    });
    expect(removed?.metadata).toMatchObject({
      reason: 'false positive',
      before: { sha256, severity: 'medium', source: 'analyst', reason: 'to be removed' },
    });
    const missing = await ctx.http
      .delete(`${url}/${sha256}?reason=again`)
      .set(headers(platformAdmin))
      .expect(404);
    expect(missing.body.code).toBe('threat_hash_not_found');
  });

  it('refuses tenant administrators, API keys and sessions without MFA', async () => {
    const sha256 = runHash('rbac');
    const body = { sha256, severity: 'high', reason: 'x' };
    const tenantAdmin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    await ctx.http.post(url).set(headers(tenantAdmin)).send(body).expect(403);
    const key = apiKeyHeader(await fx.createApiKey(orgA, ['message:read', 'policy:read']));
    await ctx.http.get(url).set(headers(key)).expect(403);
    const noMfa = await tokenOf(await fx.createPlatformUser(['platform_admin'], { mfa: false }));
    await ctx.http.post(url).set(headers(noMfa)).send(body).expect(403);
    expect(await ctx.prisma.malwareSignature.findUnique({ where: { sha256 } })).toBeNull();
  });
});

describe('platform attachment rescan jobs (A13)', () => {
  const url = '/api/v1/platform/attachment-rescans';

  it('a dry run counts the runner’s candidates on the replica and writes nothing', async () => {
    const org = await fx.createOrganization();
    fx.registerCleanup(() => deleteAttachmentFixtures([org.id]));
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [org.id]));
    // Candidate: scanned, with an attachment, not malicious.
    const candidate = await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    const candidatePart = await insertAttachment(candidate, 1, 'a.pdf');
    await insertAttachmentRound(candidate, [{ id: candidatePart, partIndex: 1 }]);
    // Not: a malicious attachment final in its current round.
    const malicious = await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    const maliciousPart = await insertAttachment(malicious, 1, 'b.pdf');
    await insertAttachmentRound(malicious, [{ id: maliciousPart, partIndex: 1 }], {
      outcome: 'malicious',
    });
    // Candidate: scan_failed always qualifies.
    const failed = await insertLifecycleMessage(ctx, org, { state: 'scan_failed' });
    await insertAttachment(failed, 1, 'c.pdf');
    // Not: no attachments; not: a state the job does not select.
    await insertLifecycleMessage(ctx, org, { state: 'scanned' });
    const delivered = await insertLifecycleMessage(ctx, org, { state: 'delivered' });
    await insertAttachment(delivered, 1, 'd.pdf');

    const estimate = async (states?: string[]) =>
      (
        await ctx.http
          .post(url)
          .set(headers(platformAdmin))
          .send({
            windowHours: 1,
            organizationId: org.publicId,
            reason: 'estimate',
            dryRun: true,
            ...(states && { states }),
          })
          .expect(200)
      ).body as { estimatedMessages: number; dryRun: boolean };
    await expect.poll(async () => (await estimate()).estimatedMessages, POLL).toBe(2);
    expect((await estimate(['scanned'])).estimatedMessages).toBe(1);
    expect(await ctx.prisma.attachmentRescanJob.count({ where: { organizationId: org.id } })).toBe(
      0,
    );
  });

  it('creates a pending admin job with its audit row; lists, reads and cancels it', async () => {
    const empty = await fx.createOrganization();
    const created = await ctx.http
      .post(url)
      .set(headers(platformAdmin))
      .send({
        windowHours: 1,
        organizationId: empty.publicId,
        states: ['scanned', 'scan_failed'],
        maxMessages: 10,
        reason: 'integration job',
      })
      .expect(202);
    jobIds.add(created.body.jobId as string);
    expect(created.body).toMatchObject({ status: 'pending', estimatedMessages: 0 });
    const jobId = created.body.jobId as string;
    // Cancelled at once: nothing for a live runner to do.
    const cancelled = await ctx.http
      .post(`${url}/${jobId}/cancel`)
      .set(headers(platformAdmin))
      .send({ reason: 'integration cleanup' })
      .expect(200);
    expect(cancelled.body).toMatchObject({ jobId, status: 'cancelled' });
    const row = await ctx.prisma.attachmentRescanJob.findUnique({ where: { publicId: jobId } });
    expect(row).toMatchObject({
      trigger: 'admin',
      status: 'cancelled',
      organizationId: empty.id,
      maxMessages: 10,
      requestedByUserId: platformAdminUser.id,
      reason: 'integration job',
      states: ['scanned', 'scan_failed'],
    });
    expect(row!.windowEnd.getTime() - row!.windowStart.getTime()).toBe(3_600_000);
    const actions = (
      await ctx.prisma.auditLog.findMany({
        where: { resourceType: 'attachment_rescan_job', resourceId: jobId },
        orderBy: { id: 'asc' },
      })
    ).map((a) => a.action);
    expect(actions).toEqual(['attachment_rescan.requested', 'attachment_rescan.cancelled']);

    await expect
      .poll(
        async () =>
          (
            (await ctx.http.get(`${url}/${jobId}`).set(headers(platformAdmin))).body as {
              status?: string;
            }
          ).status,
        POLL,
      )
      .toBe('cancelled');
    const list = await ctx.http
      .get(`${url}?status=cancelled&limit=100`)
      .set(headers(platformAdmin))
      .expect(200);
    expect(list.body.data.map((j: { jobId: string }) => j.jobId)).toContain(jobId);

    const again = await ctx.http
      .post(`${url}/${jobId}/cancel`)
      .set(headers(platformAdmin))
      .expect(409);
    expect(again.body).toMatchObject({ code: 'rescan_job_not_cancellable', status: 'cancelled' });
    const missing = await ctx.http
      .get(`${url}/${randomUUID()}`)
      .set(headers(platformAdmin))
      .expect(404);
    expect(missing.body.code).toBe('rescan_job_not_found');
    const unknownOrg = await ctx.http
      .post(url)
      .set(headers(platformAdmin))
      .send({ windowHours: 1, organizationId: randomUUID(), reason: 'x' })
      .expect(404);
    expect(unknownOrg.body.code).toBe('organization_not_found');
    fx.registerCleanup(async () => {
      await ctx.prisma.attachmentRescanJob.deleteMany({ where: { organizationId: empty.id } });
    });
  });

  it('refuses tenant administrators and API keys', async () => {
    const tenantAdmin = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
    await ctx.http
      .post(url)
      .set(headers(tenantAdmin))
      .send({ windowHours: 1, reason: 'x', dryRun: true })
      .expect(403);
    await ctx.http.get(url).set(headers(readerA)).expect(403);
  });
});
