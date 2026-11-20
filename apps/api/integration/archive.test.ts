/**
 * Archive administration against the real writer and replica (step 8.1 §9.3): settings with the
 * CAS, generation, enablement time and audit rows (changed paths, never values); retention
 * policies with the plan cap, soft delete and the default refusal; key rotation (wrapped under the
 * root key, records of the old version still decrypt); status counts; capture issues and the
 * retry; the disposal log; the export signing keys; the organization purge repository phases;
 * EXPLAIN of the replica list queries (recorded in the WP4 note).
 */
// @covers get /api/v1/archive/settings
// @covers put /api/v1/archive/settings
// @covers get /api/v1/archive/retention-policies
// @covers post /api/v1/archive/retention-policies
// @covers get /api/v1/archive/retention-policies/:policyId
// @covers put /api/v1/archive/retention-policies/:policyId
// @covers delete /api/v1/archive/retention-policies/:policyId
// @covers get /api/v1/archive/keys
// @covers post /api/v1/archive/keys/rotate
// @covers get /api/v1/archive/status
// @covers get /api/v1/archive/capture-issues
// @covers post /api/v1/archive/capture-issues/:messageId/retry
// @covers get /api/v1/archive/disposals
// @covers get /api/v1/archive/export-signing-keys
import { randomUUID } from 'node:crypto';
import {
  disposalObjectsOf,
  readDisposalObjects,
  unwrapTenantKey,
  LocalRootKeyProvider,
} from '@email-gateway/archive';
import { PrismaReadService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import {
  ArchivePurgeRefusedError,
  ArchiveTenantDataRepository,
} from '../src/modules/tenant-data/archive-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  ARCHIVE_POLL,
  ArchiveFixtures,
  archiveHttp,
  type ArchiveHttp,
  testIndexPrefix,
} from './support/archive';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';

const BASE = '/api/v1/archive';
const DAY = 86_400_000;

let ctx: IntegrationApp;
let fx: Fixtures;
let ax: ArchiveFixtures;
let org: FixtureOrganization;
let admin: ArchiveHttp;
let keyClient: ArchiveHttp;

beforeAll(async () => {
  ctx = await createIntegrationApp({ ARCHIVE_SEARCH_INDEX_PREFIX: testIndexPrefix() });
  fx = createFixtures(ctx);
  ax = new ArchiveFixtures(ctx, ctx.config.ARCHIVE_SEARCH_INDEX_PREFIX);
  fx.registerCleanup(() => ax.cleanup());
  org = await fx.createOrganization({ planCode: 'enterprise' });
  // Step 8.6 (ADR-0089): an organization admin as migrated (archive access through compliance_officer).
  const user = await fx.createUser(org, {
    roles: ['organization_admin', 'compliance_officer'],
    mfa: true,
  });
  admin = archiveHttp(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  keyClient = archiveHttp(
    ctx,
    apiKeyHeader(await fx.createApiKey(org, ['archive:read', 'archive:manage'])),
  );
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const audit = (action: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action },
    orderBy: { id: 'asc' },
  });

describe('settings and retention policies on the writer', () => {
  let policyId: string;

  it('creates a default retention policy under the plan cap and refuses longer ones', async () => {
    const tooLong = await keyClient.post(
      `${BASE}/retention-policies`,
      { name: 'Ten years', retentionDays: 3650 },
      `it-${randomUUID()}`,
    );
    expect(tooLong.status).toBe(422);
    expect(tooLong.body).toMatchObject({ code: 'archive_retention_exceeds_limit', limit: 2555 });
    const res = await admin.post(
      `${BASE}/retention-policies`,
      { name: 'Seven years', retentionDays: 2555, onExpiry: 'review' },
      `it-${randomUUID()}`,
    );
    expect(res.status).toBe(201);
    policyId = res.body.id;
    const row = await ctx.prisma.archiveRetentionPolicy.findUniqueOrThrow({
      where: { publicId: policyId },
    });
    expect(row).toMatchObject({ organizationId: org.id, retentionDays: 2555, onExpiry: 'review' });
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`${BASE}/retention-policies/${policyId}`)).status,
        ARCHIVE_POLL,
      )
      .toBe(200);
  });

  it('enables archiving with the CAS, sets the generation and enablement time, audits paths only', async () => {
    const before = await admin.get(`${BASE}/settings`);
    expect(before.body).toMatchObject({ enabled: false, entitled: true, rowVersion: 0 });
    const key = `it-${randomUUID()}`;
    const body = {
      expectedRowVersion: 0,
      enabled: true,
      defaultRetentionPolicyId: policyId,
      settings: {
        include: { quarantined: true },
        scope: { mode: 'include', addresses: ['legal@example.com'] },
      },
    };
    const res = await admin.put(`${BASE}/settings`, body, key);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body).toMatchObject({
      enabled: true,
      rowVersion: 1,
      generation: 1,
      defaultRetentionPolicyId: policyId,
    });
    const row = await ctx.prisma.archiveSetting.findUniqueOrThrow({
      where: { organizationId: org.id },
    });
    expect(row.journalEnabledAt).not.toBeNull();
    expect(row.settingsSha256).toMatch(/^[0-9a-f]{64}$/);
    const replay = await admin.put(`${BASE}/settings`, body, key);
    expect(replay.headers['idempotency-replayed']).toBe('true');
    const stale = await admin.put(
      `${BASE}/settings`,
      { ...body, expectedRowVersion: 0, enabled: false },
      `it-${randomUUID()}`,
    );
    expect(stale.body).toMatchObject({ code: 'archive_settings_conflict', currentRowVersion: 1 });
    const [entry] = await audit('archive.settings_updated');
    expect(entry?.metadata).toMatchObject({
      changedPaths: ['defaultRetentionPolicyId', 'enabled', 'settings'],
      enabling: true,
    });
    expect(JSON.stringify(entry?.metadata)).not.toContain('legal@example.com');
    // API keys may not change settings (MFA route).
    expect((await keyClient.put(`${BASE}/settings`, body, `it-${randomUUID()}`)).body.code).toBe(
      'user_required',
    );
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`${BASE}/settings`)).body.rowVersion,
        ARCHIVE_POLL,
      )
      .toBe(1);
  });

  it('refuses deleting the default policy; soft-deletes another', async () => {
    const del = await admin.delete(`${BASE}/retention-policies/${policyId}`, `it-${randomUUID()}`);
    expect(del.body.code).toBe('archive_retention_policy_is_default');
    const spare = await admin.post(
      `${BASE}/retention-policies`,
      { name: 'Spare', retentionDays: 30 },
      `it-${randomUUID()}`,
    );
    const ok = await admin.delete(
      `${BASE}/retention-policies/${spare.body.id}`,
      `it-${randomUUID()}`,
    );
    expect(ok.status).toBe(204);
    const row = await ctx.prisma.archiveRetentionPolicy.findUniqueOrThrow({
      where: { publicId: spare.body.id },
    });
    expect(row.deletedAt).not.toBeNull();
    expect(row.name).toContain('[deleted');
    const upd = await admin.put(
      `${BASE}/retention-policies/${policyId}`,
      {
        expectedRowVersion: 1,
        name: 'Seven years',
        retentionDays: 2000,
        onExpiry: 'delete',
        priority: 10,
        criteria: {},
      },
      `it-${randomUUID()}`,
    );
    expect(upd.body).toMatchObject({ retentionDays: 2000, rowVersion: 2, isDefault: true });
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`${BASE}/retention-policies`)).body.data?.length,
        ARCHIVE_POLL,
      )
      .toBe(1);
  });
});

describe('keys, status, capture issues, disposals and signing keys', () => {
  it('rotates the tenant key under the root key; old records still decrypt', async () => {
    const seeded = await ax.record(org);
    const res = await admin.post(
      `${BASE}/keys/rotate`,
      { reason: 'Annual rotation' },
      `it-${randomUUID()}`,
    );
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ previousVersion: 1, key: { version: 2, status: 'active' } });
    const rows = await ctx.prisma.archiveEncryptionKey.findMany({
      where: { organizationId: org.id },
      orderBy: { version: 'asc' },
    });
    expect(rows.map((r) => [r.version, r.status])).toEqual([
      [1, 'retired'],
      [2, 'active'],
    ]);
    const provider = LocalRootKeyProvider.fromConfig(ctx.config);
    const unwrapped = await unwrapTenantKey(provider, rows[1]!.wrappedKey!, {
      organizationId: org.id,
      version: 2,
    });
    expect(unwrapped.key).toHaveLength(32);
    expect(JSON.stringify(res.body)).not.toContain(rows[1]!.wrappedKey!);
    const journal = await admin.get(`${BASE}/messages/${seeded.row.messagePublicId}/journal`);
    expect(journal.status).toBe(200);
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`${BASE}/keys`)).body.data?.length,
        ARCHIVE_POLL,
      )
      .toBe(2);
  });

  it('lists capture issues, retries a failed intent only, shows status counts and the disposal log', async () => {
    const seeded = await ax.record(org, {}, { index: false });
    await ctx.prisma.archiveCaptureIntent.create({
      data: {
        receivedAt: seeded.row.receivedAt,
        organizationId: org.id,
        messageId: seeded.row.messageId,
        direction: 'inbound',
        sourceJournal: true,
        status: 'failed',
        lastErrorCode: 'storage_error',
        attempts: 4,
        nextCheckAt: new Date(Date.now() + DAY),
        settingsGeneration: 1n,
      },
    });
    await ctx.prisma.archiveDisposal.create({
      data: {
        requestedAt: new Date(Date.now() - 1000),
        organizationId: org.id,
        messageId: 1n,
        messagePublicId: randomUUID(),
        messageReceivedAt: new Date(Date.now() - 900 * DAY),
        archiveRecordId: 1n,
        reason: 'retention_expired',
        sha256: 'a'.repeat(64),
        sizeBytes: 10,
        objects: {},
        nextAttemptAt: new Date(),
      },
    });
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`${BASE}/capture-issues`)).body.data?.length,
        ARCHIVE_POLL,
      )
      .toBe(1);
    const issues = await admin.get(`${BASE}/capture-issues`);
    expect(issues.body.data[0]).toMatchObject({
      messageId: seeded.row.messagePublicId,
      status: 'failed',
      code: 'storage_error',
    });
    const retry = await keyClient.post(
      `${BASE}/capture-issues/${seeded.row.messagePublicId}/retry`,
      undefined,
      `it-${randomUUID()}`,
    );
    expect(retry.status).toBe(200);
    const intent = await ctx.prisma.archiveCaptureIntent.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    expect(intent.status).toBe('pending');
    expect(
      (
        await keyClient.post(
          `${BASE}/capture-issues/${seeded.row.messagePublicId}/retry`,
          undefined,
          `it-${randomUUID()}`,
        )
      ).body.code,
    ).toBe('archive_capture_retry_not_allowed');
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`${BASE}/disposals`)).body.data?.length,
        ARCHIVE_POLL,
      )
      .toBe(1);
    const status = await admin.get(`${BASE}/status`);
    expect(status.body).toMatchObject({
      settings: { enabled: true, entitled: true },
      capture: { pending: 1 },
      keys: { versions: 2, activeVersion: 2 },
      search: { configured: true },
    });
    expect(status.body.records.active).toBeGreaterThanOrEqual(2);
    const keys = await admin.get(`${BASE}/export-signing-keys`);
    expect(keys.body.data[0]).toMatchObject({
      id: ctx.config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID,
      current: true,
    });
  });

  it('capture issues list aged-out skips (max_age) and leave waits in quarantine out', async () => {
    const seeded = await Promise.all([0, 1, 2, 3].map(() => ax.record(org, {}, { index: false })));
    const old = new Date(Date.now() - 7 * 3_600_000);
    const shapes = [
      { status: 'skipped' as const, skipReason: 'max_age' },
      { status: 'skipped' as const, skipReason: 'category_excluded' },
      { status: 'pending' as const, category: 'quarantined' as const },
      { status: 'pending' as const },
    ];
    for (const [i, shape] of shapes.entries()) {
      await ctx.prisma.archiveCaptureIntent.create({
        data: {
          receivedAt: seeded[i]!.row.receivedAt,
          organizationId: org.id,
          messageId: seeded[i]!.row.messageId,
          direction: 'inbound',
          sourceJournal: true,
          nextCheckAt: new Date(Date.now() + DAY),
          settingsGeneration: 1n,
          createdAt: old,
          ...shape,
        },
      });
    }
    try {
      const listed = async () =>
        ((await admin.get(`${BASE}/capture-issues?status=skipped,pending`)).body.data ??
          []) as Array<{
          messageId: string;
          status: string;
          code: string | null;
        }>;
      await expect.poll(async () => (await listed()).length, ARCHIVE_POLL).toBe(2);
      const byId = new Map((await listed()).map((r) => [r.messageId, r]));
      // Aged out: mail that was never archived.
      expect(byId.get(seeded[0]!.row.messagePublicId)).toMatchObject({
        status: 'skipped',
        code: 'max_age',
      });
      // An excluded category is a decision, not an issue; a wait in quarantine is expected.
      expect(byId.has(seeded[1]!.row.messagePublicId)).toBe(false);
      expect(byId.has(seeded[2]!.row.messagePublicId)).toBe(false);
      expect(byId.get(seeded[3]!.row.messagePublicId)).toMatchObject({ status: 'pending' });
    } finally {
      await ctx.prisma.archiveCaptureIntent.deleteMany({
        where: { organizationId: org.id, messageId: { in: seeded.map((r) => r.row.messageId) } },
      });
    }
  });

  it('the replica list queries use their indexes (EXPLAIN)', async () => {
    const reader = ctx.get(PrismaReadService).client;
    const plans: Record<string, unknown> = {};
    const explain = async (name: string, sql: string) => {
      const rows = await reader.$queryRawUnsafe<Array<Record<string, unknown>>>(`EXPLAIN ${sql}`);
      plans[name] = rows.map((r) => ({
        table: r.f2,
        type: r.f4,
        key: r.f6,
        rows: r.f9,
        extra: r.f11,
      }));
      return rows;
    };
    const o = org.id.toString();
    const disposals = await explain(
      'disposals',
      `SELECT id FROM archive_disposals WHERE organization_id = ${o} AND requested_at >= NOW() - INTERVAL 30 DAY ORDER BY requested_at DESC, id DESC LIMIT 26`,
    );
    expect(String(disposals[0]!.f6)).toContain('organization_id');
    const intents = await explain(
      'capture_issues',
      `SELECT id FROM archive_capture_intents WHERE organization_id = ${o} AND status IN ('failed','lost') ORDER BY received_at DESC, id DESC LIMIT 26`,
    );
    expect(String(intents[0]!.f6)).toContain('organization_id');
    const keys = await explain(
      'keys',
      `SELECT id FROM archive_encryption_keys WHERE organization_id = ${o} ORDER BY version DESC LIMIT 26`,
    );
    expect(String(keys[0]!.f6)).toContain('organization_id');
    const queue = await explain(
      'index_lag',
      `SELECT created_at FROM archive_index_queue WHERE organization_id = ${o} ORDER BY created_at ASC LIMIT 1`,
    );
    expect(String(queue[0]!.f6)).toContain('organization_id');
    const policies = await explain(
      'retention_policies',
      `SELECT id FROM archive_retention_policies WHERE organization_id = ${o} AND deleted_at IS NULL ORDER BY priority, id LIMIT 26`,
    );
    expect(String(policies[0]!.f6)).toContain('organization_id');
    const records = await explain(
      'record_by_message',
      `SELECT id FROM email_archives WHERE organization_id = ${o} AND received_at >= NOW() - INTERVAL 1 DAY ORDER BY received_at DESC LIMIT 26`,
    );
    expect(String(records[0]!.f6)).toContain('organization_id');
    // Kept for the WP4 deviation note (no values, plan shapes only): EXPLAIN_OUT=<file>.
    if (process.env.EXPLAIN_OUT) {
      const { writeFileSync } = await import('node:fs');
      writeFileSync(
        process.env.EXPLAIN_OUT,
        JSON.stringify(plans, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v), 2),
      );
    }
  });
});

describe('organization purge (A24)', () => {
  it('refuses under a hold, sends records through the disposal decision, then deletes the archive', async () => {
    const other = await fx.createOrganization({ planCode: 'enterprise' });
    await ax.settings(other);
    const old = await ax.record(
      other,
      { receivedAt: new Date(Date.now() - 10 * DAY), retainUntil: new Date(Date.now() - DAY) },
      { index: false },
    );
    const hold = await ctx.prisma.archiveLegalHold.create({
      data: {
        organizationId: other.id,
        name: 'h',
        reason: 'r',
        criteria: {},
        criteriaVersion: 'archive-hold/1',
      },
    });
    const repo = ctx.get(ArchiveTenantDataRepository);
    const scope = systemScope(other.id);
    await expect(repo.purgeOrganization(scope)).rejects.toBeInstanceOf(ArchivePurgeRefusedError);
    await ctx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'released' },
    });
    const fresh = await ax.record(other, {}, { index: false });
    await expect(repo.purgeOrganization(scope)).rejects.toMatchObject({ reason: 'retention' });
    await ctx.prisma.emailArchive.updateMany({
      where: { organizationId: other.id, messageId: fresh.row.messageId },
      data: { retainUntil: new Date(Date.now() - DAY) },
    });
    const phase1 = await repo.purgeOrganization(scope);
    expect(phase1).toMatchObject({ complete: false, counts: { disposalsRequested: 2 } });
    const records = await ctx.prisma.emailArchive.findMany({ where: { organizationId: other.id } });
    expect(records.every((r) => r.status === 'disposing' && r.wrappedDek === null)).toBe(true);
    expect(
      await ctx.prisma.archiveDisposal.count({
        where: { organizationId: other.id, reason: 'organization_deleted' },
      }),
    ).toBe(2);
    // The disposal objects are in the lifecycle pipeline's shape (prefix + exact versions), the
    // same builder the archive-worker's expiry uses (step 8.1 review fix).
    const purgeDisposals = await ctx.prisma.archiveDisposal.findMany({
      where: { organizationId: other.id },
    });
    for (const d of purgeDisposals) {
      const record = records.find((r) => r.id === d.archiveRecordId)!;
      const ids = {
        organizationId: other.id,
        receivedAt: d.messageReceivedAt,
        messagePublicId: d.messagePublicId,
      };
      expect(readDisposalObjects(d.objects, ids).shape).toBe('disposal');
      expect(d.objects).toEqual(disposalObjectsOf({ ...ids, objects: record.objects }));
      expect(readDisposalObjects(d.objects, ids).objects.versions.length).toBeGreaterThanOrEqual(2);
      expect(d.replicaStatus).toEqual({ targets: [], pending: [] });
    }
    expect(
      await ctx.prisma.archiveIndexQueue.count({
        where: { organizationId: other.id, op: 'purge_org' },
      }),
    ).toBe(1);
    // The archive-worker completes the disposals (simulated): rows gone, disposals completed.
    await ctx.prisma.emailArchive.deleteMany({ where: { organizationId: other.id } });
    await ctx.prisma.archiveDisposal.updateMany({
      where: { organizationId: other.id },
      data: { state: 'completed', completedAt: new Date() },
    });
    const phase2 = await repo.purgeOrganization(scope);
    expect(phase2.complete).toBe(true);
    expect(phase2.counts.deleted).toMatchObject({ archive_settings: 1, archive_legal_holds: 1 });
    expect(phase2.counts.keysDestroyed).toBe(1);
    const key = await ctx.prisma.archiveEncryptionKey.findFirstOrThrow({
      where: { organizationId: other.id },
    });
    expect(key).toMatchObject({ status: 'destroyed', wrappedKey: null });
    expect(await ctx.prisma.archiveDisposal.count({ where: { organizationId: other.id } })).toBe(2);
    expect(old.row.organizationId).toBe(other.id);
  });
});
