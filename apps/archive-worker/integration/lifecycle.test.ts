import { randomBytes } from 'node:crypto';
import { CopyObjectCommand } from '@aws-sdk/client-s3';
import {
  archivePrefixOf,
  archiveRecordObjectsSchema,
  disposalObjectsOf,
  disposalReplicaStatusOf,
  LocalRootKeyProvider,
} from '@email-gateway/archive';
import { REGISTRY_WATERMARK } from '@email-gateway/database';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { upsertIntents } from '../src/capture/intents';
import { ROOT_REWRAP_ACTION } from '../src/keys/root-rewrap';
import { deleteRegistryRowIfUnreferenced, documentVisible } from '../src/lifecycle/disposal';
import { LIFECYCLE_RUN_ACTION } from '../src/lifecycle/expiry';
import { lockPassCursor } from '../src/lifecycle/maintenance';
import { writeCursor } from '../src/shared/db';
import { Fixtures, type SeededMessage } from './support/fixtures';
import {
  Clock,
  drainCapture,
  drainIndex,
  eventually,
  harness,
  type Harness,
  testConfig,
} from './support/harness';

const fx = new Fixtures();
const clock = new Clock();
const startedAt = new Date();
let h: Harness;

/** 2-second retention days (ARCHIVE_TEST_DAY_SECONDS, local only). */
const DAY_S = 2;

async function capture(m: SeededMessage) {
  await upsertIntents(fx.prisma, [
    {
      organizationId: m.organizationId,
      messageId: m.id,
      receivedAt: m.receivedAt,
      direction: 'inbound',
      journal: true,
      policy: false,
      policyRuleRef: null,
      settingsGeneration: 1n,
      nextCheckAt: new Date(0),
    },
  ]);
  await drainCapture(h, fx, clock.now);
  const record = await fx.prisma.emailArchive.findUnique({
    where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
  });
  expect(record).not.toBeNull();
  return record!;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function retention(key: string, versionId: string | null) {
  return h.comps.storage.getRetention(fx.archiveBucket, key, versionId);
}

beforeAll(async () => {
  h = await harness(fx, {
    clock,
    config: testConfig(fx, {
      ARCHIVE_TEST_DAY_SECONDS: String(DAY_S),
      ARCHIVE_HOLD_EXTENSION_DAYS: '5',
      ARCHIVE_REVIEW_EXTENSION_DAYS: '5',
    }),
  });
  expect(h.comps.lockState.available).toBe(true);
}, 180_000);

afterAll(async () => {
  await h?.close();
  await fx.prisma.auditLog.deleteMany({
    where: { action: ROOT_REWRAP_ACTION, organizationId: null, createdAt: { gte: startedAt } },
  });
  // Compliance locks of the suite are seconds long; wait for them before the final cleanup.
  await sleep(12_000);
  const { lockedObjects } = await fx.cleanup();
  expect(lockedObjects).toBe(0);
}, 240_000);

describe('lifecycle (A10–A15)', () => {
  it('expiry: policy extension, legal hold, review, disposal; one lifecycle_run audit row per organization', async () => {
    const org = await fx.organization('expiry', { retentionDays: 1 });
    const extended = await fx.message(org.id);
    const held = await fx.message(org.id, {
      recipients: [
        { address: 'custodian@corp-it.example', direction: 'inbound', status: 'delivered' },
      ],
    });
    const disposed = await fx.message(org.id);
    const extendedPolicy = await fx.prisma.archiveRetentionPolicy.create({
      data: {
        organizationId: org.id,
        name: 'long',
        retentionDays: 1,
        priority: 1,
        onExpiry: 'delete',
        criteria: { categories: ['delivered'] },
      },
    });
    const rExtended = await capture(extended);
    const rHeld = await capture(held);
    const rDisposed = await capture(disposed);
    expect(rExtended.retentionPolicyId).toBe(extendedPolicy.id);
    // Lengthen the policy (lazy, extend-only) and place a hold on the custodian.
    await fx.prisma.archiveRetentionPolicy.update({
      where: { id: extendedPolicy.id },
      data: { retentionDays: 1_000 },
    });
    await fx.prisma.archiveLegalHold.create({
      data: {
        organizationId: org.id,
        name: 'it hold',
        reason: 'integration',
        criteria: { custodians: ['Custodian@corp-it.example'] },
        criteriaVersion: 'archive-hold/1',
        status: 'active',
      },
    });
    // Only the held message matches the hold; the third falls back to the default (1 day, delete).
    await fx.prisma.emailArchive.updateMany({
      where: { id: { in: [rHeld.id, rDisposed.id] } },
      data: { retentionPolicyId: org.defaultPolicyId },
    });
    await sleep(DAY_S * 1000 + 500);
    const counts = await h.comps.lifecycle!.expiry.runOrganization(org.id);
    expect(counts).toMatchObject({
      policy_extended: 1,
      held: 1,
      disposed: 1,
      review: 0,
      failed: 0,
    });
    const after = await fx.prisma.emailArchive.findMany({ where: { organizationId: org.id } });
    const byId = new Map(after.map((r) => [r.id.toString(), r]));
    expect(byId.get(rExtended.id.toString())!.retainUntil.getTime()).toBeGreaterThan(
      rExtended.receivedAt.getTime() + 1_000 * DAY_S * 999,
    );
    expect(byId.get(rHeld.id.toString())).toMatchObject({ legalHold: true, status: 'active' });
    expect(byId.get(rDisposed.id.toString())).toMatchObject({
      status: 'disposing',
      wrappedDek: null,
    });
    expect(byId.get(rDisposed.id.toString())!.deletedAt).not.toBeNull();
    const disposal = await fx.prisma.archiveDisposal.findFirstOrThrow({
      where: { archiveRecordId: rDisposed.id },
    });
    expect(disposal).toMatchObject({
      reason: 'retention_expired',
      state: 'shredded',
      sha256: disposed.emlSha256,
      messagePublicId: disposed.publicId,
    });
    const audit = await fx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: LIFECYCLE_RUN_ACTION },
    });
    expect(audit).toHaveLength(1);
    expect(audit[0]!.metadata).toMatchObject({ policy_extended: 1, held: 1, disposed: 1 });
    expect(JSON.stringify(audit[0]!.metadata)).not.toContain('@');

    const reviewOrg = await fx.organization('review', { retentionDays: 1, onExpiry: 'review' });
    const reviewed = await fx.message(reviewOrg.id);
    const rReviewed = await capture(reviewed);
    await sleep(DAY_S * 1000 + 500);
    const reviewCounts = await h.comps.lifecycle!.expiry.runOrganization(reviewOrg.id);
    expect(reviewCounts.review).toBe(1);
    expect(
      await fx.prisma.emailArchive.findUnique({
        where: { id_receivedAt: { id: rReviewed.id, receivedAt: rReviewed.receivedAt } },
      }),
    ).toMatchObject({ status: 'expiry_review' });
  });

  it('a legal hold committed while a disposal decision waits is honoured (organization lock shared with hold creation)', async () => {
    const org = await fx.organization('holdrace', { retentionDays: 1 });
    const m = await fx.message(org.id, {
      recipients: [{ address: 'race@corp-it.example', direction: 'inbound', status: 'delivered' }],
    });
    const record = await capture(m);
    await sleep(DAY_S * 1000 + 500);
    // The api's hold creation: organization row FOR UPDATE, then the hold insert; held open.
    let inserted!: () => void;
    const insertedP = new Promise<void>((resolve) => (inserted = resolve));
    let commit!: () => void;
    const commitP = new Promise<void>((resolve) => (commit = resolve));
    const holdTx = fx.prisma.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT id FROM organizations WHERE id = ${org.id} FOR UPDATE`;
        await tx.archiveLegalHold.create({
          data: {
            organizationId: org.id,
            name: 'race hold',
            reason: 'integration',
            criteria: { custodians: ['race@corp-it.example'] },
            criteriaVersion: 'archive-hold/1',
            status: 'active',
          },
        });
        inserted();
        await commitP;
      },
      { timeout: 30_000, maxWait: 10_000 },
    );
    await insertedP;
    let settled = false;
    const decision = h.comps
      .lifecycle!.expiry.decideRecord(org.id, record.id, record.receivedAt)
      .finally(() => {
        settled = true;
      });
    await sleep(1_500);
    // The decision waits on the organization lock instead of deciding without the hold.
    expect(settled).toBe(false);
    commit();
    await holdTx;
    expect(await decision).toBe('held');
    const row = await fx.prisma.emailArchive.findFirstOrThrow({ where: { id: record.id } });
    expect(row).toMatchObject({ status: 'active', legalHold: true });
    expect(row.wrappedDek).not.toBeNull();
    expect(await fx.prisma.archiveDisposal.count({ where: { organizationId: org.id } })).toBe(0);
  });

  it('disposal is consistent across the archive bucket, the replica bucket, OpenSearch and MySQL', async () => {
    const org = await fx.organization('dispose', { retentionDays: 1 });
    const m = await fx.message(org.id);
    const record = await capture(m);
    const objects = archiveRecordObjectsSchema.parse(record.objects);
    // Simulated replication: the same keys in the replica bucket (MinIO CRR is not used here).
    for (const o of [objects.eml, objects.journal, ...objects.scans]) {
      await fx.s3.send(
        new CopyObjectCommand({
          Bucket: fx.replicaBucket,
          Key: o.key,
          CopySource: `${fx.archiveBucket}/${o.key}?versionId=${o.versionId}`,
        }),
      );
    }
    // An orphan of a failed earlier attempt under the record prefix.
    const prefix = archivePrefixOf({
      organizationId: org.id,
      receivedAt: m.receivedAt,
      messagePublicId: m.publicId,
    });
    await fx.put(
      fx.archiveBucket,
      `${prefix}01999999-0000-7000-8000-000000000000/eml.bin`,
      randomBytes(64),
    );
    await drainIndex(h, fx);
    expect(
      await documentVisible(fx.search, fx.prefix, {
        organizationId: org.id,
        messagePublicId: m.publicId,
      }),
    ).toBe(true);
    await sleep(DAY_S * 1000 + 500);
    expect((await h.comps.lifecycle!.expiry.runOrganization(org.id)).disposed).toBe(1);
    // Crypto-shredded at once: no DEK, content unreadable.
    await expect(
      h.comps.objects.journal(
        await fx.prisma.emailArchive.findFirstOrThrow({ where: { id: record.id } }),
      ),
    ).rejects.toThrow();
    const pipeline = h.comps.lifecycle!.disposal;
    await pipeline.runOnce(); // objects deleted; index op still queued → waits
    let d = await fx.prisma.archiveDisposal.findFirstOrThrow({
      where: { archiveRecordId: record.id },
    });
    expect(d.state).toBe('objects_deleted');
    expect(await fx.countVersions(fx.archiveBucket, prefix)).toBe(0);
    expect(await fx.countVersions(fx.replicaBucket, prefix)).toBe(0);
    await drainIndex(h, fx);
    await fx.prisma.archiveDisposal.updateMany({
      where: { id: d.id },
      data: { nextAttemptAt: new Date(0) },
    });
    await pipeline.runOnce();
    d = await fx.prisma.archiveDisposal.findFirstOrThrow({ where: { archiveRecordId: record.id } });
    expect(d.state).toBe('completed');
    expect(d.completedAt).not.toBeNull();
    expect(await fx.prisma.emailArchive.count({ where: { id: record.id } })).toBe(0);
    expect(
      await documentVisible(fx.search, fx.prefix, {
        organizationId: org.id,
        messagePublicId: m.publicId,
      }),
    ).toBe(false);
    // Registry contract: the message is above the purge watermark and its row exists → kept.
    expect(await fx.prisma.messageIdentity.count({ where: { id: m.id } })).toBe(1);
    // Below the watermark with no message row and no quarantine entry it is deleted with the
    // disposal (checked inside a rolled-back transaction: the shared watermark is never moved).
    const rolledBack = new Error('rollback');
    await expect(
      fx.prisma.$transaction(async (tx) => {
        await tx.emailMessage.deleteMany({ where: { id: m.id, receivedAt: m.receivedAt } });
        await tx.$executeRaw`
          INSERT INTO maintenance_watermarks (name, value, updated_at)
          VALUES (${REGISTRY_WATERMARK}, ${m.id + 1n}, NOW(3))
          ON DUPLICATE KEY UPDATE value = GREATEST(value, ${m.id + 1n})`;
        const deleted = await deleteRegistryRowIfUnreferenced(tx, {
          messageId: m.id,
          messageReceivedAt: m.receivedAt,
          organizationId: org.id,
        });
        expect(deleted).toBe(true);
        expect(await tx.messageIdentity.count({ where: { id: m.id } })).toBe(0);
        throw rolledBack;
      }),
    ).rejects.toBe(rolledBack);
    expect(await fx.prisma.messageIdentity.count({ where: { id: m.id } })).toBe(1);
    // Verification: a completed disposal with nothing left stays completed; a surviving replica
    // version re-opens it and the pipeline finishes it again.
    const verifier = h.comps.lifecycle!.verifier;
    const first = await verifier.runOnce();
    expect(first.reopened).toBe(0);
    await fx.put(fx.replicaBucket, objects.eml.key, randomBytes(32));
    await writeCursor(fx.prisma, `archive:disposal-verify:it-${fx.suffix}`, 0n, new Date());
    const second = await verifier.runOnce();
    expect(second.reopened).toBe(1);
    await pipeline.runOnce();
    await pipeline.runOnce();
    d = await fx.prisma.archiveDisposal.findFirstOrThrow({ where: { archiveRecordId: record.id } });
    expect(d.state).toBe('completed');
    expect(await fx.countVersions(fx.replicaBucket, prefix)).toBe(0);
  });

  it('api-written disposals (review_disposed with the shared builder, organization_deleted in the legacy record shape) run to completed', async () => {
    const org = await fx.organization('apidispose', { retentionDays: 30 });
    const reviewed = await fx.message(org.id, { ageSeconds: 0 });
    const purged = await fx.message(org.id, { ageSeconds: 0 });
    const rReviewed = await capture(reviewed);
    const rPurged = await capture(purged);
    await drainIndex(h, fx);
    // The api's writeDisposalDecision (manual dispose, organization purge phase 1): the
    // disposal row, the record crypto-shredded, an index delete op — in one transaction.
    const apiDecision = async (
      record: typeof rReviewed,
      reason: 'review_disposed' | 'organization_deleted',
      objects: unknown,
    ) =>
      fx.prisma.$transaction(async (tx) => {
        await tx.archiveDisposal.create({
          data: {
            requestedAt: new Date(),
            organizationId: record.organizationId,
            messageId: record.messageId,
            messagePublicId: record.messagePublicId,
            messageReceivedAt: record.receivedAt,
            archiveRecordId: record.id,
            reason,
            sha256: record.sha256,
            sizeBytes: record.sizeBytes,
            objects: objects as never,
            replicaStatus: disposalReplicaStatusOf([]) as never,
            state: 'shredded',
            nextAttemptAt: new Date(0),
          },
        });
        await tx.emailArchive.updateMany({
          where: { id: record.id, receivedAt: record.receivedAt },
          data: { status: 'disposing', wrappedDek: null, deletedAt: new Date() },
        });
        await tx.archiveIndexQueue.create({
          data: {
            organizationId: record.organizationId,
            messageId: record.messageId,
            receivedAt: record.receivedAt,
            messagePublicId: record.messagePublicId,
            op: 'delete',
          },
        });
      });
    await apiDecision(rReviewed, 'review_disposed', disposalObjectsOf(rReviewed));
    // Rows written before the writers shared the builder stored the record's own objects.
    await apiDecision(rPurged, 'organization_deleted', rPurged.objects);
    await drainIndex(h, fx);
    for (let i = 0; i < 3; i += 1) {
      await fx.prisma.archiveDisposal.updateMany({
        where: { organizationId: org.id, state: { not: 'completed' } },
        data: { nextAttemptAt: new Date(0) },
      });
      await h.comps.lifecycle!.disposal.runOnce();
    }
    const disposals = await fx.prisma.archiveDisposal.findMany({
      where: { organizationId: org.id },
      orderBy: { id: 'asc' },
    });
    expect(disposals.map((d) => [d.reason, d.state, d.attempts, d.lastErrorCode])).toEqual([
      ['review_disposed', 'completed', 0, null],
      ['organization_deleted', 'completed', 0, null],
    ]);
    expect(await fx.countVersions(fx.archiveBucket, `org/${org.id}/archive/`)).toBe(0);
    expect(await fx.countVersions(fx.replicaBucket, `org/${org.id}/archive/`)).toBe(0);
    // Phase 2 of the organization purge waits for exactly this: no record row left.
    expect(await fx.prisma.emailArchive.count({ where: { organizationId: org.id } })).toBe(0);
  });

  it('Object Lock governance and compliance: refused deletes, extension on hold, disposal after the lock', async () => {
    const gov = await fx.organization('gov', { lockMode: 'governance', retentionDays: 3 });
    const comp = await fx.organization('comp', { lockMode: 'compliance', retentionDays: 3 });
    const g = await fx.message(gov.id, { ageSeconds: 0 });
    const c = await fx.message(comp.id, {
      ageSeconds: 0,
      recipients: [{ address: 'held@corp-it.example', direction: 'inbound', status: 'delivered' }],
    });
    const rg = await capture(g);
    const rc = await capture(c);
    expect(rg.lockMode).toBe('governance');
    expect(rc.lockMode).toBe('compliance');
    const og = archiveRecordObjectsSchema.parse(rg.objects);
    const oc = archiveRecordObjectsSchema.parse(rc.objects);
    expect(await retention(og.eml.key, og.eml.versionId)).toMatchObject({ mode: 'governance' });
    expect(await retention(oc.journal.key, oc.journal.versionId)).toMatchObject({
      mode: 'compliance',
    });
    // Locked versions refuse deletion (governance without bypass, compliance even with it).
    expect(
      await h.comps.storage.deleteVersion(fx.archiveBucket, og.eml.key, og.eml.versionId!),
    ).toBe('locked');
    expect(
      await h.comps.storage.deleteVersion(fx.archiveBucket, oc.eml.key, oc.eml.versionId!, {
        bypassGovernance: true,
      }),
    ).toBe('locked');
    // A hold on the compliance record: at expiry the lock is EXTENDED before the row (extend-only).
    await fx.prisma.archiveLegalHold.create({
      data: {
        organizationId: comp.id,
        name: 'lock hold',
        reason: 'integration',
        criteria: { custodians: ['held@corp-it.example'] },
        criteriaVersion: 'archive-hold/1',
        status: 'active',
      },
    });
    const before = (await retention(oc.eml.key, oc.eml.versionId))!.until.getTime();
    await eventually(
      () => Date.now() > Math.max(rc.retainUntil.getTime(), rc.lockUntil!.getTime()) + 300,
      30_000,
      'retention passed',
      250,
    );
    const held = await h.comps.lifecycle!.expiry.runOrganization(comp.id);
    expect(held.held).toBe(1);
    const extendedUntil = (await retention(oc.eml.key, oc.eml.versionId))!.until.getTime();
    expect(extendedUntil).toBeGreaterThan(before);
    const heldRow = await fx.prisma.emailArchive.findFirstOrThrow({ where: { id: rc.id } });
    expect(heldRow.lockUntil!.getTime()).toBe(extendedUntil);
    expect(heldRow.legalHold).toBe(true);
    // Release: once the extended lock has passed, the record is disposed and every version goes.
    await fx.prisma.archiveLegalHold.updateMany({
      where: { organizationId: comp.id },
      data: { status: 'released', releasedAt: new Date() },
    });
    await eventually(() => Date.now() > extendedUntil + 500, 30_000, 'extended lock passed', 250);
    expect((await h.comps.lifecycle!.expiry.runOrganization(comp.id)).disposed).toBe(1);
    await drainIndex(h, fx);
    for (let i = 0; i < 3; i += 1) {
      await fx.prisma.archiveDisposal.updateMany({
        where: { organizationId: comp.id },
        data: { nextAttemptAt: new Date(0) },
      });
      await h.comps.lifecycle!.disposal.runOnce();
    }
    expect(
      await fx.prisma.archiveDisposal.findFirstOrThrow({ where: { organizationId: comp.id } }),
    ).toMatchObject({ state: 'completed' });
    expect(await fx.countVersions(fx.archiveBucket, `org/${comp.id}/archive/`)).toBe(0);
  });

  it('orphans of a failed locked capture are deleted after 24 h (governance bypass) and the apply-lock pass upgrades records', async () => {
    const org = await fx.organization('orphans', { lockMode: 'governance', retentionDays: 3 });
    const m = await fx.message(org.id, { ageSeconds: 0 });
    let fail = true;
    const hf = await harness(fx, {
      clock,
      config: testConfig(fx, { ARCHIVE_TEST_DAY_SECONDS: String(DAY_S) }),
      faults: {
        beforeCommit: () => {
          if (!fail) return Promise.resolve();
          fail = false;
          return Promise.reject(Object.assign(new Error('injected'), { code: 'P1001' }));
        },
      },
    });
    await upsertIntents(fx.prisma, [
      {
        organizationId: org.id,
        messageId: m.id,
        receivedAt: m.receivedAt,
        direction: 'inbound',
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: 1n,
        nextCheckAt: new Date(0),
      },
    ]);
    await hf.comps.capture!.scheduler.runOnce();
    const prefix = `org/${org.id}/archive/`;
    const orphans = await fx.countVersions(fx.archiveBucket, prefix);
    expect(orphans).toBeGreaterThanOrEqual(3); // locked: left for the reconciliation
    await hf.close();
    clock.advance(5_000);
    await drainCapture(h, fx, clock.now);
    const record = await fx.prisma.emailArchive.findFirstOrThrow({ where: { messageId: m.id } });
    const referenced = 2 + archiveRecordObjectsSchema.parse(record.objects).scans.length;
    expect(await fx.countVersions(fx.archiveBucket, prefix)).toBe(orphans + referenced);
    clock.advance(25 * 3_600_000);
    const report = await h.comps.lifecycle!.orphans.runOnce();
    expect(report.deleted).toBe(orphans);
    expect(await fx.countVersions(fx.archiveBucket, prefix)).toBe(referenced);
    clock.offsetMs = 0;

    // Apply-lock pass: a `none` tenant moves to governance, then compliance (needs the bypass).
    const plain = await fx.organization('applylock', { retentionDays: 3 });
    const p = await fx.message(plain.id, { ageSeconds: 0 });
    const rp = await capture(p);
    expect(rp.lockMode).toBe('none');
    const op = archiveRecordObjectsSchema.parse(rp.objects);
    expect(await retention(op.eml.key, op.eml.versionId)).toBeNull();
    for (const mode of ['governance', 'compliance'] as const) {
      await fx.prisma.archiveSetting.update({
        where: { organizationId: plain.id },
        data: { objectLockMode: mode },
      });
      await writeCursor(fx.prisma, lockPassCursor(plain.id), 0n, new Date());
      const pass = await h.comps.lifecycle!.lockPass.runOnce();
      expect(pass.applied).toBe(1);
      expect(
        await fx.prisma.streamCursor.count({ where: { name: lockPassCursor(plain.id) } }),
      ).toBe(0);
      const row = await fx.prisma.emailArchive.findFirstOrThrow({ where: { id: rp.id } });
      expect(row.lockMode).toBe(mode);
      expect(await retention(op.eml.key, op.eml.versionId)).toMatchObject({ mode });
    }
    expect(
      await fx.prisma.archiveIndexQueue.count({ where: { messageId: p.id } }),
    ).toBeGreaterThanOrEqual(2);
  });

  it('root key rotation: every tenant key is re-wrapped under the new root key, records stay readable', async () => {
    const org = await fx.organization('rewrap');
    const m = await fx.message(org.id, { ageSeconds: 0 });
    const record = await capture(m);
    const oldId = h.comps.rootKeys.currentKeyId;
    expect(
      (await fx.prisma.archiveEncryptionKey.findFirstOrThrow({ where: { organizationId: org.id } }))
        .rootKeyId,
    ).toBe(oldId);
    const newRootKey = randomBytes(32).toString('hex');
    const next = LocalRootKeyProvider.fromConfig({
      ARCHIVE_ROOT_KEY: newRootKey,
      ARCHIVE_ROOT_KEY_ID: `${oldId}x`,
      ARCHIVE_ROOT_KEY_PREVIOUS: h.config.ARCHIVE_ROOT_KEY,
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: oldId,
    });
    const rotated = await harness(fx, { rootKeys: next });
    const report = await rotated.comps.lifecycle!.rewrap.runOnce();
    expect(report.rewrapped).toBeGreaterThanOrEqual(1);
    expect(report.pending).toBe(0);
    expect(report.failed).toBe(0);
    const keys = await fx.prisma.archiveEncryptionKey.findMany({
      where: { organizationId: { in: fx.organizationIds } },
    });
    expect(keys.every((k) => k.rootKeyId === `${oldId}x`)).toBe(true);
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { action: ROOT_REWRAP_ACTION, createdAt: { gte: startedAt } },
      orderBy: { createdAt: 'desc' },
    });
    expect(audit.metadata).toMatchObject({
      fromRootKeyId: oldId,
      toRootKeyId: `${oldId}x`,
      pending: 0,
    });
    await rotated.close();
    // A worker holding only the new root key (previous removed) reads the record.
    const onlyNew = await harness(fx, {
      rootKeys: LocalRootKeyProvider.fromConfig({
        ARCHIVE_ROOT_KEY: newRootKey,
        ARCHIVE_ROOT_KEY_ID: `${oldId}x`,
      }),
    });
    expect((await onlyNew.comps.objects.journal(record)).messageId).toBe(m.publicId);
    await onlyNew.close();
  });
});
