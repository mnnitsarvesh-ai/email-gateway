import { createHash } from 'node:crypto';
import {
  archiveRecordObjectsSchema,
  archiveScanRoundsSchema,
  LocalRootKeyProvider,
  parseScanSnapshot,
  tenantAliasName,
  decryptArchiveObject,
} from '@email-gateway/archive';
import { AmqpConnection, ConfirmPublisher, QueueConsumer, uuidv7 } from '@email-gateway/common';
import { EventTypes, type EventEnvelope } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ARCHIVE_CONSUMER, ARCHIVE_EVENT_TYPES, ARCHIVE_QUEUE } from '../src/capture/consumer';
import { upsertIntents } from '../src/capture/intents';
import { FactsReader } from '../src/capture/facts';
import { TenantKeyService } from '../src/keys/tenant-keys';
import { ArchiveStorage } from '../src/storage/archive-storage';
import { createTestVhost, requireEnv, type TestVhost } from './support/broker';
import { Fixtures, type SeededMessage } from './support/fixtures';
import {
  Clock,
  drainCapture,
  drainIndex,
  eventually,
  harness,
  type Harness,
  silent,
} from './support/harness';

const fx = new Fixtures();
const clock = new Clock();
let h: Harness;

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

async function readAll(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream as AsyncIterable<Buffer>) chunks.push(Buffer.from(c));
  return Buffer.concat(chunks);
}

async function recordOf(m: SeededMessage) {
  return fx.prisma.emailArchive.findUnique({
    where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
  });
}

async function intentOf(m: SeededMessage) {
  return fx.prisma.archiveCaptureIntent.findUnique({
    where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
  });
}

beforeAll(async () => {
  h = await harness(fx, { clock });
  // First passes initialize both forward cursors at "now" (no backfill) before any seeding.
  await h.comps.capture!.journal.runOnce();
  await h.comps.capture!.policy.runOnce();
}, 180_000);

afterAll(async () => {
  await h?.close();
  const { lockedObjects } = await fx.cleanup();
  expect(lockedObjects).toBe(0);
}, 180_000);

describe('capture (A2–A7)', () => {
  it('journals inbound, outbound and internal mail: encrypted objects, records, intents, index docs, frozen scans', async () => {
    const org = await fx.organization('dirs');
    const scansBefore = await fx.prisma.emailScan.count({ where: { organizationId: org.id } });
    const inbound = await fx.message(org.id, { direction: 'inbound' });
    const outbound = await fx.message(org.id, {
      direction: 'outbound',
      recipients: [
        { address: 'partner@remote-it.example', direction: 'outbound', status: 'delivered' },
      ],
    });
    const internal = await fx.message(org.id, {
      direction: 'internal',
      recipients: [
        { address: 'colleague@corp-it.example', direction: 'internal', status: 'delivered' },
      ],
    });
    const scansSeeded = await fx.prisma.emailScan.count({ where: { organizationId: org.id } });
    const sweep = await h.comps.capture!.journal.runOnce();
    expect(sweep.intents).toBeGreaterThanOrEqual(3);
    await drainCapture(h, fx, clock.now);
    for (const m of [inbound, outbound, internal]) {
      const record = await recordOf(m);
      expect(record).not.toBeNull();
      expect(record).toMatchObject({
        organizationId: org.id,
        messagePublicId: m.publicId,
        status: 'active',
        category: 'delivered',
        capturedByJournal: true,
        capturedByPolicy: false,
        sha256: m.emlSha256,
        encryptionFormat: 'archive-object/1',
        keyVersion: 1,
        lockMode: 'none',
      });
      expect(record!.wrappedDek).toMatch(/^v1\.k1\./);
      const objects = archiveRecordObjectsSchema.parse(record!.objects);
      expect(objects.eml.key.startsWith(`org/${org.id}/archive/`)).toBe(true);
      // The stored object is ciphertext; it decrypts to the original, byte for byte.
      const sealed = await h.comps.storage.getBuffer(
        fx.archiveBucket,
        objects.eml.key,
        objects.eml.versionId,
      );
      expect(sealed.subarray(0, 6).toString('ascii')).toBe('EGARC1');
      expect(sealed.includes(m.eml.subarray(0, 40))).toBe(false);
      expect(sha(sealed)).toBe(objects.eml.sha256);
      const plain = await readAll(await h.comps.objects.emlStream(record!));
      expect(plain.equals(m.eml)).toBe(true);
      expect(sha(plain)).toBe(m.emlSha256);
      // The journal object holds the envelope, headers, attachments and the decoded body.
      const journal = await h.comps.objects.journal(record!);
      expect(journal.messageId).toBe(m.publicId);
      expect(journal.body.text).toContain('Synthetic archive test body.');
      expect(journal.attachments[0]).toMatchObject({ partIndex: 2, fileName: 'report.bin' });
      // The linked round decodes to the same read-model rows (never a rescan).
      const links = archiveScanRoundsSchema.parse(record!.scanRounds);
      expect(links).toHaveLength(1);
      const { dek } = await h.comps.objects.dek(record!);
      const scanSealed = await h.comps.storage.getBuffer(
        fx.archiveBucket,
        objects.scans[0]!.key,
        objects.scans[0]!.versionId,
      );
      const snapshot = parseScanSnapshot(
        decryptArchiveObject(scanSealed, {
          dek,
          kind: 'scan',
          organizationId: org.id,
          subjectId: m.publicId,
        }),
      );
      const reader = new FactsReader();
      const facts = await reader.message(fx.prisma, {
        organizationId: org.id,
        messageId: m.id,
        receivedAt: m.receivedAt,
      });
      const [round] = await reader.terminalRounds(fx.prisma, facts!.message);
      const live = await reader.roundRows(fx.prisma, facts!.message, round!);
      expect(snapshot.rows).toEqual(live);
      expect(snapshot.rows.scan?.id).toBe(m.scanId);
      const intent = await intentOf(m);
      expect(intent).toMatchObject({
        status: 'captured_open',
        category: 'delivered',
        archiveId: record!.id,
      });
    }
    // Capture never rescans.
    expect(await fx.prisma.emailScan.count({ where: { organizationId: org.id } })).toBe(
      scansSeeded,
    );
    expect(scansSeeded - scansBefore).toBe(3);
    // Index documents through the tenant alias (metadata only).
    await drainIndex(h, fx);
    const res = await fx.search.search<Record<string, unknown>>(
      tenantAliasName(fx.prefix, org.id),
      { query: { match_all: {} }, size: 10 },
      { routing: org.id.toString() },
    );
    expect(res.hits.map((x) => x._id).sort()).toEqual(
      [inbound, outbound, internal].map((m) => m.publicId).sort(),
    );
    const doc = res.hits.find((x) => x._id === inbound.publicId)!._source!;
    expect(doc).toMatchObject({
      org_id: org.id.toString(),
      direction: 'inbound',
      category: 'delivered',
    });
    expect(doc.attachment_names).toEqual(['report.bin']);
    expect(doc.spf).toBe('pass');
    expect(Object.keys(doc)).not.toContain('body');
    const record = await recordOf(inbound);
    expect(record!.indexedAt).not.toBeNull();
  });

  it('applies directions, categories and the journal enablement (A3, A4)', async () => {
    const org = await fx.organization('rules', {
      settings: { directions: { inbound: false }, include: { rejected: true } },
    });
    const inbound = await fx.message(org.id, { direction: 'inbound' });
    const rejected = await fx.message(org.id, {
      direction: 'outbound',
      status: 'rejected',
      statusReason: 'policy_reject',
      recipients: [{ address: 'x@remote-it.example', direction: 'outbound', status: 'discarded' }],
    });
    const failed = await fx.message(org.id, {
      direction: 'outbound',
      status: 'rejected',
      statusReason: 'delivery_failed',
      recipients: [{ address: 'y@remote-it.example', direction: 'outbound', status: 'failed' }],
    });
    const late = await fx.organization('late', { journalEnabledAt: new Date() });
    const before = await fx.message(late.id, { direction: 'outbound' });
    await h.comps.capture!.journal.runOnce();
    await drainCapture(h, fx, clock.now);
    expect(await intentOf(inbound)).toBeNull(); // direction disabled: not eligible
    expect(await intentOf(before)).toBeNull(); // received before journal_enabled_at
    expect(await recordOf(rejected)).toMatchObject({ category: 'rejected' });
    expect(await intentOf(failed)).toMatchObject({
      status: 'skipped',
      skipReason: 'category_excluded',
    });
    expect(await recordOf(failed)).toBeNull();
  });

  it('journals by scope against the real directory: department, user and verified domain, include and exclude', async () => {
    const tag = `${fx.suffix}`.toLowerCase();
    const setUp = async (label: string, mode: 'include' | 'exclude') => {
      const org = await fx.organization(label);
      const user = await fx.prisma.user.create({
        data: {
          organizationId: org.id,
          email: `scope.user-${label}@corp-${tag}.example`,
          displayName: 'Scope user',
          status: 'active',
        },
        select: { publicId: true, email: true },
      });
      const department = await fx.prisma.tenantDepartment.create({
        data: { organizationId: org.id, name: `Legal ${label}` },
        select: { id: true, publicId: true },
      });
      await fx.prisma.tenantDepartmentMember.create({
        data: {
          organizationId: org.id,
          departmentId: department.id,
          address: `dept.member-${label}@corp-${tag}.example`,
        },
      });
      const domain = await fx.prisma.domain.create({
        data: {
          organizationId: org.id,
          name: `scoped-${label}-${tag}.example`,
          status: 'verified',
          verifiedAt: new Date(),
        },
        select: { publicId: true, name: true },
      });
      // A pending (unverified) domain and an unknown user id resolve to nothing and are counted.
      const pending = await fx.prisma.domain.create({
        data: { organizationId: org.id, name: `pending-${label}-${tag}.example` },
        select: { publicId: true },
      });
      await fx.prisma.archiveSetting.update({
        where: { organizationId: org.id },
        data: {
          settings: {
            scope: {
              mode,
              departmentIds: [department.publicId],
              userIds: [user.publicId, '0190a5d0-0000-7000-8000-00000000dead'],
              domainIds: [domain.publicId, pending.publicId],
            },
          },
          generation: 2n,
        },
      });
      const to = (address: string) =>
        fx.message(org.id, {
          recipients: [{ address, direction: 'inbound', status: 'delivered' }],
        });
      return {
        org,
        department: await to(`dept.member-${label}@corp-${tag}.example`),
        user: await to(user.email),
        domain: await to(`anyone@${domain.name}`),
        outsider: await to(`outsider-${label}@elsewhere-${tag}.example`),
      };
    };
    const inc = await setUp('scope-inc', 'include');
    const exc = await setUp('scope-exc', 'exclude');
    await h.comps.capture!.journal.runOnce();
    await drainCapture(h, fx, clock.now);
    // include: the department member, the user and the verified domain are journaled; the
    // outsider gets no intent at all.
    for (const m of [inc.department, inc.user, inc.domain]) {
      expect(await recordOf(m)).toMatchObject({ capturedByJournal: true });
    }
    expect(await intentOf(inc.outsider)).toBeNull();
    expect(await recordOf(inc.outsider)).toBeNull();
    // exclude: the reverse.
    for (const m of [exc.department, exc.user, exc.domain]) {
      expect(await intentOf(m)).toBeNull();
      expect(await recordOf(m)).toBeNull();
    }
    expect(await recordOf(exc.outsider)).toMatchObject({ capturedByJournal: true });
    // Unresolved ids (an unknown user, an unverified domain) are counted, never guessed.
    for (const o of [inc.org, exc.org]) {
      const c = await h.comps.orgs.get(o.id);
      expect(c).toMatchObject({ unresolved: 2, scopeTruncated: false });
    }
  });

  it('consumes mail.message.archive_requested.v1 (policy source), ignores unknown/foreign and duplicates', async () => {
    let vhost: TestVhost | undefined;
    let conn: AmqpConnection | undefined;
    let pubConn: AmqpConnection | undefined;
    let feed: QueueConsumer<unknown> | undefined;
    let publisher: ConfirmPublisher | undefined;
    try {
      vhost = await createTestVhost();
      const org = await fx.organization('consumer', {
        settings: { directions: { inbound: false, outbound: false, internal: false } },
      });
      const other = await fx.organization('consumer-other');
      const m = await fx.message(org.id, { direction: 'inbound' });
      conn = new AmqpConnection({
        urls: [vhost.adminUrl],
        connectionName: 'it-archive',
        logger: silent,
        reconnect: { baseMs: 50, maxMs: 500 },
      });
      conn.start();
      await conn.waitUntilConnected(15_000);
      pubConn = new AmqpConnection({
        urls: [vhost.adminUrl],
        connectionName: 'it-relay',
        logger: silent,
        reconnect: { baseMs: 50, maxMs: 500 },
      });
      pubConn.start();
      await pubConn.waitUntilConnected(15_000);
      publisher = new ConfirmPublisher({
        connection: pubConn,
        logger: silent,
        appId: 'event-relay',
        confirmTimeoutMs: 15_000,
        maxMessageBytes: 131_072,
      });
      const consumerPublisher = new ConfirmPublisher({
        connection: conn,
        logger: silent,
        appId: 'archive-worker',
        confirmTimeoutMs: 15_000,
        maxMessageBytes: 131_072,
      });
      feed = new QueueConsumer<unknown>({
        connection: conn,
        publisher: consumerPublisher,
        queue: ARCHIVE_QUEUE,
        consumer: ARCHIVE_CONSUMER,
        eventTypes: [...ARCHIVE_EVENT_TYPES],
        prefetch: 4,
        logger: silent,
      });
      feed.start(h.comps.capture!.consumer.handle);
      const envelope = (orgId: bigint, payload: Record<string, unknown>): EventEnvelope => ({
        eventId: fx.track(uuidv7()),
        eventType: EventTypes.MessageArchiveRequested,
        occurredAt: new Date().toISOString(),
        correlationId: `it-arch-${fx.suffix}`,
        organizationId: orgId.toString(),
        payload,
      });
      const payload = {
        messageId: m.id.toString(),
        receivedAt: m.receivedAt.toISOString(),
        direction: 'inbound',
        lifecycleRound: 0,
        emlS3Key: m.emlKey,
        source: 'policy',
        ruleRef: `${uuidv7()}#1/archive-legal`,
        policyGeneration: '1',
        requestedAt: new Date().toISOString(),
      };
      const e = envelope(org.id, payload);
      await publisher.publish({ envelope: e });
      await publisher.publish({ envelope: e }); // duplicate delivery of the same event
      await publisher.publish({ envelope: envelope(other.id, payload) }); // foreign organization
      await publisher.publish({
        envelope: envelope(org.id, {
          ...payload,
          messageId: '999999999999',
          emlS3Key: `org/${org.id}/eml/x.eml`,
        }),
      });
      await eventually(
        async () =>
          (await fx.prisma.messageIdempotency.count({ where: { eventId: e.eventId } })) === 1,
        30_000,
        'archive request consumed',
      );
      await eventually(
        async () => {
          const text = await h.metrics.metrics();
          const count = (result: string) =>
            Number(
              new RegExp(
                `archive_consumer_events_total\\{[^}]*result="${result}"[^}]*\\} (\\d+)`,
              ).exec(text)?.[1] ?? 0,
            );
          return (
            count('unknown') === 1 &&
            count('foreign') === 1 &&
            count('duplicate') === 1 &&
            count('intent') === 1
          );
        },
        30_000,
        'unknown, foreign and duplicate counted',
      );
      const intent = await intentOf(m);
      expect(intent).toMatchObject({
        sourcePolicy: true,
        sourceJournal: false,
        policyRuleRef: payload.ruleRef,
      });
      expect(
        await fx.prisma.archiveCaptureIntent.count({ where: { organizationId: other.id } }),
      ).toBe(0);
      await drainCapture(h, fx, clock.now);
      expect(await recordOf(m)).toMatchObject({
        capturedByPolicy: true,
        capturedByJournal: false,
        policyRuleRef: payload.ruleRef,
      });
    } finally {
      await feed?.stop().catch(() => undefined);
      await publisher?.close().catch(() => undefined);
      await conn?.close().catch(() => undefined);
      await pubConn?.close().catch(() => undefined);
      await vhost?.cleanup().catch(() => undefined);
    }
  });

  it('recovers a policy ARCHIVE request from policy_execution_logs after the queue lost it', async () => {
    const vhost = await createTestVhost();
    try {
      const org = await fx.organization('reconcile', {
        settings: { directions: { inbound: false, outbound: false, internal: false } },
      });
      const m = await fx.message(org.id, { direction: 'inbound', archivePolicy: true });
      // The request was published to email.archive and the queue was purged (lossy by design).
      const mgmt = new URL(requireEnv('RABBITMQ_MGMT_URL'));
      const auth = `Basic ${Buffer.from(`${decodeURIComponent(new URL(requireEnv('RABBITMQ_URL')).username)}:${decodeURIComponent(new URL(requireEnv('RABBITMQ_URL')).password)}`).toString('base64')}`;
      const purge = await fetch(
        `${mgmt.origin}/api/queues/${encodeURIComponent(vhost.vhost)}/email.archive/contents`,
        { method: 'DELETE', headers: { authorization: auth } },
      );
      expect([200, 204]).toContain(purge.status);
      expect(await intentOf(m)).toBeNull();
      await h.comps.capture!.journal.runOnce();
      expect(await intentOf(m)).toBeNull(); // journaling is off for every direction
      const report = await h.comps.capture!.policy.runOnce();
      expect(report.intents).toBeGreaterThanOrEqual(1);
      expect(await intentOf(m)).toMatchObject({ sourcePolicy: true });
      await drainCapture(h, fx, clock.now);
      expect(await recordOf(m)).toMatchObject({ capturedByPolicy: true });
    } finally {
      await vhost.cleanup().catch(() => undefined);
    }
  });

  it('creates the tenant key once under a race (unique (organization_id, version))', async () => {
    const org = await fx.organization('keyrace');
    const provider = LocalRootKeyProvider.fromConfig(h.config);
    const services = Array.from(
      { length: 6 },
      () => new TenantKeyService(fx.prisma, provider, { cacheTtlMs: 1 }),
    );
    const keys = await Promise.all(services.map((s) => s.active(org.id)));
    expect(new Set(keys.map((k) => k.key.toString('hex'))).size).toBe(1);
    expect(keys.every((k) => k.version === 1)).toBe(true);
    const rows = await fx.prisma.archiveEncryptionKey.findMany({
      where: { organizationId: org.id },
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      status: 'active',
      rootKeyId: provider.currentKeyId,
      algorithm: 'aes-256-gcm',
    });
  });

  it('refuses an original whose SHA-256 differs (integrity_mismatch, nothing committed) and records lost originals', async () => {
    const org = await fx.organization('integrity');
    const bad = await fx.message(org.id, { wrongSha: true });
    const gone = await fx.message(org.id, { noEml: true });
    await h.comps.capture!.journal.runOnce();
    await drainCapture(h, fx, clock.now);
    expect(await intentOf(bad)).toMatchObject({
      status: 'failed',
      lastErrorCode: 'integrity_mismatch',
    });
    expect(await recordOf(bad)).toBeNull();
    expect(await fx.countVersions(fx.archiveBucket, `org/${org.id}/archive/`)).toBe(0);
    expect(await intentOf(gone)).toMatchObject({ status: 'lost', skipReason: 'original_missing' });
    expect(await h.metrics.metrics()).toMatch(/archive_integrity_failures_total\{[^}]*\} [1-9]/);
  });

  it('fault injection: S3 failure mid-upload, DB failure after upload, restart with a held lease → exactly one record', async () => {
    const org = await fx.organization('faults');
    // (a) S3 fails mid-upload: no object completes, the intent retries, then one record.
    const m1 = await fx.message(org.id, { bodyBytes: 200_000 });
    const failing = new (class extends ArchiveStorage {
      fail = true;
      override async uploadStream(input: Parameters<ArchiveStorage['uploadStream']>[0]) {
        if (!this.fail) return super.uploadStream(input);
        this.fail = false;
        let seen = 0;
        const body = input.body.pipe(
          new (await import('node:stream')).Transform({
            transform(chunk: Buffer, _e, cb) {
              seen += chunk.length;
              cb(seen > 50_000 ? new Error('injected S3 failure') : null, chunk);
            },
          }),
        );
        return super.uploadStream({ ...input, body: body });
      }
    })(
      fx.s3,
      { mail: fx.mailBucket, archive: fx.archiveBucket },
      { timeoutMs: 30_000, partSizeBytes: 5 * 1_048_576 },
    );
    const hs = await harness(fx, { clock });
    (
      hs.comps.capture!.executor as unknown as { options: { storage: ArchiveStorage } }
    ).options.storage = failing;
    await upsertIntents(fx.prisma, [
      {
        organizationId: org.id,
        messageId: m1.id,
        receivedAt: m1.receivedAt,
        direction: 'inbound',
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: 1n,
        nextCheckAt: new Date(0),
      },
    ]);
    await hs.comps.capture!.scheduler.runOnce();
    expect(await recordOf(m1)).toBeNull();
    expect(await intentOf(m1)).toMatchObject({ status: 'pending', attempts: 1 });
    expect(await fx.countVersions(fx.archiveBucket, `org/${org.id}/archive/`)).toBe(0);
    clock.advance(5_000);
    await drainCapture(hs, fx, clock.now);
    expect(await recordOf(m1)).not.toBeNull();
    await hs.close();

    // (b) The database fails after the uploads: the attempt's objects are removed, no row exists.
    const m2 = await fx.message(org.id);
    let failCommit = true;
    const hb = await harness(fx, {
      clock,
      faults: {
        beforeCommit: () => {
          if (!failCommit) return Promise.resolve();
          failCommit = false;
          return Promise.reject(
            Object.assign(new Error('injected database failure'), { code: 'P1001' }),
          );
        },
      },
    });
    await upsertIntents(fx.prisma, [
      {
        organizationId: org.id,
        messageId: m2.id,
        receivedAt: m2.receivedAt,
        direction: 'inbound',
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: 1n,
        nextCheckAt: new Date(0),
      },
    ]);
    const prefix2 = `org/${org.id}/archive/`;
    const before = await fx.countVersions(fx.archiveBucket, prefix2);
    await hb.comps.capture!.scheduler.runOnce();
    expect(await recordOf(m2)).toBeNull();
    expect(await fx.countVersions(fx.archiveBucket, prefix2)).toBe(before);
    clock.advance(5_000);
    await drainCapture(hb, fx, clock.now);
    expect(await recordOf(m2)).not.toBeNull();
    await hb.close();

    // (c) A replica claims, then "crashes" (never processes); after the lease another replica
    // captures; the first one's late work loses its lease and writes nothing.
    const m3 = await fx.message(org.id);
    await upsertIntents(fx.prisma, [
      {
        organizationId: org.id,
        messageId: m3.id,
        receivedAt: m3.receivedAt,
        direction: 'inbound',
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: 1n,
        nextCheckAt: new Date(0),
      },
    ]);
    const crashed = await harness(fx, { clock });
    const claimed = await crashed.comps.capture!.scheduler.claim(10);
    const mine = claimed.find((c) => c.messageId === m3.id)!;
    expect(mine).toBeDefined();
    clock.advance(61_000);
    const second = await harness(fx, { clock });
    await drainCapture(second, fx, clock.now);
    const outcome = await crashed.comps.capture!.scheduler.process(mine);
    expect(['lease_lost', 'lost_race']).toContain(outcome);
    expect(await fx.prisma.emailArchive.count({ where: { messageId: m3.id } })).toBe(1);
    const record = await recordOf(m3);
    const objects = archiveRecordObjectsSchema.parse(record!.objects);
    // Only the committed capture's versions remain under the message prefix.
    const left = await fx.countVersions(
      fx.archiveBucket,
      objects.eml.key.split(objects.captureId)[0]!,
    );
    expect(left).toBe(2 + objects.scans.length);
    await crashed.close();
    await second.close();
  });

  it('refreshes the outcome while captured_open: a late risk revision becomes a new linked snapshot (A7)', async () => {
    const org = await fx.organization('refresh');
    const m = await fx.message(org.id);
    await h.comps.capture!.journal.runOnce();
    await drainCapture(h, fx, clock.now);
    const before = await recordOf(m);
    expect(archiveScanRoundsSchema.parse(before!.scanRounds)).toHaveLength(1);
    await fx.riskRevision(
      { receivedAt: m.receivedAt, messageId: m.id, organizationId: org.id },
      m.scanId!,
      1,
    );
    clock.advance(61 * 60_000); // past the +1 h check
    await drainCapture(h, fx, clock.now);
    const after = await recordOf(m);
    const links = archiveScanRoundsSchema.parse(after!.scanRounds);
    expect(links.map((l) => `${l.round}:${l.revision}`)).toEqual(['0:0', '0:1']);
    const objects = archiveRecordObjectsSchema.parse(after!.objects);
    expect(objects.scans).toHaveLength(2);
    expect(objects.eml).toEqual(archiveRecordObjectsSchema.parse(before!.objects).eml);
    expect(after!.outcomeRefreshedAt).not.toBeNull();
    expect(await intentOf(m)).toMatchObject({ status: 'captured_open' });
    clock.advance(24 * 3_600_000); // past +24 h: the intent closes
    await drainCapture(h, fx, clock.now);
    expect(await intentOf(m)).toMatchObject({ status: 'closed' });
    const queued = await fx.prisma.archiveIndexQueue.count({ where: { messageId: m.id } });
    expect(queued).toBeGreaterThanOrEqual(1);
    clock.offsetMs = 0;
  });

  it('an outcome refresh with nothing changed writes nothing: parties compared regardless of MySQL JSON key order', async () => {
    const org = await fx.organization('refresh-noop');
    const m = await fx.message(org.id);
    await h.comps.capture!.journal.runOnce();
    await drainCapture(h, fx, clock.now);
    const before = await recordOf(m);
    expect(before).not.toBeNull();
    // MySQL normalized the stored parties' keys: a plain JSON.stringify comparison would differ.
    const stored = JSON.stringify((before!.parties as { recipients: unknown[] }).recipients[0]);
    expect(stored.startsWith('{"seq":')).toBe(true);
    expect(stored.indexOf('"status"')).toBeLessThan(stored.indexOf('"address"'));
    await fx.prisma.archiveIndexQueue.deleteMany({ where: { messageId: m.id } });
    clock.advance(61 * 60_000); // past the +1 h check
    await drainCapture(h, fx, clock.now);
    const after = await recordOf(m);
    expect(after!.updatedAt).toEqual(before!.updatedAt);
    expect(after!.outcomeRefreshedAt).toEqual(before!.outcomeRefreshedAt);
    expect(await fx.prisma.archiveIndexQueue.count({ where: { messageId: m.id } })).toBe(0);
    // The intent moved on to its next check (the refresh ran) without touching the record.
    const intent = await intentOf(m);
    expect(intent!.nextCheckAt.getTime()).toBeGreaterThan(clock.now().getTime());
    clock.offsetMs = 0;
  });

  it('a source that joins a captured intent reaches the record at once: journal after policy (WP6 fix)', async () => {
    const org = await fx.organization('late-source');
    const m = await fx.message(org.id);
    const upsert = (journal: boolean, policy: boolean) =>
      upsertIntents(fx.prisma, [
        {
          organizationId: org.id,
          messageId: m.id,
          receivedAt: m.receivedAt,
          direction: 'inbound',
          journal,
          policy,
          policyRuleRef: policy ? 'p#1/archive-rule' : null,
          settingsGeneration: 1n,
          nextCheckAt: clock.now(),
        },
      ]);
    // The policy request arrives first (the consumer is faster than the journal sweep).
    await upsert(false, true);
    await drainCapture(h, fx, clock.now);
    expect(await recordOf(m)).toMatchObject({ capturedByPolicy: true, capturedByJournal: false });
    const captured = await intentOf(m);
    expect(captured).toMatchObject({ status: 'captured_open' });
    expect(captured!.nextCheckAt.getTime()).toBeGreaterThan(clock.now().getTime() + 30 * 60_000);
    // The journal sweep then ORs its source in: the intent is due again at once, not at +1 h.
    await upsert(true, false);
    const joined = await intentOf(m);
    expect(joined).toMatchObject({ sourceJournal: true, sourcePolicy: true });
    expect(joined!.nextCheckAt.getTime()).toBeLessThanOrEqual(clock.now().getTime());
    await drainCapture(h, fx, clock.now);
    expect(await recordOf(m)).toMatchObject({ capturedByPolicy: true, capturedByJournal: true });
    expect(await fx.prisma.emailArchive.count({ where: { messageId: m.id } })).toBe(1);
    // A source the intent already has changes nothing (no extra refresh).
    const settled = (await intentOf(m))!.nextCheckAt;
    await upsert(true, true);
    expect((await intentOf(m))!.nextCheckAt).toEqual(settled);
  });
  it('mail held in quarantine past the intent max age and then released is still journaled (review fix)', async () => {
    const DAY = 86_400_000;
    const org = await fx.organization('quarantine-long');
    const quarantined = (address: string) =>
      fx.message(org.id, {
        status: 'quarantined',
        statusReason: 'policy_quarantine',
        recipients: [{ address, direction: 'inbound', status: 'pending' }],
      });
    const released = await quarantined('released@corp-it.example');
    const forgotten = await quarantined('forgotten@corp-it.example');
    const intent = (m: SeededMessage) => ({
      organizationId: org.id,
      messageId: m.id,
      receivedAt: m.receivedAt,
      direction: 'inbound' as const,
      journal: true,
      policy: false,
      policyRuleRef: null,
      settingsGeneration: 1n,
      nextCheckAt: new Date(0),
    });
    await upsertIntents(fx.prisma, [intent(released), intent(forgotten)]);
    await drainCapture(h, fx, clock.now);
    // Without include.quarantined the intent waits, marked as a wait in quarantine.
    for (const m of [released, forgotten]) {
      expect(await intentOf(m)).toMatchObject({ status: 'pending', category: 'quarantined' });
    }
    const due = (m: SeededMessage) =>
      fx.prisma.archiveCaptureIntent.updateMany({
        where: { messageId: m.id, receivedAt: m.receivedAt },
        data: { nextCheckAt: new Date(0) },
      });
    // 26 days later (past ARCHIVE_INTENT_MAX_AGE_DAYS = 25): still waiting, not skipped.
    clock.advance(26 * DAY);
    await due(released);
    await drainCapture(h, fx, clock.now);
    expect(await intentOf(released)).toMatchObject({ status: 'pending', category: 'quarantined' });
    // Released and delivered: captured as delivered mail.
    await fx.prisma.emailMessage.updateMany({
      where: { id: released.id, receivedAt: released.receivedAt },
      data: {
        status: 'delivered',
        statusReason: 'delivery_complete',
        statusChangedAt: clock.now(),
      },
    });
    await fx.prisma.emailRecipient.updateMany({
      where: { messageId: released.id, receivedAt: released.receivedAt },
      data: { status: 'delivered', finalAction: 'deliver' },
    });
    await due(released);
    await drainCapture(h, fx, clock.now);
    expect(await recordOf(released)).toMatchObject({ category: 'delivered' });
    expect(await intentOf(released)).toMatchObject({ status: 'captured_open' });
    expect(
      await fx.prisma.emailArchive.count({
        where: { messageId: released.id, receivedAt: released.receivedAt },
      }),
    ).toBe(1);
    // Past QUARANTINE_WAIT_MAX_DAYS (100) a wait in quarantine ends skipped (max_age).
    clock.advance(75 * DAY);
    await due(forgotten);
    await drainCapture(h, fx, clock.now);
    expect(await intentOf(forgotten)).toMatchObject({ status: 'skipped', skipReason: 'max_age' });
    expect(await recordOf(forgotten)).toBeNull();
    clock.offsetMs = 0;
  });

  it('backlog gauge: only overdue or erroring intents count; waits in quarantine are not stuck before 100 days', async () => {
    clock.offsetMs = 0;
    const DAY = 86_400_000;
    const org = await fx.organization('backlog');
    const waiting = await fx.message(org.id, { status: 'quarantined', statusReason: 'x' });
    const erroring = await fx.message(org.id);
    const later = new Date(Date.now() + 3_600_000);
    await upsertIntents(
      fx.prisma,
      [waiting, erroring].map((m) => ({
        organizationId: org.id,
        messageId: m.id,
        receivedAt: m.receivedAt,
        direction: 'inbound' as const,
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: 1n,
        nextCheckAt: later,
      })),
    );
    const set = (m: SeededMessage, data: Record<string, unknown>) =>
      fx.prisma.archiveCaptureIntent.updateMany({
        where: { messageId: m.id, receivedAt: m.receivedAt },
        data,
      });
    try {
      await set(waiting, {
        category: 'quarantined',
        createdAt: new Date(Date.now() - 60 * DAY),
        nextCheckAt: later,
      });
      await set(erroring, {
        lastErrorCode: 'capture_error',
        createdAt: new Date(Date.now() - 40 * DAY),
        nextCheckAt: later,
      });
      const first = await h.comps.capture!.scheduler.maintain();
      // The 60-day wait in quarantine does not count; the 40-day erroring intent does.
      expect(first.oldestSeconds / 86_400).toBeGreaterThan(39.9);
      expect(first.oldestSeconds / 86_400).toBeLessThan(40.1);
      expect(first.stuck).toBeGreaterThanOrEqual(1);
      expect((await intentOf(erroring))!.nextCheckAt.getTime()).toBeLessThanOrEqual(Date.now());
      expect((await intentOf(waiting))!.nextCheckAt).toEqual(later);
      // Past 100 days the wait in quarantine is made due (the scheduler then skips it).
      await set(waiting, { createdAt: new Date(Date.now() - 101 * DAY) });
      await h.comps.capture!.scheduler.maintain();
      expect((await intentOf(waiting))!.nextCheckAt.getTime()).toBeLessThanOrEqual(Date.now());
    } finally {
      for (const m of [waiting, erroring]) {
        await set(m, { status: 'closed', closedAt: new Date(), nextCheckAt: new Date() });
      }
    }
  });
});
