/**
 * Step API-2 WP5 (docs/plan/steps/36-api-mode-remediation.md R11, ADR-0102) on the real MySQL
 * writer and MinIO: the policy-engine quarantine role never treats a mailbox-located entry
 * (`quarantine_messages.location = mailbox`, an API-mode copy's registry message) as a gateway
 * message. The sweeper neither expires, purges nor adopts on its behalf; the release executor
 * records a release naming one in its ledger only; approval-request expiry returns the entry to
 * `held` without a lifecycle edge; the digest scheduler counts mailbox entries. Synthetic
 * fixtures in `it-apirem-*` organizations only, removed afterwards.
 */
import { randomUUID } from 'node:crypto';
import { PutObjectCommand } from '@aws-sdk/client-s3';
import { uuidv7 } from '@email-gateway/common';
import {
  type EventEnvelope,
  EventTypes,
  type QuarantineReleaseRequestedV1,
  quarantineNotificationRequestedV1,
} from '@email-gateway/event-contracts';
import { afterAll, describe, expect, it } from 'vitest';
import { buildPipeline, buildQuarantine, DEFAULT_EML, Fixtures } from './support/fixtures';

const fx = new Fixtures('it-apirem');
const HOUR_MS = 3_600_000;

afterAll(async () => {
  await fx.cleanup();
});

interface CopyFixture {
  messageId: bigint;
  receivedAt: Date;
  organizationId: bigint;
  emlObjectKey: string;
  recipientId: bigint;
}

/**
 * An API-mode copy as the mailbox-worker leaves it (API-1): a `mailbox_api` registry message in
 * `journaled` with one `journaled` recipient and its EML in MinIO.
 */
async function copyMessage(organizationId: bigint, address: string): Promise<CopyFixture> {
  const receivedAt = new Date(Math.floor((Date.now() - 3 * HOUR_MS) / 1000) * 1000);
  const identity = await fx.prisma.messageIdentity.create({
    data: { organizationId, ingestKey: `it-apirem-${randomUUID()}`, receivedAt },
    select: { id: true },
  });
  const emlObjectKey = `org/${organizationId.toString()}/eml/it-apirem/${randomUUID()}.eml`;
  await fx.s3.client.send(
    new PutObjectCommand({
      Bucket: fx.s3.mailBucket,
      Key: emlObjectKey,
      Body: Buffer.from(DEFAULT_EML, 'latin1'),
    }),
  );
  await fx.prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId,
      direction: 'inbound',
      status: 'journaled',
      version: 1,
      statusReason: 'mailbox_api_journaled',
      statusChangedAt: receivedAt,
      ingestSource: 'mailbox_api',
      envelopeFrom: 'mallory@phish.example',
      headerFrom: 'mallory@phish.example',
      sizeBytes: Buffer.byteLength(DEFAULT_EML, 'latin1'),
      recipientCount: 1,
      emlObjectKey,
      emlSha256: '0'.repeat(64),
      clientIp: '198.51.100.9',
      clientName: 'mailbox-api',
    },
  });
  await fx.prisma.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId,
      rcptSeq: 0,
      address,
      direction: 'inbound',
      status: 'journaled',
    },
  });
  const recipient = await fx.prisma.emailRecipient.findFirstOrThrow({
    where: { messageId: identity.id, receivedAt },
    select: { id: true },
  });
  return {
    messageId: identity.id,
    receivedAt,
    organizationId,
    emlObjectKey,
    recipientId: recipient.id,
  };
}

/** A mailbox-located entry as R9.1 writes it (the api_* links are not needed by these guards). */
function mailboxEntry(
  c: CopyFixture,
  address: string,
  over: {
    status?: 'held' | 'pending_approval' | 'releasing';
    expiresAt?: Date;
    quarantinedAt?: Date;
    container?: 'quarantine_folder' | 'junk' | 'deleted_items';
    round?: number;
    rcptSeq?: number;
    recipientId?: bigint;
  } = {},
) {
  const now = new Date();
  return fx.prisma.quarantineMessage.create({
    data: {
      organizationId: c.organizationId,
      messageId: c.messageId,
      messageReceivedAt: c.receivedAt,
      lifecycleRound: over.round ?? 0,
      recipientId: over.recipientId ?? c.recipientId,
      rcptSeq: over.rcptSeq ?? 0,
      recipientAddress: address,
      direction: 'inbound',
      kind: 'quarantine',
      origin: 'api_remediation',
      reason: 'phishing',
      status: over.status ?? 'held',
      envelopeFrom: 'mallory@phish.example',
      headerFrom: 'mallory@phish.example',
      hasHardBlock: true,
      hardBlocks: ['hb.known_phishing'],
      primaryEngine: 'rspamd',
      explanationText: 'Removed from the mailbox by the API-mode remediation policy (rule it)',
      emlObjectKey: c.emlObjectKey,
      quarantinedAt: over.quarantinedAt ?? new Date(now.getTime() - HOUR_MS),
      expiresAt: over.expiresAt ?? new Date(now.getTime() - 60_000),
      stateChangedAt: now,
      location: 'mailbox',
      mailboxContainer: over.container ?? 'quarantine_folder',
    },
  });
}

const history = (c: CopyFixture) =>
  fx.prisma.emailMessageStatusHistory.count({
    where: { messageId: c.messageId, receivedAt: c.receivedAt },
  });
const copyState = async (c: CopyFixture) => {
  const message = await fx.prisma.emailMessage.findUniqueOrThrow({
    where: { id_receivedAt: { id: c.messageId, receivedAt: c.receivedAt } },
    select: { status: true, version: true },
  });
  const recipients = await fx.prisma.emailRecipient.findMany({
    where: { messageId: c.messageId, receivedAt: c.receivedAt },
    select: { status: true },
  });
  return { ...message, recipients: recipients.map((r) => r.status) };
};

describe('policy-engine guards for mailbox-located entries (API-2 R11)', () => {
  it('the sweeper never expires or purges a due mailbox entry (no lifecycle edge, no recipient change, EML kept)', async () => {
    const t = await fx.organization('sweep');
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('sweep-x'),
      organizationIds: [t],
    });
    const c = await copyMessage(t, 'bob@corp.example');
    const entry = await mailboxEntry(c, 'bob@corp.example');
    const before = await copyState(c);
    const historyBefore = await history(c);
    // A purge row for the copy (never scheduled in practice): refused before any deletion.
    await fx.prisma.quarantineObjectPurge.create({
      data: {
        organizationId: t,
        messageId: c.messageId,
        messageReceivedAt: c.receivedAt,
        status: 'pending',
        purgeAfter: new Date(Date.now() - 60_000),
      },
    });

    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({
      expired: 0,
      messagesExpired: 0,
      purged: 0,
      retained: 0,
      purgeFailures: 1,
      adopted: 0,
    });
    expect(report.failedSteps).toEqual([]);
    const after = await fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id: entry.id } });
    expect(after).toMatchObject({
      status: 'held',
      rowVersion: entry.rowVersion,
      objectPurgedAt: null,
      location: 'mailbox',
    });
    expect(await copyState(c)).toEqual(before);
    expect(await history(c)).toBe(historyBefore);
    expect(await q.objects.exists(c.emlObjectKey)).toBe(true);
    expect(
      await fx.prisma.quarantineObjectPurge.findFirstOrThrow({
        where: { messageId: c.messageId },
      }),
    ).toMatchObject({ status: 'failed', lastErrorCode: 'mailbox_location', purgedAt: null });
    expect(
      await fx.prisma.quarantineAction.count({ where: { quarantineMessageId: entry.id } }),
    ).toBe(0);
    expect(
      await fx.prisma.messageOutbox.count({
        where: { organizationId: t, aggregateId: c.messageId.toString() },
      }),
    ).toBe(0);
    await fx.prisma.quarantineObjectPurge.deleteMany({ where: { messageId: c.messageId } });
  });

  it('adoption ignores mailbox rows: a held gateway message whose only row is mailbox-located is still adopted', async () => {
    const t = await fx.organization('adopt');
    await fx.publish(t, 'p-adopt', {
      dslVersion: 'policy-dsl/1',
      direction: 'inbound',
      priority: 100,
      rules: [
        {
          id: 'h',
          priority: 10,
          when: { field: 'direction', op: 'equals', value: 'inbound' },
          actions: [{ type: 'QUARANTINE' }],
        },
      ],
    });
    const p = buildPipeline(fx.prisma, fx.s3, { consumer: fx.consumer('adopt') });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('adopt-x'),
      organizationIds: [t],
    });
    const m = await fx.message(t);
    expect(await p.consumer.handler(fx.scanned(m))).toBe('handled');
    // As step 5.2 left it (no gateway entry) plus a mailbox-located row on the same message and
    // round (a defensive shape: copies are separate registry messages).
    const gatewayIds = (
      await fx.prisma.quarantineMessage.findMany({ where: { messageId: m.messageId } })
    ).map((e) => e.id);
    await fx.prisma.quarantineAction.deleteMany({
      where: { quarantineMessageId: { in: gatewayIds } },
    });
    await fx.prisma.quarantineMessage.deleteMany({ where: { id: { in: gatewayIds } } });
    await fx.prisma.emailRecipient.updateMany({
      where: { messageId: m.messageId },
      data: { status: 'pending', finalAction: null },
    });
    const stray = await mailboxEntry(
      { ...m, recipientId: m.recipients[0]!.id },
      'bob@corp.example',
      { rcptSeq: 9, expiresAt: new Date(Date.now() + 86_400_000) },
    );

    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({ adopted: 1, expired: 0, failedSteps: [] });
    const entries = await fx.prisma.quarantineMessage.findMany({
      where: { messageId: m.messageId },
      orderBy: { id: 'asc' },
    });
    expect(entries.map((e) => [e.location, e.origin, e.status])).toEqual([
      ['mailbox', 'api_remediation', 'held'],
      ['gateway', 'adopted', 'held'],
    ]);
    expect(entries[0]!.rowVersion).toBe(stray.rowVersion);
    expect((await q.sweeper.sweepOnce()).adopted).toBe(0);
  });

  it('the release executor records a release naming a mailbox entry in its ledger only (stale)', async () => {
    const t = await fx.organization('release');
    const operator = await fx.user(t, 'operator@corp.example');
    const consumer = fx.consumer('release-x');
    const q = buildQuarantine(fx.prisma, fx.s3, { consumer, organizationIds: [t] });
    const c = await copyMessage(t, 'bob@corp.example');
    const entry = await mailboxEntry(c, 'bob@corp.example', {
      status: 'releasing',
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    const action = await fx.prisma.quarantineAction.create({
      data: {
        organizationId: t,
        quarantineMessageId: entry.id,
        action: 'release_queued',
        actorType: 'user',
        actorUserId: operator.id,
        actorId: operator.publicId,
        reason: 'integration test release',
      },
    });
    const releaseId = randomUUID();
    const log = await fx.prisma.quarantineReleaseLog.create({
      data: {
        organizationId: t,
        quarantineMessageId: entry.id,
        actionId: action.id,
        releasePublicId: releaseId,
        mode: 'operator',
        requestedByType: 'user',
        requestedById: operator.publicId,
        releasedTo: 'bob@corp.example',
        status: 'pending',
      },
    });
    const before = await copyState(c);
    const historyBefore = await history(c);
    const event: EventEnvelope<QuarantineReleaseRequestedV1> = {
      eventId: uuidv7(),
      eventType: EventTypes.QuarantineReleaseRequested,
      occurredAt: new Date().toISOString(),
      correlationId: `it-apirem-${releaseId}`,
      organizationId: t.toString(),
      payload: {
        releaseId,
        messageId: c.messageId.toString(),
        receivedAt: c.receivedAt.toISOString(),
        entryIds: [entry.publicId],
        mode: 'operator',
        approvalRequestId: null,
        requestedBy: { type: 'user', id: operator.publicId },
        requestedAt: new Date().toISOString(),
      },
    };

    expect(await q.consumer.handler(event)).toBe('handled');
    expect(
      await fx.prisma.messageIdempotency.count({ where: { consumer, eventId: event.eventId } }),
    ).toBe(1);
    // Untouched: the entry, its release log (the restore flow owns it), the copy and recipients.
    expect(
      await fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id: entry.id } }),
    ).toMatchObject({ status: 'releasing', rowVersion: entry.rowVersion, releasedAt: null });
    expect(
      await fx.prisma.quarantineReleaseLog.findUniqueOrThrow({ where: { id: log.id } }),
    ).toMatchObject({ status: 'pending', completedAt: null });
    expect(await copyState(c)).toEqual(before);
    expect(await history(c)).toBe(historyBefore);
    expect(await fx.prisma.messageOutbox.count({ where: { organizationId: t } })).toBe(0);
    expect(await q.registry.metrics()).toMatch(
      /quarantine_releases_total\{result="stale",mode="operator",service="policy-engine-it-q"\} 1/,
    );
    // A duplicate delivery is absorbed by the ledger.
    expect(await q.consumer.handler(event)).toBe('duplicate');
  });

  it('approval-request expiry of a mailbox entry returns it to held without a lifecycle edge', async () => {
    const t = await fx.organization('approval');
    const requester = await fx.user(t, 'bob@corp.example');
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('approval-x'),
      organizationIds: [t],
    });
    const c = await copyMessage(t, 'bob@corp.example');
    const entry = await mailboxEntry(c, 'bob@corp.example', {
      status: 'pending_approval',
      expiresAt: new Date(Date.now() + 86_400_000),
    });
    const request = await fx.prisma.quarantineApprovalRequest.create({
      data: {
        organizationId: t,
        quarantineMessageId: entry.id,
        kind: 'release_approval',
        status: 'pending',
        approvalReasons: ['hard_block'],
        requestedByType: 'user',
        requestedByUserId: requester.id,
        expiresAt: new Date(Date.now() - 60_000),
      },
      select: { id: true, publicId: true },
    });
    const pending = await fx.prisma.quarantineMessage.update({
      where: { id: entry.id },
      data: { approvalRequestId: request.id, rowVersion: { increment: 1 } },
    });
    const before = await copyState(c);
    const historyBefore = await history(c);

    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({
      approvalsExpired: 1,
      expired: 0,
      messagesExpired: 0,
      purged: 0,
      failedSteps: [],
    });
    expect(
      await fx.prisma.quarantineApprovalRequest.findUniqueOrThrow({ where: { id: request.id } }),
    ).toMatchObject({ status: 'expired' });
    expect(
      await fx.prisma.quarantineMessage.findUniqueOrThrow({ where: { id: entry.id } }),
    ).toMatchObject({
      status: 'held',
      rowVersion: pending.rowVersion + 1,
      location: 'mailbox',
      terminalReason: null,
    });
    expect(
      (await fx.prisma.quarantineAction.findMany({ where: { quarantineMessageId: entry.id } })).map(
        (a) => a.action,
      ),
    ).toEqual(['approval_expired']);
    expect(await copyState(c)).toEqual(before);
    expect(await history(c)).toBe(historyBefore);
    expect(await fx.prisma.quarantineObjectPurge.count({ where: { messageId: c.messageId } })).toBe(
      0,
    );
    const notices = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
    });
    expect(notices.map((n) => quarantineNotificationRequestedV1.parse(n.payload))).toEqual([
      expect.objectContaining({
        kind: 'approval_decided',
        decision: 'expired',
        refs: { approvalRequestIds: [request.publicId], entryId: entry.publicId },
      }),
    ]);
  });

  it('the digest scheduler includes mailbox entries (location-agnostic)', async () => {
    const t = await fx.organization('digest');
    await fx.prisma.organizationSetting.create({
      data: { organizationId: t, digestSchedule: '* * * * *', timezone: 'UTC' },
    });
    const bob = await fx.prisma.user.create({
      data: {
        organizationId: t,
        email: 'bob@corp.example',
        displayName: 'Bob',
        status: 'active',
        emailVerifiedAt: new Date(),
      },
    });
    const q = buildQuarantine(fx.prisma, fx.s3, {
      consumer: fx.consumer('digest-x'),
      organizationIds: [t],
    });
    const c = await copyMessage(t, 'bob@corp.example');
    // Held two hours ago, inside a due window; not expired.
    await mailboxEntry(c, 'bob@corp.example', {
      container: 'junk',
      quarantinedAt: new Date(Date.now() - 2 * HOUR_MS),
      expiresAt: new Date(Date.now() + 86_400_000),
    });

    const report = await q.sweeper.sweepOnce();
    expect(report).toMatchObject({ digests: 1, failedSteps: [] });
    const digests = await fx.prisma.quarantineDigest.findMany({ where: { organizationId: t } });
    expect(digests.map((d) => [d.userId, d.entryCount])).toEqual([[bob.id, 1]]);
    const notices = await fx.prisma.messageOutbox.findMany({
      where: { organizationId: t, eventType: EventTypes.QuarantineNotificationRequested },
    });
    expect(notices.map((n) => quarantineNotificationRequestedV1.parse(n.payload))).toEqual([
      expect.objectContaining({
        kind: 'user_digest',
        refs: { userId: bob.publicId, digestId: digests[0]!.publicId },
      }),
    ]);
  });
});
