/**
 * The probe cleanup of common.test.ts (step 3.3 L16) against the real writer, MinIO and the
 * postfix-outbound container: a message shaped like the probe's (relay-domain organization,
 * the run's Message-ID, a delivery with an outbound queue id, the EML and a part object in the
 * mail bucket; step 4.5: a dlp result and evidence row with its evidence object) is found by
 * its marker and removed: queue id handed to `postsuper -d` (an unknown id is ignored), objects
 * and rows deleted. A message with another Message-ID stays.
 */
import { createHash, randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import { deleteLifecycleFixtures } from './support/lifecycle';
import {
  cleanupProbeMessages,
  findProbeMessages,
  mailBucketClient,
  partPrefix,
  s3Commands,
} from './support/probe-cleanup';
import { insertDomain, type InsertedDomain } from './support/smtp';

let ctx: IntegrationApp;
let fx: Fixtures;
let org: FixtureOrganization;
let domain: InsertedDomain;

const sha = (text: string) => createHash('sha256').update(text).digest('hex');

async function insertProbeLike(internetMessageId: string, receivedAt: Date) {
  const identity = await ctx.prisma.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${sha(randomUUID())}`, receivedAt },
    select: { id: true },
  });
  const emlObjectKey = `org/${org.id}/eml/2026/11/04/${sha(randomUUID()).slice(0, 32)}.eml`;
  await ctx.prisma.emailMessage.create({
    data: {
      id: identity.id,
      receivedAt,
      organizationId: org.id,
      direction: 'inbound',
      status: 'delivery_retry',
      statusChangedAt: receivedAt,
      internetMessageId,
      envelopeFrom: 'no-reply@gateway.local',
      sizeBytes: 100,
      recipientCount: 1,
      emlObjectKey,
      emlSha256: sha('probe'),
    },
  });
  const recipient = await ctx.prisma.emailRecipient.create({
    data: {
      receivedAt,
      messageId: identity.id,
      organizationId: org.id,
      rcptSeq: 0,
      address: `probe@${domain.name}`,
    },
    select: { id: true },
  });
  await ctx.prisma.emailDelivery.create({
    data: {
      receivedAt,
      messageId: identity.id,
      recipientId: recipient.id,
      organizationId: org.id,
      status: 'deferred',
      // Not a queue file that exists: postsuper ignores it (exit status only).
      outboundQueueId: `Zz${randomUUID().replace(/-/g, '').slice(0, 12)}`,
    },
  });
  return { id: identity.id, receivedAt, organizationId: org.id, emlObjectKey };
}

/** The DLP rows of a scanned round of the message, as the email-worker writes them (step 4.5). */
async function insertDlpRows(message: { id: bigint; receivedAt: Date; organizationId: bigint }) {
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const scanId = message.id;
  await ctx.prisma.dlpScanResult.create({
    data: {
      ...base,
      scanId,
      lifecycleRound: 0,
      direction: 'inbound',
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      rulesVersion: 'dlp-map/1',
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      policyVersion: 'pol/1;h=0123456789ab',
      extractorVersion: 'dlp-extract/1',
      verdict: 'suspicious',
      action: 'alert',
      actionSource: 'default_policy',
      coverage: 'complete',
      coverageDetail: [],
      categories: [],
      findings: [],
      policy: { winner: null, matched: [], exceptionsApplied: [] },
      findingCount: 1,
      evidenceStatus: 'stored',
      durationMs: 1,
    },
  });
  const objectKey = `org/${message.organizationId}/dlp-evidence/2026/11/${scanId}-${randomUUID()}.bin`;
  await ctx.prisma.dlpEvidence.create({
    data: {
      ...base,
      scanId,
      objectKey,
      objectSha256: sha('evidence'),
      objectSizeBytes: 8,
      wrappedKey: 'v1.k1.a.b.c',
      keyId: 'k1',
      algorithm: 'dlp-evidence/1',
      matchCount: 1,
      expiresAt: new Date(Date.now() + 86_400_000),
    },
  });
  return objectKey;
}

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  org = await fx.createOrganization();
  domain = await insertDomain(ctx, org, { label: 'probe' });
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [org.id]));
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

describe('cleanupProbeMessages (L16)', () => {
  it('removes the run’s message: S3 objects, rows; other messages stay', async () => {
    const since = new Date(Date.now() - 1000);
    const marker = `<${randomUUID()}@gateway.local>`;
    const receivedAt = new Date();
    const probe = await insertProbeLike(marker, receivedAt);
    const other = await insertProbeLike(`<${randomUUID()}@gateway.local>`, receivedAt);

    const { s3, bucket } = mailBucketClient();
    const { PutObjectCommand, ListObjectsV2Command } = s3Commands();
    const partKey = `${partPrefix(probe)}0.text`;
    const evidenceKey = await insertDlpRows(probe);
    try {
      for (const key of [probe.emlObjectKey, partKey, evidenceKey, other.emlObjectKey]) {
        await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: 'probe' }));
      }
      expect(
        await findProbeMessages(ctx.prisma, {
          relayDomain: domain.name,
          since,
          messageIds: [marker],
        }),
      ).toHaveLength(1);

      const result = await cleanupProbeMessages(ctx.prisma, {
        relayDomain: domain.name,
        since,
        messageIds: [marker],
        waitMs: 2000,
      });
      expect(result).toMatchObject({ messages: 1, objects: 3 });

      const list = async (prefix: string) =>
        (await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }))).Contents ??
        [];
      expect(await list(partPrefix(probe))).toEqual([]);
      expect(await list(probe.emlObjectKey)).toEqual([]);
      expect(await list(evidenceKey)).toEqual([]);
      expect(await ctx.prisma.dlpEvidence.count({ where: { messageId: probe.id } })).toBe(0);
      expect(await ctx.prisma.dlpScanResult.count({ where: { messageId: probe.id } })).toBe(0);
      expect((await list(other.emlObjectKey)).map((o) => o.Key)).toEqual([other.emlObjectKey]);

      expect(await ctx.prisma.emailMessage.count({ where: { id: probe.id } })).toBe(0);
      expect(await ctx.prisma.emailDelivery.count({ where: { messageId: probe.id } })).toBe(0);
      expect(await ctx.prisma.emailRecipient.count({ where: { messageId: probe.id } })).toBe(0);
      expect(await ctx.prisma.messageIdentity.count({ where: { id: probe.id } })).toBe(0);
      expect(await ctx.prisma.emailMessage.count({ where: { id: other.id } })).toBe(1);
    } finally {
      const { DeleteObjectCommand } = s3Commands();
      await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: other.emlObjectKey }));
      s3.destroy();
    }
  });

  it('finds nothing without a sent Message-ID or outside the relay domain', async () => {
    expect(
      await findProbeMessages(ctx.prisma, {
        relayDomain: domain.name,
        since: new Date(0),
        messageIds: [],
      }),
    ).toEqual([]);
    expect(
      await findProbeMessages(ctx.prisma, {
        relayDomain: 'not-a-relay-domain.invalid',
        since: new Date(0),
        messageIds: ['<x@y>'],
      }),
    ).toEqual([]);
  });
});
