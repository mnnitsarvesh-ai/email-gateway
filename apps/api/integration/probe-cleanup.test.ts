/**
 * The probe cleanup of common.test.ts (step 3.3 L16) against the real writer, MinIO and the
 * postfix-outbound container: a message shaped like the probe's (relay-domain organization,
 * the run's Message-ID, a delivery with an outbound queue id, the EML and a part object in the
 * mail bucket) is found by its marker and removed: queue id handed to `postsuper -d` (an
 * unknown id is ignored), objects and rows deleted. A message with another Message-ID stays.
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
    try {
      for (const key of [probe.emlObjectKey, partKey, other.emlObjectKey]) {
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
      expect(result).toMatchObject({ messages: 1, objects: 2 });

      const list = async (prefix: string) =>
        (await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix }))).Contents ??
        [];
      expect(await list(partPrefix(probe))).toEqual([]);
      expect(await list(probe.emlObjectKey)).toEqual([]);
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
