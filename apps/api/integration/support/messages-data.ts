/**
 * SQL fixtures of the step 6.1 WP2 integration suites (messages-list, messages-data,
 * recipient-suppressions, tenant-isolation-messages-data, messages-explain): a message graph
 * (registry row, message, recipients, deliveries, one scan round, attachments with results,
 * URLs with results, a rewrite and clicks) inserted on the writer with the partition rules of
 * integration/support/lifecycle.ts (every child row copies the message's `received_at`; clicks
 * keep it in `message_received_at`), the bulk loader of the EXPLAIN suite, and the cleanup.
 * Fixtures set preconditions directly; no production code path writes these rows this way.
 */
import { createHash, randomUUID } from 'node:crypto';
import type {
  MessageAction,
  MessageDirection,
  MessageVerdict,
  UrlClickDecision,
} from '@email-gateway/database';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';
import { uniqueIp } from './http';

const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

export interface SeedAttachment {
  sha256: string;
  filename?: string;
  verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
}

export interface SeedUrl {
  url: string;
  host: string;
  verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
}

export interface SeedClick {
  urlSeq: number;
  decision: UrlClickDecision;
  clickedAt: Date;
  verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
}

export interface SeedMessageOptions {
  receivedAt?: Date;
  direction?: MessageDirection;
  verdict?: MessageVerdict | null;
  action?: MessageAction | null;
  riskScore?: number | null;
  envelopeFrom?: string;
  headerFrom?: string | null;
  subject?: string;
  domainId?: bigint | null;
  internetMessageId?: string | null;
  recipients?: string[];
  attachments?: SeedAttachment[];
  urls?: SeedUrl[];
  clicks?: SeedClick[];
}

export interface SeededMessage {
  id: bigint;
  publicId: string;
  receivedAt: Date;
  organizationId: bigint;
  recipientIds: bigint[];
  scanId: bigint;
  clickPublicIds: string[];
}

/** One message of `org` with its graph (see the file comment). */
export async function seedMessage(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  options: SeedMessageOptions = {},
): Promise<SeededMessage> {
  const p = ctx.prisma;
  const receivedAt = options.receivedAt ?? new Date(Date.now() - 60_000);
  const direction = options.direction ?? 'inbound';
  const recipients = options.recipients ?? ['alice@acme.example'];
  const attachments = options.attachments ?? [];
  const identity = await p.messageIdentity.create({
    data: { organizationId: org.id, ingestKey: `v2:${sha(randomUUID())}`, receivedAt },
    select: { id: true, publicId: true },
  });
  const id = identity.id;
  await p.emailMessage.create({
    data: {
      id,
      receivedAt,
      organizationId: org.id,
      domainId: options.domainId ?? null,
      direction,
      status: 'delivered',
      statusChangedAt: receivedAt,
      version: 3,
      envelopeFrom: options.envelopeFrom ?? `sender@${org.slug}.example`,
      headerFrom:
        options.headerFrom === undefined ? 'Sender <sender@vendor.example>' : options.headerFrom,
      subject: options.subject ?? 'Integration message',
      internetMessageId:
        options.internetMessageId === undefined
          ? `<${randomUUID()}@vendor.example>`
          : options.internetMessageId,
      sizeBytes: 2048,
      recipientCount: recipients.length,
      attachmentCount: attachments.length,
      emlObjectKey: `org/${org.id}/eml/fixture/${randomUUID()}.eml`,
      emlSha256: sha('fixture'),
      clientIp: '198.51.100.7',
      clientHelo: 'mx.vendor.example',
      mtaQueueId: 'FIXTUREQ1',
      finalVerdict: options.verdict === undefined ? 'clean' : options.verdict,
      finalAction: options.action === undefined ? 'deliver' : options.action,
      riskScore: options.riskScore === undefined ? 50 : options.riskScore,
    },
  });
  await p.emailRecipient.createMany({
    data: recipients.map((address, rcptSeq) => ({
      receivedAt,
      messageId: id,
      organizationId: org.id,
      rcptSeq,
      address,
      status: 'delivered' as const,
      finalAction: 'deliver' as const,
      direction,
    })),
  });
  const recipientIds = (
    await p.emailRecipient.findMany({
      where: { messageId: id, receivedAt },
      select: { id: true },
      orderBy: { rcptSeq: 'asc' },
    })
  ).map((r) => r.id);
  if (recipientIds[0] !== undefined) {
    await p.emailDelivery.createMany({
      data: [0, 1].map((deliverySeq) => ({
        receivedAt,
        messageId: id,
        recipientId: recipientIds[0]!,
        organizationId: org.id,
        deliverySeq,
        status: deliverySeq === 0 ? ('deferred' as const) : ('delivered' as const),
        finalSmtpCode: deliverySeq === 0 ? 451 : 250,
        deliveredAt: deliverySeq === 0 ? null : receivedAt,
        statusChangedAt: receivedAt,
      })),
    });
  }
  const scan = await p.emailScan.create({
    data: {
      receivedAt,
      messageId: id,
      organizationId: org.id,
      status: 'completed',
      lifecycleRound: 0,
      completedAt: receivedAt,
    },
    select: { id: true },
  });
  for (const [index, attachment] of attachments.entries()) {
    const partIndex = index + 1;
    await p.emailAttachment.create({
      data: {
        receivedAt,
        messageId: id,
        organizationId: org.id,
        partIndex,
        depth: 1,
        disposition: 'attachment',
        filename: attachment.filename ?? `file-${partIndex}.pdf`,
        originalFilename: `ORIGINAL-${partIndex}.pdf`,
        declaredContentType: 'application/pdf',
        detectedContentType: 'application/pdf',
        sizeBytes: 1000 + partIndex,
        sha256: attachment.sha256,
        objectKey: `org/${org.id}/part/fixture/${id}/${partIndex}.att`,
      },
    });
    const row = await p.emailAttachment.findFirstOrThrow({
      where: { messageId: id, partIndex, receivedAt },
      select: { id: true },
    });
    const verdict = attachment.verdict ?? 'clean';
    await p.attachmentScanResult.create({
      data: {
        receivedAt,
        messageId: id,
        organizationId: org.id,
        scanId: scan.id,
        attachmentId: row.id,
        partIndex,
        sha256: attachment.sha256,
        sizeBytes: 1000 + partIndex,
        detectedType: 'pdf',
        typeFamily: 'document',
        typeMismatch: false,
        verdict,
        reasonCodes: verdict === 'clean' ? ['clean.no_findings'] : ['malware.clamav'],
        clamavEngineVersion: '1.4.1',
        clamavDbVersion: 27450,
        cacheResult: 'miss',
        durationMs: 12,
      },
    });
  }
  for (const [urlSeq, url] of (options.urls ?? []).entries()) {
    const urlSha256 = sha(url.url);
    await p.messageUrl.create({
      data: {
        receivedAt,
        messageId: id,
        organizationId: org.id,
        urlSeq,
        url: url.url,
        urlSha256,
        scheme: 'https',
        host: url.host,
        registrableDomain: url.host,
        hostKind: 'domain',
        sources: { html_href: 1 },
        occurrences: 1,
        firstLifecycleRound: 0,
        extractorVersion: 'url-extract/1',
      },
    });
    const verdict = url.verdict ?? 'clean';
    await p.urlScanResult.create({
      data: {
        receivedAt,
        messageId: id,
        organizationId: org.id,
        scanId: scan.id,
        urlSeq,
        urlSha256,
        verdict,
        reasonCodes: verdict === 'clean' ? ['clean.no_findings'] : ['url.feed_malicious'],
        reputation: [],
        fetchStatus: 'not_attempted',
        rewritten: true,
        dynamicRequested: false,
        fetchCache: 'none',
        durationMs: 3,
      },
    });
  }
  if ((options.urls ?? []).length > 0) {
    await p.urlRewrite.create({
      data: {
        receivedAt,
        messageId: id,
        organizationId: org.id,
        scanId: scan.id,
        lifecycleRound: 0,
        status: 'rewritten',
        linksRewritten: options.urls!.length,
        partsRewritten: 1,
        tokenKid: 1,
        expiresAt: new Date(receivedAt.getTime() + 30 * 86_400_000),
        settingsVersion: 'fixture',
      },
    });
  }
  const clickPublicIds: string[] = [];
  for (const click of options.clicks ?? []) {
    const publicId = randomUUID();
    clickPublicIds.push(publicId);
    await p.urlClickEvent.create({
      data: {
        clickedAt: click.clickedAt,
        publicId,
        organizationId: org.id,
        messageId: id,
        messageReceivedAt: receivedAt,
        urlSeq: click.urlSeq,
        decision: click.decision,
        verdict: click.verdict ?? 'malicious',
        reasonCodes: ['url.feed_malicious'],
        tokenKid: 1,
        clientNetwork: '203.0.113.0/24',
        durationMs: 5,
      },
    });
  }
  return {
    id,
    publicId: identity.publicId,
    receivedAt,
    organizationId: org.id,
    recipientIds,
    scanId: scan.id,
    clickPublicIds,
  };
}

/**
 * Bulk messages for the EXPLAIN suite: `count` registry + message rows (plus one recipient each)
 * spread evenly over `[from, to)`, in multi-row inserts of `batch` rows. Verdicts cycle through
 * `verdicts`; every `recipientEvery`-th message goes to `hotAddress`.
 */
export async function bulkMessages(
  ctx: IntegrationApp,
  org: FixtureOrganization,
  options: {
    count: number;
    from: Date;
    to: Date;
    batch?: number;
    verdicts: MessageVerdict[];
    hotAddress: string;
    recipientEvery: number;
  },
): Promise<void> {
  const p = ctx.prisma;
  const batch = options.batch ?? 2_000;
  const span = options.to.getTime() - options.from.getTime();
  const tag = randomUUID().slice(0, 8);
  for (let start = 0; start < options.count; start += batch) {
    const n = Math.min(batch, options.count - start);
    const rows = Array.from({ length: n }, (_, i) => {
      const k = start + i;
      return {
        k,
        receivedAt: new Date(options.from.getTime() + Math.floor((span * k) / options.count)),
        ingestKey: `v2:bulk-${tag}-${k}`,
      };
    });
    await p.messageIdentity.createMany({
      data: rows.map((r) => ({
        organizationId: org.id,
        ingestKey: r.ingestKey,
        receivedAt: r.receivedAt,
      })),
    });
    const ids = await p.messageIdentity.findMany({
      where: { organizationId: org.id, ingestKey: { in: rows.map((r) => r.ingestKey) } },
      select: { id: true, ingestKey: true },
    });
    const idOf = new Map(ids.map((r) => [r.ingestKey, r.id]));
    await p.emailMessage.createMany({
      data: rows.map((r) => ({
        id: idOf.get(r.ingestKey)!,
        receivedAt: r.receivedAt,
        organizationId: org.id,
        direction: r.k % 7 === 0 ? ('outbound' as const) : ('inbound' as const),
        status: 'delivered' as const,
        statusChangedAt: r.receivedAt,
        envelopeFrom: `bulk${r.k % 97}@sender.example`,
        sizeBytes: 1000 + (r.k % 1000),
        recipientCount: 1,
        attachmentCount: r.k % 11 === 0 ? 1 : 0,
        emlObjectKey: `org/${org.id}/eml/bulk/${tag}/${r.k}.eml`,
        emlSha256: sha('bulk'),
        finalVerdict: options.verdicts[r.k % options.verdicts.length]!,
        finalAction: 'deliver' as const,
        riskScore: r.k % 1000,
      })),
    });
    await p.emailRecipient.createMany({
      data: rows.map((r) => ({
        receivedAt: r.receivedAt,
        messageId: idOf.get(r.ingestKey)!,
        organizationId: org.id,
        rcptSeq: 0,
        address:
          r.k % options.recipientEvery === 0 ? options.hotAddress : `user${r.k % 500}@acme.example`,
        status: 'delivered' as const,
      })),
    });
  }
}

/** Deletes every WP2 fixture row of the organizations (partitioned tables have no FKs). */
export async function deleteMessagesData(
  ctx: IntegrationApp,
  organizationIds: readonly bigint[],
): Promise<void> {
  const where = { organizationId: { in: [...organizationIds] } };
  const p = ctx.prisma;
  await p.urlClickEvent.deleteMany({ where });
  await p.urlRewrite.deleteMany({ where });
  await p.urlScanResult.deleteMany({ where });
  await p.messageUrl.deleteMany({ where });
  await p.attachmentScanResult.deleteMany({ where });
  await p.emailAttachment.deleteMany({ where });
  await p.emailScan.deleteMany({ where });
  await p.emailDelivery.deleteMany({ where });
  await p.emailRecipient.deleteMany({ where });
  await p.emailMessage.deleteMany({ where });
  await p.messageIdentity.deleteMany({ where });
  await p.deliverySuppression.deleteMany({ where });
  await p.apiIdempotencyKey.deleteMany({ where });
}

/** A GET from its own client IP (per-IP limits never interfere). */
export function getAs(ctx: IntegrationApp, headers: Record<string, string>, path: string) {
  return ctx.http.get(`/api/v1${path}`).set(headers).set('X-Forwarded-For', uniqueIp());
}

export const POLL = { timeout: 15_000, interval: 200 };

/** `data.length` of a list response (for `expect.poll`), or undefined. */
export const dataLength = (res: { body: unknown }): number | undefined =>
  (res.body as { data?: unknown[] }).data?.length;
