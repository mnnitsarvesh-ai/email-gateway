/**
 * Helpers of the step 6.2 API integration suites (webhooks, webhook deliveries, notifications,
 * tenant isolation): seeding of delivery history (stored events, deliveries, attempts) on the
 * writer as the webhook-worker would write it, HTTP shortcuts with a fresh client IP, and the
 * secret cipher of the configuration (the api encrypts; tests decrypt to prove the AAD).
 */
import { randomUUID } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import type { AuditLog, WebhookDeliveryStatus, WebhookSubscription } from '@email-gateway/database';
import { buildEnvelope, WebhookSecretCipher } from '@email-gateway/webhooks';
import type { IntegrationApp } from './app';
import { uniqueIp } from './http';

export const WEBHOOKS = '/api/v1/webhooks';

/**
 * A unique endpoint per call under the reserved `.test` TLD (RFC 2606): never resolved by the
 * api, and a webhook-worker running against the same database could never reach the Internet
 * with it (NXDOMAIN). The query string carries a receiver token, which audit rows must not.
 */
export const endpoint = (label = 'hook'): string =>
  `https://${label}-${randomUUID().slice(0, 8)}.webhooks-it.test/in?token=t-${randomUUID().slice(0, 6)}`;

export const createBody = (patch: Record<string, unknown> = {}) => ({
  name: 'integration hook',
  url: endpoint(),
  eventTypes: ['email.received', 'domain.dns.failed'],
  ...patch,
});

export function http(ctx: IntegrationApp, headers: Record<string, string>) {
  const ip = () => ({ 'X-Forwarded-For': uniqueIp() });
  return {
    get: (path: string) => ctx.http.get(path).set(headers).set(ip()),
    post: (path: string, body: unknown = {}, key?: string) => {
      const req = ctx.http.post(path).set(headers).set(ip());
      if (key) req.set('Idempotency-Key', key);
      return req.send(body as object);
    },
    patch: (path: string, body: unknown) =>
      ctx.http
        .patch(path)
        .set(headers)
        .set(ip())
        .send(body as object),
    put: (path: string, body: unknown) =>
      ctx.http
        .put(path)
        .set(headers)
        .set(ip())
        .send(body as object),
    delete: (path: string, key?: string) => {
      const req = ctx.http.delete(path).set(headers).set(ip());
      if (key) req.set('Idempotency-Key', key);
      return req;
    },
  };
}

export const cipherOf = (ctx: IntegrationApp): WebhookSecretCipher =>
  WebhookSecretCipher.fromConfig(ctx.config);

export interface SeededDelivery {
  id: bigint;
  publicId: string;
  eventId: string;
  occurredAt: Date;
}

/**
 * One stored event (a valid `webhook.ping` envelope) and its original delivery (seq 0) of a
 * subscription, as the webhook-worker writes them; `attempts` adds attempt rows.
 */
export async function seedDelivery(
  ctx: IntegrationApp,
  sub: { id: bigint; organizationId: bigint; publicId: string },
  options: {
    occurredAt: Date;
    organizationPublicId: string;
    status?: WebhookDeliveryStatus;
    eventType?: string;
    attempts?: number;
    withoutEvent?: boolean;
  },
): Promise<SeededDelivery> {
  const built = buildEnvelope({
    type: 'webhook.ping',
    occurredAt: options.occurredAt,
    organizationPublicId: options.organizationPublicId,
    sourceEventId: randomUUID(),
    data: { subscriptionId: sub.publicId, requestedAt: options.occurredAt.toISOString() },
  });
  const eventType = options.eventType ?? 'webhook.ping';
  if (!options.withoutEvent) {
    await ctx.prisma.webhookEvent.create({
      data: {
        organizationId: sub.organizationId,
        occurredAt: options.occurredAt,
        eventId: built.envelope.id,
        eventType,
        sourceEventId: randomUUID(),
        sourceEventType: 'integration.seed',
        severity: 'info',
        payloadJson: built.json,
        payloadSha256: built.sha256,
      },
    });
  }
  const status = options.status ?? 'succeeded';
  const attempts = options.attempts ?? 1;
  const delivery = await ctx.prisma.webhookDelivery.create({
    data: {
      organizationId: sub.organizationId,
      subscriptionId: sub.id,
      publicId: uuidv7(options.occurredAt.getTime()),
      eventId: built.envelope.id,
      eventType,
      eventOccurredAt: options.occurredAt,
      status,
      attemptCount: attempts,
      firstAttemptAt: attempts > 0 ? options.occurredAt : null,
      lastAttemptAt: attempts > 0 ? options.occurredAt : null,
      lastResponseCode: status === 'succeeded' ? 200 : 500,
      lastError: status === 'succeeded' ? null : 'http_500',
      completedAt: status === 'pending' ? null : options.occurredAt,
      nextAttemptAt: status === 'pending' ? options.occurredAt : null,
      createdAt: options.occurredAt,
    },
    select: { id: true, publicId: true },
  });
  for (let n = 1; n <= attempts; n += 1) {
    await ctx.prisma.webhookDeliveryAttempt.create({
      data: {
        organizationId: sub.organizationId,
        subscriptionId: sub.id,
        deliveryId: delivery.id,
        deliveryEventOccurredAt: options.occurredAt,
        attemptedAt: new Date(options.occurredAt.getTime() + n * 1000),
        attemptNo: n,
        outcome: n === attempts && status === 'succeeded' ? 'succeeded' : 'http_error',
        httpStatus: n === attempts && status === 'succeeded' ? 200 : 500,
        latencyMs: 10 * n,
        responseSnippet: 'ok',
        signatureCount: 1,
      },
    });
  }
  return {
    id: delivery.id,
    publicId: delivery.publicId,
    eventId: built.envelope.id,
    occurredAt: options.occurredAt,
  };
}

/** The subscription row of a public id on the writer. */
export function subscriptionRow(
  ctx: IntegrationApp,
  publicId: string,
): Promise<WebhookSubscription> {
  return ctx.prisma.webhookSubscription.findUniqueOrThrow({ where: { publicId } });
}

/** Audit rows of one subscription (oldest first). */
export function webhookAudit(ctx: IntegrationApp, publicId: string): Promise<AuditLog[]> {
  return ctx.prisma.auditLog.findMany({
    where: { resourceType: 'webhook_subscription', resourceId: publicId },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
  });
}

/** A response body as a plain record (typed reads inside `expect.poll`). */
export const bodyOf = (res: {
  body: unknown;
}): Record<string, unknown> & { data?: Array<Record<string, unknown>> } =>
  res.body as Record<string, unknown> & { data?: Array<Record<string, unknown>> };
