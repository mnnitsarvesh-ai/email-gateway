import { describe, expect, it } from 'vitest';
import { isStrictRequestSchema } from '../../validation/strict-schema';
import { errorCodeOf, filtersOf, toDeliveryView, toWebhookView } from './webhooks.mapper';
import type { SubscriptionRow } from './repositories/webhook-subscriptions.repository';
import {
  CreateReplayBodySchema,
  CreateWebhookBodySchema,
  DeliveryListQuerySchema,
  EVENT_TYPES_VIEW,
  RotateSecretBodySchema,
  UpdateWebhookBodySchema,
  WebhookListQuerySchema,
  WebhookSchema,
} from './webhooks.schemas';

const at = new Date('2026-11-13T09:00:00.000Z');
const row = {
  id: 5n,
  publicId: '0193a2c4-5d6e-7f80-9a1b-2c3d4e5f6a7b',
  organizationId: 1n,
  name: 'n',
  description: null,
  url: 'https://h.example.com/',
  eventTypes: ['email.received', 'not.a.type'],
  filters: { minSeverity: 'high' },
  status: 'active',
  disabledReason: null,
  disabledAt: null,
  maxConcurrency: null,
  secretVersion: 1,
  secretRotatedAt: null,
  previousSecretExpiresAt: null,
  consecutiveFailures: 0,
  failingSince: null,
  lastSuccessAt: null,
  lastFailureAt: null,
  deletedAt: null,
  rowVersion: 1,
  createdAt: at,
  updatedAt: at,
  createdBy: null,
} as unknown as SubscriptionRow;

describe('webhooks mapper (§6.1)', () => {
  it('represents a subscription without ciphertexts and with known event types only', () => {
    const withSecrets = {
      ...row,
      secretCiphertext: 'v1.k1.x',
      previousSecretCiphertext: 'v1.k1.y',
    };
    const view = toWebhookView(withSecrets);
    expect(view.eventTypes).toEqual(['email.received']);
    expect(JSON.stringify(view)).not.toMatch(/ciphertext|v1\.k1/);
    expect(WebhookSchema.strict().safeParse(view).success).toBe(true);
  });

  it('drops an invalid stored filter document and keeps codes only', () => {
    expect(filtersOf({ nope: 1 })).toBeNull();
    expect(filtersOf(null)).toBeNull();
    expect(errorCodeOf('http_500')).toBe('http_500');
    expect(errorCodeOf('free text with spaces')).toBe('error');
    expect(errorCodeOf(null)).toBeNull();
  });

  it('shows nextAttemptAt only for pending deliveries', () => {
    const d = {
      id: 1n,
      eventOccurredAt: at,
      publicId: row.publicId,
      subscriptionId: 5n,
      organizationId: 1n,
      eventId: row.publicId,
      eventType: 'email.received',
      deliverySeq: 0,
      trigger: 'event',
      status: 'succeeded',
      attemptCount: 1,
      nextAttemptAt: at,
      firstAttemptAt: at,
      lastAttemptAt: at,
      lastResponseCode: 200,
      lastLatencyMs: 3,
      lastError: null,
      completedAt: at,
      createdAt: at,
    } as const;
    expect(toDeliveryView(d as never).nextAttemptAt).toBeNull();
    expect(toDeliveryView({ ...d, status: 'pending' } as never).nextAttemptAt).toBe(
      at.toISOString(),
    );
  });
});

describe('webhooks schemas', () => {
  it('every request schema is strict at every object node (D1)', () => {
    for (const schema of [
      CreateWebhookBodySchema,
      UpdateWebhookBodySchema,
      RotateSecretBodySchema,
      CreateReplayBodySchema,
      WebhookListQuerySchema,
      DeliveryListQuerySchema,
    ]) {
      expect(isStrictRequestSchema(schema)).toEqual([]);
    }
  });

  it('builds a valid example envelope for each of the 11 envelope types', () => {
    expect(EVENT_TYPES_VIEW.data).toHaveLength(11);
    for (const entry of EVENT_TYPES_VIEW.data)
      expect(entry.example).toMatchObject({ type: entry.type, version: 1 });
  });
});
