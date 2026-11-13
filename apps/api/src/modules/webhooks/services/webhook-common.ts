import { BadRequestException } from '@nestjs/common';
import type { z } from 'zod';
import type { Principal } from '../../../auth-contracts/principal';
import { formatZodIssues } from '../../../validation/zod-validation.pipe';
import { WebhookIdSchema } from '../webhooks.schemas';

/** Writer transaction budget of the webhook mutations (D15: ≥ the 15 s default). */
export const WEBHOOK_TX_TIMEOUT_MS = 30_000;

/** Plan feature that gates create, re-activation, test and replay (W5). */
export const WEBHOOKS_FEATURE = 'webhooks';

/** `audit_logs.resource_type` of subscriptions. */
export const WEBHOOK_RESOURCE_TYPE = 'webhook_subscription';

/** Stable Idempotency-Key operation names (§6.1; one key space per organization). */
export const WEBHOOK_OPERATIONS = {
  create: 'webhook.create',
  delete: 'webhook.delete',
  rotate: 'webhook.secret_rotate',
  deliveryReplay: 'webhook.delivery_replay',
  rangeReplay: 'webhook.range_replay',
} as const;

/** Audit actions (§6.1). Metadata: ids, codes, `urlHost` + `urlSha256`; never URL or secret. */
export const WEBHOOK_AUDIT = {
  created: 'webhook.created',
  updated: 'webhook.updated',
  deleted: 'webhook.deleted',
  secretRotated: 'webhook.secret_rotated',
  testRequested: 'webhook.test_requested',
  deliveryReplayed: 'webhook.delivery_replayed',
  replayRequested: 'webhook.replay_requested',
} as const;

/** A path id (`{webhookId}`, `{deliveryId}`, `{replayId}`): a UUID, `400` before any read. */
export function parsePublicId(raw: unknown, name: string): string {
  const parsed = WebhookIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException([`${name}: must be a UUID`]);
  return parsed.data.toLowerCase();
}

/** A body parsed in the service (after the Idempotency-Key checks); `400 validation_failed`. */
export function parseBody<S extends z.ZodType>(schema: S, raw: unknown): z.output<S> {
  const parsed = schema.safeParse(raw ?? {});
  if (!parsed.success) throw new BadRequestException(formatZodIssues(parsed.error));
  return parsed.data;
}

/** `user` / `api_key` and the public id of the principal (replay requester). */
export function requester(principal: Principal): { type: 'user' | 'api_key'; id: string } {
  return principal.kind === 'api_key'
    ? { type: 'api_key', id: principal.apiKeyPublicId }
    : { type: 'user', id: principal.userPublicId };
}
