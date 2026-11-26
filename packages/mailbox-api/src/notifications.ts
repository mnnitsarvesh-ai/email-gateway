/**
 * Graph change and lifecycle notification payloads (design D9, D12.4). The public callback route
 * reads only `value[].{subscriptionId, clientState, changeType, lifecycleEvent, tenantId,
 * subscriptionExpirationDateTime}`; everything else (resource, resourceData, …) is ignored and
 * dropped by the parse, so content never travels further. A notification is a hint to sync a
 * mailbox, never a source of content or tenant.
 */
import { z } from 'zod';

/** Graph's lifecycle events (`lifecycleEvent`). */
export const GRAPH_LIFECYCLE_EVENTS = [
  'reauthorizationRequired',
  'subscriptionRemoved',
  'missed',
] as const;
export type GraphLifecycleEvent = (typeof GRAPH_LIFECYCLE_EVENTS)[number];

const nullableText = (max: number) =>
  z
    .string()
    .max(max)
    .nullish()
    .transform((v) => v ?? undefined);

export const graphNotificationItemSchema = z.object({
  subscriptionId: z.string().min(1).max(128),
  clientState: nullableText(255),
  changeType: nullableText(32),
  lifecycleEvent: nullableText(64),
  tenantId: nullableText(64),
  subscriptionExpirationDateTime: nullableText(64),
});

/** `{ value: [1..1000 items] }`; unknown keys allowed but dropped. */
export const graphNotificationSchema = z.object({
  value: z.array(graphNotificationItemSchema).min(1).max(1000),
});

export type GraphNotificationItem = z.infer<typeof graphNotificationItemSchema>;
export type GraphNotificationPayload = z.infer<typeof graphNotificationSchema>;

export function isGraphLifecycleEvent(value: string | undefined): value is GraphLifecycleEvent {
  return value !== undefined && (GRAPH_LIFECYCLE_EVENTS as readonly string[]).includes(value);
}

/**
 * Graph's validation handshake token as the callback route accepts it (D12.4): 1–1024 printable
 * ASCII characters. The route echoes it as `text/plain`.
 */
export function isGraphValidationToken(value: string | null | undefined): value is string {
  return typeof value === 'string' && /^[\x20-\x7e]{1,1024}$/.test(value);
}
