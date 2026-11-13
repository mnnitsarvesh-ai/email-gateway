import { ToneBadge } from '@/components/domain/tone-badge';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import type { Tone } from '@/lib/design/tokens';
import { humanize } from '@/lib/format';

export type Webhook = SuccessBody<'WebhooksController_get_v1'>;
export type WebhookStatus = Webhook['status'];
export type WebhookEventType = Webhook['eventTypes'][number];
export type WebhookDelivery = ListItem<'WebhookDeliveriesController_list_v1'>;
export type EventCatalog = SuccessBody<'WebhooksController_eventTypes_v1'>;

export const WEBHOOK_STATUSES: readonly WebhookStatus[] = [
  'active',
  'paused',
  'disabled',
  'deleted',
];
export const DELIVERY_STATUSES = ['pending', 'succeeded', 'failed', 'dead', 'cancelled'] as const;
export const DELIVERY_TRIGGERS = ['event', 'replay', 'test'] as const;
export const DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export const SCAN_VERDICTS = [
  'clean',
  'spam',
  'suspicious',
  'malicious',
  'unknown',
  'timeout',
  'error',
] as const;
export const SEVERITIES = ['info', 'low', 'medium', 'high'] as const;

const WEBHOOK_TONE: Record<WebhookStatus, Tone> = {
  active: 'success',
  paused: 'warning',
  disabled: 'danger',
  deleted: 'neutral',
};

export function WebhookStatusBadge({ status }: { status: WebhookStatus }) {
  return <ToneBadge tone={WEBHOOK_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

const DELIVERY_TONE: Record<WebhookDelivery['status'], Tone> = {
  pending: 'info',
  succeeded: 'success',
  failed: 'warning',
  dead: 'danger',
  cancelled: 'neutral',
};

export function WebhookDeliveryBadge({ status }: { status: WebhookDelivery['status'] }) {
  return <ToneBadge tone={DELIVERY_TONE[status] ?? 'neutral'}>{humanize(status)}</ToneBadge>;
}

/** What a redacted replay of a secret-bearing route means (ADR-0057). */
export const REDACTED_REPLAY_EXPLANATION =
  'This request had already been applied, so the api answered with the stored response, which never contains the secret. The secret was shown only in the original response. If you did not store it, rotate the secret: a new one is shown once.';
