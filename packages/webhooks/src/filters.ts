import { SCAN_VERDICTS, type ScanVerdict } from '@email-gateway/security-contracts';
import { z } from 'zod';
import {
  SEVERITIES,
  type Severity,
  severityRank,
  WEBHOOK_EVENT_TYPES,
  type WebhookEventType,
} from './catalogue';

const unique = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;
const uniqueList = <S extends z.ZodType>(item: S, max: number) =>
  z
    .array(item)
    .min(1)
    .max(max)
    .refine((values) => unique(values), { message: 'Duplicate value' });

export const WEBHOOK_DIRECTIONS = ['inbound', 'outbound', 'internal'] as const;
export type WebhookDirection = (typeof WEBHOOK_DIRECTIONS)[number];
/** Most tenant domain ids in a `domainIds` filter. */
export const WEBHOOK_MAX_FILTER_DOMAINS = 20;

/**
 * Subscription filters (§5.3, strict, every field optional). `domainIds` are tenant domain
 * public ids, resolved inside the tenant scope at write time by the api (unknown or foreign id →
 * `422 webhook_filter_invalid`).
 */
export const subscriptionFiltersSchema = z.strictObject({
  directions: uniqueList(z.enum(WEBHOOK_DIRECTIONS), 3).optional(),
  domainIds: uniqueList(z.uuid(), WEBHOOK_MAX_FILTER_DOMAINS).optional(),
  minSeverity: z.enum(SEVERITIES).optional(),
  verdicts: uniqueList(z.enum(SCAN_VERDICTS), SCAN_VERDICTS.length).optional(),
});
export type SubscriptionFilters = z.infer<typeof subscriptionFiltersSchema>;

/** `eventTypes` of a subscription: 1–10 unique catalogue types, no wildcard (W5). */
export const subscriptionEventTypesSchema = uniqueList(
  z.enum(WEBHOOK_EVENT_TYPES),
  WEBHOOK_EVENT_TYPES.length,
);

/**
 * The attributes of a public event a subscription is matched against. An attribute that is
 * `undefined` is not carried by the event's type (domain events carry no direction or verdict)
 * and passes the corresponding filter; `domainPublicId: null` is carried but unknown (a message
 * of no tenant domain) and never matches a `domainIds` filter.
 */
export interface MatchableEvent {
  type: WebhookEventType;
  severity: Severity;
  direction?: WebhookDirection;
  domainPublicId?: string | null;
  verdict?: ScanVerdict;
}

export interface MatchableSubscription {
  eventTypes: readonly string[];
  filters?: SubscriptionFilters | null;
}

/**
 * W5: the event's type is one of the subscription's types **and** every present filter matches
 * the event's attribute when the event carries it.
 */
export function matchesSubscription(
  subscription: MatchableSubscription,
  event: MatchableEvent,
): boolean {
  if (!subscription.eventTypes.includes(event.type)) return false;
  const filters = subscription.filters;
  if (!filters) return true;
  if (
    filters.directions !== undefined &&
    event.direction !== undefined &&
    !filters.directions.includes(event.direction)
  ) {
    return false;
  }
  if (filters.domainIds !== undefined && event.domainPublicId !== undefined) {
    if (event.domainPublicId === null || !filters.domainIds.includes(event.domainPublicId)) {
      return false;
    }
  }
  if (
    filters.minSeverity !== undefined &&
    severityRank(event.severity) < severityRank(filters.minSeverity)
  ) {
    return false;
  }
  if (
    filters.verdicts !== undefined &&
    event.verdict !== undefined &&
    !filters.verdicts.includes(event.verdict)
  ) {
    return false;
  }
  return true;
}
