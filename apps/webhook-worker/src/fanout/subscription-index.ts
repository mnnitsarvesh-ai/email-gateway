import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  type AlertKind,
  type MatchableEvent,
  matchesSubscription,
  type ResolvedNotificationSettings,
  resolveNotificationSettings,
  severityRank,
  type Severity,
  type SubscriptionFilters,
  subscriptionEventTypesSchema,
  subscriptionFiltersSchema,
} from '@email-gateway/webhooks';
import { type InconsistencySink, wrongRead } from '../shared/errors';

/** The plan feature that must be enabled for deliveries (W5). */
export const WEBHOOKS_FEATURE = 'webhooks';
/** Organizations kept in the cache at most (least recently loaded evicted first). */
const MAX_ENTRIES = 10_000;

export interface IndexedSubscription {
  id: bigint;
  publicId: string;
  eventTypes: readonly string[];
  filters: SubscriptionFilters | null;
  createdAt: Date;
}

/** What the fanout knows about one organization without reading per event (W5, N2). */
export interface OrganizationIndex {
  organizationId: bigint;
  /** `organizations.public_id` (the envelope `organizationId`). */
  publicId: string;
  /** `organizations.status = 'active'` (suspended / pending_deletion / deleted get nothing). */
  organizationActive: boolean;
  /** `organization_features.webhooks` enabled (no row = disabled). */
  webhooksEnabled: boolean;
  /** `active` subscriptions only (paused / disabled / deleted receive no new deliveries). */
  subscriptions: readonly IndexedSubscription[];
  /** Resolved `notification_settings` (defaults when absent or invalid). */
  settings: ResolvedNotificationSettings;
  settingsInvalid: boolean;
}

/**
 * W5: the active subscriptions created at or before the event that match its attributes; none
 * when the organization is not `active` or its `webhooks` feature is off.
 */
export function matchingSubscriptions(
  index: OrganizationIndex,
  event: MatchableEvent,
  occurredAt: Date,
): IndexedSubscription[] {
  if (!index.organizationActive || !index.webhooksEnabled) return [];
  return index.subscriptions.filter(
    (s) => s.createdAt.getTime() <= occurredAt.getTime() && matchesSubscription(s, event),
  );
}

/** N2: whether an event of `kind` with `severity` requests an alert under the tenant settings. */
export function alertEnabled(
  settings: ResolvedNotificationSettings,
  kind: AlertKind,
  severity: Severity,
): boolean {
  switch (kind) {
    case 'threat_detected':
      return (
        settings.alerts.threatDetected.enabled &&
        severityRank(severity) >= severityRank(settings.alerts.threatDetected.minSeverity)
      );
    case 'domain_dns_failed':
      return settings.alerts.domainDnsFailed.enabled;
    case 'webhook_disabled':
      return settings.alerts.webhookDisabled.enabled;
  }
}

interface Entry {
  at: number;
  value: Promise<OrganizationIndex | null>;
}

/**
 * The per-organization subscription index of the fanout (W5): active subscriptions with their
 * types, filters and creation time, the organization status, the `webhooks` feature, the organization public id and the
 * resolved notification settings. Read on the **writer** (echo-checked), cached for
 * `WEBHOOK_SUBSCRIPTION_CACHE_SECONDS` (one load in flight per organization). Changes take effect
 * within the TTL (documented); the `created_at ≤ occurredAt` rule keeps the effect deterministic.
 */
export class SubscriptionIndex {
  private readonly entries = new Map<string, Entry>();
  private readonly now: () => number;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly ttlMs: number,
    private readonly sink: InconsistencySink,
    private readonly logger: Logger,
    now?: () => number,
  ) {
    this.now = now ?? Date.now;
  }

  /** The index of `organizationId`, or null when the organization does not exist. */
  get(organizationId: bigint): Promise<OrganizationIndex | null> {
    const key = organizationId.toString();
    const cached = this.entries.get(key);
    const now = this.now();
    if (cached && now - cached.at < this.ttlMs) return cached.value;
    const value = this.load(organizationId);
    this.entries.delete(key);
    this.entries.set(key, { at: now, value });
    // A failed load is not cached.
    value.catch(() => {
      if (this.entries.get(key)?.value === value) this.entries.delete(key);
    });
    while (this.entries.size > MAX_ENTRIES) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
    return value;
  }

  /** Drops the cached index of one organization (tests, explicit refresh). */
  invalidate(organizationId?: bigint): void {
    if (organizationId === undefined) this.entries.clear();
    else this.entries.delete(organizationId.toString());
  }

  private async load(organizationId: bigint): Promise<OrganizationIndex | null> {
    const organization = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { id: true, publicId: true, status: true },
    });
    if (organization === null) return null;
    if (organization.id !== organizationId) {
      wrongRead(this.sink, 'organization', 'organization id');
    }
    const [feature, rows, stored] = await Promise.all([
      this.prisma.organizationFeature.findUnique({
        where: { organizationId_featureKey: { organizationId, featureKey: WEBHOOKS_FEATURE } },
        select: { organizationId: true, featureKey: true, enabled: true },
      }),
      this.prisma.webhookSubscription.findMany({
        where: { organizationId, status: 'active' },
        select: {
          id: true,
          publicId: true,
          organizationId: true,
          status: true,
          eventTypes: true,
          filters: true,
          createdAt: true,
        },
        orderBy: { id: 'asc' },
      }),
      this.prisma.notificationSettings.findUnique({
        where: { organizationId },
        select: { organizationId: true, settings: true },
      }),
    ]);
    if (
      feature !== null &&
      (feature.organizationId !== organizationId || feature.featureKey !== WEBHOOKS_FEATURE)
    ) {
      wrongRead(this.sink, 'organization', 'feature row');
    }
    if (stored !== null && stored.organizationId !== organizationId) {
      wrongRead(this.sink, 'notification_settings', 'organization');
    }
    const subscriptions: IndexedSubscription[] = [];
    for (const row of rows) {
      if (row.organizationId !== organizationId || row.status !== 'active') {
        wrongRead(this.sink, 'subscriptions', 'organization or status');
      }
      const types = subscriptionEventTypesSchema.safeParse(row.eventTypes);
      const filters =
        row.filters === null ? null : subscriptionFiltersSchema.safeParse(row.filters);
      if (!types.success || (filters !== null && !filters.success)) {
        // Written by the api with the same schemas; a stored row that no longer validates
        // matches nothing (never a guess).
        this.logger.warn(
          { subscriptionId: row.publicId },
          'webhook subscription has invalid event types or filters; it receives nothing',
        );
        continue;
      }
      subscriptions.push({
        id: row.id,
        publicId: row.publicId,
        eventTypes: types.data,
        filters: filters === null ? null : (filters.data ?? null),
        createdAt: row.createdAt,
      });
    }
    const resolution = resolveNotificationSettings(stored?.settings ?? null);
    return {
      organizationId,
      publicId: organization.publicId,
      organizationActive: organization.status === 'active',
      webhooksEnabled: feature?.enabled ?? false,
      subscriptions,
      settings: resolution.settings,
      settingsInvalid: resolution.invalidStored,
    };
  }
}
