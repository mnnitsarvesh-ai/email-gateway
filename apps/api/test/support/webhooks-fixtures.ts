/**
 * In-memory doubles of the step 6.2 repositories for the stubbed e2e suites (webhooks,
 * notifications, route inventory): a tiny tenant-scoped "database" of webhook subscriptions,
 * deliveries, attempts, stored events, range replays, notification settings and preferences,
 * with the organization scoping of the real repositories, plus a recording AuditService, a
 * no-op organization row lock, a switchable `webhooks` feature and the quarantine settings the
 * preference center reads. Test-only: never used by production code.
 */
import type { TestingModuleBuilder } from '@nestjs/testing';
import { resolveQuarantineSettings } from '@email-gateway/quarantine';
import { AuditService } from '../../src/audit/audit.service';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import type { TimeIdKey } from '../../src/modules/messages/domain/v1-list';
import { NotificationsRepository } from '../../src/modules/notifications/notifications.repository';
import { QuarantineContext } from '../../src/modules/quarantine/services/quarantine-context';
import {
  type DeliveryAttemptRow,
  type DeliveryFilters,
  type DeliveryRow,
  type NewDelivery,
  type NewReplay,
  type NewWebhookEvent,
  type ReplayRow,
  WebhookDeliveriesRepository,
} from '../../src/modules/webhooks/repositories/webhook-deliveries.repository';
import {
  type LockedSubscription,
  type NewSubscription,
  type SubscriptionChanges,
  type SubscriptionRow,
  WebhookSubscriptionsRepository,
} from '../../src/modules/webhooks/repositories/webhook-subscriptions.repository';
import { OrganizationFeaturesService } from '../../src/tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../src/tenancy/organization-limits.service';
import { RecordingAuditService } from './messages-fixtures';

type StoredSubscription = LockedSubscription & {
  previousSecretCiphertext: string | null;
  createdByUserId: bigint | null;
};
type StoredDelivery = DeliveryRow;
type StoredEvent = NewWebhookEvent & { organizationId: bigint };
type StoredAttempt = DeliveryAttemptRow & { deliveryEventOccurredAt: Date };

const cmp = (a: TimeIdKey, b: TimeIdKey): number =>
  a.at.getTime() !== b.at.getTime()
    ? a.at.getTime() - b.at.getTime()
    : a.id === b.id
      ? 0
      : a.id < b.id
        ? -1
        : 1;

const copy = <T>(value: T): T => structuredClone(value);

export class WebhooksWorld {
  subscriptions: StoredSubscription[] = [];
  deliveries: StoredDelivery[] = [];
  events: StoredEvent[] = [];
  attempts: StoredAttempt[] = [];
  replays: Array<ReplayRow & { requestedByType: string; requestedById: string }> = [];
  domains: Array<{ publicId: string; organizationId: bigint; deleted?: boolean }> = [];
  users = new Map<bigint, string>();
  /** Organizations whose plan includes `webhooks` (default: every organization). */
  featureDisabled = new Set<bigint>();
  settings = new Map<bigint, { settings: unknown; rowVersion: number; updatedAt: Date }>();
  preferences = new Map<bigint, { organizationId: bigint; preferences: unknown }>();
  digest = new Map<bigint, { organizationId: bigint; digestOptOut: boolean }>();
  allowDigestOptOut = true;
  private nextId = 1000n;

  id(): bigint {
    this.nextId += 1n;
    return this.nextId;
  }

  reset(): void {
    this.subscriptions = [];
    this.deliveries = [];
    this.events = [];
    this.attempts = [];
    this.replays = [];
    this.domains = [];
    this.featureDisabled.clear();
    this.settings.clear();
    this.preferences.clear();
    this.digest.clear();
    this.allowDigestOptOut = true;
  }

  private row(s: StoredSubscription): SubscriptionRow {
    const {
      secretCiphertext: _c,
      previousSecretCiphertext: _p,
      createdByUserId: _u,
      ...rest
    } = copy(s);
    return rest;
  }

  /** Adds a subscription directly (fixtures). */
  addSubscription(
    organizationId: bigint,
    patch: Partial<StoredSubscription> & { publicId: string },
  ): StoredSubscription {
    const now = new Date();
    const row: StoredSubscription = {
      id: this.id(),
      organizationId,
      name: 'hook',
      description: null,
      url: 'https://hooks.example.com/in',
      eventTypes: ['email.received'],
      filters: null,
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
      createdAt: now,
      updatedAt: now,
      createdBy: null,
      secretCiphertext: 'v1.k1.fixture',
      previousSecretCiphertext: null,
      createdByUserId: null,
      ...patch,
    };
    this.subscriptions.push(row);
    return row;
  }

  /** Adds a delivery (and, unless `noEvent`, its stored event) directly (fixtures). */
  addDelivery(
    sub: StoredSubscription,
    patch: Partial<StoredDelivery> & { publicId: string; eventId: string; eventOccurredAt: Date },
    options: { noEvent?: boolean } = {},
  ): StoredDelivery {
    const row: StoredDelivery = {
      id: this.id(),
      subscriptionId: sub.id,
      organizationId: sub.organizationId,
      eventType: 'email.received',
      deliverySeq: 0,
      trigger: 'event',
      status: 'succeeded',
      attemptCount: 1,
      nextAttemptAt: null,
      firstAttemptAt: patch.eventOccurredAt,
      lastAttemptAt: patch.eventOccurredAt,
      lastResponseCode: 200,
      lastLatencyMs: 12,
      lastError: null,
      completedAt: patch.eventOccurredAt,
      createdAt: patch.eventOccurredAt,
      ...patch,
    };
    this.deliveries.push(row);
    if (!options.noEvent && !this.events.some((e) => e.eventId === row.eventId)) {
      this.events.push({
        organizationId: sub.organizationId,
        eventId: row.eventId,
        eventType: row.eventType,
        occurredAt: row.eventOccurredAt,
        sourceEventId: row.eventId,
        sourceEventType: 'mail.message.received.v1',
        severity: 'info',
        payloadJson: JSON.stringify({
          id: row.eventId,
          type: 'webhook.ping',
          version: 1,
          occurredAt: row.eventOccurredAt.toISOString(),
          organizationId: '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b10',
          data: { subscriptionId: sub.publicId, requestedAt: row.eventOccurredAt.toISOString() },
        }),
        payloadSha256: '0'.repeat(64),
      });
    }
    return row;
  }

  subscriptionsDouble(): WebhookSubscriptionsRepository {
    const own = (scope: TenantScope) => (s: StoredSubscription) =>
      s.organizationId === scope.organizationId;
    return {
      list: (
        scope: TenantScope,
        page: { take: number; beforeId?: bigint; statuses: readonly string[] },
      ) =>
        Promise.resolve(
          this.subscriptions
            .filter(own(scope))
            .filter((s) => page.statuses.includes(s.status))
            .filter((s) => page.beforeId === undefined || s.id < page.beforeId)
            .sort((a, b) => (a.id < b.id ? 1 : -1))
            .slice(0, page.take)
            .map((s) => this.row(s)),
        ),
      find: (scope: TenantScope, publicId: string) => {
        const s = this.subscriptions.find((r) => own(scope)(r) && r.publicId === publicId);
        return Promise.resolve(s ? this.row(s) : null);
      },
      countLive: (_tx: unknown, scope: TenantScope) =>
        Promise.resolve(
          this.subscriptions.filter((s) => own(scope)(s) && s.status !== 'deleted').length,
        ),
      existingDomainIds: (_tx: unknown, scope: TenantScope, ids: readonly string[]) =>
        Promise.resolve(
          new Set(
            this.domains
              .filter(
                (d) =>
                  d.organizationId === scope.organizationId &&
                  !d.deleted &&
                  ids.includes(d.publicId),
              )
              .map((d) => d.publicId),
          ),
        ),
      create: (_tx: unknown, scope: TenantScope, data: NewSubscription) => {
        const row = this.addSubscription(scope.organizationId, {
          publicId: data.publicId,
          name: data.name,
          description: data.description,
          url: data.url,
          eventTypes: data.eventTypes,
          filters: (data.filters ?? null) as never,
          status: data.status,
          maxConcurrency: data.maxConcurrency,
          secretCiphertext: data.secretCiphertext,
          createdByUserId: data.createdByUserId,
          createdBy:
            data.createdByUserId === null
              ? null
              : { publicId: this.users.get(data.createdByUserId) ?? data.publicId },
        });
        return Promise.resolve(this.row(row));
      },
      lock: (_tx: unknown, scope: TenantScope, publicId: string) => {
        const s = this.subscriptions.find(
          (r) => own(scope)(r) && r.publicId === publicId && r.status !== 'deleted',
        );
        return Promise.resolve(s ? copy(s) : null);
      },
      update: (
        _tx: unknown,
        scope: TenantScope,
        id: bigint,
        rowVersion: number,
        changes: SubscriptionChanges,
      ) => {
        const s = this.subscriptions.find((r) => own(scope)(r) && r.id === id);
        if (!s || s.rowVersion !== rowVersion) return Promise.resolve(false);
        Object.assign(s, copy(changes), { rowVersion: s.rowVersion + 1, updatedAt: new Date() });
        return Promise.resolve(true);
      },
      reload: (_tx: unknown, scope: TenantScope, id: bigint) => {
        const s = this.subscriptions.find((r) => own(scope)(r) && r.id === id)!;
        return Promise.resolve(this.row(s));
      },
    } as unknown as WebhookSubscriptionsRepository;
  }

  deliveriesDouble(): WebhookDeliveriesRepository {
    const page = (
      scope: TenantScope,
      input: {
        subscriptionId: bigint;
        range: { from: Date; to: Date };
        after?: TimeIdKey;
        boundary?: TimeIdKey | null;
        filters?: DeliveryFilters;
      },
    ) =>
      this.deliveries
        .filter(
          (d) =>
            d.organizationId === scope.organizationId &&
            d.subscriptionId === input.subscriptionId &&
            d.eventOccurredAt >= input.range.from &&
            d.eventOccurredAt < input.range.to,
        )
        .sort(
          (a, b) => -cmp({ at: a.eventOccurredAt, id: a.id }, { at: b.eventOccurredAt, id: b.id }),
        )
        .filter((d) => !input.after || cmp({ at: d.eventOccurredAt, id: d.id }, input.after) < 0);
    return {
      deliveries: (scope: TenantScope, input: Parameters<typeof page>[1] & { take: number }) => {
        const f = input.filters ?? {};
        return Promise.resolve(
          page(scope, input)
            .filter(
              (d) =>
                !input.boundary || cmp({ at: d.eventOccurredAt, id: d.id }, input.boundary) >= 0,
            )
            .filter((d) => !f.statuses?.length || f.statuses.includes(d.status))
            .filter((d) => !f.eventTypes?.length || f.eventTypes.includes(d.eventType))
            .filter((d) => !f.triggers?.length || f.triggers.includes(d.trigger))
            .slice(0, input.take)
            .map(copy),
        );
      },
      deliveriesBoundary: (
        scope: TenantScope,
        input: Parameters<typeof page>[1] & { budget: number },
      ) => {
        const row = page(scope, input)[input.budget - 1];
        return Promise.resolve(row ? { at: row.eventOccurredAt, id: row.id } : null);
      },
      findDelivery: (scope: TenantScope, subscriptionId: bigint, publicId: string) =>
        Promise.resolve(
          copy(
            this.deliveries.find(
              (d) =>
                d.organizationId === scope.organizationId &&
                d.subscriptionId === subscriptionId &&
                d.publicId === publicId,
            ) ?? null,
          ),
        ),
      attempts: (scope: TenantScope, delivery: DeliveryRow) =>
        Promise.resolve(
          this.attempts
            .filter(
              (a) =>
                a.organizationId === scope.organizationId &&
                a.deliveryId === delivery.id &&
                a.deliveryEventOccurredAt.getTime() === delivery.eventOccurredAt.getTime(),
            )
            .sort((a, b) => a.attemptNo - b.attemptNo)
            .map(({ deliveryEventOccurredAt: _d, ...rest }) => copy(rest)),
        ),
      storedEvent: (scope: TenantScope, eventId: string, occurredAt: Date) =>
        Promise.resolve(
          this.events.find(
            (e) =>
              e.organizationId === scope.organizationId &&
              e.eventId === eventId &&
              e.occurredAt.getTime() === occurredAt.getTime(),
          )?.payloadJson ?? null,
        ),
      findReplay: (scope: TenantScope, subscriptionId: bigint, publicId: string) => {
        const r = this.replays.find(
          (x) =>
            x.organizationId === scope.organizationId &&
            x.subscriptionId === subscriptionId &&
            x.publicId === publicId,
        );
        return Promise.resolve(r ? copy(r) : null);
      },
      cancelPending: (
        _tx: unknown,
        scope: TenantScope,
        subscriptionId: bigint,
        reason: string,
        now: Date,
      ) => {
        let count = 0;
        for (const d of this.deliveries) {
          if (
            d.organizationId === scope.organizationId &&
            d.subscriptionId === subscriptionId &&
            d.status === 'pending'
          ) {
            Object.assign(d, {
              status: 'cancelled',
              nextAttemptAt: null,
              completedAt: now,
              lastError: `cancelled:${reason}`,
            });
            count += 1;
          }
        }
        return Promise.resolve(count);
      },
      parkPending: (_tx: unknown, scope: TenantScope, subscriptionId: bigint) => {
        let count = 0;
        for (const d of this.deliveries) {
          if (
            d.organizationId === scope.organizationId &&
            d.subscriptionId === subscriptionId &&
            d.status === 'pending' &&
            d.nextAttemptAt !== null
          ) {
            d.nextAttemptAt = null;
            count += 1;
          }
        }
        return Promise.resolve(count);
      },
      unparkPending: (_tx: unknown, scope: TenantScope, subscriptionId: bigint, now: Date) => {
        let count = 0;
        for (const d of this.deliveries) {
          if (
            d.organizationId === scope.organizationId &&
            d.subscriptionId === subscriptionId &&
            d.status === 'pending' &&
            d.nextAttemptAt === null
          ) {
            d.nextAttemptAt = now;
            count += 1;
          }
        }
        return Promise.resolve(count);
      },
      findDeliveryTx: (
        _tx: unknown,
        scope: TenantScope,
        subscriptionId: bigint,
        publicId: string,
      ) =>
        Promise.resolve(
          copy(
            this.deliveries.find(
              (d) =>
                d.organizationId === scope.organizationId &&
                d.subscriptionId === subscriptionId &&
                d.publicId === publicId,
            ) ?? null,
          ),
        ),
      eventExists: (_tx: unknown, scope: TenantScope, eventId: string, occurredAt: Date) =>
        Promise.resolve(
          this.events.some(
            (e) =>
              e.organizationId === scope.organizationId &&
              e.eventId === eventId &&
              e.occurredAt.getTime() === occurredAt.getTime(),
          ),
        ),
      sequence: (
        _tx: unknown,
        scope: TenantScope,
        key: { subscriptionId: bigint; eventId: string; eventOccurredAt: Date },
      ) => {
        const rows = this.deliveries.filter(
          (d) =>
            d.organizationId === scope.organizationId &&
            d.subscriptionId === key.subscriptionId &&
            d.eventId === key.eventId &&
            d.eventOccurredAt.getTime() === key.eventOccurredAt.getTime(),
        );
        return Promise.resolve({
          maxSeq: Math.max(0, ...rows.map((r) => r.deliverySeq)),
          replays: rows.filter((r) => r.deliverySeq > 0).length,
        });
      },
      insertDelivery: (_tx: unknown, scope: TenantScope, data: NewDelivery) => {
        const sub = this.subscriptions.find((s) => s.id === data.subscriptionId)!;
        const row = this.addDelivery(
          sub,
          {
            publicId: data.publicId,
            eventId: data.eventId,
            eventType: data.eventType,
            eventOccurredAt: data.eventOccurredAt,
            deliverySeq: data.deliverySeq,
            trigger: data.trigger,
            status: 'pending',
            attemptCount: 0,
            nextAttemptAt: data.now,
            firstAttemptAt: null,
            lastAttemptAt: null,
            lastResponseCode: null,
            lastLatencyMs: null,
            completedAt: null,
            createdAt: data.now,
            organizationId: scope.organizationId,
          },
          { noEvent: true },
        );
        return Promise.resolve(copy(row));
      },
      insertEvent: (_tx: unknown, scope: TenantScope, data: NewWebhookEvent) => {
        this.events.push({ ...copy(data), organizationId: scope.organizationId });
        return Promise.resolve();
      },
      activeReplay: (_tx: unknown, scope: TenantScope, subscriptionId: bigint) => {
        const r = this.replays.find(
          (x) =>
            x.organizationId === scope.organizationId &&
            x.subscriptionId === subscriptionId &&
            (x.status === 'queued' || x.status === 'running'),
        );
        return Promise.resolve(r ? { publicId: r.publicId } : null);
      },
      insertReplay: (_tx: unknown, scope: TenantScope, data: NewReplay) => {
        const now = new Date();
        const row = {
          id: this.id(),
          publicId: data.publicId,
          organizationId: scope.organizationId,
          subscriptionId: data.subscriptionId,
          requestedByType: data.requestedByType,
          requestedById: data.requestedById,
          status: 'queued' as const,
          rangeFrom: data.rangeFrom,
          rangeTo: data.rangeTo,
          statuses: data.statuses,
          eventTypes: data.eventTypes,
          matchedCount: 0,
          createdCount: 0,
          truncated: false,
          errorCode: null,
          createdAt: now,
          startedAt: null,
          completedAt: null,
        };
        this.replays.push(row);
        return Promise.resolve(copy(row));
      },
    } as unknown as WebhookDeliveriesRepository;
  }

  notificationsDouble(): NotificationsRepository {
    const settingsOf = (scope: TenantScope) => {
      const row = this.settings.get(scope.organizationId);
      return row ? copy(row) : null;
    };
    const mine = <T extends { organizationId: bigint }>(
      scope: TenantScope,
      row: T | undefined,
    ): T | undefined => {
      if (row && row.organizationId !== scope.organizationId) throw new Error('echo');
      return row;
    };
    return {
      settings: (scope: TenantScope) => Promise.resolve(settingsOf(scope)),
      lockSettings: (_tx: unknown, scope: TenantScope) => Promise.resolve(settingsOf(scope)),
      insertSettings: (_tx: unknown, scope: TenantScope, data: { settings: unknown }) => {
        const row = { settings: copy(data.settings), rowVersion: 1, updatedAt: new Date() };
        this.settings.set(scope.organizationId, row);
        return Promise.resolve(copy(row));
      },
      updateSettings: (
        _tx: unknown,
        scope: TenantScope,
        rowVersion: number,
        data: { settings: unknown },
      ) => {
        const row = this.settings.get(scope.organizationId);
        if (!row || row.rowVersion !== rowVersion) return Promise.resolve(false);
        Object.assign(row, {
          settings: copy(data.settings),
          rowVersion: row.rowVersion + 1,
          updatedAt: new Date(),
        });
        return Promise.resolve(true);
      },
      reloadSettings: (_tx: unknown, scope: TenantScope) => Promise.resolve(settingsOf(scope)!),
      preferences: (scope: TenantScope, userId: bigint) =>
        Promise.resolve(mine(scope, this.preferences.get(userId))?.preferences ?? null),
      digestOptOut: (scope: TenantScope, userId: bigint) =>
        Promise.resolve(mine(scope, this.digest.get(userId))?.digestOptOut ?? false),
      lockPreferences: (_tx: unknown, scope: TenantScope, userId: bigint) =>
        Promise.resolve({
          preferences: mine(scope, this.preferences.get(userId))?.preferences ?? null,
          digestOptOut: mine(scope, this.digest.get(userId))?.digestOptOut ?? false,
        }),
      upsertPreferences: (_tx: unknown, scope: TenantScope, userId: bigint, prefs: unknown) => {
        this.preferences.set(userId, {
          organizationId: scope.organizationId,
          preferences: copy(prefs),
        });
        return Promise.resolve();
      },
      upsertDigestOptOut: (_tx: unknown, scope: TenantScope, userId: bigint, value: boolean) => {
        this.digest.set(userId, { organizationId: scope.organizationId, digestOptOut: value });
        return Promise.resolve();
      },
    } as unknown as NotificationsRepository;
  }

  quarantineDouble(): QuarantineContext {
    const settings = () =>
      resolveQuarantineSettings(
        { digest: { allowOptOut: this.allowDigestOptOut } },
        { maxHoldDays: 60, maxReviewDays: 13 },
      ).settings;
    return {
      settings: () => Promise.resolve(settings()),
      settingsTx: () => Promise.resolve(settings()),
    } as unknown as QuarantineContext;
  }
}

/** Overrides the step 6.2 repositories (and audit, features, org lock) with the doubles. */
export function overrideWebhooks(
  builder: TestingModuleBuilder,
  world: WebhooksWorld,
  audit: RecordingAuditService,
): TestingModuleBuilder {
  return builder
    .overrideProvider(WebhookSubscriptionsRepository)
    .useValue(world.subscriptionsDouble())
    .overrideProvider(WebhookDeliveriesRepository)
    .useValue(world.deliveriesDouble())
    .overrideProvider(NotificationsRepository)
    .useValue(world.notificationsDouble())
    .overrideProvider(QuarantineContext)
    .useValue(world.quarantineDouble())
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(OrganizationFeaturesService)
    .useValue({
      isEnabled: (organizationId: bigint, key: string) =>
        Promise.resolve(key === 'webhooks' && !world.featureDisabled.has(organizationId)),
    })
    .overrideProvider(OrganizationLimitsService)
    .useValue({ lockOrganization: () => Promise.resolve() });
}

export { RecordingAuditService };
