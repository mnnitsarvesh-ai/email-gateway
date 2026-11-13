import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma, WebhookStatus } from '@email-gateway/database';
import {
  buildEnvelope,
  type SubscriptionFilters,
  WEBHOOK_PING_TYPE,
} from '@email-gateway/webhooks';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import {
  canonicalJson,
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
  scopeOrganizationPublicId,
} from '../../messages/domain/v1-list';
import { hostOf, WebhookUrlPolicy } from '../domain/webhook-url';
import { WebhookDeliveriesRepository } from '../repositories/webhook-deliveries.repository';
import {
  type LockedSubscription,
  type SubscriptionChanges,
  WebhookSubscriptionsRepository,
} from '../repositories/webhook-subscriptions.repository';
import {
  webhookFilterInvalid,
  webhookLimitReached,
  webhookNotActive,
  webhookNotFound,
  webhooksNotEnabled,
  webhookUrlNotAllowed,
  webhookVersionConflict,
} from '../webhooks.errors';
import { toWebhookView } from '../webhooks.mapper';
import {
  type CreatedWebhookView,
  CreateWebhookBodySchema,
  EVENT_TYPES_VIEW,
  type EventTypesView,
  type RotatedSecretView,
  RotateSecretBodySchema,
  type TestAccepted,
  type UpdateWebhookBody,
  type WebhookListQuery,
  type WebhookPage,
  WEBHOOKS_RESOURCE,
  type WebhookView,
} from '../webhooks.schemas';
import {
  parseBody,
  parsePublicId,
  WEBHOOK_AUDIT,
  WEBHOOK_OPERATIONS,
  WEBHOOK_RESOURCE_TYPE,
  WEBHOOK_TX_TIMEOUT_MS,
  WEBHOOKS_FEATURE,
} from './webhook-common';
import { WebhookSecrets } from './webhook-secrets';

type Tx = Prisma.TransactionClient;

type Config = Pick<
  ApiConfig,
  | 'WEBHOOK_ALLOWED_PORTS'
  | 'WEBHOOK_ALLOW_HTTP'
  | 'WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG'
  | 'WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT'
  | 'URL_CLICK_BASE_URL'
  | 'PORTAL_PUBLIC_URL'
>;

const HOUR_MS = 3_600_000;
/** Statuses listed when the caller does not filter (never `deleted` unless asked, §6.1). */
const DEFAULT_LIST_STATUSES: WebhookStatus[] = ['active', 'paused', 'disabled'];

/** Source event type of a test ping (`webhook_events.source_event_type`). */
export const TEST_SOURCE_EVENT_TYPE = 'api.webhook.test_requested';

export interface CreateWebhookInput {
  idempotencyKey: unknown;
  body: unknown;
  /** The host the request reached (the api's own host, refused as an endpoint). */
  requestHost: string | null;
}

export interface RotateSecretInput {
  webhookId: unknown;
  idempotencyKey: unknown;
  body: unknown;
}

/** Dotted paths of the top-level fields that differ (audit metadata of `webhook.updated`). */
export function changedFields(changes: SubscriptionChanges): string[] {
  return Object.keys(changes)
    .filter(
      (key) =>
        ![
          'consecutiveFailures',
          'failingSince',
          'disabledReason',
          'disabledAt',
          'deletedAt',
        ].includes(key),
    )
    .sort();
}

/**
 * Webhook subscriptions of the caller's organization (step 6.2 W5–W7, §6.1): the replica list
 * and detail, and the writer mutations — create and rotate with the redacted-replay
 * Idempotency-Key of ADR-0057 (the secret lives only in a local of the transaction's work
 * function and is added to the live response after the commit; the stored response says
 * `secret: null`), the CAS `PATCH`, the keyed soft delete that cancels pending deliveries in the
 * same transaction, and the test ping. Every mutation writes its audit row in its transaction;
 * audit metadata names `urlHost` and `urlSha256`, never the URL or a secret.
 */
@Injectable()
export class WebhooksService {
  private readonly urls: WebhookUrlPolicy;

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly subscriptions: WebhookSubscriptionsRepository,
    private readonly deliveries: WebhookDeliveriesRepository,
    private readonly secrets: WebhookSecrets,
    private readonly idempotency: IdempotencyService,
    private readonly runner: TransactionRunner,
    private readonly features: OrganizationFeaturesService,
    private readonly limits: OrganizationLimitsService,
    private readonly audit: AuditService,
    private readonly codec: CursorCodec,
  ) {
    this.urls = new WebhookUrlPolicy({
      allowedPorts: config.WEBHOOK_ALLOWED_PORTS,
      allowHttp: config.WEBHOOK_ALLOW_HTTP,
      denyHosts: [hostOf(config.URL_CLICK_BASE_URL), hostOf(config.PORTAL_PUBLIC_URL)].filter(
        (h): h is string => h !== null,
      ),
    });
  }

  now(): Date {
    return new Date();
  }

  eventTypes(): EventTypesView {
    return EVENT_TYPES_VIEW;
  }

  async list(
    principal: Principal,
    scope: TenantScope,
    query: WebhookListQuery,
  ): Promise<WebhookPage> {
    const binding = listBinding({
      resource: WEBHOOKS_RESOURCE,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    const beforeId = decoded ? decimalKey(decoded.keys[0]) : undefined;
    const statuses = query.filters.status?.values ?? DEFAULT_LIST_STATUSES;
    const fetched = await this.subscriptions.list(scope, {
      take: query.limit + 1,
      beforeId,
      statuses,
    });
    const decision = decideKeysetPage({ fetched, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: fetched.slice(0, decision.rows).map(toWebhookView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }

  async get(scope: TenantScope, rawId: unknown): Promise<WebhookView> {
    const row = await this.subscriptions.find(scope, parsePublicId(rawId, 'webhookId'));
    if (!row) throw webhookNotFound();
    return toWebhookView(row);
  }

  /**
   * `POST /webhooks` (W6, W7, ADR-0057): URL rules (`422 webhook_url_not_allowed`), then in one
   * writer transaction under the organization row lock: feature (`403 webhooks_not_enabled`),
   * cap (`409 webhook_limit_reached`), filter domains (`422 webhook_filter_invalid`), the
   * encrypted secret, the row, the audit row and the stored (redacted) response.
   */
  async create(
    principal: Principal,
    scope: TenantScope,
    input: CreateWebhookInput,
    sourceIp: string | null,
  ): Promise<IdempotentResult<CreatedWebhookView>> {
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(CreateWebhookBodySchema, input.body);
    const url = this.checkUrl(body.url, input.requestHost);
    const live: { secret: string | null } = { secret: null };
    const result = await this.idempotency.execute<CreatedWebhookView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: WEBHOOK_OPERATIONS.create,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({
          operation: WEBHOOK_OPERATIONS.create,
          resourceId: '-',
          body,
        }),
      },
      async (tx) => {
        live.secret = null;
        await this.limits.lockOrganization(tx, scope.organizationId);
        await this.requireFeature(tx, scope);
        const max = this.config.WEBHOOK_MAX_SUBSCRIPTIONS_PER_ORG;
        if ((await this.subscriptions.countLive(tx, scope)) >= max) {
          throw webhookLimitReached(max);
        }
        const filters = await this.resolveFilters(tx, scope, body.filters ?? null);
        const publicId = uuidv7();
        const issued = this.secrets.issue(scope.organizationId, publicId, 1);
        const row = await this.subscriptions.create(tx, scope, {
          publicId,
          name: body.name,
          description: body.description || null,
          url: url.url,
          eventTypes: [...body.eventTypes],
          filters: filters,
          status: body.status,
          maxConcurrency: body.maxConcurrency ?? null,
          secretCiphertext: issued.ciphertext,
          createdByUserId: principal.kind === 'user' ? principal.userId : null,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.created,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: publicId,
            sourceIp,
            metadata: {
              urlHost: url.host,
              urlSha256: url.sha256,
              eventTypes: [...body.eventTypes],
              filterNames: filters ? Object.keys(filters).sort() : [],
              status: body.status,
              maxConcurrency: body.maxConcurrency ?? null,
            },
          },
          tx,
        );
        // Only after every write succeeded: the secret never reaches the stored response.
        live.secret = issued.secret;
        return { statusCode: 201, body: { ...toWebhookView(row), secret: null } };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
    return withSecret(result, live.secret);
  }

  /**
   * `PATCH /webhooks/{webhookId}` (W5): CAS on `expectedRowVersion` (`409
   * webhook_version_conflict`); activation checks the feature and resets the failure state;
   * `disabled` (manual) cancels pending deliveries; URL and filter rules as on create. Unchanged
   * values change nothing (no new row version, no audit row).
   */
  async update(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    body: UpdateWebhookBody,
    requestHost: string | null,
    sourceIp: string | null,
  ): Promise<WebhookView> {
    const publicId = parsePublicId(rawId, 'webhookId');
    const url = body.url === undefined ? undefined : this.checkUrl(body.url, requestHost);
    return this.runner.run(
      async (tx) => {
        const row = await this.subscriptions.lock(tx, scope, publicId);
        if (!row) throw webhookNotFound();
        if (row.rowVersion !== body.expectedRowVersion)
          throw webhookVersionConflict(row.rowVersion);
        const now = this.now();
        const changes: SubscriptionChanges = {};
        if (body.name !== undefined && body.name !== row.name) changes.name = body.name;
        if (body.description !== undefined) {
          const description = body.description || null;
          if (description !== row.description) changes.description = description;
        }
        if (url && url.url !== row.url) changes.url = url.url;
        if (
          body.eventTypes !== undefined &&
          canonicalJson([...body.eventTypes].sort()) !==
            canonicalJson([...(row.eventTypes as string[])].sort())
        ) {
          changes.eventTypes = [...body.eventTypes];
        }
        if (body.filters !== undefined) {
          const filters = await this.resolveFilters(tx, scope, body.filters);
          if (canonicalJson(filters) !== canonicalJson(row.filters ?? null)) {
            changes.filters = filters;
          }
        }
        if (body.maxConcurrency !== undefined && body.maxConcurrency !== row.maxConcurrency) {
          changes.maxConcurrency = body.maxConcurrency;
        }
        const statusChange =
          body.status !== undefined && body.status !== row.status ? body.status : undefined;
        if (statusChange !== undefined) {
          changes.status = statusChange;
          if (statusChange === 'active') {
            await this.requireFeature(tx, scope);
            Object.assign(changes, {
              consecutiveFailures: 0,
              failingSince: null,
              disabledReason: null,
              disabledAt: null,
            });
          } else if (statusChange === 'disabled') {
            Object.assign(changes, { disabledReason: 'manual', disabledAt: now });
          } else {
            Object.assign(changes, { disabledReason: null, disabledAt: null });
          }
        }
        const paths = changedFields(changes);
        if (paths.length === 0) return toWebhookView(row);
        if (!(await this.subscriptions.update(tx, scope, row.id, row.rowVersion, changes))) {
          throw webhookVersionConflict(row.rowVersion);
        }
        const cancelled =
          statusChange === 'disabled'
            ? await this.deliveries.cancelPending(tx, scope, row.id, 'disabled', now)
            : 0;
        // Pause parks the pending deliveries (out of the due index), resume makes them due now.
        const parked =
          statusChange === 'paused' ? await this.deliveries.parkPending(tx, scope, row.id) : 0;
        const resumed =
          statusChange === 'active'
            ? await this.deliveries.unparkPending(tx, scope, row.id, now)
            : 0;
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.updated,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              changedPaths: paths,
              ...(changes.url !== undefined && url && { urlHost: url.host, urlSha256: url.sha256 }),
              ...(statusChange !== undefined && {
                fromStatus: row.status,
                toStatus: statusChange,
                cancelledDeliveries: cancelled,
                ...(statusChange === 'paused' && { parkedDeliveries: parked }),
                ...(statusChange === 'active' && { resumedDeliveries: resumed }),
              }),
              rowVersion: row.rowVersion + 1,
            },
          },
          tx,
        );
        return toWebhookView(await this.subscriptions.reload(tx, scope, row.id));
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
  }

  /**
   * `DELETE /webhooks/{webhookId}` (W5): Idempotency-Key, soft delete (`status = deleted`,
   * `deleted_at`), pending deliveries `cancelled` in the same transaction, audit row. A replay
   * answers 204 again; a new key for a deleted subscription is `404`.
   */
  async delete(
    principal: Principal,
    scope: TenantScope,
    input: { webhookId: unknown; idempotencyKey: unknown },
    sourceIp: string | null,
  ): Promise<IdempotentResult<{ id: string; deleted: true }>> {
    const publicId = parsePublicId(input.webhookId, 'webhookId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    return this.idempotency.execute<{ id: string; deleted: true }>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: WEBHOOK_OPERATIONS.delete,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: WEBHOOK_OPERATIONS.delete,
          resourceId: publicId,
          body: {},
        }),
      },
      async (tx) => {
        const row = await this.subscriptions.lock(tx, scope, publicId);
        if (!row) throw webhookNotFound();
        const now = this.now();
        const changes: SubscriptionChanges = { status: 'deleted', deletedAt: now };
        if (!(await this.subscriptions.update(tx, scope, row.id, row.rowVersion, changes))) {
          throw webhookVersionConflict(row.rowVersion);
        }
        const cancelled = await this.deliveries.cancelPending(tx, scope, row.id, 'deleted', now);
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.deleted,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              formerStatus: row.status,
              urlHost: hostOf(row.url),
              cancelledDeliveries: cancelled,
            },
          },
          tx,
        );
        return { statusCode: 204, body: { id: row.publicId, deleted: true } };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
  }

  /**
   * `POST /webhooks/{webhookId}/rotate-secret` (W7, ADR-0057): a new secret (version + 1); the
   * current ciphertext becomes the previous one until `now + overlapHours` (0 = none). A second
   * rotation during an overlap retires the then-current secret (one previous secret only).
   */
  async rotate(
    principal: Principal,
    scope: TenantScope,
    input: RotateSecretInput,
    sourceIp: string | null,
  ): Promise<IdempotentResult<RotatedSecretView>> {
    const publicId = parsePublicId(input.webhookId, 'webhookId');
    const key = parseIdempotencyKey(input.idempotencyKey);
    const body = parseBody(RotateSecretBodySchema, input.body);
    const overlapHours = body.overlapHours ?? this.config.WEBHOOK_SECRET_OVERLAP_HOURS_DEFAULT;
    const live: { secret: string | null } = { secret: null };
    const result = await this.idempotency.execute<RotatedSecretView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation: WEBHOOK_OPERATIONS.rotate,
        key,
        resourceId: publicId,
        fingerprint: requestFingerprint({
          operation: WEBHOOK_OPERATIONS.rotate,
          resourceId: publicId,
          body,
        }),
      },
      async (tx) => {
        live.secret = null;
        const row = await this.subscriptions.lock(tx, scope, publicId);
        if (!row) throw webhookNotFound();
        const now = this.now();
        const version = row.secretVersion + 1;
        const issued = this.secrets.issue(scope.organizationId, row.publicId, version);
        const previousExpiresAt =
          overlapHours > 0 ? new Date(now.getTime() + overlapHours * HOUR_MS) : null;
        const changes: SubscriptionChanges = {
          secretCiphertext: issued.ciphertext,
          secretVersion: version,
          secretRotatedAt: now,
          previousSecretCiphertext: previousExpiresAt ? row.secretCiphertext : null,
          previousSecretExpiresAt: previousExpiresAt,
        };
        if (!(await this.subscriptions.update(tx, scope, row.id, row.rowVersion, changes))) {
          throw webhookVersionConflict(row.rowVersion);
        }
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.secretRotated,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: row.publicId,
            sourceIp,
            metadata: {
              version,
              overlapHours,
              previousExpiresAt: previousExpiresAt?.toISOString() ?? null,
            },
          },
          tx,
        );
        live.secret = issued.secret;
        return {
          statusCode: 200,
          body: {
            id: row.publicId,
            secret: null,
            secretVersion: version,
            secretRotatedAt: now.toISOString(),
            previousSecretExpiresAt: previousExpiresAt?.toISOString() ?? null,
          },
        };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
    return withSecret(result, live.secret);
  }

  /**
   * `POST /webhooks/{webhookId}/test` (§6.1): a `webhook.ping` event and a `trigger = test`
   * delivery in one writer transaction; the webhook-worker sends it like any delivery. The
   * subscription must be `active` and the feature enabled.
   */
  async test(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<TestAccepted> {
    const publicId = parsePublicId(rawId, 'webhookId');
    return this.runner.run(
      async (tx) => {
        const row = await this.lockActive(tx, scope, publicId);
        const now = this.now();
        const sourceEventId = randomUUID();
        const built = buildEnvelope({
          type: WEBHOOK_PING_TYPE,
          occurredAt: now,
          organizationPublicId: scopeOrganizationPublicId(principal),
          sourceEventId,
          data: { subscriptionId: row.publicId, requestedAt: now.toISOString() },
        });
        await this.deliveries.insertEvent(tx, scope, {
          eventId: built.envelope.id,
          eventType: WEBHOOK_PING_TYPE,
          occurredAt: now,
          sourceEventId,
          sourceEventType: TEST_SOURCE_EVENT_TYPE,
          severity: 'info',
          payloadJson: built.json,
          payloadSha256: built.sha256,
        });
        const delivery = await this.deliveries.insertDelivery(tx, scope, {
          publicId: uuidv7(now.getTime()),
          subscriptionId: row.id,
          eventId: built.envelope.id,
          eventType: WEBHOOK_PING_TYPE,
          eventOccurredAt: now,
          deliverySeq: 0,
          trigger: 'test',
          now,
        });
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: WEBHOOK_AUDIT.testRequested,
            resourceType: WEBHOOK_RESOURCE_TYPE,
            resourceId: row.publicId,
            sourceIp,
            metadata: { deliveryId: delivery.publicId, eventId: built.envelope.id },
          },
          tx,
        );
        return { deliveryId: delivery.publicId, eventId: built.envelope.id };
      },
      { timeoutMs: WEBHOOK_TX_TIMEOUT_MS },
    );
  }

  // ---- shared rules ------------------------------------------------------------------------

  /** The locked, live subscription that must be active with the feature enabled. */
  async lockActive(tx: Tx, scope: TenantScope, publicId: string): Promise<LockedSubscription> {
    const row = await this.subscriptions.lock(tx, scope, publicId);
    if (!row) throw webhookNotFound();
    await this.requireFeature(tx, scope);
    if (row.status !== 'active') throw webhookNotActive(row.status);
    return row;
  }

  /** `403 webhooks_not_enabled` without the plan feature (writer read, W5). */
  async requireFeature(tx: Tx, scope: TenantScope): Promise<void> {
    if (!(await this.features.isEnabled(scope.organizationId, WEBHOOKS_FEATURE, tx))) {
      throw webhooksNotEnabled();
    }
  }

  private checkUrl(raw: string, requestHost: string | null) {
    const decision = this.urls.check(raw, requestHost);
    if (!decision.allowed) throw webhookUrlNotAllowed(decision.reason);
    return decision;
  }

  /**
   * The filter document to store (null = none): `domainIds` must all be live domains of the
   * scope (`422 webhook_filter_invalid` naming the path, never confirming another tenant's id).
   */
  private async resolveFilters(
    tx: Tx,
    scope: TenantScope,
    filters: SubscriptionFilters | null,
  ): Promise<SubscriptionFilters | null> {
    if (filters === null || Object.keys(filters).length === 0) return null;
    if (filters.domainIds !== undefined) {
      const ids = filters.domainIds.map((id) => id.toLowerCase());
      const found = await this.subscriptions.existingDomainIds(tx, scope, ids);
      const missing = ids.findIndex((id) => !found.has(id));
      if (missing >= 0) throw webhookFilterInvalid(`filters.domainIds.${missing}`);
      return { ...filters, domainIds: ids };
    }
    return filters;
  }
}

/** The live response of create/rotate: the stored body plus the secret, unless replayed. */
export function withSecret<T extends { secret: string | null }>(
  result: IdempotentResult<T>,
  secret: string | null,
): IdempotentResult<T> {
  if (result.replayed || secret === null)
    return { ...result, body: { ...result.body, secret: null } };
  return { ...result, body: { ...result.body, secret } };
}
