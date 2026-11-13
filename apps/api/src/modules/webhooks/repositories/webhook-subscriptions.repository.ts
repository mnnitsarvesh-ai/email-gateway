import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import { Prisma, type WebhookStatus } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho, InconsistentReadError } from '../../../http/listing/echo-check';
import { clampTake } from '../../tenant-data/page';

type Tx = Prisma.TransactionClient;

/** Every column the API represents. Never the secret ciphertexts (§6.1). */
export const subscriptionSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  description: true,
  url: true,
  eventTypes: true,
  filters: true,
  status: true,
  disabledReason: true,
  disabledAt: true,
  maxConcurrency: true,
  secretVersion: true,
  secretRotatedAt: true,
  previousSecretExpiresAt: true,
  consecutiveFailures: true,
  failingSince: true,
  lastSuccessAt: true,
  lastFailureAt: true,
  deletedAt: true,
  rowVersion: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { publicId: true } },
} satisfies Prisma.WebhookSubscriptionSelect;

export type SubscriptionRow = Prisma.WebhookSubscriptionGetPayload<{
  select: typeof subscriptionSelect;
}>;

/** The locked row of a mutation: the representation plus the current secret ciphertext. */
export type LockedSubscription = SubscriptionRow & { secretCiphertext: string };

export interface NewSubscription {
  publicId: string;
  name: string;
  description: string | null;
  url: string;
  eventTypes: string[];
  filters: Prisma.InputJsonValue | null;
  status: WebhookStatus;
  maxConcurrency: number | null;
  secretCiphertext: string;
  createdByUserId: bigint | null;
}

export interface SubscriptionChanges {
  name?: string;
  description?: string | null;
  url?: string;
  eventTypes?: string[];
  filters?: Prisma.InputJsonValue | null;
  status?: WebhookStatus;
  maxConcurrency?: number | null;
  consecutiveFailures?: number;
  failingSince?: Date | null;
  disabledReason?: string | null;
  disabledAt?: Date | null;
  deletedAt?: Date | null;
  secretCiphertext?: string;
  secretVersion?: number;
  secretRotatedAt?: Date;
  previousSecretCiphertext?: string | null;
  previousSecretExpiresAt?: Date | null;
}

/**
 * `webhook_subscriptions` of a scope (step 6.2 W5–W7, D15): replica reads for the list and the
 * detail (keyset `id` desc over `webhook_subscriptions_organization_id_id_idx`), writer reads and
 * writes inside the caller's transaction (`SELECT … FOR UPDATE` before every mutation, CAS on
 * `row_version`). Every returned row is echo-checked (organization and key).
 */
@Injectable()
export class WebhookSubscriptionsRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /** One page newest first (ids below `beforeId`), of the given statuses. */
  async list(
    scope: TenantScope,
    page: { take: number; beforeId?: bigint | undefined; statuses: readonly WebhookStatus[] },
  ): Promise<SubscriptionRow[]> {
    const rows = await this.db.webhookSubscription.findMany({
      where: tenantWhere(scope, {
        status: { in: [...page.statuses] },
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: subscriptionSelect,
      orderBy: { id: 'desc' },
      take: clampTake(page.take),
    });
    assertEcho('webhooks.list', rows, {
      organizationId: scope.organizationId,
      status: [...page.statuses],
    });
    return rows;
  }

  /** The scope's subscription by public id on the replica (deleted ones included), or null. */
  async find(scope: TenantScope, publicId: string): Promise<SubscriptionRow | null> {
    const row = await this.db.webhookSubscription.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: subscriptionSelect,
    });
    if (!row) return null;
    assertEcho('webhooks.find', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  // ---- Writer (inside the caller's transaction) -------------------------------------------

  /** Non-deleted subscriptions of the scope (the W5 cap; under the organization row lock). */
  countLive(tx: Tx, scope: TenantScope): Promise<number> {
    return tx.webhookSubscription.count({
      where: tenantWhere(scope, { status: { not: 'deleted' as const } }),
    });
  }

  /** The public ids among `publicIds` that are live domains of the scope (filter resolution). */
  async existingDomainIds(
    tx: Tx,
    scope: TenantScope,
    publicIds: readonly string[],
  ): Promise<Set<string>> {
    if (publicIds.length === 0) return new Set();
    const rows = await tx.domain.findMany({
      where: tenantWhere(scope, { publicId: { in: [...publicIds] }, deletedAt: null }),
      select: { publicId: true, organizationId: true },
    });
    assertEcho('webhooks.domains', rows, {
      organizationId: scope.organizationId,
      publicId: [...publicIds],
    });
    return new Set(rows.map((r) => r.publicId));
  }

  async create(tx: Tx, scope: TenantScope, data: NewSubscription): Promise<SubscriptionRow> {
    const row = await tx.webhookSubscription.create({
      data: {
        organizationId: scope.organizationId,
        publicId: data.publicId,
        name: data.name,
        description: data.description,
        url: data.url,
        eventTypes: data.eventTypes,
        filters: data.filters ?? Prisma.DbNull,
        status: data.status,
        maxConcurrency: data.maxConcurrency,
        secretCiphertext: data.secretCiphertext,
        secretVersion: 1,
        createdByUserId: data.createdByUserId,
      },
      select: subscriptionSelect,
    });
    assertEcho('webhooks.create', [row], {
      organizationId: scope.organizationId,
      publicId: data.publicId,
    });
    return row;
  }

  /** `SELECT … FOR UPDATE` of the scope's live (non-deleted) subscription, or null. */
  async lock(tx: Tx, scope: TenantScope, publicId: string): Promise<LockedSubscription | null> {
    const locked = await tx.$queryRaw<Array<{ id: bigint; organization_id: bigint }>>`
      SELECT id, organization_id FROM webhook_subscriptions
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
        AND status <> 'deleted'
      FOR UPDATE`;
    if (locked.length === 0) return null;
    assertEcho(
      'webhooks.lock',
      locked.map((r) => ({ organizationId: BigInt(r.organization_id), id: BigInt(r.id) })),
      { organizationId: scope.organizationId },
    );
    const row = await tx.webhookSubscription.findFirst({
      where: tenantWhere(scope, { id: BigInt(locked[0]!.id) }),
      select: { ...subscriptionSelect, secretCiphertext: true },
    });
    if (!row || row.status === 'deleted') throw new InconsistentReadError('webhooks.locked');
    assertEcho('webhooks.locked', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /**
   * CAS update of a locked row: applies `changes`, `row_version + 1`. False when the row
   * changed meanwhile (never happens under the lock; kept as the CAS guard).
   */
  async update(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    rowVersion: number,
    changes: SubscriptionChanges,
  ): Promise<boolean> {
    const { filters, ...rest } = changes;
    const result = await tx.webhookSubscription.updateMany({
      where: tenantWhere(scope, { id, rowVersion }),
      data: {
        ...rest,
        ...(filters !== undefined && { filters: filters ?? Prisma.DbNull }),
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  /** The scope's row by internal id on the writer (read-after-write), echo-checked. */
  async reload(tx: Tx, scope: TenantScope, id: bigint): Promise<SubscriptionRow> {
    const row = await tx.webhookSubscription.findFirst({
      where: tenantWhere(scope, { id }),
      select: subscriptionSelect,
    });
    if (!row) throw new InconsistentReadError('webhooks.reload');
    assertEcho('webhooks.reload', [row], { organizationId: scope.organizationId, id });
    return row;
  }
}
