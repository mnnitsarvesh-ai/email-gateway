import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import {
  type AtoProviderIntegration,
  type AtoProviderStream,
  Prisma,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { assertEcho } from '../../../http/listing/echo-check';

type Tx = Prisma.TransactionClient;
/** The replica (default) or the writer transaction (read-after-write). */
export type Db = Prisma.TransactionClient;

export type IntegrationRow = AtoProviderIntegration;
export type StreamRow = AtoProviderStream;

/** Writable columns of an integration (the generated `active_marker` is never written). */
export type IntegrationWrite = Omit<
  Prisma.AtoProviderIntegrationUncheckedCreateInput,
  'id' | 'publicId' | 'organizationId' | 'activeMarker' | 'createdAt' | 'updatedAt'
>;
export type IntegrationUpdate = Omit<
  Prisma.AtoProviderIntegrationUncheckedUpdateInput,
  'id' | 'publicId' | 'organizationId' | 'activeMarker' | 'createdAt' | 'updatedAt'
>;
export type StreamWrite = Omit<
  Prisma.AtoProviderStreamUncheckedCreateInput,
  'id' | 'organizationId' | 'integrationId' | 'createdAt' | 'updatedAt'
>;
export type StreamUpdate = Omit<
  Prisma.AtoProviderStreamUncheckedUpdateInput,
  'id' | 'organizationId' | 'integrationId' | 'stream' | 'createdAt' | 'updatedAt'
>;

const NOT_DISABLED = ['active', 'paused', 'error'] as const;

/**
 * Identity-provider integrations and their stream rows (step 8.5 §4.1, §6, D4): reads on the
 * replica (or the writer transaction a mutation passes, for read-after-write), writes only inside
 * the caller's writer transaction. Every query is scoped by the caller's `TenantScope` and every
 * read echo-checked, except `directoryInUse`, the platform-wide uniqueness probe of ADR-0084
 * decision 3, which answers a boolean and never returns another organization's row.
 */
@Injectable()
export class AtoProvidersRepository {
  constructor(private readonly replica: PrismaReadService) {}

  private db(db?: Db): Db {
    return db ?? this.replica.client;
  }

  /**
   * The client the connection directory reads with (`AtoConnectionDirectory`): the writer
   * transaction when one is passed, the replica otherwise.
   */
  readClient(db?: Db): Db {
    return this.db(db);
  }

  // ===================================================================== reads

  /**
   * The organization's integrations: every non-disabled one (≤ ATO_IDP_MAX_INTEGRATIONS_PER_ORG,
   * oldest first), then, when asked, the newest `disabledLimit` disabled ones. Uses the index
   * `(organization_id, status, id)`.
   */
  async list(
    scope: TenantScope,
    input: { includeDisabled: boolean; disabledLimit: number; activeLimit: number },
    db?: Db,
  ): Promise<IntegrationRow[]> {
    const client = this.db(db);
    const [active, disabled] = await Promise.all([
      client.atoProviderIntegration.findMany({
        where: tenantWhere(scope, { status: { in: [...NOT_DISABLED] } }),
        orderBy: { id: 'asc' },
        take: input.activeLimit,
      }),
      input.includeDisabled
        ? client.atoProviderIntegration.findMany({
            where: tenantWhere(scope, { status: 'disabled' as const }),
            orderBy: { id: 'desc' },
            take: input.disabledLimit,
          })
        : [],
    ]);
    const rows = [...active, ...disabled];
    assertEcho('ato.providers.list', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** One integration by public id (null for none or another organization's). */
  async findByPublicId(
    scope: TenantScope,
    publicId: string,
    db?: Db,
  ): Promise<IntegrationRow | null> {
    const row = await this.db(db).atoProviderIntegration.findFirst({
      where: tenantWhere(scope, { publicId }),
    });
    if (row === null) return null;
    assertEcho('ato.providers.get', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /** Integrations by internal id (mailbox state joins). */
  async findByIds(scope: TenantScope, ids: readonly bigint[], db?: Db): Promise<IntegrationRow[]> {
    if (ids.length === 0) return [];
    const rows = await this.db(db).atoProviderIntegration.findMany({
      where: tenantWhere(scope, { id: { in: [...ids] } }),
      orderBy: { id: 'asc' },
    });
    assertEcho('ato.providers.by_ids', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** The stream rows of the integrations (7 per integration at most). */
  async streams(
    scope: TenantScope,
    integrationIds: readonly bigint[],
    db?: Db,
  ): Promise<StreamRow[]> {
    if (integrationIds.length === 0) return [];
    const rows = await this.db(db).atoProviderStream.findMany({
      where: tenantWhere(scope, { integrationId: { in: [...integrationIds] } }),
      orderBy: [{ integrationId: 'asc' }, { id: 'asc' }],
      take: integrationIds.length * 7,
    });
    assertEcho('ato.providers.streams', rows, { organizationId: scope.organizationId });
    return rows;
  }

  /** Non-disabled integrations of the organization (count, settings section, bound connections). */
  async nonDisabled(scope: TenantScope, db?: Db): Promise<IntegrationRow[]> {
    const rows = await this.db(db).atoProviderIntegration.findMany({
      where: tenantWhere(scope, { status: { in: [...NOT_DISABLED] } }),
      orderBy: { id: 'asc' },
      take: 100,
    });
    assertEcho('ato.providers.non_disabled', rows, { organizationId: scope.organizationId });
    return rows;
  }

  // ==================================================================== writes

  /**
   * Serializes the binding decisions of one organization (D4: one integration per connection and
   * at most ATO_IDP_MAX_INTEGRATIONS_PER_ORG): a row lock on the organization. Under READ
   * COMMITTED a `FOR UPDATE` of the (possibly absent) integration rows takes no gap lock, so the
   * organization row is the lock that always exists.
   */
  async lockOrganization(tx: Tx, scope: TenantScope): Promise<void> {
    await tx.$queryRaw`SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
  }

  /** The integration of the organization by public id under a row lock (null when absent). */
  async lockByPublicId(
    tx: Tx,
    scope: TenantScope,
    publicId: string,
  ): Promise<IntegrationRow | null> {
    const ids = await tx.$queryRaw<{ id: bigint }[]>`
      SELECT id FROM ato_provider_integrations
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    const id = ids[0]?.id;
    if (id === undefined) return null;
    const row = await tx.atoProviderIntegration.findUnique({ where: { id: BigInt(id) } });
    if (row === null) return null;
    assertEcho('ato.providers.lock', [row], { organizationId: scope.organizationId, publicId });
    return row;
  }

  /** The organization's row of a binding key (any status: the key is unique per organization). */
  async byBindingKey(
    tx: Tx,
    scope: TenantScope,
    bindingKey: string,
  ): Promise<IntegrationRow | null> {
    const row = await tx.atoProviderIntegration.findFirst({
      where: tenantWhere(scope, { bindingKey }),
    });
    if (row !== null)
      assertEcho('ato.providers.binding', [row], { organizationId: scope.organizationId });
    return row;
  }

  /**
   * Whether a non-disabled integration of ANY organization monitors the directory (ADR-0084
   * decision 3). Answers only a boolean: the other organization is never disclosed.
   */
  async directoryInUse(tx: Tx, provider: string, directoryRefHash: string): Promise<boolean> {
    const rows = await tx.$queryRaw<{ n: bigint }[]>`
      SELECT COUNT(*) AS n FROM ato_provider_integrations
      WHERE provider = ${provider} AND directory_ref_hash = ${directoryRefHash}
        AND active_marker = 1`;
    return Number(rows[0]?.n ?? 0) > 0;
  }

  async create(tx: Tx, scope: TenantScope, data: IntegrationWrite): Promise<IntegrationRow> {
    return tx.atoProviderIntegration.create({
      data: { ...data, organizationId: scope.organizationId },
    });
  }

  /** Updates one integration of the organization and returns the new row. */
  async update(
    tx: Tx,
    scope: TenantScope,
    id: bigint,
    data: IntegrationUpdate,
  ): Promise<IntegrationRow> {
    const changed = await tx.atoProviderIntegration.updateMany({
      where: tenantWhere(scope, { id }),
      data,
    });
    if (changed.count !== 1) throw new Error('ato provider integration update matched no row');
    return tx.atoProviderIntegration.findUniqueOrThrow({ where: { id } });
  }

  /** Replaces the stream rows of an integration (bind and re-bind). */
  async replaceStreams(
    tx: Tx,
    scope: TenantScope,
    integrationId: bigint,
    rows: readonly StreamWrite[],
  ): Promise<void> {
    await tx.atoProviderStream.deleteMany({ where: tenantWhere(scope, { integrationId }) });
    await tx.atoProviderStream.createMany({
      data: rows.map((r) => ({ ...r, organizationId: scope.organizationId, integrationId })),
    });
  }

  /** Updates one stream row of the integration (bumps `row_version`, so a runner's CAS retries). */
  async updateStream(
    tx: Tx,
    scope: TenantScope,
    integrationId: bigint,
    stream: StreamRow['stream'],
    data: StreamUpdate,
  ): Promise<void> {
    await tx.atoProviderStream.updateMany({
      where: tenantWhere(scope, { integrationId, stream }),
      data: { ...data, rowVersion: { increment: 1 } },
    });
  }

  /**
   * Provider actions of the integration that are still in flight (`approved`, `executing`,
   * `rollback_requested`), locked, oldest first: removal ends them `integration_disabled`.
   */
  async pendingProviderActions(
    tx: Tx,
    scope: TenantScope,
    integrationId: bigint,
  ): Promise<Array<{ id: bigint; status: string }>> {
    const rows = await tx.$queryRaw<{ id: bigint; status: string; organization_id: bigint }[]>`
      SELECT id, status, organization_id FROM ato_response_actions
      WHERE organization_id = ${scope.organizationId} AND integration_id = ${integrationId}
        AND status IN ('approved', 'executing', 'rollback_requested')
      ORDER BY id
      LIMIT 500
      FOR UPDATE`;
    return rows
      .filter((r) => BigInt(r.organization_id) === scope.organizationId)
      .map((r) => ({ id: BigInt(r.id), status: r.status }));
  }
}

/** The index (or columns) a P2002 unique-key violation names, as one string ('' otherwise). */
function uniqueTarget(error: unknown): string | null {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') {
    return null;
  }
  const target = (error.meta as { target?: unknown } | undefined)?.target;
  if (Array.isArray(target)) return target.filter((t) => typeof t === 'string').join(',');
  return typeof target === 'string' ? target : '';
}

/** True for a unique-key violation of the directory key (a concurrent bind of the directory). */
export function isDirectoryKeyViolation(error: unknown): boolean {
  const target = uniqueTarget(error);
  return target !== null && (target.includes('directory') || target.includes('directoryRefHash'));
}

/** True for a unique-key violation of `(organization_id, binding_key)`. */
export function isBindingKeyViolation(error: unknown): boolean {
  const target = uniqueTarget(error);
  return target !== null && (target.includes('binding_key') || target.includes('bindingKey'));
}
