import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import {
  Prisma,
  type SmtpConnectorAuthType,
  type SmtpConnectorStatus,
} from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ParsedNetwork } from '../domain/networks';

type Client = Prisma.TransactionClient;

/** Never selects `secret_hash` (D10): the hash is only ever written here. */
const connectorSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  authType: true,
  status: true,
  saslUsername: true,
  secretSetAt: true,
  certFingerprintSha256: true,
  requireTls: true,
  createdAt: true,
  updatedAt: true,
  networks: {
    select: { id: true, cidr: true, ipVersion: true },
    orderBy: [{ ipVersion: 'asc' }, { rangeStart: 'asc' }],
  },
} satisfies Prisma.SmtpConnectorSelect;

export type ConnectorRow = Prisma.SmtpConnectorGetPayload<{ select: typeof connectorSelect }>;

export interface ConnectorListFilter {
  status?: SmtpConnectorStatus;
  authType?: SmtpConnectorAuthType;
}

export interface ConnectorInsert {
  name: string;
  authType: SmtpConnectorAuthType;
  saslUsername: string | null;
  secretHash: string | null;
  secretSetAt: Date | null;
  certFingerprintSha256: string | null;
  requireTls: boolean;
  createdByUserId: bigint | null;
}

export interface ConnectorWrite {
  name?: string;
  status?: SmtpConnectorStatus;
  requireTls?: boolean;
}

/** Which unique key a `P2002` violated (`name`, `username`, `fingerprint`), or null. */
export function connectorUniqueViolation(
  err: unknown,
): 'name' | 'username' | 'fingerprint' | 'other' | null {
  if (!(err instanceof Prisma.PrismaClientKnownRequestError) || err.code !== 'P2002') return null;
  const target = err.meta?.target;
  const text = Array.isArray(target) ? target.join(',') : typeof target === 'string' ? target : '';
  if (text.includes('sasl_username') || text.includes('saslUsername')) return 'username';
  if (text.includes('cert_fingerprint') || text.includes('certFingerprint')) return 'fingerprint';
  if (text.includes('name')) return 'name';
  return 'other';
}

/**
 * MySQL named lock that serializes every change of `smtp_connector_networks` (D10), so the
 * global non-overlap check and the insert are atomic across organizations and replicas.
 */
export const NETWORK_LOCK_NAME = 'smtp_connector_networks';

/**
 * Tenant-scoped access to `smtp_connectors` and `smtp_connector_networks` (step 2.2 D10). Every
 * tenant method takes the scope first and filters by its organization; a connector of another
 * tenant and an unknown id both come back as null. The uniqueness and overlap checks are
 * **global** by design (a username, a certificate and an address range map to at most one
 * connector of one organization) and return booleans only, never another tenant's data.
 */
@Injectable()
export class SmtpConnectorsRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  findByPublicId(
    scope: TenantScope,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<ConnectorRow | null> {
    return client.smtpConnector.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: connectorSelect,
    });
  }

  /** Locks the scope's connector row (`SELECT … FOR UPDATE`) and returns it; null if absent. */
  async lockByPublicId(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<ConnectorRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM smtp_connectors
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId}
      FOR UPDATE`;
    if (rows.length === 0) return null;
    return tx.smtpConnector.findFirst({
      where: tenantWhere(scope, { id: rows[0]!.id }),
      select: connectorSelect,
    });
  }

  /** The scope's connectors, newest first (reader). */
  list(
    scope: TenantScope,
    filter: ConnectorListFilter,
    page: { take: number; beforeId?: bigint },
  ): Promise<ConnectorRow[]> {
    return this.reader.client.smtpConnector.findMany({
      where: tenantWhere(scope, {
        ...(filter.status && { status: filter.status }),
        ...(filter.authType && { authType: filter.authType }),
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
      }),
      select: connectorSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  count(tx: Client, scope: TenantScope): Promise<number> {
    return tx.smtpConnector.count({ where: tenantWhere(scope) });
  }

  /** True when another connector of the scope already has this name. */
  async nameTaken(
    tx: Client,
    scope: TenantScope,
    name: string,
    exceptId?: bigint,
  ): Promise<boolean> {
    const row = await tx.smtpConnector.findFirst({
      where: tenantWhere(scope, {
        name,
        ...(exceptId !== undefined && { id: { not: exceptId } }),
      }),
      select: { id: true },
    });
    return row !== null;
  }

  /** Global: true when any connector (any organization) has this SASL username. */
  async usernameTaken(tx: Client, username: string): Promise<boolean> {
    const row = await tx.smtpConnector.findUnique({
      where: { saslUsername: username },
      select: { id: true },
    });
    return row !== null;
  }

  /** Global: true when any connector (any organization) pins this certificate fingerprint. */
  async fingerprintTaken(tx: Client, fingerprint: string): Promise<boolean> {
    const row = await tx.smtpConnector.findUnique({
      where: { certFingerprintSha256: fingerprint },
      select: { id: true },
    });
    return row !== null;
  }

  create(
    tx: Client,
    scope: TenantScope,
    data: ConnectorInsert,
  ): Promise<{ id: bigint; publicId: string }> {
    return tx.smtpConnector.create({
      data: { organizationId: scope.organizationId, ...data },
      select: { id: true, publicId: true },
    });
  }

  async update(tx: Client, scope: TenantScope, id: bigint, data: ConnectorWrite): Promise<void> {
    await tx.smtpConnector.updateMany({ where: tenantWhere(scope, { id }), data });
  }

  /** Replaces the SASL secret hash (rotation); `updated_at` changes with it. */
  async setSecret(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    secretHash: string,
    at: Date,
  ): Promise<void> {
    await tx.smtpConnector.updateMany({
      where: tenantWhere(scope, { id, authType: 'sasl' as SmtpConnectorAuthType }),
      data: { secretHash, secretSetAt: at },
    });
  }

  /** Hard delete; networks cascade (D10, §4.1). */
  async delete(tx: Client, scope: TenantScope, id: bigint): Promise<boolean> {
    const { count } = await tx.smtpConnector.deleteMany({ where: tenantWhere(scope, { id }) });
    return count === 1;
  }

  /** Touches `updated_at` (network-only changes invalidate the adapter's cached view). */
  async touch(tx: Client, scope: TenantScope, id: bigint, at: Date): Promise<void> {
    await tx.smtpConnector.updateMany({
      where: tenantWhere(scope, { id }),
      data: { updatedAt: at },
    });
  }

  // ---- Networks (global non-overlap, D10) ------------------------------------------------

  /**
   * `GET_LOCK(NETWORK_LOCK_NAME, timeout)` on the transaction's connection. True when acquired,
   * false on timeout (callers answer `503`). Session-scoped: always release it with
   * `releaseNetworkLock` on the same transaction.
   */
  async acquireNetworkLock(tx: Client, timeoutSeconds: number): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ acquired: bigint | number | null }>>`
      SELECT GET_LOCK(${NETWORK_LOCK_NAME}, ${timeoutSeconds}) AS acquired`;
    return Number(rows[0]?.acquired ?? 0) === 1;
  }

  async releaseNetworkLock(tx: Client): Promise<void> {
    await tx.$queryRaw`SELECT RELEASE_LOCK(${NETWORK_LOCK_NAME}) AS released`;
  }

  /**
   * Global: true when any stored network (any connector, any organization) shares an address
   * with `network`. Stored ranges never overlap, so the only candidate is the range with the
   * greatest start ≤ the new end (index `(ip_version, range_start)`). A locking read (`FOR
   * SHARE`): it sees the latest committed rows and waits for uncommitted ones, never a stale
   * snapshot.
   */
  async overlapsExisting(
    tx: Client,
    network: Pick<ParsedNetwork, 'ipVersion' | 'rangeStart' | 'rangeEnd'>,
  ): Promise<boolean> {
    const rows = await tx.$queryRaw<Array<{ rangeEnd: Uint8Array }>>`
      SELECT range_end AS rangeEnd FROM smtp_connector_networks
      WHERE ip_version = ${network.ipVersion} AND range_start <= ${network.rangeEnd}
      ORDER BY range_start DESC
      LIMIT 1
      FOR SHARE`;
    const candidate = rows[0];
    if (!candidate) return false;
    return Buffer.compare(Buffer.from(candidate.rangeEnd), network.rangeStart) >= 0;
  }

  async deleteNetworks(tx: Client, scope: TenantScope, connectorId: bigint): Promise<void> {
    await tx.smtpConnectorNetwork.deleteMany({ where: tenantWhere(scope, { connectorId }) });
  }

  async insertNetworks(
    tx: Client,
    scope: TenantScope,
    connectorId: bigint,
    networks: readonly ParsedNetwork[],
  ): Promise<void> {
    if (networks.length === 0) return;
    await tx.smtpConnectorNetwork.createMany({
      data: networks.map((n) => ({
        organizationId: scope.organizationId,
        connectorId,
        cidr: n.cidr,
        ipVersion: n.ipVersion,
        rangeStart: new Uint8Array(n.rangeStart),
        rangeEnd: new Uint8Array(n.rangeEnd),
      })),
    });
  }
}
