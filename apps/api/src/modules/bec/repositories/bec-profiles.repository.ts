import { Injectable } from '@nestjs/common';
import { PrismaReadService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { InconsistentBecReadError } from '../bec.errors';

type Client = Prisma.TransactionClient;

/**
 * The organization row, `FOR UPDATE`, for the rest of the transaction: serializes the BEC
 * writes of one tenant whose per-tenant caps or unique keys are checked before the insert
 * (profiles, trusted senders, feedback suppressions). Echo-checked.
 */
export async function lockOrganizationRow(tx: Client, scope: TenantScope): Promise<void> {
  const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
    SELECT id FROM organizations WHERE id = ${scope.organizationId} FOR UPDATE`;
  if (rows.length !== 1 || BigInt(rows[0]!.id) !== scope.organizationId) {
    throw new InconsistentBecReadError('organization_lock');
  }
}

const executiveSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  displayName: true,
  normalizedName: true,
  aliases: true,
  knownAddresses: true,
  title: true,
  enabled: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { publicId: true } },
  updatedBy: { select: { publicId: true } },
} satisfies Prisma.BecExecutiveProfileSelect;

export type ExecutiveRow = Prisma.BecExecutiveProfileGetPayload<{
  select: typeof executiveSelect;
}>;

const vendorSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  name: true,
  normalizedName: true,
  aliases: true,
  domains: true,
  knownSenders: true,
  paymentChangeSensitive: true,
  enabled: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { publicId: true } },
  updatedBy: { select: { publicId: true } },
} satisfies Prisma.BecVendorProfileSelect;

export type VendorRow = Prisma.BecVendorProfileGetPayload<{ select: typeof vendorSelect }>;

const trustedSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  kind: true,
  value: true,
  reason: true,
  expiresAt: true,
  version: true,
  createdAt: true,
  updatedAt: true,
  createdBy: { select: { publicId: true } },
} satisfies Prisma.BecTrustedSenderSelect;

export type TrustedSenderRow = Prisma.BecTrustedSenderGetPayload<{ select: typeof trustedSelect }>;

export interface ExecutiveData {
  displayName: string;
  normalizedName: string;
  aliases: string[];
  knownAddresses: string[];
  title: string | null;
  enabled: boolean;
}

export interface VendorData {
  name: string;
  normalizedName: string;
  aliases: string[];
  domains: string[];
  knownSenders: string[];
  paymentChangeSensitive: boolean;
  enabled: boolean;
}

export interface TrustedSenderData {
  kind: 'address' | 'domain';
  value: string;
  reason: string;
  expiresAt: Date | null;
}

export interface ProfilePage {
  take: number;
  beforeId?: bigint;
  enabled?: boolean;
}

/** Throws when a writer read returned a row of another organization or key (4.2 §6). */
function echo<T extends { organizationId: bigint }>(
  row: T | null,
  scope: TenantScope,
  read: string,
  matches: (row: T) => boolean,
): T | null {
  if (row !== null && (row.organizationId !== scope.organizationId || !matches(row))) {
    throw new InconsistentBecReadError(read);
  }
  return row;
}

/**
 * Tenant-scoped access to the BEC executive profiles, vendor profiles and trusted senders (step
 * 4.4 B7, B18). Lists and single reads use the replica (`PrismaReadService`, writer fallback above
 * the lag threshold); every read that decides a write runs on the writer transaction the service
 * passes, is locked (`FOR UPDATE`) and echo-checked (organization and key); every query matches
 * the scope's organization, so another tenant's rows are never read or written.
 */
@Injectable()
export class BecProfilesRepository {
  constructor(private readonly reader: PrismaReadService) {}

  private get db() {
    return this.reader.client;
  }

  /**
   * Serializes the creates of one organization (the per-tenant caps are counted under this
   * lock): the organization row, `FOR UPDATE`, for the rest of the transaction.
   */
  lockOrganization(tx: Client, scope: TenantScope): Promise<void> {
    return lockOrganizationRow(tx, scope);
  }

  // ------------------------------------------------------------------------------- executives

  listExecutives(scope: TenantScope, page: ProfilePage): Promise<ExecutiveRow[]> {
    return this.db.becExecutiveProfile.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.enabled !== undefined && { enabled: page.enabled }),
      }),
      select: executiveSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  findExecutive(scope: TenantScope, publicId: string): Promise<ExecutiveRow | null> {
    return this.db.becExecutiveProfile.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: executiveSelect,
    });
  }

  async findExecutiveForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<ExecutiveRow | null> {
    await tx.$queryRaw`SELECT id FROM bec_executive_profiles
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.becExecutiveProfile.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: executiveSelect,
    });
    return echo(row, scope, 'executive', (r) => r.publicId === publicId);
  }

  async findExecutiveByName(
    tx: Client,
    scope: TenantScope,
    normalizedName: string,
  ): Promise<ExecutiveRow | null> {
    const row = await tx.becExecutiveProfile.findFirst({
      where: tenantWhere(scope, { normalizedName }),
      select: executiveSelect,
    });
    return echo(row, scope, 'executive_name', (r) => r.normalizedName === normalizedName);
  }

  countExecutives(tx: Client, scope: TenantScope): Promise<number> {
    return tx.becExecutiveProfile.count({ where: tenantWhere(scope) });
  }

  createExecutive(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: ExecutiveData,
    userId: bigint | null,
  ): Promise<ExecutiveRow> {
    return tx.becExecutiveProfile.create({
      data: {
        ...data,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: executiveSelect,
    });
  }

  /** Compare-and-set on `version`; false when the version moved. */
  async updateExecutive(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: ExecutiveData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.becExecutiveProfile.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: { ...data, updatedByUserId: userId, version: { increment: 1 } },
    });
    return count === 1;
  }

  async deleteExecutive(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.becExecutiveProfile.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async executiveById(tx: Client, scope: TenantScope, id: bigint): Promise<ExecutiveRow> {
    const row = await tx.becExecutiveProfile.findFirst({
      where: tenantWhere(scope, { id }),
      select: executiveSelect,
    });
    const checked = echo(row, scope, 'executive_id', (r) => r.id === id);
    if (checked === null) throw new InconsistentBecReadError('executive_id');
    return checked;
  }

  // ---------------------------------------------------------------------------------- vendors

  listVendors(scope: TenantScope, page: ProfilePage): Promise<VendorRow[]> {
    return this.db.becVendorProfile.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.enabled !== undefined && { enabled: page.enabled }),
      }),
      select: vendorSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  findVendor(scope: TenantScope, publicId: string): Promise<VendorRow | null> {
    return this.db.becVendorProfile.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: vendorSelect,
    });
  }

  async findVendorForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<VendorRow | null> {
    await tx.$queryRaw`SELECT id FROM bec_vendor_profiles
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.becVendorProfile.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: vendorSelect,
    });
    return echo(row, scope, 'vendor', (r) => r.publicId === publicId);
  }

  async findVendorByName(
    tx: Client,
    scope: TenantScope,
    normalizedName: string,
  ): Promise<VendorRow | null> {
    const row = await tx.becVendorProfile.findFirst({
      where: tenantWhere(scope, { normalizedName }),
      select: vendorSelect,
    });
    return echo(row, scope, 'vendor_name', (r) => r.normalizedName === normalizedName);
  }

  countVendors(tx: Client, scope: TenantScope): Promise<number> {
    return tx.becVendorProfile.count({ where: tenantWhere(scope) });
  }

  createVendor(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: VendorData,
    userId: bigint | null,
  ): Promise<VendorRow> {
    return tx.becVendorProfile.create({
      data: {
        ...data,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
        updatedByUserId: userId,
      },
      select: vendorSelect,
    });
  }

  async updateVendor(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: VendorData,
    userId: bigint | null,
  ): Promise<boolean> {
    const { count } = await tx.becVendorProfile.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: { ...data, updatedByUserId: userId, version: { increment: 1 } },
    });
    return count === 1;
  }

  async deleteVendor(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.becVendorProfile.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async vendorById(tx: Client, scope: TenantScope, id: bigint): Promise<VendorRow> {
    const row = await tx.becVendorProfile.findFirst({
      where: tenantWhere(scope, { id }),
      select: vendorSelect,
    });
    const checked = echo(row, scope, 'vendor_id', (r) => r.id === id);
    if (checked === null) throw new InconsistentBecReadError('vendor_id');
    return checked;
  }

  // -------------------------------------------------------------------------- trusted senders

  listTrustedSenders(
    scope: TenantScope,
    page: { take: number; beforeId?: bigint; kind?: 'address' | 'domain' },
  ): Promise<TrustedSenderRow[]> {
    return this.db.becTrustedSender.findMany({
      where: tenantWhere(scope, {
        ...(page.beforeId !== undefined && { id: { lt: page.beforeId } }),
        ...(page.kind !== undefined && { kind: page.kind }),
      }),
      select: trustedSelect,
      orderBy: { id: 'desc' },
      take: page.take,
    });
  }

  async findTrustedForUpdate(
    tx: Client,
    scope: TenantScope,
    publicId: string,
  ): Promise<TrustedSenderRow | null> {
    await tx.$queryRaw`SELECT id FROM bec_trusted_senders
      WHERE organization_id = ${scope.organizationId} AND public_id = ${publicId} FOR UPDATE`;
    const row = await tx.becTrustedSender.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: trustedSelect,
    });
    return echo(row, scope, 'trusted_sender', (r) => r.publicId === publicId);
  }

  async findTrustedByValue(
    tx: Client,
    scope: TenantScope,
    kind: 'address' | 'domain',
    value: string,
  ): Promise<TrustedSenderRow | null> {
    const row = await tx.becTrustedSender.findFirst({
      where: tenantWhere(scope, { kind, value }),
      select: trustedSelect,
    });
    return echo(row, scope, 'trusted_value', (r) => r.kind === kind && r.value === value);
  }

  countTrustedSenders(tx: Client, scope: TenantScope): Promise<number> {
    return tx.becTrustedSender.count({ where: tenantWhere(scope) });
  }

  createTrustedSender(
    tx: Client,
    scope: TenantScope,
    publicId: string,
    data: TrustedSenderData,
    userId: bigint | null,
  ): Promise<TrustedSenderRow> {
    return tx.becTrustedSender.create({
      data: {
        ...data,
        publicId,
        organizationId: scope.organizationId,
        createdByUserId: userId,
      },
      select: trustedSelect,
    });
  }

  async updateTrustedSender(
    tx: Client,
    scope: TenantScope,
    id: bigint,
    expectedVersion: number,
    data: { reason: string; expiresAt: Date | null },
  ): Promise<boolean> {
    const { count } = await tx.becTrustedSender.updateMany({
      where: tenantWhere(scope, { id, version: expectedVersion }),
      data: { ...data, version: { increment: 1 } },
    });
    return count === 1;
  }

  async deleteTrustedSender(tx: Client, scope: TenantScope, id: bigint): Promise<void> {
    await tx.becTrustedSender.deleteMany({ where: tenantWhere(scope, { id }) });
  }

  async trustedById(tx: Client, scope: TenantScope, id: bigint): Promise<TrustedSenderRow> {
    const row = await tx.becTrustedSender.findFirst({
      where: tenantWhere(scope, { id }),
      select: trustedSelect,
    });
    const checked = echo(row, scope, 'trusted_id', (r) => r.id === id);
    if (checked === null) throw new InconsistentBecReadError('trusted_id');
    return checked;
  }
}
