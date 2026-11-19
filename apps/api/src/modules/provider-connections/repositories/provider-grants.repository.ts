import { Injectable } from '@nestjs/common';
import type { Prisma, ProviderAuthMethod, ProviderGrantStatus } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { type GrantRow, grantSelect } from './provider-connections.repository';

type Tx = Prisma.TransactionClient;

/** Columns a grant write may set (never read back: the ciphertext is write-only for the api). */
export interface GrantWrite {
  profileVersion?: number;
  authMethod?: ProviderAuthMethod;
  status?: ProviderGrantStatus;
  clientId?: string | null;
  subjectEmail?: string | null;
  credentialCiphertext?: string | null;
  credentialKeyId?: string | null;
  credentialVersion?: number;
  credentialFingerprint?: string | null;
  credentialSetAt?: Date | null;
  credentialExpiresAt?: Date | null;
  requestedPermissions?: Prisma.InputJsonValue;
  observedPermissions?: null;
  missingPermissions?: null;
  excessPermissions?: null;
  claimedTenantId?: string | null;
  consentedAt?: Date | null;
  consentedByUserId?: bigint | null;
  verifyRequestedAt?: Date | null;
  verifiedAt?: Date | null;
  verifyClaimedUntil?: null;
  lastErrorCode?: string | null;
  consecutiveFailures?: number;
}

/** A consent state row the completion route locks (D3.3). */
export interface ConsentStateRow {
  id: bigint;
  connectionId: bigint;
  grantId: bigint;
  userId: bigint;
  expiresAt: Date;
  usedAt: Date | null;
}

/**
 * Tenant-scoped writes of `provider_connection_grants` and `provider_consent_states` (step 8.2
 * D2, D3, D5) inside the caller's writer transaction. The credential ciphertext is written here
 * and never selected by the api (ADR-0077).
 */
@Injectable()
export class ProviderGrantsRepository {
  /** Locks the connection's grant of `profile` (`FOR UPDATE`); null when there is none. */
  async lockGrant(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
    profile: string,
  ): Promise<GrantRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM provider_connection_grants
      WHERE organization_id = ${scope.organizationId} AND connection_id = ${connectionId}
        AND profile = ${profile}
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    return tx.providerConnectionGrant.findFirst({
      where: tenantWhere(scope, { id }),
      select: grantSelect,
    });
  }

  create(
    tx: Tx,
    scope: TenantScope,
    data: {
      publicId: string;
      connectionId: bigint;
      profile: string;
      profileVersion: number;
      authMethod: ProviderAuthMethod;
      clientId: string | null;
      requestedPermissions: string[];
    },
  ): Promise<GrantRow> {
    return tx.providerConnectionGrant.create({
      data: { organizationId: scope.organizationId, status: 'pending_consent', ...data },
      select: grantSelect,
    });
  }

  /** CAS update on `row_version`; returns the updated row, or null when the version moved. */
  async update(
    tx: Tx,
    scope: TenantScope,
    grant: Pick<GrantRow, 'id' | 'rowVersion'>,
    data: GrantWrite,
  ): Promise<GrantRow | null> {
    const { count } = await tx.providerConnectionGrant.updateMany({
      where: tenantWhere(scope, { id: grant.id, rowVersion: grant.rowVersion }),
      data: {
        ...data,
        rowVersion: { increment: 1 },
      } as Prisma.ProviderConnectionGrantUpdateManyMutationInput,
    });
    if (count !== 1) return null;
    return tx.providerConnectionGrant.findFirst({
      where: tenantWhere(scope, { id: grant.id }),
      select: grantSelect,
    });
  }

  /** Revokes every non-revoked grant of a connection and wipes the ciphertexts (D13 disconnect). */
  async revokeAll(tx: Tx, scope: TenantScope, connectionId: bigint): Promise<number> {
    const { count } = await tx.providerConnectionGrant.updateMany({
      where: tenantWhere(scope, { connectionId, status: { not: 'revoked' as const } }),
      data: {
        status: 'revoked',
        credentialCiphertext: null,
        credentialKeyId: null,
        verifyRequestedAt: null,
        rowVersion: { increment: 1 },
      },
    });
    return count;
  }

  insertConsentState(
    tx: Tx,
    scope: TenantScope,
    data: {
      connectionId: bigint;
      grantId: bigint;
      userId: bigint;
      stateSha256: string;
      expiresAt: Date;
    },
  ): Promise<{ id: bigint }> {
    return tx.providerConsentState.create({
      data: { organizationId: scope.organizationId, ...data },
      select: { id: true },
    });
  }

  /** Locks the scope's consent state by its hash (any user; the caller compares). */
  async lockConsentState(
    tx: Tx,
    scope: TenantScope,
    stateSha256: string,
  ): Promise<ConsentStateRow | null> {
    const rows = await tx.$queryRaw<Array<{ id: bigint }>>`
      SELECT id FROM provider_consent_states
      WHERE organization_id = ${scope.organizationId} AND state_sha256 = ${stateSha256}
      FOR UPDATE`;
    const id = rows[0]?.id;
    if (id === undefined) return null;
    return tx.providerConsentState.findFirst({
      where: tenantWhere(scope, { id }),
      select: {
        id: true,
        connectionId: true,
        grantId: true,
        userId: true,
        expiresAt: true,
        usedAt: true,
      },
    });
  }

  async markConsentUsed(tx: Tx, scope: TenantScope, id: bigint, at: Date): Promise<boolean> {
    const { count } = await tx.providerConsentState.updateMany({
      where: tenantWhere(scope, { id, usedAt: null }),
      data: { usedAt: at },
    });
    return count === 1;
  }

  /** Marks every open consent state of a grant used (a new consent or a revocation). */
  async closeConsentStates(tx: Tx, scope: TenantScope, grantId: bigint, at: Date): Promise<void> {
    await tx.providerConsentState.updateMany({
      where: tenantWhere(scope, { grantId, usedAt: null }),
      data: { usedAt: at },
    });
  }

  /** The grant by internal id (writer, for the consent completion). */
  findById(tx: Tx, scope: TenantScope, id: bigint): Promise<GrantRow | null> {
    return tx.providerConnectionGrant.findFirst({
      where: tenantWhere(scope, { id }),
      select: grantSelect,
    });
  }

  /** The connection public id and status of a connection id (consent completion). */
  connectionOf(
    tx: Tx,
    scope: TenantScope,
    connectionId: bigint,
  ): Promise<{ id: bigint; publicId: string; status: string; rowVersion: number } | null> {
    return tx.providerConnection.findFirst({
      where: tenantWhere(scope, { id: connectionId }),
      select: { id: true, publicId: true, status: true, rowVersion: true },
    });
  }
}
