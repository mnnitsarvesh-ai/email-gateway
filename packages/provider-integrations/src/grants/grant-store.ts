import { Prisma, type PrismaClient } from '@email-gateway/database';
import {
  credentialAad,
  ProviderCredentialCipherError,
  type CredentialAadParts,
  type ProviderCredential,
  type ProviderCredentialCipher,
} from '../crypto/credential-cipher';
import { ProviderRequestError } from '../errors';
import type { GrantTokenRecord, GrantTokenSource } from '../tokens/token-service';
import {
  isCustomerCredentialMethod,
  type GrantRef,
  type IntegrationProvider,
  type ProviderAuthMethod,
  type ProviderConnectionStatus,
  type ProviderGrantStatus,
} from '../types';

/** A grant with its connection, as the writer holds it; never the ciphertext. */
export interface StoredGrant {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  profile: string;
  profileVersion: number;
  authMethod: ProviderAuthMethod;
  status: ProviderGrantStatus;
  clientId: string | null;
  subjectEmail: string | null;
  credentialVersion: number;
  credentialKeyId: string | null;
  hasCredential: boolean;
  credentialExpiresAt: Date | null;
  requestedPermissions: string[];
  observedPermissions: string[] | null;
  claimedTenantId: string | null;
  verifyRequestedAt: Date | null;
  verifiedAt: Date | null;
  lastErrorCode: string | null;
  consecutiveFailures: number;
  rowVersion: number;
  connection: {
    id: bigint;
    publicId: string;
    provider: IntegrationProvider;
    status: ProviderConnectionStatus;
    externalTenantId: string | null;
    rowVersion: number;
  };
}

/** A grant with its decrypted credential (customer-owned methods only). */
export interface GrantWithCredential extends StoredGrant {
  credential: ProviderCredential | null;
  /** The ciphertext is under the previous key: the maintenance role re-encrypts it. */
  credentialUnderPreviousKey: boolean;
}

/** Fields the worker updates on a grant (CAS on `row_version`). */
export interface GrantStatusPatch {
  status?: ProviderGrantStatus;
  lastErrorCode?: string | null;
  observedPermissions?: string[] | null;
  missingPermissions?: string[] | null;
  excessPermissions?: string[] | null;
  verifiedAt?: Date | null;
  verifyRequestedAt?: Date | null;
  verifyClaimedUntil?: Date | null;
  lastTokenAt?: Date | null;
  /** `increment` adds one, `reset` sets zero. */
  consecutiveFailures?: 'increment' | 'reset';
}

/** Fields the worker updates on a connection (CAS on `row_version`). */
export interface ConnectionStatusPatch {
  status?: ProviderConnectionStatus;
  externalTenantId?: string | null;
  externalTenantName?: string | null;
  tenantVerifiedAt?: Date | null;
  activeTenantKey?: string | null;
}

export interface ReencryptionSummary {
  scanned: number;
  reencrypted: number;
  /** Rows that do not decrypt with either key (left untouched, reported). */
  failed: number;
  /** Rows changed concurrently (CAS lost; picked up by the next batch). */
  skipped: number;
}

type Db = PrismaClient | Prisma.TransactionClient;

const grantSelect = {
  id: true,
  publicId: true,
  organizationId: true,
  profile: true,
  profileVersion: true,
  authMethod: true,
  status: true,
  clientId: true,
  subjectEmail: true,
  credentialCiphertext: true,
  credentialKeyId: true,
  credentialVersion: true,
  credentialExpiresAt: true,
  requestedPermissions: true,
  observedPermissions: true,
  claimedTenantId: true,
  verifyRequestedAt: true,
  verifiedAt: true,
  lastErrorCode: true,
  consecutiveFailures: true,
  rowVersion: true,
  connection: {
    select: {
      id: true,
      publicId: true,
      provider: true,
      status: true,
      externalTenantId: true,
      rowVersion: true,
    },
  },
} as const satisfies Prisma.ProviderConnectionGrantSelect;

type GrantRow = Prisma.ProviderConnectionGrantGetPayload<{ select: typeof grantSelect }>;

const stringList = (value: Prisma.JsonValue | null): string[] | null =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : null;

const jsonList = (value: string[] | null | undefined) =>
  value === undefined ? undefined : value === null ? Prisma.DbNull : value;

function toStored(row: GrantRow): StoredGrant {
  return {
    id: row.id,
    publicId: row.publicId,
    organizationId: row.organizationId,
    profile: row.profile,
    profileVersion: row.profileVersion,
    authMethod: row.authMethod,
    status: row.status,
    clientId: row.clientId,
    subjectEmail: row.subjectEmail,
    credentialVersion: row.credentialVersion,
    credentialKeyId: row.credentialKeyId,
    hasCredential: row.credentialCiphertext !== null,
    credentialExpiresAt: row.credentialExpiresAt,
    requestedPermissions: stringList(row.requestedPermissions) ?? [],
    observedPermissions: stringList(row.observedPermissions),
    claimedTenantId: row.claimedTenantId,
    verifyRequestedAt: row.verifyRequestedAt,
    verifiedAt: row.verifiedAt,
    lastErrorCode: row.lastErrorCode,
    consecutiveFailures: row.consecutiveFailures,
    rowVersion: row.rowVersion,
    connection: { ...row.connection },
  };
}

/**
 * Writer-side access to grants (D6): reads of a connection + grant with the decrypted credential
 * (decrypting holders only: pass `cipher`), status updates with `row_version` compare-and-set,
 * and the key-rotation re-encryption batch (ADR-0077 decision 6). Every read is scoped by the
 * organization id (I2). It implements `GrantTokenSource` for `ProviderTokenService`.
 */
export class ProviderGrantStore implements GrantTokenSource {
  constructor(
    private readonly db: PrismaClient,
    private readonly cipher: ProviderCredentialCipher | null = null,
  ) {}

  /** The grant of a connection and profile, or null (another organization's grant is null). */
  async findGrant(ref: GrantRef, tx: Db = this.db): Promise<StoredGrant | null> {
    const row = await this.findRow(ref, tx);
    return row ? toStored(row) : null;
  }

  /** The grant with its decrypted credential (customer-owned methods). */
  async loadGrant(ref: GrantRef, tx: Db = this.db): Promise<GrantWithCredential | null> {
    const row = await this.findRow(ref, tx);
    if (!row) return null;
    const stored = toStored(row);
    if (!isCustomerCredentialMethod(row.authMethod) || row.credentialCiphertext === null) {
      return { ...stored, credential: null, credentialUnderPreviousKey: false };
    }
    if (!this.cipher) throw new ProviderRequestError('credential_unavailable');
    try {
      const opened = this.cipher.decryptCredential(row.credentialCiphertext, this.aadOf(row));
      if (opened.credential.method !== row.authMethod) throw new ProviderCredentialCipherError();
      return {
        ...stored,
        credential: opened.credential,
        credentialUnderPreviousKey: opened.usedPreviousKey,
      };
    } catch (error) {
      if (error instanceof ProviderCredentialCipherError) {
        throw new ProviderRequestError('credential_unavailable');
      }
      throw error;
    }
  }

  async loadForToken(ref: GrantRef): Promise<GrantTokenRecord> {
    const grant = await this.loadGrant(ref);
    if (!grant) throw new ProviderRequestError('credential_unavailable');
    return {
      grantPublicId: grant.publicId,
      profile: grant.profile,
      authMethod: grant.authMethod,
      status: grant.status,
      credentialVersion: grant.credentialVersion,
      tenantId: grant.claimedTenantId ?? grant.connection.externalTenantId,
      clientId: grant.clientId,
      subjectEmail: grant.subjectEmail,
      credential: grant.credential,
    };
  }

  /**
   * Updates a grant if its `row_version` is still `expectedRowVersion`; returns the new row
   * version, or null when the CAS was lost (someone else changed the row).
   */
  async updateGrantStatus(
    grantId: bigint,
    expectedRowVersion: number,
    patch: GrantStatusPatch,
    tx: Db = this.db,
  ): Promise<number | null> {
    const data: Prisma.ProviderConnectionGrantUpdateManyMutationInput = {
      rowVersion: { increment: 1 },
      ...(patch.status !== undefined ? { status: patch.status } : {}),
      ...(patch.lastErrorCode !== undefined ? { lastErrorCode: patch.lastErrorCode } : {}),
      ...(patch.observedPermissions !== undefined
        ? { observedPermissions: jsonList(patch.observedPermissions) }
        : {}),
      ...(patch.missingPermissions !== undefined
        ? { missingPermissions: jsonList(patch.missingPermissions) }
        : {}),
      ...(patch.excessPermissions !== undefined
        ? { excessPermissions: jsonList(patch.excessPermissions) }
        : {}),
      ...(patch.verifiedAt !== undefined ? { verifiedAt: patch.verifiedAt } : {}),
      ...(patch.verifyRequestedAt !== undefined
        ? { verifyRequestedAt: patch.verifyRequestedAt }
        : {}),
      ...(patch.verifyClaimedUntil !== undefined
        ? { verifyClaimedUntil: patch.verifyClaimedUntil }
        : {}),
      ...(patch.lastTokenAt !== undefined ? { lastTokenAt: patch.lastTokenAt } : {}),
      ...(patch.consecutiveFailures === 'increment'
        ? { consecutiveFailures: { increment: 1 } }
        : patch.consecutiveFailures === 'reset'
          ? { consecutiveFailures: 0 }
          : {}),
    };
    const result = await tx.providerConnectionGrant.updateMany({
      where: { id: grantId, rowVersion: expectedRowVersion },
      data,
    });
    return result.count === 1 ? expectedRowVersion + 1 : null;
  }

  /** Connection counterpart of `updateGrantStatus` (CAS on the connection's `row_version`). */
  async updateConnectionStatus(
    connectionId: bigint,
    expectedRowVersion: number,
    patch: ConnectionStatusPatch,
    tx: Db = this.db,
  ): Promise<number | null> {
    const result = await tx.providerConnection.updateMany({
      where: { id: connectionId, rowVersion: expectedRowVersion },
      data: {
        rowVersion: { increment: 1 },
        ...(patch.status !== undefined ? { status: patch.status } : {}),
        ...(patch.externalTenantId !== undefined
          ? { externalTenantId: patch.externalTenantId }
          : {}),
        ...(patch.externalTenantName !== undefined
          ? { externalTenantName: patch.externalTenantName }
          : {}),
        ...(patch.tenantVerifiedAt !== undefined
          ? { tenantVerifiedAt: patch.tenantVerifiedAt }
          : {}),
        ...(patch.activeTenantKey !== undefined ? { activeTenantKey: patch.activeTenantKey } : {}),
      },
    });
    return result.count === 1 ? expectedRowVersion + 1 : null;
  }

  /**
   * Re-encrypts up to `limit` grants whose ciphertext is under `fromKeyId` (default: the
   * cipher's previous key id) with the current key (key rotation, ADR-0077 decision 6). The
   * credential version, and so the AAD, is unchanged. Idempotent; counts only.
   */
  async reencryptBatch(
    options: { limit?: number; fromKeyId?: string } = {},
  ): Promise<ReencryptionSummary> {
    const cipher = this.cipher;
    if (!cipher) throw new ProviderRequestError('credential_unavailable');
    const fromKeyId = options.fromKeyId ?? cipher.previousKeyId;
    const summary: ReencryptionSummary = { scanned: 0, reencrypted: 0, failed: 0, skipped: 0 };
    if (!fromKeyId || fromKeyId === cipher.currentKeyId) return summary;
    const rows = await this.db.providerConnectionGrant.findMany({
      where: { credentialKeyId: fromKeyId, credentialCiphertext: { not: null } },
      select: grantSelect,
      orderBy: { id: 'asc' },
      take: Math.min(Math.max(options.limit ?? 100, 1), 1000),
    });
    for (const row of rows) {
      summary.scanned += 1;
      try {
        const aad = credentialAad(this.aadOf(row));
        const opened = cipher.decrypt(row.credentialCiphertext!, aad);
        const sealed = cipher.encrypt(opened.plaintext, aad);
        const updated = await this.db.providerConnectionGrant.updateMany({
          where: { id: row.id, rowVersion: row.rowVersion, credentialKeyId: fromKeyId },
          data: {
            credentialCiphertext: sealed.ciphertext,
            credentialKeyId: sealed.keyId,
            rowVersion: { increment: 1 },
          },
        });
        if (updated.count === 1) summary.reencrypted += 1;
        else summary.skipped += 1;
      } catch (error) {
        if (error instanceof ProviderCredentialCipherError) summary.failed += 1;
        else throw error;
      }
    }
    return summary;
  }

  private aadOf(row: GrantRow): CredentialAadParts {
    return {
      organizationId: row.organizationId,
      connectionPublicId: row.connection.publicId,
      grantPublicId: row.publicId,
      credentialVersion: row.credentialVersion,
    };
  }

  private async findRow(ref: GrantRef, tx: Db): Promise<GrantRow | null> {
    return tx.providerConnectionGrant.findFirst({
      where: {
        organizationId: ref.organizationId,
        profile: ref.profile,
        connection: { publicId: ref.connectionPublicId, organizationId: ref.organizationId },
      },
      select: grantSelect,
    });
  }
}
