import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type {
  AiChatTenantKeyProvider,
  AiChatTenantKeyStatus,
  Prisma,
} from '@email-gateway/database';

type Tx = Prisma.TransactionClient;

/** Every column except the ciphertext (views, routing decisions). */
export const providerKeySelect = {
  organizationId: true,
  provider: true,
  model: true,
  keyKid: true,
  keyFingerprint: true,
  keyVersion: true,
  status: true,
  lastValidatedAt: true,
  lastErrorCode: true,
  setByUserId: true,
  setAt: true,
  rowVersion: true,
  updatedAt: true,
} satisfies Prisma.AiChatProviderKeySelect;
export type ProviderKeyRow = Prisma.AiChatProviderKeyGetPayload<{
  select: typeof providerKeySelect;
}>;

/** The row with its ciphertext (decrypted only to build a provider client, I27). */
export type ProviderKeySecretRow = ProviderKeyRow & { keyCiphertext: string };

export interface ProviderKeyWrite {
  provider: AiChatTenantKeyProvider;
  model: string;
  keyCiphertext: string;
  keyKid: string;
  keyFingerprint: string;
  keyVersion: number;
  status: AiChatTenantKeyStatus;
  lastValidatedAt: Date;
  setByUserId: bigint;
  setAt: Date;
}

/**
 * `ai_chat_provider_keys` (step AI-6 §3, D7, ADR-0097, I27): at most one row per organization,
 * the API key only as AES-256-GCM ciphertext. Writer only (the key decides where a turn goes).
 * Every statement is scoped by the organization id of the caller's scope.
 */
@Injectable()
export class ProviderKeysRepository {
  constructor(private readonly writer: PrismaService) {}

  find(organizationId: bigint, tx?: Tx): Promise<ProviderKeyRow | null> {
    return (tx ?? this.writer).aiChatProviderKey.findUnique({
      where: { organizationId },
      select: providerKeySelect,
    });
  }

  findSecret(organizationId: bigint, tx?: Tx): Promise<ProviderKeySecretRow | null> {
    return (tx ?? this.writer).aiChatProviderKey.findUnique({
      where: { organizationId },
      select: { ...providerKeySelect, keyCiphertext: true },
    });
  }

  /**
   * Stores a new key: creates the row, or replaces the existing one only while its `key_version`
   * is still `expectedKeyVersion` (a concurrent replacement loses). False when the CAS lost.
   */
  async put(
    organizationId: bigint,
    expectedKeyVersion: number | null,
    data: ProviderKeyWrite,
    tx: Tx,
  ): Promise<boolean> {
    const row = { ...data, lastErrorCode: null };
    if (expectedKeyVersion === null) {
      await tx.aiChatProviderKey.create({
        data: { organizationId, ...row },
        select: { organizationId: true },
      });
      return true;
    }
    const result = await tx.aiChatProviderKey.updateMany({
      where: { organizationId, keyVersion: expectedKeyVersion },
      data: { ...row, rowVersion: { increment: 1 } },
    });
    return result.count === 1;
  }

  /**
   * The outcome of a probe or a turn's `auth` refusal, for the key version it concerns (a key
   * replaced meanwhile is left alone). False when the version is gone.
   */
  async setStatus(
    organizationId: bigint,
    keyVersion: number,
    status: AiChatTenantKeyStatus,
    errorCode: string | null,
    validatedAt: Date,
    tx?: Tx,
  ): Promise<boolean> {
    const result = await (tx ?? this.writer).aiChatProviderKey.updateMany({
      where: { organizationId, keyVersion },
      data: {
        status,
        lastErrorCode: errorCode?.slice(0, 64) ?? null,
        lastValidatedAt: validatedAt,
        rowVersion: { increment: 1 },
      },
    });
    return result.count === 1;
  }

  async remove(organizationId: bigint, tx: Tx): Promise<boolean> {
    const result = await tx.aiChatProviderKey.deleteMany({ where: { organizationId } });
    return result.count === 1;
  }

  /** `{ id, displayName }` of the user who stored the key (the row stores the internal id). */
  async setBy(userId: bigint): Promise<{ id: string; displayName: string } | null> {
    const row = await this.writer.user.findUnique({
      where: { id: userId },
      select: { publicId: true, displayName: true },
    });
    return row ? { id: row.publicId, displayName: row.displayName } : null;
  }
}
