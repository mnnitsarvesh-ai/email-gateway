import { Injectable } from '@nestjs/common';
import { PrismaReadService, PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { tenantWhere, type TenantScope } from '../../auth-contracts/tenant-scope';

type Client = Prisma.TransactionClient;

/** An API key as administrators see it: never the key or its hash. */
export interface ApiKeyRecord {
  id: bigint;
  publicId: string;
  name: string;
  keyPrefix: string;
  scopes: unknown;
  createdBy: { publicId: string; displayName: string } | null;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  revokedAt: Date | null;
  createdAt: Date;
}

const apiKeySelect = {
  id: true,
  publicId: true,
  name: true,
  keyPrefix: true,
  scopes: true,
  createdBy: { select: { publicId: true, displayName: true } },
  lastUsedAt: true,
  expiresAt: true,
  revokedAt: true,
  createdAt: true,
} satisfies Prisma.ApiKeySelect;

export interface NewApiKey {
  name: string;
  keyPrefix: string;
  keyHash: string;
  scopes: string[];
  createdByUserId: bigint;
  expiresAt: Date;
}

/**
 * `api_keys` management (D11). Scoped by the tenant scope on every query; the list uses the
 * replica, creation and revocation the writer. Authentication lookups by prefix live in the
 * auth module.
 */
@Injectable()
export class ApiKeysRepository {
  constructor(
    private readonly prisma: PrismaService,
    private readonly reader: PrismaReadService,
  ) {}

  /** Keys of the scope (revoked and expired included), newest first (reader). */
  async list(
    scope: TenantScope,
    window: { take: number; beforeId?: bigint },
  ): Promise<ApiKeyRecord[]> {
    return this.reader.client.apiKey.findMany({
      where: tenantWhere(scope, {
        ...(window.beforeId !== undefined && { id: { lt: window.beforeId } }),
      }),
      select: apiKeySelect,
      orderBy: { id: 'desc' },
      take: window.take,
    });
  }

  async findByPublicId(
    scope: TenantScope,
    publicId: string,
    client: Client = this.prisma,
  ): Promise<ApiKeyRecord | null> {
    return client.apiKey.findFirst({
      where: tenantWhere(scope, { publicId }),
      select: apiKeySelect,
    });
  }

  async create(tx: Client, scope: TenantScope, data: NewApiKey): Promise<ApiKeyRecord> {
    return tx.apiKey.create({
      data: { ...tenantWhere(scope), ...data },
      select: apiKeySelect,
    });
  }

  /** Revokes the key if it is not revoked yet; false when it already was. */
  async revoke(tx: Client, scope: TenantScope, id: bigint, now: Date): Promise<boolean> {
    const result = await tx.apiKey.updateMany({
      where: tenantWhere(scope, { id, revokedAt: null }),
      data: { revokedAt: now },
    });
    return result.count === 1;
  }
}
