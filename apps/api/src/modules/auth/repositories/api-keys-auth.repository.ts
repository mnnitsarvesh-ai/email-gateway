import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { OrganizationStatus } from '@email-gateway/database';

export interface ApiKeyAuthRecord {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  keyHash: string;
  scopes: unknown;
  expiresAt: Date | null;
  revokedAt: Date | null;
  organization: { publicId: string; status: OrganizationStatus; deletedAt: Date | null };
}

/** API-key authentication lookups (D9): by the unique prefix, on the writer. */
@Injectable()
export class ApiKeysAuthRepository {
  constructor(private readonly prisma: PrismaService) {}

  async findByPrefix(keyPrefix: string): Promise<ApiKeyAuthRecord | null> {
    return this.prisma.apiKey.findUnique({
      where: { keyPrefix },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        keyHash: true,
        scopes: true,
        expiresAt: true,
        revokedAt: true,
        organization: { select: { publicId: true, status: true, deletedAt: true } },
      },
    });
  }

  /** The organization of a key (immutable), read before the key cache is filled. */
  async findOrganizationIdByPrefix(keyPrefix: string): Promise<bigint | null> {
    const row = await this.prisma.apiKey.findUnique({
      where: { keyPrefix },
      select: { organizationId: true },
    });
    return row?.organizationId ?? null;
  }

  async touchLastUsed(id: bigint, now: Date): Promise<void> {
    await this.prisma.apiKey.updateMany({ where: { id }, data: { lastUsedAt: now } });
  }
}
