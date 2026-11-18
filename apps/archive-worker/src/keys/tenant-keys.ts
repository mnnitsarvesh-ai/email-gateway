import { randomBytes } from 'node:crypto';
import {
  ARCHIVE_TENANT_KEY_ALGORITHM,
  type ArchiveRootKeyProvider,
  unwrapTenantKey,
  wrapTenantKey,
} from '@email-gateway/archive';
import type { PrismaClient } from '@email-gateway/database';
import { InconsistentReadError, isUniqueViolation } from '../shared/errors';

export interface TenantKey {
  organizationId: bigint;
  version: number;
  key: Buffer;
}

export class TenantKeyUnavailableError extends Error {
  readonly code = 'tenant_key_unavailable';
  constructor() {
    super('tenant key unavailable');
    this.name = 'TenantKeyUnavailableError';
  }
}

interface Cached<T> {
  value: T;
  at: number;
}

/**
 * Tenant key versions (A8, A9, ADR-0065). `active(org)` returns the organization's active
 * version, creating version 1 on the first capture (`INSERT` on the unique `(organization_id,
 * version)`; the loser of a race re-reads). `version(org, v)` unwraps any non-destroyed version
 * (decrypt-only for retired ones). Unwrapped keys are cached for `ARCHIVE_KEY_CACHE_TTL_MS`, so a
 * rotation by the api reaches new captures within that time. Key material never leaves memory.
 */
export class TenantKeyService {
  private readonly activeCache = new Map<string, Cached<TenantKey>>();
  private readonly versionCache = new Map<string, Cached<TenantKey>>();

  constructor(
    private readonly prisma: PrismaClient,
    private readonly provider: ArchiveRootKeyProvider,
    private readonly options: { cacheTtlMs: number; now?: () => number },
  ) {}

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  private fresh<T>(entry: Cached<T> | undefined): T | null {
    return entry !== undefined && this.now() - entry.at < this.options.cacheTtlMs
      ? entry.value
      : null;
  }

  async active(organizationId: bigint): Promise<TenantKey> {
    const cacheKey = organizationId.toString();
    const cached = this.fresh(this.activeCache.get(cacheKey));
    if (cached) return cached;
    let row = await this.readActive(organizationId);
    if (row === null) {
      const any = await this.prisma.archiveEncryptionKey.count({ where: { organizationId } });
      if (any > 0) throw new TenantKeyUnavailableError();
      await this.createFirst(organizationId);
      row = await this.readActive(organizationId);
      if (row === null) throw new TenantKeyUnavailableError();
    }
    const key = await this.unwrap(organizationId, row.version, row.wrappedKey);
    const value: TenantKey = { organizationId, version: row.version, key };
    this.activeCache.set(cacheKey, { value, at: this.now() });
    this.versionCache.set(`${cacheKey}:${row.version}`, { value, at: this.now() });
    return value;
  }

  async version(organizationId: bigint, version: number): Promise<TenantKey> {
    const cacheKey = `${organizationId.toString()}:${version}`;
    const cached = this.fresh(this.versionCache.get(cacheKey));
    if (cached) return cached;
    const row = await this.prisma.archiveEncryptionKey.findUnique({
      where: { organizationId_version: { organizationId, version } },
      select: { organizationId: true, version: true, status: true, wrappedKey: true },
    });
    if (row === null || row.status === 'destroyed' || row.wrappedKey === null) {
      throw new TenantKeyUnavailableError();
    }
    if (row.organizationId !== organizationId || row.version !== version) {
      throw new InconsistentReadError('tenant_key');
    }
    const key = await this.unwrap(organizationId, version, row.wrappedKey);
    const value: TenantKey = { organizationId, version, key };
    this.versionCache.set(cacheKey, { value, at: this.now() });
    return value;
  }

  /** Drops cached keys (tests; a rotation is otherwise picked up after the TTL). */
  clear(): void {
    this.activeCache.clear();
    this.versionCache.clear();
  }

  private async readActive(
    organizationId: bigint,
  ): Promise<{ version: number; wrappedKey: string } | null> {
    const row = await this.prisma.archiveEncryptionKey.findFirst({
      where: { organizationId, status: 'active', wrappedKey: { not: null } },
      orderBy: { version: 'desc' },
      select: { organizationId: true, version: true, wrappedKey: true },
    });
    if (row === null || row.wrappedKey === null) return null;
    if (row.organizationId !== organizationId) throw new InconsistentReadError('tenant_key');
    return { version: row.version, wrappedKey: row.wrappedKey };
  }

  private async createFirst(organizationId: bigint): Promise<void> {
    const key = randomBytes(32);
    try {
      const wrapped = await wrapTenantKey(this.provider, { organizationId, version: 1 }, key);
      await this.prisma.archiveEncryptionKey.create({
        data: {
          organizationId,
          version: 1,
          status: 'active',
          wrappedKey: wrapped,
          rootKeyId: this.provider.currentKeyId,
          algorithm: ARCHIVE_TENANT_KEY_ALGORITHM,
          activatedAt: new Date(this.now()),
        },
        select: { id: true },
      });
    } catch (error) {
      // Lost the creation race: the winner's version 1 is read by the caller.
      if (!isUniqueViolation(error)) throw error;
    } finally {
      key.fill(0);
    }
  }

  private async unwrap(organizationId: bigint, version: number, wrapped: string): Promise<Buffer> {
    const result = await unwrapTenantKey(this.provider, wrapped, { organizationId, version });
    return result.key;
  }
}
