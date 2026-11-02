import { Injectable, Logger } from '@nestjs/common';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import type { ApiKeyPrincipal } from '../../../auth-contracts/principal';
import { parseApiKey, safeEqualHex, TokenHasher } from '../../../crypto/tokens';
import { KeyValueStore } from '../../../kv/key-value-store';
import { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import {
  API_KEY_CACHE_TTL_SECONDS,
  API_KEY_FORBIDDEN_SCOPES,
  API_KEY_LAST_USED_THROTTLE_SECONDS,
  kvKeys,
} from '../auth.constants';
import { ApiKeysAuthRepository } from '../repositories/api-keys-auth.repository';
import { PrincipalCacheService } from './principal-cache.service';

const TENANT = new Set<string>(TENANT_PERMISSIONS);

/**
 * Cached API-key record (60 s), valid only while its organization version and key version are
 * current. Both are read before the database when the record is filled (D9).
 */
interface CachedApiKey {
  orgVersion: number;
  keyVersion: string;
  id: string;
  publicId: string;
  organizationId: string;
  organizationPublicId: string;
  organizationActive: boolean;
  keyHash: string;
  scopes: string[];
  expiresAt: string | null;
  revoked: boolean;
}

/** Effective permissions of a key: its scopes ∩ tenant permissions, minus forbidden scopes (D9, D11). */
export function effectiveApiKeyPermissions(scopes: unknown): Set<string> {
  if (!Array.isArray(scopes)) return new Set();
  return new Set(
    scopes.filter(
      (s): s is string =>
        typeof s === 'string' && TENANT.has(s) && !API_KEY_FORBIDDEN_SCOPES.has(s),
    ),
  );
}

/**
 * The `X-API-Key` authentication path (D9): lookup by prefix (cache, writer on miss), constant-
 * time HMAC comparison, revocation/expiry, active organization, the `api_access` feature, and a
 * throttled `last_used_at` update. Returns null for every rejection (the guard answers `401`).
 */
@Injectable()
export class ApiKeyAuthenticatorService {
  private readonly logger = new Logger(ApiKeyAuthenticatorService.name);

  constructor(
    private readonly repository: ApiKeysAuthRepository,
    private readonly hasher: TokenHasher,
    private readonly kv: KeyValueStore,
    private readonly cache: PrincipalCacheService,
    private readonly features: OrganizationFeaturesService,
  ) {}

  async authenticate(rawKey: string, now: Date = new Date()): Promise<ApiKeyPrincipal | null> {
    const parsed = parseApiKey(rawKey);
    if (!parsed) return null;
    const record = await this.load(parsed.prefix);
    if (!record) return null;
    if (!safeEqualHex(this.hasher.hmacHex(rawKey), record.keyHash)) return null;
    if (record.revoked || !record.organizationActive) return null;
    if (record.expiresAt !== null && new Date(record.expiresAt) <= now) return null;
    const organizationId = BigInt(record.organizationId);
    if (!(await this.features.isEnabled(organizationId, 'api_access'))) return null;

    const apiKeyId = BigInt(record.id);
    this.touch(apiKeyId, now);
    return {
      kind: 'api_key',
      apiKeyId,
      apiKeyPublicId: record.publicId,
      organizationId,
      organizationPublicId: record.organizationPublicId,
      permissions: effectiveApiKeyPermissions(record.scopes),
    };
  }

  private async load(prefix: string): Promise<CachedApiKey | null> {
    const raw = await this.kv.get(kvKeys.apiKey(prefix));
    if (raw !== null) {
      try {
        const cached = JSON.parse(raw) as CachedApiKey;
        const orgVersion = await this.cache.organizationVersion(BigInt(cached.organizationId));
        if (
          cached.orgVersion === orgVersion &&
          typeof cached.keyVersion === 'string' &&
          cached.keyVersion === (await this.cache.apiKeyVersion(prefix))
        ) {
          return cached;
        }
      } catch {
        // fall through to the database
      }
    }
    // Versions first, then the key row: a suspension, deletion or revocation committed after the
    // row was read moves a version, so this record is never served from the cache.
    const organizationId = await this.repository.findOrganizationIdByPrefix(prefix);
    if (organizationId === null) return null;
    const orgVersion = await this.cache.organizationVersion(organizationId);
    const keyVersion = await this.cache.apiKeyVersion(prefix);
    const row = await this.repository.findByPrefix(prefix);
    if (!row) return null;
    const record: CachedApiKey = {
      orgVersion,
      keyVersion,
      id: row.id.toString(),
      publicId: row.publicId,
      organizationId: row.organizationId.toString(),
      organizationPublicId: row.organization.publicId,
      organizationActive:
        row.organization.status === 'active' && row.organization.deletedAt === null,
      keyHash: row.keyHash,
      scopes: Array.isArray(row.scopes) ? row.scopes.filter((s) => typeof s === 'string') : [],
      expiresAt: row.expiresAt?.toISOString() ?? null,
      revoked: row.revokedAt !== null,
    };
    if (row.organizationId === organizationId) {
      await this.kv.set(kvKeys.apiKey(prefix), JSON.stringify(record), API_KEY_CACHE_TTL_SECONDS);
    }
    return record;
  }

  /** At most one `last_used_at` write per key per minute, off the request path. */
  private touch(apiKeyId: bigint, now: Date): void {
    void (async () => {
      const first = await this.kv.setIfAbsent(
        kvKeys.apiKeyUsed(apiKeyId),
        '1',
        API_KEY_LAST_USED_THROTTLE_SECONDS,
      );
      if (first) await this.repository.touchLastUsed(apiKeyId, now);
    })().catch((err: unknown) =>
      this.logger.error({ message: 'Failed to record API key use', err }),
    );
  }
}
