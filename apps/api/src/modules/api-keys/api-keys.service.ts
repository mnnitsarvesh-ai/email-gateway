import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { TENANT_PERMISSIONS } from '@email-gateway/database';
import { AuditService } from '../../audit/audit.service';
import type { Principal, UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { generateApiKey, TokenHasher } from '../../crypto/tokens';
import { TransactionRunner } from '../../database/transaction-runner';
import { type Page, type PageQuery, pageWindow, toPage } from '../../http/pagination';
import { OrganizationFeaturesService } from '../../tenancy/organization-features.service';
import { API_KEY_FORBIDDEN_SCOPES } from '../auth/auth.constants';
import { PrincipalCacheService } from '../auth/services/principal-cache.service';
import type { ClientContext } from '../auth/services/session.service';
import { missingPermissions } from '../roles/role-rules';
import { type ApiKeyRecord, ApiKeysRepository } from './api-keys.repository';
import type { ApiKeyView, CreateApiKeyRequest, CreatedApiKeyView } from './api-keys.schemas';

/**
 * Scopes an API key can never hold (D11): managing keys, roles or other users' sessions needs a
 * person. The authenticator applies the same set (single definition in the auth constants).
 */
export { API_KEY_FORBIDDEN_SCOPES };

const DAY_MS = 24 * 60 * 60 * 1000;
export const API_KEY_DEFAULT_TTL_DAYS = 365;
export const API_KEY_MAX_TTL_DAYS = 730;

const TENANT: ReadonlySet<string> = new Set(TENANT_PERMISSIONS);

/**
 * Scope rules (D11): non-empty (schema), tenant permissions only and none of the forbidden
 * scopes (`400`), and only permissions the creator holds (`403`, no escalation).
 */
export function assertValidApiKeyScopes(
  scopes: readonly string[],
  creatorPermissions: ReadonlySet<string>,
): void {
  if (scopes.length === 0) throw new BadRequestException(['scopes: at least one scope']);
  const unknown = scopes.filter((s) => !TENANT.has(s));
  if (unknown.length > 0) {
    throw new BadRequestException([`scopes: not a tenant permission: ${unknown.join(', ')}`]);
  }
  const forbidden = scopes.filter((s) => API_KEY_FORBIDDEN_SCOPES.has(s));
  if (forbidden.length > 0) {
    throw new BadRequestException([`scopes: not allowed for API keys: ${forbidden.join(', ')}`]);
  }
  const missing = missingPermissions(creatorPermissions, scopes);
  if (missing.length > 0) {
    throw new ForbiddenException(`Cannot grant scopes you do not hold: ${missing.join(', ')}`);
  }
}

/** `expiresAt`: default now + 365 days; must be in the future and at most now + 730 days. */
export function resolveApiKeyExpiry(expiresAt: string | undefined, now: Date): Date {
  if (expiresAt === undefined) return new Date(now.getTime() + API_KEY_DEFAULT_TTL_DAYS * DAY_MS);
  const value = new Date(expiresAt);
  if (value.getTime() <= now.getTime()) {
    throw new BadRequestException(['expiresAt: must be in the future']);
  }
  if (value.getTime() > now.getTime() + API_KEY_MAX_TTL_DAYS * DAY_MS) {
    throw new BadRequestException([`expiresAt: at most ${API_KEY_MAX_TTL_DAYS} days ahead`]);
  }
  return value;
}

export function toApiKeyView(key: ApiKeyRecord): ApiKeyView {
  return {
    id: key.publicId,
    name: key.name,
    prefix: key.keyPrefix,
    scopes: Array.isArray(key.scopes)
      ? key.scopes.filter((s): s is string => typeof s === 'string')
      : [],
    createdBy: key.createdBy
      ? { id: key.createdBy.publicId, displayName: key.createdBy.displayName }
      : null,
    lastUsedAt: key.lastUsedAt?.toISOString() ?? null,
    expiresAt: key.expiresAt?.toISOString() ?? null,
    revokedAt: key.revokedAt?.toISOString() ?? null,
    createdAt: key.createdAt.toISOString(),
  };
}

/**
 * API key management (D11, §4.2). The key is generated here, returned once and stored only as
 * its prefix and peppered HMAC; it is never logged or audited.
 */
@Injectable()
export class ApiKeysService {
  constructor(
    private readonly keys: ApiKeysRepository,
    private readonly transactions: TransactionRunner,
    private readonly hasher: TokenHasher,
    private readonly features: OrganizationFeaturesService,
    private readonly audit: AuditService,
    private readonly principalCache: PrincipalCacheService,
  ) {}

  async list(scope: TenantScope, query: PageQuery): Promise<Page<ApiKeyView>> {
    const rows = await this.keys.list(scope, pageWindow(query));
    return toPage(rows, query.limit, toApiKeyView);
  }

  async create(
    principal: UserPrincipal,
    scope: TenantScope,
    body: CreateApiKeyRequest,
    client: ClientContext,
  ): Promise<CreatedApiKeyView> {
    if (principal.override) {
      // A key would outlive the time-boxed override: platform staff cannot mint tenant keys.
      throw new ForbiddenException('API keys cannot be created under a platform override');
    }
    if (!(await this.features.isEnabled(scope.organizationId, 'api_access'))) {
      throw new ForbiddenException('API access is not enabled for this organization');
    }
    assertValidApiKeyScopes(body.scopes, principal.permissions);
    const now = new Date();
    const expiresAt = resolveApiKeyExpiry(body.expiresAt, now);
    const generated = generateApiKey();

    const created = await this.transactions.run(async (tx) => {
      const row = await this.keys.create(tx, scope, {
        name: body.name,
        keyPrefix: generated.prefix,
        keyHash: this.hasher.hmacHex(generated.key),
        scopes: body.scopes,
        createdByUserId: principal.userId,
        expiresAt,
      });
      await this.audit.record(
        {
          organizationId: scope.organizationId,
          actor: this.audit.actorFrom(principal),
          action: 'apikey.created',
          resourceType: 'api_key',
          resourceId: row.publicId,
          sourceIp: client.ip,
          metadata: {
            name: row.name,
            prefix: row.keyPrefix,
            scopes: body.scopes,
            expiresAt: expiresAt.toISOString(),
          },
        },
        tx,
      );
      return row;
    });
    return { apiKey: toApiKeyView(created), key: generated.key };
  }

  /** Idempotent: revoking a revoked key is a no-op `204`; another tenant's key is `404`. */
  async revoke(
    principal: Principal,
    scope: TenantScope,
    publicId: string,
    client: ClientContext,
  ): Promise<void> {
    const key = await this.transactions.run(async (tx) => {
      const key = await this.keys.findByPublicId(scope, publicId, tx);
      if (!key) throw new NotFoundException('API key not found');
      if (await this.keys.revoke(tx, scope, key.id, new Date())) {
        await this.audit.record(
          {
            organizationId: scope.organizationId,
            actor: this.audit.actorFrom(principal),
            action: 'apikey.revoked',
            resourceType: 'api_key',
            resourceId: key.publicId,
            sourceIp: client.ip,
            metadata: { name: key.name, prefix: key.keyPrefix, scopes: key.scopes },
          },
          tx,
        );
      }
      return key;
    });
    // Always drop the cached record, also for a repeated revoke (heals a failed invalidation).
    await this.principalCache.invalidateApiKey(key.keyPrefix);
  }
}
