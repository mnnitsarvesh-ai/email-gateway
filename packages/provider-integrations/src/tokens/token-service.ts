import type { Logger } from '@email-gateway/logger';
import type { ProviderCredential } from '../crypto/credential-cipher';
import type { ProviderEndpoints } from '../endpoints';
import { ProviderRequestError } from '../errors';
import type { ProviderHttpSettings } from '../http/provider-http';
import { requestGoogleToken } from '../google/token';
import {
  requestMicrosoftToken,
  type AcquiredToken,
  type MicrosoftClientCredential,
} from '../microsoft/token';
import { profileByKey } from '../profiles';
import type { PermissionProfile } from '../profiles/types';
import type { GrantRef, ProviderAuthMethod, ProviderGrantStatus } from '../types';
import { EMPTY_PLATFORM_CREDENTIALS, type PlatformCredentials } from './platform-credentials';

/** R1: the token resource. `google` is the Google default; `o365_management` only for `ato_*`. */
export type TokenResource = 'graph' | 'o365_management' | 'google';

export interface TokenOptions {
  resource?: TokenResource;
  /** Google: the impersonated user (default: the grant's delegated admin). */
  subject?: string;
}

/**
 * What the token service needs from a grant (`ProviderGrantStore.loadForToken` implements it);
 * the credential is decrypted only for customer-owned methods.
 */
export interface GrantTokenRecord {
  grantPublicId: string;
  profile: string;
  authMethod: ProviderAuthMethod;
  status: ProviderGrantStatus;
  credentialVersion: number;
  /** Microsoft: the tenant to request the token for (claimed until verified, then bound). */
  tenantId: string | null;
  /** Microsoft customer app id. */
  clientId: string | null;
  /** Google delegated admin. */
  subjectEmail: string | null;
  credential: ProviderCredential | null;
}

export interface GrantTokenSource {
  loadForToken(grant: GrantRef): Promise<GrantTokenRecord>;
}

export interface ProviderTokenServiceOptions {
  grants: GrantTokenSource;
  endpoints: ProviderEndpoints;
  platform?: PlatformCredentials;
  http?: ProviderHttpSettings;
  /** `PROVIDER_TOKEN_CACHE_MAX` (library option, default 2 000 entries, R1). */
  cacheMax?: number;
  /** Tokens are reused until this long before expiry (5 minutes, ADR-0077). */
  refreshMarginMs?: number;
  now?: () => Date;
  logger?: Pick<Logger, 'debug' | 'warn'>;
  /** Metrics hook (`provider_token_requests_total{provider,method,result}`). */
  onTokenRequest?: (event: {
    provider: PermissionProfile['provider'];
    method: ProviderAuthMethod;
    result: 'ok' | 'cache_hit' | ProviderRequestError['code'];
  }) => void;
}

export const DEFAULT_TOKEN_CACHE_MAX = 2_000;
export const TOKEN_REFRESH_MARGIN_MS = 5 * 60_000;

/** Statuses a token may be requested for (verification, active use, re-checks of failures). */
const TOKEN_STATUSES: ReadonlySet<ProviderGrantStatus> = new Set(['verifying', 'active', 'error']);

/**
 * Token acquisition per grant (D2, R1, ADR-0077): methods per auth method, an in-memory LRU
 * cache keyed `(grantPublicId, credentialVersion, resource, subject)` until 5 minutes before
 * expiry (never Redis or MySQL), concurrent requests for one key share one provider call, and
 * classified errors. Access tokens are never logged.
 */
export class ProviderTokenService {
  private readonly cache = new Map<string, AcquiredToken>();
  private readonly inflight = new Map<string, Promise<AcquiredToken>>();
  private readonly cacheMax: number;
  private readonly margin: number;
  private readonly now: () => Date;
  private readonly platform: PlatformCredentials;

  constructor(private readonly options: ProviderTokenServiceOptions) {
    this.cacheMax = Math.max(1, options.cacheMax ?? DEFAULT_TOKEN_CACHE_MAX);
    this.margin = options.refreshMarginMs ?? TOKEN_REFRESH_MARGIN_MS;
    this.now = options.now ?? (() => new Date());
    this.platform = options.platform ?? EMPTY_PLATFORM_CREDENTIALS;
  }

  /** Number of cached tokens (metrics, tests). */
  get cacheSize(): number {
    return this.cache.size;
  }

  /** Drops every cached token of a grant (credential replaced, grant revoked). */
  invalidate(grantPublicId: string): void {
    for (const key of [...this.cache.keys()]) {
      if (key.startsWith(`${grantPublicId}|`)) this.cache.delete(key);
    }
  }

  async getAccessToken(
    grant: GrantRef,
    signal: AbortSignal,
    options: TokenOptions = {},
  ): Promise<AcquiredToken> {
    const record = await this.options.grants.loadForToken(grant);
    const profile = profileByKey(record.profile);
    if (!profile || record.profile !== grant.profile) {
      throw new ProviderRequestError('credential_unavailable');
    }
    if (!TOKEN_STATUSES.has(record.status))
      throw new ProviderRequestError('credential_unavailable');
    if (!profile.authMethods.includes(record.authMethod)) {
      throw new ProviderRequestError('credential_unavailable');
    }

    const resource = this.resolveResource(profile, options.resource);
    const subject =
      profile.provider === 'google_workspace'
        ? (options.subject ?? record.subjectEmail ?? '').toLowerCase()
        : '';
    if (profile.provider === 'microsoft_365' && options.subject !== undefined) {
      // Client credentials have no subject; a subject is a programming error.
      throw new ProviderRequestError('credential_unavailable');
    }
    if (profile.provider === 'google_workspace' && !subject) {
      throw new ProviderRequestError('credential_unavailable');
    }

    const key = [record.grantPublicId, record.credentialVersion, resource, subject].join('|');
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt.getTime() - this.margin > this.now().getTime()) {
      this.cache.delete(key);
      this.cache.set(key, cached); // LRU: most recently used last
      this.options.onTokenRequest?.({
        provider: profile.provider,
        method: record.authMethod,
        result: 'cache_hit',
      });
      return { ...cached, observedPermissions: [...cached.observedPermissions] };
    }
    if (cached) this.cache.delete(key);

    let pending = this.inflight.get(key);
    if (!pending) {
      pending = this.acquire(profile, record, resource, subject, signal).finally(() => {
        this.inflight.delete(key);
      });
      this.inflight.set(key, pending);
    }
    const token = await pending;
    this.cache.set(key, token);
    while (this.cache.size > this.cacheMax) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
    return { ...token, observedPermissions: [...token.observedPermissions] };
  }

  private resolveResource(
    profile: PermissionProfile,
    requested: TokenResource | undefined,
  ): TokenResource {
    if (profile.provider === 'google_workspace') {
      if (requested && requested !== 'google')
        throw new ProviderRequestError('credential_unavailable');
      return 'google';
    }
    const resource = requested ?? 'graph';
    if (resource === 'google') throw new ProviderRequestError('credential_unavailable');
    if (resource === 'o365_management' && !profile.purpose.startsWith('ato_')) {
      // R1: a mail-flow grant asking for the management resource is a programming error.
      throw new ProviderRequestError('credential_unavailable');
    }
    return resource;
  }

  private async acquire(
    profile: PermissionProfile,
    record: GrantTokenRecord,
    resource: TokenResource,
    subject: string,
    signal: AbortSignal,
  ): Promise<AcquiredToken> {
    const report = (result: 'ok' | ProviderRequestError['code']) =>
      this.options.onTokenRequest?.({
        provider: profile.provider,
        method: record.authMethod,
        result,
      });
    try {
      const token =
        profile.provider === 'microsoft_365'
          ? await this.microsoft(profile, record, resource, signal)
          : await this.google(profile, record, subject, signal);
      report('ok');
      return token;
    } catch (error) {
      if (error instanceof ProviderRequestError) {
        report(error.code);
        this.options.logger?.debug(
          { grantId: record.grantPublicId, profile: profile.key, code: error.code },
          'provider token request failed',
        );
      }
      throw error;
    }
  }

  private async microsoft(
    profile: PermissionProfile,
    record: GrantTokenRecord,
    resource: TokenResource,
    signal: AbortSignal,
  ): Promise<AcquiredToken> {
    if (!record.tenantId) throw new ProviderRequestError('credential_unavailable');
    let clientId: string;
    let credential: MicrosoftClientCredential;
    if (record.authMethod === 'platform_app') {
      const app = this.platform.microsoft.get(profile.key);
      if (!app) throw new ProviderRequestError('credential_unavailable');
      clientId = app.clientId;
      // A certificate wins over a secret when both are configured (production, D2).
      if (app.certificate) credential = { kind: 'certificate', ...app.certificate };
      else if (app.secret) credential = { kind: 'secret', secret: app.secret };
      else throw new ProviderRequestError('credential_unavailable');
    } else if (record.authMethod === 'customer_app_secret') {
      if (record.credential?.method !== 'customer_app_secret' || !record.clientId) {
        throw new ProviderRequestError('credential_unavailable');
      }
      clientId = record.clientId;
      credential = { kind: 'secret', secret: record.credential.clientSecret };
    } else {
      throw new ProviderRequestError('credential_unavailable');
    }
    const scope =
      resource === 'o365_management'
        ? this.options.endpoints.m365ManagementScope
        : this.options.endpoints.m365GraphScope;
    return requestMicrosoftToken({
      loginUrl: this.options.endpoints.m365Login,
      tenantId: record.tenantId,
      clientId,
      credential,
      scope,
      signal,
      http: { allowHttp: this.options.endpoints.allowHttp, ...this.options.http },
      now: this.now,
    });
  }

  private async google(
    profile: PermissionProfile,
    record: GrantTokenRecord,
    subject: string,
    signal: AbortSignal,
  ): Promise<AcquiredToken> {
    let key;
    if (record.authMethod === 'platform_service_account') {
      key = this.platform.google.get(profile.key);
    } else if (record.authMethod === 'customer_service_account') {
      key =
        record.credential?.method === 'customer_service_account'
          ? record.credential.key
          : undefined;
    }
    if (!key) throw new ProviderRequestError('credential_unavailable');
    return requestGoogleToken({
      tokenUrl: this.options.endpoints.googleToken,
      key,
      subject,
      scopes: profile.permissions,
      signal,
      http: { allowHttp: this.options.endpoints.allowHttp, ...this.options.http },
      now: this.now,
    });
  }
}

/** The token-provider surface the API clients depend on (the service, or a test double). */
export type AccessTokenProvider = Pick<ProviderTokenService, 'getAccessToken'>;
