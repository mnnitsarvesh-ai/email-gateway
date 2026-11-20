/**
 * Worker binding of the connection port (design note §0.3, §0.4; merge note M4; ADR-0082): the
 * ato-worker's `ProviderConnectionAccess` over step 8.2's connection reads
 * (`ProviderConnectionReader`), grant store (`ProviderGrantStore`, the decrypting holder; R3) and
 * token service (`ProviderTokenService` with the R1 options). Together with `kinds.ts` and
 * `connection-directory.ts` this is the only code of the package that knows 8.2's names.
 *
 * Mapping (§0.4; the built 8.2 code wins over the design table):
 * - connection status: `draft`, `connecting`, `configuring` → `configuring`; `active`, `disabled`
 *   as is (`error` is never produced from 8.2);
 * - grant status: `pending_consent`, `verifying` → `pending`; others as is;
 * - `externalTenantId`: 8.2's reader returns the BOUND tenant only (null while merely claimed);
 * - `observedPermissions`: 8.2's reader returns `[]` for a grant it never verified; that is mapped
 *   to `null` ("never verified") because a verified grant always carries its permissions;
 * - token errors (`ProviderRequestError.code`): `invalid_client`, `unauthorized_client`,
 *   `credential_unavailable` → `credentials_invalid`; `consent_missing` → `consent_missing`;
 *   `tenant_not_found` → `connection_inactive`; `forbidden` → `scope_not_granted`; `throttled` →
 *   `throttled` (with `retryAfterMs`); `unavailable`, `timeout`, `bad_response` →
 *   `provider_unavailable`; no grant row of the profile → `grant_missing`; grant not active →
 *   `consent_missing`.
 *
 * Access tokens stay in memory (8.2's LRU cache, keyed by grant, credential version, resource and
 * subject); this file never logs, stores or returns anything but the token to the adapter.
 */
import type { PrismaClient } from '@email-gateway/database';
import {
  isProviderRequestError,
  PERMISSION_PROFILES,
  ProviderConnectionReader,
  ProviderGrantStore,
  ProviderTokenService,
  type AccessTokenProvider,
  type ProviderConnectionView as Connection82View,
  type ProviderCredentialCipher,
  type ProviderEndpoints,
  type ProviderErrorCode,
  type ProviderHttpSettings,
  type PlatformCredentials,
  type ProviderTokenServiceOptions,
  type TokenOptions,
} from '@email-gateway/provider-integrations';
import {
  ConnectionAccessError,
  type ConnectionAccessErrorCode,
  type ProviderAccessToken,
  type ProviderConnectionAccess,
  type ProviderConnectionView,
  type ProviderGrantView,
  type TokenResource,
} from '../port/connection-port';

/** 8.2's connection reads as the binding uses them (the reader, or a test double). */
export type ConnectionReads = Pick<ProviderConnectionReader, 'get' | 'listForOrganization'>;

const CONNECTION_STATUS: Readonly<
  Record<Connection82View['status'], ProviderConnectionView['status']>
> = Object.freeze({
  draft: 'configuring',
  connecting: 'configuring',
  configuring: 'configuring',
  active: 'active',
  disabled: 'disabled',
});

const GRANT_STATUS: Readonly<
  Record<Connection82View['grants'][number]['status'], ProviderGrantView['status']>
> = Object.freeze({
  pending_consent: 'pending',
  verifying: 'pending',
  active: 'active',
  error: 'error',
  revoked: 'revoked',
});

const TOKEN_ERROR: Readonly<Record<ProviderErrorCode, ConnectionAccessErrorCode>> = Object.freeze({
  invalid_client: 'credentials_invalid',
  unauthorized_client: 'credentials_invalid',
  credential_unavailable: 'credentials_invalid',
  consent_missing: 'consent_missing',
  tenant_not_found: 'connection_inactive',
  forbidden: 'scope_not_granted',
  throttled: 'throttled',
  unavailable: 'provider_unavailable',
  timeout: 'provider_unavailable',
  bad_response: 'provider_unavailable',
});

/** Maps one 8.2 connection view onto the port's view (§0.4). */
export function toPortConnection(view: Connection82View): ProviderConnectionView {
  return {
    publicId: view.publicId,
    organizationId: view.organizationId,
    provider: view.provider,
    displayName: view.displayName.slice(0, 128),
    status: CONNECTION_STATUS[view.status],
    externalTenantId: view.externalTenantId,
    linkedDomains: view.linkedDomains.map((d) => ({
      name: d.name,
      providerVerified: d.providerVerified,
    })),
    grants: view.grants.map((g) => ({
      publicId: g.publicId,
      profile: g.profile,
      status: GRANT_STATUS[g.status],
      observedPermissions: g.observedPermissions.length > 0 ? [...g.observedPermissions] : null,
      subjectEmail: g.subjectEmail,
    })),
    updatedAt: view.updatedAt.toISOString(),
  };
}

/** Maps a token failure onto the port's vocabulary (§0.4). */
export function toConnectionAccessError(error: unknown): ConnectionAccessError {
  if (error instanceof ConnectionAccessError) return error;
  if (isProviderRequestError(error)) {
    const code = TOKEN_ERROR[error.code] ?? 'provider_unavailable';
    return new ConnectionAccessError(code, code === 'throttled' ? error.retryAfterMs : undefined);
  }
  return new ConnectionAccessError('provider_unavailable');
}

/** R1 options of a port token request (`graph` and `google` are 8.2's defaults). */
export function tokenOptionsOf(request: {
  resource: TokenResource;
  subject?: string;
}): TokenOptions {
  return {
    ...(request.resource === 'o365_management' ? { resource: 'o365_management' as const } : {}),
    ...(request.subject !== undefined ? { subject: request.subject } : {}),
  };
}

function organizationIdOf(value: string): bigint | null {
  return /^[1-9][0-9]{0,19}$/.test(value) ? BigInt(value) : null;
}

/**
 * `ProviderConnectionAccess` over 8.2's library. Every read is scoped by the organization (8.2
 * I2) and echo-checked; tokens are requested only for an active grant of the requested profile.
 */
export class ProviderConnectionBinding implements ProviderConnectionAccess {
  constructor(
    private readonly deps: {
      connections: ConnectionReads;
      tokens: AccessTokenProvider;
    },
  ) {}

  async get(
    organizationId: string,
    connectionPublicId: string,
    _signal: AbortSignal,
  ): Promise<ProviderConnectionView | null> {
    const org = organizationIdOf(organizationId);
    if (org === null) return null;
    const view = await this.deps.connections.get(org, connectionPublicId);
    if (!view || view.organizationId !== organizationId) return null;
    return toPortConnection(view);
  }

  async list(organizationId: string, _signal: AbortSignal): Promise<ProviderConnectionView[]> {
    const org = organizationIdOf(organizationId);
    if (org === null) return [];
    const views = await this.deps.connections.listForOrganization(org);
    return views.filter((v) => v.organizationId === organizationId).map(toPortConnection);
  }

  async acquireToken(
    connection: ProviderConnectionView,
    request: { profile: string; resource: TokenResource; subject?: string },
    signal: AbortSignal,
  ): Promise<ProviderAccessToken> {
    const org = organizationIdOf(connection.organizationId);
    if (org === null) throw new ConnectionAccessError('connection_not_found');
    const grant = connection.grants.find((g) => g.profile === request.profile);
    if (!grant) throw new ConnectionAccessError('grant_missing');
    if (grant.status !== 'active') throw new ConnectionAccessError('consent_missing');
    try {
      const token = await this.deps.tokens.getAccessToken(
        {
          organizationId: org,
          connectionPublicId: connection.publicId,
          profile: request.profile,
        },
        signal,
        tokenOptionsOf(request),
      );
      return { accessToken: token.token, expiresAt: token.expiresAt.getTime() };
    } catch (error) {
      throw toConnectionAccessError(error);
    }
  }
}

export interface ProviderConnectionRuntimeOptions {
  /** The writer (8.2's grant and connection reads are writer reads, D6). */
  writer: PrismaClient;
  /** `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (+ `_PREVIOUS`): the `ato-respond` holder only (R3). */
  cipher: ProviderCredentialCipher;
  endpoints: ProviderEndpoints;
  /** Platform ATO apps / service accounts (`platformCredentialsFromEnv` over the ATO profiles). */
  platform?: PlatformCredentials;
  http?: ProviderHttpSettings;
  /** `ATO_IDP_GMAIL_TOKEN_CACHE_MAX` (per-user Gmail tokens) plus headroom; R1 LRU cap. */
  cacheMax?: number;
  logger?: ProviderTokenServiceOptions['logger'];
  onTokenRequest?: ProviderTokenServiceOptions['onTokenRequest'];
  now?: () => Date;
}

/**
 * Builds the worker binding from 8.2's own classes: the decrypting grant store, the token
 * service (in-memory LRU cache only) and the connection reader, all over the writer.
 */
export function createProviderConnectionBinding(
  options: ProviderConnectionRuntimeOptions,
): ProviderConnectionBinding {
  const grants = new ProviderGrantStore(options.writer, options.cipher);
  const tokens = new ProviderTokenService({
    grants,
    endpoints: options.endpoints,
    ...(options.platform ? { platform: options.platform } : {}),
    ...(options.http ? { http: options.http } : {}),
    ...(options.cacheMax !== undefined ? { cacheMax: options.cacheMax } : {}),
    ...(options.logger ? { logger: options.logger } : {}),
    ...(options.onTokenRequest ? { onTokenRequest: options.onTokenRequest } : {}),
    ...(options.now ? { now: options.now } : {}),
  });
  return new ProviderConnectionBinding({
    connections: new ProviderConnectionReader(options.writer),
    tokens,
  });
}

/** The ATO permission profiles of 8.2's registry (for `platformCredentialsFromEnv`). */
export function atoPermissionProfiles(): typeof PERMISSION_PROFILES {
  return PERMISSION_PROFILES.filter((p) => p.purpose.startsWith('ato_'));
}
