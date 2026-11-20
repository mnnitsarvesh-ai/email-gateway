/**
 * In-memory implementation of the connection port (design note §0.3) for the library tests and
 * the worker tests before the rebase. Tokens are minted as `EXAMPLE-sim-token-<n>` and registered
 * with the simulators' token registry together with the grant's permissions, so a permission
 * that is not granted (or revoked later) produces a real `403` from the simulators.
 *
 * Post-rebase the production binding over 8.2's grant store and token service replaces it
 * (`src/bindings/provider-connections.ts`, WP3); this class stays a test double.
 */
import {
  ConnectionAccessError,
  type ConnectionAccessErrorCode,
  type ProviderAccessToken,
  type ProviderConnectionAccess,
  type ProviderConnectionView,
  type ProviderGrantView,
  type TokenResource,
} from '../port/connection-port';
import type { SimTokenRegistry } from './simulators/tokens';

export interface InMemoryGrant {
  publicId: string;
  profile: string;
  status: ProviderGrantView['status'];
  subjectEmail?: string | null;
  /** Permissions (Microsoft app roles / Google scopes) the provider grants this profile. */
  permissions: readonly string[];
  /**
   * Whether 8.2 has verified the permissions (`observedPermissions` reported); `false` reports
   * `null` (never verified). Default `true`.
   */
  observed?: boolean;
}

export interface InMemoryConnection extends Omit<ProviderConnectionView, 'grants'> {
  grants: InMemoryGrant[];
}

export interface TokenRequestLog {
  connectionPublicId: string;
  profile: string;
  resource: TokenResource;
  subject?: string;
}

export class InMemoryConnectionAccess implements ProviderConnectionAccess {
  private readonly connections = new Map<string, InMemoryConnection>();
  private readonly failures: {
    code: ConnectionAccessErrorCode;
    retryAfterMs?: number;
    times: number;
    profile?: string;
  }[] = [];
  readonly tokenRequests: TokenRequestLog[] = [];

  constructor(
    private readonly tokens: SimTokenRegistry,
    private readonly options: { now?: () => number; tokenTtlMs?: number } = {},
  ) {}

  private key(organizationId: string, publicId: string): string {
    return `${organizationId}|${publicId}`;
  }

  /** Adds (or replaces) a connection and registers its grants' permissions with the simulators. */
  add(connection: InMemoryConnection): void {
    this.connections.set(
      this.key(connection.organizationId, connection.publicId),
      structuredClone(connection),
    );
    this.registerGrants(connection);
  }

  private registerGrants(connection: InMemoryConnection): void {
    const directoryId = connection.externalTenantId;
    if (!directoryId) return;
    for (const grant of connection.grants) {
      this.tokens.setGrant(directoryId, grant.profile, grant.permissions);
    }
  }

  /** Changes a connection (status, domains, grants…); grants are re-registered. */
  update(
    organizationId: string,
    publicId: string,
    patch: Partial<Omit<InMemoryConnection, 'publicId' | 'organizationId'>>,
  ): void {
    const current = this.connections.get(this.key(organizationId, publicId));
    if (!current) throw new Error('in_memory_connection_not_found');
    const next = { ...current, ...structuredClone(patch) };
    this.connections.set(this.key(organizationId, publicId), next);
    if (patch.grants) this.registerGrants(next);
  }

  remove(organizationId: string, publicId: string): void {
    this.connections.delete(this.key(organizationId, publicId));
  }

  setGrantStatus(
    organizationId: string,
    publicId: string,
    profile: string,
    status: ProviderGrantView['status'],
  ): void {
    const current = this.connections.get(this.key(organizationId, publicId));
    const grant = current?.grants.find((g) => g.profile === profile);
    if (!grant) throw new Error('in_memory_grant_not_found');
    grant.status = status;
  }

  /** The next `times` token acquisitions (optionally of one profile) fail with `code`. */
  failTokens(
    code: ConnectionAccessErrorCode,
    options: { times?: number; retryAfterMs?: number; profile?: string } = {},
  ): void {
    this.failures.push({
      code,
      times: options.times ?? 1,
      ...(options.retryAfterMs !== undefined ? { retryAfterMs: options.retryAfterMs } : {}),
      ...(options.profile !== undefined ? { profile: options.profile } : {}),
    });
  }

  private view(connection: InMemoryConnection): ProviderConnectionView {
    const directoryId = connection.externalTenantId;
    return {
      publicId: connection.publicId,
      organizationId: connection.organizationId,
      provider: connection.provider,
      displayName: connection.displayName,
      status: connection.status,
      externalTenantId: connection.externalTenantId,
      linkedDomains: connection.linkedDomains.map((d) => ({ ...d })),
      updatedAt: connection.updatedAt,
      grants: connection.grants.map((grant) => ({
        publicId: grant.publicId,
        profile: grant.profile,
        status: grant.status,
        subjectEmail: grant.subjectEmail ?? null,
        observedPermissions:
          grant.observed === false || !directoryId
            ? null
            : this.tokens.grantedPermissions(directoryId, grant.profile),
      })),
    };
  }

  get(organizationId: string, connectionPublicId: string): Promise<ProviderConnectionView | null> {
    const connection = this.connections.get(this.key(organizationId, connectionPublicId));
    return Promise.resolve(connection ? this.view(connection) : null);
  }

  list(organizationId: string): Promise<ProviderConnectionView[]> {
    return Promise.resolve(
      [...this.connections.values()]
        .filter((connection) => connection.organizationId === organizationId)
        .map((connection) => this.view(connection)),
    );
  }

  acquireToken(
    connection: ProviderConnectionView,
    request: { profile: string; resource: TokenResource; subject?: string },
  ): Promise<ProviderAccessToken> {
    this.tokenRequests.push({
      connectionPublicId: connection.publicId,
      profile: request.profile,
      resource: request.resource,
      ...(request.subject ? { subject: request.subject } : {}),
    });
    const failure = this.failures.find(
      (f) => f.times > 0 && (f.profile === undefined || f.profile === request.profile),
    );
    if (failure) {
      failure.times -= 1;
      return Promise.reject(new ConnectionAccessError(failure.code, failure.retryAfterMs));
    }
    const stored = this.connections.get(this.key(connection.organizationId, connection.publicId));
    if (!stored) return Promise.reject(new ConnectionAccessError('connection_not_found'));
    if (stored.status !== 'active' || !stored.externalTenantId) {
      return Promise.reject(new ConnectionAccessError('connection_inactive'));
    }
    const grant = stored.grants.find((g) => g.profile === request.profile);
    if (!grant) return Promise.reject(new ConnectionAccessError('grant_missing'));
    if (grant.status !== 'active')
      return Promise.reject(new ConnectionAccessError('consent_missing'));
    const now = (this.options.now ?? Date.now)();
    const expiresAt = now + (this.options.tokenTtlMs ?? 3_600_000);
    const accessToken = this.tokens.issue({
      directoryId: stored.externalTenantId,
      resource: request.resource,
      profile: request.profile,
      ...(request.subject ? { subject: request.subject } : {}),
      expiresAt,
    });
    return Promise.resolve({ accessToken, expiresAt });
  }
}
