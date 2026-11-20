/**
 * One adapter operation's view of its connection: the echo-checked 8.2 connection view, cached
 * access tokens per (profile, resource, subject) and budgeted requests. Tokens stay in memory, are
 * dropped after a `401` and are never logged, returned or put in an error (invariant 2).
 */
import type { AdapterDeps } from '../adapter-types';
import {
  ConnectionAccessError,
  type ProviderConnectionView,
  type TokenResource,
} from '../port/connection-port';
import type { ApiFamily } from '../port/state-ports';
import { takeBudget } from './budget';
import { ProviderCallError, fromConnectionAccessError } from './errors';
import type { ProviderRequest, ProviderResponse, TokenSource } from './http';

const TOKEN_REFRESH_MARGIN_MS = 60_000;

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

/** Per-adapter token cache (memory only). */
export class TokenCache {
  private readonly entries = new Map<string, CachedToken>();

  constructor(
    private readonly deps: Pick<AdapterDeps, 'connections' | 'clock'>,
    private readonly maxEntries = 2_000,
  ) {}

  source(
    view: ProviderConnectionView,
    request: { profile: string; resource: TokenResource; subject?: string },
  ): TokenSource {
    const key = `${view.publicId}|${request.profile}|${request.resource}|${request.subject ?? ''}`;
    return {
      get: async (signal) => {
        const cached = this.entries.get(key);
        if (cached && cached.expiresAt - TOKEN_REFRESH_MARGIN_MS > this.deps.clock().getTime()) {
          return cached.accessToken;
        }
        let token;
        try {
          token = await this.deps.connections.acquireToken(view, request, signal);
        } catch (error) {
          if (error instanceof ConnectionAccessError) throw fromConnectionAccessError(error);
          throw new ProviderCallError('provider_unavailable');
        }
        if (this.entries.size >= this.maxEntries) {
          const oldest = this.entries.keys().next();
          if (!oldest.done) this.entries.delete(oldest.value);
        }
        this.entries.set(key, { accessToken: token.accessToken, expiresAt: token.expiresAt });
        return token.accessToken;
      },
      invalidate: () => {
        this.entries.delete(key);
      },
    };
  }

  clear(): void {
    this.entries.clear();
  }
}

export interface SessionCall<T> extends Omit<ProviderRequest<T>, 'token' | 'signal'> {
  profile: string;
  resource: TokenResource;
  subject?: string;
}

export class ProviderSession {
  constructor(
    readonly view: ProviderConnectionView,
    private readonly deps: AdapterDeps,
    private readonly tokens: TokenCache,
    readonly signal: AbortSignal,
  ) {}

  /** A budgeted request with the token of the given profile/resource/subject. */
  async call<T>(request: SessionCall<T>): Promise<ProviderResponse<T>> {
    await takeBudget({
      budget: this.deps.budget,
      integrationId: this.deps.integration.id,
      family: request.family,
      signal: this.signal,
      sleep: this.deps.sleep,
      metrics: this.deps.metrics,
    });
    const { profile, resource, subject, ...rest } = request;
    return this.deps.http.request<T>({
      ...rest,
      token: this.tokens.source(this.view, { profile, resource, ...(subject ? { subject } : {}) }),
      signal: this.signal,
    });
  }

  /** Acquires a token without a provider call (probe step 2). */
  async checkToken(profile: string, resource: TokenResource, subject?: string): Promise<void> {
    await this.tokens
      .source(this.view, { profile, resource, ...(subject ? { subject } : {}) })
      .get(this.signal);
  }

  grant(profile: string) {
    return this.view.grants.find((grant) => grant.profile === profile) ?? null;
  }

  /** Whether the grant of `profile` is active and its observed permissions include `permission`. */
  hasObservedPermission(profile: string, permission: string): boolean {
    const grant = this.grant(profile);
    if (!grant || grant.status !== 'active') return false;
    return grant.observedPermissions === null
      ? true
      : grant.observedPermissions.includes(permission);
  }

  family(family: ApiFamily): string {
    return this.deps.http.baseUrl(family);
  }
}

/**
 * Loads the integration's 8.2 connection, echo-checking organization, public id and provider.
 * Throws `connection_not_found` or `connection_inactive`.
 */
export async function openSession(
  deps: AdapterDeps,
  tokens: TokenCache,
  signal: AbortSignal,
  expectedProvider: ProviderConnectionView['provider'],
): Promise<ProviderSession> {
  let view: ProviderConnectionView | null;
  try {
    view = await deps.connections.get(
      deps.integration.organizationId,
      deps.integration.connectionPublicId,
      signal,
    );
  } catch (error) {
    if (error instanceof ConnectionAccessError) throw fromConnectionAccessError(error);
    throw new ProviderCallError('provider_unavailable');
  }
  if (
    !view ||
    view.organizationId !== deps.integration.organizationId ||
    view.publicId !== deps.integration.connectionPublicId ||
    view.provider !== expectedProvider
  ) {
    throw new ProviderCallError('connection_not_found', { retryable: false });
  }
  if (view.status !== 'active')
    throw new ProviderCallError('connection_inactive', { retryable: false });
  return new ProviderSession(view, deps, tokens, signal);
}

/** Linked-domain guard (invariant 4): provider-verified linked domains of the connection. */
export function verifiedLinkedDomains(view: ProviderConnectionView): Set<string> {
  return new Set(
    view.linkedDomains.filter((d) => d.providerVerified).map((d) => d.name.toLowerCase()),
  );
}
