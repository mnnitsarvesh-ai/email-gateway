/**
 * Per-adapter state of the Microsoft adapter: dependencies, the token cache, the owner and
 * publisher caches, and session opening (connection view echo-checked for the organization).
 */
import type { AdapterDeps } from '../adapter-types';
import { ProviderCallError } from '../core/errors';
import { type ProviderSession, TokenCache, openSession } from '../core/session';
import type { ProviderIdentityRef } from '../port/ato-port';
import { MICROSOFT_PROVIDER, OWNER_CACHE_MS, PUBLISHER_CACHE_MS } from './constants';
import { GraphClient } from './graph-client';
import { O365Client } from './o365-client';
import type { GraphUser } from './schemas';
import { normalizedAddress, boundedText } from '../core/normalize';

export interface MicrosoftCalls {
  session: ProviderSession;
  graph: GraphClient;
  /** Office 365 Management client of the connection's tenant. */
  o365(): O365Client;
}

export class MicrosoftContext {
  readonly tokens: TokenCache;
  private readonly owners = new Map<string, { identity: ProviderIdentityRef | null; at: number }>();
  private readonly publishers = new Map<string, { verified: boolean | undefined; at: number }>();

  constructor(readonly deps: AdapterDeps) {
    this.tokens = new TokenCache(deps);
  }

  get now(): Date {
    return this.deps.clock();
  }

  async open(signal: AbortSignal): Promise<MicrosoftCalls> {
    const session = await openSession(this.deps, this.tokens, signal, 'microsoft_365');
    const relativizeGraph = (link: string) => this.deps.http.relativize('graph', link);
    const relativizeO365 = (link: string) => this.deps.http.relativize('o365', link);
    const graph = new GraphClient(session, relativizeGraph);
    let o365: O365Client | null = null;
    return {
      session,
      graph,
      o365: () => {
        const tenantId = session.view.externalTenantId;
        if (!tenantId) throw new ProviderCallError('connection_inactive', { retryable: false });
        o365 ??= new O365Client(session, tenantId, relativizeO365);
        return o365;
      },
    };
  }

  /** Directory domains used to classify forwarding targets as external. */
  directoryDomains(session: ProviderSession): string[] {
    return [
      ...(this.deps.integration.directoryDomains ?? session.view.linkedDomains.map((d) => d.name)),
    ].map((d) => d.toLowerCase());
  }

  identityFromUser(user: GraphUser): ProviderIdentityRef {
    const upn = boundedText(user.userPrincipalName, 256);
    const email = normalizedAddress(user.mail) ?? normalizedAddress(upn);
    return {
      provider: MICROSOFT_PROVIDER,
      externalId: user.id,
      ...(upn ? { userPrincipalName: upn } : {}),
      ...(email ? { primaryEmail: email } : {}),
    };
  }

  /** Mailbox owner → identity through Graph (cached 1 h; `null` when unknown). */
  async owner(calls: MicrosoftCalls, key: string): Promise<ProviderIdentityRef | null> {
    const cacheKey = key.toLowerCase();
    const cached = this.owners.get(cacheKey);
    const nowMs = this.now.getTime();
    if (cached && nowMs - cached.at < OWNER_CACHE_MS) return cached.identity;
    const user = await calls.graph.getUser(key);
    const identity = user ? this.identityFromUser(user) : null;
    if (this.owners.size > 10_000) this.owners.clear();
    this.owners.set(cacheKey, { identity, at: nowMs });
    return identity;
  }

  /** Publisher verification of a service principal (cached 24 h per integration). */
  async publisherVerified(
    calls: MicrosoftCalls,
    servicePrincipalId: string,
  ): Promise<boolean | undefined> {
    const cached = this.publishers.get(servicePrincipalId);
    const nowMs = this.now.getTime();
    if (cached && nowMs - cached.at < PUBLISHER_CACHE_MS) return cached.verified;
    const verified = await calls.graph.publisherVerified(servicePrincipalId);
    if (this.publishers.size > 10_000) this.publishers.clear();
    this.publishers.set(servicePrincipalId, { verified, at: nowMs });
    return verified;
  }
}
