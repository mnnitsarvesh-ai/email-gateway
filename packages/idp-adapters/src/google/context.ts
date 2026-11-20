/**
 * Per-adapter state of the Google adapter: dependencies, the token cache (per profile and subject;
 * per-user Gmail tokens bounded by `ATO_IDP_GMAIL_TOKEN_CACHE_MAX`, R1) and session opening (the
 * 8.2 connection echo-checked for the organization).
 */
import type { AdapterDeps } from '../adapter-types';
import { normalizedAddress } from '../core/normalize';
import { type ProviderSession, TokenCache, openSession } from '../core/session';
import type { ProviderIdentityRef } from '../port/ato-port';
import { GOOGLE_PROFILES } from '../requirements';
import { GOOGLE_PROVIDER } from './constants';
import { DirectoryClient } from './directory-client';
import { GmailClient } from './gmail-client';
import { ReportsClient } from './reports-client';
import type { DirectoryUser } from './schemas';

/** Admin-subject tokens of the three profiles on top of the per-user Gmail tokens. */
const ADMIN_TOKEN_HEADROOM = 16;

export interface GoogleCalls {
  session: ProviderSession;
  reports: ReportsClient;
  /** Directory calls as the delegated administrator of `profile`'s grant. */
  directory(profile?: string): DirectoryClient;
  /** Gmail settings calls impersonating each mailbox owner with `profile`'s grant. */
  gmail(profile?: string): GmailClient;
}

export class GoogleContext {
  readonly tokens: TokenCache;

  constructor(readonly deps: AdapterDeps) {
    this.tokens = new TokenCache(deps, deps.config.gmailTokenCacheMax + ADMIN_TOKEN_HEADROOM);
  }

  get now(): Date {
    return this.deps.clock();
  }

  async open(signal: AbortSignal): Promise<GoogleCalls> {
    const session = await openSession(this.deps, this.tokens, signal, 'google_workspace');
    const subject = session.grant(GOOGLE_PROFILES.telemetry)?.subjectEmail ?? undefined;
    return {
      session,
      reports: new ReportsClient(session, subject),
      directory: (profile = GOOGLE_PROFILES.telemetry) => new DirectoryClient(session, profile),
      gmail: (profile = GOOGLE_PROFILES.telemetry) => new GmailClient(session, profile),
    };
  }

  /** Directory domains used to classify forwarding targets as external. */
  directoryDomains(session: ProviderSession): string[] {
    return [
      ...(this.deps.integration.directoryDomains ?? session.view.linkedDomains.map((d) => d.name)),
    ].map((d) => d.toLowerCase());
  }

  identityFromUser(user: DirectoryUser): ProviderIdentityRef {
    const email = normalizedAddress(user.primaryEmail);
    return {
      provider: GOOGLE_PROVIDER,
      externalId: user.id,
      ...(email ? { primaryEmail: email } : {}),
    };
  }
}
