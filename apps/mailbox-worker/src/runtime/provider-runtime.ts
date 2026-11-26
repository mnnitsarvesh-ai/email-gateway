import { readFileSync } from 'node:fs';
import type { PrismaClient } from '@email-gateway/database';
import {
  ProviderHttpClient,
  toConnectionAccessError,
  type ApiFamily,
  type IdpMetricsSink,
  type RateBudget,
  type Sleep,
  type TokenSource,
} from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import {
  GmailClient,
  GoogleDirectoryClient,
  GraphMailClient,
  MAILBOX_PROFILE_KEYS,
  type MailboxClientContext,
  type ThrottleGate,
} from '@email-gateway/mailbox-api';
import {
  GOOGLE_MAILBOX_REMEDIATION_PROFILE,
  M365_MAILBOX_REMEDIATION_PROFILE,
  platformCredentialsFromEnv,
  ProviderCredentialCipher,
  ProviderGrantStore,
  ProviderTokenService,
  resolveProviderEndpoints,
  urlString,
  type GrantRef,
  type TokenOptions,
} from '@email-gateway/provider-integrations';
import { isTestEnv, type WorkerConfig } from '../config';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import type { ConnectionContext } from '../domain/connections';

/** Timeouts and caps of the provider JSON calls (MIME bodies are capped per call). */
export const PROVIDER_HTTP_TIMEOUT_MS = 30_000;
export const PROVIDER_HTTP_MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
export const PROVIDER_HTTP_MAX_BACKOFF_MS = 900_000;

/**
 * Token acquisition of a `*.mailbox_remediation` grant (8.2's `ProviderTokenService` shape):
 * the decrypting grant store and the in-memory token cache (ADR-0077 as amended by ADR-0099).
 */
export interface MailboxAccessTokens {
  getAccessToken(
    grant: GrantRef,
    signal: AbortSignal,
    options?: TokenOptions,
  ): Promise<{ token: string; expiresAt: Date }>;
  invalidate(grantPublicId: string): void;
}

/**
 * Builds 8.2's token service for the two mailbox profiles from the configuration: the grant store
 * decrypts customer-owned credentials with `PROVIDER_CREDENTIAL_ENCRYPTION_KEY` (+ `_PREVIOUS`),
 * the platform app / service account come from the `PROVIDER_*_MAILBOX_*` keys
 * (`platformCredentialsFromEnv`; a configured file that is unreadable stops the worker).
 */
export function createMailboxAccessTokens(
  config: Readonly<WorkerConfig>,
  deps: { prisma: PrismaClient; logger: Logger; now: () => Date },
): MailboxAccessTokens {
  if (!config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY) {
    throw new Error('PROVIDER_CREDENTIAL_ENCRYPTION_KEY is required to call provider mailboxes');
  }
  const allowHttp = config.PROVIDER_ALLOW_HTTP_ENDPOINTS && isTestEnv(config);
  const endpoints = resolveProviderEndpoints({
    m365LoginUrl: config.PROVIDER_M365_LOGIN_URL,
    m365GraphUrl: config.PROVIDER_M365_GRAPH_URL,
    googleTokenUrl: config.PROVIDER_GOOGLE_TOKEN_URL,
    googleAdminUrl: config.PROVIDER_GOOGLE_ADMIN_URL,
    allowHttp,
  });
  const grants = new ProviderGrantStore(
    deps.prisma,
    ProviderCredentialCipher.fromConfig({
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY: config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY,
      PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS:
        config.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS,
    }),
  );
  return new ProviderTokenService({
    grants,
    endpoints,
    platform: platformCredentialsFromEnv(
      config as unknown as Record<string, string | undefined>,
      [M365_MAILBOX_REMEDIATION_PROFILE, GOOGLE_MAILBOX_REMEDIATION_PROFILE],
      {
        readFile: (path) => readFileSync(path, 'utf8'),
        googleTokenUrl: urlString(endpoints.googleToken),
        allowPlatformSecret: config.PROVIDER_M365_ALLOW_PLATFORM_SECRET,
      },
    ),
    // Per-mailbox Gmail tokens (subject = the mailbox) plus Graph and Directory tokens.
    cacheMax: 20_000,
    logger: deps.logger.child({ component: 'mailbox-tokens' }),
    now: deps.now,
  });
}

/**
 * A `TokenSource` over the grant's token service: memory only, never logged; failures become the
 * port's classified `ConnectionAccessError` (consent missing, credentials invalid, …).
 */
export class GrantTokenSource implements TokenSource {
  constructor(
    private readonly tokens: MailboxAccessTokens,
    private readonly ref: GrantRef,
    private readonly grantPublicId: string,
    private readonly options: TokenOptions,
  ) {}

  async get(signal: AbortSignal): Promise<string> {
    try {
      return (await this.tokens.getAccessToken(this.ref, signal, this.options)).token;
    } catch (error) {
      throw toConnectionAccessError(error);
    }
  }

  invalidate(): void {
    this.tokens.invalidate(this.grantPublicId);
  }
}

/** Per-run tally of provider calls of one connection (counters `provider_requests` / `_errors`). */
export class CallTally implements IdpMetricsSink {
  requests = 0;
  errors = 0;

  constructor(private readonly global: MailboxMetrics | null) {}

  httpRequest(labels: { provider: string; family: ApiFamily; statusClass: string }): void {
    this.requests += 1;
    if (labels.statusClass !== '2xx') this.errors += 1;
    this.global?.httpRequest(labels);
  }

  rateBudgetWait(labels: { family: ApiFamily }): void {
    this.global?.rateBudgetWait(labels);
  }
}

export interface MailboxClients {
  graph: GraphMailClient | null;
  gmail: GmailClient | null;
  directory: GoogleDirectoryClient | null;
  tally: CallTally;
}

export interface ProviderRuntimeDeps {
  tokens: MailboxAccessTokens;
  budget: RateBudget;
  throttle: ThrottleGate;
  logger: Logger;
  metrics: MailboxMetrics | null;
  /** The HTTP client's clock (backoff only). */
  nowMs: () => number;
  sleep?: Sleep;
  /** TEST SEAM: the HTTP client's fetch. */
  fetch?: typeof fetch;
}

/**
 * The provider side of the mailbox-worker: per connection run, an HTTPS client of 8.5 (origin
 * allow-list of `API_MODE_*_URL`, no redirects, byte caps, `Retry-After`, redaction) whose metrics
 * sink tallies the connection's requests, the per-connection Redis budget and the shared throttle
 * gate, and the three mailbox clients with grant token sources (Graph: resource `graph`; Gmail:
 * subject = the mailbox; Directory: subject = the delegated administrator).
 */
export class ProviderRuntime {
  private readonly allowHttp: boolean;

  constructor(
    private readonly config: Readonly<WorkerConfig>,
    private readonly deps: ProviderRuntimeDeps,
  ) {
    this.allowHttp = config.API_MODE_ALLOW_HTTP_ENDPOINTS && isTestEnv(config);
  }

  private httpClient(provider: string, sink: IdpMetricsSink): ProviderHttpClient {
    return new ProviderHttpClient({
      baseUrls: {
        graph: this.config.API_MODE_GRAPH_URL,
        // Not used by the mailbox clients; any configured origin keeps the allow-list closed.
        o365: this.config.API_MODE_GRAPH_URL,
        google_admin: this.config.API_MODE_GOOGLE_ADMIN_URL,
        gmail: this.config.API_MODE_GMAIL_URL,
      },
      allowHttpEndpoints: this.allowHttp,
      timeoutMs: PROVIDER_HTTP_TIMEOUT_MS,
      maxResponseBytes: PROVIDER_HTTP_MAX_RESPONSE_BYTES,
      maxBackoffMs: PROVIDER_HTTP_MAX_BACKOFF_MS,
      provider,
      logger: this.deps.logger.child({ component: 'mailbox-http' }),
      metrics: sink,
      now: this.deps.nowMs,
      ...(this.deps.fetch ? { fetch: this.deps.fetch } : {}),
    });
  }

  /** The clients of one connection run (null for the other provider's clients or no grant). */
  clientsFor(ctx: ConnectionContext): MailboxClients {
    const tally = new CallTally(this.deps.metrics);
    if (!ctx.grant) return { graph: null, gmail: null, directory: null, tally };
    const context: MailboxClientContext = {
      http: this.httpClient(ctx.provider, tally),
      apiConnectionPublicId: ctx.publicId,
      budget: this.deps.budget,
      throttle: this.deps.throttle,
      metrics: tally,
      ...(this.deps.sleep ? { sleep: this.deps.sleep } : {}),
    };
    const ref: GrantRef = {
      organizationId: ctx.organizationId,
      connectionPublicId: ctx.providerConnectionPublicId,
      profile: MAILBOX_PROFILE_KEYS[ctx.provider],
    };
    const grantId = ctx.grant.publicId;
    if (ctx.provider === 'microsoft_365') {
      return {
        graph: new GraphMailClient(
          context,
          new GrantTokenSource(this.deps.tokens, ref, grantId, { resource: 'graph' }),
        ),
        gmail: null,
        directory: null,
        tally,
      };
    }
    const sources = new Map<string, TokenSource>();
    const gmailToken = (mailbox: string): TokenSource => {
      const subject = mailbox.toLowerCase();
      let source = sources.get(subject);
      if (!source) {
        source = new GrantTokenSource(this.deps.tokens, ref, grantId, {
          resource: 'google',
          subject,
        });
        sources.set(subject, source);
      }
      return source;
    };
    const admin = ctx.grant.subjectEmail;
    return {
      graph: null,
      gmail: new GmailClient(context, gmailToken),
      directory: admin
        ? new GoogleDirectoryClient(
            context,
            new GrantTokenSource(this.deps.tokens, ref, grantId, {
              resource: 'google',
              subject: admin,
            }),
          )
        : null,
      tally,
    };
  }
}
