import { readFileSync } from 'node:fs';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  GoogleAdminClient,
  GoogleDirectory,
  type IntegrationProvider,
  MicrosoftDirectory,
  MicrosoftGraphClient,
  PERMISSION_PROFILES,
  platformCredentialsFromEnv,
  type PlatformCredentials,
  type ProviderDirectory,
  type ProviderEndpointsConfig,
  type ProviderHttpSettings,
  ProviderCredentialCipher,
  ProviderGrantStore,
  ProviderTokenService,
  resolveProviderEndpoints,
  type RetryPolicy,
  urlString,
} from '@email-gateway/provider-integrations';
import type { WorkerConfig } from '../config';
import { type IntegrationMetrics, providerOfApi } from '../metrics/integration-metrics';

export interface ProviderRuntimeOptions {
  /** Overrides the configured endpoints (integration suites: the in-process fake). */
  endpoints?: ProviderEndpointsConfig;
  /** Overrides the platform credentials (integration suites). */
  platform?: PlatformCredentials;
  retry?: RetryPolicy;
  now?: () => Date;
}

/**
 * The provider side of the worker (D2, D5, D6): the decrypting grant store, the token service
 * (in-memory cache only, ADR-0077), the read-only Graph and Admin SDK clients and the
 * directories per provider, all wired to the D18 metrics. The worker is the only holder of the
 * platform app secret / certificate and the platform service-account key.
 */
export class ProviderRuntime {
  readonly cipher: ProviderCredentialCipher;
  readonly grants: ProviderGrantStore;
  readonly tokens: ProviderTokenService;
  readonly directories: Readonly<Record<IntegrationProvider, ProviderDirectory>>;
  readonly googleTokenUrl: string;

  constructor(
    config: Readonly<WorkerConfig>,
    writer: PrismaClient,
    metrics: IntegrationMetrics,
    logger: Logger,
    options: ProviderRuntimeOptions = {},
  ) {
    const endpointConfig: ProviderEndpointsConfig = options.endpoints ?? {
      m365LoginUrl: config.PROVIDER_M365_LOGIN_URL,
      m365GraphUrl: config.PROVIDER_M365_GRAPH_URL,
      googleTokenUrl: config.PROVIDER_GOOGLE_TOKEN_URL,
      googleAdminUrl: config.PROVIDER_GOOGLE_ADMIN_URL,
      allowHttp: config.PROVIDER_ALLOW_HTTP_ENDPOINTS,
    };
    const endpoints = resolveProviderEndpoints(endpointConfig);
    this.googleTokenUrl = urlString(endpoints.googleToken);
    this.cipher = ProviderCredentialCipher.fromConfig(config);
    this.grants = new ProviderGrantStore(writer, this.cipher);
    const platform =
      options.platform ??
      platformCredentialsFromEnv(
        config as unknown as Record<string, string | undefined>,
        PERMISSION_PROFILES,
        {
          readFile: (path) => readFileSync(path, 'utf8'),
          googleTokenUrl: this.googleTokenUrl,
          allowPlatformSecret: config.PROVIDER_M365_ALLOW_PLATFORM_SECRET,
        },
      );
    const providerLogger = logger.child({ component: 'provider-http' });
    const http: ProviderHttpSettings = {
      timeoutMs: config.INTEGRATION_HTTP_TIMEOUT_MS,
      maxResponseBytes: config.INTEGRATION_HTTP_MAX_RESPONSE_BYTES,
      allowHttp: endpoints.allowHttp,
      logger: providerLogger,
      observe: (o) => {
        const provider = providerOfApi(o.api);
        metrics.apiRequests.inc({ provider, api: o.api, result: o.result });
        metrics.apiDuration.observe({ provider, api: o.api }, o.durationMs / 1000);
      },
    };
    this.tokens = new ProviderTokenService({
      grants: this.grants,
      endpoints,
      platform,
      http,
      logger: providerLogger,
      ...(options.now ? { now: options.now } : {}),
      onTokenRequest: (event) =>
        metrics.tokenRequests.inc({
          provider: event.provider,
          method: event.method,
          result: event.result,
        }),
    });
    const retry = options.retry ?? { retries: 1 };
    const graph = new MicrosoftGraphClient({
      graphUrl: endpoints.m365Graph,
      tokens: this.tokens,
      http,
      retry,
    });
    const admin = new GoogleAdminClient({
      adminUrl: endpoints.googleAdmin,
      tokens: this.tokens,
      http,
      retry,
    });
    this.directories = Object.freeze({
      microsoft_365: new MicrosoftDirectory(graph),
      google_workspace: new GoogleDirectory(admin),
    });
  }
}
