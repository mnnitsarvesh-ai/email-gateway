import { readFileSync } from 'node:fs';
import type { ProviderRegistry } from '@email-gateway/ato-detection';
import type { AtoProviderIntegration, PrismaClient } from '@email-gateway/database';
import {
  atoPermissionProfiles,
  createIdpAdapter,
  createProviderConnectionBinding,
  createProviderHttpClient,
  defaultBindingSettings,
  isAtoProviderKind,
  loadIdpAdapterConfig,
  validateBindingSettings,
  type AdapterIntegration,
  type AtoProviderKind,
  type IdpAdapter,
  type IdpAdapterConfig,
  type IdpHealthDetail,
  type ProviderConnectionAccess,
  type ProviderHttpClient,
  type RateBudget,
  type Sleep,
} from '@email-gateway/idp-adapters';
import type { Logger } from '@email-gateway/logger';
import {
  platformCredentialsFromEnv,
  ProviderCredentialCipher,
  resolveProviderEndpoints,
  urlString,
} from '@email-gateway/provider-integrations';
import { idpEnvOf, type WorkerConfig } from '../config';
import type { IdpMetrics } from '../metrics/idp-metrics';
import {
  MysqlActionStateStore,
  MysqlMailboxStateStore,
  RedisRateBudget,
  type BudgetRedis,
} from './stores';

/** The worker's provider registry type: factories receive the full integration row (PX2). */
export type IdpRegistry = ProviderRegistry<AtoProviderIntegration>;

/** Adapters kept per integration (re-built when the binding's settings or last probe change). */
const ADAPTER_CACHE_MAX = 1000;

export class IdpBindingError extends Error {
  constructor(readonly code: 'integration_unbound' | 'settings_invalid' | 'kind_unknown') {
    super(code);
    this.name = 'IdpBindingError';
  }
}

export interface IdpRuntimeDeps {
  prisma: PrismaClient;
  redis: BudgetRedis;
  logger: Logger;
  metrics: IdpMetrics | null;
  now: () => Date;
  /** TEST SEAMS (integration suites): an in-memory 8.2 connection port bound to the in-process
   * simulators, a rate budget, the HTTP client's sleep and clock. Never set in production. */
  connections?: ProviderConnectionAccess;
  budget?: RateBudget;
  sleep?: Sleep;
}

/** A parsed probe report of `health_detail` (shape-checked; anything else is "never probed"). */
export function healthDetailOf(value: unknown): IdpHealthDetail | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const v = value as Partial<IdpHealthDetail>;
  if (typeof v.checkedAt !== 'string' || Number.isNaN(Date.parse(v.checkedAt))) return null;
  if (!v.streams || typeof v.streams !== 'object' || !v.actions || !Array.isArray(v.grants)) {
    return null;
  }
  return v as IdpHealthDetail;
}

/** The binding settings of a row (`{}` of an 8.4 row = the defaults; invalid = refused). */
export function bindingSettingsOf(kind: AtoProviderKind, value: unknown) {
  if (
    value === null ||
    value === undefined ||
    (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0)
  ) {
    return defaultBindingSettings();
  }
  const result = validateBindingSettings(kind, value);
  if (!result.ok) throw new IdpBindingError('settings_invalid');
  return result.settings;
}

/** `directory_domains` of a row (lower-case names, ≤ 500). */
export function directoryDomainsOf(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((d): d is string => typeof d === 'string' && /^[a-z0-9.-]{1,253}$/.test(d))
    .slice(0, 500);
}

/** The adapter's view of an integration row (D1). */
export function adapterIntegrationOf(row: AtoProviderIntegration): AdapterIntegration {
  if (!isAtoProviderKind(row.provider)) throw new IdpBindingError('kind_unknown');
  if (!row.connectorRef) throw new IdpBindingError('integration_unbound');
  const domains = directoryDomainsOf(row.directoryDomains);
  return {
    id: row.id.toString(),
    publicId: row.publicId,
    organizationId: row.organizationId.toString(),
    provider: row.provider,
    connectionPublicId: row.connectorRef,
    settings: bindingSettingsOf(row.provider, row.settings),
    health: healthDetailOf(row.healthDetail),
    directoryRefHash: row.directoryRefHash,
    ...(domains.length > 0 ? { directoryDomains: domains } : {}),
  };
}

/**
 * The identity-provider side of the ato-worker (step 8.5 D1, D2, D7.5; ADR-0082): the adapter
 * configuration (`ATO_IDP_*`, endpoint override rule), 8.2's connection port with in-memory
 * tokens (`createProviderConnectionBinding`: the decrypting grant store, the token service and the
 * connection reader over the writer; R1, R3), one provider HTTPS client per provider kind, the
 * Redis rate budget, and the per-integration adapter factories registered in the 8.4
 * `ProviderRegistry` (PX2). Built only where a provider-calling role runs with the adapters on;
 * `ato-detect` never holds a credential (R3).
 */
export class IdpRuntime {
  readonly config: IdpAdapterConfig;
  readonly connections: ProviderConnectionAccess;
  readonly budget: RateBudget;
  private readonly http = new Map<AtoProviderKind, ProviderHttpClient>();
  private readonly cache = new Map<string, { key: string; adapter: IdpAdapter }>();

  constructor(
    workerConfig: Readonly<WorkerConfig>,
    private readonly deps: IdpRuntimeDeps,
  ) {
    const testEnv = workerConfig.APP_ENV === 'local' || workerConfig.APP_ENV === 'ci';
    const allowHttp = workerConfig.PROVIDER_ALLOW_HTTP_ENDPOINTS && testEnv;
    this.config = loadIdpAdapterConfig({
      env: idpEnvOf(workerConfig),
      appEnv: workerConfig.APP_ENV,
      allowHttpEndpoints: allowHttp,
    });
    // Rate budgets limit real request rates: wall-clock seconds, never the injected clock.
    this.budget = deps.budget ?? new RedisRateBudget(deps.redis, this.config.ratePerSecond);
    if (deps.connections) {
      this.connections = deps.connections;
    } else {
      if (!workerConfig.PROVIDER_CREDENTIAL_ENCRYPTION_KEY) {
        throw new Error('PROVIDER_CREDENTIAL_ENCRYPTION_KEY is required for the ATO adapters');
      }
      const endpoints = resolveProviderEndpoints({
        m365LoginUrl: workerConfig.PROVIDER_M365_LOGIN_URL,
        m365GraphUrl: workerConfig.PROVIDER_M365_GRAPH_URL,
        m365ManagementUrl: workerConfig.PROVIDER_M365_MANAGEMENT_URL,
        googleTokenUrl: workerConfig.PROVIDER_GOOGLE_TOKEN_URL,
        googleAdminUrl: workerConfig.PROVIDER_GOOGLE_ADMIN_URL,
        allowHttp,
      });
      const logger = deps.logger.child({ component: 'ato-idp-tokens' });
      this.connections = createProviderConnectionBinding({
        writer: deps.prisma,
        cipher: ProviderCredentialCipher.fromConfig({
          PROVIDER_CREDENTIAL_ENCRYPTION_KEY: workerConfig.PROVIDER_CREDENTIAL_ENCRYPTION_KEY,
          PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS:
            workerConfig.PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS,
        }),
        endpoints,
        // The six ATO profiles' platform apps / service accounts (key names in `platformApp`);
        // a configured path whose file is unreadable stops the worker (fail closed).
        platform: platformCredentialsFromEnv(
          workerConfig as unknown as Record<string, string | undefined>,
          atoPermissionProfiles(),
          {
            readFile: (path) => readFileSync(path, 'utf8'),
            googleTokenUrl: urlString(endpoints.googleToken),
            allowPlatformSecret: workerConfig.PROVIDER_M365_ALLOW_PLATFORM_SECRET,
          },
        ),
        // Per-user Gmail tokens (R1) plus admin and Graph tokens.
        cacheMax: this.config.gmailTokenCacheMax + 256,
        logger,
        now: deps.now,
      });
    }
  }

  /** The HTTPS client of a provider kind (one per process, D2). */
  httpClient(kind: AtoProviderKind): ProviderHttpClient {
    let client = this.http.get(kind);
    if (!client) {
      client = createProviderHttpClient(this.config, {
        provider: kind,
        logger: this.deps.logger.child({ component: 'ato-idp-http' }),
        ...(this.deps.metrics ? { metrics: this.deps.metrics.sink() } : {}),
        now: () => this.deps.now().getTime(),
      });
      this.http.set(kind, client);
    }
    return client;
  }

  /**
   * The adapter bound to an integration row (PX2). Cached per integration while its connection,
   * settings, status and last probe are unchanged, so per-adapter caches (user lookups, publisher
   * verification, Gmail tokens) survive between polls.
   */
  adapterFor(row: AtoProviderIntegration): IdpAdapter {
    const integration = adapterIntegrationOf(row);
    const key = [
      row.connectorRef,
      row.settingsVersion,
      row.healthCheckedAt?.getTime() ?? 0,
      row.directoryRefHash ?? '',
      JSON.stringify(integration.settings),
      (integration.directoryDomains ?? []).length,
    ].join('|');
    const hit = this.cache.get(integration.id);
    if (hit && hit.key === key) return hit.adapter;
    const kind = integration.provider;
    const adapter = createIdpAdapter(kind, {
      integration,
      connections: this.connections,
      http: this.httpClient(kind),
      budget: this.budget,
      mailboxState: new MysqlMailboxStateStore(
        this.deps.prisma,
        { organizationId: row.organizationId, integrationId: row.id },
        this.deps.now,
      ),
      actionState: new MysqlActionStateStore(this.deps.prisma, row.organizationId),
      clock: this.deps.now,
      config: this.config,
      ...(this.deps.metrics ? { metrics: this.deps.metrics.sink() } : {}),
      logger: this.deps.logger.child({ component: 'ato-idp-adapter' }),
      ...(this.deps.sleep ? { sleep: this.deps.sleep } : {}),
    });
    if (this.cache.size >= ADAPTER_CACHE_MAX && !this.cache.has(integration.id)) {
      const oldest = this.cache.keys().next().value;
      if (oldest !== undefined) this.cache.delete(oldest);
    }
    this.cache.set(integration.id, { key, adapter });
    return adapter;
  }

  /** Drops the cached adapter of an integration (after a probe or a status change). */
  forget(integrationId: bigint): void {
    this.cache.delete(integrationId.toString());
  }

  /** Registers the Microsoft Entra ID and Google Workspace factories (PX2). */
  register(registry: IdpRegistry): void {
    for (const kind of ['microsoft_entra', 'google_workspace'] as const) {
      registry.registerFactory(kind, (row) => this.adapterFor(row));
    }
  }
}
