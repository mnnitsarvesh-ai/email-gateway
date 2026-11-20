/**
 * A ready-wired Microsoft adapter on the in-process simulators for library and worker tests: the
 * Graph and Office 365 Management simulators on 127.0.0.1, the in-memory connection port with the
 * three ATO grants, in-memory state stores, a capturing logger and an injectable clock.
 */
import type { AdapterIntegration } from '../adapter-types';
import { loadIdpAdapterConfig, type IdpAdapterConfig } from '../config';
import type { Sleep } from '../core/budget';
import { directoryRefHash } from '../core/hash';
import { ProviderHttpClient, type IdpLogger, type IdpMetricsSink } from '../core/http';
import { defaultBindingSettings, type IdpBindingSettings } from '../core/settings';
import { createMicrosoftAdapter, type MicrosoftAdapter } from '../microsoft/adapter';
import type { RateBudget } from '../port/state-ports';
import { MICROSOFT_PROFILES } from '../requirements';
import {
  MS_DOMAIN,
  MS_MFA_GROUP_ID,
  MS_PROFILE_PERMISSIONS,
  MS_TENANT_ID,
  microsoftDirectory,
} from './datasets/microsoft';
import { InMemoryConnectionAccess, type InMemoryGrant } from './in-memory-connections';
import {
  InMemoryActionStateStore,
  InMemoryMailboxStateStore,
  UnlimitedRateBudget,
} from './in-memory-stores';
import { startSimulators, type RunningSimulators } from './simulators/main';
import type { MsDirectory } from './simulators/types';

export const TEST_ORGANIZATION_ID = '1001';
export const TEST_MS_CONNECTION_ID = '0190aaaa-0000-7000-8000-000000000001';
export const TEST_MS_INTEGRATION_ID = '501';
export const TEST_MS_INTEGRATION_PUBLIC_ID = '0190bbbb-0000-7000-8000-000000000001';

export interface CapturedLog {
  level: 'debug' | 'warn';
  obj: Record<string, unknown>;
  msg: string;
}

export class CapturingLogger implements IdpLogger {
  readonly lines: CapturedLog[] = [];
  debug(obj: Record<string, unknown>, msg: string): void {
    this.lines.push({ level: 'debug', obj, msg });
  }
  warn(obj: Record<string, unknown>, msg: string): void {
    this.lines.push({ level: 'warn', obj, msg });
  }
  /** Everything logged, serialized (for leak assertions). */
  text(): string {
    return JSON.stringify(this.lines);
  }
}

/** A settable clock shared by the adapter, the HTTP client, the stores and the simulators. */
export class TestClock {
  constructor(private current: Date) {}
  now = (): Date => new Date(this.current.getTime());
  ms = (): number => this.current.getTime();
  set(date: Date): void {
    this.current = new Date(date.getTime());
  }
  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
}

export const immediateSleep: Sleep = () => Promise.resolve();

export interface MicrosoftTestbedOptions {
  now?: Date;
  directory?: (now: Date) => MsDirectory;
  settings?: (settings: IdpBindingSettings) => IdpBindingSettings;
  /** Grants of the connection (default: the three profiles, active, with their permissions). */
  grants?: InMemoryGrant[];
  budget?: RateBudget;
  metrics?: IdpMetricsSink;
  configEnv?: Record<string, string>;
}

export interface MicrosoftTestbed {
  clock: TestClock;
  sims: RunningSimulators;
  directory: MsDirectory;
  connections: InMemoryConnectionAccess;
  mailboxState: InMemoryMailboxStateStore;
  actionState: InMemoryActionStateStore;
  budget: RateBudget;
  logger: CapturingLogger;
  config: IdpAdapterConfig;
  http: ProviderHttpClient;
  integration: AdapterIntegration;
  adapter: MicrosoftAdapter;
  /** A fresh adapter over the same dependencies (e.g. another worker process). */
  newAdapter(integration?: Partial<AdapterIntegration>): MicrosoftAdapter;
  stop(): Promise<void>;
}

export function defaultMicrosoftGrants(): InMemoryGrant[] {
  return [
    {
      publicId: '0190cccc-0000-7000-8000-000000000001',
      profile: MICROSOFT_PROFILES.telemetry,
      status: 'active',
      permissions: [...MS_PROFILE_PERMISSIONS['m365.ato_telemetry']],
    },
    {
      publicId: '0190cccc-0000-7000-8000-000000000002',
      profile: MICROSOFT_PROFILES.response,
      status: 'active',
      permissions: [...MS_PROFILE_PERMISSIONS['m365.ato_response']],
    },
    {
      publicId: '0190cccc-0000-7000-8000-000000000003',
      profile: MICROSOFT_PROFILES.responseExtended,
      status: 'active',
      permissions: [...MS_PROFILE_PERMISSIONS['m365.ato_response_extended']],
    },
  ];
}

export async function createMicrosoftTestbed(
  options: MicrosoftTestbedOptions = {},
): Promise<MicrosoftTestbed> {
  const clock = new TestClock(options.now ?? new Date('2026-11-10T12:00:00.000Z'));
  const directory = (options.directory ?? microsoftDirectory)(clock.now());
  const sims = await startSimulators({
    dataset: { microsoft: { directories: [directory] } },
    now: clock.ms,
  });
  const connections = new InMemoryConnectionAccess(sims.tokens, { now: clock.ms });
  connections.add({
    publicId: TEST_MS_CONNECTION_ID,
    organizationId: TEST_ORGANIZATION_ID,
    provider: 'microsoft_365',
    displayName: 'Contoso IT (example)',
    status: 'active',
    externalTenantId: MS_TENANT_ID,
    linkedDomains: [{ name: MS_DOMAIN, providerVerified: true }],
    grants: options.grants ?? defaultMicrosoftGrants(),
    updatedAt: clock.now().toISOString(),
  });
  const logger = new CapturingLogger();
  const config = loadIdpAdapterConfig({
    env: {
      ATO_IDP_GRAPH_BASE_URL: sims.baseUrl('graph'),
      ATO_IDP_O365_MANAGEMENT_BASE_URL: sims.baseUrl('o365'),
      ATO_IDP_HTTP_TIMEOUT_MS: '5000',
      ...options.configEnv,
    },
    appEnv: 'ci',
    allowHttpEndpoints: true,
  });
  const http = new ProviderHttpClient({
    baseUrls: config.baseUrls,
    allowHttpEndpoints: config.allowHttpEndpoints,
    timeoutMs: config.httpTimeoutMs,
    maxResponseBytes: config.httpMaxResponseBytes,
    maxBackoffMs: config.maxBackoffMs,
    provider: 'microsoft_entra',
    logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    random: () => 0.5,
    now: clock.ms,
    env: {},
  });
  const settings = defaultBindingSettings();
  settings.mfaEnforcement.groupId = MS_MFA_GROUP_ID;
  const integration: AdapterIntegration = {
    id: TEST_MS_INTEGRATION_ID,
    publicId: TEST_MS_INTEGRATION_PUBLIC_ID,
    organizationId: TEST_ORGANIZATION_ID,
    provider: 'microsoft_entra',
    connectionPublicId: TEST_MS_CONNECTION_ID,
    settings: options.settings ? options.settings(settings) : settings,
    health: null,
    directoryRefHash: directoryRefHash('microsoft_entra', MS_TENANT_ID),
  };
  const mailboxState = new InMemoryMailboxStateStore(clock.ms);
  const actionState = new InMemoryActionStateStore();
  const budget = options.budget ?? new UnlimitedRateBudget();
  const build = (patch: Partial<AdapterIntegration> = {}) =>
    createMicrosoftAdapter({
      integration: { ...integration, ...patch },
      connections,
      http,
      budget,
      mailboxState,
      actionState,
      clock: clock.now,
      config,
      logger,
      sleep: immediateSleep,
      ...(options.metrics ? { metrics: options.metrics } : {}),
    });
  return {
    clock,
    sims,
    directory,
    connections,
    mailboxState,
    actionState,
    budget,
    logger,
    config,
    http,
    integration,
    adapter: build(),
    newAdapter: build,
    stop: () => sims.stop(),
  };
}
