/**
 * A ready-wired Google Workspace adapter on the in-process simulators for library and worker
 * tests: the Google Admin SDK and Gmail simulators on 127.0.0.1, the in-memory connection port
 * with the three ATO grants (delegated administrator `ato-admin@fabrikam-it.example`), in-memory
 * state stores, a capturing logger and an injectable clock. Built through `createIdpAdapter`.
 */
import type { AdapterIntegration } from '../adapter-types';
import { loadIdpAdapterConfig, type IdpAdapterConfig } from '../config';
import { directoryRefHash } from '../core/hash';
import type { IdpMetricsSink, ProviderHttpClient } from '../core/http';
import { defaultBindingSettings, type IdpBindingSettings } from '../core/settings';
import { createIdpAdapter, createProviderHttpClient } from '../factory';
import type { GoogleAdapter } from '../google/adapter';
import type { RateBudget } from '../port/state-ports';
import { GOOGLE_PROFILES, PERMISSION_REQUIREMENTS } from '../requirements';
import {
  GS_ADMIN_EMAIL,
  GS_CUSTOMER_ID,
  GS_DOMAIN,
  GS_MFA_OU,
  GS_UNVERIFIED_DOMAIN,
  googleCustomer,
} from './datasets/google';
import { CapturingLogger, TEST_ORGANIZATION_ID, TestClock, immediateSleep } from './harness';
import { InMemoryConnectionAccess, type InMemoryGrant } from './in-memory-connections';
import {
  InMemoryActionStateStore,
  InMemoryMailboxStateStore,
  UnlimitedRateBudget,
} from './in-memory-stores';
import type { GsCustomer } from './simulators/google-types';
import { startSimulators, type RunningSimulators } from './simulators/main';

export const TEST_GS_CONNECTION_ID = '0190aaaa-0000-7000-8000-000000000002';
export const TEST_GS_INTEGRATION_ID = '502';
export const TEST_GS_INTEGRATION_PUBLIC_ID = '0190bbbb-0000-7000-8000-000000000002';

/** Scopes of each Google ATO profile (D5), as `PERMISSION_REQUIREMENTS` lists them. */
export function googleProfileScopes(profile: string): string[] {
  const found = PERMISSION_REQUIREMENTS.google_workspace.profiles.find((p) => p.key === profile);
  if (!found) throw new Error(`unknown_profile: ${profile}`);
  return found.permissions.map((permission) => permission.name);
}

export function defaultGoogleGrants(): InMemoryGrant[] {
  return [
    {
      publicId: '0190cccc-0000-7000-8000-000000000011',
      profile: GOOGLE_PROFILES.telemetry,
      status: 'active',
      subjectEmail: GS_ADMIN_EMAIL,
      permissions: googleProfileScopes(GOOGLE_PROFILES.telemetry),
    },
    {
      publicId: '0190cccc-0000-7000-8000-000000000012',
      profile: GOOGLE_PROFILES.response,
      status: 'active',
      subjectEmail: GS_ADMIN_EMAIL,
      permissions: googleProfileScopes(GOOGLE_PROFILES.response),
    },
    {
      publicId: '0190cccc-0000-7000-8000-000000000013',
      profile: GOOGLE_PROFILES.responseExtended,
      status: 'active',
      subjectEmail: GS_ADMIN_EMAIL,
      permissions: googleProfileScopes(GOOGLE_PROFILES.responseExtended),
    },
  ];
}

export interface GoogleTestbedOptions {
  now?: Date;
  customer?: (now: Date) => GsCustomer;
  settings?: (settings: IdpBindingSettings) => IdpBindingSettings;
  /** Grants of the connection (default: the three profiles, active, with their scopes). */
  grants?: InMemoryGrant[];
  budget?: RateBudget;
  metrics?: IdpMetricsSink;
  configEnv?: Record<string, string>;
}

export interface GoogleTestbed {
  clock: TestClock;
  sims: RunningSimulators;
  customer: GsCustomer;
  connections: InMemoryConnectionAccess;
  mailboxState: InMemoryMailboxStateStore;
  actionState: InMemoryActionStateStore;
  budget: RateBudget;
  logger: CapturingLogger;
  config: IdpAdapterConfig;
  http: ProviderHttpClient;
  integration: AdapterIntegration;
  adapter: GoogleAdapter;
  /** A fresh adapter over the same dependencies (e.g. another worker process). */
  newAdapter(integration?: Partial<AdapterIntegration>): GoogleAdapter;
  stop(): Promise<void>;
}

export async function createGoogleTestbed(
  options: GoogleTestbedOptions = {},
): Promise<GoogleTestbed> {
  const clock = new TestClock(options.now ?? new Date('2026-11-10T12:00:00.000Z'));
  const customer = (options.customer ?? googleCustomer)(clock.now());
  const sims = await startSimulators({
    dataset: { google: { customers: [customer] } },
    now: clock.ms,
  });
  const connections = new InMemoryConnectionAccess(sims.tokens, { now: clock.ms });
  connections.add({
    publicId: TEST_GS_CONNECTION_ID,
    organizationId: TEST_ORGANIZATION_ID,
    provider: 'google_workspace',
    displayName: 'Fabrikam IT (example)',
    status: 'active',
    externalTenantId: GS_CUSTOMER_ID,
    linkedDomains: [
      { name: GS_DOMAIN, providerVerified: true },
      { name: GS_UNVERIFIED_DOMAIN, providerVerified: false },
    ],
    grants: options.grants ?? defaultGoogleGrants(),
    updatedAt: clock.now().toISOString(),
  });
  const logger = new CapturingLogger();
  const config = loadIdpAdapterConfig({
    env: {
      ATO_IDP_GOOGLE_ADMIN_BASE_URL: sims.baseUrl('google-admin'),
      ATO_IDP_GMAIL_BASE_URL: sims.baseUrl('gmail'),
      ATO_IDP_HTTP_TIMEOUT_MS: '5000',
      ...options.configEnv,
    },
    appEnv: 'ci',
    allowHttpEndpoints: true,
  });
  const http = createProviderHttpClient(config, {
    provider: 'google_workspace',
    logger,
    ...(options.metrics ? { metrics: options.metrics } : {}),
    random: () => 0.5,
    now: clock.ms,
    env: {},
  });
  const settings = defaultBindingSettings();
  settings.mfaEnforcement.orgUnitPath = GS_MFA_OU;
  const integration: AdapterIntegration = {
    id: TEST_GS_INTEGRATION_ID,
    publicId: TEST_GS_INTEGRATION_PUBLIC_ID,
    organizationId: TEST_ORGANIZATION_ID,
    provider: 'google_workspace',
    connectionPublicId: TEST_GS_CONNECTION_ID,
    settings: options.settings ? options.settings(settings) : settings,
    health: null,
    directoryRefHash: directoryRefHash('google_workspace', GS_CUSTOMER_ID),
  };
  const mailboxState = new InMemoryMailboxStateStore(clock.ms);
  const actionState = new InMemoryActionStateStore();
  const budget = options.budget ?? new UnlimitedRateBudget();
  const build = (patch: Partial<AdapterIntegration> = {}) =>
    createIdpAdapter('google_workspace', {
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
    }) as GoogleAdapter;
  return {
    clock,
    sims,
    customer,
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
