import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { AdapterDeps } from './adapter-types';
import { loadIdpAdapterConfig } from './config';
import { defaultBindingSettings } from './core/settings';
import {
  IDP_ADAPTER_VERSIONS,
  IdpAdapterFactoryError,
  createIdpAdapter,
  createProviderHttpClient,
  isAtoProviderKind,
} from './factory';
import { GoogleAdapter } from './google/adapter';
import { hasIdpAdapterExtras } from './adapter-types';
import { MicrosoftAdapter } from './microsoft/adapter';
import type { AtoProviderKind } from './kinds';
import { InMemoryConnectionAccess } from './testing/in-memory-connections';
import {
  InMemoryActionStateStore,
  InMemoryMailboxStateStore,
  UnlimitedRateBudget,
} from './testing/in-memory-stores';
import { SimTokenRegistry } from './testing/simulators/tokens';
import { createGoogleTestbed, type GoogleTestbed } from './testing/google-harness';

function deps(provider: AtoProviderKind): AdapterDeps {
  const config = loadIdpAdapterConfig({ env: {}, appEnv: 'production' });
  return {
    integration: {
      id: '1',
      publicId: '0190bbbb-0000-7000-8000-00000000000f',
      organizationId: '1001',
      provider,
      connectionPublicId: '0190aaaa-0000-7000-8000-00000000000f',
      settings: defaultBindingSettings(),
      health: null,
    },
    connections: new InMemoryConnectionAccess(new SimTokenRegistry()),
    http: createProviderHttpClient(config, { env: {} }),
    budget: new UnlimitedRateBudget(),
    mailboxState: new InMemoryMailboxStateStore(),
    actionState: new InMemoryActionStateStore(),
    clock: () => new Date(),
    config,
  };
}

describe('createIdpAdapter (D1)', () => {
  it('creates the adapter of each kind with its version and the 8.5 extras', () => {
    const microsoft = createIdpAdapter('microsoft_entra', deps('microsoft_entra'));
    const google = createIdpAdapter('google_workspace', deps('google_workspace'));
    expect(microsoft).toBeInstanceOf(MicrosoftAdapter);
    expect(google).toBeInstanceOf(GoogleAdapter);
    expect([microsoft.version, google.version]).toEqual(['msgraph-ato/1', 'gws-ato/1']);
    expect(IDP_ADAPTER_VERSIONS).toEqual({
      microsoft_entra: 'msgraph-ato/1',
      google_workspace: 'gws-ato/1',
    });
    expect(hasIdpAdapterExtras(microsoft) && hasIdpAdapterExtras(google)).toBe(true);
    expect(google.kind).toBe('google_workspace');
  });

  it('refuses an integration of another provider and an unknown kind', () => {
    expect(() => createIdpAdapter('google_workspace', deps('microsoft_entra'))).toThrow(
      new IdpAdapterFactoryError('adapter_provider_mismatch'),
    );
    expect(() => createIdpAdapter('okta' as AtoProviderKind, deps('microsoft_entra'))).toThrow(
      new IdpAdapterFactoryError('adapter_kind_unknown'),
    );
    expect(isAtoProviderKind('google_workspace')).toBe(true);
    expect(isAtoProviderKind('fake')).toBe(false);
  });

  it('builds the provider HTTP client from the configuration (production origins by default)', () => {
    const config = loadIdpAdapterConfig({ env: {}, appEnv: 'production' });
    const http = createProviderHttpClient(config, { env: {} });
    expect(http.baseUrl('google_reports')).toBe('https://admin.googleapis.com');
    expect(http.baseUrl('google_directory')).toBe('https://admin.googleapis.com');
    expect(http.baseUrl('gmail')).toBe('https://gmail.googleapis.com');
    expect(http.baseUrl('graph')).toBe('https://graph.microsoft.com');
  });
});

describe('createIdpAdapter: Google adapter wired end to end on the simulators', () => {
  let tb: GoogleTestbed;
  beforeAll(async () => {
    tb = await createGoogleTestbed();
  });
  afterAll(async () => {
    await tb.stop();
  });

  it('ingests and probes through the factory-built adapter', async () => {
    const signal = new AbortController().signal;
    expect((await tb.adapter.probe(signal)).ok).toBe(true);
    expect((await tb.adapter.ingest('sign_ins', null, signal)).events.length).toBeGreaterThan(0);
  });
});
