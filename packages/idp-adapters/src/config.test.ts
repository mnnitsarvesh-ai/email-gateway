import { describe, expect, it } from 'vitest';
import { IdpConfigError, PRODUCTION_BASE_URLS, loadIdpAdapterConfig } from './config';

describe('idpAdapterConfigSchema (§4.2, D2, D12)', () => {
  it('applies the documented defaults', () => {
    const config = loadIdpAdapterConfig({ env: {}, appEnv: 'production' });
    expect(config).toMatchObject({
      enabled: true,
      baseUrls: PRODUCTION_BASE_URLS,
      allowHttpEndpoints: false,
      httpTimeoutMs: 15_000,
      httpMaxResponseBytes: 8_388_608,
      maxBackoffMs: 900_000,
      ratePerSecond: { graph: 5, o365: 2, google_reports: 2, google_directory: 5, gmail: 10 },
      pageMaxEvents: 200,
      claimBatch: 10,
      snapshotMaxUsersPerPoll: 200,
      gmailTokenCacheMax: 2_000,
      healthIntervalSeconds: 900,
      streamLagWarnSeconds: 3_600,
      backfillMaxDays: 30,
      historicalSignalAgeHours: 24,
      confirmTimeoutMinutes: 30,
      maxIntegrationsPerOrg: 5,
    });
  });

  it('accepts the production defaults explicitly (trailing slash ignored) and empty values', () => {
    const config = loadIdpAdapterConfig({
      env: { ATO_IDP_GRAPH_BASE_URL: 'https://graph.microsoft.com/', ATO_IDP_GMAIL_BASE_URL: '' },
      appEnv: 'production',
    });
    expect(config.baseUrls.graph).toBe('https://graph.microsoft.com');
    expect(config.baseUrls.gmail).toBe('https://gmail.googleapis.com');
  });

  it('refuses endpoint overrides outside local and ci', () => {
    for (const appEnv of ['production', 'staging', 'development']) {
      expect(() =>
        loadIdpAdapterConfig({
          env: { ATO_IDP_O365_MANAGEMENT_BASE_URL: 'https://sim.example/o365' },
          appEnv,
        }),
      ).toThrow(
        new IdpConfigError('ato_idp_endpoint_override_refused', 'ATO_IDP_O365_MANAGEMENT_BASE_URL'),
      );
    }
    expect(
      loadIdpAdapterConfig({
        env: { ATO_IDP_O365_MANAGEMENT_BASE_URL: 'https://sim.example/o365' },
        appEnv: 'local',
      }).baseUrls.o365,
    ).toBe('https://sim.example/o365');
  });

  it('allows http only with allowHttpEndpoints in local/ci, and refuses the flag elsewhere', () => {
    const env = { ATO_IDP_GRAPH_BASE_URL: 'http://idp-simulator:8080/graph' };
    expect(() => loadIdpAdapterConfig({ env, appEnv: 'ci' })).toThrow(
      'ato_idp_http_endpoint_refused',
    );
    expect(
      loadIdpAdapterConfig({ env, appEnv: 'ci', allowHttpEndpoints: true }).baseUrls.graph,
    ).toBe('http://idp-simulator:8080/graph');
    expect(() =>
      loadIdpAdapterConfig({ env: {}, appEnv: 'production', allowHttpEndpoints: true }),
    ).toThrow('ato_idp_http_endpoint_refused');
  });

  it('refuses invalid numbers and names the key, never the value', () => {
    try {
      loadIdpAdapterConfig({
        env: { ATO_IDP_PAGE_MAX_EVENTS: 'EXAMPLE-not-a-number' },
        appEnv: 'ci',
      });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(IdpConfigError);
      expect((error as IdpConfigError).code).toBe('ato_idp_config_invalid');
      expect(String(error)).toContain('ATO_IDP_PAGE_MAX_EVENTS');
      expect(String(error)).not.toContain('EXAMPLE-not-a-number');
    }
    expect(() =>
      loadIdpAdapterConfig({ env: { ATO_IDP_BACKFILL_MAX_DAYS: '31' }, appEnv: 'ci' }),
    ).toThrow(IdpConfigError);
    expect(() =>
      loadIdpAdapterConfig({ env: { ATO_IDP_ADAPTERS_ENABLED: 'yes' }, appEnv: 'ci' }),
    ).toThrow(IdpConfigError);
    expect(
      loadIdpAdapterConfig({ env: { ATO_IDP_ADAPTERS_ENABLED: 'false' }, appEnv: 'ci' }).enabled,
    ).toBe(false);
  });
});
