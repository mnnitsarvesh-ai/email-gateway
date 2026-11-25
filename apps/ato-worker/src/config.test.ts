import { describe, expect, it } from 'vitest';
import {
  ATO_WORKER_ROLES,
  callsIdentityProviders,
  hasRole,
  idpEnvOf,
  loadWorkerConfig,
} from './config';

const HMAC = 'a'.repeat(48);
// Step 8.5: the provider-calling roles need 8.2's credential key while the adapters are on.
const CREDENTIAL_KEY = '0123456789abcdef'.repeat(4);
const base = {
  DATABASE_URL: 'mysql://u:p@localhost:3306/db',
  REDIS_URL: 'redis://localhost:6379/0',
  RABBITMQ_ATO_URL: 'amqp://u:p@localhost:5672/v',
  ATO_HMAC_KEY: HMAC,
  PROVIDER_CREDENTIAL_ENCRYPTION_KEY: CREDENTIAL_KEY,
};

describe('ato-worker config (§4.2)', () => {
  it('applies the design defaults', () => {
    const c = loadWorkerConfig(base);
    expect(c.HTTP_PORT).toBe(3085);
    expect(c.ATO_WORKER_ROLES).toEqual([...ATO_WORKER_ROLES]);
    expect(c).toMatchObject({
      ATO_EVENTS_PREFETCH: 32,
      ATO_MAIL_PREFETCH: 32,
      ATO_RESPONSES_PREFETCH: 4,
      ATO_TX_TIMEOUT_MS: 120_000,
      ATO_SETTINGS_CACHE_SECONDS: 30,
      ATO_GEOIP_RELOAD_SECONDS: 3600,
      ATO_GEOIP_MAX_AGE_DAYS: 35,
      ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: false,
      ATO_REPUTATION_TIMEOUT_MS: 1500,
      ATO_IP_CAMPAIGN_MIN_ACCOUNTS: 10,
      ATO_IP_CAMPAIGN_WINDOW_MINUTES: 60,
      ATO_IP_CAMPAIGN_FLAG_HOURS: 24,
      ATO_AUTOMATED_RESPONSES_ENABLED: true,
      ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR: 10,
      ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG: 500,
      ATO_APPROVAL_TTL_HOURS: 24,
      ATO_DECAY_SWEEP_INTERVAL_SECONDS: 900,
      ATO_BASELINE_REBUILD_HOUR_UTC: 2,
      ATO_BASELINE_BATCH: 500,
      ATO_MAINTENANCE_INTERVAL_SECONDS: 60,
      ATO_RETENTION_INCIDENT_DAYS: 730,
      ATO_MAIL_CATCHUP_INTERVAL_SECONDS: 600,
      ATO_MAIL_CATCHUP_LAG_SECONDS: 900,
      ATO_MAIL_CATCHUP_BATCH: 1000,
      ATO_MAIL_CATCHUP_MAX_AGE_HOURS: 24,
      ATO_PROVIDER_FAKE_ENABLED: false,
      ATO_PROVIDER_POLL_INTERVAL_SECONDS: 60,
      ATO_PROVIDER_MAX_PAGES_PER_POLL: 10,
      ATO_PROVIDER_MAX_CONSECUTIVE_FAILURES: 10,
      ATO_DIGEST_ENABLED: true,
    });
    expect(c.ATO_GEOIP_CITY_DB_PATH).toBeUndefined();
    expect(c.ATO_DNS_SERVERS).toEqual([]);
  });

  it('parses roles and refuses unknown or repeated roles', () => {
    const c = loadWorkerConfig({ ...base, ATO_WORKER_ROLES: 'respond, maintenance,provider' });
    expect(c.ATO_WORKER_ROLES).toEqual(['respond', 'maintenance', 'provider']);
    expect(hasRole(c, 'detect')).toBe(false);
    expect(() => loadWorkerConfig({ ...base, ATO_WORKER_ROLES: 'detect,scan' })).toThrow(
      /ATO_WORKER_ROLES/,
    );
    expect(() => loadWorkerConfig({ ...base, ATO_WORKER_ROLES: 'detect,detect' })).toThrow(/twice/);
  });

  it('requires the broker only for detect and respond', () => {
    const { RABBITMQ_ATO_URL: _url, ...noBroker } = base;
    void _url;
    expect(() => loadWorkerConfig(noBroker)).toThrow(/RABBITMQ_ATO_URL/);
    expect(
      loadWorkerConfig({ ...noBroker, ATO_WORKER_ROLES: 'maintenance,provider' }).RABBITMQ_ATO_URL,
    ).toBeUndefined();
  });

  it('refuses the test seams outside local and ci', () => {
    for (const APP_ENV of ['staging', 'production']) {
      expect(() =>
        loadWorkerConfig({ ...base, APP_ENV, ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: 'true' }),
      ).toThrow(/ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES/);
      expect(() =>
        loadWorkerConfig({ ...base, APP_ENV, ATO_PROVIDER_FAKE_ENABLED: 'true' }),
      ).toThrow(/ATO_PROVIDER_FAKE_ENABLED/);
    }
    for (const APP_ENV of ['local', 'ci']) {
      const c = loadWorkerConfig({
        ...base,
        APP_ENV,
        ATO_GEOIP_ALLOW_DOCUMENTATION_RANGES: 'true',
        ATO_PROVIDER_FAKE_ENABLED: 'true',
      });
      expect(c.ATO_PROVIDER_FAKE_ENABLED).toBe(true);
    }
  });

  it('enforces the bounds (transaction budget, key length, intervals, DNSBL syntax)', () => {
    expect(() => loadWorkerConfig({ ...base, ATO_TX_TIMEOUT_MS: '60000' })).toThrow(
      /ATO_TX_TIMEOUT_MS/,
    );
    expect(() => loadWorkerConfig({ ...base, ATO_HMAC_KEY: 'short' })).toThrow(/ATO_HMAC_KEY/);
    expect(() => loadWorkerConfig({ ...base, ATO_BASELINE_REBUILD_HOUR_UTC: '24' })).toThrow();
    expect(() => loadWorkerConfig({ ...base, ATO_IP_CAMPAIGN_MIN_ACCOUNTS: '1' })).toThrow();
    expect(() => loadWorkerConfig({ ...base, ATO_DNSBL_IP_ZONES: 'not a zone' })).toThrow(
      /ATO_DNSBL_IP_ZONES/,
    );
    expect(
      loadWorkerConfig({ ...base, ATO_DNSBL_IP_ZONES: 'xbl.example.test=127.0.0.4:other' })
        .ATO_DNSBL_IP_ZONES,
    ).toBe('xbl.example.test=127.0.0.4:other');
    expect(() => loadWorkerConfig({ ...base, ATO_DNS_SERVERS: 'dns.example' })).toThrow(
      /ATO_DNS_SERVERS/,
    );
    expect(
      loadWorkerConfig({ ...base, ATO_DNS_SERVERS: '192.0.2.53, [2001:db8::53]:5353' })
        .ATO_DNS_SERVERS,
    ).toEqual(['192.0.2.53', '[2001:db8::53]:5353']);
  });

  it('sizes the writer pool (step AI-4 D14): defaults, bounds and the pool-timeout rule', () => {
    expect(loadWorkerConfig(base)).toMatchObject({
      ATO_DATABASE_CONNECTION_LIMIT: 32,
      ATO_DATABASE_POOL_TIMEOUT_SECONDS: 30,
    });
    expect(
      loadWorkerConfig({
        ...base,
        ATO_DATABASE_CONNECTION_LIMIT: '4',
        ATO_DATABASE_POOL_TIMEOUT_SECONDS: '300',
      }),
    ).toMatchObject({ ATO_DATABASE_CONNECTION_LIMIT: 4, ATO_DATABASE_POOL_TIMEOUT_SECONDS: 300 });
    expect(loadWorkerConfig({ ...base, ATO_DATABASE_CONNECTION_LIMIT: '200' })).toMatchObject({
      ATO_DATABASE_CONNECTION_LIMIT: 200,
    });
    for (const value of ['3', '201', '2.5', 'many']) {
      expect(() => loadWorkerConfig({ ...base, ATO_DATABASE_CONNECTION_LIMIT: value })).toThrow(
        /ATO_DATABASE_CONNECTION_LIMIT/,
      );
    }
    for (const value of ['4', '301', '30.5']) {
      expect(() => loadWorkerConfig({ ...base, ATO_DATABASE_POOL_TIMEOUT_SECONDS: value })).toThrow(
        /ATO_DATABASE_POOL_TIMEOUT_SECONDS/,
      );
    }
    // In range (5–300) but shorter than the transaction maxWait of 30 s: refused, with the reason.
    for (const value of ['5', '29']) {
      expect(() => loadWorkerConfig({ ...base, ATO_DATABASE_POOL_TIMEOUT_SECONDS: value })).toThrow(
        /ATO_DATABASE_POOL_TIMEOUT_SECONDS.*at least 30/s,
      );
    }
  });

  it('never echoes a secret value in an error', () => {
    const secret = `x${'s'.repeat(10)}`;
    try {
      loadWorkerConfig({ ...base, ATO_HMAC_KEY: secret });
      expect.unreachable();
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(secret);
    }
  });
});

describe('ato-worker config: identity-provider adapters (step 8.5 §4.2)', () => {
  it('applies the §4.2 defaults (production origins, bounds)', () => {
    const c = loadWorkerConfig(base);
    expect(c).toMatchObject({
      ATO_IDP_ADAPTERS_ENABLED: true,
      ATO_IDP_GRAPH_BASE_URL: 'https://graph.microsoft.com',
      ATO_IDP_O365_MANAGEMENT_BASE_URL: 'https://manage.office.com',
      ATO_IDP_GOOGLE_ADMIN_BASE_URL: 'https://admin.googleapis.com',
      ATO_IDP_GMAIL_BASE_URL: 'https://gmail.googleapis.com',
      ATO_IDP_HTTP_TIMEOUT_MS: 15_000,
      ATO_IDP_HTTP_MAX_RESPONSE_BYTES: 8_388_608,
      ATO_IDP_MAX_BACKOFF_MS: 900_000,
      ATO_IDP_RATE_GRAPH_PER_SECOND: 5,
      ATO_IDP_RATE_O365_PER_SECOND: 2,
      ATO_IDP_RATE_GOOGLE_REPORTS_PER_SECOND: 2,
      ATO_IDP_RATE_GOOGLE_DIRECTORY_PER_SECOND: 5,
      ATO_IDP_RATE_GMAIL_PER_SECOND: 10,
      ATO_IDP_PAGE_MAX_EVENTS: 200,
      ATO_IDP_CLAIM_BATCH: 10,
      ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL: 200,
      ATO_IDP_GMAIL_TOKEN_CACHE_MAX: 2000,
      ATO_IDP_HEALTH_INTERVAL_SECONDS: 900,
      ATO_IDP_STREAM_LAG_WARN_SECONDS: 3600,
      ATO_IDP_BACKFILL_MAX_DAYS: 30,
      ATO_IDP_HISTORICAL_SIGNAL_AGE_HOURS: 24,
      ATO_IDP_CONFIRM_TIMEOUT_MINUTES: 30,
      PROVIDER_ALLOW_HTTP_ENDPOINTS: false,
      PROVIDER_M365_ALLOW_PLATFORM_SECRET: false,
      PROVIDER_M365_MANAGEMENT_URL: 'https://manage.office.com',
    });
    expect(c.PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_ID).toBeUndefined();
    expect(callsIdentityProviders(c)).toBe(true);
    expect(idpEnvOf(c).ATO_IDP_GRAPH_BASE_URL).toBe('https://graph.microsoft.com');
  });

  it('needs the credential key only where a provider-calling role runs (R3)', () => {
    const { PROVIDER_CREDENTIAL_ENCRYPTION_KEY: _key, ...noKey } = base;
    void _key;
    expect(() => loadWorkerConfig(noKey)).toThrow(/PROVIDER_CREDENTIAL_ENCRYPTION_KEY/);
    // ato-detect: no credential, no provider call.
    const detect = loadWorkerConfig({ ...noKey, ATO_WORKER_ROLES: 'detect' });
    expect(detect.PROVIDER_CREDENTIAL_ENCRYPTION_KEY).toBeUndefined();
    expect(callsIdentityProviders(detect)).toBe(false);
    // Adapters switched off: no key needed.
    const off = loadWorkerConfig({ ...noKey, ATO_IDP_ADAPTERS_ENABLED: 'false' });
    expect(callsIdentityProviders(off)).toBe(false);
    expect(() =>
      loadWorkerConfig({ ...base, PROVIDER_CREDENTIAL_ENCRYPTION_KEY: 'not-hex' }),
    ).toThrow(/PROVIDER_CREDENTIAL_ENCRYPTION_KEY/);
  });

  it('refuses endpoint overrides and http outside local and ci (D12)', () => {
    for (const APP_ENV of ['staging', 'production']) {
      expect(() =>
        loadWorkerConfig({
          ...base,
          APP_ENV,
          ATO_IDP_GRAPH_BASE_URL: 'https://graph.example.test',
        }),
      ).toThrow(/ATO_IDP_GRAPH_BASE_URL/);
      expect(() =>
        loadWorkerConfig({ ...base, APP_ENV, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true' }),
      ).toThrow(/PROVIDER_ALLOW_HTTP_ENDPOINTS/);
    }
    // Local: the simulator over http needs PROVIDER_ALLOW_HTTP_ENDPOINTS.
    const sim = 'http://idp-simulator:8080/graph';
    expect(() =>
      loadWorkerConfig({ ...base, APP_ENV: 'local', ATO_IDP_GRAPH_BASE_URL: sim }),
    ).toThrow(/ATO_IDP_GRAPH_BASE_URL/);
    const local = loadWorkerConfig({
      ...base,
      APP_ENV: 'local',
      ATO_IDP_GRAPH_BASE_URL: sim,
      PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true',
    });
    expect(local.ATO_IDP_GRAPH_BASE_URL).toBe(sim);
  });

  it('treats empty platform credential keys as unset and never echoes their values', () => {
    const c = loadWorkerConfig({
      ...base,
      PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_ID: '',
      PROVIDER_GOOGLE_ATO_RESPONSE_SA_KEY_PATH: ' ',
    });
    expect(c.PROVIDER_M365_ATO_TELEMETRY_APP_CLIENT_ID).toBeUndefined();
    expect(c.PROVIDER_GOOGLE_ATO_RESPONSE_SA_KEY_PATH).toBeUndefined();
    const secret = 'zz'.repeat(31);
    try {
      loadWorkerConfig({ ...base, PROVIDER_CREDENTIAL_ENCRYPTION_KEY: secret });
      expect.unreachable();
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(secret);
    }
  });
});
