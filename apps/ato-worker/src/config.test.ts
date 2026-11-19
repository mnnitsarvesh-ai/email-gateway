import { describe, expect, it } from 'vitest';
import { ATO_WORKER_ROLES, hasRole, loadWorkerConfig } from './config';

const HMAC = 'a'.repeat(48);
const base = {
  DATABASE_URL: 'mysql://u:p@localhost:3306/db',
  REDIS_URL: 'redis://localhost:6379/0',
  RABBITMQ_ATO_URL: 'amqp://u:p@localhost:5672/v',
  ATO_HMAC_KEY: HMAC,
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
