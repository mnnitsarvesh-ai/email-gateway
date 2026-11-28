import { describe, expect, it } from 'vitest';
import { hasRole, loadWorkerConfig, notificationsAvailable } from './config';

const KEY = 'a'.repeat(64);
const base = {
  APP_ENV: 'local',
  DATABASE_URL: 'mysql://user:example-password@127.0.0.1:3306/db',
  REDIS_URL: 'redis://127.0.0.1:6379/0',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'gateway-mail',
  S3_BUCKET_ARCHIVE: 'gateway-archive',
  RABBITMQ_MAILBOX_URL: 'amqp://eg-mailbox:example-password@127.0.0.1:5672/email-gateway',
  PROVIDER_CREDENTIAL_ENCRYPTION_KEY: KEY,
};

const fails = (env: Record<string, string>, key: string) => {
  expect(() => loadWorkerConfig(env as NodeJS.ProcessEnv)).toThrow(key);
};

describe('mailbox-worker configuration (D16)', () => {
  it('applies the design defaults', () => {
    const cfg = loadWorkerConfig(base);
    expect(cfg.MAILBOX_WORKER_HTTP_PORT).toBe(3087);
    expect(cfg.MAILBOX_WORKER_ROLES).toEqual([
      'copies',
      'feeds',
      'inventory',
      'health',
      'remediate',
      'clawback',
      'reports',
    ]);
    expect(cfg.API_MODE_GRAPH_URL).toBe('https://graph.microsoft.com');
    expect(cfg.API_MODE_FEED_TICK_MS).toBe(5000);
    expect(cfg.API_MODE_FEED_BATCH).toBe(50);
    expect(cfg.API_MODE_FETCH_CONCURRENCY).toBe(16);
    expect(cfg.API_MODE_FETCH_CONCURRENCY_PER_CONNECTION).toBe(4);
    expect(cfg.API_MODE_GRAPH_REQUESTS_PER_SECOND).toBe(8);
    expect(cfg.API_MODE_GMAIL_REQUESTS_PER_SECOND).toBe(10);
    expect(cfg.API_MODE_DIRECTORY_REQUESTS_PER_SECOND).toBe(5);
    expect(cfg.API_MODE_MAX_MESSAGE_BYTES).toBe(52_428_800);
    expect(cfg.API_MODE_GRAPH_SUBSCRIPTION_MINUTES).toBe(4230);
    expect(cfg.API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES).toBe(720);
    expect(cfg.API_MODE_DEDUPE_WINDOW_HOURS).toBe(168);
    expect(cfg.API_MODE_HYBRID_LINK_WINDOW_HOURS).toBe(72);
    expect(cfg.API_MODE_COUNTER_FLUSH_SECONDS).toBe(30);
    expect(cfg.INGEST_HEADER_MAX_BYTES).toBe(65_536);
    expect(notificationsAvailable(cfg)).toBe(false);
    expect(hasRole(cfg, 'health')).toBe(true);
  });

  it('parses roles and refuses unknown or repeated ones', () => {
    const cfg = loadWorkerConfig({ ...base, MAILBOX_WORKER_ROLES: 'copies, health' });
    expect(cfg.MAILBOX_WORKER_ROLES).toEqual(['copies', 'health']);
    expect(
      loadWorkerConfig({ ...base, MAILBOX_WORKER_ROLES: 'copies,remediate' }).MAILBOX_WORKER_ROLES,
    ).toEqual(['copies', 'remediate']);
    fails({ ...base, MAILBOX_WORKER_ROLES: 'copies,purge' }, 'MAILBOX_WORKER_ROLES');
    fails({ ...base, MAILBOX_WORKER_ROLES: ' , ' }, 'MAILBOX_WORKER_ROLES');
    fails({ ...base, MAILBOX_WORKER_ROLES: 'copies,copies' }, 'MAILBOX_WORKER_ROLES');
  });

  it('refuses http and foreign provider origins outside local/ci', () => {
    const prod = { ...base, APP_ENV: 'production' };
    expect(() => loadWorkerConfig(prod as NodeJS.ProcessEnv)).not.toThrow();
    fails({ ...prod, API_MODE_GRAPH_URL: 'https://graph.example' }, 'API_MODE_GRAPH_URL');
    fails({ ...prod, API_MODE_ALLOW_HTTP_ENDPOINTS: 'true' }, 'API_MODE_ALLOW_HTTP_ENDPOINTS');
    fails({ ...prod, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true' }, 'PROVIDER_ALLOW_HTTP_ENDPOINTS');
    fails(
      {
        ...prod,
        API_MODE_GRAPH_NOTIFICATION_URL: 'http://api.example/api/v1/provider-notifications/graph',
        API_MODE_NOTIFICATION_SECRET: 'b'.repeat(64),
      },
      'API_MODE_GRAPH_NOTIFICATION_URL',
    );
  });

  it('allows the simulator origins over http locally only with the switch', () => {
    const sim = { ...base, API_MODE_GRAPH_URL: 'http://idp-simulator:8080/graph' };
    fails(sim, 'API_MODE_GRAPH_URL');
    const cfg = loadWorkerConfig({ ...sim, API_MODE_ALLOW_HTTP_ENDPOINTS: 'true' });
    expect(cfg.API_MODE_GRAPH_URL).toBe('http://idp-simulator:8080/graph');
  });

  it('needs the credential key for provider roles, the broker URL for copies', () => {
    const { PROVIDER_CREDENTIAL_ENCRYPTION_KEY: _k, ...noKey } = base;
    fails(noKey, 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
    expect(() =>
      loadWorkerConfig({ ...noKey, MAILBOX_WORKER_ROLES: 'copies,health' }),
    ).not.toThrow();
    const { RABBITMQ_MAILBOX_URL: _u, ...noBroker } = base;
    fails(noBroker, 'RABBITMQ_MAILBOX_URL');
    expect(() => loadWorkerConfig({ ...noBroker, MAILBOX_WORKER_ROLES: 'feeds' })).not.toThrow();
    // The remediate role calls providers (decrypts grants) like feeds and inventory.
    fails({ ...noKey, MAILBOX_WORKER_ROLES: 'remediate' }, 'PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
  });

  it('applies the step API-2 remediation defaults (R17) and the quarantine bounds', () => {
    const cfg = loadWorkerConfig(base);
    expect(hasRole(cfg, 'remediate')).toBe(true);
    expect(cfg).toMatchObject({
      API_MODE_REMEDIATION_TICK_MS: 2000,
      API_MODE_REMEDIATION_BATCH: 50,
      API_MODE_REMEDIATION_LEASE_SECONDS: 120,
      API_MODE_REMEDIATION_CONCURRENCY: 8,
      API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION: 2,
      API_MODE_REMEDIATION_MAX_ATTEMPTS: 8,
      API_MODE_REMEDIATION_LOCATE_ATTEMPTS: 6,
      API_MODE_REMEDIATION_BACKOFF_MAX_SECONDS: 3600,
      API_MODE_QUARANTINE_FOLDER_NAME: 'Email Gateway Quarantine',
      API_MODE_QUARANTINE_FOLDER_HIDDEN: true,
      API_MODE_GMAIL_QUARANTINE_LABEL: 'Email Gateway/Quarantine',
      API_MODE_TAG_NAME: 'Email Gateway: Suspicious',
      API_MODE_HARD_DELETE_ENABLED: false,
      API_MODE_REMEDIATION_FAILURE_WARN_PERCENT: 10,
      API_MODE_REMEDIATION_FAILURE_FAIL_PERCENT: 50,
      API_MODE_REMEDIATION_BACKLOG_WARN_MINUTES: 15,
      API_MODE_REMEDIATION_BACKLOG_FAIL_MINUTES: 60,
      API_MODE_REMEDIATION_RETENTION_DAYS: 400,
      QUARANTINE_MAX_HOLD_DAYS: 60,
      QUARANTINE_MAX_REVIEW_DAYS: 13,
    });
    const custom = loadWorkerConfig({
      ...base,
      API_MODE_HARD_DELETE_ENABLED: 'true',
      API_MODE_QUARANTINE_FOLDER_NAME: '  Threats  ',
      API_MODE_TAG_NAME: '',
    });
    expect(custom.API_MODE_HARD_DELETE_ENABLED).toBe(true);
    expect(custom.API_MODE_QUARANTINE_FOLDER_NAME).toBe('Threats');
    expect(custom.API_MODE_TAG_NAME).toBe('Email Gateway: Suspicious');
  });

  it('bounds the remediation keys', () => {
    fails({ ...base, API_MODE_REMEDIATION_BATCH: '0' }, 'API_MODE_REMEDIATION_BATCH');
    fails(
      { ...base, API_MODE_REMEDIATION_LEASE_SECONDS: '5' },
      'API_MODE_REMEDIATION_LEASE_SECONDS',
    );
    fails(
      { ...base, API_MODE_REMEDIATION_RETENTION_DAYS: '7' },
      'API_MODE_REMEDIATION_RETENTION_DAYS',
    );
    fails(
      { ...base, API_MODE_QUARANTINE_FOLDER_NAME: 'a\u0001b' },
      'API_MODE_QUARANTINE_FOLDER_NAME',
    );
    fails(
      { ...base, API_MODE_GMAIL_QUARANTINE_LABEL: 'x'.repeat(226) },
      'API_MODE_GMAIL_QUARANTINE_LABEL',
    );
    fails({ ...base, API_MODE_HARD_DELETE_ENABLED: 'yes' }, 'API_MODE_HARD_DELETE_ENABLED');
    fails({ ...base, QUARANTINE_MAX_HOLD_DAYS: '90' }, 'QUARANTINE_MAX_HOLD_DAYS');
    fails({ ...base, QUARANTINE_MAX_REVIEW_DAYS: '14' }, 'QUARANTINE_MAX_REVIEW_DAYS');
  });

  it('needs the notification secret with a notification URL', () => {
    const url = 'https://gateway.example/api/v1/provider-notifications/graph';
    fails({ ...base, API_MODE_GRAPH_NOTIFICATION_URL: url }, 'API_MODE_NOTIFICATION_SECRET');
    fails(
      {
        ...base,
        API_MODE_GRAPH_NOTIFICATION_URL: `${url}?token=x`,
        API_MODE_NOTIFICATION_SECRET: 'c'.repeat(64),
      },
      'API_MODE_GRAPH_NOTIFICATION_URL',
    );
    const cfg = loadWorkerConfig({
      ...base,
      API_MODE_GRAPH_NOTIFICATION_URL: url,
      API_MODE_NOTIFICATION_SECRET: 'c'.repeat(64),
    });
    expect(notificationsAvailable(cfg)).toBe(true);
  });

  it('keeps thresholds ordered', () => {
    fails(
      { ...base, API_MODE_COVERAGE_FAIL_PERCENT: '96', API_MODE_COVERAGE_WARN_PERCENT: '95' },
      'API_MODE_COVERAGE_FAIL_PERCENT',
    );
    fails({ ...base, API_MODE_LAG_FAIL_SECONDS: '100' }, 'API_MODE_LAG_FAIL_SECONDS');
    fails(
      { ...base, API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES: '4230' },
      'API_MODE_SUBSCRIPTION_RENEW_BEFORE_MINUTES',
    );
    fails(
      {
        ...base,
        API_MODE_REMEDIATION_FAILURE_WARN_PERCENT: '40',
        API_MODE_REMEDIATION_FAILURE_FAIL_PERCENT: '30',
      },
      'API_MODE_REMEDIATION_FAILURE_FAIL_PERCENT',
    );
    fails(
      { ...base, API_MODE_REMEDIATION_BACKLOG_FAIL_MINUTES: '10' },
      'API_MODE_REMEDIATION_BACKLOG_FAIL_MINUTES',
    );
    fails(
      {
        ...base,
        API_MODE_REMEDIATION_CONCURRENCY: '2',
        API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION: '4',
      },
      'API_MODE_REMEDIATION_CONCURRENCY_PER_CONNECTION',
    );
  });

  it('step API-3: clawback and reports keys (C17), defaults and bounds', () => {
    const cfg = loadWorkerConfig(base);
    expect(cfg.API_MODE_CLAWBACK_TICK_MS).toBe(5000);
    expect(cfg.API_MODE_CLAWBACK_LEASE_SECONDS).toBe(120);
    expect(cfg.API_MODE_CLAWBACK_MAX_TARGETS).toBe(20_000);
    expect(cfg.API_MODE_CLAWBACK_QUEUE_BATCH).toBe(500);
    expect(cfg.API_MODE_CLAWBACK_MAX_PENDING_PER_CONNECTION).toBe(1000);
    expect(cfg.API_MODE_CLAWBACK_MAX_WINDOW_DAYS).toBe(31);
    expect(cfg.API_MODE_CLAWBACK_TI_INTERVAL_SECONDS).toBe(60);
    expect(cfg.API_MODE_CLAWBACK_TI_BATCH).toBe(100);
    expect(cfg.API_MODE_PURGE_APPROVAL_TTL_HOURS).toBe(72);
    expect(cfg.API_MODE_CLAWBACK_STALLED_WARN_MINUTES).toBe(60);
    expect(cfg.API_MODE_CLAWBACK_STALLED_FAIL_MINUTES).toBe(240);
    expect(cfg.API_MODE_CLAWBACK_RETENTION_DAYS).toBe(400);
    expect(cfg.API_MODE_REPORT_RETENTION_DAYS).toBe(400);
    expect(cfg.API_MODE_REPORTS_TICK_MS).toBe(5000);
    expect(cfg.API_MODE_REPORT_MAX_BYTES).toBe(26_214_400);
    expect(cfg.API_MODE_REPORTS_PER_REPORTER_PER_HOUR).toBe(30);
    expect(cfg.API_MODE_REPORT_TRIAGE_WARN_HOURS).toBe(24);
    expect(cfg.API_MODE_REPORT_ALERT_MIN_INTERVAL_MINUTES).toBe(60);
    expect(cfg.API_MODE_REPORT_SCAN_TIMEOUT_MINUTES).toBe(60);
    fails({ ...base, API_MODE_CLAWBACK_MAX_TARGETS: '0' }, 'API_MODE_CLAWBACK_MAX_TARGETS');
    fails({ ...base, API_MODE_CLAWBACK_TI_BATCH: '1001' }, 'API_MODE_CLAWBACK_TI_BATCH');
    fails(
      { ...base, API_MODE_REPORT_SCAN_TIMEOUT_MINUTES: '4' },
      'API_MODE_REPORT_SCAN_TIMEOUT_MINUTES',
    );
    fails({ ...base, API_MODE_REPORT_MAX_BYTES: '1024' }, 'API_MODE_REPORT_MAX_BYTES');
    fails({ ...base, API_MODE_CLAWBACK_RETENTION_DAYS: '7' }, 'API_MODE_CLAWBACK_RETENTION_DAYS');
    fails(
      { ...base, API_MODE_CLAWBACK_STALLED_FAIL_MINUTES: '30' },
      'API_MODE_CLAWBACK_STALLED_FAIL_MINUTES',
    );
    fails(
      { ...base, API_MODE_CLAWBACK_MAX_TARGETS: '100', API_MODE_CLAWBACK_QUEUE_BATCH: '500' },
      'API_MODE_CLAWBACK_QUEUE_BATCH',
    );
  });

  it('step API-3: clawback and reports are not provider-calling roles (no credential key)', () => {
    const { PROVIDER_CREDENTIAL_ENCRYPTION_KEY: _key, ...noKey } = base;
    const cfg = loadWorkerConfig({ ...noKey, MAILBOX_WORKER_ROLES: 'clawback,reports' });
    expect(cfg.MAILBOX_WORKER_ROLES).toEqual(['clawback', 'reports']);
    expect(hasRole(cfg, 'clawback')).toBe(true);
    fails(
      { ...noKey, MAILBOX_WORKER_ROLES: 'clawback,remediate' },
      'PROVIDER_CREDENTIAL_ENCRYPTION_KEY',
    );
  });

  it('names keys, never values, when refusing', () => {
    try {
      loadWorkerConfig({ ...base, PROVIDER_CREDENTIAL_ENCRYPTION_KEY: 'not-hex-secret-value' });
      expect.unreachable();
    } catch (error) {
      expect(String(error)).toContain('PROVIDER_CREDENTIAL_ENCRYPTION_KEY');
      expect(String(error)).not.toContain('not-hex-secret-value');
    }
  });
});

describe('step API-4 configuration (note 38 A1–A3, B6)', () => {
  it('reads the policy runtime keys and the API-4 switches with their defaults', () => {
    const cfg = loadWorkerConfig(base);
    expect(cfg.POLICY_PLATFORM_DEFAULT).toBe('pol-default/1');
    expect(cfg.POLICY_SNAPSHOT_CACHE_MAX_ENTRIES).toBe(1000);
    expect(cfg.API_MODE_POLICY_EVALUATION_ENABLED).toBe(true);
    expect(cfg.API_MODE_SCOPE_REFRESH_MINUTES).toBe(15);
    expect(cfg.API_MODE_SCOPE_MAX_DEPARTMENTS).toBe(20);
    expect(
      loadWorkerConfig({ ...base, API_MODE_POLICY_EVALUATION_ENABLED: 'false' })
        .API_MODE_POLICY_EVALUATION_ENABLED,
    ).toBe(false);
  });

  it('validates them like the policy-engine (platform default key, cache bounds)', () => {
    fails({ ...base, POLICY_PLATFORM_DEFAULT: 'pol-unknown/9' }, 'POLICY_PLATFORM_DEFAULT');
    fails({ ...base, POLICY_SNAPSHOT_CACHE_MAX_ENTRIES: '5' }, 'POLICY_SNAPSHOT_CACHE_MAX_ENTRIES');
    fails({ ...base, API_MODE_SCOPE_MAX_DEPARTMENTS: '21' }, 'API_MODE_SCOPE_MAX_DEPARTMENTS');
    fails({ ...base, API_MODE_SCOPE_REFRESH_MINUTES: '0' }, 'API_MODE_SCOPE_REFRESH_MINUTES');
    fails(
      { ...base, API_MODE_POLICY_EVALUATION_ENABLED: 'maybe' },
      'API_MODE_POLICY_EVALUATION_ENABLED',
    );
  });
});
