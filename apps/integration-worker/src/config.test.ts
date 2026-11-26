import { randomBytes } from 'node:crypto';
import {
  PERMISSION_PROFILES,
  platformCredentialsFromEnv,
  testing,
} from '@email-gateway/provider-integrations';
import { describe, expect, it } from 'vitest';
import { hasRole, isLocalEnv, loadWorkerConfig, parseGatewayMxHosts, probeHelo } from './config';

const key = () => randomBytes(32).toString('hex');

const base = (extra: Record<string, string> = {}): NodeJS.ProcessEnv => ({
  APP_ENV: 'local',
  DATABASE_URL: 'mysql://u:p@localhost:3306/db',
  PROVIDER_CREDENTIAL_ENCRYPTION_KEY: key(),
  GATEWAY_MX_HOSTS: '10:mx1.mail-gateway.test,20:mx2.mail-gateway.test',
  ...extra,
});

const issues = (env: NodeJS.ProcessEnv): string => {
  try {
    loadWorkerConfig(env);
    return '';
  } catch (error) {
    return (error as Error).message;
  }
};

describe('integration-worker configuration (§4.4)', () => {
  it('has the documented defaults', () => {
    const cfg = loadWorkerConfig(base());
    expect(cfg.INTEGRATION_WORKER_ROLES).toEqual(['tasks', 'health', 'maintenance']);
    expect(cfg.INTEGRATION_WORKER_HTTP_PORT).toBe(3086);
    expect(cfg.INTEGRATION_TASK_POLL_MS).toBe(2_000);
    expect(cfg.INTEGRATION_TASK_CONCURRENCY).toBe(4);
    expect(cfg.INTEGRATION_TX_TIMEOUT_MS).toBe(120_000);
    expect(cfg.INTEGRATION_HEALTH_TICK_SECONDS).toBe(60);
    expect(cfg.INTEGRATION_HEALTH_INTERVAL_SECONDS).toBe(900);
    expect(cfg.INTEGRATION_HEALTH_ERROR_GRACE_MINUTES).toBe(60);
    expect(cfg.INTEGRATION_RELAY_IDLE_WARN_HOURS).toBe(72);
    expect(cfg.INTEGRATION_SMTP_PROBE_TIMEOUT_MS).toBe(15_000);
    expect(cfg.PROVIDER_PROBE_TTL_SECONDS).toBe(86_400);
    expect(cfg.PROVIDER_EGRESS_MAX_AGE_DAYS).toBe(45);
    expect(cfg.PROVIDER_M365_LOGIN_URL).toBe('https://login.microsoftonline.com');
    expect(cfg.GATEWAY_MX_HOSTS).toEqual(['mx1.mail-gateway.test', 'mx2.mail-gateway.test']);
    expect(probeHelo(cfg)).toBe('out.gateway.local');
    expect(isLocalEnv(cfg)).toBe(true);
    expect(hasRole(cfg, 'health')).toBe(true);
  });

  it('accepts http: endpoints only with PROVIDER_ALLOW_HTTP_ENDPOINTS in local/ci', () => {
    const http = { PROVIDER_M365_GRAPH_URL: 'http://provider-fake:8480/m365/graph' };
    expect(issues(base(http))).toContain('PROVIDER_M365_GRAPH_URL');
    expect(issues(base({ ...http, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true' }))).toBe('');
    expect(
      issues(base({ ...http, PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true', APP_ENV: 'production' })),
    ).toContain('PROVIDER_ALLOW_HTTP_ENDPOINTS: is refused unless APP_ENV is local or ci');
    expect(issues(base({ PROVIDER_GOOGLE_TOKEN_URL: 'ftp://x/token' }))).toContain(
      'PROVIDER_GOOGLE_TOKEN_URL',
    );
  });

  it('refuses INTEGRATION_PROBE_CA_PATH outside local/ci', () => {
    expect(issues(base({ INTEGRATION_PROBE_CA_PATH: '/pki/ca/ca.pem' }))).toBe('');
    expect(
      issues(base({ INTEGRATION_PROBE_CA_PATH: '/pki/ca/ca.pem', APP_ENV: 'staging' })),
    ).toContain('INTEGRATION_PROBE_CA_PATH');
  });

  it('assumes production with NODE_ENV=production and no APP_ENV', () => {
    const env = base({ PROVIDER_ALLOW_HTTP_ENDPOINTS: 'true', NODE_ENV: 'production' });
    delete env.APP_ENV;
    expect(issues(env)).toContain('PROVIDER_ALLOW_HTTP_ENDPOINTS');
  });

  it('validates keys, roles and the platform secret switch', () => {
    expect(issues(base({ PROVIDER_CREDENTIAL_ENCRYPTION_KEY: 'short' }))).toContain(
      'PROVIDER_CREDENTIAL_ENCRYPTION_KEY',
    );
    const current = key();
    expect(
      issues(
        base({
          PROVIDER_CREDENTIAL_ENCRYPTION_KEY: current,
          PROVIDER_CREDENTIAL_ENCRYPTION_KEY_PREVIOUS: current,
        }),
      ),
    ).toContain('must differ');
    expect(issues(base({ INTEGRATION_WORKER_ROLES: 'tasks,unknown' }))).toContain(
      'INTEGRATION_WORKER_ROLES',
    );
    expect(issues(base({ INTEGRATION_WORKER_ROLES: 'tasks,tasks' }))).toContain('twice');
    expect(
      loadWorkerConfig(base({ INTEGRATION_WORKER_ROLES: 'health' })).INTEGRATION_WORKER_ROLES,
    ).toEqual(['health']);
    expect(issues(base({ PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET: 'x' }))).toContain(
      'PROVIDER_M365_ALLOW_PLATFORM_SECRET',
    );
    expect(
      issues(
        base({
          PROVIDER_M365_MAILFLOW_APP_CLIENT_SECRET: 'x',
          PROVIDER_M365_ALLOW_PLATFORM_SECRET: 'true',
        }),
      ),
    ).toBe('');
    expect(issues(base({ INTEGRATION_TX_TIMEOUT_MS: '60000' }))).toContain(
      'INTEGRATION_TX_TIMEOUT_MS',
    );
    expect(issues(base({ INTEGRATION_PROBE_DNS_SERVERS: 'dns-sink' }))).toContain(
      'INTEGRATION_PROBE_DNS_SERVERS',
    );
    expect(
      loadWorkerConfig(base({ INTEGRATION_PROBE_DNS_SERVERS: '172.31.250.53, 127.0.0.1:1053' }))
        .INTEGRATION_PROBE_DNS_SERVERS,
    ).toEqual(['172.31.250.53', '127.0.0.1:1053']);
  });

  it('step API-1 (D4): loads the mailbox-access platform credentials by key name', () => {
    const tokenUrl = 'https://oauth2.googleapis.com/token';
    const sa = testing.testServiceAccountKey('mailbox@platform.example.iam', tokenUrl);
    const m365ClientId = testing.testGuid();
    const cfg = loadWorkerConfig(
      base({
        PROVIDER_M365_MAILBOX_APP_CLIENT_ID: m365ClientId,
        PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET: 'platform-secret-placeholder',
        PROVIDER_M365_ALLOW_PLATFORM_SECRET: 'true',
        PROVIDER_GOOGLE_MAILBOX_SA_CLIENT_ID: sa.account.clientId,
        PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH: '/run/secrets/google-mailbox-sa.json',
      }),
    );
    expect(cfg.PROVIDER_M365_MAILBOX_APP_CLIENT_ID).toBe(m365ClientId);
    expect(cfg.PROVIDER_GOOGLE_MAILBOX_SA_KEY_PATH).toBe('/run/secrets/google-mailbox-sa.json');
    const read: string[] = [];
    const platform = platformCredentialsFromEnv(
      cfg as unknown as Record<string, string | undefined>,
      PERMISSION_PROFILES,
      {
        readFile: (path) => (read.push(path), JSON.stringify(sa.document)),
        googleTokenUrl: tokenUrl,
        allowPlatformSecret: cfg.PROVIDER_M365_ALLOW_PLATFORM_SECRET,
      },
    );
    expect(platform.microsoft.get('m365.mailbox_remediation')).toEqual({
      clientId: m365ClientId,
      secret: 'platform-secret-placeholder',
    });
    expect(platform.google.get('google.mailbox_remediation')?.client_id).toBe(sa.account.clientId);
    expect(read).toEqual(['/run/secrets/google-mailbox-sa.json']);
    // Mail flow keeps its own app: nothing of the mailbox app leaks into its profile.
    expect(platform.microsoft.has('m365.mail_flow')).toBe(false);
    // The platform secret rule applies to the mailbox app too.
    expect(issues(base({ PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET: 'x' }))).toContain(
      'PROVIDER_M365_MAILBOX_APP_CLIENT_SECRET',
    );
  });

  it('never echoes a secret value in an error', () => {
    const secret = 'zz'.repeat(40);
    expect(issues(base({ PROVIDER_CREDENTIAL_ENCRYPTION_KEY: secret }))).not.toContain(secret);
  });

  it('parses GATEWAY_MX_HOSTS', () => {
    expect(parseGatewayMxHosts('10:MX1.Example.NET.,20:mx2.example.net')).toEqual([
      'mx1.example.net',
      'mx2.example.net',
    ]);
    expect(() => parseGatewayMxHosts('mx1.example.net')).toThrow();
    expect(issues(base({ GATEWAY_MX_HOSTS: '' }))).toContain('GATEWAY_MX_HOSTS');
  });
});
