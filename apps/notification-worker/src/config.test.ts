import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from './config';

const valid = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_NOTIFICATION_URL: 'amqp://eg-notification:pw@localhost:5672/email-gateway',
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'gateway-mail',
  S3_BUCKET_ARCHIVE: 'gateway-archive',
};

const rejection = (env: Record<string, string>): string => {
  try {
    loadWorkerConfig(env);
  } catch (error) {
    return String(error);
  }
  return '';
};

describe('loadWorkerConfig (step 5.2 §5, P25)', () => {
  it('defaults the port, prefetch, budget, recipient cap and portal origin', () => {
    const cfg = loadWorkerConfig(valid);
    expect(cfg.HTTP_PORT).toBe(3050);
    expect(cfg.NOTIFICATION_PREFETCH).toBe(4);
    expect(cfg.NOTIFICATION_DB_TX_TIMEOUT_MS).toBe(120_000);
    expect(cfg.NOTIFICATION_MAX_RECIPIENTS).toBe(50);
    expect(cfg.PORTAL_PUBLIC_URL).toBe('http://localhost:3001');
    expect(cfg.RABBITMQ_NOTIFICATION_URL).toHaveLength(1);
    expect(cfg.NOTIFY_SMTP_HOST).toBeUndefined();
    // Step 8.4 D16: the platform SOC audience is off by default.
    expect(cfg.NOTIFY_ATO_PLATFORM_SOC_EMAIL).toBe('');
  });

  it('reads NOTIFY_ATO_PLATFORM_SOC_EMAIL (trimmed, lower-cased; empty = off) (step 8.4 D16)', () => {
    expect(
      loadWorkerConfig({ ...valid, NOTIFY_ATO_PLATFORM_SOC_EMAIL: ' SOC@Platform.Example ' })
        .NOTIFY_ATO_PLATFORM_SOC_EMAIL,
    ).toBe('soc@platform.example');
    expect(
      loadWorkerConfig({ ...valid, NOTIFY_ATO_PLATFORM_SOC_EMAIL: '' })
        .NOTIFY_ATO_PLATFORM_SOC_EMAIL,
    ).toBe('');
    expect(rejection({ ...valid, NOTIFY_ATO_PLATFORM_SOC_EMAIL: 'not-an-address' })).toContain(
      'NOTIFY_ATO_PLATFORM_SOC_EMAIL',
    );
  });

  it('reads the relay keys and the bounds', () => {
    const cfg = loadWorkerConfig({
      ...valid,
      APP_ENV: 'local',
      NOTIFY_SMTP_HOST: 'postfix-notify',
      NOTIFY_SMTP_PORT: '25',
      NOTIFY_SMTP_SECURE: 'none',
      NOTIFY_SMTP_FROM: 'Email Gateway <no-reply@gateway.example>',
      NOTIFICATION_PREFETCH: '32',
      NOTIFICATION_DB_TX_TIMEOUT_MS: '600000',
      NOTIFICATION_MAX_RECIPIENTS: '500',
      PORTAL_PUBLIC_URL: 'https://portal.example/',
    });
    expect(cfg).toMatchObject({
      NOTIFY_SMTP_PORT: 25,
      NOTIFICATION_PREFETCH: 32,
      NOTIFICATION_DB_TX_TIMEOUT_MS: 600_000,
      NOTIFICATION_MAX_RECIPIENTS: 500,
      PORTAL_PUBLIC_URL: 'https://portal.example',
    });
  });

  it.each([
    [{ RABBITMQ_NOTIFICATION_URL: '' }, 'RABBITMQ_NOTIFICATION_URL'],
    [{ NOTIFICATION_PREFETCH: '0' }, 'NOTIFICATION_PREFETCH'],
    [{ NOTIFICATION_PREFETCH: '33' }, 'NOTIFICATION_PREFETCH'],
    [{ NOTIFICATION_DB_TX_TIMEOUT_MS: '119999' }, 'NOTIFICATION_DB_TX_TIMEOUT_MS'],
    [{ NOTIFICATION_DB_TX_TIMEOUT_MS: '600001' }, 'NOTIFICATION_DB_TX_TIMEOUT_MS'],
    [{ NOTIFICATION_MAX_RECIPIENTS: '0' }, 'NOTIFICATION_MAX_RECIPIENTS'],
    [{ NOTIFICATION_MAX_RECIPIENTS: '501' }, 'NOTIFICATION_MAX_RECIPIENTS'],
    [{ NOTIFY_SMTP_HOST: 'relay.example' }, 'NOTIFY_SMTP_FROM'],
    [
      {
        APP_ENV: 'production',
        NOTIFY_SMTP_HOST: 'relay.example',
        NOTIFY_SMTP_FROM: 'no-reply@x.example',
        NOTIFY_SMTP_SECURE: 'none',
        PORTAL_PUBLIC_URL: 'https://portal.example',
      },
      'NOTIFY_SMTP_SECURE',
    ],
    [{ APP_ENV: 'production', PORTAL_PUBLIC_URL: 'http://portal.example' }, 'PORTAL_PUBLIC_URL'],
    [{ NOTIFICATION_REPORT_MAX_HTML_BYTES: '65535' }, 'NOTIFICATION_REPORT_MAX_HTML_BYTES'],
    [{ NOTIFICATION_REPORT_MAX_HTML_BYTES: '4194305' }, 'NOTIFICATION_REPORT_MAX_HTML_BYTES'],
    [{ S3_BUCKET_MAIL: '' }, 'S3_BUCKET_MAIL'],
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });

  it('reads object storage and the report HTML bound (step AI-R D8)', () => {
    const cfg = loadWorkerConfig(valid);
    expect(cfg.NOTIFICATION_REPORT_MAX_HTML_BYTES).toBe(2_097_152);
    expect(cfg).toMatchObject({
      S3_REGION: 'ap-south-1',
      S3_BUCKET_MAIL: 'gateway-mail',
      S3_FORCE_PATH_STYLE: false,
    });
    expect(cfg.S3_ENDPOINT).toBeUndefined();
    const bounds = ['65536', '4194304'].map(
      (v) =>
        loadWorkerConfig({
          ...valid,
          NOTIFICATION_REPORT_MAX_HTML_BYTES: v,
          S3_ENDPOINT: 'http://minio:9000',
          S3_FORCE_PATH_STYLE: 'true',
        }).NOTIFICATION_REPORT_MAX_HTML_BYTES,
    );
    expect(bounds).toEqual([65_536, 4_194_304]);
    const { S3_REGION: _region, ...withoutRegion } = valid;
    expect(rejection(withoutRegion)).toContain('S3_REGION');
  });
});
