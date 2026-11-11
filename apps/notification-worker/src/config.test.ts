import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from './config';

const valid = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_NOTIFICATION_URL: 'amqp://eg-notification:pw@localhost:5672/email-gateway',
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
  ])('refuses %o naming %s', (env, key) => {
    expect(rejection({ ...valid, ...env })).toContain(key);
  });
});
