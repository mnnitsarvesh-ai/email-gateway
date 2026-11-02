import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig } from './load-config';
import { databaseReadConfigSchema } from './schemas';

describe('databaseReadConfigSchema', () => {
  it('defaults to no reader with a 10 s lag limit probed every 5 s', () => {
    const cfg = loadConfig(databaseReadConfigSchema, {});
    expect(cfg).toEqual({
      DATABASE_READ_URL: undefined,
      DATABASE_READ_MAX_LAG_SECONDS: 10,
      DATABASE_READ_LAG_CHECK_INTERVAL_MS: 5000,
    });
  });

  it('treats an empty reader URL as unset', () => {
    expect(loadConfig(databaseReadConfigSchema, { DATABASE_READ_URL: '' }).DATABASE_READ_URL).toBe(
      undefined,
    );
  });

  it('accepts a mysql:// reader URL and coerces numbers', () => {
    const cfg = loadConfig(databaseReadConfigSchema, {
      DATABASE_READ_URL: 'mysql://reader:pw@replica:3306/db',
      DATABASE_READ_MAX_LAG_SECONDS: '0',
      DATABASE_READ_LAG_CHECK_INTERVAL_MS: '60000',
    });
    expect(cfg.DATABASE_READ_URL).toBe('mysql://reader:pw@replica:3306/db');
    expect(cfg.DATABASE_READ_MAX_LAG_SECONDS).toBe(0);
    expect(cfg.DATABASE_READ_LAG_CHECK_INTERVAL_MS).toBe(60000);
  });

  it.each([
    ['DATABASE_READ_URL', 'postgres://reader:TopSecret@replica/db'],
    ['DATABASE_READ_MAX_LAG_SECONDS', '-1'],
    ['DATABASE_READ_MAX_LAG_SECONDS', '1.5'],
    ['DATABASE_READ_LAG_CHECK_INTERVAL_MS', '999'],
    ['DATABASE_READ_LAG_CHECK_INTERVAL_MS', '60001'],
  ])('rejects %s=%s without echoing the value', (key, value) => {
    try {
      loadConfig(databaseReadConfigSchema, { [key]: value });
      expect.fail('expected ConfigValidationError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigValidationError);
      expect((err as Error).message).toContain(key);
      expect((err as Error).message).not.toContain('TopSecret');
    }
  });
});
