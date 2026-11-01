import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig, resolveFileSecrets } from './load-config';
import { baseConfigSchema, databaseConfigSchema, httpConfigSchema } from './schemas';

const schema = baseConfigSchema
  .extend(httpConfigSchema(3000).shape)
  .extend(databaseConfigSchema.shape);

describe('loadConfig', () => {
  it('applies defaults and coerces types', () => {
    const cfg = loadConfig(schema, { HTTP_PORT: '4000', DATABASE_URL: 'mysql://u:p@h:3306/db' });
    expect(cfg.HTTP_PORT).toBe(4000);
    expect(loadConfig(schema, { DATABASE_URL: 'mysql://u:p@h:3306/db' }).HTTP_PORT).toBe(3000);
    expect(cfg.LOG_LEVEL).toBe('info');
    expect(Object.isFrozen(cfg)).toBe(true);
  });

  it('treats empty values as unset', () => {
    const cfg = loadConfig(schema, {
      DATABASE_URL: 'mysql://u:p@h/db',
      OTEL_EXPORTER_OTLP_ENDPOINT: '',
      LOG_LEVEL: '',
    });
    expect(cfg.OTEL_EXPORTER_OTLP_ENDPOINT).toBeUndefined();
    expect(cfg.LOG_LEVEL).toBe('info');
  });

  it('reports every invalid key without echoing secret values', () => {
    const secret = 'postgres://user:SuperSecret@host/db';
    try {
      loadConfig(schema, { HTTP_PORT: '99999', DATABASE_URL: secret });
      expect.fail('expected ConfigValidationError');
    } catch (err) {
      expect(err).toBeInstanceOf(ConfigValidationError);
      const message = (err as Error).message;
      expect(message).toContain('HTTP_PORT');
      expect(message).toContain('DATABASE_URL');
      expect(message).not.toContain('SuperSecret');
    }
  });
});

describe('resolveFileSecrets', () => {
  it('reads <KEY>_FILE into <KEY>', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    const file = join(dir, 'db_url');
    writeFileSync(file, 'mysql://from-file@h/db\n');
    expect(resolveFileSecrets({ DATABASE_URL_FILE: file }).DATABASE_URL).toBe(
      'mysql://from-file@h/db',
    );
  });

  it('prefers an explicit value over the _FILE variant', () => {
    const env = resolveFileSecrets({
      DATABASE_URL: 'mysql://explicit',
      DATABASE_URL_FILE: '/nonexistent',
    });
    expect(env.DATABASE_URL).toBe('mysql://explicit');
  });
});
