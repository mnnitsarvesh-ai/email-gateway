import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig } from './load-config';
import {
  archiveKeysConfigSchema,
  archiveSearchConfigSchema,
  archiveStorageConfigSchema,
  archiveTestSeamSchema,
} from './schemas';

const hex = () => randomBytes(32).toString('hex');

function issues(schema: Parameters<typeof loadConfig>[0], env: Record<string, string>): string {
  try {
    loadConfig(schema, env);
  } catch (err) {
    expect(err).toBeInstanceOf(ConfigValidationError);
    return (err as Error).message;
  }
  return expect.fail('expected ConfigValidationError');
}

describe('archiveKeysConfigSchema', () => {
  it('requires the root key and defaults its id to r1', () => {
    const key = hex();
    expect(loadConfig(archiveKeysConfigSchema, { ARCHIVE_ROOT_KEY: key })).toEqual({
      ARCHIVE_ROOT_KEY: key,
      ARCHIVE_ROOT_KEY_ID: 'r1',
    });
    expect(issues(archiveKeysConfigSchema, {})).toContain('ARCHIVE_ROOT_KEY');
  });

  it('treats empty previous keys as unset and accepts a rotation pair', () => {
    const cfg = loadConfig(archiveKeysConfigSchema, {
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_PREVIOUS: '',
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: '',
    });
    expect(cfg.ARCHIVE_ROOT_KEY_PREVIOUS).toBeUndefined();
    const rotated = loadConfig(archiveKeysConfigSchema, {
      ARCHIVE_ROOT_KEY: hex(),
      ARCHIVE_ROOT_KEY_ID: 'r2',
      ARCHIVE_ROOT_KEY_PREVIOUS: hex(),
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r1',
    });
    expect(rotated.ARCHIVE_ROOT_KEY_PREVIOUS_ID).toBe('r1');
  });

  it.each([
    [{ ARCHIVE_ROOT_KEY: 'abc' }, 'ARCHIVE_ROOT_KEY'],
    [{ ARCHIVE_ROOT_KEY_ID: 'R1' }, 'ARCHIVE_ROOT_KEY_ID'],
    [{ ARCHIVE_ROOT_KEY_ID: 'r'.repeat(17) }, 'ARCHIVE_ROOT_KEY_ID'],
    [
      { ARCHIVE_ROOT_KEY_PREVIOUS: 'xyz', ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0' },
      'ARCHIVE_ROOT_KEY_PREVIOUS',
    ],
    [{ ARCHIVE_ROOT_KEY_PREVIOUS: hex() }, 'ARCHIVE_ROOT_KEY_PREVIOUS_ID'],
    [{ ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0' }, 'ARCHIVE_ROOT_KEY_PREVIOUS'],
    [
      { ARCHIVE_ROOT_KEY_PREVIOUS: hex(), ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r1' },
      'ARCHIVE_ROOT_KEY_PREVIOUS_ID',
    ],
  ])('rejects %j naming %s, never a value', (env, key) => {
    const full = { ARCHIVE_ROOT_KEY: hex(), ...env } as Record<string, string>;
    const message = issues(archiveKeysConfigSchema, full);
    expect(message).toContain(key);
    for (const value of Object.values(full)) {
      if (value.length >= 32) expect(message).not.toContain(value);
    }
  });

  it('rejects a previous key equal to the current one', () => {
    const key = hex();
    const message = issues(archiveKeysConfigSchema, {
      ARCHIVE_ROOT_KEY: key,
      ARCHIVE_ROOT_KEY_PREVIOUS: key.toUpperCase(),
      ARCHIVE_ROOT_KEY_PREVIOUS_ID: 'r0',
    });
    expect(message).toContain('ARCHIVE_ROOT_KEY_PREVIOUS: must differ from ARCHIVE_ROOT_KEY');
    expect(message).not.toContain(key);
  });
});

describe('archiveSearchConfigSchema', () => {
  it('has no URL by default, 10 s timeout and the eg-archive prefix', () => {
    expect(loadConfig(archiveSearchConfigSchema, {})).toEqual({
      ARCHIVE_SEARCH_TIMEOUT_MS: 10000,
      ARCHIVE_SEARCH_INDEX_PREFIX: 'eg-archive',
    });
  });

  it('accepts http(s) URLs with credentials in separate keys', () => {
    const cfg = loadConfig(archiveSearchConfigSchema, {
      ARCHIVE_SEARCH_URL: 'https://search.example.com:9200',
      ARCHIVE_SEARCH_USERNAME: 'archive',
      ARCHIVE_SEARCH_PASSWORD: 'pw-for-test',
      ARCHIVE_SEARCH_TIMEOUT_MS: '1000',
      ARCHIVE_SEARCH_INDEX_PREFIX: 'eg-test-archive',
    });
    expect(cfg).toMatchObject({
      ARCHIVE_SEARCH_TIMEOUT_MS: 1000,
      ARCHIVE_SEARCH_INDEX_PREFIX: 'eg-test-archive',
    });
    expect(
      loadConfig(archiveSearchConfigSchema, { ARCHIVE_SEARCH_URL: 'http://localhost:9201' })
        .ARCHIVE_SEARCH_URL,
    ).toBe('http://localhost:9201');
  });

  it.each([
    [{ ARCHIVE_SEARCH_URL: 'ftp://search' }, 'ARCHIVE_SEARCH_URL'],
    [{ ARCHIVE_SEARCH_URL: 'not a url' }, 'ARCHIVE_SEARCH_URL'],
    [{ ARCHIVE_SEARCH_URL: 'http://admin:pw-in-url@search:9200' }, 'ARCHIVE_SEARCH_URL'],
    [{ ARCHIVE_SEARCH_USERNAME: 'archive' }, 'ARCHIVE_SEARCH_PASSWORD'],
    [{ ARCHIVE_SEARCH_PASSWORD: 'pw-for-test' }, 'ARCHIVE_SEARCH_USERNAME'],
    [{ ARCHIVE_SEARCH_TIMEOUT_MS: '999' }, 'ARCHIVE_SEARCH_TIMEOUT_MS'],
    [{ ARCHIVE_SEARCH_TIMEOUT_MS: '60001' }, 'ARCHIVE_SEARCH_TIMEOUT_MS'],
    [{ ARCHIVE_SEARCH_INDEX_PREFIX: 'EG' }, 'ARCHIVE_SEARCH_INDEX_PREFIX'],
    [{ ARCHIVE_SEARCH_INDEX_PREFIX: 'eg_archive' }, 'ARCHIVE_SEARCH_INDEX_PREFIX'],
    [{ ARCHIVE_SEARCH_INDEX_PREFIX: 'e'.repeat(42) }, 'ARCHIVE_SEARCH_INDEX_PREFIX'],
  ])('rejects %j naming %s', (env, key) => {
    const message = issues(archiveSearchConfigSchema, env);
    expect(message).toContain(key);
    expect(message).not.toContain('pw-in-url');
    expect(message).not.toContain('pw-for-test');
  });
});

describe('archiveStorageConfigSchema', () => {
  it('defaults to auto Object Lock and a 3 650-day cap', () => {
    expect(loadConfig(archiveStorageConfigSchema, {})).toEqual({
      ARCHIVE_OBJECT_LOCK: 'auto',
      ARCHIVE_MAX_RETENTION_DAYS: 3650,
    });
    expect(
      loadConfig(archiveStorageConfigSchema, {
        ARCHIVE_OBJECT_LOCK: 'disabled',
        ARCHIVE_MAX_RETENTION_DAYS: '36500',
      }),
    ).toEqual({ ARCHIVE_OBJECT_LOCK: 'disabled', ARCHIVE_MAX_RETENTION_DAYS: 36500 });
  });

  it.each([
    ['ARCHIVE_OBJECT_LOCK', 'on'],
    ['ARCHIVE_MAX_RETENTION_DAYS', '0'],
    ['ARCHIVE_MAX_RETENTION_DAYS', '36501'],
    ['ARCHIVE_MAX_RETENTION_DAYS', '1.5'],
  ])('rejects %s=%s', (key, value) => {
    expect(issues(archiveStorageConfigSchema, { [key]: value })).toContain(key);
  });
});

describe('archiveTestSeamSchema', () => {
  it('is unset by default', () => {
    expect(loadConfig(archiveTestSeamSchema, {})).toEqual({ APP_ENV: 'local' });
  });

  it.each(['local', 'ci'])('accepts ARCHIVE_TEST_DAY_SECONDS when APP_ENV=%s', (appEnv) => {
    expect(
      loadConfig(archiveTestSeamSchema, { APP_ENV: appEnv, ARCHIVE_TEST_DAY_SECONDS: '5' }),
    ).toEqual({
      APP_ENV: appEnv,
      ARCHIVE_TEST_DAY_SECONDS: 5,
    });
  });

  it.each(['staging', 'production'])(
    'refuses ARCHIVE_TEST_DAY_SECONDS when APP_ENV=%s',
    (appEnv) => {
      expect(
        issues(archiveTestSeamSchema, { APP_ENV: appEnv, ARCHIVE_TEST_DAY_SECONDS: '5' }),
      ).toContain('ARCHIVE_TEST_DAY_SECONDS: is allowed only when APP_ENV is local or ci');
      expect(loadConfig(archiveTestSeamSchema, { APP_ENV: appEnv })).toEqual({ APP_ENV: appEnv });
    },
  );

  it.each(['0', '86401', 'x'])('rejects ARCHIVE_TEST_DAY_SECONDS=%s', (value) => {
    expect(issues(archiveTestSeamSchema, { ARCHIVE_TEST_DAY_SECONDS: value })).toContain(
      'ARCHIVE_TEST_DAY_SECONDS',
    );
  });
});
