import { randomBytes } from 'node:crypto';
import { ConfigValidationError } from '@email-gateway/config';
import { generateArtifactKeyPair } from '@email-gateway/sandbox';
import { describe, expect, it } from 'vitest';
import {
  CONTROLLER_ENV_KEYS,
  controllerVersion,
  FORBIDDEN_KEYS,
  FORBIDDEN_PREFIXES,
  forbiddenKeysPresent,
  loadControllerConfig,
} from './config';

const hex = (): string => randomBytes(32).toString('hex');
const pair = generateArtifactKeyPair();

function env(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return {
    APP_ENV: 'local',
    RABBITMQ_SANDBOX_URL: 'amqp://eg-sandbox:secret-value@127.0.0.1:5672/email-gateway',
    SANDBOX_RESULT_KEY: hex(),
    ...overrides,
  };
}

function staticEnv(overrides: Record<string, string | undefined> = {}): NodeJS.ProcessEnv {
  return env({
    SANDBOX_BACKEND: 'static',
    SANDBOX_S3_ACCESS_KEY_ID: 'eg-sandbox-controller',
    SANDBOX_S3_SECRET_ACCESS_KEY: 'a'.repeat(40),
    SANDBOX_SAMPLE_KEY: hex(),
    SANDBOX_ARTIFACT_PUBLIC_KEY: pair.publicKey,
    ...overrides,
  });
}

function issues(e: NodeJS.ProcessEnv): string[] {
  try {
    loadControllerConfig(e);
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigValidationError);
    return (error as ConfigValidationError).issues;
  }
  return [];
}

describe('forbidden configuration (X1)', () => {
  const forbidden = [
    ...FORBIDDEN_PREFIXES.map((p) => `${p}ANYTHING`),
    ...FORBIDDEN_KEYS,
    'RABBITMQ_RELAY_URL',
    'RABBITMQ_SCANNER_PASSWORD',
    'RABBITMQ_MGMT_URL',
    'RABBITMQ_URL_BROWSER_URL',
    'S3_ACCESS_KEY_ID',
    'MINIO_ROOT_PASSWORD',
    'DATABASE_URL',
    'REDIS_URL',
    'DLP_EVIDENCE_KEY',
    'BEC_LLM_API_KEY',
    'URL_TOKEN_KEY_1',
    'AUTH_JWT_SECRET',
    'CLICK_DATABASE_URL',
  ];

  it.each(forbidden)('refuses %s and its _FILE variant, naming the key only', (key) => {
    for (const name of [key, `${key}_FILE`]) {
      const value = `value-that-must-not-leak-${name}`;
      const found = issues(env({ [name]: value }));
      expect(found.some((i) => i.startsWith(`${name}:`))).toBe(true);
      expect(found.join('\n')).not.toContain(value);
    }
  });

  it('allows its own broker credentials and every dev-env key', () => {
    expect(
      forbiddenKeysPresent({
        RABBITMQ_SANDBOX_URL: 'x',
        RABBITMQ_SANDBOX_PASSWORD: 'y',
        RABBITMQ_SANDBOX_URL_FILE: '/f',
      }),
    ).toEqual([]);
    const all = Object.fromEntries(CONTROLLER_ENV_KEYS.map((k) => [k, 'x']));
    expect(forbiddenKeysPresent(all)).toEqual([]);
  });

  it('ignores empty values and refuses the artifact private key', () => {
    expect(forbiddenKeysPresent({ DATABASE_URL: '' })).toEqual([]);
    expect(issues(staticEnv({ SANDBOX_ARTIFACT_PRIVATE_KEY: pair.privateKey }))).toEqual([
      expect.stringMatching(/^SANDBOX_ARTIFACT_PRIVATE_KEY:/),
    ]);
  });
});

describe('backends and keys', () => {
  it('starts disabled by default with the broker URL and the result key only', () => {
    const c = loadControllerConfig(env());
    expect(c.SANDBOX_BACKEND).toBe('disabled');
    expect(c.SANDBOX_ALLOW_NON_VM_EXECUTION).toBe(false);
    expect(c.SANDBOX_HTTP_PORT).toBe(3092);
    expect(c.SANDBOX_CONCURRENCY).toBe(1);
    expect(c.SANDBOX_TASK_TIMEOUT_MS).toBe(180_000);
    expect(c.SANDBOX_VM_ALLOWED_HANDLERS).toEqual([
      'runsc',
      'kata',
      'kata-qemu',
      'kata-clh',
      'kata-fc',
    ]);
    expect(Object.isFrozen(c)).toBe(true);
  });

  it('requires the result key for every publishing backend, not for vm', () => {
    expect(issues(env({ SANDBOX_RESULT_KEY: undefined }))).toEqual([
      'SANDBOX_RESULT_KEY: is required',
    ]);
    expect(issues(env({ SANDBOX_RESULT_KEY: 'short' }))[0]).toMatch(
      /^SANDBOX_RESULT_KEY: must be 32 bytes/,
    );
    expect(issues(env({ SANDBOX_BACKEND: 'vm', SANDBOX_RESULT_KEY: undefined }))).toEqual([]);
  });

  it('requires the bucket credentials and envelope keys for static', () => {
    expect(loadControllerConfig(staticEnv()).SANDBOX_BACKEND).toBe('static');
    const found = issues(env({ SANDBOX_BACKEND: 'static' }));
    expect(found).toEqual(
      expect.arrayContaining([
        'SANDBOX_S3_ACCESS_KEY_ID: is required for static',
        'SANDBOX_S3_SECRET_ACCESS_KEY: is required for static',
        'SANDBOX_SAMPLE_KEY: is required',
        'SANDBOX_ARTIFACT_PUBLIC_KEY: is required for static',
      ]),
    );
  });

  it('parses the artifact public key as X25519 SPKI and checks the previous sample key', () => {
    expect(issues(staticEnv({ SANDBOX_ARTIFACT_PUBLIC_KEY: pair.privateKey }))[0]).toMatch(
      /^SANDBOX_ARTIFACT_PUBLIC_KEY: must be an X25519 public key/,
    );
    expect(issues(staticEnv({ SANDBOX_ARTIFACT_PUBLIC_KEY: 'not base64!' }))[0]).toMatch(
      /^SANDBOX_ARTIFACT_PUBLIC_KEY:/,
    );
    const sample = hex();
    expect(
      issues(staticEnv({ SANDBOX_SAMPLE_KEY: sample, SANDBOX_SAMPLE_KEY_PREVIOUS: sample }))[0],
    ).toMatch(/^SANDBOX_SAMPLE_KEY_PREVIOUS:/);
    expect(issues(staticEnv({ SANDBOX_SAMPLE_KEY_PREVIOUS: hex() }))).toEqual([]);
  });

  it('allows hardened-container only in local/ci, outside Kubernetes, opted in', () => {
    const ok = {
      SANDBOX_BACKEND: 'hardened-container',
      SANDBOX_ALLOW_NON_VM_EXECUTION: 'true',
      SANDBOX_SINKHOLE_ADMIN_TOKEN: 'x'.repeat(32),
    };
    expect(issues(staticEnv(ok))).toEqual([]);
    expect(issues(staticEnv({ ...ok, APP_ENV: 'ci' }))).toEqual([]);
    expect(issues(staticEnv({ ...ok, APP_ENV: 'production' }))).toEqual(
      expect.arrayContaining([
        'SANDBOX_ALLOW_NON_VM_EXECUTION: is refused outside APP_ENV local/ci',
        expect.stringMatching(
          /^SANDBOX_BACKEND: hardened-container \(not a VM boundary\) requires APP_ENV local or ci/,
        ),
      ]),
    );
    expect(issues(staticEnv({ ...ok, APP_ENV: 'staging' })).length).toBeGreaterThan(0);
    expect(issues(staticEnv({ ...ok, KUBERNETES_SERVICE_HOST: '10.0.0.1' }))).toEqual([
      'SANDBOX_BACKEND: hardened-container is refused inside Kubernetes',
    ]);
    expect(issues(staticEnv({ ...ok, SANDBOX_ALLOW_NON_VM_EXECUTION: 'false' }))).toEqual([
      'SANDBOX_ALLOW_NON_VM_EXECUTION: must be true for hardened-container',
    ]);
    expect(issues(staticEnv({ ...ok, SANDBOX_SINKHOLE_ADMIN_TOKEN: undefined }))).toEqual([
      'SANDBOX_SINKHOLE_ADMIN_TOKEN: is required for hardened-container',
    ]);
  });

  it('refuses the execution opt-in outside local/ci, and counts NODE_ENV=production without APP_ENV as production', () => {
    expect(issues(env({ APP_ENV: 'production', SANDBOX_ALLOW_NON_VM_EXECUTION: 'true' }))).toEqual([
      'SANDBOX_ALLOW_NON_VM_EXECUTION: is refused outside APP_ENV local/ci',
    ]);
    expect(
      issues(
        env({ APP_ENV: undefined, NODE_ENV: 'production', SANDBOX_ALLOW_NON_VM_EXECUTION: 'true' }),
      ),
    ).toEqual(['SANDBOX_ALLOW_NON_VM_EXECUTION: is refused outside APP_ENV local/ci']);
  });
});

describe('bounds', () => {
  it.each([
    ['SANDBOX_CONCURRENCY', '5'],
    ['SANDBOX_CONCURRENCY', '0'],
    ['SANDBOX_TASK_TIMEOUT_MS', '1000'],
    ['SANDBOX_MAX_RUN_TIMEOUT_MS', '700000'],
    ['SANDBOX_MAX_MEMORY_MB', '8192'],
    ['SANDBOX_MAX_CPU_MILLIS', '50'],
    ['SANDBOX_MAX_PIDS', '2048'],
    ['SANDBOX_MAX_SCRATCH_MB', '4'],
    ['SANDBOX_MAX_ARTIFACTS', '17'],
    ['SANDBOX_MAX_ARTIFACT_BYTES', '8388609'],
    ['SANDBOX_MAX_TOTAL_ARTIFACT_BYTES', '33554433'],
    ['SANDBOX_MAX_SAMPLE_BYTES', '67108865'],
    ['SANDBOX_HTTP_PORT', '70000'],
    ['SANDBOX_STATIC_HEAP_MB', '16'],
    ['SANDBOX_SCRATCH_DIR', 'relative/dir'],
    ['SANDBOX_SCRATCH_DIR', '/'],
    ['SANDBOX_CONTROLLER_NAME', 'Not_A_Label'],
    ['SANDBOX_BACKEND', 'docker'],
    ['SANDBOX_VM_ALLOWED_HANDLERS', 'runc;rm'],
    ['SANDBOX_SINKHOLE_ADMIN_URL', 'http://u:p@172.31.252.53:3094'],
  ])('refuses %s=%s', (key, value) => {
    expect(issues(env({ [key]: value })).some((i) => i.startsWith(`${key}:`))).toBe(true);
  });

  it('keeps the analyzer limits consistent with each other and the task timeout', () => {
    expect(
      issues(env({ SANDBOX_STATIC_HEAP_MB: '512', SANDBOX_STATIC_MAX_RSS_MB: '384' })),
    ).toEqual(['SANDBOX_STATIC_MAX_RSS_MB: must be above SANDBOX_STATIC_HEAP_MB']);
    expect(issues(env({ SANDBOX_STATIC_TIMEOUT_MS: '180000' }))).toEqual([
      'SANDBOX_STATIC_TIMEOUT_MS: must be below SANDBOX_TASK_TIMEOUT_MS',
    ]);
  });

  it('formats the controller version as a bounded token', () => {
    expect(controllerVersion({ SERVICE_VERSION: '0.1.0-local' })).toBe(
      'sandbox-controller/0.1.0-local',
    );
    expect(controllerVersion({ SERVICE_VERSION: 'a b'.repeat(40) }).length).toBeLessThanOrEqual(64);
  });
});
