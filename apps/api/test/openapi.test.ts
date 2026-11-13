/**
 * OpenAPI contract (design §9, D3): the document builds from the running app with its
 * dependencies stubbed; every operation under /api/v1 has a tag and a security requirement
 * (except the public authentication routes and /api/v1/meta); and it matches the committed
 * snapshot docs/api/openapi.json. Regenerate the snapshot after an intended API change with
 *
 *   UPDATE_OPENAPI=1 pnpm --filter @email-gateway/api test:e2e -- openapi
 */
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import type { OpenAPIObject } from '@nestjs/swagger';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import {
  ACCESS_TOKEN_SCHEME,
  API_KEY_SCHEME,
  buildOpenApiDocument,
  OPENAPI_TAGS,
} from '../src/http/openapi';
import { KeyValueStore } from '../src/kv/key-value-store';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const SNAPSHOT = resolve(__dirname, '../../../docs/api/openapi.json');
const UPDATE = process.env.UPDATE_OPENAPI === '1';

const config = loadApiConfig({
  ...TEST_DOMAIN_ENV,
  NODE_ENV: 'test',
  HTTP_PORT: '3000',
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'us-east-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
  AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex'),
  DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  AUTH_BACKGROUND_JOBS_ENABLED: 'false',
});

/** Operations reachable without credentials (`@Public()`), as `METHOD path`. */
const PUBLIC_OPERATIONS = new Set([
  'GET /api/v1/meta',
  'POST /api/v1/auth/login',
  'POST /api/v1/auth/mfa/verify',
  'POST /api/v1/auth/refresh',
  'POST /api/v1/auth/password/forgot',
  'POST /api/v1/auth/password/reset',
  'POST /api/v1/auth/email/verify',
  'POST /api/v1/auth/invitations/inspect',
  'POST /api/v1/auth/invitations/accept',
]);

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'options', 'head'] as const;

interface Operation {
  key: string;
  tags: string[];
  security: Array<Record<string, string[]>>;
}

function operations(doc: OpenAPIObject): Operation[] {
  return Object.entries(doc.paths).flatMap(([path, item]) =>
    METHODS.flatMap((method) => {
      const op = (item as Record<string, unknown>)[method] as
        { tags?: string[]; security?: Array<Record<string, string[]>> } | undefined;
      return op
        ? [
            {
              key: `${method.toUpperCase()} ${path}`,
              tags: op.tags ?? [],
              security: op.security ?? [],
            },
          ]
        : [];
    }),
  );
}

/** Serialized like Prettier formats JSON (the repository's format check covers the file). */
async function serialize(doc: OpenAPIObject): Promise<string> {
  const prettier = await import('prettier');
  const options = (await prettier.resolveConfig(SNAPSHOT)) ?? {};
  return prettier.format(JSON.stringify(doc), { ...options, parser: 'json' });
}

describe('OpenAPI document (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  let doc: OpenAPIObject;

  beforeAll(async () => {
    const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue(stub('mysql'))
      .overrideProvider(PrismaReadService)
      .useValue(stub('mysql-reader'))
      .overrideProvider(RedisService)
      .useValue(stub('redis'))
      .overrideProvider(S3Service)
      .useValue(stub('s3'))
      .overrideProvider(KeyValueStore)
      .useValue(new InMemoryKeyValueStore())
      .overrideProvider(EmailSender)
      .useValue(new RecordingEmailSender())
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, config);
    await app.init();
    doc = buildOpenApiDocument(app);
  });

  afterAll(async () => {
    await app?.close();
  });

  it('documents business routes under /api/v1 only (step 6.1 D13: no probes, no metrics)', () => {
    for (const path of Object.keys(doc.paths)) {
      expect(path.startsWith('/api/v1/'), path).toBe(true);
    }
    for (const internal of ['/health/live', '/health/ready', '/metrics']) {
      expect(doc.paths[internal], internal).toBeUndefined();
    }
  });

  it('defines the shared error schemas and response headers (step 6.1 D14)', () => {
    expect(Object.keys(doc.components?.schemas ?? {})).toEqual(
      expect.arrayContaining(['ErrorBody', 'ValidationErrorBody', 'RateLimitedErrorBody']),
    );
    expect(Object.keys(doc.components?.headers ?? {}).sort()).toEqual(
      [
        'Idempotency-Replayed',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'Retry-After',
        'X-Correlation-Id',
        'X-Request-Id',
      ].sort(),
    );
  });

  it('gives every operation the standard error responses and headers (step 6.1 D14)', () => {
    type Response = { headers?: Record<string, unknown> };
    type Op = {
      security?: unknown[];
      parameters?: Array<{ in: string }>;
      requestBody?: unknown;
      responses: Record<string, Response>;
      'x-eg-idempotency'?: string;
    };
    const failures: string[] = [];
    let count = 0;
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const method of METHODS) {
        const op = (item as Record<string, Op | undefined>)[method];
        if (!op) continue;
        count += 1;
        const key = `${method.toUpperCase()} ${path}`;
        const secured = (op.security ?? []).length > 0;
        const expected = ['429', '500', '503'];
        if ((op.parameters ?? []).length > 0 || op.requestBody) expected.push('400');
        if (secured) expected.push('401', '403');
        if (path.includes('{')) expected.push('404');
        for (const status of expected) {
          if (!op.responses[status]) failures.push(`${key}: no ${status}`);
        }
        for (const [status, response] of Object.entries(op.responses)) {
          const headers = Object.keys(response.headers ?? {}).map((h) => h.toLowerCase());
          const want = ['x-request-id', 'x-correlation-id'];
          if (secured) want.push('ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset');
          if (status === '429') want.push('retry-after');
          if (op['x-eg-idempotency'] && status.startsWith('2')) want.push('idempotency-replayed');
          for (const header of want) {
            if (!headers.includes(header)) failures.push(`${key} ${status}: no ${header}`);
          }
        }
      }
    }
    expect(failures).toEqual([]);
    // 231 operations before step 6.1, minus the two probes (D13), plus the 20 new routes of
    // §3.3 (step 6.1 §1.2): 249; plus the 17 webhook and notification routes of step 6.2
    // (docs/plan/steps/19-webhooks-notifications.md §6.1): 266, all under /api/v1.
    expect(count).toBe(266);
  });

  it('gives every /api/v1 operation a tag', () => {
    const untagged = operations(doc)
      .filter((op) => op.key.includes(' /api/v1/') && op.tags.length === 0)
      .map((op) => op.key);
    expect(untagged).toEqual([]);
  });

  it('gives every protected /api/v1 operation a security requirement', () => {
    const ops = operations(doc).filter((op) => op.key.includes(' /api/v1/'));
    const unsecured = ops
      .filter((op) => op.security.length === 0 && !PUBLIC_OPERATIONS.has(op.key))
      .map((op) => op.key);
    expect(unsecured).toEqual([]);
    // Public operations must not claim a credential they do not need.
    const publicWithSecurity = ops
      .filter((op) => PUBLIC_OPERATIONS.has(op.key) && op.security.length > 0)
      .map((op) => op.key);
    expect(publicWithSecurity).toEqual([]);
    // Only the declared schemes are referenced.
    const schemes = new Set(ops.flatMap((op) => op.security.flatMap((s) => Object.keys(s))));
    for (const scheme of schemes) expect([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME]).toContain(scheme);
  });

  it('documents every organization endpoint of §4.3 with the organizations tag', () => {
    const expected = [
      'POST /api/v1/organizations',
      'GET /api/v1/organizations',
      'GET /api/v1/organizations/{id}',
      'PUT /api/v1/organizations/{id}',
      'PATCH /api/v1/organizations/{id}/status',
      'GET /api/v1/organizations/{id}/usage',
      'GET /api/v1/organizations/{id}/settings',
      'PUT /api/v1/organizations/{id}/settings',
      'GET /api/v1/organizations/{id}/features',
      'PUT /api/v1/organizations/{id}/features/{featureKey}',
      'DELETE /api/v1/organizations/{id}/features/{featureKey}',
      'GET /api/v1/organizations/{id}/limits',
      'PUT /api/v1/organizations/{id}/limits/{limitKey}',
      'DELETE /api/v1/organizations/{id}/limits/{limitKey}',
      'GET /api/v1/organizations/{id}/deletion',
      'POST /api/v1/organizations/{id}/deletion',
      'POST /api/v1/organizations/{id}/deletion/confirm',
      'POST /api/v1/organizations/{id}/deletion/cancel',
    ];
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const key of expected) {
      expect(byKey.get(key)?.tags, key).toContain('organizations');
    }
    // API keys are accepted exactly on the "K" routes of §4.3.
    const apiKeyRoutes = expected.filter((key) =>
      byKey.get(key)?.security.some((s) => API_KEY_SCHEME in s),
    );
    expect(apiKeyRoutes.sort()).toEqual(
      [
        'GET /api/v1/organizations',
        'GET /api/v1/organizations/{id}',
        'PUT /api/v1/organizations/{id}',
        'GET /api/v1/organizations/{id}/usage',
        'GET /api/v1/organizations/{id}/settings',
        'PUT /api/v1/organizations/{id}/settings',
        'GET /api/v1/organizations/{id}/features',
        'GET /api/v1/organizations/{id}/limits',
      ].sort(),
    );
  });

  it('documents every domain endpoint of steps 2.1 §4 and 2.2 §4.1 for tokens and API keys', () => {
    const expected = [
      'POST /api/v1/domains',
      'GET /api/v1/domains',
      'GET /api/v1/domains/{id}',
      'POST /api/v1/domains/{id}/verify',
      'GET /api/v1/domains/{id}/dns-records',
      'GET /api/v1/domains/{id}/status',
      'POST /api/v1/domains/{id}/dkim/rotate',
      'PATCH /api/v1/domains/{id}/status',
      'DELETE /api/v1/domains/{id}',
      // Step 2.2 §4.1: inbound recipient validation.
      'GET /api/v1/domains/{id}/recipient-validation',
      'PUT /api/v1/domains/{id}/recipient-validation',
      'GET /api/v1/domains/{id}/recipients',
      'POST /api/v1/domains/{id}/recipients',
      'POST /api/v1/domains/{id}/recipients/remove',
      // Step 2.3 R13: destination servers.
      'GET /api/v1/domains/{id}/destinations',
      'PUT /api/v1/domains/{id}/destinations',
      'DELETE /api/v1/domains/{id}/destinations',
    ];
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const key of expected) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual(['domains']);
      const schemes = op!.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    const domainOps = operations(doc).filter((op) => op.key.includes(' /api/v1/domains'));
    expect(domainOps.map((op) => op.key).sort()).toEqual([...expected].sort());
  });

  it('documents every SMTP connector endpoint of step 2.2 §4.1, with the shared-IP warning', () => {
    const expected = [
      'POST /api/v1/smtp-connectors',
      'GET /api/v1/smtp-connectors',
      'GET /api/v1/smtp-connectors/{id}',
      'PATCH /api/v1/smtp-connectors/{id}',
      'POST /api/v1/smtp-connectors/{id}/rotate-secret',
      'DELETE /api/v1/smtp-connectors/{id}',
    ];
    const ops = operations(doc).filter((op) => op.key.includes(' /api/v1/smtp-connectors'));
    expect(ops.map((op) => op.key).sort()).toEqual([...expected].sort());
    for (const op of ops) {
      expect(op.tags, op.key).toEqual(['smtp-connectors']);
      const schemes = op.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, op.key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    const create = (
      doc.paths['/api/v1/smtp-connectors'] as Record<string, { description?: string }>
    ).post!;
    expect(create.description).toContain('Microsoft 365');
    expect(create.description).toContain('Google Workspace');
    // The secret hash is never part of any response schema.
    expect(JSON.stringify(doc)).not.toMatch(/secretHash|secret_hash/);
  });

  it('documents the step 2.3 destination and delivery status endpoints (R13)', () => {
    const expected: Record<string, string> = {
      'GET /api/v1/destination-providers': 'domains',
      'GET /api/v1/domains/{id}/destinations': 'domains',
      'PUT /api/v1/domains/{id}/destinations': 'domains',
      'DELETE /api/v1/domains/{id}/destinations': 'domains',
      'GET /api/v1/messages/{messageId}/deliveries': 'deliveries',
      'GET /api/v1/messages/{messageId}/deliveries/events': 'deliveries',
      'GET /api/v1/deliveries': 'deliveries',
    };
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const [key, tag] of Object.entries(expected)) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual([tag]);
      const schemes = op!.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    const deliveryOps = operations(doc).filter(
      (op) =>
        op.key.includes(' /api/v1/deliveries') ||
        (op.key.includes(' /api/v1/messages') && op.key.includes('/deliveries')),
    );
    expect(deliveryOps.map((op) => op.key).sort()).toEqual(
      Object.keys(expected)
        .filter((key) => key.includes('deliveries'))
        .sort(),
    );
    // The 422 of PUT documents every stable refusal reason.
    const put = (doc.paths['/api/v1/domains/{id}/destinations'] as Record<string, unknown>).put as {
      responses: Record<string, { content?: Record<string, { schema?: unknown }> }>;
    };
    const refusal = JSON.stringify(put.responses['422']);
    for (const reason of [
      'ip_not_public',
      'metadata_address',
      'gateway_host',
      'duplicate_server',
    ]) {
      expect(refusal).toContain(reason);
    }
  });

  it('documents the step 3.2 dead-letter endpoints (Q9) for access tokens only', () => {
    const expected = [
      'GET /api/v1/platform/dead-letters',
      'POST /api/v1/platform/dead-letters/replay',
    ];
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const key of expected) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual(['platform']);
      const schemes = op!.security.flatMap((s) => Object.keys(s));
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME]);
    }
    const replay = (doc.paths['/api/v1/platform/dead-letters/replay'] as Record<string, unknown>)
      .post as { responses: Record<string, unknown>; description?: string };
    // Step 6.1 D14 adds the standard 429 and 500 to every operation.
    expect(Object.keys(replay.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '409', '429', '500', '503'].sort(),
    );
    expect(replay.description).toContain('source_queue_not_replayable');
    // The internal Prometheus endpoint is not part of the contract.
    expect(doc.paths['/metrics']).toBeUndefined();
  });

  it('documents the step 3.3 lifecycle endpoints (L10, L12) with their errors and headers', () => {
    const expected = [
      'GET /api/v1/messages/{messageId}/lifecycle',
      'GET /api/v1/messages/{messageId}/lifecycle/history',
      'POST /api/v1/messages/{messageId}/rescan',
      'POST /api/v1/messages/{messageId}/release',
    ];
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const key of expected) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual(['messages']);
      const schemes = op!.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    // Step 6.1 adds the list, the detail and the recipients / attachments / urls sub-resources
    // (WP2, asserted below in the step 6.1 test); the step 3.3 lifecycle set is unchanged.
    const STEP_6_1 = new Set([
      'GET /api/v1/messages',
      'GET /api/v1/messages/{messageId}',
      'GET /api/v1/messages/{messageId}/recipients',
      'GET /api/v1/messages/{messageId}/attachments',
      'GET /api/v1/messages/{messageId}/urls',
    ]);
    const messageOps = operations(doc).filter(
      (op) =>
        op.key.includes(' /api/v1/messages') &&
        !STEP_6_1.has(op.key) &&
        !op.key.includes('/deliveries') &&
        !op.key.endsWith('/scans') &&
        !op.key.endsWith('/bec-feedback') &&
        !op.key.endsWith('/dlp-evidence') &&
        !op.key.endsWith('/risk/dry-run') &&
        !op.key.endsWith('/policy/dry-run') &&
        !op.key.endsWith('/policy-evaluations'),
    );
    expect(messageOps.map((op) => op.key).sort()).toEqual([...expected].sort());

    type Op = {
      parameters?: Array<{ name: string; in: string; required?: boolean }>;
      responses: Record<string, { headers?: Record<string, unknown> }>;
      requestBody?: unknown;
    };
    for (const action of ['rescan', 'release']) {
      const op = (doc.paths[`/api/v1/messages/{messageId}/${action}`] as Record<string, Op>).post!;
      expect(Object.keys(op.responses).sort(), action).toEqual(
        ['202', '400', '401', '403', '404', '409', '422', '429', '500', '503'].sort(),
      );
      expect(op.parameters?.find((p) => p.name === 'Idempotency-Key')).toMatchObject({
        in: 'header',
        required: true,
      });
      expect(op.responses['202']!.headers).toHaveProperty('Idempotency-Replayed');
      expect(op.requestBody).toBeDefined();
      const text = JSON.stringify(op.responses);
      for (const code of [
        'idempotency_key_required',
        'idempotency_key_invalid',
        'idempotency_key_reused',
        'message_not_found',
        'message_version_conflict',
        'message_state_conflict',
      ]) {
        expect(text, `${action} ${code}`).toContain(code);
      }
    }
    const release = JSON.stringify(
      (doc.paths['/api/v1/messages/{messageId}/release'] as Record<string, Op>).post!.responses,
    );
    expect(release).toContain('quarantine_workflow_required');
    // Step 5.3 (Q30): the release answers 409 quarantine_workflow_required; no other refusal.
    expect(release).not.toContain('no_releasable_recipients');
    // The deliveries view carries the lifecycle reason since step 3.3.
    expect(JSON.stringify(doc.paths['/api/v1/messages/{messageId}/deliveries'])).toContain(
      'statusReason',
    );
  });

  it('documents the step 4.1 scan endpoints (S13, S16) with their security and errors', () => {
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    const tenant: Record<string, string> = {
      'GET /api/v1/messages/{messageId}/scans': 'messages',
      'GET /api/v1/scan-settings': 'scan-settings',
      'PUT /api/v1/scan-settings/{engine}': 'scan-settings',
      'DELETE /api/v1/scan-settings/{engine}': 'scan-settings',
    };
    for (const [key, tag] of Object.entries(tenant)) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual([tag]);
      const schemes = op!.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    const training =
      'POST /api/v1/platform/organizations/{organizationId}/messages/{messageId}/scan-training';
    expect(byKey.get(training)?.tags).toEqual(['platform']);
    expect(byKey.get(training)!.security.flatMap((s) => Object.keys(s))).toEqual([
      ACCESS_TOKEN_SCHEME,
    ]);

    type Op = { responses: Record<string, unknown>; description?: string };
    const op = (path: string, method: string) => (doc.paths[path] as Record<string, Op>)[method]!;
    const scans = op('/api/v1/messages/{messageId}/scans', 'get');
    expect(Object.keys(scans.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '429', '500', '503'].sort(),
    );
    expect(JSON.stringify(scans.responses)).toContain('message_not_found');
    const put = op('/api/v1/scan-settings/{engine}', 'put');
    expect(Object.keys(put.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '409', '422', '429', '500', '503'].sort(),
    );
    for (const code of ['scan_engine_not_found', 'version_conflict', 'scan_settings_invalid']) {
      expect(JSON.stringify(put.responses)).toContain(code);
    }
    expect(put.description).toContain('SCAN_SETTINGS_CACHE_TTL_MS');
    const train = op(
      '/api/v1/platform/organizations/{organizationId}/messages/{messageId}/scan-training',
      'post',
    );
    expect(Object.keys(train.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '409', '422', '429', '500', '503'].sort(),
    );
    for (const code of ['content_unavailable', 'rspamd_unavailable', 'organization_not_found']) {
      expect(JSON.stringify(train.responses)).toContain(code);
    }
    // Step 4.1 S14: the rescan is scanned by the registered engines; scan.spam is replayable.
    expect(op('/api/v1/messages/{messageId}/rescan', 'post').description).toContain(
      'registered scan engine',
    );
    expect(op('/api/v1/platform/dead-letters/replay', 'post').description).toContain('scan.spam');
  });

  it('documents the step 4.4 BEC endpoints (B18) with their security, errors and the export', () => {
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    const expected = [
      'GET /api/v1/bec/executives',
      'POST /api/v1/bec/executives',
      'GET /api/v1/bec/executives/{id}',
      'PATCH /api/v1/bec/executives/{id}',
      'DELETE /api/v1/bec/executives/{id}',
      'GET /api/v1/bec/vendors',
      'POST /api/v1/bec/vendors',
      'GET /api/v1/bec/vendors/{id}',
      'PATCH /api/v1/bec/vendors/{id}',
      'DELETE /api/v1/bec/vendors/{id}',
      'GET /api/v1/bec/trusted-senders',
      'POST /api/v1/bec/trusted-senders',
      'PATCH /api/v1/bec/trusted-senders/{id}',
      'DELETE /api/v1/bec/trusted-senders/{id}',
      'POST /api/v1/messages/{messageId}/scans/{scanId}/bec-feedback',
      'GET /api/v1/bec/feedback',
      'GET /api/v1/bec/feedback/export',
      'GET /api/v1/bec/suppressions',
      'DELETE /api/v1/bec/suppressions/{id}',
      'DELETE /api/v1/bec/history',
    ];
    const becOps = operations(doc).filter((op) => op.tags.includes('bec'));
    expect(becOps.map((op) => op.key).sort()).toEqual([...expected].sort());
    for (const key of expected) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual(['bec']);
      expect(op!.security.length, key).toBeGreaterThan(0);
    }
    type Op = { responses: Record<string, unknown>; description?: string };
    const op = (path: string, method: string) => (doc.paths[path] as Record<string, Op>)[method]!;
    const create = op('/api/v1/bec/executives', 'post');
    for (const code of ['executive_exists', 'version_conflict', 'bec_limit_reached']) {
      expect(JSON.stringify(create.responses)).toContain(code);
    }
    const feedback = op('/api/v1/messages/{messageId}/scans/{scanId}/bec-feedback', 'post');
    for (const code of [
      'message_not_found',
      'scan_not_found',
      'bec_result_not_found',
      'feedback_exists',
      'suppression_not_allowed',
      'inconsistent_read',
    ]) {
      expect(JSON.stringify(feedback.responses)).toContain(code);
    }
    const exported = op('/api/v1/bec/feedback/export', 'get');
    expect(JSON.stringify(exported.responses['200'])).toContain('application/x-ndjson');
    expect(Object.keys(exported.responses)).toContain('429');
    expect(Object.keys(op('/api/v1/bec/history', 'delete').responses)).toContain('202');
    // The bec section of the scans read API and the bec engine settings (B13, B15).
    const scans = JSON.stringify(op('/api/v1/messages/{messageId}/scans', 'get').responses);
    for (const key of ['deterministicVerdict', 'thresholds', 'aiShadow', 'scanId']) {
      expect(scans).toContain(key);
    }
    expect(JSON.stringify(op('/api/v1/scan-settings', 'get').responses)).toContain(
      'freemailExtraDomains',
    );
  });

  it('documents the step 5.1 risk scoring endpoints (R15) with their errors and disclaimers', () => {
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    const expected = [
      'GET /api/v1/risk-scoring/platform-profile',
      'GET /api/v1/risk-scoring/profile',
      'GET /api/v1/risk-scoring/profile/versions',
      'POST /api/v1/risk-scoring/profile/versions',
      'GET /api/v1/risk-scoring/profile/versions/{versionId}',
      'PUT /api/v1/risk-scoring/profile/versions/{versionId}',
      'DELETE /api/v1/risk-scoring/profile/versions/{versionId}',
      'POST /api/v1/risk-scoring/profile/versions/{versionId}/publish',
      'POST /api/v1/risk-scoring/profile/versions/{versionId}/activate',
      'POST /api/v1/risk-scoring/profile/reset',
      'POST /api/v1/messages/{messageId}/scans/{scanId}/risk/dry-run',
    ];
    const riskOps = operations(doc).filter((op) => op.tags.includes('risk-scoring'));
    expect(riskOps.map((op) => op.key).sort()).toEqual([...expected].sort());
    for (const key of expected) {
      expect(byKey.get(key)?.tags, key).toEqual(['risk-scoring']);
      expect(byKey.get(key)!.security.length, key).toBeGreaterThan(0);
    }
    type Op = { responses: Record<string, unknown>; description?: string };
    const op = (path: string, method: string) => (doc.paths[path] as Record<string, Op>)[method]!;
    const create = op('/api/v1/risk-scoring/profile/versions', 'post');
    for (const code of [
      'risk_profile_invalid',
      'risk_profile_limit_reached',
      'inconsistent_read',
    ]) {
      expect(JSON.stringify(create.responses)).toContain(code);
    }
    const update = op('/api/v1/risk-scoring/profile/versions/{versionId}', 'put');
    for (const code of ['risk_profile_version_conflict', 'risk_profile_version_immutable']) {
      expect(JSON.stringify(update.responses)).toContain(code);
    }
    const activate = op('/api/v1/risk-scoring/profile/versions/{versionId}/activate', 'post');
    expect(JSON.stringify(activate.responses)).toContain('risk_profile_version_not_published');
    const dryRun = op('/api/v1/messages/{messageId}/scans/{scanId}/risk/dry-run', 'post');
    for (const code of [
      'message_not_found',
      'scan_not_found',
      'risk_profile_version_not_found',
      'scan_round_not_complete',
      'risk_revision_unavailable',
      'risk_profile_invalid',
    ]) {
      expect(JSON.stringify(dryRun.responses)).toContain(code);
    }
    expect(dryRun.description).toContain('Writes nothing');
    for (const [path, method] of [
      ['/api/v1/risk-scoring/platform-profile', 'get'],
      ['/api/v1/risk-scoring/profile', 'get'],
      ['/api/v1/risk-scoring/profile/versions/{versionId}/publish', 'post'],
      ['/api/v1/messages/{messageId}/scans/{scanId}/risk/dry-run', 'post'],
    ] as const) {
      const description = op(path, method).description ?? '';
      expect(description, path).toContain('recommends and does not enforce');
      expect(description, path).toContain('not validated detection accuracy');
    }
    for (const [path, method] of [
      ['/api/v1/risk-scoring/profile/versions/{versionId}/publish', 'post'],
      ['/api/v1/risk-scoring/profile/versions/{versionId}/activate', 'post'],
      ['/api/v1/risk-scoring/profile/reset', 'post'],
    ] as const) {
      expect(op(path, method).description, path).toContain('next scan round only');
    }
    // The risk section of the scans read API.
    const scans = op('/api/v1/messages/{messageId}/scans', 'get');
    expect(JSON.stringify(scans.responses)).toContain('recommendedAction');
    expect(JSON.stringify(scans.responses)).toContain('inputSha256');
    expect(scans.description).toContain('risk');
  });

  it('documents the step 5.2 policy and department endpoints (P22) with errors and notes', () => {
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    const policies = [
      'GET /api/v1/policies/catalog',
      'GET /api/v1/policies',
      'POST /api/v1/policies',
      'GET /api/v1/policies/{policyId}',
      'PATCH /api/v1/policies/{policyId}',
      'POST /api/v1/policies/{policyId}/disable',
      'POST /api/v1/policies/{policyId}/enable',
      'DELETE /api/v1/policies/{policyId}',
      'GET /api/v1/policies/{policyId}/versions',
      'POST /api/v1/policies/{policyId}/versions',
      'GET /api/v1/policies/{policyId}/versions/{versionNo}',
      'PUT /api/v1/policies/{policyId}/versions/{versionNo}',
      'DELETE /api/v1/policies/{policyId}/versions/{versionNo}',
      'POST /api/v1/policies/{policyId}/versions/{versionNo}/publish',
      'POST /api/v1/policies/{policyId}/versions/{versionNo}/activate',
      'GET /api/v1/policy-settings',
      'PUT /api/v1/policy-settings',
      'POST /api/v1/policies/test',
      'GET /api/v1/policies/executions',
      'POST /api/v1/messages/{messageId}/scans/{scanId}/policy/dry-run',
      'GET /api/v1/messages/{messageId}/policy-evaluations',
    ];
    const departments = [
      'GET /api/v1/departments',
      'POST /api/v1/departments',
      'GET /api/v1/departments/{departmentId}',
      'PATCH /api/v1/departments/{departmentId}',
      'DELETE /api/v1/departments/{departmentId}',
      'GET /api/v1/departments/{departmentId}/members',
      'POST /api/v1/departments/{departmentId}/members',
      'DELETE /api/v1/departments/{departmentId}/members/{memberId}',
    ];
    expect(
      operations(doc)
        .filter((op) => op.tags.includes('policies'))
        .map((op) => op.key)
        .sort(),
    ).toEqual([...policies].sort());
    expect(
      operations(doc)
        .filter((op) => op.tags.includes('departments'))
        .map((op) => op.key)
        .sort(),
    ).toEqual([...departments].sort());
    for (const key of [...policies, ...departments]) {
      expect(byKey.get(key)!.security.length, key).toBeGreaterThan(0);
    }
    type Op = { responses: Record<string, unknown>; description?: string };
    const op = (path: string, method: string) => (doc.paths[path] as Record<string, Op>)[method]!;
    const responses = (path: string, method: string) => JSON.stringify(op(path, method).responses);
    for (const code of [
      'policy_definition_invalid',
      'policy_name_taken',
      'policy_limit_reached',
      'inconsistent_read',
    ]) {
      expect(responses('/api/v1/policies', 'post')).toContain(code);
    }
    for (const code of [
      'policy_conflict',
      'policy_version_immutable',
      'policy_rule_limit_reached',
    ]) {
      expect(
        responses('/api/v1/policies/{policyId}/versions/{versionNo}/publish', 'post'),
      ).toContain(code);
    }
    expect(
      responses('/api/v1/policies/{policyId}/versions/{versionNo}/activate', 'post'),
    ).toContain('policy_version_not_published');
    expect(responses('/api/v1/policies/{policyId}/enable', 'post')).toContain(
      'policy_no_active_version',
    );
    expect(responses('/api/v1/policies/{policyId}/versions', 'post')).toContain(
      'policy_version_limit_reached',
    );
    for (const code of [
      'message_not_found',
      'scan_not_found',
      'scan_round_not_complete',
      'policy_version_not_found',
    ]) {
      expect(
        responses('/api/v1/messages/{messageId}/scans/{scanId}/policy/dry-run', 'post'),
      ).toContain(code);
    }
    expect(responses('/api/v1/departments/{departmentId}', 'delete')).toContain(
      'department_in_use',
    );
    expect(responses('/api/v1/departments/{departmentId}/members', 'post')).toContain(
      'member_address_not_tenant',
    );
    expect(
      op('/api/v1/messages/{messageId}/scans/{scanId}/policy/dry-run', 'post').description,
    ).toContain('Writes nothing');
    expect(op('/api/v1/policies/test', 'post').description).toContain('Writes nothing');
    for (const [path, method] of [
      ['/api/v1/policies/{policyId}/versions/{versionNo}/publish', 'post'],
      ['/api/v1/policies/{policyId}/versions/{versionNo}/activate', 'post'],
      ['/api/v1/policy-settings', 'put'],
    ] as const) {
      expect(op(path, method).description, path).toContain('next evaluation');
    }
    for (const [path, method] of [
      ['/api/v1/policies/catalog', 'get'],
      ['/api/v1/policies', 'post'],
      ['/api/v1/policies/test', 'post'],
    ] as const) {
      const description = op(path, method).description ?? '';
      expect(description, path).toContain('enforces');
      expect(description, path).toContain('requests');
      expect(description, path).toContain('step 5.3');
      expect(description, path).toContain('step 8.1');
    }
    expect(responses('/api/v1/messages/{messageId}/scans', 'get')).toContain('snapshotSha256');
  });

  it('documents the step 5.3 quarantine endpoints (Q26) with their tag, errors and headers', () => {
    const quarantine = operations(doc).filter((op) => op.key.includes(' /api/v1/quarantine'));
    expect(quarantine).toHaveLength(29);
    for (const op of quarantine) {
      expect(op.tags, op.key).toEqual(['quarantine']);
      expect(op.security.length, op.key).toBeGreaterThan(0);
    }
    const path = (p: string) => JSON.stringify(doc.paths[`/api/v1/quarantine${p}`]);
    expect(path('/entries/{entryId}/preview')).toContain('no-store');
    expect(path('/entries/{entryId}/preview')).toContain('quarantine_content_purged');
    expect(path('/entries/{entryId}/release')).toContain('quarantine_rescan_required');
    expect(path('/entries/{entryId}/release')).toContain('Idempotency-Key');
    expect(path('/entries/{entryId}/delete')).toContain('quarantine_legal_hold');
    expect(path('/entries/{entryId}/delete')).toContain('quarantine_retention_active');
    expect(path('/entries/{entryId}/download-grants')).toContain('quarantine_reauth_failed');
    expect(path('/downloads/{token}')).toContain('application/octet-stream');
    expect(path('/downloads/{token}')).toContain('quarantine_download_token_used');
    expect(path('/approvals/{approvalId}/approve')).toContain('quarantine_approval_forbidden');
    expect(path('/bulk')).toContain('quarantine_bulk_rate_limited');
    expect(path('/entries')).toContain('quarantine_cursor_invalid');
    // Never an S3 URL, a body or a subject search parameter.
    expect(path('/entries')).not.toMatch(/"name":"(subject|q|text)"/);
  });

  it('describes every tag and states the step 6.1 conventions and deferrals (D14)', () => {
    const used = new Set(operations(doc).flatMap((op) => op.tags));
    const described = new Map((doc.tags ?? []).map((t) => [t.name, t.description ?? '']));
    expect([...used].filter((tag) => !described.get(tag)?.trim()).sort()).toEqual([]);
    // No description for a tag nothing uses, and the module list matches OPENAPI_TAGS.
    expect([...described.keys()].sort()).toEqual([...used].sort());
    expect(OPENAPI_TAGS.map((t) => t.name).sort()).toEqual([...used].sort());
    const description = doc.info.description ?? '';
    for (const text of [
      '/api/v1',
      'X-API-Key',
      'X-Request-Id',
      'nextCursor',
      'cursor_invalid',
      'RateLimit-Limit',
      'Idempotency-Key',
      'step 8.1',
      'step 6.2',
      'step 8.2',
      'step 8.3',
      '/api/v1/smtp-connectors',
      '/api/v1/api-keys',
      'delivery_routes',
      'threat indicators',
    ]) {
      expect(description, text).toContain(text);
    }
  });

  it('documents the 20 step 6.1 routes with their module tags (§3.3, D14)', () => {
    const expected: Record<string, string> = {
      'GET /api/v1/messages': 'messages',
      'GET /api/v1/messages/{messageId}': 'messages',
      'GET /api/v1/messages/{messageId}/recipients': 'messages',
      'GET /api/v1/messages/{messageId}/attachments': 'attachments',
      'GET /api/v1/attachments': 'attachments',
      'GET /api/v1/messages/{messageId}/urls': 'url-protection',
      'GET /api/v1/url-protection/clicks': 'url-protection',
      'GET /api/v1/recipients/suppressions': 'recipients',
      'GET /api/v1/recipients/suppressions/{suppressionId}': 'recipients',
      'POST /api/v1/recipients/suppressions': 'recipients',
      'DELETE /api/v1/recipients/suppressions/{suppressionId}': 'recipients',
      'GET /api/v1/audit/logs': 'audit',
      'GET /api/v1/platform/audit/logs': 'platform',
      'GET /api/v1/reports/traffic': 'reports',
      'GET /api/v1/reports/threats': 'reports',
      'GET /api/v1/reports/url-clicks': 'reports',
      'GET /api/v1/usage': 'usage',
      'GET /api/v1/billing/plan': 'billing',
      'GET /api/v1/billing/usage': 'billing',
      'GET /api/v1/threat-intelligence/lookup': 'threat-intelligence',
    };
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const [key, tag] of Object.entries(expected)) {
      expect(byKey.get(key)?.tags, key).toEqual([tag]);
      expect(byKey.get(key)?.security.length, key).toBeGreaterThan(0);
    }
  });

  it('marks every Idempotency-Key operation with x-eg-idempotency (step 6.1 D9)', () => {
    const keyed: string[] = [];
    for (const [path, item] of Object.entries(doc.paths)) {
      for (const method of METHODS) {
        const op = (item as Record<string, unknown>)[method] as
          | { parameters?: Array<{ name: string; in: string }>; 'x-eg-idempotency'?: string }
          | undefined;
        const header = op?.parameters?.some(
          (p) => p.in === 'header' && p.name === 'Idempotency-Key',
        );
        if (!op || !header) continue;
        keyed.push(`${method.toUpperCase()} ${path}`);
        expect(['required', 'legacy'], path).toContain(op['x-eg-idempotency']);
      }
    }
    // §3.5: 13 transactional since 3.3/5.3, 2 new transactional, 22 legacy (interceptor);
    // step 6.2: 5 transactional webhook routes (create, delete, rotate, replay, range replay).
    expect(keyed).toHaveLength(42);
  });

  it('documents the 17 step 6.2 routes with their tags, permissions and the redacted replay (§6.1, ADR-0057)', () => {
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    const expected: Record<string, [string, string | null]> = {
      'GET /api/v1/webhooks': ['webhooks', 'webhook:read'],
      'POST /api/v1/webhooks': ['webhooks', 'webhook:manage'],
      'GET /api/v1/webhooks/event-types': ['webhooks', 'webhook:read'],
      'GET /api/v1/webhooks/{webhookId}': ['webhooks', 'webhook:read'],
      'PATCH /api/v1/webhooks/{webhookId}': ['webhooks', 'webhook:manage'],
      'DELETE /api/v1/webhooks/{webhookId}': ['webhooks', 'webhook:manage'],
      'POST /api/v1/webhooks/{webhookId}/rotate-secret': ['webhooks', 'webhook:manage'],
      'POST /api/v1/webhooks/{webhookId}/test': ['webhooks', 'webhook:manage'],
      'GET /api/v1/webhooks/{webhookId}/deliveries': ['webhooks', 'webhook:read'],
      'GET /api/v1/webhooks/{webhookId}/deliveries/{deliveryId}': ['webhooks', 'webhook:read'],
      'POST /api/v1/webhooks/{webhookId}/deliveries/{deliveryId}/replay': [
        'webhooks',
        'webhook:manage',
      ],
      'POST /api/v1/webhooks/{webhookId}/replays': ['webhooks', 'webhook:manage'],
      'GET /api/v1/webhooks/{webhookId}/replays/{replayId}': ['webhooks', 'webhook:read'],
      'GET /api/v1/notifications/settings': ['notifications', 'organization:read'],
      'PUT /api/v1/notifications/settings': ['notifications', 'settings:manage'],
      'GET /api/v1/notifications/preferences': ['notifications', null],
      'PUT /api/v1/notifications/preferences': ['notifications', null],
    };
    for (const [key, [tag, permission]] of Object.entries(expected)) {
      const op = byKey.get(key) as
        (ReturnType<typeof operations>[number] & Record<string, unknown>) | undefined;
      expect(op?.tags, key).toEqual([tag]);
      expect(op?.security.length, key).toBeGreaterThan(0);
      const raw = (doc.paths[key.split(' ')[1]!] as Record<string, Record<string, unknown>>)[
        key.split(' ')[0]!.toLowerCase()
      ]!;
      expect(raw['x-eg-permissions'], key).toEqual(
        permission === null ? undefined : { mode: 'all', permissions: [permission] },
      );
    }
    const secretOps = ['/api/v1/webhooks', '/api/v1/webhooks/{webhookId}/rotate-secret'].map(
      (path) => (doc.paths[path] as Record<string, Record<string, unknown>>).post!,
    );
    for (const op of secretOps) {
      expect(op['x-eg-returns-secret']).toBe(true);
      expect(op['x-eg-secret-replay']).toBe('redacted');
      expect(op['x-eg-idempotency']).toBe('required');
      expect(op['x-eg-rate-class']).toBe('sensitive');
    }
    const tags = new Map((doc.tags ?? []).map((t) => [t.name, t.description ?? '']));
    expect(tags.get('webhooks')).toContain('Step 6.2');
    expect(tags.get('notifications')).toContain('Step 6.2');
    expect(doc.info.description).toContain('x-eg-secret-replay: redacted');
  });

  it('matches the committed snapshot docs/api/openapi.json', async () => {
    const serialized = await serialize(doc);
    if (UPDATE) {
      writeFileSync(SNAPSHOT, serialized);
      return;
    }
    let committed: unknown;
    try {
      committed = JSON.parse(readFileSync(SNAPSHOT, 'utf8'));
    } catch {
      throw new Error(
        'docs/api/openapi.json is missing or invalid: run UPDATE_OPENAPI=1 pnpm --filter ' +
          '@email-gateway/api test:e2e -- openapi',
      );
    }
    expect(
      JSON.parse(serialized),
      'The API changed: regenerate docs/api/openapi.json with UPDATE_OPENAPI=1',
    ).toEqual(committed);
  });
});
