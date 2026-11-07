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
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME, buildOpenApiDocument } from '../src/http/openapi';
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

  it('documents business routes under /api/v1 only (plus the unprefixed probes)', () => {
    for (const path of Object.keys(doc.paths)) {
      expect(path.startsWith('/api/v1/') || path.startsWith('/health/'), path).toBe(true);
    }
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
    expect(Object.keys(replay.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '409', '503'].sort(),
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
    const messageOps = operations(doc).filter(
      (op) =>
        op.key.includes(' /api/v1/messages') &&
        !op.key.includes('/deliveries') &&
        !op.key.endsWith('/scans') &&
        !op.key.endsWith('/bec-feedback'),
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
        ['202', '400', '401', '403', '404', '409', '422'].sort(),
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
    expect(release).toContain('no_releasable_recipients');
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
    expect(Object.keys(scans.responses).sort()).toEqual(['200', '400', '401', '403', '404']);
    expect(JSON.stringify(scans.responses)).toContain('message_not_found');
    const put = op('/api/v1/scan-settings/{engine}', 'put');
    expect(Object.keys(put.responses).sort()).toEqual(
      ['200', '400', '401', '403', '404', '409', '422'].sort(),
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
      ['200', '400', '401', '403', '404', '409', '422', '429', '503'].sort(),
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
