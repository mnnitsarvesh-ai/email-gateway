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
