/**
 * OpenAPI contract (design §9, D3): the document builds from the running app with its
 * dependencies stubbed; every operation under /api/v1 has a tag and a security requirement
 * (except the public authentication routes and /api/v1/meta); and it matches the committed
 * snapshot docs/api/openapi.json. Regenerate the snapshot after an intended API change with
 *
 *   UPDATE_OPENAPI=1 pnpm --filter @email-gateway/api test:e2e -- openapi
 *
 * The same flag writes docs/api/policy-catalog.json (step 7.3 §2 B1): the policy catalogue with
 * the shipped default bounds and the time-zone list replaced by a marker (it depends on the Node
 * ICU build); without the flag the test fails when the file differs.
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
import { catalogView } from '../src/modules/policies/domain/policy-definition';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const SNAPSHOT = resolve(__dirname, '../../../docs/api/openapi.json');
const POLICY_CATALOG = resolve(__dirname, '../../../docs/api/policy-catalog.json');
/** `timeZones` of docs/api/policy-catalog.json (the runtime list depends on the ICU build). */
const POLICY_CATALOG_TIME_ZONES_MARKER = "<runtime: Intl.supportedValuesOf('timeZone')>";
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
  // Step API-1 D12.4: the Microsoft Graph notification callbacks.
  'POST /api/v1/provider-notifications/graph',
  'POST /api/v1/provider-notifications/graph/lifecycle',
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
async function serialize(doc: unknown, file: string = SNAPSHOT): Promise<string> {
  const prettier = await import('prettier');
  const options = (await prettier.resolveConfig(file)) ?? {};
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
    // (docs/plan/steps/19-webhooks-notifications.md §6.1): 266; plus the 3 reports of step 7.1
    // (docs/plan/steps/20-admin-portal.md §3.3): 269; plus the 5 saved views routes of step 7.2
    // WP1 (docs/plan/steps/21-email-explorer-details.md §3.3): 274; plus the headers route and the
    // two reveal operations of step 7.2 WP2: 277; plus the validate and sample dry-run routes of
    // step 7.3 (docs/plan/steps/22-policy-builder.md §4.4): 279; step 8.1
    // (docs/plan/steps/23-journaling-archiving.md §4.4): 320; step 8.4
    // (docs/plan/steps/24-account-takeover-core.md §5.1, §5.2): 354; plus the 24 provider-connection operations of step 8.2
    // (docs/plan/steps/25-m365-google-connectors.md §5.2): 378; plus the 13 identity-provider and
    // mailbox state operations of step 8.5 (docs/plan/steps/26-ato-provider-adapters.md §6): 391;
    // plus the 12 journaling operations of step 8.6
    // (docs/plan/steps/27-journal-intake-and-archive-split.md D11): 403; plus the 15 assistant
    // operations of step AI-1 (docs/plan/steps/28-ai-chat-management.md §4.1): 418; plus the 3
    // confirmation operations of step AI-2 (docs/plan/steps/29-ai-chat-confirmations-mail-writes.md
    // §4.1): 421; plus the API key read of step AI-3
    // (docs/plan/steps/30-ai-chat-identity-tenant-admin.md D8): 422; plus the report read of step
    // AI-R (docs/plan/steps/31-ai-chat-reports.md §4.1): 423; plus the four single-item reads of
    // step AI-4 (docs/plan/steps/32-ai-chat-security-operations.md D8): 427; plus the capture-issue
    // read of step AI-5 (docs/plan/steps/33-ai-chat-compliance-integrations.md D8): 428; plus the
    // 11 hardening operations of step AI-6 (docs/plan/steps/34-ai-chat-hardening-operations.md
    // §4.1, contracts §35.6): 439; plus the 16 operations of step API-1
    // (docs/plan/steps/35-api-mode-protection.md D12): 455; plus the 9 remediation operations of
    // step API-2 (docs/plan/steps/36-api-mode-remediation.md R13): 464; plus the 19 clawback,
    // report and settings operations of step API-3
    // (docs/plan/steps/37-api-mode-clawback-reporting.md C14): 483; plus the 5 onboarding
    // operations of step API-4 (docs/plan/steps/38-api-mode-parity-onboarding.md A10, B3, B6, B8):
    // 488, all under /api/v1.
    expect(count).toBe(488);
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
      // Step API-4 B3: ownership through the bound provider tenant.
      'POST /api/v1/domains/{domainId}/ownership/provider-check',
    ];
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const key of expected) {
      const op = byKey.get(key);
      expect(op?.tags, key).toEqual(['domains']);
      const schemes = op!.security.flatMap((s) => Object.keys(s)).sort();
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
    }
    // Step API-1 D12 #3: the domain mode change lives in the API-mode area (tag `api-mode`).
    const domainOps = operations(doc).filter(
      (op) => op.key.includes(' /api/v1/domains') && !op.key.endsWith('/protection-mode'),
    );
    expect(domainOps.map((op) => op.key).sort()).toEqual([...expected].sort());
    expect(byKey.get('PUT /api/v1/domains/{domainId}/protection-mode')?.tags).toEqual(['api-mode']);
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
        !op.key.endsWith('/policy-evaluations') &&
        // Step 7.2 WP2 (asserted in its own test below).
        !op.key.endsWith('/headers') &&
        !op.key.endsWith('/reveal'),
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
      'GET /api/v1/bec/trusted-senders/{id}',
      'PATCH /api/v1/bec/trusted-senders/{id}',
      'DELETE /api/v1/bec/trusted-senders/{id}',
      'POST /api/v1/messages/{messageId}/scans/{scanId}/bec-feedback',
      'GET /api/v1/bec/feedback',
      'GET /api/v1/bec/feedback/export',
      'GET /api/v1/bec/suppressions',
      'GET /api/v1/bec/suppressions/{id}',
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
      // Step 7.3 §4.2, §4.3.
      'POST /api/v1/policies/validate',
      'POST /api/v1/policies/dry-run',
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
    // Step 8.1 A23: archive retention no longer refuses the delete (code deprecated).
    expect(path('/entries/{entryId}/delete')).not.toContain('"quarantine_retention_active"');
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

  it('documents the 20 step 6.1 routes and the 3 step 7.1 reports with their module tags (§3.3, D14)', () => {
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
      // Step 7.1 §3.3 (docs/plan/steps/20-admin-portal.md).
      'GET /api/v1/reports/delivery': 'reports',
      'GET /api/v1/reports/processing': 'reports',
      'GET /api/v1/reports/top-domains': 'reports',
    };
    const byKey = new Map(operations(doc).map((op) => [op.key, op]));
    for (const [key, tag] of Object.entries(expected)) {
      expect(byKey.get(key)?.tags, key).toEqual([tag]);
      expect(byKey.get(key)?.security.length, key).toBeGreaterThan(0);
    }
  });

  it('names the step 7.1 report operations and keeps the forwarder headers internal (ADR-0060)', () => {
    const ids = Object.fromEntries(
      ['delivery', 'processing', 'top-domains'].map((p) => [
        p,
        (doc.paths[`/api/v1/reports/${p}`]?.get as { operationId?: string } | undefined)
          ?.operationId,
      ]),
    );
    expect(ids).toEqual({
      delivery: 'ReportsController_delivery_v1',
      processing: 'ReportsController_processing_v1',
      'top-domains': 'ReportsController_topDomains_v1',
    });
    const text = JSON.stringify(doc).toLowerCase();
    expect(text).not.toContain('x-eg-client-ip');
    expect(text).not.toContain('x-eg-forwarder-token');
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
    // step 6.2: 5 transactional webhook routes (create, delete, rotate, replay, range replay);
    // step 8.1: 15 transactional archive, legal hold and eDiscovery mutations; step 8.4: 14
    // transactional account takeover and incident mutations; step 8.2: 12 transactional
    // provider-connection mutations; step 8.5: 8 transactional identity-provider and mailbox
    // state mutations; step 8.6: 4 transactional journaling mutations (settings, source create,
    // update and address rotation); step API-1: 5 transactional protection-mode and API-mode
    // mutations (organization and domain mode, settings, inventory sync, mailbox resync); step
    // API-2: 6 transactional remediation mutations (policy, domain policy put and delete, retry,
    // remediate, restore); step API-3: 12 transactional clawback, report and settings mutations
    // (create, submit, hard-delete submit, approve, deny, cancel, restore, triage, report
    // clawback, report mailbox add and set, settings put); step API-4: 2 transactional
    // mutations (the domain scope put and the provider ownership check).
    expect(keyed).toHaveLength(120);
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

  it('documents the step 7.2 WP2 headers and reveal operations and the masked fields (§2 E5-E8, ADR-0062)', () => {
    type RawOp = Record<string, unknown> & {
      operationId?: string;
      tags?: string[];
      security?: Array<Record<string, unknown>>;
      requestBody?: { content?: Record<string, { schema?: unknown; examples?: unknown }> };
      responses: Record<
        string,
        { headers?: Record<string, unknown>; content?: Record<string, { schema?: unknown }> }
      >;
    };
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, RawOp>)[method]!;
    const expected: Array<[string, string, string, string]> = [
      [
        'get',
        '/api/v1/messages/{messageId}/headers',
        'MessageHeadersController_headers_v1',
        'message:read',
      ],
      [
        'post',
        '/api/v1/messages/reveal',
        'MessageRevealController_revealMany_v1',
        'message:reveal',
      ],
      [
        'post',
        '/api/v1/messages/{messageId}/reveal',
        'MessageRevealController_reveal_v1',
        'message:reveal',
      ],
    ];
    for (const [method, path, operationId, permission] of expected) {
      const op = raw(method, path);
      expect(op.operationId, path).toBe(operationId);
      expect(op.tags, path).toEqual(['messages']);
      expect(op['x-eg-permissions'], path).toEqual({ mode: 'all', permissions: [permission] });
      const schemes = (op.security ?? []).flatMap((s) => Object.keys(s)).sort();
      expect(schemes, path).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
      expect(op['x-eg-idempotency'], path).toBeUndefined();
      expect(op['x-eg-rate-class'], path).toBeUndefined();
    }
    for (const path of ['/api/v1/messages/reveal', '/api/v1/messages/{messageId}/reveal']) {
      const op = raw('post', path);
      expect(Object.keys(op.responses).sort(), path).toEqual(
        expect.arrayContaining(['200', '400', '401', '403', '429', '500', '503']),
      );
      expect(op.responses['201'], path).toBeUndefined();
      expect(op.responses['200']!.headers, path).toHaveProperty('Cache-Control');
      expect(op.responses['429']!.headers, path).toHaveProperty('Retry-After');
      expect(op.requestBody?.content?.['application/json']?.examples, path).toBeDefined();
      const text = JSON.stringify(op);
      for (const word of ['API_MESSAGES_REVEAL_PER_MINUTE', 'message.revealed', 'no-store']) {
        expect(text, `${path} ${word}`).toContain(word);
      }
      // Examples are obvious placeholders.
      expect(text, path).toContain('EXAMPLE');
    }
    expect(JSON.stringify(raw('post', '/api/v1/messages/{messageId}/reveal').responses)).toContain(
      'cursor_invalid',
    );
    expect(JSON.stringify(raw('post', '/api/v1/messages/{messageId}/reveal').responses)).toContain(
      'message_not_found',
    );
    const headersOp = JSON.stringify(raw('get', '/api/v1/messages/{messageId}/headers'));
    for (const word of ['retention_expired', 'not_parsed', 'none_stored', 'masked']) {
      expect(headersOp, word).toContain(word);
    }
    // The changed read operations describe the masked fields.
    const item = JSON.stringify(raw('get', '/api/v1/messages'));
    expect(item).toContain('subjectMasked');
    expect(item).toContain('withheld');
    expect(JSON.stringify(raw('get', '/api/v1/messages/{messageId}/recipients'))).toContain(
      'addressMasked',
    );
    for (const path of ['/api/v1/messages/{messageId}/deliveries', '/api/v1/deliveries']) {
      expect(JSON.stringify(raw('get', path)), path).toContain('recipientMasked');
    }
    expect(JSON.stringify(raw('get', '/api/v1/messages/{messageId}/deliveries/events'))).toContain(
      'local part',
    );
    for (const path of ['/api/v1/quarantine/entries', '/api/v1/quarantine/entries/{entryId}']) {
      const text = JSON.stringify(raw('get', path));
      expect(text, path).toContain('recipientMasked');
      expect(text, path).toContain('message:reveal');
    }
  });

  it('documents the step 7.3 policy builder routes and the catalogue presentation keys (§4.1–§4.4, ADR-0063)', () => {
    type RawOp = Record<string, unknown> & {
      operationId?: string;
      tags?: string[];
      description?: string;
      security?: Array<Record<string, unknown>>;
      requestBody?: { content?: Record<string, { schema?: unknown; examples?: unknown }> };
      responses: Record<
        string,
        { headers?: Record<string, unknown>; content?: Record<string, { schema?: unknown }> }
      >;
    };
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, RawOp>)[method]!;
    const schemaOf = (op: RawOp, status: string) =>
      op.responses[status]!.content!['application/json']!.schema as {
        required?: string[];
        properties: Record<string, { items?: { required?: string[] }; required?: string[] }>;
      };
    // The catalogue: every §4.1 key, required, strict.
    const catalog = schemaOf(raw('get', '/api/v1/policies/catalog'), '200');
    for (const key of [
      'fieldGroups',
      'operatorDefinitions',
      'actionDefinitions',
      'quantifiers',
      'scopeNouns',
      'contextRules',
      'weekdays',
      'timeZones',
      'policyDirections',
      'messageDirections',
    ]) {
      expect(catalog.required, key).toContain(key);
      expect(catalog.properties, key).toHaveProperty(key);
    }
    expect(catalog.properties.fields!.items!.required).toEqual(
      expect.arrayContaining(['label', 'group', 'unit', 'suggestions', 'contexts']),
    );
    expect(catalog.properties.operatorDefinitions!.items!.required).toEqual(
      expect.arrayContaining(['op', 'valueShape', 'itemKind', 'maxItems', 'allowedInException']),
    );
    expect(JSON.stringify(catalog.properties.limits)).toContain('dryRunSampleMax');
    expect(raw('get', '/api/v1/policies/catalog').description).toContain('operatorDefinitions');

    const validate = raw('post', '/api/v1/policies/validate');
    const sample = raw('post', '/api/v1/policies/dry-run');
    expect(validate.operationId).toBe('PolicyToolsController_validate_v1');
    expect(sample.operationId).toBe('PolicyToolsController_sampleDryRun_v1');
    for (const [op, permissions] of [
      [validate, ['policy:manage']],
      [sample, ['policy:manage', 'message:read']],
    ] as const) {
      expect(op.tags).toEqual(['policies']);
      expect(op['x-eg-permissions']).toEqual({ mode: 'all', permissions });
      const schemes = (op.security ?? []).flatMap((x) => Object.keys(x)).sort();
      expect(schemes).toEqual([ACCESS_TOKEN_SCHEME, API_KEY_SCHEME].sort());
      expect(op['x-eg-idempotency']).toBeUndefined();
      expect(op.description).toContain('Writes nothing');
      expect(op.description).toContain('327680 bytes');
      expect(op.requestBody?.content?.['application/json']?.examples).toBeDefined();
      expect(Object.keys(op.responses)).toEqual(
        expect.arrayContaining(['200', '400', '401', '403', '413', '429', '500', '503']),
      );
      expect(JSON.stringify(op.responses['413'])).toContain('payload_too_large');
      expect(op.responses['201']).toBeUndefined();
    }
    expect(validate['x-eg-rate-class']).toBeUndefined();
    expect(sample['x-eg-rate-class']).toBe('expensive');
    expect(JSON.stringify(validate.responses['400'])).toContain('validation_failed');
    expect(schemaOf(validate, '200').required).toEqual(
      expect.arrayContaining(['valid', 'violations', 'referenceViolations', 'definitionSha256']),
    );
    const sampleText = JSON.stringify(sample);
    for (const word of [
      'POLICY_DRY_RUN_SAMPLE_MAX',
      'POLICY_DRY_RUN_DEADLINE_MS',
      'POLICY_SAMPLE_DRY_RUNS_PER_MINUTE',
      'POLICY_HISTORY_MAX_RANGE_DAYS',
      'truncated',
    ]) {
      expect(sampleText, word).toContain(word);
    }
    const errors = JSON.stringify(sample.responses);
    for (const code of [
      'validation_failed',
      'policy_definition_invalid',
      'policy_version_not_found',
      'rate_limited',
      'service_unavailable',
    ]) {
      expect(errors, code).toContain(code);
    }
    expect(JSON.stringify(sample.responses['429'])).toContain('route');
    expect(sample.responses['429']!.headers).toHaveProperty('Retry-After');
    expect(schemaOf(sample, '200').required).toEqual(
      expect.arrayContaining(['target', 'window', 'truncated', 'exhausted', 'summary', 'items']),
    );
  });

  it('documents the step 8.1 archive and eDiscovery operations (§4.4) without secret-shaped examples', () => {
    const ops = operations(doc).filter(
      (op) =>
        op.key.includes(' /api/v1/archive') ||
        op.key.includes(' /api/v1/legal-holds') ||
        op.key.includes(' /api/v1/ediscovery'),
    );
    // 41 of step 8.1 plus the capture-issue read of step AI-5 (D8).
    expect(ops).toHaveLength(42);
    // Step 8.6 D11: the settings and capture-issue operations are also in the journaling area.
    const alsoJournaling = [
      'GET /api/v1/archive/settings',
      'PUT /api/v1/archive/settings',
      'GET /api/v1/archive/capture-issues',
      'GET /api/v1/archive/capture-issues/{messageId}',
      'POST /api/v1/archive/capture-issues/{messageId}/retry',
    ];
    for (const op of ops) {
      if (alsoJournaling.includes(op.key)) {
        expect([...op.tags].sort(), op.key).toEqual(['archive', 'journaling']);
        continue;
      }
      expect(op.tags.length, op.key).toBe(1);
      expect(['archive', 'ediscovery'], op.key).toContain(op.tags[0]);
    }
    const description = doc.info.description ?? '';
    expect(description).not.toMatch(/Archive, journal search, retention policies/);
    const archiveDocs = JSON.stringify(
      Object.entries(doc.paths).filter(
        ([path]) =>
          path.startsWith('/api/v1/archive') ||
          path.startsWith('/api/v1/legal-holds') ||
          path.startsWith('/api/v1/ediscovery'),
      ),
    );
    expect(archiveDocs).toContain('EXAMPLE');
    expect(archiveDocs).not.toMatch(
      /whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/,
    );
    expect(archiveDocs).toContain('archive_override_forbidden');
    expect(archiveDocs).toContain('X-EG-Index-Lag-Seconds');
  });

  it('documents the 12 step 8.6 journaling operations with their ids, permissions, the redacted replay and the tag groups (D11)', () => {
    const ops = operations(doc).filter((op) => op.key.includes(' /api/v1/journaling'));
    expect(ops.map((op) => op.key).sort()).toEqual(
      [
        'GET /api/v1/journaling/settings',
        'PUT /api/v1/journaling/settings',
        'GET /api/v1/journaling/status',
        'GET /api/v1/journaling/intake-sources',
        'POST /api/v1/journaling/intake-sources',
        'GET /api/v1/journaling/intake-sources/{sourceId}',
        'PATCH /api/v1/journaling/intake-sources/{sourceId}',
        'DELETE /api/v1/journaling/intake-sources/{sourceId}',
        'POST /api/v1/journaling/intake-sources/{sourceId}/rotate-address',
        'GET /api/v1/journaling/intake-sources/{sourceId}/wizard',
        'GET /api/v1/journaling/intake-sources/{sourceId}/setup-guide',
        'POST /api/v1/journaling/intake-sources/{sourceId}/attestations',
      ].sort(),
    );
    for (const op of ops) expect(op.tags, op.key).toEqual(['journaling']);
    const op = (method: string, path: string) =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    const ids: Record<string, string> = {
      'get /api/v1/journaling/settings': 'JournalingController_get_v1',
      'put /api/v1/journaling/settings': 'JournalingController_update_v1',
      'get /api/v1/journaling/status': 'JournalingController_status_v1',
      'get /api/v1/journaling/intake-sources': 'IntakeSourcesController_list_v1',
      'post /api/v1/journaling/intake-sources': 'IntakeSourcesController_create_v1',
      'get /api/v1/journaling/intake-sources/{sourceId}': 'IntakeSourcesController_get_v1',
      'patch /api/v1/journaling/intake-sources/{sourceId}': 'IntakeSourcesController_update_v1',
      'delete /api/v1/journaling/intake-sources/{sourceId}': 'IntakeSourcesController_disable_v1',
      'post /api/v1/journaling/intake-sources/{sourceId}/rotate-address':
        'IntakeSourcesController_rotate_v1',
      'get /api/v1/journaling/intake-sources/{sourceId}/wizard':
        'IntakeSourcesController_wizard_v1',
      'get /api/v1/journaling/intake-sources/{sourceId}/setup-guide':
        'IntakeSourcesController_guide_v1',
      'post /api/v1/journaling/intake-sources/{sourceId}/attestations':
        'IntakeSourcesController_attest_v1',
    };
    for (const [key, id] of Object.entries(ids)) {
      const [method, path] = key.split(' ') as [string, string];
      expect(op(method, path).operationId, key).toBe(id);
    }
    expect(op('get', '/api/v1/journaling/settings')['x-eg-permissions']).toEqual({
      mode: 'any',
      permissions: ['journal:read', 'archive:read'],
    });
    expect(op('post', '/api/v1/journaling/intake-sources')['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['journal:manage'],
    });
    for (const path of [
      '/api/v1/journaling/intake-sources',
      '/api/v1/journaling/intake-sources/{sourceId}/rotate-address',
    ]) {
      expect(op('post', path)['x-eg-secret-replay'], path).toBe('redacted');
      expect(op('post', path)['x-eg-idempotency'], path).toBe('required');
    }
    // Step 8.6: the archive record routes move to archive:search; settings are per path.
    expect(op('get', '/api/v1/archive/messages/{messageId}')['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['archive:search'],
    });
    expect(op('put', '/api/v1/archive/settings')['x-eg-permissions']).toEqual({
      mode: 'any',
      permissions: ['journal:manage', 'archive:manage'],
    });
    expect(JSON.stringify(op('put', '/api/v1/archive/settings'))).toContain(
      'archive_settings_forbidden_path',
    );
    expect((doc as unknown as Record<string, unknown>)['x-tagGroups']).toEqual([
      expect.objectContaining({ name: 'Gateway and platform' }),
      { name: 'Journaling', tags: ['journaling'] },
      { name: 'Archive', tags: ['archive', 'ediscovery'] },
      { name: 'API-mode protection', tags: ['api-mode'] },
      { name: 'Callbacks', tags: ['provider-notifications'] },
    ]);
    const journalingDocs = JSON.stringify(
      Object.entries(doc.paths).filter(([path]) => path.startsWith('/api/v1/journaling')),
    );
    expect(journalingDocs).not.toMatch(
      /whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/,
    );
  });

  it('documents the 16 step API-1 operations with their ids, permissions, keys, tags and no secret-shaped examples (D12)', () => {
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    // Step API-2's remediation and step API-3's clawback, report and settings operations are
    // checked by their own tests below.
    const isApi2 = (key: string) => {
      const [method, path] = key.split(' ') as [string, string];
      return /^ApiMode(Remediation|Clawback|Reports|Settings|Onboarding)Controller_/.test(
        String(raw(method.toLowerCase(), path).operationId),
      );
    };
    const ops = operations(doc).filter(
      (o) =>
        (o.tags.includes('api-mode') || o.tags.includes('provider-notifications')) &&
        !isApi2(o.key),
    );
    expect(ops.map((o) => o.key).sort()).toEqual(
      [
        'GET /api/v1/organizations/{id}/protection-mode',
        'PUT /api/v1/organizations/{id}/protection-mode',
        'PUT /api/v1/domains/{domainId}/protection-mode',
        'GET /api/v1/api-mode/overview',
        'GET /api/v1/api-mode/connections',
        'GET /api/v1/api-mode/connections/{connectionId}',
        'GET /api/v1/api-mode/connections/{connectionId}/setup-guide',
        'PUT /api/v1/api-mode/connections/{connectionId}/settings',
        'POST /api/v1/api-mode/connections/{connectionId}/inventory-sync',
        'GET /api/v1/api-mode/mailboxes',
        'GET /api/v1/api-mode/mailboxes/{mailboxId}',
        'POST /api/v1/api-mode/mailboxes/{mailboxId}/resync',
        'GET /api/v1/api-mode/detections',
        'GET /api/v1/api-mode/detections/{detectionId}',
        'POST /api/v1/provider-notifications/graph',
        'POST /api/v1/provider-notifications/graph/lifecycle',
      ].sort(),
    );
    // The operation ids the portal client (WP6) uses.
    expect(
      ops
        .map((o) => {
          const [method, path] = o.key.split(' ') as [string, string];
          return raw(method.toLowerCase(), path).operationId as string;
        })
        .sort(),
    ).toEqual(
      [
        'ProtectionModeController_getOrganization_v1',
        'ProtectionModeController_putOrganization_v1',
        'ProtectionModeController_putDomain_v1',
        'ApiModeController_overview_v1',
        'ApiModeController_listConnections_v1',
        'ApiModeController_getConnection_v1',
        'ApiModeController_setupGuide_v1',
        'ApiModeController_updateSettings_v1',
        'ApiModeController_inventorySync_v1',
        'ApiModeController_listMailboxes_v1',
        'ApiModeController_getMailbox_v1',
        'ApiModeController_resyncMailbox_v1',
        'ApiModeController_listDetections_v1',
        'ApiModeController_getDetection_v1',
        'ProviderNotificationsController_graph_v1',
        'ProviderNotificationsController_lifecycle_v1',
      ].sort(),
    );
    expect(
      raw('put', '/api/v1/api-mode/connections/{connectionId}/settings')['x-eg-permissions'],
    ).toEqual({ mode: 'all', permissions: ['remediation:write'] });
    expect(raw('get', '/api/v1/api-mode/detections')['x-eg-permissions']).toEqual({
      mode: 'all',
      permissions: ['remediation:read'],
    });
    for (const [method, path] of [
      ['put', '/api/v1/organizations/{id}/protection-mode'],
      ['put', '/api/v1/domains/{domainId}/protection-mode'],
      ['put', '/api/v1/api-mode/connections/{connectionId}/settings'],
      ['post', '/api/v1/api-mode/connections/{connectionId}/inventory-sync'],
      ['post', '/api/v1/api-mode/mailboxes/{mailboxId}/resync'],
    ] as const) {
      expect(raw(method, path)['x-eg-idempotency'], path).toBe('required');
      expect(raw(method, path)['x-eg-rate-class'], path).toBe('sensitive');
    }
    expect(raw('get', '/api/v1/api-mode/mailboxes')['x-eg-cursor']).toBe('v1');
    expect(raw('get', '/api/v1/api-mode/detections')['x-eg-cursor']).toBe('v1');
    expect(raw('post', '/api/v1/provider-notifications/graph').security ?? []).toEqual([]);
    // The coded errors of D12.3 are documented where they apply.
    const all = JSON.stringify(ops.map((o) => doc.paths[o.key.split(' ')[1]!]));
    for (const code of [
      'api_mode_not_enabled',
      'protection_mode_mx_points_to_gateway',
      'api_mode_mailbox_access_required',
      'api_mode_notifications_unavailable',
      'api_mode_connection_conflict',
      'api_mode_connection_not_found',
      'api_mode_mailbox_not_found',
      'api_mode_detection_not_found',
    ]) {
      expect(all, code).toContain(code);
    }
    expect(JSON.stringify(raw('post', '/api/v1/domains'))).toContain(
      'protection_mode_inbound_conflict',
    );
    expect(JSON.stringify(raw('post', '/api/v1/provider-connections/{id}/grants'))).toContain(
      'remediation_permission_required',
    );
    // API-mode views never document a cursor, a subscription id or a client-state hash (the
    // callback bodies do name `subscriptionId`: it is Graph's input).
    const views = JSON.stringify(
      ops.filter((o) => o.tags.includes('api-mode')).map((o) => doc.paths[o.key.split(' ')[1]!]),
    );
    expect(views).not.toMatch(/feedCursor|subscriptionId|clientStateHash|clientState"|deltaLink/);
    expect(all).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
  });

  it('documents the 9 step API-2 remediation operations with their ids, permissions, keys, classes, cursor, errors and no provider ids or secret-shaped examples (R13)', () => {
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    const ops = operations(doc).filter((o) => {
      const [method, path] = o.key.split(' ') as [string, string];
      return String(raw(method.toLowerCase(), path).operationId).startsWith(
        'ApiModeRemediationController_',
      );
    });
    const expected: Array<[string, string, string, 'read' | 'write']> = [
      ['GET', '/api/v1/api-mode/remediation-policy', 'getPolicy', 'read'],
      ['PUT', '/api/v1/api-mode/remediation-policy', 'putPolicy', 'write'],
      ['PUT', '/api/v1/api-mode/remediation-policy/domains/{domainId}', 'putDomainPolicy', 'write'],
      [
        'DELETE',
        '/api/v1/api-mode/remediation-policy/domains/{domainId}',
        'deleteDomainPolicy',
        'write',
      ],
      ['GET', '/api/v1/api-mode/remediations', 'list', 'read'],
      ['GET', '/api/v1/api-mode/remediations/{remediationId}', 'detail', 'read'],
      ['POST', '/api/v1/api-mode/remediations/{remediationId}/retry', 'retry', 'write'],
      ['POST', '/api/v1/api-mode/detections/{detectionId}/remediate', 'remediate', 'write'],
      ['POST', '/api/v1/api-mode/detections/{detectionId}/restore', 'restore', 'write'],
    ];
    expect(ops.map((o) => o.key).sort()).toEqual(expected.map(([m, p]) => `${m} ${p}`).sort());
    for (const [method, path, name, kind] of expected) {
      const op = raw(method.toLowerCase(), path);
      // The operation ids the registry and the portal client rely on (R13, R16).
      expect(op.operationId, path).toBe(`ApiModeRemediationController_${name}_v1`);
      expect(op.tags, path).toEqual(['api-mode']);
      expect(op['x-eg-permissions'], path).toEqual({
        mode: 'all',
        permissions: [kind === 'read' ? 'remediation:read' : 'remediation:write'],
      });
      if (kind === 'write') {
        expect(op['x-eg-idempotency'], path).toBe('required');
        expect(op['x-eg-rate-class'], path).toBe('sensitive');
      } else {
        expect(op['x-eg-idempotency'], path).toBeUndefined();
      }
    }
    expect(raw('get', '/api/v1/api-mode/remediations')['x-eg-cursor']).toBe('v1');
    const all = JSON.stringify(ops.map((o) => doc.paths[o.key.split(' ')[1]!]));
    for (const code of [
      'api_mode_hard_delete_disabled',
      'api_mode_hard_delete_not_manual',
      'api_mode_remediation_in_progress',
      'api_mode_remediation_already_applied',
      'api_mode_nothing_to_restore',
      'api_mode_restore_not_possible',
      'api_mode_remediation_not_retryable',
      'api_mode_remediation_policy_conflict',
      'api_mode_remediation_not_found',
      'api_mode_detection_not_remediable',
      'quarantine_permission_required',
      'domain_not_found',
    ]) {
      expect(all, code).toContain(code);
    }
    // Views never document provider message ids (only the container and counts).
    const detail = JSON.stringify(raw('get', '/api/v1/api-mode/remediations/{remediationId}'));
    expect(detail).toContain('providerRefs');
    expect(detail).not.toMatch(/providerMessageId|internetMessageId|AAMk/);
    expect(all).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    // The API-1 views gained the remediation fields (R13) and the quarantine entries the location.
    expect(JSON.stringify(raw('get', '/api/v1/api-mode/overview'))).toContain(
      'oldestPendingAgeSeconds',
    );
    expect(JSON.stringify(raw('get', '/api/v1/api-mode/detections'))).toContain('remediationState');
    expect(
      JSON.stringify(raw('put', '/api/v1/api-mode/connections/{connectionId}/settings')),
    ).toContain('remediationPaused');
    expect(JSON.stringify(raw('get', '/api/v1/quarantine/entries'))).toContain('mailboxAddress');
    expect(JSON.stringify(raw('get', '/api/v1/quarantine/entries/{entryId}'))).toContain(
      'detectionId',
    );
  });

  it('documents the 19 step API-3 clawback, report and settings operations with their ids, permissions, keys, classes, cursors, errors and no secret-shaped examples (C14)', () => {
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    const ops = operations(doc).filter((o) => {
      const [method, path] = o.key.split(' ') as [string, string];
      return /^ApiMode(Clawback|Reports|Settings)Controller_/.test(
        String(raw(method.toLowerCase(), path).operationId),
      );
    });
    const B = '/api/v1/api-mode';
    const K = `${B}/clawbacks/{clawbackId}`;
    const R = `${B}/reports/{reportId}`;
    const purge = ['remediation:purge'];
    const expected: Array<[string, string, string, string[], boolean]> = [
      ['POST', `${B}/clawbacks`, 'ApiModeClawbackController_create_v1', purge, true],
      ['GET', `${B}/clawbacks`, 'ApiModeClawbackController_list_v1', ['remediation:read'], false],
      ['GET', K, 'ApiModeClawbackController_detail_v1', ['remediation:read'], false],
      ['GET', `${K}/targets`, 'ApiModeClawbackController_targets_v1', ['remediation:read'], false],
      ['POST', `${K}/submit`, 'ApiModeClawbackController_submit_v1', purge, true],
      [
        'POST',
        `${K}/submit-hard-delete`,
        'ApiModeClawbackController_submitHardDelete_v1',
        purge,
        true,
      ],
      ['POST', `${K}/approve`, 'ApiModeClawbackController_approve_v1', purge, true],
      ['POST', `${K}/deny`, 'ApiModeClawbackController_deny_v1', purge, true],
      ['POST', `${K}/cancel`, 'ApiModeClawbackController_cancel_v1', purge, true],
      [
        'POST',
        `${K}/restore`,
        'ApiModeClawbackController_restore_v1',
        ['remediation:purge', 'quarantine:release'],
        true,
      ],
      ['GET', `${B}/reports`, 'ApiModeReportsController_list_v1', ['remediation:read'], false],
      ['GET', R, 'ApiModeReportsController_detail_v1', ['remediation:read'], false],
      ['POST', `${R}/triage`, 'ApiModeReportsController_triage_v1', ['remediation:write'], true],
      ['POST', `${R}/clawback`, 'ApiModeReportsController_clawback_v1', purge, true],
      [
        'GET',
        `${B}/report-mailboxes`,
        'ApiModeReportsController_listMailboxes_v1',
        ['remediation:read'],
        false,
      ],
      [
        'POST',
        `${B}/report-mailboxes`,
        'ApiModeReportsController_addMailbox_v1',
        ['remediation:write'],
        true,
      ],
      [
        'PUT',
        `${B}/mailboxes/{mailboxId}/report-mailbox`,
        'ApiModeReportsController_setMailbox_v1',
        ['remediation:write'],
        true,
      ],
      ['GET', `${B}/settings`, 'ApiModeSettingsController_get_v1', ['remediation:read'], false],
      ['PUT', `${B}/settings`, 'ApiModeSettingsController_put_v1', ['remediation:write'], true],
    ];
    expect(ops.map((o) => o.key).sort()).toEqual(expected.map(([m, p]) => `${m} ${p}`).sort());
    for (const [method, path, operationId, permissions, keyed] of expected) {
      const op = raw(method.toLowerCase(), path);
      // The operation ids the registry and the portal client rely on (C14, C15).
      expect(op.operationId, path).toBe(operationId);
      expect(op.tags, path).toEqual(['api-mode']);
      expect(op['x-eg-permissions'], path).toEqual({ mode: 'all', permissions });
      if (keyed) {
        expect(op['x-eg-idempotency'], path).toBe('required');
        expect(op['x-eg-rate-class'], path).toBe('sensitive');
      } else {
        expect(op['x-eg-idempotency'], path).toBeUndefined();
      }
    }
    for (const path of [`${B}/clawbacks`, `${K}/targets`, `${B}/reports`]) {
      expect(raw('get', path)['x-eg-cursor'], path).toBe('v1');
    }
    const all = JSON.stringify(ops.map((o) => doc.paths[o.key.split(' ')[1]!]));
    for (const code of [
      'api_mode_clawback_not_found',
      'api_mode_report_not_found',
      'api_mode_clawback_criteria_invalid',
      'api_mode_clawback_state_conflict',
      'api_mode_clawback_not_cancellable',
      'api_mode_clawback_not_restorable',
      'api_mode_purge_approval_forbidden',
      'api_mode_purge_approval_not_pending',
      'api_mode_report_state_conflict',
      'api_mode_report_not_reopenable',
      'api_mode_report_original_unknown',
      'api_mode_report_mailbox_limit',
      'api_mode_report_address_out_of_scope',
      'api_mode_settings_conflict',
      'api_mode_hard_delete_disabled',
    ]) {
      expect(all, code).toContain(code);
    }
    expect(all).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    expect(all).not.toMatch(/providerMessageId|AAMk/);
    // The additive changes of C13/C14: overview blocks, detection fields and filter, the
    // remediation trigger filter and clawbackId.
    const overview = JSON.stringify(raw('get', `${B}/overview`));
    for (const field of [
      'internal',
      'clawback',
      'reports',
      'oldestActiveAgeSeconds',
      'resolved24h',
    ]) {
      expect(overview, field).toContain(field);
    }
    const detections = JSON.stringify(raw('get', `${B}/detections`));
    expect(detections).toContain('verdictRevision');
    expect(detections).toContain('"direction"');
    const remediations = JSON.stringify(raw('get', `${B}/remediations`));
    expect(remediations).toContain('clawbackId');
    expect(remediations).toContain('purge');
  });

  it('documents the step 8.4 account takeover and incident operations (§5) with their operation ids and no secret-shaped examples', () => {
    const isStep85 = (key: string) =>
      key.includes('/api/v1/ato/providers') || key.includes('/mailbox-state');
    const ops = operations(doc).filter(
      (op) =>
        !isStep85(op.key) &&
        (op.key.includes(' /api/v1/ato/') || /\/api\/v1\/incidents($|\/)/.test(op.key)),
    );
    expect(ops).toHaveLength(34);
    for (const op of ops) {
      expect(op.tags, op.key).toEqual([op.key.includes('/ato/') ? 'ato' : 'incidents']);
    }
    const operationIds = Object.values(doc.paths)
      .flatMap((p) => Object.values(p as Record<string, { operationId?: string }>))
      .map((o) => o.operationId)
      .filter((id): id is string => /^(Ato|Incidents)[A-Za-z]*Controller_/.test(id ?? ''))
      .filter((id) => !/^(AtoProvidersController|AtoAccountMailboxController)_/.test(id));
    expect(operationIds.sort()).toEqual(
      [
        'AtoOverviewController_overview_v1',
        'AtoOverviewController_attention_v1',
        'AtoAccountsController_list_v1',
        'AtoAccountsController_get_v1',
        'AtoAccountsController_update_v1',
        'AtoAccountsController_signals_v1',
        'AtoAccountsController_authEvents_v1',
        'AtoAccountsController_activity_v1',
        'AtoAccountsController_scoreHistory_v1',
        'AtoAccountsController_setOverride_v1',
        'AtoAccountsController_clearOverride_v1',
        'AtoAccountsController_addTrustedContext_v1',
        'AtoAccountsController_removeTrustedContext_v1',
        'AtoIncidentEvidenceController_signals_v1',
        'AtoIncidentEvidenceController_authEvents_v1',
        'AtoResponsesController_request_v1',
        'AtoResponsesController_list_v1',
        'AtoResponsesController_get_v1',
        'AtoResponsesController_approve_v1',
        'AtoResponsesController_reject_v1',
        'AtoResponsesController_cancel_v1',
        'AtoResponsesController_rollback_v1',
        'AtoRestrictionsController_list_v1',
        'AtoSettingsController_get_v1',
        'AtoSettingsController_update_v1',
        'AtoRulesController_list_v1',
        'IncidentsController_list_v1',
        'IncidentsController_create_v1',
        'IncidentsController_get_v1',
        'IncidentsController_update_v1',
        'IncidentsController_addNote_v1',
        'IncidentsController_timeline_v1',
        'IncidentsController_messages_v1',
        'IncidentsController_report_v1',
      ].sort(),
    );
    const docs = JSON.stringify(
      Object.entries(doc.paths).filter(
        ([path]) => path.startsWith('/api/v1/ato/') || /^\/api\/v1\/incidents($|\/)/.test(path),
      ),
    );
    expect(docs).toContain('EXAMPLE');
    expect(docs).toContain('ato_not_enabled');
    expect(docs).toContain('incident_not_found');
    expect(docs).toContain('x-eg-permissions');
    expect(docs).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    const tags = new Map((doc.tags ?? []).map((t) => [t.name, t.description ?? '']));
    expect(tags.get('ato')).toContain('Step 8.4');
    expect(tags.get('incidents')).toContain('Step 8.4');
  });

  it('documents the step 8.5 identity-provider and mailbox state operations (§6) with their operation ids, permissions and no secret-shaped examples', () => {
    const ops = operations(doc).filter(
      (op) => op.key.includes('/api/v1/ato/providers') || op.key.includes('/mailbox-state'),
    );
    expect(ops.map((op) => op.key).sort()).toEqual(
      [
        'GET /api/v1/ato/providers',
        'GET /api/v1/ato/providers/requirements',
        'GET /api/v1/ato/providers/connections',
        'POST /api/v1/ato/providers',
        'GET /api/v1/ato/providers/{integrationId}',
        'PATCH /api/v1/ato/providers/{integrationId}',
        'POST /api/v1/ato/providers/{integrationId}/pause',
        'POST /api/v1/ato/providers/{integrationId}/resume',
        'POST /api/v1/ato/providers/{integrationId}/health-check',
        'POST /api/v1/ato/providers/{integrationId}/backfill',
        'DELETE /api/v1/ato/providers/{integrationId}',
        'GET /api/v1/ato/accounts/{accountId}/mailbox-state',
        'POST /api/v1/ato/accounts/{accountId}/mailbox-state/refresh',
      ].sort(),
    );
    for (const op of ops) expect(op.tags, op.key).toEqual(['ato']);
    const ids = new Map<string, string>();
    const permissions = new Map<string, unknown>();
    for (const [path, item] of Object.entries(doc.paths)) {
      if (!path.startsWith('/api/v1/ato/providers') && !path.includes('/mailbox-state')) continue;
      for (const [method, op] of Object.entries(
        item as Record<string, { operationId?: string; 'x-eg-permissions'?: unknown }>,
      )) {
        ids.set(`${method.toUpperCase()} ${path}`, op.operationId ?? '');
        permissions.set(op.operationId ?? '', op['x-eg-permissions']);
      }
    }
    expect([...ids.values()].sort()).toEqual(
      [
        'AtoProvidersController_list_v1',
        'AtoProvidersController_requirements_v1',
        'AtoProvidersController_connections_v1',
        'AtoProvidersController_create_v1',
        'AtoProvidersController_get_v1',
        'AtoProvidersController_update_v1',
        'AtoProvidersController_pause_v1',
        'AtoProvidersController_resume_v1',
        'AtoProvidersController_healthCheck_v1',
        'AtoProvidersController_backfill_v1',
        'AtoProvidersController_remove_v1',
        'AtoAccountMailboxController_get_v1',
        'AtoAccountMailboxController_refresh_v1',
      ].sort(),
    );
    const perm = (id: string) =>
      (permissions.get(id) as { permissions?: string[] } | undefined)?.permissions;
    expect(perm('AtoProvidersController_list_v1')).toEqual(['ato:read']);
    expect(perm('AtoProvidersController_connections_v1')).toEqual(['ato:configure']);
    expect(perm('AtoProvidersController_create_v1')).toEqual(['ato:configure']);
    expect(perm('AtoAccountMailboxController_get_v1')).toEqual(['ato:read']);
    expect(perm('AtoAccountMailboxController_refresh_v1')).toEqual(['ato:manage']);
    const docs = JSON.stringify(
      Object.entries(doc.paths).filter(
        ([path]) => path.startsWith('/api/v1/ato/providers') || path.includes('/mailbox-state'),
      ),
    );
    expect(docs).toContain('EXAMPLE');
    for (const code of [
      'ato_provider_not_found',
      'ato_provider_connection_not_found',
      'ato_provider_connection_ineligible',
      'ato_provider_already_bound',
      'ato_provider_directory_in_use',
      'ato_provider_limit_reached',
      'ato_provider_settings_invalid',
      'ato_provider_conflict',
      'ato_provider_connection_inactive',
      'ato_provider_backfill_active',
      'ato_provider_backfill_range_invalid',
      'ato_provider_refresh_unavailable',
      'ato_provider_disabled',
      'ato_not_enabled',
    ]) {
      expect(docs, code).toContain(code);
    }
    expect(docs).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    // The 8.4 settings view carries the integrations (no `availableInStep` any more).
    expect(JSON.stringify(doc)).not.toContain('availableInStep');
    expect(
      new Map((doc.tags ?? []).map((t) => [t.name, t.description ?? ''])).get('ato'),
    ).toContain('Step 8.5');
  });

  it('documents the 15 step AI-1, 3 step AI-2, 1 step AI-R and 11 step AI-6 assistant operations with their ids, permissions, classes, cursors, user-only security and error codes (§4.1)', () => {
    const ops = operations(doc).filter((op) => op.key.includes(' /api/v1/assistant'));
    const expected: Record<string, [string, string, string | null, 'v1' | null]> = {
      'GET /api/v1/assistant/status': [
        'AssistantStatusController_get_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/settings': [
        'AssistantSettingsController_get_v1',
        'assistant:configure',
        null,
        null,
      ],
      'PUT /api/v1/assistant/settings': [
        'AssistantSettingsController_update_v1',
        'assistant:configure',
        'sensitive',
        null,
      ],
      'GET /api/v1/assistant/usage': [
        'AssistantUsageController_get_v1',
        'assistant:configure',
        null,
        null,
      ],
      'GET /api/v1/assistant/tools': [
        'AssistantToolsController_list_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/conversations': [
        'AssistantConversationsController_list_v1',
        'assistant:use',
        null,
        'v1',
      ],
      'POST /api/v1/assistant/conversations': [
        'AssistantConversationsController_create_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/conversations/{conversationId}': [
        'AssistantConversationsController_get_v1',
        'assistant:use',
        null,
        null,
      ],
      'PATCH /api/v1/assistant/conversations/{conversationId}': [
        'AssistantConversationsController_update_v1',
        'assistant:use',
        null,
        null,
      ],
      'DELETE /api/v1/assistant/conversations/{conversationId}': [
        'AssistantConversationsController_remove_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/conversations/{conversationId}/messages': [
        'AssistantMessagesController_list_v1',
        'assistant:use',
        null,
        'v1',
      ],
      'POST /api/v1/assistant/conversations/{conversationId}/turns': [
        'AssistantTurnsController_create_v1',
        'assistant:use',
        'expensive',
        null,
      ],
      'POST /api/v1/assistant/turns/{turnId}/cancel': [
        'AssistantTurnsController_cancel_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/executions/{executionId}': [
        'AssistantExecutionsController_get_v1',
        'assistant:use',
        null,
        null,
      ],
      'POST /api/v1/assistant/executions/{executionId}/more': [
        'AssistantExecutionsController_more_v1',
        'assistant:use',
        'expensive',
        null,
      ],
      // Step AI-2 §4.1.
      'GET /api/v1/assistant/confirmations/{confirmationId}': [
        'AssistantConfirmationsController_get_v1',
        'assistant:use',
        null,
        null,
      ],
      'POST /api/v1/assistant/confirmations/{confirmationId}/confirm': [
        'AssistantConfirmationsController_confirm_v1',
        'assistant:use',
        'sensitive',
        null,
      ],
      'POST /api/v1/assistant/confirmations/{confirmationId}/cancel': [
        'AssistantConfirmationsController_cancel_v1',
        'assistant:use',
        'sensitive',
        null,
      ],
      // Step AI-R §4.1.
      'GET /api/v1/assistant/reports/{reportId}': [
        'AssistantReportsController_get_v1',
        'assistant:use',
        null,
        null,
      ],
      // Step AI-6 §4.1 (contracts §35.6).
      'PUT /api/v1/assistant/settings/provider-key': [
        'AssistantProviderKeyController_set_v1',
        'assistant:configure',
        'sensitive',
        null,
      ],
      'DELETE /api/v1/assistant/settings/provider-key': [
        'AssistantProviderKeyController_remove_v1',
        'assistant:configure',
        'sensitive',
        null,
      ],
      'POST /api/v1/assistant/settings/provider-key/validate': [
        'AssistantProviderKeyController_validate_v1',
        'assistant:configure',
        'sensitive',
        null,
      ],
      'GET /api/v1/assistant/search': [
        'AssistantSearchController_search_v1',
        'assistant:use',
        'expensive',
        'v1',
      ],
      'PUT /api/v1/assistant/messages/{messageId}/feedback': [
        'AssistantFeedbackController_set_v1',
        'assistant:use',
        null,
        null,
      ],
      'DELETE /api/v1/assistant/messages/{messageId}/feedback': [
        'AssistantFeedbackController_remove_v1',
        'assistant:use',
        null,
        null,
      ],
      'GET /api/v1/assistant/admin/usage/users': [
        'AssistantAdminController_usageByUser_v1',
        'assistant:configure',
        null,
        'v1',
      ],
      'GET /api/v1/assistant/admin/feedback': [
        'AssistantAdminController_feedback_v1',
        'assistant:configure',
        null,
        'v1',
      ],
      'GET /api/v1/assistant/admin/conversations': [
        'AssistantAdminAuditController_conversations_v1',
        'audit:read',
        null,
        'v1',
      ],
      'GET /api/v1/assistant/admin/conversations/{conversationId}': [
        'AssistantAdminAuditController_conversation_v1',
        'audit:read',
        null,
        null,
      ],
      'GET /api/v1/assistant/admin/executions': [
        'AssistantAdminAuditController_executions_v1',
        'audit:read',
        null,
        'v1',
      ],
    };
    expect(ops.map((op) => op.key).sort()).toEqual(Object.keys(expected).sort());
    for (const [key, [operationId, permission, rateClass, cursor]] of Object.entries(expected)) {
      const [method, path] = key.split(' ') as [string, string];
      const raw = (doc.paths[path] as Record<string, Record<string, unknown>>)[
        method.toLowerCase()
      ]!;
      expect(raw.operationId, key).toBe(operationId);
      expect(raw.tags, key).toEqual(['assistant']);
      expect(raw['x-eg-permissions'], key).toEqual({ mode: 'all', permissions: [permission] });
      expect(raw['x-eg-rate-class'] ?? null, key).toBe(rateClass);
      expect(raw['x-eg-cursor'] ?? null, key).toBe(cursor);
      expect(raw['x-eg-idempotency'], key).toBeUndefined();
      // Users only: the access-token scheme, never X-API-Key.
      const schemes = ((raw.security ?? []) as Array<Record<string, unknown>>).flatMap((s) =>
        Object.keys(s),
      );
      expect(schemes, key).toEqual([ACCESS_TOKEN_SCHEME]);
    }
    const docs = JSON.stringify(
      Object.entries(doc.paths).filter(([path]) => path.startsWith('/api/v1/assistant')),
    );
    for (const code of [
      'assistant_disabled',
      'assistant_not_enabled',
      'assistant_tenant_disabled',
      'assistant_provider_unavailable',
      'assistant_busy',
      'assistant_budget_exhausted',
      'assistant_turn_in_progress',
      'assistant_conversation_limit',
      'assistant_conversation_not_found',
      'assistant_execution_not_found',
      'assistant_no_more_results',
      'assistant_settings_conflict',
      'text/event-stream',
      'turn.completed',
      // Step AI-2 §4.1, §4.2.
      'assistant_confirmation_not_found',
      'assistant_confirmation_session_mismatch',
      'assistant_confirmation_not_pending',
      'assistant_confirmation_expired',
      'assistant_confirmation_token_invalid',
      'assistant_confirmation_digest_mismatch',
      'assistant_confirmation_tool_changed',
      'assistant_confirmation_state_changed',
      'assistant_reauth_required',
      'assistant_reauth_failed',
      'confirmation.required',
      'pending_confirmation',
      'assistant-confirmation/1',
      // Step AI-3 D10, §4.1.
      'assistant_action_not_allowed',
      'denied_guard',
      // Step AI-R §4.1.
      'assistant_report_not_found',
      'assistant_report_purged',
      'assistant_report_too_large',
      'assistant_report_generation_limit',
      'assistant_report_email_limit',
      'assistant_report_storage_failed',
      'assistant_report_sources_unavailable',
      'report_recipient_not_allowed',
      'report_needs_organization',
      'assistant-report-view/1',
      // Step AI-6 §4.1 (contracts §35.6).
      'assistant_tenant_keys_disabled',
      'assistant_tenant_key_rejected',
      'assistant_tenant_key_unverified',
      'assistant_tenant_key_not_found',
      'assistant_tenant_key_invalid',
      'assistant_message_not_found',
      'assistant_feedback_not_allowed',
      'assistant_search_timeout',
      'assistant_admin_conversation_not_found',
      'assistant_report_not_ready',
      'assistant_unknown_placeholder',
      'pseudonymized',
      'keySource',
      'fallbackActive',
      'userDailyTokenBudget',
      'tenantKeysOffered',
      'effectiveLimits',
      'tenantKeyFallbackToPlatform',
    ]) {
      expect(docs, code).toContain(code);
    }
    expect(docs).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    expect(
      new Map((doc.tags ?? []).map((t) => [t.name, t.description ?? ''])).get('assistant'),
    ).toContain('Step AI-1');
  });

  it('documents the step AI-6 changed views and keeps the tenant key write-only (§35.6, I27)', () => {
    const op = (path: string, method: string): Record<string, unknown> =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    const json = (value: unknown): string => JSON.stringify(value);
    // The three provider-key routes need an MFA session (documented 403 `mfa_required`).
    for (const [path, method] of [
      ['/api/v1/assistant/settings/provider-key', 'put'],
      ['/api/v1/assistant/settings/provider-key', 'delete'],
      ['/api/v1/assistant/settings/provider-key/validate', 'post'],
    ] as const) {
      expect(json(op(path, method).responses), `${method} ${path}`).toContain('mfa_required');
    }
    // `apiKey`: write-only, a password-format string, never an example anywhere.
    const body = op('/api/v1/assistant/settings/provider-key', 'put').requestBody as {
      content: Record<string, { schema: { properties: Record<string, Record<string, unknown>> } }>;
    };
    const apiKey = body.content['application/json']!.schema.properties.apiKey!;
    expect(apiKey).toMatchObject({
      type: 'string',
      writeOnly: true,
      minLength: 20,
      maxLength: 512,
    });
    expect(apiKey.example).toBeUndefined();
    expect(apiKey.examples).toBeUndefined();
    const whole = json(doc);
    expect(whole).not.toMatch(/"apiKey":"[^"]*"/);
    expect(whole).not.toContain('not-a-secret');
    // Changed views (additive).
    const settings = json(op('/api/v1/assistant/settings', 'get').responses);
    for (const field of [
      'pseudonymized',
      'userDailyTokenBudget',
      'useTenantKey',
      'tenantKeyFallbackToPlatform',
      'tenantKey',
      'tenantKeysOffered',
      'effectiveLimits',
    ]) {
      expect(settings, field).toContain(field);
    }
    const status = json(op('/api/v1/assistant/status', 'get').responses);
    for (const field of ['keySource', 'fallbackActive', 'dataSharing']) {
      expect(status, field).toContain(field);
    }
    expect(
      json(op('/api/v1/assistant/conversations/{conversationId}/messages', 'get').responses),
    ).toContain('"feedback"');
    const report = json(op('/api/v1/assistant/reports/{reportId}', 'get').responses);
    expect(report).toContain('"job"');
    expect(report).toContain('queued');
    expect(json(op('/api/v1/assistant/conversations/{conversationId}/turns', 'post'))).toContain(
      'queued',
    );
  });

  it('matches the committed policy catalogue snapshot docs/api/policy-catalog.json (step 7.3 B1)', async () => {
    const bounds = {
      POLICY_PLATFORM_DEFAULT: config.POLICY_PLATFORM_DEFAULT,
      POLICY_MAX_POLICIES: config.POLICY_MAX_POLICIES,
      POLICY_MAX_VERSIONS_PER_POLICY: config.POLICY_MAX_VERSIONS_PER_POLICY,
      POLICY_MAX_ACTIVE_RULES: config.POLICY_MAX_ACTIVE_RULES,
      POLICY_HISTORY_MAX_RANGE_DAYS: config.POLICY_HISTORY_MAX_RANGE_DAYS,
      POLICY_DRY_RUN_SAMPLE_MAX: config.POLICY_DRY_RUN_SAMPLE_MAX,
      POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: config.POLICY_SAMPLE_DRY_RUNS_PER_MINUTE,
    };
    // The suite's config sets none of these keys: the shipped defaults.
    expect(bounds).toMatchObject({
      POLICY_MAX_POLICIES: 100,
      POLICY_DRY_RUN_SAMPLE_MAX: 50,
      POLICY_SAMPLE_DRY_RUNS_PER_MINUTE: 6,
    });
    const catalog = catalogView(bounds);
    expect(catalog.timeZones).toContain('UTC');
    const serialized = await serialize(
      { ...catalog, timeZones: [POLICY_CATALOG_TIME_ZONES_MARKER] },
      POLICY_CATALOG,
    );
    if (UPDATE) {
      writeFileSync(POLICY_CATALOG, serialized);
      return;
    }
    let committed: unknown;
    try {
      committed = JSON.parse(readFileSync(POLICY_CATALOG, 'utf8'));
    } catch {
      throw new Error(
        'docs/api/policy-catalog.json is missing or invalid: run UPDATE_OPENAPI=1 pnpm --filter ' +
          '@email-gateway/api test:e2e -- openapi',
      );
    }
    expect(
      JSON.parse(serialized),
      'The policy catalogue changed: regenerate docs/api/policy-catalog.json with UPDATE_OPENAPI=1',
    ).toEqual(committed);
  });

  it('documents the 5 step API-4 onboarding operations and the changed bodies and views (A10, A12, B3, B6, B7, B8)', () => {
    const raw = (method: string, path: string) =>
      (doc.paths[path] as Record<string, Record<string, unknown>>)[method]!;
    const B = '/api/v1/api-mode';
    const expected: Array<[string, string, string, string[], boolean]> = [
      [
        'GET',
        `${B}/protection-coverage`,
        'ApiModeOnboardingController_protectionCoverage_v1',
        ['domain:read'],
        false,
      ],
      [
        'GET',
        `${B}/domains/{domainId}/onboarding`,
        'ApiModeOnboardingController_domainOnboarding_v1',
        ['domain:read'],
        false,
      ],
      [
        'GET',
        `${B}/domains/{domainId}/scope`,
        'ApiModeOnboardingController_getScope_v1',
        ['remediation:read'],
        false,
      ],
      [
        'PUT',
        `${B}/domains/{domainId}/scope`,
        'ApiModeOnboardingController_putScope_v1',
        ['remediation:write'],
        true,
      ],
      [
        'POST',
        '/api/v1/domains/{domainId}/ownership/provider-check',
        'DomainsController_providerOwnershipCheck_v1',
        ['domain:manage'],
        true,
      ],
    ];
    for (const [method, path, operationId, permissions, keyed] of expected) {
      const op = raw(method.toLowerCase(), path);
      // The operation ids the registry (B10) and the portal client (WP6) rely on.
      expect(op.operationId, path).toBe(operationId);
      expect(op['x-eg-permissions'], path).toEqual({ mode: 'all', permissions });
      if (keyed) {
        expect(op['x-eg-idempotency'], path).toBe('required');
        expect(op['x-eg-rate-class'], path).toBe('sensitive');
      } else {
        expect(op['x-eg-idempotency'], path).toBeUndefined();
      }
    }
    expect(raw('get', `${B}/protection-coverage`)['x-eg-cursor']).toBe('v1');
    expect(raw('post', '/api/v1/domains/{domainId}/ownership/provider-check').tags).toEqual([
      'domains',
    ]);
    const all = JSON.stringify(expected.map(([, path]) => doc.paths[path]));
    for (const code of [
      'api_mode_scope_department_invalid',
      'api_mode_scope_domain_not_api',
      'api_mode_scope_conflict',
      'api_mode_scope_mailbox_invalid',
      'domain_provider_connection_unavailable',
      'domain_not_pending',
    ]) {
      expect(all, code).toContain(code);
    }
    expect(all).not.toMatch(/whsec_|AKIA|ghp_|BEGIN [A-Z ]*PRIVATE KEY|egk_|sk-[A-Za-z0-9]{8}/);
    // Changed bodies and views.
    const remediationPut = JSON.stringify(raw('put', `${B}/remediation-policy`));
    for (const text of ['detectOnly', 'policyMapping', 'api_mode_detect_only_invalid']) {
      expect(remediationPut, text).toContain(text);
    }
    const remediationGet = JSON.stringify(raw('get', `${B}/remediation-policy`));
    for (const text of ['effectivePolicyMapping', 'simulatedSinceStart']) {
      expect(remediationGet, text).toContain(text);
    }
    const overview = JSON.stringify(raw('get', `${B}/overview`));
    for (const text of ['evaluated24h', 'detections24h', 'excluded']) {
      expect(overview, text).toContain(text);
    }
    const detections = JSON.stringify(raw('get', `${B}/detections`));
    for (const text of ['policyDisposition', 'dlpAction', 'policyState', 'outbound']) {
      expect(detections, text).toContain(text);
    }
    const settings = JSON.stringify(raw('put', `${B}/settings`));
    for (const text of ['policyEvaluationEnabled', 'outboundDetectionEnabled']) {
      expect(settings, text).toContain(text);
    }
    expect(JSON.stringify(raw('get', '/api/v1/domains/{id}'))).toContain('providerCheckAvailable');
    expect(JSON.stringify(raw('get', '/api/v1/policies/executions'))).toContain('evaluationMode');
    expect(JSON.stringify(raw('get', '/api/v1/notifications/settings'))).toContain('dlpDetected');
  });

  // Serializing the ~420-operation document through Prettier takes seconds when the whole e2e
  // suite runs in parallel: an explicit timeout instead of the 5 s default.
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
  }, 60_000);
});
