/**
 * Route security (design §8, §9): every route the API serves is either `@Public()` or declares
 * an authorization requirement, and every non-public route answers `401` without credentials.
 * Routes are enumerated from the running app (Nest discovery + the Express router), so routes
 * added by later modules are covered automatically.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { type INestApplication, RequestMethod, VERSION_NEUTRAL } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA, VERSION_METADATA } from '@nestjs/common/constants';
import { DiscoveryModule, DiscoveryService, MetadataScanner, Reflector } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import {
  AUTHZ_KEY,
  IS_PUBLIC_KEY,
  REQUIRE_MFA_KEY,
  USER_ONLY_KEY,
} from '../src/auth-contracts/decorators';
import { loadApiConfig } from '../src/config';
import { RATE_LIMIT_KEY, type RateLimitOptions } from '../src/rate-limit/rate-limit.options';
import { EmailSender } from '../src/email/email-sender';
import { API_GLOBAL_PREFIX, configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

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

/** Probes and the Prometheus scrape stay outside the `/api` prefix (configureApiApp). */
const PREFIX_EXCLUDED = new Set(['health/live', 'health/ready', 'metrics']);
const DEFAULT_VERSION = '1';

interface DiscoveredRoute {
  method: string;
  path: string;
  name: string;
  isPublic: boolean;
  hasRequirement: boolean;
  requirement: unknown;
  requireMfa: boolean;
  userOnly: boolean;
  rateLimits: RateLimitOptions[];
}

const asArray = (value: unknown): string[] =>
  Array.isArray(value) ? (value as string[]) : [typeof value === 'string' ? value : ''];
const join = (...parts: string[]) =>
  `/${parts
    .flatMap((p) => p.split('/'))
    .filter(Boolean)
    .join('/')}`;

function discoverRoutes(app: INestApplication): DiscoveredRoute[] {
  const discovery = app.get(DiscoveryService);
  const scanner = app.get(MetadataScanner);
  const reflector = app.get(Reflector);
  const routes: DiscoveredRoute[] = [];
  for (const wrapper of discovery.getControllers()) {
    const controller = wrapper.metatype as (new (...args: never[]) => object) | null;
    if (!controller || !wrapper.instance) continue;
    const prototype = Object.getPrototypeOf(wrapper.instance) as Record<string, unknown>;
    for (const name of scanner.getAllMethodNames(prototype)) {
      const handler = prototype[name] as (...args: unknown[]) => unknown;
      const methodPath = Reflect.getMetadata(PATH_METADATA, handler) as unknown;
      if (methodPath === undefined) continue;
      const verb = RequestMethod[Reflect.getMetadata(METHOD_METADATA, handler) as number];
      const version =
        (Reflect.getMetadata(VERSION_METADATA, handler) as string | symbol | undefined) ??
        (Reflect.getMetadata(VERSION_METADATA, controller) as string | symbol | undefined) ??
        DEFAULT_VERSION;
      for (const base of asArray(Reflect.getMetadata(PATH_METADATA, controller))) {
        for (const sub of asArray(methodPath)) {
          const relative = join(base, sub).slice(1);
          const prefix = PREFIX_EXCLUDED.has(relative) ? '' : API_GLOBAL_PREFIX;
          const versionSegment = version === VERSION_NEUTRAL ? '' : `v${String(version)}`;
          routes.push({
            method: verb!.toLowerCase(),
            path: join(prefix, versionSegment, relative),
            name: `${controller.name}.${name}`,
            isPublic: !!reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [handler, controller]),
            hasRequirement:
              reflector.getAllAndOverride<unknown>(AUTHZ_KEY, [handler, controller]) !== undefined,
            requirement: reflector.getAllAndOverride<unknown>(AUTHZ_KEY, [handler, controller]),
            requireMfa: !!reflector.getAllAndOverride<boolean>(REQUIRE_MFA_KEY, [
              handler,
              controller,
            ]),
            userOnly: !!reflector.getAllAndOverride<boolean>(USER_ONLY_KEY, [handler, controller]),
            rateLimits: (Reflect.getMetadata(RATE_LIMIT_KEY, handler) as RateLimitOptions[]) ?? [],
          });
        }
      }
    }
  }
  return routes;
}

/**
 * Controller routes registered on the Express router. Middleware applied with `forRoutes()` (the
 * correlation-id middleware) is mounted for every HTTP verb; such catch-all layers are not
 * controller routes and are skipped.
 */
function expressRoutes(app: INestApplication): string[] {
  const instance = app.getHttpAdapter().getInstance() as {
    router: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> };
  };
  return instance.router.stack.flatMap((layer) => {
    const route = layer.route;
    if (!route) return [];
    const methods = Object.keys(route.methods).filter((m) => m !== '_all');
    if (route.methods._all || methods.length > 5) return [];
    return methods.map((m) => `${m} ${route.path}`);
  });
}

describe('route security (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  let routes: DiscoveredRoute[];

  beforeAll(async () => {
    const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule.forRoot(config), DiscoveryModule],
    })
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
    routes = discoverRoutes(app);
  });

  afterAll(async () => {
    await app.close();
  });

  it('discovers exactly the routes Express serves', () => {
    const discovered = routes.map((r) => `${r.method} ${r.path}`).sort();
    expect(discovered).toEqual([...new Set(expressRoutes(app))].sort());
    expect(discovered).toContain('post /api/v1/auth/login');
    expect(discovered).toContain('get /health/live');
  });

  it('every route is @Public() or declares an authorization requirement', () => {
    const unprotected = routes.filter((r) => !r.isPublic && !r.hasRequirement).map((r) => r.name);
    expect(unprotected).toEqual([]);
  });

  it('only the documented routes are public', () => {
    expect(
      routes
        .filter((r) => r.isPublic)
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual(
      [
        'get /health/live',
        'get /health/ready',
        // Step 3.2 §5.3: Prometheus series (internal port only, never routed publicly).
        'get /metrics',
        'get /api/v1/meta',
        'post /api/v1/auth/login',
        'post /api/v1/auth/mfa/verify',
        'post /api/v1/auth/refresh',
        'post /api/v1/auth/password/forgot',
        'post /api/v1/auth/password/reset',
        'post /api/v1/auth/email/verify',
        'post /api/v1/auth/invitations/inspect',
        'post /api/v1/auth/invitations/accept',
      ].sort(),
    );
  });

  it('every non-public route answers 401 without credentials', async () => {
    const protectedRoutes = routes.filter((r) => !r.isPublic);
    expect(protectedRoutes.length).toBeGreaterThan(0);
    const failures: string[] = [];
    for (const route of protectedRoutes) {
      const path = route.path.replace(/:[A-Za-z0-9_]+/g, randomUUID());
      const res = await request(app.getHttpServer())
        [route.method as 'get' | 'post' | 'put' | 'patch' | 'delete'](path)
        .send({});
      if (res.status !== 401) failures.push(`${route.method} ${route.path} → ${res.status}`);
    }
    expect(failures).toEqual([]);
  });

  it('every step 2.3 route requires exactly its permission (R13)', () => {
    const expected: Record<string, string> = {
      'get /api/v1/destination-providers': 'domain:read',
      'get /api/v1/domains/:id/destinations': 'domain:read',
      'put /api/v1/domains/:id/destinations': 'domain:routing_manage',
      'delete /api/v1/domains/:id/destinations': 'domain:routing_manage',
      'get /api/v1/messages/:messageId/deliveries': 'delivery:read',
      'get /api/v1/messages/:messageId/deliveries/events': 'delivery:read',
      'get /api/v1/deliveries': 'delivery:read',
    };
    for (const [key, permission] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
    }
  });

  it('the step 3.3 lifecycle routes require exactly their permission (L10, L12)', () => {
    const expected: Record<string, string> = {
      'get /api/v1/messages/:messageId/lifecycle': 'message:read',
      'get /api/v1/messages/:messageId/lifecycle/history': 'message:read',
      'post /api/v1/messages/:messageId/rescan': 'message:rescan',
      'post /api/v1/messages/:messageId/release': 'quarantine:release',
    };
    for (const [key, permission] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
    }
  });

  it('the step 3.2 dead-letter routes require their platform permissions (Q9)', () => {
    const expected: Record<string, string> = {
      'get /api/v1/platform/dead-letters': 'platform:operations',
      'post /api/v1/platform/dead-letters/replay': 'platform:dead_letter_replay',
    };
    for (const [key, permission] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
    }
  });

  it('the step 4.1 scan routes require exactly their permission (S13, S16)', () => {
    const expected: Record<string, string> = {
      'get /api/v1/messages/:messageId/scans': 'message:read',
      'get /api/v1/scan-settings': 'policy:read',
      'put /api/v1/scan-settings/:engine': 'scan:settings_manage',
      'delete /api/v1/scan-settings/:engine': 'scan:settings_manage',
      'post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training':
        'platform:scan_training',
    };
    for (const [key, permission] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
    }
  });

  it('the step 4.4 BEC routes require exactly their permission, MFA and users where B18 says (B18)', () => {
    const expected: Record<string, [string, { mfa?: boolean; userOnly?: boolean }?]> = {
      'get /api/v1/bec/executives': ['bec:read'],
      'get /api/v1/bec/executives/:id': ['bec:read'],
      'post /api/v1/bec/executives': ['bec:manage'],
      'patch /api/v1/bec/executives/:id': ['bec:manage'],
      'delete /api/v1/bec/executives/:id': ['bec:manage'],
      'get /api/v1/bec/vendors': ['bec:read'],
      'get /api/v1/bec/vendors/:id': ['bec:read'],
      'post /api/v1/bec/vendors': ['bec:manage'],
      'patch /api/v1/bec/vendors/:id': ['bec:manage'],
      'delete /api/v1/bec/vendors/:id': ['bec:manage'],
      'get /api/v1/bec/trusted-senders': ['bec:read'],
      'post /api/v1/bec/trusted-senders': ['bec:manage'],
      'patch /api/v1/bec/trusted-senders/:id': ['bec:manage'],
      'delete /api/v1/bec/trusted-senders/:id': ['bec:manage'],
      'post /api/v1/messages/:messageId/scans/:scanId/bec-feedback': [
        'bec:feedback',
        { userOnly: true },
      ],
      'get /api/v1/bec/feedback': ['bec:read'],
      'get /api/v1/bec/feedback/export': ['bec:feedback_export', { mfa: true }],
      'get /api/v1/bec/suppressions': ['bec:read'],
      'delete /api/v1/bec/suppressions/:id': ['bec:manage'],
      'delete /api/v1/bec/history': ['bec:manage', { mfa: true }],
    };
    const becRoutes = routes.filter(
      (r) => r.path.includes('/api/v1/bec/') || r.path.endsWith('/bec-feedback'),
    );
    expect(becRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permission, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
      expect(route?.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route?.userOnly, key).toBe(flags?.userOnly ?? false);
    }
  });

  it('the step 4.5 DLP routes require exactly their permission, MFA, users and rate limits where D21 says', () => {
    type Flags = { mfa?: boolean; userOnly?: boolean; perMinute?: number };
    const expected: Record<string, [string, Flags?]> = {
      'get /api/v1/dlp/policies': ['dlp:read'],
      'get /api/v1/dlp/policies/:id': ['dlp:read'],
      'post /api/v1/dlp/policies': ['dlp:manage'],
      'patch /api/v1/dlp/policies/:id': ['dlp:manage'],
      'delete /api/v1/dlp/policies/:id': ['dlp:manage'],
      'post /api/v1/dlp/policies/:id/rules': ['dlp:manage'],
      'patch /api/v1/dlp/policies/:id/rules/:ruleId': ['dlp:manage'],
      'delete /api/v1/dlp/policies/:id/rules/:ruleId': ['dlp:manage'],
      'get /api/v1/dlp/exceptions': ['dlp:read'],
      'post /api/v1/dlp/exceptions': ['dlp:manage'],
      'patch /api/v1/dlp/exceptions/:id': ['dlp:manage'],
      'delete /api/v1/dlp/exceptions/:id': ['dlp:manage'],
      'get /api/v1/dlp/patterns': ['dlp:read'],
      'get /api/v1/dlp/patterns/:id': ['dlp:read'],
      'post /api/v1/dlp/patterns': ['dlp:manage'],
      'post /api/v1/dlp/patterns/test': ['dlp:manage', { perMinute: 30 }],
      'patch /api/v1/dlp/patterns/:id': ['dlp:manage'],
      'delete /api/v1/dlp/patterns/:id': ['dlp:manage'],
      'get /api/v1/dlp/dictionaries': ['dlp:read'],
      'get /api/v1/dlp/dictionaries/:id': ['dlp:read'],
      'post /api/v1/dlp/dictionaries': ['dlp:manage'],
      'patch /api/v1/dlp/dictionaries/:id': ['dlp:manage'],
      'delete /api/v1/dlp/dictionaries/:id': ['dlp:manage'],
      'get /api/v1/dlp/compliance': ['dlp:read'],
      'put /api/v1/dlp/compliance/aadhaar': [
        'dlp:compliance_manage',
        { mfa: true, userOnly: true },
      ],
      'delete /api/v1/dlp/compliance/aadhaar': [
        'dlp:compliance_manage',
        { mfa: true, userOnly: true },
      ],
      'get /api/v1/dlp/incidents': ['dlp:read'],
      'get /api/v1/messages/:messageId/scans/:scanId/dlp-evidence': [
        'dlp:evidence_read',
        { mfa: true, userOnly: true, perMinute: 30 },
      ],
      'delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence': [
        'dlp:manage',
        { mfa: true },
      ],
      'delete /api/v1/dlp/evidence': ['dlp:manage', { mfa: true }],
    };
    const dlpRoutes = routes.filter(
      (r) => r.path.includes('/api/v1/dlp/') || r.path.endsWith('/dlp-evidence'),
    );
    expect(dlpRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permission, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
      expect(route?.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route?.userOnly, key).toBe(flags?.userOnly ?? false);
      if (flags?.perMinute === undefined) {
        expect(route?.rateLimits, key).toEqual([]);
      } else {
        expect(route?.rateLimits, key).toEqual([
          expect.objectContaining({ limit: flags.perMinute, windowSeconds: 60, by: 'principal' }),
        ]);
      }
    }
    // The scans read API stays message:read; the dlp section is gated on dlp:read inside (D20).
    expect(routes.find((r) => r.path === '/api/v1/messages/:messageId/scans')?.requirement).toEqual(
      { mode: 'all', permissions: ['message:read'] },
    );
  });

  it('non-public routes also reject a junk bearer token and a junk API key', async () => {
    const route = routes.find((r) => !r.isPublic)!;
    const path = route.path.replace(/:[A-Za-z0-9_]+/g, randomUUID());
    const send = (headers: Record<string, string>) =>
      request(app.getHttpServer())[route.method as 'get' | 'post'](path).set(headers);
    await send({ Authorization: 'Bearer a.b.c' }).expect(401);
    await send({ 'X-API-Key': 'egk_not-a-real-key' }).expect(401);
  });
});
