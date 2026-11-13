/**
 * Route security (design §8, §9): every route the API serves is either `@Public()` or declares
 * an authorization requirement, and every non-public route answers `401` without credentials.
 * Routes are enumerated from the running app (Nest discovery + the Express router), so routes
 * added by later modules are covered automatically.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { ROUTE_ARGS_METADATA } from '@nestjs/common/constants';
import { RouteParamtypes } from '@nestjs/common/enums/route-paramtypes.enum';
import { DiscoveryModule, DiscoveryService } from '@nestjs/core';
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
import type { z } from 'zod';
import { AppModule } from '../src/app.module';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { BulkBodySchema } from '../src/modules/quarantine/dto/quarantine.schemas';
import { isStrictRequestSchema } from '../src/validation/strict-schema';
import { ZodValidationPipe } from '../src/validation/zod-validation.pipe';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { type DiscoveredRoute, discoverRoutes, expressRoutes } from './support/route-discovery';
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

/** Step 6.1 §3.5: the legacy sensitive mutations and their operation names. */
const LEGACY_SENSITIVE: Record<string, string> = {
  'post /api/v1/domains/:id/dkim/rotate': 'domain.dkim_rotate',
  'patch /api/v1/organizations/:id/status': 'organization.status_change',
  'post /api/v1/organizations/:id/deletion': 'organization.deletion_request',
  'post /api/v1/organizations/:id/deletion/confirm': 'organization.deletion_confirm',
  'post /api/v1/users/invitations': 'user.invite',
  'post /api/v1/users/:id/invitation': 'user.invitation_resend',
  'post /api/v1/users/:id/mfa/reset': 'user.mfa_reset',
  'post /api/v1/policies/:policyId/versions/:versionNo/publish': 'policy.version_publish',
  'post /api/v1/policies/:policyId/versions/:versionNo/activate': 'policy.version_activate',
  'post /api/v1/risk-scoring/profile/versions/:versionId/publish': 'risk_profile.publish',
  'post /api/v1/risk-scoring/profile/versions/:versionId/activate': 'risk_profile.activate',
  'post /api/v1/risk-scoring/profile/reset': 'risk_profile.reset',
  'delete /api/v1/bec/history': 'bec.history_purge',
  'delete /api/v1/dlp/evidence': 'dlp.evidence_purge_all',
  'delete /api/v1/messages/:messageId/scans/:scanId/dlp-evidence': 'dlp.evidence_purge',
  'put /api/v1/dlp/compliance/aadhaar': 'dlp.aadhaar_enable',
  'delete /api/v1/dlp/compliance/aadhaar': 'dlp.aadhaar_disable',
  'post /api/v1/platform/dead-letters/replay': 'platform.dead_letter_replay',
  'post /api/v1/platform/attachment-rescans': 'platform.attachment_rescan',
  'post /api/v1/platform/organizations/:organizationId/messages/:messageId/scan-training':
    'platform.scan_training',
  'post /api/v1/platform/threat-hashes': 'platform.threat_hash_add',
  'post /api/v1/platform/threat-indicators': 'platform.threat_indicator_add',
};

/** Step 6.1 §3.5: keyed by IdempotencyService (transactional) since step 5.3. */
const KEYED_QUARANTINE = [
  'post /api/v1/quarantine/bulk',
  'post /api/v1/quarantine/entries',
  'post /api/v1/quarantine/entries/:entryId/release',
  'post /api/v1/quarantine/entries/:entryId/request-release',
  'post /api/v1/quarantine/entries/:entryId/reject',
  'post /api/v1/quarantine/entries/:entryId/delete',
  'post /api/v1/quarantine/approvals/:approvalId/approve',
  'post /api/v1/quarantine/approvals/:approvalId/deny',
  'post /api/v1/quarantine/approvals/:approvalId/cancel',
  'post /api/v1/quarantine/me/entries/:entryId/release',
  'post /api/v1/quarantine/me/entries/:entryId/request-release',
];

/** Step 6.1 D9: secret-bearing responses (never stored under an Idempotency-Key). */
const SECRET_BEARING = [
  'post /api/v1/api-keys',
  'post /api/v1/smtp-connectors',
  'post /api/v1/smtp-connectors/:id/rotate-secret',
  'post /api/v1/platform/overrides',
  'post /api/v1/auth/mfa/totp/setup',
  'post /api/v1/auth/mfa/recovery-codes',
];

/** Step 6.1 §3.5: the legacy routes of the expensive class (reports etc. are WP3's). */
const EXPENSIVE_LEGACY = [
  'post /api/v1/policies/test',
  'post /api/v1/messages/:messageId/scans/:scanId/policy/dry-run',
  'post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run',
];

/** Step 6.1 D3: the pre-6.1 cursor lists (unsigned v0 cursors, unchanged). */
const V0_LISTS = [
  'get /api/v1/users',
  'get /api/v1/api-keys',
  'get /api/v1/audit/login-events',
  'get /api/v1/organizations',
  'get /api/v1/domains',
  'get /api/v1/domains/:id/recipients',
  'get /api/v1/smtp-connectors',
  'get /api/v1/deliveries',
  'get /api/v1/messages/:messageId/deliveries/events',
  'get /api/v1/platform/threat-hashes',
  'get /api/v1/platform/threat-indicators',
  'get /api/v1/platform/attachment-rescans',
  'get /api/v1/bec/executives',
  'get /api/v1/bec/vendors',
  'get /api/v1/bec/trusted-senders',
  'get /api/v1/bec/feedback',
  'get /api/v1/bec/suppressions',
  'get /api/v1/dlp/policies',
  'get /api/v1/dlp/exceptions',
  'get /api/v1/dlp/patterns',
  'get /api/v1/dlp/dictionaries',
  'get /api/v1/dlp/incidents',
  'get /api/v1/risk-scoring/profile/versions',
  'get /api/v1/policies',
  'get /api/v1/policies/:policyId/versions',
  'get /api/v1/policies/executions',
  'get /api/v1/departments',
  'get /api/v1/departments/:departmentId/members',
  'get /api/v1/quarantine/entries',
  'get /api/v1/quarantine/me/entries',
  'get /api/v1/quarantine/approvals',
];

/** Controllers of the pre-6.1 modules converged by WP4 (the messages module is WP2's). */
const LEGACY_CONTROLLERS = new Set([
  'AuthController',
  'MfaController',
  'SessionsController',
  'PlatformOverrideController',
  'MetaController',
  'UsersController',
  'PermissionsController',
  'RolesController',
  'ApiKeysController',
  'LoginEventsController',
  'OrganizationsController',
  'OrganizationConfigurationController',
  'OrganizationDeletionController',
  'DomainsController',
  'DomainDnsController',
  'DomainRecipientsController',
  'SmtpConnectorsController',
  'DestinationProvidersController',
  'DomainDestinationsController',
  'DeliveriesController',
  'DeadLettersController',
  'ScanSettingsController',
  'ScanTrainingController',
  'ThreatHashesController',
  'ThreatIndicatorsController',
  'AttachmentRescansController',
  'BecExecutivesController',
  'BecVendorsController',
  'BecTrustedSendersController',
  'BecFeedbackController',
  'BecMessageFeedbackController',
  'DlpPoliciesController',
  'DlpExceptionsController',
  'DlpPatternsController',
  'DlpDictionariesController',
  'DlpComplianceController',
  'DlpIncidentsController',
  'DlpMessageEvidenceController',
  'DlpEvidenceController',
  'RiskProfilesController',
  'RiskDryRunController',
  'PolicyToolsController',
  'PolicyManagementController',
  'PolicySettingsController',
  'PolicyMessagesController',
  'DepartmentsController',
  'QuarantineToolsController',
  'QuarantineSelfController',
  'QuarantineApprovalsController',
  'QuarantineEntriesController',
]);

const BODY: number = RouteParamtypes.BODY;
const QUERY: number = RouteParamtypes.QUERY;

type RouteArg = { pipes?: unknown[] };
const routeArgs = (controller: object): Record<string, Record<string, RouteArg>> => {
  const out: Record<string, Record<string, RouteArg>> = {};
  const prototype = (controller as { prototype: object }).prototype;
  for (const name of Object.getOwnPropertyNames(prototype)) {
    const args = Reflect.getMetadata(ROUTE_ARGS_METADATA, controller, name) as
      Record<string, RouteArg> | undefined;
    if (args) out[name] = args;
  }
  return out;
};

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

  it('the step 5.1 risk scoring routes require exactly their permissions (R15)', () => {
    const expected: Record<string, string[]> = {
      'get /api/v1/risk-scoring/platform-profile': ['policy:read'],
      'get /api/v1/risk-scoring/profile': ['policy:read'],
      'get /api/v1/risk-scoring/profile/versions': ['policy:read'],
      'get /api/v1/risk-scoring/profile/versions/:versionId': ['policy:read'],
      'post /api/v1/risk-scoring/profile/versions': ['policy:manage'],
      'put /api/v1/risk-scoring/profile/versions/:versionId': ['policy:manage'],
      'delete /api/v1/risk-scoring/profile/versions/:versionId': ['policy:manage'],
      'post /api/v1/risk-scoring/profile/versions/:versionId/publish': ['policy:publish'],
      'post /api/v1/risk-scoring/profile/versions/:versionId/activate': ['policy:publish'],
      'post /api/v1/risk-scoring/profile/reset': ['policy:publish'],
      'post /api/v1/messages/:messageId/scans/:scanId/risk/dry-run': [
        'policy:manage',
        'message:read',
      ],
    };
    const riskRoutes = routes.filter(
      (r) => r.path.includes('/api/v1/risk-scoring/') || r.path.endsWith('/risk/dry-run'),
    );
    expect(riskRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, permissions] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions });
      expect(route?.requireMfa, key).toBe(false);
      expect(route?.userOnly, key).toBe(false);
      expect(route?.rateLimits, key).toEqual([]);
    }
  });

  it('the step 5.2 policy and department routes require exactly their permissions (P22)', () => {
    const expected: Record<string, string[]> = {
      'get /api/v1/policies/catalog': ['policy:read'],
      'get /api/v1/policies': ['policy:read'],
      'post /api/v1/policies': ['policy:manage'],
      'get /api/v1/policies/:policyId': ['policy:read'],
      'patch /api/v1/policies/:policyId': ['policy:manage'],
      'post /api/v1/policies/:policyId/disable': ['policy:publish'],
      'post /api/v1/policies/:policyId/enable': ['policy:publish'],
      'delete /api/v1/policies/:policyId': ['policy:publish'],
      'get /api/v1/policies/:policyId/versions': ['policy:read'],
      'post /api/v1/policies/:policyId/versions': ['policy:manage'],
      'get /api/v1/policies/:policyId/versions/:versionNo': ['policy:read'],
      'put /api/v1/policies/:policyId/versions/:versionNo': ['policy:manage'],
      'delete /api/v1/policies/:policyId/versions/:versionNo': ['policy:manage'],
      'post /api/v1/policies/:policyId/versions/:versionNo/publish': ['policy:publish'],
      'post /api/v1/policies/:policyId/versions/:versionNo/activate': ['policy:publish'],
      'get /api/v1/policy-settings': ['policy:read'],
      'put /api/v1/policy-settings': ['policy:publish'],
      'post /api/v1/policies/test': ['policy:manage'],
      'get /api/v1/policies/executions': ['policy:read'],
      'post /api/v1/messages/:messageId/scans/:scanId/policy/dry-run': [
        'policy:manage',
        'message:read',
      ],
      'get /api/v1/messages/:messageId/policy-evaluations': ['message:read'],
      'get /api/v1/departments': ['user:read'],
      'post /api/v1/departments': ['user:manage'],
      'get /api/v1/departments/:departmentId': ['user:read'],
      'patch /api/v1/departments/:departmentId': ['user:manage'],
      'delete /api/v1/departments/:departmentId': ['user:manage'],
      'get /api/v1/departments/:departmentId/members': ['user:read'],
      'post /api/v1/departments/:departmentId/members': ['user:manage'],
      'delete /api/v1/departments/:departmentId/members/:memberId': ['user:manage'],
    };
    const policyRoutes = routes.filter(
      (r) =>
        r.path.startsWith('/api/v1/policies') ||
        r.path.startsWith('/api/v1/policy-settings') ||
        r.path.startsWith('/api/v1/departments') ||
        r.path.endsWith('/policy/dry-run') ||
        r.path.endsWith('/policy-evaluations'),
    );
    expect(policyRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, permissions] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions });
      expect(route?.requireMfa, key).toBe(false);
      expect(route?.userOnly, key).toBe(false);
      expect(route?.rateLimits, key).toEqual([]);
    }
    // The static /policies routes are registered before /policies/:policyId.
    const order = routes.map((r) => `${r.method} ${r.path}`);
    expect(order.indexOf('get /api/v1/policies/catalog')).toBeLessThan(
      order.indexOf('get /api/v1/policies/:policyId'),
    );
  });

  it('the step 5.3 quarantine routes require exactly their permissions, users, MFA and rate limits (Q26)', () => {
    type Flags = { any?: boolean; mfa?: boolean; userOnly?: boolean; rate?: string };
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/quarantine/catalog': [['quarantine:read', 'quarantine:self'], { any: true }],
      'get /api/v1/quarantine/summary': [['quarantine:read']],
      'get /api/v1/quarantine/settings': [['quarantine:read']],
      'put /api/v1/quarantine/settings': [['settings:manage']],
      'post /api/v1/quarantine/bulk': [
        ['quarantine:release', 'quarantine:reject', 'quarantine:delete', 'quarantine:approve'],
        { any: true, rate: 'bulk' },
      ],
      'get /api/v1/quarantine/releases/:releaseId': [['quarantine:read']],
      'get /api/v1/quarantine/downloads/:token': [
        ['quarantine:download'],
        { userOnly: true, rate: 'download' },
      ],
      'get /api/v1/quarantine/entries': [['quarantine:read']],
      'post /api/v1/quarantine/entries': [['quarantine:manage']],
      'get /api/v1/quarantine/entries/:entryId': [['quarantine:read']],
      'get /api/v1/quarantine/entries/:entryId/history': [['quarantine:read']],
      'get /api/v1/quarantine/entries/:entryId/preview': [
        ['quarantine:preview'],
        { rate: 'preview' },
      ],
      'post /api/v1/quarantine/entries/:entryId/download-grants': [
        ['quarantine:download'],
        { userOnly: true, mfa: true, rate: 'download_grant' },
      ],
      'post /api/v1/quarantine/entries/:entryId/release': [['quarantine:release']],
      'post /api/v1/quarantine/entries/:entryId/request-release': [['quarantine:request_release']],
      'post /api/v1/quarantine/entries/:entryId/reject': [['quarantine:reject']],
      'post /api/v1/quarantine/entries/:entryId/delete': [['quarantine:delete']],
      'get /api/v1/quarantine/approvals': [['quarantine:read']],
      'get /api/v1/quarantine/approvals/:approvalId': [['quarantine:read']],
      'post /api/v1/quarantine/approvals/:approvalId/approve': [
        ['quarantine:approve'],
        { userOnly: true, mfa: true },
      ],
      'post /api/v1/quarantine/approvals/:approvalId/deny': [
        ['quarantine:approve'],
        { userOnly: true, mfa: true },
      ],
      'post /api/v1/quarantine/approvals/:approvalId/cancel': [
        [
          'quarantine:approve',
          'quarantine:release',
          'quarantine:request_release',
          'quarantine:self',
        ],
        { any: true },
      ],
      'get /api/v1/quarantine/me/entries': [['quarantine:self'], { userOnly: true }],
      'get /api/v1/quarantine/me/entries/:entryId': [['quarantine:self'], { userOnly: true }],
      'get /api/v1/quarantine/me/entries/:entryId/preview': [
        ['quarantine:self'],
        { userOnly: true, rate: 'preview' },
      ],
      'post /api/v1/quarantine/me/entries/:entryId/release': [
        ['quarantine:self'],
        { userOnly: true },
      ],
      'post /api/v1/quarantine/me/entries/:entryId/request-release': [
        ['quarantine:self'],
        { userOnly: true },
      ],
      'get /api/v1/quarantine/me/preferences': [['quarantine:self'], { userOnly: true }],
      'put /api/v1/quarantine/me/preferences': [['quarantine:self'], { userOnly: true }],
    };
    const quarantineRoutes = routes.filter((r) => r.path.startsWith('/api/v1/quarantine'));
    expect(quarantineRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: flags?.any ? 'any' : 'all', permissions });
      expect(route?.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route?.userOnly, key).toBe(flags?.userOnly ?? false);
      expect(route?.rateLimits, key).toEqual([]);
      expect(route?.quarantineRate, key).toBe(flags?.rate ?? null);
    }
    // The operator release of step 3.3 keeps its route and permission (it answers 409, Q30).
    expect(
      routes.find((r) => `${r.method} ${r.path}` === 'post /api/v1/messages/:messageId/release')
        ?.requirement,
    ).toEqual({ mode: 'all', permissions: ['quarantine:release'] });
  });

  it('every §3.5 legacy sensitive mutation is @Idempotent (legacy) in the sensitive class (step 6.1 D9, D10)', () => {
    for (const [key, operation] of Object.entries(LEGACY_SENSITIVE)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route, key).toBeDefined();
      expect(route?.idempotency, key).toEqual({ operation, legacy: true });
      expect(route?.rateClass, key).toBe('sensitive');
      expect(route?.returnsSecret, key).toBe(false);
    }
    // Operation names are unique (one key space per organization, bound to the operation).
    expect(new Set(Object.values(LEGACY_SENSITIVE)).size).toBe(22);
  });

  it('the already-keyed quarantine mutations are in the sensitive class, transactional (step 6.1 §3.5)', () => {
    for (const key of KEYED_QUARANTINE) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.rateClass, key).toBe('sensitive');
      // Their IdempotencyService transaction stays; no reservation interceptor on top.
      expect(route?.idempotency, key).toBeNull();
    }
    expect(KEYED_QUARANTINE).toHaveLength(11);
  });

  it('the secret-bearing routes are @ReturnsSecret, sensitive and never idempotency-stored (D9)', () => {
    for (const key of SECRET_BEARING) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.returnsSecret, key).toBe(true);
      expect(route?.idempotency, key).toBeNull();
      expect(route?.rateClass, key).toBe('sensitive');
    }
    // Step 6.2 (ADR-0057): the two webhook secret routes return a secret with a transactional,
    // redacted-replay Idempotency-Key; every other secret-bearing route keeps D9.
    expect(
      routes
        .filter((r) => r.returnsSecret && !r.secretRedactedReplay)
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual([...SECRET_BEARING].sort());
    expect(
      routes
        .filter((r) => r.secretRedactedReplay)
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual(['post /api/v1/webhooks', 'post /api/v1/webhooks/:webhookId/rotate-secret']);
    expect(routes.filter((r) => r.secretRedactedReplay && !r.returnsSecret)).toEqual([]);
    expect(routes.filter((r) => r.returnsSecret && r.idempotency !== null)).toEqual([]);
  });

  it('the policy test and the two dry-runs are in the expensive class (D8)', () => {
    for (const key of EXPENSIVE_LEGACY) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.rateClass, key).toBe('expensive');
      expect(route?.idempotency, key).toBeNull();
    }
  });

  it('GET /meta is limited per IP (120 per minute, D8)', () => {
    const meta = routes.find((r) => `${r.method} ${r.path}` === 'get /api/v1/meta');
    expect(meta?.rateLimits).toEqual([{ bucket: 'meta', limit: 120, windowSeconds: 60, by: 'ip' }]);
  });

  it('every legacy cursor list declares the v0 encoding (D3)', () => {
    for (const key of V0_LISTS) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.cursor, key).toBe('v0');
    }
  });

  it('every body and query schema of the legacy routes is strict at every object node (D1)', () => {
    const offenders: string[] = [];
    let checked = 0;
    for (const wrapper of app.get(DiscoveryService).getControllers()) {
      const controller = wrapper.metatype as (new (...args: never[]) => object) | null;
      if (!controller || !wrapper.instance) continue;
      for (const [name, args] of Object.entries(routeArgs(controller))) {
        const route = routes.find((r) => r.name === `${controller.name}.${name}`);
        if (!route || !LEGACY_CONTROLLERS.has(controller.name)) continue;
        for (const [key, arg] of Object.entries(args)) {
          const type = Number(key.split(':')[0]);
          if (type !== BODY && type !== QUERY) continue;
          const schemas = (arg.pipes ?? []).flatMap((pipe) =>
            pipe instanceof ZodValidationPipe
              ? [(pipe as unknown as { schema: z.ZodType }).schema]
              : [],
          );
          // `@Body() body: unknown` is parsed (strictly) in the service: quarantine bulk only.
          if (
            schemas.length === 0 &&
            `${controller.name}.${name}` !== 'QuarantineToolsController.bulk'
          ) {
            offenders.push(`${route.method} ${route.path}: no schema`);
          }
          for (const schema of schemas) {
            checked += 1;
            for (const path of isStrictRequestSchema(schema)) {
              offenders.push(
                `${route.method} ${route.path} ${type === BODY ? 'body' : 'query'} ${path}`,
              );
            }
          }
        }
      }
    }
    expect(offenders).toEqual([]);
    expect(checked).toBeGreaterThan(130);
    expect(isStrictRequestSchema(BulkBodySchema)).toEqual([]);
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
