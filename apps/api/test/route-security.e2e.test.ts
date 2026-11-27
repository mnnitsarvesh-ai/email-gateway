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
  // Step 7.3 §4.3: the sample dry-run.
  'post /api/v1/policies/dry-run',
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
        // Step API-1 D12.4: the Microsoft Graph notification callbacks.
        'post /api/v1/provider-notifications/graph',
        'post /api/v1/provider-notifications/graph/lifecycle',
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
      'get /api/v1/bec/trusted-senders/:id': ['bec:read'],
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
      'get /api/v1/bec/suppressions/:id': ['bec:read'],
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
      'get /api/v1/dlp/exceptions/:id': ['dlp:read'],
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

  it('the step 5.2 and 7.3 policy and department routes require exactly their permissions (P22)', () => {
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
      // Step 7.3 §4.2, §4.3 (no new permission).
      'post /api/v1/policies/validate': ['policy:manage'],
      'post /api/v1/policies/dry-run': ['policy:manage', 'message:read'],
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
    // The static /policies routes are registered before every /policies/:policyId route.
    const order = routes.map((r) => `${r.method} ${r.path}`);
    const firstParam = order.findIndex((k) => k.includes(' /api/v1/policies/:policyId'));
    expect(firstParam).toBeGreaterThan(0);
    for (const key of [
      'get /api/v1/policies/catalog',
      'post /api/v1/policies/test',
      'get /api/v1/policies/executions',
      'post /api/v1/policies/validate',
      'post /api/v1/policies/dry-run',
    ]) {
      expect(order.indexOf(key), key).toBeGreaterThanOrEqual(0);
      expect(order.indexOf(key), key).toBeLessThan(firstParam);
    }
  });

  it('the step 7.3 policy builder routes: classes, the sample limit, no key, users and API keys (§4.2, §4.3)', () => {
    const validate = routes.find(
      (r) => `${r.method} ${r.path}` === 'post /api/v1/policies/validate',
    );
    expect(validate?.rateClass).toBeNull();
    expect(validate?.policySampleRate).toBeNull();
    expect(validate?.idempotency).toBeNull();
    const sample = routes.find((r) => `${r.method} ${r.path}` === 'post /api/v1/policies/dry-run');
    expect(sample?.rateClass).toBe('expensive');
    expect(sample?.policySampleRate).toBe('policy-sample-dry-run');
    expect(sample?.idempotency).toBeNull();
    for (const route of [validate, sample]) {
      expect(route?.returnsSecret).toBe(false);
      expect(route?.userOnly).toBe(false);
      expect(route?.requireMfa).toBe(false);
      expect(route?.quarantineRate).toBeNull();
      expect(route?.revealRate).toBeNull();
      expect(route?.cursor).toBeNull();
    }
    // Only the sample dry-run carries the sample limit.
    expect(
      routes.filter((r) => r.policySampleRate !== null).map((r) => `${r.method} ${r.path}`),
    ).toEqual(['post /api/v1/policies/dry-run']);
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

  it('the step 7.2 saved views routes require message:read, users only, no class or idempotency (§3.3)', () => {
    const expected = [
      'get /api/v1/saved-views',
      'post /api/v1/saved-views',
      'get /api/v1/saved-views/:viewId',
      'put /api/v1/saved-views/:viewId',
      'delete /api/v1/saved-views/:viewId',
    ];
    expect(
      routes
        .filter((r) => r.path.startsWith('/api/v1/saved-views'))
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual([...expected].sort());
    for (const key of expected) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: ['message:read'] });
      expect(route?.userOnly, key).toBe(true);
      expect(route?.requireMfa, key).toBe(false);
      expect(route?.idempotency, key).toBeNull();
      expect(route?.returnsSecret, key).toBe(false);
    }
    // GET /messages keeps message:read at the route; its filter-level permissions are checked
    // in the service (403 message_filter_forbidden, §2 E2).
    expect(
      routes.find((r) => `${r.method} ${r.path}` === 'get /api/v1/messages')?.requirement,
    ).toEqual({ mode: 'all', permissions: ['message:read'] });
  });

  it('the step 7.2 WP2 headers and reveal routes: exact permission, API keys allowed, the reveal limit, no key (§2 E6, E7)', () => {
    const expected: Record<string, [string, string | null]> = {
      'get /api/v1/messages/:messageId/headers': ['message:read', null],
      'post /api/v1/messages/reveal': ['message:reveal', 'message-reveal'],
      'post /api/v1/messages/:messageId/reveal': ['message:reveal', 'message-reveal'],
    };
    for (const [key, [permission, revealRate]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
      // User tokens and API keys (no user-only flag), no MFA step-up.
      expect(route?.userOnly, key).toBe(false);
      expect(route?.requireMfa, key).toBe(false);
      // No Idempotency-Key: a read with an audit side effect, not a §3.5 sensitive mutation.
      expect(route?.idempotency, key).toBeNull();
      expect(route?.rateClass, key).toBeNull();
      expect(route?.returnsSecret, key).toBe(false);
      expect(route?.rateLimits, key).toEqual([]);
      expect(route?.quarantineRate, key).toBeNull();
      expect(route?.revealRate, key).toBe(revealRate);
      expect(route?.cursor, key).toBeNull();
    }
    // Only the two reveal operations carry the reveal limit.
    expect(
      routes
        .filter((r) => r.revealRate !== null)
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual(['post /api/v1/messages/:messageId/reveal', 'post /api/v1/messages/reveal']);
  });

  it('the step 8.1 archive, legal hold and eDiscovery routes: exact permissions, MFA, users, limits, classes and keys (§4.4, A20)', () => {
    type Flags = {
      any?: boolean;
      mfa?: boolean;
      user?: boolean;
      rate?: string;
      cls?: string;
      key?: string;
      cursor?: boolean;
    };
    const R = 'archive:read';
    const M = 'archive:manage';
    const E = 'ediscovery:manage';
    // Step 8.6 D11/D12 (ADR-0089): the Journaling area and the record-route re-scope.
    const JR = 'journal:read';
    const JM = 'journal:manage';
    const S = 'archive:search';
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/archive/settings': [[R, JR], { any: true }],
      'put /api/v1/archive/settings': [
        [JM, M],
        { any: true, mfa: true, user: true, cls: 'sensitive', key: 'archive.settings_update' },
      ],
      'get /api/v1/archive/retention-policies': [[R], { cursor: true }],
      'post /api/v1/archive/retention-policies': [
        [M],
        { cls: 'sensitive', key: 'archive.retention_policy_create' },
      ],
      'get /api/v1/archive/retention-policies/:policyId': [[R]],
      'put /api/v1/archive/retention-policies/:policyId': [
        [M],
        { cls: 'sensitive', key: 'archive.retention_policy_update' },
      ],
      'delete /api/v1/archive/retention-policies/:policyId': [
        [M],
        { cls: 'sensitive', key: 'archive.retention_policy_delete' },
      ],
      'get /api/v1/archive/keys': [[R], { cursor: true }],
      'post /api/v1/archive/keys/rotate': [
        [M],
        { mfa: true, user: true, cls: 'sensitive', key: 'archive.key_rotate' },
      ],
      'get /api/v1/archive/status': [[R, JR], { any: true }],
      'get /api/v1/archive/capture-issues': [[JM, M], { any: true, cursor: true }],
      // Step AI-5 D8: the single read keeps the list's permissions and flags (API keys allowed).
      'get /api/v1/archive/capture-issues/:messageId': [[JM, M], { any: true }],
      'post /api/v1/archive/capture-issues/:messageId/retry': [
        [JM, M],
        { any: true, cls: 'sensitive', key: 'archive.capture_retry' },
      ],
      'get /api/v1/archive/disposals': [[R], { cursor: true }],
      'get /api/v1/archive/export-signing-keys': [[R]],
      'get /api/v1/archive/messages': [['archive:search'], { cls: 'expensive', cursor: true }],
      'get /api/v1/archive/messages/:messageId': [[S]],
      'get /api/v1/archive/messages/:messageId/journal': [[S]],
      'get /api/v1/archive/messages/:messageId/security': [[S]],
      'post /api/v1/archive/messages/:messageId/reveal': [
        [S, 'message:reveal'],
        { rate: 'reveal' },
      ],
      'get /api/v1/archive/messages/:messageId/preview': [
        ['archive:retrieve'],
        { mfa: true, user: true, rate: 'preview' },
      ],
      'post /api/v1/archive/messages/:messageId/download-grants': [
        ['archive:retrieve'],
        { mfa: true, user: true, rate: 'download_grant' },
      ],
      'get /api/v1/archive/downloads/:token': [
        ['archive:retrieve', 'archive:export'],
        { any: true, user: true, rate: 'download' },
      ],
      'post /api/v1/archive/messages/:messageId/dispose': [
        [M],
        { mfa: true, user: true, cls: 'sensitive', key: 'archive.dispose' },
      ],
      'get /api/v1/legal-holds': [['archive:legal_hold', E], { any: true, cursor: true }],
      'get /api/v1/legal-holds/:holdId': [['archive:legal_hold', E], { any: true }],
      'post /api/v1/legal-holds/:holdId/release': [
        ['archive:legal_hold'],
        { mfa: true, user: true, cls: 'sensitive', key: 'legal_hold.release' },
      ],
      'post /api/v1/ediscovery/cases/:caseId/holds': [
        ['archive:legal_hold', E],
        { mfa: true, user: true, cls: 'sensitive', key: 'legal_hold.create' },
      ],
      'get /api/v1/ediscovery/cases': [[E], { cursor: true }],
      'post /api/v1/ediscovery/cases': [[E], { cls: 'sensitive', key: 'ediscovery.case_create' }],
      'get /api/v1/ediscovery/cases/:caseId': [[E]],
      'patch /api/v1/ediscovery/cases/:caseId': [
        [E],
        { cls: 'sensitive', key: 'ediscovery.case_update' },
      ],
      'post /api/v1/ediscovery/cases/:caseId/close': [
        [E],
        { mfa: true, user: true, cls: 'sensitive', key: 'ediscovery.case_close' },
      ],
      'post /api/v1/ediscovery/cases/:caseId/searches': [
        [E, 'archive:search'],
        { cls: 'expensive', key: 'ediscovery.search_create' },
      ],
      'get /api/v1/ediscovery/cases/:caseId/searches': [[E], { cursor: true }],
      'get /api/v1/ediscovery/cases/:caseId/searches/:searchId': [[E]],
      'get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits': [[E], { cursor: true }],
      'post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review': [
        [E],
        { user: true, cls: 'sensitive', key: 'ediscovery.review' },
      ],
      'post /api/v1/ediscovery/cases/:caseId/exports': [
        [E, 'archive:export'],
        { cls: 'expensive', key: 'ediscovery.export_create' },
      ],
      'get /api/v1/ediscovery/cases/:caseId/exports': [[E], { cursor: true }],
      'get /api/v1/ediscovery/cases/:caseId/exports/:exportId': [[E]],
      'post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants': [
        [E, 'archive:export'],
        { mfa: true, user: true, rate: 'download_grant' },
      ],
    };
    const archiveRoutes = routes.filter((r) =>
      /^\/api\/v1\/(archive|legal-holds|ediscovery)(\/|$)/.test(r.path),
    );
    expect(archiveRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    // 41 of step 8.1 plus the capture-issue read of step AI-5 (D8).
    expect(archiveRoutes).toHaveLength(42);
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: flags?.any ? 'any' : 'all', permissions });
      expect(route.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route.userOnly, key).toBe(flags?.user ?? false);
      expect(route.archiveRate, key).toBe(flags?.rate ?? null);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      // Transactional keys are not the reservation interceptor (`@Idempotent`).
      expect(route.idempotency, key).toBeNull();
      // Grants and the reveal carry no key (secret-bearing / values never stored).
      expect(route.returnsSecret, key).toBe(false);
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
  });

  it('the step 8.6 journaling routes: exact permissions, MFA, users, classes, keys, secrets and cursors (D11)', () => {
    type Flags = { any?: boolean; mfa?: boolean; cls?: string; secret?: boolean; cursor?: boolean };
    const JR = 'journal:read';
    const JM = 'journal:manage';
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/journaling/settings': [[JR, 'archive:read'], { any: true }],
      'put /api/v1/journaling/settings': [[JM], { mfa: true, cls: 'sensitive' }],
      'get /api/v1/journaling/status': [[JR]],
      'get /api/v1/journaling/intake-sources': [[JR], { cursor: true }],
      'post /api/v1/journaling/intake-sources': [
        [JM],
        { mfa: true, cls: 'sensitive', secret: true },
      ],
      'get /api/v1/journaling/intake-sources/:sourceId': [[JR]],
      'patch /api/v1/journaling/intake-sources/:sourceId': [[JM], { mfa: true, cls: 'sensitive' }],
      'delete /api/v1/journaling/intake-sources/:sourceId': [[JM], { mfa: true, cls: 'sensitive' }],
      'post /api/v1/journaling/intake-sources/:sourceId/rotate-address': [
        [JM],
        { mfa: true, cls: 'sensitive', secret: true },
      ],
      'get /api/v1/journaling/intake-sources/:sourceId/wizard': [[JR]],
      'get /api/v1/journaling/intake-sources/:sourceId/setup-guide': [[JR]],
      'post /api/v1/journaling/intake-sources/:sourceId/attestations': [
        [JM],
        { mfa: true, cls: 'sensitive' },
      ],
    };
    const journaling = routes.filter((r) => /^\/api\/v1\/journaling(\/|$)/.test(r.path));
    expect(journaling.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: flags?.any ? 'any' : 'all', permissions });
      expect(route.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route.userOnly, key).toBe(flags?.mfa ?? false);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      expect(route.idempotency, key).toBeNull();
      expect(route.returnsSecret, key).toBe(flags?.secret ?? false);
      expect(route.secretRedactedReplay, key).toBe(flags?.secret ?? false);
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
  });

  it('the step API-1 protection-mode and API-mode routes (+ step API-2 remediation routes): exact permissions, keys, classes, cursors; the callbacks are public (D12, R13)', () => {
    type Flags = { any?: boolean; cls?: string; cursor?: boolean };
    const READ = 'remediation:read';
    const WRITE = 'remediation:write';
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/organizations/:id/protection-mode': [
        ['organization:read', 'platform:organizations'],
        { any: true },
      ],
      'put /api/v1/organizations/:id/protection-mode': [
        ['organization:manage', 'platform:organizations'],
        { any: true, cls: 'sensitive' },
      ],
      'put /api/v1/domains/:domainId/protection-mode': [['domain:manage'], { cls: 'sensitive' }],
      'get /api/v1/api-mode/overview': [[READ]],
      'get /api/v1/api-mode/connections': [[READ]],
      'get /api/v1/api-mode/connections/:connectionId': [[READ]],
      'get /api/v1/api-mode/connections/:connectionId/setup-guide': [[READ]],
      'put /api/v1/api-mode/connections/:connectionId/settings': [[WRITE], { cls: 'sensitive' }],
      'post /api/v1/api-mode/connections/:connectionId/inventory-sync': [
        [WRITE],
        { cls: 'sensitive' },
      ],
      'get /api/v1/api-mode/mailboxes': [[READ], { cursor: true }],
      'get /api/v1/api-mode/mailboxes/:mailboxId': [[READ]],
      'post /api/v1/api-mode/mailboxes/:mailboxId/resync': [[WRITE], { cls: 'sensitive' }],
      'get /api/v1/api-mode/detections': [[READ], { cursor: true }],
      'get /api/v1/api-mode/detections/:detectionId': [[READ]],
      // Step API-2 R13 (docs/plan/steps/36-api-mode-remediation.md): the remediation routes. The
      // restore additionally checks `quarantine:release` in the service when it delegates.
      'get /api/v1/api-mode/remediation-policy': [[READ]],
      'put /api/v1/api-mode/remediation-policy': [[WRITE], { cls: 'sensitive' }],
      'put /api/v1/api-mode/remediation-policy/domains/:domainId': [[WRITE], { cls: 'sensitive' }],
      'delete /api/v1/api-mode/remediation-policy/domains/:domainId': [
        [WRITE],
        { cls: 'sensitive' },
      ],
      'get /api/v1/api-mode/remediations': [[READ], { cursor: true }],
      'get /api/v1/api-mode/remediations/:remediationId': [[READ]],
      'post /api/v1/api-mode/remediations/:remediationId/retry': [[WRITE], { cls: 'sensitive' }],
      'post /api/v1/api-mode/detections/:detectionId/remediate': [[WRITE], { cls: 'sensitive' }],
      'post /api/v1/api-mode/detections/:detectionId/restore': [[WRITE], { cls: 'sensitive' }],
    };
    const apiMode = routes.filter(
      (r) => /^\/api\/v1\/api-mode(\/|$)/.test(r.path) || /\/protection-mode$/.test(r.path),
    );
    expect(apiMode.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: flags?.any ? 'any' : 'all', permissions });
      expect(route.requireMfa, key).toBe(false);
      expect(route.userOnly, key).toBe(false);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      // Transactional keys (IdempotencyService.execute), never the reservation interceptor.
      expect(route.idempotency, key).toBeNull();
      expect(route.returnsSecret, key).toBe(false);
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
    for (const key of [
      'post /api/v1/provider-notifications/graph',
      'post /api/v1/provider-notifications/graph/lifecycle',
    ]) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(true);
      expect(route.requirement, key).toBeUndefined();
    }
  });

  it('the step AI-1, AI-2, AI-R and AI-6 assistant routes: exact permissions, users only, MFA only for the tenant key, classes, no keys, no secrets, v1 cursors (§4.1)', () => {
    type Flags = { cls?: string; cursor?: boolean; mfa?: boolean };
    const USE = 'assistant:use';
    const CONFIGURE = 'assistant:configure';
    const AUDIT = 'audit:read';
    const expected: Record<string, [string, Flags?]> = {
      'get /api/v1/assistant/status': [USE],
      'get /api/v1/assistant/settings': [CONFIGURE],
      'put /api/v1/assistant/settings': [CONFIGURE, { cls: 'sensitive' }],
      'get /api/v1/assistant/usage': [CONFIGURE],
      'get /api/v1/assistant/tools': [USE],
      'get /api/v1/assistant/conversations': [USE, { cursor: true }],
      'post /api/v1/assistant/conversations': [USE],
      'get /api/v1/assistant/conversations/:conversationId': [USE],
      'patch /api/v1/assistant/conversations/:conversationId': [USE],
      'delete /api/v1/assistant/conversations/:conversationId': [USE],
      'get /api/v1/assistant/conversations/:conversationId/messages': [USE, { cursor: true }],
      'post /api/v1/assistant/conversations/:conversationId/turns': [USE, { cls: 'expensive' }],
      'post /api/v1/assistant/turns/:turnId/cancel': [USE],
      'get /api/v1/assistant/executions/:executionId': [USE],
      'post /api/v1/assistant/executions/:executionId/more': [USE, { cls: 'expensive' }],
      'get /api/v1/assistant/confirmations/:confirmationId': [USE],
      'post /api/v1/assistant/confirmations/:confirmationId/confirm': [USE, { cls: 'sensitive' }],
      'post /api/v1/assistant/confirmations/:confirmationId/cancel': [USE, { cls: 'sensitive' }],
      // Step AI-R §4.1.
      'get /api/v1/assistant/reports/:reportId': [USE],
      // Step AI-6 §4.1 (contracts §35.6): the tenant key needs an MFA session (D7).
      'put /api/v1/assistant/settings/provider-key': [CONFIGURE, { cls: 'sensitive', mfa: true }],
      'delete /api/v1/assistant/settings/provider-key': [
        CONFIGURE,
        { cls: 'sensitive', mfa: true },
      ],
      'post /api/v1/assistant/settings/provider-key/validate': [
        CONFIGURE,
        { cls: 'sensitive', mfa: true },
      ],
      'get /api/v1/assistant/search': [USE, { cls: 'expensive', cursor: true }],
      'put /api/v1/assistant/messages/:messageId/feedback': [USE],
      'delete /api/v1/assistant/messages/:messageId/feedback': [USE],
      'get /api/v1/assistant/admin/usage/users': [CONFIGURE, { cursor: true }],
      'get /api/v1/assistant/admin/feedback': [CONFIGURE, { cursor: true }],
      'get /api/v1/assistant/admin/conversations': [AUDIT, { cursor: true }],
      'get /api/v1/assistant/admin/conversations/:conversationId': [AUDIT],
      'get /api/v1/assistant/admin/executions': [AUDIT, { cursor: true }],
    };
    const assistant = routes.filter((r) => /^\/api\/v1\/assistant(\/|$)/.test(r.path));
    expect(assistant.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    for (const [key, [permission, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
      // API keys never chat (D1, §4.1); MFA is the organization's login policy, not per route,
      // except for the write-only tenant key of step AI-6 (D7).
      expect(route.userOnly, key).toBe(true);
      expect(route.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      expect(route.idempotency, key).toBeNull();
      expect(route.returnsSecret, key).toBe(false);
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
  });

  it('the step 8.4 account takeover and incident routes: exact permissions incl. the registry lists, users, MFA, classes, keys and cursors (§5.1, §5.2)', () => {
    type Flags = {
      any?: boolean;
      mfa?: boolean;
      user?: boolean;
      cls?: string;
      key?: string;
      cursor?: boolean;
    };
    const R = 'ato:read';
    const M = 'ato:manage';
    const P = 'ato:respond';
    const C = 'ato:configure';
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/ato/overview': [[R], { cls: 'expensive' }],
      'get /api/v1/ato/attention': [[R]],
      'get /api/v1/ato/accounts': [[R], { cursor: true }],
      'get /api/v1/ato/accounts/:accountId': [[R]],
      'patch /api/v1/ato/accounts/:accountId': [
        [M],
        { user: true, cls: 'sensitive', key: 'ato.account_update' },
      ],
      'get /api/v1/ato/accounts/:accountId/signals': [[R], { cursor: true }],
      'get /api/v1/ato/accounts/:accountId/auth-events': [[R], { cursor: true }],
      'get /api/v1/ato/accounts/:accountId/activity': [[R]],
      'get /api/v1/ato/accounts/:accountId/score-history': [[R], { cursor: true }],
      'put /api/v1/ato/accounts/:accountId/override': [
        [M],
        { user: true, cls: 'sensitive', key: 'ato.override_set' },
      ],
      'post /api/v1/ato/accounts/:accountId/override/clear': [
        [M],
        { user: true, cls: 'sensitive', key: 'ato.override_clear' },
      ],
      'post /api/v1/ato/accounts/:accountId/trusted-contexts': [
        [M],
        { user: true, cls: 'sensitive', key: 'ato.trusted_context_add' },
      ],
      'delete /api/v1/ato/accounts/:accountId/trusted-contexts/:contextId': [
        [M],
        { user: true, cls: 'sensitive', key: 'ato.trusted_context_remove' },
      ],
      'get /api/v1/ato/incidents/:incidentId/signals': [[R], { cursor: true }],
      'get /api/v1/ato/incidents/:incidentId/auth-events': [[R], { cursor: true }],
      'post /api/v1/ato/incidents/:incidentId/responses': [
        [P],
        { cls: 'sensitive', key: 'ato.response_request' },
      ],
      'get /api/v1/ato/responses': [[R], { cursor: true }],
      'get /api/v1/ato/responses/:responseId': [[R]],
      'post /api/v1/ato/responses/:responseId/approve': [
        [P],
        { user: true, mfa: true, cls: 'sensitive', key: 'ato.response_approve' },
      ],
      'post /api/v1/ato/responses/:responseId/reject': [
        [P],
        { user: true, cls: 'sensitive', key: 'ato.response_reject' },
      ],
      'post /api/v1/ato/responses/:responseId/cancel': [
        [P],
        { cls: 'sensitive', key: 'ato.response_cancel' },
      ],
      'post /api/v1/ato/responses/:responseId/rollback': [
        [P],
        { user: true, mfa: true, cls: 'sensitive', key: 'ato.response_rollback' },
      ],
      'get /api/v1/ato/restrictions': [[R], { cursor: true }],
      'get /api/v1/ato/settings': [[R]],
      'put /api/v1/ato/settings': [
        [C],
        { user: true, cls: 'sensitive', key: 'ato.settings_update' },
      ],
      'get /api/v1/ato/rules': [[R]],
      // §5.2: RequireAnyPermission lists derived from the category registry (8.4: exactly ATO's).
      'get /api/v1/incidents': [[R], { any: true, cursor: true }],
      'post /api/v1/incidents': [[M], { any: true, cls: 'sensitive', key: 'incident.create' }],
      'get /api/v1/incidents/:incidentId': [[R], { any: true }],
      'patch /api/v1/incidents/:incidentId': [
        [M],
        { any: true, cls: 'sensitive', key: 'incident.update' },
      ],
      'post /api/v1/incidents/:incidentId/notes': [
        [M],
        { any: true, cls: 'sensitive', key: 'incident.note_add' },
      ],
      'get /api/v1/incidents/:incidentId/timeline': [[R], { any: true, cursor: true }],
      'get /api/v1/incidents/:incidentId/messages': [[R], { any: true, cursor: true }],
      'get /api/v1/incidents/:incidentId/report': [[R], { any: true, cls: 'expensive' }],
    };
    // Step 8.5's identity-provider and mailbox state routes have their own block below.
    const stepRoutes = routes.filter(
      (r) =>
        /^\/api\/v1\/(ato|incidents)(\/|$)/.test(r.path) &&
        !r.path.startsWith('/api/v1/ato/providers') &&
        !r.path.includes('/mailbox-state'),
    );
    expect(stepRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    expect(stepRoutes).toHaveLength(34);
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: flags?.any ? 'any' : 'all', permissions });
      expect(route.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route.userOnly, key).toBe(flags?.user ?? false);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      // Transactional keys (IdempotencyService), never the reservation interceptor.
      expect(route.idempotency, key).toBeNull();
      expect(route.returnsSecret, key).toBe(false);
      expect(route.rateLimits, key).toEqual([]);
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
  });

  it('the step 8.5 identity-provider and mailbox state routes: exact permissions, users, MFA, classes and keys; no tenant header (§6)', () => {
    type Flags = { mfa?: boolean; user?: boolean; key?: string };
    const R = 'ato:read';
    const M = 'ato:manage';
    const C = 'ato:configure';
    const P = '/api/v1/ato/providers';
    const expected: Record<string, [string[], Flags?]> = {
      [`get ${P}`]: [[R]],
      [`get ${P}/requirements`]: [[R]],
      [`get ${P}/connections`]: [[C]],
      [`post ${P}`]: [[C], { user: true, mfa: true, key: 'ato.provider_create' }],
      [`get ${P}/:integrationId`]: [[R]],
      [`patch ${P}/:integrationId`]: [[C], { user: true, mfa: true, key: 'ato.provider_update' }],
      [`post ${P}/:integrationId/pause`]: [[C], { user: true, key: 'ato.provider_pause' }],
      [`post ${P}/:integrationId/resume`]: [[C], { user: true, key: 'ato.provider_resume' }],
      [`post ${P}/:integrationId/health-check`]: [[C], { key: 'ato.provider_health_check' }],
      [`post ${P}/:integrationId/backfill`]: [[C], { user: true, key: 'ato.provider_backfill' }],
      [`delete ${P}/:integrationId`]: [[C], { user: true, mfa: true, key: 'ato.provider_remove' }],
      'get /api/v1/ato/accounts/:accountId/mailbox-state': [[R]],
      'post /api/v1/ato/accounts/:accountId/mailbox-state/refresh': [
        [M],
        { key: 'ato.mailbox_refresh' },
      ],
    };
    const stepRoutes = routes.filter(
      (r) => r.path.startsWith(P) || r.path.includes('/mailbox-state'),
    );
    expect(stepRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    expect(stepRoutes).toHaveLength(13);
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      // No new permission: the four 8.4 `ato:*` keys only.
      expect(route.requirement, key).toEqual({ mode: 'all', permissions });
      expect(route.requireMfa, key).toBe(flags?.mfa ?? false);
      expect(route.userOnly, key).toBe(flags?.user ?? false);
      // Every mutation is keyed (transactional) and `sensitive`; reads have no class.
      expect(route.rateClass, key).toBe(flags?.key ? 'sensitive' : null);
      expect(route.idempotency, key).toBeNull();
      expect(route.returnsSecret, key).toBe(false);
      expect(route.rateLimits, key).toEqual([]);
      expect(route.cursor, key).toBeNull();
    }
  });

  it('the step 8.2 provider-connection routes: exact permissions, limits, classes, keys and cursors (§5.2, D16, D17)', () => {
    type Flags = {
      cls?: string;
      secret?: boolean;
      rate?: string;
      limit?: number;
      cursor?: boolean;
    };
    const R = 'integration:read';
    const M = 'integration:manage';
    const P = '/api/v1/provider-connections';
    const expected: Record<string, [string[], Flags?]> = {
      'get /api/v1/provider-integrations/catalog': [[R]],
      [`get ${P}`]: [[R], { cursor: true }],
      [`post ${P}`]: [[M]],
      [`get ${P}/:id`]: [[R]],
      [`patch ${P}/:id`]: [[M]],
      [`delete ${P}/:id`]: [[M, 'connector:manage'], { cls: 'sensitive' }],
      [`get ${P}/:id/wizard`]: [[R]],
      [`post ${P}/:id/grants`]: [[M], { cls: 'sensitive', secret: true }],
      [`post ${P}/consent/complete`]: [[M], { cls: 'sensitive' }],
      [`put ${P}/:id/grants/:profile/credentials`]: [[M], { cls: 'sensitive' }],
      [`post ${P}/:id/grants/:profile/verify`]: [[M], { cls: 'sensitive' }],
      [`delete ${P}/:id/grants/:profile`]: [[M], { cls: 'sensitive' }],
      [`get ${P}/:id/domains`]: [[R]],
      [`put ${P}/:id/domains`]: [[M]],
      [`post ${P}/:id/mail-flow/preview`]: [[M]],
      [`post ${P}/:id/mail-flow/apply`]: [[M], { limit: 30 }],
      [`get ${P}/:id/mail-flow`]: [[R]],
      [`post ${P}/:id/attestations`]: [[M]],
      [`post ${P}/:id/validations`]: [[M], { cls: 'sensitive', secret: true, rate: 'validation' }],
      [`get ${P}/:id/validations`]: [[R], { cursor: true }],
      [`get ${P}/:id/validations/:runId`]: [[R]],
      [`get ${P}/:id/health`]: [[R]],
      [`post ${P}/:id/health/check`]: [[M], { rate: 'health_check' }],
      [`get ${P}/:id/setup-guide`]: [[R]],
    };
    const providerRoutes = routes.filter((r) =>
      /^\/api\/v1\/provider-(connections|integrations)(\/|$)/.test(r.path),
    );
    expect(providerRoutes.map((r) => `${r.method} ${r.path}`).sort()).toEqual(
      Object.keys(expected).sort(),
    );
    expect(providerRoutes).toHaveLength(24);
    for (const [key, [permissions, flags]] of Object.entries(expected)) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key)!;
      expect(route.isPublic, key).toBe(false);
      expect(route.requirement, key).toEqual({ mode: 'all', permissions });
      // No step-up MFA and API keys allowed (the consent routes refuse API keys in the service).
      expect(route.requireMfa, key).toBe(false);
      expect(route.userOnly, key).toBe(false);
      expect(route.rateClass, key).toBe(flags?.cls ?? null);
      expect(route.returnsSecret, key).toBe(flags?.secret ?? false);
      expect(route.secretRedactedReplay, key).toBe(flags?.secret ?? false);
      expect(route.providerRate, key).toBe(flags?.rate ?? null);
      expect(
        route.rateLimits.map((l) => l.limit),
        key,
      ).toEqual(flags?.limit === undefined ? [] : [flags.limit]);
      // Transactional keys (IdempotencyService), never the reservation interceptor.
      expect(route.idempotency, key).toBeNull();
      expect(route.cursor, key).toBe(flags?.cursor ? 'v1' : null);
    }
    // Only these two routes carry the per-connection limits.
    expect(
      routes
        .filter((r) => r.providerRate !== null)
        .map((r) => `${r.method} ${r.path}`)
        .sort(),
    ).toEqual([`post ${P}/:id/health/check`, `post ${P}/:id/validations`]);
  });

  it('the step 8.2 changes of existing routes: provider_relay connectors and shared ranges (§5.3)', () => {
    // Unchanged authorization of the connector and domain routes that gained the coded refusals.
    for (const key of [
      'post /api/v1/smtp-connectors',
      'patch /api/v1/smtp-connectors/:id',
      'post /api/v1/smtp-connectors/:id/rotate-secret',
      'delete /api/v1/smtp-connectors/:id',
    ]) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: ['connector:manage'] });
    }
    expect(
      routes.find((r) => `${r.method} ${r.path}` === 'post /api/v1/domains')?.requirement,
    ).toEqual({ mode: 'all', permissions: ['domain:manage'] });
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
    ).toEqual(
      [
        'post /api/v1/webhooks',
        'post /api/v1/webhooks/:webhookId/rotate-secret',
        // Step 8.2: the consent URL and the probe address (ADR-0057 redacted replay).
        'post /api/v1/provider-connections/:id/grants',
        'post /api/v1/provider-connections/:id/validations',
        // Step 8.6: the intake address shown once on creation and rotation.
        'post /api/v1/journaling/intake-sources',
        'post /api/v1/journaling/intake-sources/:sourceId/rotate-address',
      ].sort(),
    );
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

  it('the step AI-3 API key read: apikey:read, API keys may call it, no MFA, no secret, no cursor (D8)', () => {
    const route = routes.find((r) => `${r.method} ${r.path}` === 'get /api/v1/api-keys/:id');
    expect(route?.isPublic).toBe(false);
    expect(route?.requirement).toEqual({ mode: 'all', permissions: ['apikey:read'] });
    expect(route?.requireMfa).toBe(false);
    expect(route?.userOnly).toBe(false);
    expect(route?.returnsSecret).toBe(false);
    expect(route?.rateClass).toBeNull();
    expect(route?.cursor ?? null).toBeNull();
    // The list keeps its pre-6.1 shape (v0 cursor, same permission).
    const list = routes.find((r) => `${r.method} ${r.path}` === 'get /api/v1/api-keys');
    expect(list?.requirement).toEqual(route?.requirement);
    expect(list?.userOnly).toBe(false);
  });

  it('the step AI-4 single-item reads keep the flags of their lists and are no cursor lists (D8)', () => {
    const pairs: Array<[string, string, string]> = [
      ['get /api/v1/bec/trusted-senders/:id', 'get /api/v1/bec/trusted-senders', 'bec:read'],
      ['get /api/v1/bec/suppressions/:id', 'get /api/v1/bec/suppressions', 'bec:read'],
      ['get /api/v1/dlp/exceptions/:id', 'get /api/v1/dlp/exceptions', 'dlp:read'],
      [
        'get /api/v1/platform/threat-indicators/:id',
        'get /api/v1/platform/threat-indicators',
        'platform:threat_intel_manage',
      ],
    ];
    for (const [key, listKey, permission] of pairs) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      const list = routes.find((r) => `${r.method} ${r.path}` === listKey);
      expect(route?.isPublic, key).toBe(false);
      expect(route?.requirement, key).toEqual({ mode: 'all', permissions: [permission] });
      expect(route?.requirement, key).toEqual(list?.requirement);
      expect(route?.requireMfa, key).toBe(list?.requireMfa);
      expect(route?.userOnly, key).toBe(list?.userOnly);
      expect(route?.returnsSecret, key).toBe(false);
      expect(route?.cursor ?? null, key).toBeNull();
      expect(route?.idempotency ?? null, key).toBeNull();
    }
    // BEC and DLP: API keys allowed, no MFA; the platform catalog: users only with MFA.
    const indicator = routes.find(
      (r) => `${r.method} ${r.path}` === 'get /api/v1/platform/threat-indicators/:id',
    );
    expect(indicator?.userOnly).toBe(true);
    expect(indicator?.requireMfa).toBe(true);
    for (const key of [
      'get /api/v1/bec/trusted-senders/:id',
      'get /api/v1/bec/suppressions/:id',
      'get /api/v1/dlp/exceptions/:id',
    ]) {
      const route = routes.find((r) => `${r.method} ${r.path}` === key);
      expect(route?.userOnly, key).toBe(false);
      expect(route?.requireMfa, key).toBe(false);
    }
  });

  it('the step AI-5 capture-issue read keeps the flags of its list and is no cursor list (D8)', () => {
    const route = routes.find(
      (r) => `${r.method} ${r.path}` === 'get /api/v1/archive/capture-issues/:messageId',
    );
    const list = routes.find(
      (r) => `${r.method} ${r.path}` === 'get /api/v1/archive/capture-issues',
    );
    expect(route?.isPublic).toBe(false);
    expect(route?.requirement).toEqual({
      mode: 'any',
      permissions: ['journal:manage', 'archive:manage'],
    });
    expect(route?.requirement).toEqual(list?.requirement);
    expect(route?.requireMfa).toBe(list?.requireMfa);
    expect(route?.userOnly).toBe(list?.userOnly);
    expect(route?.userOnly).toBe(false);
    expect(route?.returnsSecret).toBe(false);
    expect(route?.rateClass ?? null).toBeNull();
    expect(route?.cursor ?? null).toBeNull();
    expect(route?.idempotency ?? null).toBeNull();
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
