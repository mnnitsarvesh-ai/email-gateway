/**
 * The e2e harness of the step 5.2 policy and department routes: the real AppModule (controllers,
 * validation, guards, services, writer) with MySQL, Redis and S3 stubbed and the policy
 * repositories replaced by `InMemoryPolicies` (the repository semantics) and fakes of the
 * replica reads of a message round. Two organizations (`A` = 1, `B` = 2); the principal and its
 * permissions are chosen per request with `as(...)`.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { vi } from 'vitest';
import { AppModule } from '../../src/app.module';
import { AuditService } from '../../src/audit/audit.service';
import type { TenantScope } from '../../src/auth-contracts/tenant-scope';
import { loadApiConfig } from '../../src/config';
import { TransactionRunner } from '../../src/database/transaction-runner';
import { EmailSender } from '../../src/email/email-sender';
import { configureApiApp } from '../../src/http/configure-api-app';
import { KeyValueStore } from '../../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../../src/modules/auth/services/session.service';
import { TokenService } from '../../src/modules/auth/services/token.service';
import { DepartmentsRepository } from '../../src/modules/directory/repositories/departments.repository';
import { PoliciesManagementRepository } from '../../src/modules/policies/repositories/policies-management.repository';
import { PolicyExecutionsRepository } from '../../src/modules/policies/repositories/policy-executions.repository';
import { PolicyFactsRepository } from '../../src/modules/policies/repositories/policy-facts.repository';
import { InMemoryKeyValueStore } from './in-memory-key-value-store';
import { InMemoryPolicies } from './in-memory-policies';
import { cleanRound } from './policy-fixtures';
import { RecordingEmailSender } from './recording-email-sender';
import { TEST_DOMAIN_ENV } from './test-env';

export const roleOf = (key: string): string[] => [
  ...SYSTEM_ROLES.find((role) => role.key === key)!.permissions,
];

export const ORGS = {
  A: { id: '1', publicId: randomUUID() },
  B: { id: '2', publicId: randomUUID() },
} as const;
export type OrgKey = keyof typeof ORGS;
export const USER = { id: '10', publicId: '0190f0f0-0000-7000-8000-00000000000a' };
export const MESSAGE_ID = '0190f0f0-0000-7000-8000-0000000000f1';
export const SCAN = '900';

export interface PolicyApp {
  app: INestApplication;
  http: () => ReturnType<typeof request>;
  store: () => InMemoryPolicies;
  audit: { record: ReturnType<typeof vi.fn>; actorFrom: () => unknown };
  actions: () => string[];
  as: (permissions: string[], org?: OrgKey) => Promise<Record<string, string>>;
  round: ReturnType<typeof cleanRound>;
  /** The stored evaluation the round's reads return (set per test). */
  stored: { row: unknown };
  executions: {
    history: ReturnType<typeof vi.fn>;
    messagePublicIds: ReturnType<typeof vi.fn>;
    forMessage: ReturnType<typeof vi.fn>;
  };
  reset: () => void;
  close: () => Promise<void>;
}

export async function createPolicyApp(extraEnv: Record<string, string> = {}): Promise<PolicyApp> {
  const env = {
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
    ...extraEnv,
  };
  const cfg = loadApiConfig(env);
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(cfg);
  let store = new InMemoryPolicies();
  let snapshot: PrincipalSnapshot;
  let currentOrg: OrgKey = 'A';
  const audit = {
    actorFrom: () => ({ type: 'user', id: USER.publicId }),
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
  };
  const round = cleanRound({
    messageId: 77n,
    receivedAt: new Date('2026-11-10T10:00:00.000Z'),
    organizationId: 1n,
    scanId: 900n,
  });
  const stored: { row: unknown } = { row: null };
  const facts = {
    snapshot: (s: TenantScope) => store.facts.snapshot(s),
    policyVersion: (s: TenantScope, id: string, n: number) => store.facts.policyVersion(s, id, n),
    directory: (s: TenantScope, a: readonly string[], r: never) => store.facts.directory(s, a, r),
    message: (scope: TenantScope, id: string) =>
      Promise.resolve(
        scope.organizationId === 1n && id === MESSAGE_ID
          ? { ...round.message, publicId: MESSAGE_ID }
          : null,
      ),
    scan: (_s: unknown, _m: unknown, id: bigint) =>
      Promise.resolve(id === 900n ? round.scan : null),
    roundRows: () => Promise.resolve(round.rows),
    storedEvaluation: () => Promise.resolve(stored.row),
  };
  const executions = {
    history: vi.fn(() => Promise.resolve([] as unknown[])),
    messagePublicIds: vi.fn(() => Promise.resolve(new Map<bigint, string>())),
    forMessage: vi.fn(() => Promise.resolve([] as unknown[])),
  };
  const proxy = (pick: () => object) =>
    new Proxy({}, { get: (_t, key: string) => (pick() as Record<string, unknown>)[key] });
  const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
  const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(cfg)] })
    .overrideProvider(PrismaService)
    .useValue(stub('mysql'))
    .overrideProvider(PrismaReadService)
    .useValue(stub('mysql-reader'))
    .overrideProvider(RedisService)
    .useValue(stub('redis'))
    .overrideProvider(S3Service)
    .useValue(stub('s3'))
    .overrideProvider(KeyValueStore)
    .useValue(kv)
    .overrideProvider(EmailSender)
    .useValue(new RecordingEmailSender())
    .overrideProvider(SessionService)
    .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
    .overrideProvider(PrincipalLoaderService)
    .useValue({ load: () => Promise.resolve(snapshot) })
    .overrideProvider(ApiKeyAuthenticatorService)
    .useValue({ authenticate: () => Promise.reject(new Error('no api keys in this suite')) })
    .overrideProvider(TransactionRunner)
    .useValue({
      run: (fn: (tx: unknown) => Promise<unknown>, options: unknown) =>
        store.transactions.run(fn as never, options),
    })
    .overrideProvider(AuditService)
    .useValue(audit)
    .overrideProvider(PoliciesManagementRepository)
    .useValue(proxy(() => store.repository))
    .overrideProvider(DepartmentsRepository)
    .useValue(proxy(() => store.departments))
    .overrideProvider(PolicyFactsRepository)
    .useValue(facts)
    .overrideProvider(PolicyExecutionsRepository)
    .useValue(executions)
    .compile();
  const app = moduleRef.createNestApplication({ logger: false });
  configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
  configureApiApp(app, cfg);
  // Listen up front: requests are built across awaits (the principal is switched per request).
  await app.listen(0, '127.0.0.1');

  const principalWith = (permissions: string[], org: OrgKey) => {
    currentOrg = org;
    snapshot = {
      orgVersion: 0,
      userVersion: '',
      user: {
        id: USER.id,
        publicId: USER.publicId,
        status: 'active',
        deleted: false,
        mfaEnabled: true,
      },
      org: {
        id: ORGS[org].id,
        publicId: ORGS[org].publicId,
        kind: 'customer',
        status: 'active',
        deleted: false,
        mfaRequired: false,
      },
      permissions,
    };
  };
  const reset = () => {
    vi.clearAllMocks();
    kv.entries.clear();
    store = new InMemoryPolicies();
    store.addUser(10n, { organizationId: 1n, email: 'admin@acme.example' });
    store.users.get(10n)!.publicId = USER.publicId;
    store.activeDomains.add('1:acme.example');
    stored.row = null;
    principalWith(roleOf('organization_admin'), 'A');
  };
  reset();
  return {
    app,
    http: () => request(app.getHttpServer()),
    store: () => store,
    audit,
    actions: () => audit.record.mock.calls.map(([entry]) => (entry as { action: string }).action),
    as: async (permissions, org = 'A') => {
      principalWith(permissions, org);
      kv.entries.clear();
      const { token } = await tokens.issue({
        userPublicId: USER.publicId,
        organizationPublicId: ORGS[currentOrg].publicId,
        sessionId: randomUUID(),
        amr: ['pwd', 'otp'],
      });
      return { Authorization: `Bearer ${token}` };
    },
    round,
    stored,
    executions,
    reset,
    close: () => app.close(),
  };
}
