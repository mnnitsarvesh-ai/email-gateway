/**
 * The stubbed in-process api of the e2e suites (step 6.1, for WP1–WP5): the whole AppModule
 * with MySQL, Redis and S3 stubbed, an in-memory key-value store, a recording email sender, the
 * shared HTTP setup (`configureHttpApp` + `configureApiApp`) and, optionally, test principals:
 * a user (bearer tokens signed with the test config) and an API key whose permissions and flags
 * each test chooses. Nothing here is used by production code.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication, ModuleMetadata } from '@nestjs/common';
import { DiscoveryModule } from '@nestjs/core';
import { Test, type TestingModuleBuilder } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { AppModule } from '../../src/app.module';
import type { ApiKeyPrincipal } from '../../src/auth-contracts/principal';
import { type ApiConfig, loadApiConfig } from '../../src/config';
import { EmailSender } from '../../src/email/email-sender';
import { TransactionRunner } from '../../src/database/transaction-runner';
import { configureApiApp } from '../../src/http/configure-api-app';
import {
  IdempotencyReservationRepository,
  type NewReservation,
} from '../../src/http/idempotency/idempotency-reservation.repository';
import {
  type IdempotencyRecord,
  IdempotencyRepository,
  type NewIdempotencyRecord,
} from '../../src/http/idempotency/idempotency.repository';
import { KeyValueStore } from '../../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../../src/modules/auth/services/session.service';
import { TokenService } from '../../src/modules/auth/services/token.service';
import { InMemoryKeyValueStore } from './in-memory-key-value-store';
import { RecordingEmailSender } from './recording-email-sender';
import { TEST_DOMAIN_ENV } from './test-env';

/** The env of every stubbed api (no real dependency is reached). */
export function stubbedApiEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
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
    ...overrides,
  };
}

export interface TestUserFlags {
  mfaAuthenticated?: boolean;
  mfaEnrollmentRequired?: boolean;
  orgKind?: 'customer' | 'platform';
}

/**
 * Test principals behind the real AuthGuard: `bearer()` is a valid access token whose session
 * and principal snapshot are stubbed; `apiKeyHeaders` authenticates as `apiKey`.
 */
export class TestPrincipals {
  readonly ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
  /** Internal organization id of both principals. */
  organizationId = 1n;
  snapshot!: PrincipalSnapshot;
  private flags: TestUserFlags = {};
  readonly apiKey: ApiKeyPrincipal;
  readonly apiKeyHeaders = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };

  constructor(private readonly tokens: TokenService) {
    this.apiKey = {
      kind: 'api_key',
      apiKeyId: 5n,
      apiKeyPublicId: randomUUID(),
      organizationId: this.organizationId,
      organizationPublicId: this.ids.org,
      permissions: new Set(),
    };
    this.user([]);
  }

  /** The user's permissions and MFA state for the next requests. */
  user(permissions: string[], flags: TestUserFlags = {}): this {
    this.flags = flags;
    this.snapshot = {
      orgVersion: 0,
      userVersion: '',
      user: {
        id: '10',
        publicId: this.ids.user,
        status: 'active',
        deleted: false,
        mfaEnabled: !flags.mfaEnrollmentRequired,
      },
      org: {
        id: this.organizationId.toString(10),
        publicId: this.ids.org,
        kind: flags.orgKind ?? 'customer',
        status: 'active',
        deleted: false,
        mfaRequired: flags.mfaEnrollmentRequired === true,
      },
      permissions,
    };
    return this;
  }

  /** The API key's permissions for the next requests. */
  apiKeyWith(permissions: string[]): this {
    (this.apiKey as { permissions: ReadonlySet<string> }).permissions = new Set(permissions);
    return this;
  }

  async bearer(): Promise<{ Authorization: string }> {
    const { token } = await this.tokens.issue({
      userPublicId: this.ids.user,
      organizationPublicId: this.ids.org,
      sessionId: this.ids.session,
      amr: this.flags.mfaAuthenticated ? ['pwd', 'otp'] : ['pwd'],
    });
    return { Authorization: `Bearer ${token}` };
  }
}

export interface StubbedApiAppOptions {
  /** Extra modules, e.g. a test-only controller module (never in production code). */
  imports?: ModuleMetadata['imports'];
  /** Further provider overrides on the testing module builder. */
  override?: (builder: TestingModuleBuilder) => TestingModuleBuilder;
  /** Stub authentication with TestPrincipals (default true). */
  principals?: boolean;
  /** Import DiscoveryModule (for route-discovery). */
  discovery?: boolean;
  /** Runs after the shared HTTP setup and before `app.init()`, like main.ts' `configure`. */
  beforeInit?: (app: INestApplication, config: Readonly<ApiConfig>) => void;
}

export interface StubbedApiApp {
  app: INestApplication;
  config: Readonly<ApiConfig>;
  kv: InMemoryKeyValueStore;
  emails: RecordingEmailSender;
  principals: TestPrincipals;
  http: () => ReturnType<typeof request>;
  close(): Promise<void>;
}

/** Builds and initializes the stubbed AppModule (see the file comment). */
export async function createStubbedApiApp(
  envOverrides: Record<string, string> = {},
  options: StubbedApiAppOptions = {},
): Promise<StubbedApiApp> {
  const config = loadApiConfig(stubbedApiEnv(envOverrides));
  const kv = new InMemoryKeyValueStore();
  const emails = new RecordingEmailSender();
  const principals = new TestPrincipals(new TokenService(config));
  const stub = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
  let builder = Test.createTestingModule({
    imports: [
      AppModule.forRoot(config),
      ...(options.discovery ? [DiscoveryModule] : []),
      ...(options.imports ?? []),
    ],
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
    .useValue(kv)
    .overrideProvider(EmailSender)
    .useValue(emails);
  if (options.principals !== false) {
    builder = builder
      .overrideProvider(SessionService)
      .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
      .overrideProvider(PrincipalLoaderService)
      .useValue({ load: () => Promise.resolve(principals.snapshot) })
      .overrideProvider(ApiKeyAuthenticatorService)
      .useValue({ authenticate: () => Promise.resolve(principals.apiKey) });
  }
  if (options.override) builder = options.override(builder);
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication({ logger: false });
  configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
  configureApiApp(app, config);
  options.beforeInit?.(app, config);
  await app.init();
  return {
    app,
    config,
    kv,
    emails,
    principals,
    http: () => request(app.getHttpServer()),
    close: () => app.close(),
  };
}

/**
 * `api_idempotency_keys` in memory, standing in for IdempotencyRepository and
 * IdempotencyReservationRepository (with `TransactionRunner` replaced by `immediateRunner`) in
 * e2e suites of idempotent routes: one row per (organization, key), completed and pending states.
 */
export class InMemoryIdempotencyStore {
  readonly rows = new Map<
    string,
    IdempotencyRecord & { organizationId: bigint; idempotencyKey: string }
  >();
  private nextId = 1n;
  private readonly k = (org: bigint, key: string) => `${org}:${key}`;

  readonly records = {
    lock: (_tx: unknown, org: bigint, key: string) =>
      Promise.resolve(this.rows.get(this.k(org, key)) ?? null),
    delete: (_tx: unknown, id: bigint) => {
      for (const [k, row] of this.rows) if (row.id === id) this.rows.delete(k);
      return Promise.resolve();
    },
    insert: (_tx: unknown, r: NewIdempotencyRecord) => {
      this.rows.set(this.k(r.organizationId, r.idempotencyKey), {
        ...r,
        id: this.nextId++,
        state: 'completed',
      });
      return Promise.resolve();
    },
  };

  readonly reservations = {
    reserve: (_tx: unknown, r: NewReservation) => {
      const id = this.nextId++;
      this.rows.set(this.k(r.organizationId, r.idempotencyKey), {
        ...r,
        id,
        statusCode: 0,
        response: null,
        state: 'pending',
      });
      return Promise.resolve(id);
    },
    complete: (
      _tx: unknown,
      reservation: { id: bigint },
      out: { statusCode: number; body: unknown; expiresAt: Date },
    ) => {
      const row = [...this.rows.values()].find(
        (r) => r.id === reservation.id && r.state === 'pending',
      );
      if (!row) return Promise.resolve(false);
      Object.assign(row, {
        state: 'completed',
        statusCode: out.statusCode,
        response: out.body === Prisma.JsonNull ? null : out.body,
        expiresAt: out.expiresAt,
      });
      return Promise.resolve(true);
    },
    release: (_tx: unknown, reservation: { id: bigint }) => {
      for (const [k, row] of this.rows) {
        if (row.id === reservation.id && row.state === 'pending') {
          this.rows.delete(k);
          return Promise.resolve(true);
        }
      }
      return Promise.resolve(false);
    },
  };

  /** Overrides for `createStubbedApiApp({ override })`. */
  override(builder: TestingModuleBuilder): TestingModuleBuilder {
    return builder
      .overrideProvider(TransactionRunner)
      .useValue(immediateRunner)
      .overrideProvider(IdempotencyRepository)
      .useValue(this.records)
      .overrideProvider(IdempotencyReservationRepository)
      .useValue(this.reservations);
  }
}

/** A TransactionRunner that runs the function with a dummy client (in-memory stores only). */
export const immediateRunner = {
  run: <T>(fn: (tx: never) => Promise<T>): Promise<T> => fn({} as never),
};
