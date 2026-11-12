/**
 * In-process API integration harness (design §5, WP3). Later suites (identity administration,
 * organizations and the tenant-isolation suites of WP4/WP5) reuse `createIntegrationApp`,
 * `fixtures.ts` and `http.ts` instead of building their own app.
 *
 * - Real MySQL (writer + replica) and Redis from the local `.env` (loaded by `setup.ts`).
 * - `HTTP_TRUST_PROXY=1`, so each test can choose its client IP with `X-Forwarded-For`
 *   (`uniqueIp()`), and every background job off (`AUTH_BACKGROUND_JOBS_ENABLED`,
 *   `DOMAIN_BACKGROUND_JOBS_ENABLED`, `DKIM_SIGNING_SYNC_ENABLED` = false). Passing
 *   `REDIS_DKIM_URL: ''` disables the DKIM signing publisher entirely.
 * - Generous global API rate limits (step 6.1 D8, `TEST_GENEROUS_RATE_LIMITS`), overridable.
 * - `EmailSender` is always a `RecordingEmailSender`: tests never send real email (D13).
 * - Logs go to an in-memory buffer (`logs`) so tests can assert that secrets never appear.
 * - The server listens on an ephemeral 127.0.0.1 port for the app's lifetime, so concurrent
 *   requests (`Promise.all`) are safe.
 */
import { Writable } from 'node:stream';
import type { INestApplication, ModuleMetadata } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { configureHttpApp, NestPinoLogger, PrismaService } from '@email-gateway/common';
import { PLATFORM_ORGANIZATION_SLUG } from '@email-gateway/database';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { AppModule } from '../../src/app.module';
import { type ApiConfig, loadApiConfig } from '../../src/config';
import { EmailSender } from '../../src/email/email-sender';
import { configureApiApp } from '../../src/http/configure-api-app';
import { KeyValueStore } from '../../src/kv/key-value-store';
import { RecordingEmailSender } from '../../test/support/recording-email-sender';
import { TEST_GENEROUS_RATE_LIMITS } from '../../test/support/test-env';

export interface IntegrationApp {
  app: INestApplication;
  /** Supertest agent bound to the in-process server. */
  http: ReturnType<typeof request>;
  /** Writer client (fixtures and assertions). */
  prisma: PrismaService;
  kv: KeyValueStore;
  emails: RecordingEmailSender;
  config: Readonly<ApiConfig>;
  /** Every log line written by the app (JSON strings). */
  logs: string[];
  get<T>(token: abstract new (...args: never[]) => T): T;
  close(): Promise<void>;
}

export interface IntegrationAppOptions {
  /** Extra modules, e.g. a test-only controller module of one suite (never production code). */
  imports?: ModuleMetadata['imports'];
}

export async function createIntegrationApp(
  envOverrides: Record<string, string> = {},
  options: IntegrationAppOptions = {},
): Promise<IntegrationApp> {
  const config = loadApiConfig({
    ...process.env,
    HTTP_TRUST_PROXY: '1',
    AUTH_BACKGROUND_JOBS_ENABLED: 'false',
    DOMAIN_BACKGROUND_JOBS_ENABLED: 'false',
    // No periodic DKIM sync: suites call DkimSigningPublisher.reconcile() themselves.
    DKIM_SIGNING_SYNC_ENABLED: 'false',
    // Step 6.1 D8: global API limits no suite reaches; suites that test the limiter override them.
    ...TEST_GENEROUS_RATE_LIMITS,
    ...envOverrides,
  });
  const emails = new RecordingEmailSender();
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule.forRoot(config), ...(options.imports ?? [])],
  })
    .overrideProvider(EmailSender)
    .useValue(emails)
    .compile();

  const logs: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      logs.push(chunk.toString('utf8'));
      callback();
    },
  });
  const logger = createLogger({ service: 'api-integration', level: 'debug', destination });
  const app = moduleRef.createNestApplication({ logger: new NestPinoLogger(logger) });
  configureHttpApp(app, logger);
  configureApiApp(app, config);
  // Listen up front on an ephemeral loopback port. Otherwise supertest starts a shared listener
  // per request batch and closes it when the batch settles; a request created while that
  // listener is closing never starts (a hung test).
  await app.listen(0, '127.0.0.1');

  const prisma = app.get(PrismaService);
  const platform = await prisma.organization.findUnique({
    where: { slug: PLATFORM_ORGANIZATION_SLUG },
    select: { id: true },
  });
  if (!platform) {
    await app.close();
    throw new Error(
      'The platform organization is missing: run `pnpm db:seed` before the API integration tests',
    );
  }

  return {
    app,
    http: request(app.getHttpServer()),
    prisma,
    kv: app.get(KeyValueStore),
    emails,
    config,
    logs,
    get: (token) => app.get(token),
    close: () => app.close(),
  };
}
