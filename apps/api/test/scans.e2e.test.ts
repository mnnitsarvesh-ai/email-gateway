/**
 * Step 4.1 scan routes (S13, S16) and the step 4.2 additions (A8 attachment settings, A13 rescan
 * jobs, A16 per-attachment results and known-threat hashes) over HTTP with MySQL, Redis, S3 and
 * Rspamd stubbed:
 * authorization (401, 403 per permission, API keys refused and MFA required on the platform
 * training route), validation before any database access (400, 404 unknown engine, 422 invalid
 * settings with violations), the version compare-and-set (409), the scan read mapping and its
 * coded 404, the training route's 503 without a configured controller and its rate limit. The
 * same routes against the real MySQL, MinIO and Rspamd run in integration/scans.test.ts.
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
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
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../src/app.module';
import { AuditService } from '../src/audit/audit.service';
import type { ApiKeyPrincipal } from '../src/auth-contracts/principal';
import { loadApiConfig } from '../src/config';
import { TransactionRunner } from '../src/database/transaction-runner';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { KeyValueStore } from '../src/kv/key-value-store';
import { ApiKeyAuthenticatorService } from '../src/modules/auth/services/api-key-authenticator.service';
import type { PrincipalSnapshot } from '../src/modules/auth/services/principal-cache.service';
import { PrincipalLoaderService } from '../src/modules/auth/services/principal-loader.service';
import { SessionService } from '../src/modules/auth/services/session.service';
import { type AuthMethod, TokenService } from '../src/modules/auth/services/token.service';
import {
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../src/modules/messages/repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../src/modules/messages/repositories/message-scans-read.repository';
import { AttachmentRescansRepository } from '../src/modules/scans/repositories/attachment-rescans.repository';
import { ScanSettingsRepository } from '../src/modules/scans/repositories/scan-settings.repository';
import { OrganizationFeaturesService } from '../src/tenancy/organization-features.service';
import { ScanTrainingRepository } from '../src/modules/scans/repositories/scan-training.repository';
import { ThreatHashesRepository } from '../src/modules/scans/repositories/threat-hashes.repository';
import { ThreatIndicatorsRepository } from '../src/modules/scans/repositories/threat-indicators.repository';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

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
  // No RSPAMD_CONTROLLER_URL: the training route answers 503 once authorized and found.
};

const READ = 'message:read';
const POLICY_READ = 'policy:read';
const MANAGE = 'scan:settings_manage';
const TRAIN = 'platform:scan_training';
const THREAT_INTEL = 'platform:threat_intel_manage';
const RESCAN = 'platform:scan_rescan';
const SHA = 'c'.repeat(64);
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[], kind: 'customer' | 'platform' = 'customer'): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '1',
      publicId: ids.org,
      kind,
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions,
  };
}

let apiKeyPermissions = new Set<string>([READ, POLICY_READ]);
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: apiKeyPermissions,
});

const knownMessage: LifecycleMessageRow = {
  id: 77n,
  publicId: randomUUID(),
  receivedAt: new Date('2026-11-05T08:00:00.000Z'),
  direction: 'inbound',
  status: 'scanned',
  statusReason: 'scan_complete',
  version: 4,
  lifecycleRound: 0,
  statusChangedAt: new Date('2026-11-05T08:01:00.000Z'),
};

const scanRow = {
  id: 900n,
  lifecycleRound: 0,
  scanKind: 'initial' as const,
  status: 'completed' as const,
  scanVerdict: 'spam' as const,
  reasonCodes: ['spam.score', 'reputation.ip_listed'],
  requiredEngines: ['rspamd'],
  startedAt: new Date('2026-11-05T08:00:01.000Z'),
  completedAt: new Date('2026-11-05T08:00:05.000Z'),
  deadlineAt: new Date('2026-11-05T08:30:01.000Z'),
};
const engineRow = (attempt: number, isFinal: boolean) => ({
  scanId: 900n,
  engine: 'rspamd',
  engineVersion: '3.12.1',
  outcome: isFinal ? ('spam' as const) : ('timeout' as const),
  score: isFinal ? new Prisma.Decimal('8.5') : null,
  requiredScore: isFinal ? new Prisma.Decimal('15') : null,
  action: isFinal ? 'no action' : null,
  reasonCodes: isFinal ? ['spam.score'] : ['engine.timeout'],
  errorCode: isFinal ? null : 'timeout',
  settingsVersion: isFinal ? 'rspamd-map/1;p=abc;t=none' : null,
  durationMs: 1200,
  evidence: isFinal
    ? { signals: [{ name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] }, { bad: true }] }
    : null,
  attempt,
  isFinal,
  completedAt: new Date(`2026-11-05T08:00:0${attempt + 1}.000Z`),
});

const attachmentEngineRow = {
  ...engineRow(1, true),
  engine: 'attachment',
  engineVersion: 'clamav/1.4.6/28173;yara-x/0.10.0/462fab6e5cc4',
  outcome: 'suspicious' as const,
  score: null,
  requiredScore: null,
  action: null,
  reasonCodes: ['type.executable_disguised'],
  settingsVersion: 'attachment-map/1;p=abc;t=none',
  evidence: { signals: [] },
};
const attachmentResultRow = {
  scanId: 900n,
  attachmentId: 4000n,
  partIndex: 1,
  sha256: 'd'.repeat(64),
  sizeBytes: 2048,
  detectedType: 'pe_executable',
  typeFamily: 'executable',
  typeMismatch: true,
  verdict: 'suspicious' as const,
  reasonCodes: ['type.executable_disguised', 'type.denied'],
  clamavSignature: null,
  clamavEngineVersion: '1.4.6',
  clamavDbVersion: 28173,
  yaraBundleId: 'yara-1-462fab6e5cc4',
  yaraMatches: [],
  archive: null,
  knownHashSeverity: null,
  cacheResult: 'miss' as const,
  durationMs: 15,
};
const urlEngineRow = {
  ...engineRow(1, true),
  engine: 'url',
  engineVersion: 'url/1;url-fetch/1;aaaaaaaa;bbbbbbbb',
  outcome: 'suspicious' as const,
  score: null,
  requiredScore: null,
  action: null,
  reasonCodes: ['url.redirect_blocked_internal'],
  settingsVersion: 'url-map/1;p=abc;t=none',
  durationMs: 987,
  evidence: { signals: [] },
  completedAt: new Date('2026-11-05T08:00:04.321Z'),
};
const URL_SHA = 'a'.repeat(64);
const messageUrlRow = {
  urlSeq: 0,
  url: 'http://short-link.test/s/internal',
  urlSha256: URL_SHA,
  host: 'short-link.test',
  unicodeHost: null,
  registrableDomain: 'short-link.test',
  hostKind: 'domain' as const,
  flags: [],
  sources: { html_href: 1 },
};
const urlResultRow = {
  scanId: 900n,
  urlSeq: 0,
  urlSha256: URL_SHA,
  verdict: 'suspicious' as const,
  reasonCodes: ['url.redirect_blocked_internal', 'url.shortened'],
  reputation: [
    {
      provider: 'local_feed',
      version: 'local_feed/1',
      kind: 'url',
      status: 'clear',
      category: null,
      severity: null,
      cache: 'none',
    },
  ],
  lookalike: null,
  fetchStatus: 'blocked' as const,
  fetchError: 'loopback',
  hopCount: 1,
  redirectChain: [
    { host: 'short-link.test', port: 80, status: 302, kind: 'initial', blocked: null },
    { host: '127.0.0.1', port: 80, status: null, kind: 'http', blocked: 'loopback' },
  ],
  finalUrl: null,
  finalStatus: null,
  landing: null,
  rewritten: true,
  fetchCache: 'miss' as const,
  durationMs: 33,
};
const hashRow = (sha256 = SHA) => ({
  id: 12n,
  sha256,
  md5: null,
  severity: 'critical' as const,
  family: 'Win.Test',
  source: 'analyst',
  reason: 'campaign',
  expiresAt: null,
  firstSeenAt: new Date('2026-11-05T09:00:00.000Z'),
  lastSeenAt: new Date('2026-11-05T09:00:00.000Z'),
  createdAt: new Date('2026-11-05T09:00:00.000Z'),
  updatedAt: new Date('2026-11-05T09:00:00.000Z'),
  addedBy: { publicId: ids.user },
});
const JOB_ID = randomUUID();
const jobRow = (status: 'pending' | 'completed' = 'pending') => ({
  id: 3n,
  publicId: JOB_ID,
  trigger: 'admin' as const,
  status,
  organizationId: null,
  windowStart: new Date('2026-11-04T09:00:00.000Z'),
  windowEnd: new Date('2026-11-05T09:00:00.000Z'),
  states: ['scanned'],
  component: null,
  fromVersion: null,
  toVersion: null,
  maxMessages: 5000,
  selectedCount: 0,
  requestedCount: 0,
  skippedCount: 0,
  reason: 'x',
  lastError: null,
  startedAt: null,
  completedAt: null,
  createdAt: new Date('2026-11-05T09:00:00.000Z'),
  updatedAt: new Date('2026-11-05T09:00:00.000Z'),
  organization: null,
  requestedBy: { publicId: ids.user },
});

const pendingSubmission = {
  id: 31n,
  scanId: 900n,
  attachmentId: 4000n,
  partIndex: 1,
  sha256: 'd'.repeat(64),
  status: 'pending',
  skipReason: null,
  sandboxVerdict: null,
  sandboxReasonCodes: null,
  completedAt: null,
  analysisId: null,
  externalRef: null,
};
const SANDBOX_TASK = '0193a7c0-0000-7000-8000-00000000abcd';
const sandboxEngineRow = {
  ...engineRow(1, true),
  engine: 'sandbox',
  engineVersion: '0.1.0+static/sandbox-static/1',
  outcome: 'unknown' as const,
  score: null,
  requiredScore: null,
  action: null,
  reasonCodes: ['sandbox.static_only', 'sandbox.static.script_download_cradle'],
  settingsVersion: 'sandbox-map/1;p=abc;t=1',
  durationMs: 0,
  evidence: { submissions: 1, executed: 0, isolation: ['process'] },
  completedAt: new Date('2026-11-05T08:03:07.654Z'),
};
const sandboxState = {
  submissions: [pendingSubmission] as unknown[],
  extraEngineRows: [] as unknown[],
};

describe('step 4.1 scan routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const settingsRows = {
    list: vi.fn(() => Promise.resolve([] as unknown[])),
    find: vi.fn(() => Promise.resolve(null as unknown)),
    create: vi.fn(() => Promise.resolve({})),
    replaceIfVersion: vi.fn(() => Promise.resolve(true)),
  };
  const hashes = {
    list: vi.fn(() => Promise.resolve([hashRow()])),
    findForUpdate: vi.fn((_tx: unknown, sha256: string) =>
      Promise.resolve(sha256 === SHA ? hashRow() : null),
    ),
    create: vi.fn((_tx: unknown, input: { sha256: string }) =>
      Promise.resolve(hashRow(input.sha256)),
    ),
    remove: vi.fn(() => Promise.resolve()),
  };
  const indicatorRow = (value = 'evil.example', id = 21n) => ({
    id,
    organizationId: null,
    indicatorType: 'domain' as const,
    value,
    valueSha256: createHash('sha256').update(value).digest('hex'),
    severity: 'high' as const,
    category: 'phishing' as const,
    source: 'analyst',
    reason: 'campaign',
    expiresAt: null,
    firstSeenAt: new Date('2026-11-06T09:00:00.000Z'),
    lastSeenAt: new Date('2026-11-06T09:00:00.000Z'),
    createdAt: new Date('2026-11-06T09:00:00.000Z'),
    updatedAt: new Date('2026-11-06T09:00:00.000Z'),
    addedBy: { publicId: ids.user },
  });
  const LISTED_SHA = createHash('sha256').update('listed.example').digest('hex');
  const indicators = {
    list: vi.fn(() => Promise.resolve([indicatorRow()])),
    findAnalystForUpdate: vi.fn((_tx: unknown, _type: string, valueSha256: string) =>
      Promise.resolve(valueSha256 === LISTED_SHA ? indicatorRow('listed.example', 22n) : null),
    ),
    findPlatformForUpdate: vi.fn((_tx: unknown, id: bigint) =>
      Promise.resolve(id === 21n ? indicatorRow() : null),
    ),
    create: vi.fn((_tx: unknown, input: { value: string }) =>
      Promise.resolve(indicatorRow(input.value, 23n)),
    ),
    remove: vi.fn(() => Promise.resolve()),
  };
  const rescans = {
    findOrganization: vi.fn((publicId: string) =>
      Promise.resolve(publicId === ids.org ? { id: 1n, publicId } : null),
    ),
    countCandidates: vi.fn(() => Promise.resolve(7)),
    create: vi.fn(() => Promise.resolve(jobRow())),
    list: vi.fn(() => Promise.resolve([jobRow()])),
    find: vi.fn((publicId: string) => Promise.resolve(publicId === JOB_ID ? jobRow() : null)),
    findOnWriter: vi.fn((_tx: unknown, publicId: string) =>
      Promise.resolve(publicId === JOB_ID ? jobRow() : null),
    ),
    cancel: vi.fn(() => Promise.resolve(true)),
  };
  const training = {
    findOrganization: vi.fn((publicId: string) =>
      Promise.resolve(publicId === ids.org ? { id: 1n, publicId } : null),
    ),
    findMessage: vi.fn(() =>
      Promise.resolve({
        id: 77n,
        publicId: knownMessage.publicId,
        receivedAt: knownMessage.receivedAt,
        organizationId: 1n,
        emlObjectKey: 'org/1/eml/x.eml',
      }),
    ),
    insertTrainingEvent: vi.fn(() => Promise.resolve()),
  };
  const audit = {
    actorFrom: () => ({ type: 'user', id: ids.user }),
    record: vi.fn((_entry: Record<string, unknown>) => Promise.resolve()),
  };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };
  const features = {
    isEnabled: vi.fn((_organizationId: bigint, _key: string, _tx?: unknown) =>
      Promise.resolve(false),
    ),
  };
  const sandboxReads = {
    analyses: vi.fn((_ids: bigint[]) => Promise.resolve([] as unknown[])),
    artifacts: vi.fn((_ids: bigint[]) => Promise.resolve([] as unknown[])),
  };

  const bearer = async (amr: AuthMethod[] = ['pwd', 'otp']) => {
    const { token } = await tokens.issue({
      userPublicId: ids.user,
      organizationPublicId: ids.org,
      sessionId: ids.session,
      amr,
    });
    return { Authorization: `Bearer ${token}` };
  };
  const apiKey = { 'X-API-Key': `egk_${'a'.repeat(12)}_${'b'.repeat(43)}` };
  const trainUrl = (org: string = ids.org, message: string = knownMessage.publicId) =>
    `/api/v1/platform/organizations/${org}/messages/${message}/scan-training`;
  const learn = { operation: 'learn_spam', reason: 'confirmed spam campaign' };

  beforeAll(async () => {
    const config = loadApiConfig(env);
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
      .useValue(kv)
      .overrideProvider(EmailSender)
      .useValue(new RecordingEmailSender())
      .overrideProvider(SessionService)
      .useValue({ isRevoked: () => Promise.resolve(false), isLive: () => Promise.resolve(true) })
      .overrideProvider(PrincipalLoaderService)
      .useValue({ load: () => Promise.resolve(snapshot) })
      .overrideProvider(ApiKeyAuthenticatorService)
      .useValue({ authenticate: () => Promise.resolve(apiKeyPrincipal()) })
      .overrideProvider(TransactionRunner)
      .useValue(transactions)
      .overrideProvider(AuditService)
      .useValue(audit)
      .overrideProvider(MessageLifecycleReadRepository)
      .useValue({
        findMessage: (_scope: unknown, publicId: string) =>
          Promise.resolve(publicId === knownMessage.publicId ? knownMessage : null),
      })
      .overrideProvider(MessageScansReadRepository)
      .useValue({
        rounds: () => Promise.resolve([scanRow]),
        engineResults: () =>
          Promise.resolve([
            engineRow(2, true),
            engineRow(1, false),
            attachmentEngineRow,
            urlEngineRow,
            ...sandboxState.extraEngineRows,
          ]),
        messageUrls: () => Promise.resolve([messageUrlRow]),
        urlResults: () => Promise.resolve([urlResultRow]),
        urlRewrites: () =>
          Promise.resolve([
            {
              scanId: 900n,
              lifecycleRound: 0,
              status: 'rewritten',
              skipReason: null,
              linksRewritten: 1,
              partsRewritten: 1,
              dkimSigned: false,
              expiresAt: new Date('2026-12-05T08:00:04.321Z'),
            },
          ]),
        urlInspections: () => Promise.resolve([]),
        urlClicks: () =>
          Promise.resolve([
            {
              urlSeq: 0,
              total: 2,
              lastDecision: 'warned',
              lastAt: new Date('2026-11-05T09:10:11.999Z'),
            },
          ]),
        attachmentResults: () => Promise.resolve([attachmentResultRow]),
        attachmentParts: () =>
          Promise.resolve([{ partIndex: 1, filename: 'invoice.pdf', declaredContentType: null }]),
        sandboxSubmissions: () => Promise.resolve(sandboxState.submissions),
        // Step 5.1 R15: no stored risk score for this round (rounds scored before 5.1).
        riskScores: () => Promise.resolve([]),
        policyEvaluations: () => Promise.resolve([]),
        sandboxAnalyses: (ids: bigint[]) => sandboxReads.analyses(ids),
        sandboxArtifacts: (ids: bigint[]) => sandboxReads.artifacts(ids),
        authResults: () =>
          Promise.resolve([
            {
              scanId: 900n,
              engine: 'rspamd',
              spf: 'fail',
              spfDomain: 'spoof.scan.test',
              dkim: 'none',
              dkimSignatures: [],
              dmarc: 'fail',
              dmarcPolicy: 'reject',
              dmarcDomain: 'spoof.scan.test',
              arc: null,
            },
          ]),
      })
      .overrideProvider(ScanSettingsRepository)
      .useValue(settingsRows)
      .overrideProvider(OrganizationFeaturesService)
      .useValue(features)
      .overrideProvider(ScanTrainingRepository)
      .useValue(training)
      .overrideProvider(ThreatHashesRepository)
      .useValue(hashes)
      .overrideProvider(ThreatIndicatorsRepository)
      .useValue(indicators)
      .overrideProvider(AttachmentRescansRepository)
      .useValue(rescans)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, config);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    kv.entries.clear();
    apiKeyPermissions = new Set([READ, POLICY_READ]);
    principalWith([READ, POLICY_READ, MANAGE]);
    sandboxState.submissions = [pendingSubmission];
    sandboxState.extraEngineRows = [];
    features.isEnabled.mockResolvedValue(false);
  });

  it('answers 401 without credentials', async () => {
    await http().get(`/api/v1/messages/${knownMessage.publicId}/scans`).expect(401);
    await http().get('/api/v1/scan-settings').expect(401);
    await http().put('/api/v1/scan-settings/rspamd').send({}).expect(401);
    await http().delete('/api/v1/scan-settings/rspamd?expectedVersion=1').expect(401);
    await http().post(trainUrl()).send(learn).expect(401);
  });

  describe('GET /messages/{messageId}/scans', () => {
    it('requires message:read', async () => {
      principalWith([POLICY_READ]);
      await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(await bearer())
        .expect(403);
    });

    it('maps rounds, engines (final + attempts), symbols and auth (API key)', async () => {
      const res = await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(apiKey)
        .expect(200);
      expect(res.body).toEqual({
        messageId: knownMessage.publicId,
        nextCursor: null,
        data: [
          {
            scanId: '900',
            round: 0,
            scanKind: 'initial',
            status: 'completed',
            verdict: 'spam',
            reasonCodes: ['spam.score', 'reputation.ip_listed'],
            requiredEngines: ['rspamd'],
            startedAt: '2026-11-05T08:00:01.000Z',
            completedAt: '2026-11-05T08:00:05.000Z',
            deadlineAt: '2026-11-05T08:30:01.000Z',
            auth: {
              spf: 'fail',
              spfDomain: 'spoof.scan.test',
              dkim: 'none',
              dkimSignatures: [],
              dmarc: 'fail',
              dmarcPolicy: 'reject',
              dmarcDomain: 'spoof.scan.test',
              arc: null,
            },
            engines: [
              {
                engine: 'rspamd',
                final: true,
                engineVersion: '3.12.1',
                outcome: 'spam',
                score: 8.5,
                requiredScore: 15,
                action: 'no action',
                reasonCodes: ['spam.score'],
                symbols: [{ name: 'EG_TEST_RBL', score: 5, options: ['66.2.0.192'] }],
                attempts: [
                  {
                    attempt: 1,
                    outcome: 'timeout',
                    errorCode: 'timeout',
                    durationMs: 1200,
                    at: '2026-11-05T08:00:02.000Z',
                  },
                  {
                    attempt: 2,
                    outcome: 'spam',
                    errorCode: null,
                    durationMs: 1200,
                    at: '2026-11-05T08:00:03.000Z',
                  },
                ],
                durationMs: 1200,
                settingsVersion: 'rspamd-map/1;p=abc;t=none',
                completedAt: '2026-11-05T08:00:03.000Z',
              },
              {
                engine: 'attachment',
                final: true,
                engineVersion: 'clamav/1.4.6/28173;yara-x/0.10.0/462fab6e5cc4',
                outcome: 'suspicious',
                score: null,
                requiredScore: null,
                action: null,
                reasonCodes: ['type.executable_disguised'],
                symbols: [],
                attempts: [
                  {
                    attempt: 1,
                    outcome: 'suspicious',
                    errorCode: null,
                    // Withheld for the attachment engine (cross-tenant cache, A10).
                    durationMs: null,
                    at: '2026-11-05T08:00:02.000Z',
                  },
                ],
                durationMs: null,
                settingsVersion: 'attachment-map/1;p=abc;t=none',
                completedAt: '2026-11-05T08:00:02.000Z',
                attachments: [
                  {
                    partIndex: 1,
                    filename: 'invoice.pdf',
                    declaredContentType: null,
                    sha256: 'd'.repeat(64),
                    sizeBytes: 2048,
                    detectedType: 'pe_executable',
                    typeFamily: 'executable',
                    typeMismatch: true,
                    verdict: 'suspicious',
                    reasonCodes: ['type.executable_disguised', 'type.denied'],
                    clamav: { signature: null, engineVersion: '1.4.6', dbVersion: 28173 },
                    yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [] },
                    archive: null,
                    knownHash: null,
                    sandbox: {
                      submissionId: '31',
                      status: 'pending',
                      skipReason: null,
                      verdict: null,
                      reasonCodes: [],
                      executed: null,
                      isolation: null,
                      completedAt: null,
                    },
                  },
                ],
              },
              {
                engine: 'url',
                final: true,
                engineVersion: 'url/1;url-fetch/1;aaaaaaaa;bbbbbbbb',
                outcome: 'suspicious',
                score: null,
                requiredScore: null,
                action: null,
                reasonCodes: ['url.redirect_blocked_internal'],
                symbols: [],
                attempts: [
                  {
                    attempt: 1,
                    outcome: 'suspicious',
                    errorCode: null,
                    // Withheld for the url engine (cross-tenant caches, U6/U16).
                    durationMs: null,
                    at: '2026-11-05T08:00:04.000Z',
                  },
                ],
                durationMs: null,
                settingsVersion: 'url-map/1;p=abc;t=none',
                completedAt: '2026-11-05T08:00:04.000Z',
                urls: [
                  {
                    urlSeq: 0,
                    url: 'http://short-link.test/s/internal',
                    host: 'short-link.test',
                    unicodeHost: null,
                    registrableDomain: 'short-link.test',
                    hostKind: 'domain',
                    sources: { html_href: 1 },
                    flags: [],
                    verdict: 'suspicious',
                    reasonCodes: ['url.redirect_blocked_internal', 'url.shortened'],
                    reputation: [
                      { provider: 'local_feed', kind: 'url', status: 'clear', category: null },
                    ],
                    lookalike: [],
                    fetch: {
                      status: 'blocked',
                      error: null,
                      hops: 1,
                      chain: [
                        { host: 'short-link.test', status: 302, kind: 'initial', blocked: null },
                        { host: '127.0.0.1', status: null, kind: 'http', blocked: 'loopback' },
                      ],
                      finalUrl: null,
                      finalStatus: null,
                    },
                    landing: null,
                    dynamic: null,
                    rewritten: true,
                    clicks: {
                      total: 2,
                      lastDecision: 'warned',
                      lastAt: '2026-11-05T09:10:11.000Z',
                    },
                  },
                ],
                rewrite: {
                  status: 'rewritten',
                  skipReason: null,
                  linksRewritten: 1,
                  partsRewritten: 1,
                  dkimSigned: false,
                  expiresAt: '2026-12-05T08:00:04.000Z',
                },
              },
            ],
            risk: [],
            policy: null,
          },
        ],
      });
      // No cache outcome or per-URL duration reaches the tenant (cross-tenant caches, U16).
      expect(JSON.stringify(res.body.data[0].engines[2])).not.toMatch(
        /fetchCache|"cache"|"durationMs":\d/,
      );
    });

    it('answers the coded 404 for an unknown (or another organization’s) message', async () => {
      const res = await http()
        .get(`/api/v1/messages/${randomUUID()}/scans`)
        .set(apiKey)
        .expect(404);
      expect(res.body).toMatchObject({ statusCode: 404, code: 'message_not_found' });
    });

    it.each([
      ['not a uuid', '/api/v1/messages/not-a-uuid/scans'],
      ['limit above 20', `/api/v1/messages/${randomUUID()}/scans?limit=21`],
      ['bad cursor', `/api/v1/messages/${randomUUID()}/scans?cursor=bogus`],
      ['unknown query', `/api/v1/messages/${randomUUID()}/scans?x=1`],
    ])('400 for %s', async (_label, path) => {
      await http().get(path).set(apiKey).expect(400);
    });
  });

  describe('scan settings', () => {
    it('GET requires policy:read and lists the catalog engines with the platform settings', async () => {
      principalWith([MANAGE]);
      await http()
        .get('/api/v1/scan-settings')
        .set(await bearer())
        .expect(403);
      const res = await http().get('/api/v1/scan-settings').set(apiKey).expect(200);
      expect(res.body.data).toEqual([
        expect.objectContaining({
          engine: 'rspamd',
          required: true,
          tenantMayDisable: false,
          override: null,
          overrideApplied: false,
          version: 0,
          platform: expect.objectContaining({ spamScore: 6, suspiciousScore: 4 }),
          effective: expect.objectContaining({ spamScore: 6, phishingVerdict: 'suspicious' }),
        }),
        expect.objectContaining({
          engine: 'attachment',
          required: true,
          tenantMayDisable: false,
          override: null,
          platform: expect.objectContaining({ maxAttachmentBytes: 26_214_400, archiveMaxDepth: 3 }),
          effective: expect.objectContaining({
            allowedTypes: null,
            deniedTypeVerdict: 'suspicious',
          }),
        }),
        expect.objectContaining({
          engine: 'url',
          required: true,
          tenantMayDisable: false,
          override: null,
          platform: expect.objectContaining({ scanTimeFetch: 'suspicious' }),
          effective: expect.objectContaining({
            click: { suspicious: 'warn', unknown: 'warn', allowContinue: true },
          }),
        }),
        expect.objectContaining({
          engine: 'bec',
          required: true,
          tenantMayDisable: false,
          override: null,
          platform: expect.objectContaining({ suspiciousScore: 40, maliciousScore: 80 }),
          effective: expect.objectContaining({ history: { enabled: false, retentionDays: 365 } }),
        }),
        expect.objectContaining({
          engine: 'dlp',
          required: true,
          tenantMayDisable: false,
          override: null,
          platform: expect.objectContaining({ confidenceThreshold: 0.6, defaultPolicy: 'alert' }),
          effective: expect.objectContaining({
            inboundEnabled: false,
            evidence: { enabled: true, retentionDays: 30 },
          }),
        }),
        expect.objectContaining({
          engine: 'sandbox',
          mode: 'asynchronous',
          required: false,
          tenantMayDisable: true,
          override: null,
          platform: expect.objectContaining({
            tenantDefaultEnabled: false,
            maxSampleBytes: 26_214_400,
          }),
          effective: expect.objectContaining({ enabled: false, browserAnalysis: true }),
          feature: { attachmentSandbox: false },
          execution: 'disabled',
        }),
      ]);
      expect(res.body.note).toContain('SCAN_SETTINGS_CACHE_TTL_MS');
    });

    it('PUT and DELETE require scan:settings_manage (users and API keys)', async () => {
      principalWith([READ, POLICY_READ]);
      const body = { expectedVersion: 0, settings: { spamScore: 7 } };
      await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send(body)
        .expect(403);
      await http()
        .delete('/api/v1/scan-settings/rspamd?expectedVersion=1')
        .set(await bearer())
        .expect(403);
      await http().put('/api/v1/scan-settings/rspamd').set(apiKey).send(body).expect(403);
      apiKeyPermissions = new Set([MANAGE]);
      await http().put('/api/v1/scan-settings/rspamd').set(apiKey).send(body).expect(200);
      expect(settingsRows.create).toHaveBeenCalledTimes(1);
    });

    it('404 for an engine that is not registered, before any database access', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/clamav')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: {} })
        .expect(404);
      expect(res.body.code).toBe('scan_engine_not_found');
      await http()
        .delete('/api/v1/scan-settings/nope?expectedVersion=0')
        .set(await bearer())
        .expect(404);
      expect(transactions.run).not.toHaveBeenCalled();
    });

    it('422 scan_settings_invalid with every violation, before any database access', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { spamScore: 50, authFailureVerdict: 'reason_only', disabled: true },
        })
        .expect(422);
      expect(res.body).toMatchObject({ statusCode: 422, code: 'scan_settings_invalid' });
      expect(res.body.violations).toEqual([
        expect.objectContaining({ path: 'disabled', code: 'unknown_key' }),
      ]);
      const lowered = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { spamScore: 50, suspiciousScore: 3 } })
        .expect(422);
      expect(lowered.body.violations).toEqual([
        expect.objectContaining({ path: 'spamScore', code: 'out_of_bounds' }),
      ]);
      expect(transactions.run).not.toHaveBeenCalled();
    });

    it.each([
      [{ settings: {} }, 'expectedVersion'],
      [{ expectedVersion: -1, settings: {} }, 'expectedVersion'],
      [{ expectedVersion: 0, settings: 'x' }, 'settings'],
      [{ expectedVersion: 0, settings: {}, extra: 1 }, 'Unrecognized key'],
    ])('400 for body %j', async (body, text) => {
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
    });

    it('409 version_conflict when expectedVersion is not the current version', async () => {
      settingsRows.find.mockResolvedValueOnce({
        engine: 'rspamd',
        settings: { spamScore: 7 },
        version: 3,
        updatedAt: new Date(),
      });
      const res = await http()
        .put('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .send({ expectedVersion: 2, settings: { spamScore: 8 } })
        .expect(409);
      expect(res.body).toMatchObject({ code: 'version_conflict', currentVersion: 3 });
      await http()
        .delete('/api/v1/scan-settings/rspamd')
        .set(await bearer())
        .expect(400);
      expect(audit.record).not.toHaveBeenCalled();
    });
  });

  describe('sandbox settings (step 4.6 X17)', () => {
    it('PUT enabled=true without the plan feature is 409 feature_not_enabled, nothing written', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { enabled: true } })
        .expect(409);
      expect(res.body).toMatchObject({
        statusCode: 409,
        code: 'feature_not_enabled',
        feature: 'attachment_sandbox',
      });
      // The feature is read for the authenticated organization (scope), never from the client.
      expect(features.isEnabled).toHaveBeenCalledWith(1n, 'attachment_sandbox', {});
      expect(settingsRows.create).not.toHaveBeenCalled();
      expect(audit.record).not.toHaveBeenCalled();
    });

    it('PUT with the plan feature stores the opt-in (audited), and needs scan:settings_manage', async () => {
      principalWith([READ, POLICY_READ]);
      await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { enabled: true } })
        .expect(403);
      principalWith([READ, POLICY_READ, MANAGE]);
      features.isEnabled.mockResolvedValue(true);
      settingsRows.find.mockResolvedValueOnce(null).mockResolvedValueOnce({
        engine: 'sandbox',
        settings: { enabled: true, fileTypes: ['pdf', 'script_shell'] },
        version: 1,
        updatedAt: new Date('2026-11-08T09:00:00.000Z'),
      });
      const res = await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { enabled: true, fileTypes: ['pdf', 'script_shell'] },
        })
        .expect(200);
      expect(res.body).toMatchObject({
        engine: 'sandbox',
        version: 1,
        override: { enabled: true, fileTypes: ['pdf', 'script_shell'] },
        effective: { enabled: true, fileTypes: ['pdf', 'script_shell'] },
        feature: { attachmentSandbox: true },
        execution: 'disabled',
      });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'scan_settings.updated',
          resourceId: 'sandbox',
          metadata: expect.objectContaining({
            after: { enabled: true, fileTypes: ['pdf', 'script_shell'] },
          }),
        }),
        {},
      );
    });

    it('PUT refuses out-of-bounds sandbox settings (422) before any database access', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { fileTypes: ['zip'], maxSampleBytes: 0, backend: 'hardened-container' },
        })
        .expect(422);
      expect(res.body.code).toBe('scan_settings_invalid');
      expect(res.body.violations).toEqual([
        expect.objectContaining({ path: 'backend', code: 'unknown_key' }),
      ]);
      const bounds = await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { fileTypes: ['zip'], maxSampleBytes: 0 } })
        .expect(422);
      expect(bounds.body.violations).toEqual([
        expect.objectContaining({ path: 'fileTypes', code: 'out_of_bounds' }),
        expect.objectContaining({ path: 'maxSampleBytes', code: 'out_of_bounds' }),
      ]);
      expect(transactions.run).not.toHaveBeenCalled();
    });

    it('409 version_conflict before the feature check; DELETE resets without a feature', async () => {
      settingsRows.find.mockResolvedValueOnce({
        engine: 'sandbox',
        settings: { enabled: false },
        version: 2,
        updatedAt: new Date(),
      });
      const res = await http()
        .put('/api/v1/scan-settings/sandbox')
        .set(await bearer())
        .send({ expectedVersion: 1, settings: { enabled: true } })
        .expect(409);
      expect(res.body).toMatchObject({ code: 'version_conflict', currentVersion: 2 });
      settingsRows.find
        .mockResolvedValueOnce({
          engine: 'sandbox',
          settings: { enabled: true },
          version: 2,
          updatedAt: new Date(),
        })
        .mockResolvedValueOnce({
          engine: 'sandbox',
          settings: {},
          version: 3,
          updatedAt: new Date(),
        });
      const reset = await http()
        .delete('/api/v1/scan-settings/sandbox?expectedVersion=2')
        .set(await bearer())
        .expect(200);
      expect(reset.body).toMatchObject({ engine: 'sandbox', version: 3, override: null });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'scan_settings.reset', resourceId: 'sandbox' }),
        {},
      );
    });
  });

  describe('sandbox results on GET /messages/{messageId}/scans (step 4.6 X18)', () => {
    const completed = {
      ...pendingSubmission,
      status: 'completed',
      sandboxVerdict: 'unknown',
      sandboxReasonCodes: ['sandbox.static_only', 'sandbox.static.script_download_cradle'],
      completedAt: new Date('2026-11-05T08:03:07.321Z'),
      analysisId: 66n,
      externalRef: SANDBOX_TASK,
    };
    const analysisRow = {
      id: 66n,
      publicId: SANDBOX_TASK,
      report: {
        v: 1,
        findings: [{ code: 'static.script_download_cradle', severity: 'high', count: 1 }],
        indicators: { dns: ['dl.example'], httpHosts: [], tlsSni: [], ips: [] },
        networkTotals: { dns: 1, http: 0, tls: 0, connections: 0 },
        processes: { count: 0, images: [] },
        droppedFiles: [],
        deniedWrites: 0,
        limitsHit: [],
        browser: null,
      },
      backend: 'static',
      backendVersion: 'sandbox-static/1',
      isolation: 'process',
      executed: false,
      controllerVersion: '0.1.0',
      analyzerVersion: 'sandbox-static/1',
      mapVersion: 'sandbox-map/1',
    };

    it('shows the submission outcome on the attachment and the report on the sandbox entry', async () => {
      sandboxState.submissions = [completed];
      sandboxState.extraEngineRows = [sandboxEngineRow];
      sandboxReads.analyses.mockResolvedValueOnce([analysisRow]);
      sandboxReads.artifacts.mockResolvedValueOnce([
        {
          analysisId: 66n,
          seq: 0,
          kind: 'static_report',
          contentType: 'application/json',
          sizeBytes: 812,
          plainSha256: 'e'.repeat(64),
          expiresAt: new Date('2026-12-05T08:03:07.111Z'),
          purgedAt: null,
        },
      ]);
      const res = await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(apiKey)
        .expect(200);
      // Analyses are read only by the ids of this organization's own submissions.
      expect(sandboxReads.analyses).toHaveBeenCalledWith([66n]);
      const round = res.body.data[0];
      // The asynchronous sandbox final never changes the round verdict.
      expect(round.verdict).toBe('spam');
      const attachment = round.engines.find((e: { engine: string }) => e.engine === 'attachment');
      expect(attachment.attachments[0].sandbox).toEqual({
        submissionId: '31',
        status: 'completed',
        skipReason: null,
        verdict: 'unknown',
        reasonCodes: ['sandbox.static_only', 'sandbox.static.script_download_cradle'],
        executed: false,
        isolation: 'process',
        completedAt: '2026-11-05T08:03:07.000Z',
      });
      const sandbox = round.engines.find((e: { engine: string }) => e.engine === 'sandbox');
      expect(sandbox).toMatchObject({
        engine: 'sandbox',
        outcome: 'unknown',
        symbols: [],
        durationMs: null,
        completedAt: '2026-11-05T08:03:07.000Z',
        attempts: [{ attempt: 1, durationMs: null, at: '2026-11-05T08:03:07.000Z' }],
        submissions: [
          {
            submissionId: '31',
            partIndex: 1,
            sha256: 'd'.repeat(64),
            status: 'completed',
            verdict: 'unknown',
            executed: false,
            isolation: 'process',
            backend: 'static',
            versions: {
              controller: '0.1.0',
              backend: 'sandbox-static/1',
              analyzer: 'sandbox-static/1',
              map: 'sandbox-map/1',
            },
            findings: [{ code: 'static.script_download_cradle', severity: 'high', count: 1 }],
            indicators: { dns: ['dl.example'], httpHosts: [], tlsSni: [], ips: [] },
            artifacts: [
              {
                seq: 0,
                kind: 'static_report',
                contentType: 'application/json',
                sizeBytes: 812,
                sha256: 'e'.repeat(64),
                expiresAt: '2026-12-05T00:00:00.000Z',
                purged: false,
              },
            ],
          },
        ],
      });
      // No analysis id, reuse flag, analysis timing or object key reaches the tenant.
      const json = JSON.stringify(sandbox);
      expect(json).not.toContain(SANDBOX_TASK);
      expect(json).not.toMatch(
        /analysisId|reuse|objectKey|wrappedKey|dispatchedAt|"durationMs":\d/,
      );
    });

    it('shows a skipped submission (tenant not opted in) without reading any analysis', async () => {
      sandboxState.submissions = [
        {
          ...pendingSubmission,
          status: 'skipped',
          skipReason: 'tenant_disabled',
          sandboxReasonCodes: ['sandbox.tenant_disabled'],
          completedAt: new Date('2026-11-05T08:00:06.500Z'),
        },
      ];
      sandboxState.extraEngineRows = [
        {
          ...sandboxEngineRow,
          outcome: 'skipped',
          engineVersion: 'sandbox-engine/1',
          reasonCodes: ['sandbox.tenant_disabled'],
        },
      ];
      const res = await http()
        .get(`/api/v1/messages/${knownMessage.publicId}/scans`)
        .set(apiKey)
        .expect(200);
      expect(sandboxReads.analyses).not.toHaveBeenCalled();
      const sandbox = res.body.data[0].engines.find(
        (e: { engine: string }) => e.engine === 'sandbox',
      );
      expect(sandbox.outcome).toBe('skipped');
      expect(sandbox.submissions).toEqual([
        expect.objectContaining({
          status: 'skipped',
          skipReason: 'tenant_disabled',
          verdict: null,
          executed: null,
          findings: [],
          artifacts: [],
        }),
      ]);
    });

    it('needs message:read only (no new permission); another organization’s message is 404', async () => {
      apiKeyPermissions = new Set([POLICY_READ]);
      await http().get(`/api/v1/messages/${knownMessage.publicId}/scans`).set(apiKey).expect(403);
      apiKeyPermissions = new Set([READ]);
      await http().get(`/api/v1/messages/${knownMessage.publicId}/scans`).set(apiKey).expect(200);
      await http().get(`/api/v1/messages/${randomUUID()}/scans`).set(apiKey).expect(404);
    });
  });

  describe('POST /platform/organizations/{organizationId}/messages/{messageId}/scan-training', () => {
    beforeEach(() => principalWith([TRAIN], 'platform'));

    it('refuses API keys, sessions without MFA and users without the permission', async () => {
      apiKeyPermissions = new Set([TRAIN]);
      await http().post(trainUrl()).set(apiKey).send(learn).expect(403);
      await http()
        .post(trainUrl())
        .set(await bearer(['pwd']))
        .send(learn)
        .expect(403);
      principalWith([READ, POLICY_READ, MANAGE], 'platform');
      await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(403);
      // A tenant administrator never holds the platform permission.
      principalWith([READ, POLICY_READ, MANAGE, 'message:rescan']);
      await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(403);
      expect(training.findOrganization).not.toHaveBeenCalled();
    });

    it.each([
      [{ operation: 'fuzzy_add', reason: 'x' }, 'fuzzyFlag'],
      [{ ...learn, fuzzyFlag: 'spam' }, 'fuzzyFlag'],
      [{ operation: 'learn', reason: 'x' }, 'operation'],
      [{ operation: 'learn_ham' }, 'reason'],
      [{ ...learn, reason: 'x'.repeat(513) }, 'reason'],
    ])('400 for body %j', async (body, text) => {
      const res = await http()
        .post(trainUrl())
        .set(await bearer())
        .send(body)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
    });

    it('404 for an unknown organization; 503 rspamd_unavailable without a controller', async () => {
      const missing = await http()
        .post(trainUrl(randomUUID()))
        .set(await bearer())
        .send(learn)
        .expect(404);
      expect(missing.body.code).toBe('organization_not_found');
      await http()
        .post(trainUrl('not-a-uuid'))
        .set(await bearer())
        .send(learn)
        .expect(400);
      const unavailable = await http()
        .post(trainUrl())
        .set(await bearer())
        .send(learn)
        .expect(503);
      expect(unavailable.body.code).toBe('rspamd_unavailable');
      // The refused call is audited with its outcome; no timeline event.
      expect(audit.record).toHaveBeenCalledTimes(1);
      expect(audit.record.mock.calls[0]![0]).toMatchObject({
        action: 'scan_training.learn_spam',
        resourceType: 'message',
        resourceId: knownMessage.publicId,
        metadata: { operation: 'learn_spam', outcome: 'rspamd_unavailable' },
      });
      expect(training.insertTrainingEvent).not.toHaveBeenCalled();
    });

    it('allows 60 calls per caller per minute (429 after)', async () => {
      const auth = await bearer();
      for (let i = 0; i < 60; i += 1) {
        await http().post(trainUrl(randomUUID())).set(auth).send(learn).expect(404);
      }
      await http().post(trainUrl(randomUUID())).set(auth).send(learn).expect(429);
    });
  });

  describe('attachment settings (step 4.2 A8)', () => {
    it('PUT validates an attachment override against the platform bounds (422 with violations)', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/attachment')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { allowedTypes: ['pe_executable'], maxAttachmentBytes: 99_000_000, zip: 1 },
        })
        .expect(422);
      expect(res.body.code).toBe('scan_settings_invalid');
      expect(res.body.violations.map((v: { path: string }) => v.path).sort()).toEqual(['zip']);
      expect(settingsRows.find).not.toHaveBeenCalled();
    });

    it('PUT stores a valid attachment override (audited)', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/attachment')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { deniedTypes: ['zip'] } })
        .expect(200);
      expect(res.body).toMatchObject({ engine: 'attachment' });
      expect(settingsRows.create).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({ engine: 'attachment', settings: { deniedTypes: ['zip'] } }),
      );
      expect(audit.record.mock.calls[0]![0]).toMatchObject({
        action: 'scan_settings.updated',
        resourceId: 'attachment',
      });
    });
  });

  describe('platform known-threat hashes (step 4.2 A16, A17)', () => {
    const url = '/api/v1/platform/threat-hashes';
    const body = { sha256: 'e'.repeat(64), severity: 'high', reason: 'campaign' };
    beforeEach(() => principalWith([THREAT_INTEL], 'platform'));

    it('refuses API keys, sessions without MFA, users without the permission and tenants', async () => {
      apiKeyPermissions = new Set([THREAT_INTEL]);
      await http().get(url).set(apiKey).expect(403);
      await http()
        .post(url)
        .set(await bearer(['pwd']))
        .send(body)
        .expect(403);
      principalWith([TRAIN, RESCAN], 'platform');
      await http()
        .delete(`${url}/${SHA}?reason=x`)
        .set(await bearer())
        .expect(403);
      principalWith([READ, POLICY_READ, MANAGE]);
      await http()
        .get(url)
        .set(await bearer())
        .expect(403);
      expect(hashes.list).not.toHaveBeenCalled();
      expect(hashes.create).not.toHaveBeenCalled();
    });

    it.each([
      [{ ...body, sha256: 'E'.repeat(64) }, 'sha256'],
      [{ ...body, sha256: 'e'.repeat(63) }, 'sha256'],
      [{ ...body, md5: 'x' }, 'md5'],
      [{ ...body, severity: 'severe' }, 'severity'],
      [{ ...body, family: 'f'.repeat(129) }, 'family'],
      [{ ...body, reason: '' }, 'reason'],
      [{ ...body, reason: 'r'.repeat(513) }, 'reason'],
      [{ ...body, expiresAt: '2020-01-01T00:00:00.000Z' }, 'expiresAt'],
      [{ ...body, source: 'feed:x' }, 'source'],
    ])('400 for body %j', async (input, text) => {
      const res = await http()
        .post(url)
        .set(await bearer())
        .send(input)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
      expect(hashes.create).not.toHaveBeenCalled();
    });

    it('adds (201, audited), refuses a listed hash (409), lists and deletes (204, 404)', async () => {
      const created = await http()
        .post(url)
        .set(await bearer())
        .send(body)
        .expect(201);
      expect(created.body).toMatchObject({ sha256: 'e'.repeat(64), source: 'analyst' });
      expect(audit.record.mock.calls[0]![0]).toMatchObject({ action: 'threat_hash.added' });
      const exists = await http()
        .post(url)
        .set(await bearer())
        .send({ ...body, sha256: SHA })
        .expect(409);
      expect(exists.body.code).toBe('hash_exists');
      const list = await http()
        .get(`${url}?limit=5`)
        .set(await bearer())
        .expect(200);
      expect(list.body.data[0]).toMatchObject({ sha256: SHA, addedByUserId: ids.user });
      await http()
        .delete(`${url}/${SHA}?reason=false%20positive`)
        .set(await bearer())
        .expect(204);
      expect(audit.record.mock.calls.at(-1)![0]).toMatchObject({
        action: 'threat_hash.removed',
        metadata: { reason: 'false positive', before: expect.objectContaining({ sha256: SHA }) },
      });
      const missing = await http()
        .delete(`${url}/${'f'.repeat(64)}?reason=x`)
        .set(await bearer())
        .expect(404);
      expect(missing.body.code).toBe('threat_hash_not_found');
      await http()
        .delete(`${url}/${SHA}`)
        .set(await bearer())
        .expect(400);
    });

    it('allows 60 calls per caller per minute (429 after)', async () => {
      const auth = await bearer();
      for (let i = 0; i < 60; i += 1) await http().get(url).set(auth).expect(200);
      await http().get(url).set(auth).expect(429);
    });
  });

  describe('url settings (step 4.3 U13)', () => {
    it('PUT normalizes domains and stores the override (audited scan_settings.updated)', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/url')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { allowedDomains: ['Partner.Example.'], click: { unknown: 'block' } },
        })
        .expect(200);
      expect(res.body).toMatchObject({ engine: 'url' });
      expect(settingsRows.create).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        expect.objectContaining({
          engine: 'url',
          settings: { allowedDomains: ['partner.example'], click: { unknown: 'block' } },
        }),
      );
      expect(audit.record.mock.calls[0]![0]).toMatchObject({
        action: 'scan_settings.updated',
        resourceId: 'url',
      });
    });

    it('PUT refuses public suffixes, conflicts and out-of-bounds values (422) without a write', async () => {
      const res = await http()
        .put('/api/v1/scan-settings/url')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { blockedDomains: ['co.uk', 'github.io'], scanTimeFetch: 'all' },
        })
        .expect(422);
      expect(res.body.code).toBe('scan_settings_invalid');
      expect(res.body.violations.map((v: { path: string }) => v.path)).toEqual([
        'blockedDomains.0',
        'blockedDomains.1',
      ]);
      const conflict = await http()
        .put('/api/v1/scan-settings/url')
        .set(await bearer())
        .send({
          expectedVersion: 0,
          settings: { allowedDomains: ['a.example'], blockedDomains: ['a.example'] },
        })
        .expect(422);
      expect(conflict.body.violations[0]).toMatchObject({
        path: 'blockedDomains',
        code: 'invalid',
      });
      const bounds = await http()
        .put('/api/v1/scan-settings/url')
        .set(await bearer())
        .send({ expectedVersion: 0, settings: { rewrite: { expiryDays: 365 } } })
        .expect(422);
      expect(bounds.body.violations[0]).toMatchObject({
        path: 'rewrite.expiryDays',
        code: 'out_of_bounds',
      });
      expect(settingsRows.create).not.toHaveBeenCalled();
      expect(transactions.run).not.toHaveBeenCalled();
    });
  });

  describe('platform threat indicators (step 4.3 U16)', () => {
    const url = '/api/v1/platform/threat-indicators';
    const body = {
      type: 'domain',
      value: 'Evil-New.Example.',
      severity: 'high',
      category: 'phishing',
      reason: 'campaign',
    };
    beforeEach(() => principalWith([THREAT_INTEL], 'platform'));

    it('refuses API keys, sessions without MFA, users without the permission and tenants', async () => {
      apiKeyPermissions = new Set([THREAT_INTEL]);
      await http().get(url).set(apiKey).expect(403);
      await http()
        .post(url)
        .set(await bearer(['pwd']))
        .send(body)
        .expect(403);
      principalWith([TRAIN, RESCAN], 'platform');
      await http()
        .delete(`${url}/21?reason=x`)
        .set(await bearer())
        .expect(403);
      principalWith([READ, POLICY_READ, MANAGE]);
      await http()
        .get(url)
        .set(await bearer())
        .expect(403);
      expect(indicators.list).not.toHaveBeenCalled();
      expect(indicators.create).not.toHaveBeenCalled();
    });

    it.each([
      [{ ...body, type: 'email' }, 'type'],
      [{ ...body, value: '' }, 'value'],
      [{ ...body, value: 'co.uk' }, 'value'],
      [{ ...body, value: '10.0.0.1' }, 'value'],
      [{ ...body, type: 'ip', value: 'evil.example' }, 'value'],
      [{ ...body, type: 'url', value: 'javascript:alert(1)' }, 'value'],
      [{ ...body, severity: 'severe' }, 'severity'],
      [{ ...body, category: 'nasty' }, 'category'],
      [{ ...body, reason: '' }, 'reason'],
      [{ ...body, expiresAt: '2020-01-01T00:00:00.000Z' }, 'expiresAt'],
      [{ ...body, source: 'feed:x' }, 'source'],
    ])('400 for body %j', async (input, text) => {
      const res = await http()
        .post(url)
        .set(await bearer())
        .send(input)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
      expect(indicators.create).not.toHaveBeenCalled();
    });

    it('adds normalized (201, audited), 409 for a listed value, lists and deletes (204, 404)', async () => {
      const created = await http()
        .post(url)
        .set(await bearer())
        .send(body)
        .expect(201);
      expect(created.body).toMatchObject({
        id: '23',
        type: 'domain',
        value: 'evil-new.example',
        source: 'analyst',
      });
      expect(indicators.create).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          value: 'evil-new.example',
          valueSha256: createHash('sha256').update('evil-new.example').digest('hex'),
        }),
      );
      expect(audit.record.mock.calls[0]![0]).toMatchObject({
        action: 'threat_indicator.added',
        organizationId: null,
      });
      const exists = await http()
        .post(url)
        .set(await bearer())
        .send({ ...body, value: 'LISTED.example' })
        .expect(409);
      expect(exists.body).toMatchObject({ code: 'indicator_exists', id: '22' });
      const list = await http()
        .get(`${url}?limit=5&type=domain&value=Evil.Example`)
        .set(await bearer())
        .expect(200);
      expect(list.body.data[0]).toMatchObject({ id: '21', value: 'evil.example' });
      expect(indicators.list).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'domain',
          valueSha256: createHash('sha256').update('evil.example').digest('hex'),
        }),
      );
      await http()
        .get(`${url}?value=evil.example`)
        .set(await bearer())
        .expect(400);
      await http()
        .delete(`${url}/21?reason=false%20positive`)
        .set(await bearer())
        .expect(204);
      expect(audit.record.mock.calls.at(-1)![0]).toMatchObject({
        action: 'threat_indicator.removed',
        metadata: {
          reason: 'false positive',
          before: expect.objectContaining({ id: '21', value: 'evil.example' }),
        },
      });
      const missing = await http()
        .delete(`${url}/99?reason=x`)
        .set(await bearer())
        .expect(404);
      expect(missing.body.code).toBe('threat_indicator_not_found');
      await http()
        .delete(`${url}/21`)
        .set(await bearer())
        .expect(400);
      await http()
        .delete(`${url}/abc?reason=x`)
        .set(await bearer())
        .expect(400);
    });

    it('allows 60 calls per caller per minute (429 after)', async () => {
      const auth = await bearer();
      for (let i = 0; i < 60; i += 1) await http().get(url).set(auth).expect(200);
      await http().get(url).set(auth).expect(429);
    });
  });

  describe('platform attachment rescan jobs (step 4.2 A13)', () => {
    const url = '/api/v1/platform/attachment-rescans';
    const body = { windowHours: 24, reason: 'new signatures' };
    beforeEach(() => principalWith([RESCAN], 'platform'));

    it('refuses API keys, sessions without MFA and users without the permission', async () => {
      apiKeyPermissions = new Set([RESCAN]);
      await http().post(url).set(apiKey).send(body).expect(403);
      await http()
        .post(url)
        .set(await bearer(['pwd']))
        .send(body)
        .expect(403);
      principalWith([THREAT_INTEL], 'platform');
      await http()
        .get(url)
        .set(await bearer())
        .expect(403);
      expect(rescans.create).not.toHaveBeenCalled();
    });

    it.each([
      [{ ...body, windowHours: 0 }, 'windowHours'],
      [{ ...body, windowHours: 169 }, 'windowHours'],
      [{ ...body, states: ['delivered'] }, 'states'],
      [{ ...body, states: [] }, 'states'],
      [{ ...body, organizationId: 'x' }, 'organizationId'],
      [{ ...body, maxMessages: 0 }, 'maxMessages'],
      [{ ...body, maxMessages: 5001 }, 'maxMessages'],
      [{ windowHours: 1 }, 'reason'],
    ])('400 for body %j', async (input, text) => {
      const res = await http()
        .post(url)
        .set(await bearer())
        .send(input)
        .expect(400);
      expect(JSON.stringify(res.body.message)).toContain(text);
      expect(rescans.create).not.toHaveBeenCalled();
    });

    it('a dry run answers 200 with the estimate; a request 202 with the job (audited)', async () => {
      const dry = await http()
        .post(url)
        .set(await bearer())
        .send({ ...body, dryRun: true })
        .expect(200);
      expect(dry.body).toMatchObject({ dryRun: true, estimatedMessages: 7, maxMessages: 5000 });
      expect(rescans.create).not.toHaveBeenCalled();
      const created = await http()
        .post(url)
        .set(await bearer())
        .send({ ...body, organizationId: ids.org, states: ['scanned'] })
        .expect(202);
      expect(created.body).toEqual({ jobId: JOB_ID, status: 'pending', estimatedMessages: 7 });
      expect(audit.record.mock.calls.at(-1)![0]).toMatchObject({
        action: 'attachment_rescan.requested',
        organizationId: 1n,
      });
      const unknown = await http()
        .post(url)
        .set(await bearer())
        .send({ ...body, organizationId: randomUUID() })
        .expect(404);
      expect(unknown.body.code).toBe('organization_not_found');
    });

    it('lists, reads and cancels jobs (404 unknown, 409 not cancellable)', async () => {
      const list = await http()
        .get(url)
        .set(await bearer())
        .expect(200);
      expect(list.body.data[0]).toMatchObject({ jobId: JOB_ID, status: 'pending' });
      await http()
        .get(`${url}/${JOB_ID}`)
        .set(await bearer())
        .expect(200);
      const missing = await http()
        .get(`${url}/${randomUUID()}`)
        .set(await bearer())
        .expect(404);
      expect(missing.body.code).toBe('rescan_job_not_found');
      await http()
        .post(`${url}/${JOB_ID}/cancel`)
        .set(await bearer())
        .expect(200);
      expect(audit.record.mock.calls.at(-1)![0]).toMatchObject({
        action: 'attachment_rescan.cancelled',
      });
      rescans.cancel.mockResolvedValueOnce(false);
      rescans.findOnWriter
        .mockResolvedValueOnce(jobRow('completed'))
        .mockResolvedValueOnce(jobRow('completed'));
      const conflict = await http()
        .post(`${url}/${JOB_ID}/cancel`)
        .set(await bearer())
        .send({ reason: 'late' })
        .expect(409);
      expect(conflict.body).toMatchObject({
        code: 'rescan_job_not_cancellable',
        status: 'completed',
      });
    });

    it('allows 10 calls per caller per minute (429 after)', async () => {
      const auth = await bearer();
      for (let i = 0; i < 10; i += 1) await http().get(url).set(auth).expect(200);
      await http().get(url).set(auth).expect(429);
    });
  });
});
