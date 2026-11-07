/**
 * Step 4.5 DLP routes (D9, D16, D17, D20, D21) over HTTP with MySQL, Redis and S3 stubbed:
 * authorization (401, 403 per permission, MFA and users only where D21 says, API keys where
 * allowed), validation before any database access (400 with the D9/D8 codes), the coded
 * conflicts, the pattern test (masked matches, 30/min, **the sample and the pattern never in
 * any log line, audit call or response**), the evidence door (audit row before the object is
 * fetched, `Cache-Control: no-store`, 410s, a forced decryption failure audited twice), the
 * scans read API `dlp` section withheld without `dlp:read` and the `dlp` scan settings. The same
 * routes against the real MySQL and MinIO run in integration/dlp.test.ts.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  NestPinoLogger,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { sealEvidence } from '@email-gateway/dlp';
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
import { NO_DLP_IDS } from '../src/modules/dlp/domain/dlp-result';
import { DlpConfigRepository } from '../src/modules/dlp/repositories/dlp-config.repository';
import { DlpResultsRepository } from '../src/modules/dlp/repositories/dlp-results.repository';
import { DlpEvidenceStore } from '../src/modules/dlp/services/dlp-evidence-store';
import { MessageLifecycleReadRepository } from '../src/modules/messages/repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../src/modules/messages/repositories/message-scans-read.repository';
import { ScanSettingsRepository } from '../src/modules/scans/repositories/scan-settings.repository';
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
};

const READ = 'dlp:read';
const MANAGE = 'dlp:manage';
const EVIDENCE = 'dlp:evidence_read';
const COMPLIANCE = 'dlp:compliance_manage';
const ids = { user: randomUUID(), org: randomUUID(), session: randomUUID() };
const NOW = new Date();
const POLICY_ID = '0190f0f0-0000-7000-8000-0000000000a1';
const RULE_ID = '0190f0f0-0000-7000-8000-0000000000b1';
const PATTERN_ID = '0190f0f0-0000-7000-8000-0000000000c1';
const MESSAGE_ID = '0190f0f0-0000-7000-8000-0000000000f1';
const SCAN = '900';

/** Marker strings that must never reach a log line, an audit call or an error body. */
const SAMPLE_MARKER = 'SAMPLE-MARKER-7f3a';
const PATTERN_MARKER = 'PATMARK';

let snapshot: PrincipalSnapshot;
function principalWith(permissions: string[]): void {
  snapshot = {
    orgVersion: 0,
    userVersion: '',
    user: { id: '10', publicId: ids.user, status: 'active', deleted: false, mfaEnabled: true },
    org: {
      id: '1',
      publicId: ids.org,
      kind: 'customer',
      status: 'active',
      deleted: false,
      mfaRequired: false,
    },
    permissions,
  };
}

let apiKeyPermissions = new Set<string>([READ]);
const apiKeyPrincipal = (): ApiKeyPrincipal => ({
  kind: 'api_key',
  apiKeyId: 5n,
  apiKeyPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: ids.org,
  permissions: apiKeyPermissions,
});

const base = {
  organizationId: 1n,
  version: 1,
  createdAt: NOW,
  updatedAt: NOW,
  createdBy: { publicId: ids.user },
  updatedBy: null,
};
const policyRow = {
  ...base,
  id: 31n,
  publicId: POLICY_ID,
  name: 'Card data outbound',
  description: null,
  enabled: true,
  mode: 'enforce' as const,
  priority: 100,
  directions: ['outbound', 'internal'],
  _count: { rules: 1 },
};
const ruleRow = {
  ...base,
  id: 41n,
  publicId: RULE_ID,
  policyId: 31n,
  policy: { publicId: POLICY_ID },
  name: 'Cards to external',
  enabled: true,
  priority: 10,
  conditions: { selectors: { categories: ['payment_card'] }, recipients: { externalOnly: true } },
  action: 'quarantine' as const,
};
const patternRow = {
  ...base,
  id: 17n,
  publicId: PATTERN_ID,
  name: 'Employee id',
  pattern: 'EMP-[0-9]{6}',
  caseInsensitive: false,
  validator: 'none' as const,
  contextKeywords: ['employee'],
  requireContext: false,
  severity: 'medium' as const,
  baseConfidence: { toNumber: () => 0.8 },
  maskStyle: 'last4' as const,
  enabled: true,
};
const evidenceKey = TEST_DOMAIN_ENV.DLP_EVIDENCE_KEY!;
const message = { id: 77n, publicId: MESSAGE_ID, receivedAt: new Date('2026-11-07T10:00:00Z') };
const evidenceDocument = {
  format: 'dlp-evidence/1',
  textDerivationVersion: 'dlp-text/1',
  extractorVersion: 'dlp-extract/1',
  aadhaar: 'disabled',
  matches: [
    {
      detector: 'NI1',
      code: 'dlp.national_id.india_pan',
      source: { kind: 'body_text', segment: 0 },
      start: 5,
      end: 15,
      value: 'ABCPD1234E',
      context: { before: 'PAN: ', after: ' thanks' },
    },
  ],
  dropped: 0,
};

describe('step 4.5 DLP routes (e2e, dependencies stubbed)', () => {
  let app: INestApplication;
  const kv = new InMemoryKeyValueStore();
  const tokens = new TokenService(loadApiConfig(env));
  const http = () => request(app.getHttpServer());
  const logLines: string[] = [];
  const sealed = sealEvidence({ current: evidenceKey }, JSON.stringify(evidenceDocument), {
    organizationId: '1',
    messageId: '77',
    scanId: SCAN,
  });
  const evidenceRow = (overrides: Record<string, unknown> = {}) => ({
    id: 5n,
    receivedAt: message.receivedAt,
    organizationId: 1n,
    messageId: 77n,
    scanId: 900n,
    objectKey: 'org/1/dlp-evidence/2026/11/900-0190f0f0.bin',
    objectSha256: sealed.sha256,
    objectSizeBytes: sealed.size,
    wrappedKey: sealed.wrappedKey,
    keyId: sealed.keyId,
    algorithm: 'dlp-evidence/1',
    matchCount: 1,
    expiresAt: new Date(Date.now() + 86_400_000),
    purgedAt: null,
    purgeReason: null,
    ...overrides,
  });
  const config = {
    lockOrganization: vi.fn(() => Promise.resolve()),
    listPolicies: vi.fn(() => Promise.resolve([policyRow])),
    findPolicy: vi.fn((_s: unknown, id: string) =>
      Promise.resolve(id === POLICY_ID ? policyRow : null),
    ),
    rulesOf: vi.fn(() => Promise.resolve([ruleRow])),
    findPolicyForUpdate: vi.fn((_t: unknown, _s: unknown, id: string) =>
      Promise.resolve(id === POLICY_ID ? policyRow : null),
    ),
    policyByName: vi.fn(() => Promise.resolve(null as unknown)),
    countPolicies: vi.fn(() => Promise.resolve(0)),
    createPolicy: vi.fn(() => Promise.resolve(policyRow)),
    updatePolicy: vi.fn(() => Promise.resolve(true)),
    policyById: vi.fn(() => Promise.resolve(policyRow)),
    rulesOfForUpdate: vi.fn(() => Promise.resolve([ruleRow])),
    deletePolicy: vi.fn(() => Promise.resolve(1)),
    countExceptionsTargeting: vi.fn(() => Promise.resolve(0)),
    findRuleForUpdate: vi.fn(() => Promise.resolve(ruleRow)),
    ruleByName: vi.fn(() => Promise.resolve(null)),
    countRules: vi.fn(() => Promise.resolve(0)),
    createRule: vi.fn(() => Promise.resolve(ruleRow)),
    existingPatternIds: vi.fn((_t: unknown, _s: unknown, list: string[]) =>
      Promise.resolve(new Set(list.filter((id) => id === PATTERN_ID))),
    ),
    existingDictionaryIds: vi.fn(() => Promise.resolve(new Set<string>())),
    listPatterns: vi.fn(() => Promise.resolve([patternRow])),
    patternByName: vi.fn(() => Promise.resolve(null)),
    countPatterns: vi.fn(() => Promise.resolve(0)),
    createPattern: vi.fn(() => Promise.resolve(patternRow)),
    findPatternForUpdate: vi.fn(() => Promise.resolve(patternRow)),
    allRuleConditions: vi.fn(() =>
      Promise.resolve([
        { publicId: RULE_ID, conditions: { selectors: { customPatternIds: [PATTERN_ID] } } },
      ]),
    ),
    deletePattern: vi.fn(() => Promise.resolve()),
    dictionaryByName: vi.fn(() => Promise.resolve(null)),
    countDictionaries: vi.fn(() => Promise.resolve(0)),
    createDictionary: vi.fn(),
    findCompliance: vi.fn(() => Promise.resolve(null)),
    findComplianceForUpdate: vi.fn(() => Promise.resolve(null)),
  };
  const results = {
    findMessage: vi.fn((_t: unknown, _s: unknown, id: string) =>
      Promise.resolve(id === MESSAGE_ID ? message : null),
    ),
    scanExists: vi.fn(() => Promise.resolve(true)),
    evidenceOf: vi.fn(() => Promise.resolve(evidenceRow() as unknown)),
    shred: vi.fn((_t: unknown, _s: unknown, rows: unknown[]) => Promise.resolve(rows.length)),
    clearObjectKey: vi.fn(() => Promise.resolve()),
    purgeBatch: vi.fn(() => Promise.resolve([] as unknown[])),
    listIncidents: vi.fn(() => Promise.resolve([] as unknown[])),
    messagePublicIds: vi.fn(() => Promise.resolve(new Map<string, string>())),
    publicIds: vi.fn(() => Promise.resolve(NO_DLP_IDS)),
  };
  const store = {
    read: vi.fn(() => Promise.resolve(Buffer.from(sealed.object))),
    delete: vi.fn(() => Promise.resolve()),
  };
  const scanReads = {
    rounds: vi.fn(() =>
      Promise.resolve([
        {
          id: 900n,
          lifecycleRound: 0,
          scanKind: 'initial',
          status: 'completed',
          scanVerdict: 'suspicious',
          reasonCodes: [],
          requiredEngines: ['dlp'],
          startedAt: null,
          completedAt: null,
          deadlineAt: null,
        },
      ]),
    ),
    engineResults: vi.fn(() =>
      Promise.resolve([
        {
          scanId: 900n,
          engine: 'dlp',
          engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
          outcome: 'suspicious',
          score: null,
          requiredScore: null,
          action: null,
          reasonCodes: ['dlp.action.quarantine', 'dlp.payment_card.number'],
          errorCode: null,
          settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
          durationMs: 120,
          evidence: null,
          attempt: 1,
          isFinal: true,
          completedAt: NOW,
        },
      ]),
    ),
    authResults: () => Promise.resolve([]),
    attachmentResults: () => Promise.resolve([]),
    attachmentParts: () => Promise.resolve([]),
    sandboxSubmissions: () => Promise.resolve([]),
    dlpResults: vi.fn(() =>
      Promise.resolve([
        {
          scanId: 900n,
          engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
          rulesVersion: 'dlp-map/1',
          settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
          policyVersion: 'pol/1;h=0123456789ab',
          extractorVersion: 'dlp-extract/1',
          verdict: 'suspicious',
          action: 'quarantine',
          actionSource: 'tenant_policy',
          matchedPolicyId: 31n,
          matchedRuleId: 41n,
          coverage: 'complete',
          coverageDetail: [
            { source: 'body_text', format: 'text', status: 'scanned', reasons: [], chars: 90 },
          ],
          categories: [
            { category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 0.95 },
          ],
          findings: [
            {
              detector: 'PC1',
              code: 'dlp.payment_card.number',
              category: 'payment_card',
              severity: 'high',
              confidence: 0.95,
              count: 1,
              capped: false,
              sources: [{ kind: 'body_text' }],
              masked: ['************0366'],
            },
          ],
          policy: {
            winner: { policyId: '31', ruleId: '41' },
            matched: [{ policyId: '31', ruleId: '41', action: 'quarantine', mode: 'enforce' }],
            exceptionsApplied: [],
          },
          evidenceStatus: 'stored',
        },
      ]),
    ),
    dlpEvidence: vi.fn(() =>
      Promise.resolve([
        { scanId: 900n, expiresAt: new Date('2026-12-07T10:00:00Z'), purgedAt: null },
      ]),
    ),
    dlpPublicIds: vi.fn(() =>
      Promise.resolve({
        ...NO_DLP_IDS,
        policy: { byInternal: new Map([['31', POLICY_ID]]), known: new Set([POLICY_ID]) },
        rule: { byInternal: new Map([['41', RULE_ID]]), known: new Set([RULE_ID]) },
      }),
    ),
  };
  const settingsRows = {
    list: vi.fn(() => Promise.resolve([] as unknown[])),
    find: vi.fn(() => Promise.resolve(null as unknown)),
    create: vi.fn(() => Promise.resolve({})),
    replaceIfVersion: vi.fn(() => Promise.resolve(true)),
  };
  const audit = {
    actorFrom: () => ({ type: 'user', id: ids.user }),
    record: vi.fn((_entry: Record<string, unknown>, _tx?: unknown) => Promise.resolve()),
  };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };

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
  const evidenceUrl = `/api/v1/messages/${MESSAGE_ID}/scans/${SCAN}/dlp-evidence`;
  const actions = () => audit.record.mock.calls.map(([entry]) => entry.action);

  beforeAll(async () => {
    const cfg = loadApiConfig(env);
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
      .useValue({ authenticate: () => Promise.resolve(apiKeyPrincipal()) })
      .overrideProvider(TransactionRunner)
      .useValue(transactions)
      .overrideProvider(AuditService)
      .useValue(audit)
      .overrideProvider(DlpConfigRepository)
      .useValue(config)
      .overrideProvider(DlpResultsRepository)
      .useValue(results)
      .overrideProvider(DlpEvidenceStore)
      .useValue(store)
      .overrideProvider(MessageLifecycleReadRepository)
      .useValue({
        findMessage: (_scope: unknown, publicId: string) =>
          Promise.resolve(
            publicId === MESSAGE_ID
              ? {
                  id: 77n,
                  publicId,
                  receivedAt: message.receivedAt,
                  direction: 'outbound',
                  status: 'scanned',
                  statusReason: null,
                  version: 3,
                  lifecycleRound: 0,
                  statusChangedAt: NOW,
                }
              : null,
          ),
      })
      .overrideProvider(MessageScansReadRepository)
      .useValue(scanReads)
      .overrideProvider(ScanSettingsRepository)
      .useValue(settingsRows)
      .compile();
    // Production logging: the Nest logger on pino (every service log line and the exception
    // filter), captured in memory so the pattern-test markers can be searched for.
    const destination = { write: (line: string) => void logLines.push(line) };
    const logger = createLogger({ service: 'api-test', level: 'trace', destination });
    app = moduleRef.createNestApplication({ logger: new NestPinoLogger(logger) });
    configureHttpApp(app, logger);
    configureApiApp(app, cfg);
    await app.init();
  });

  afterAll(async () => {
    await app?.close();
  });

  beforeEach(() => {
    vi.clearAllMocks();
    kv.entries.clear();
    apiKeyPermissions = new Set([READ]);
    principalWith([READ, MANAGE, EVIDENCE, COMPLIANCE, 'message:read', 'policy:read']);
    results.evidenceOf.mockImplementation(() => Promise.resolve(evidenceRow()));
    store.read.mockImplementation(() => Promise.resolve(Buffer.from(sealed.object)));
  });

  it('answers 401 without credentials', async () => {
    await http().get('/api/v1/dlp/policies').expect(401);
    await http().post('/api/v1/dlp/patterns/test').send({}).expect(401);
    await http().get(evidenceUrl).expect(401);
    await http().delete('/api/v1/dlp/evidence').expect(401);
  });

  it('reads with dlp:read (users and API keys); 403 without it', async () => {
    const res = await http().get('/api/v1/dlp/policies').set(apiKey).expect(200);
    expect(res.body).toEqual({
      data: [expect.objectContaining({ id: POLICY_ID, ruleCount: 1, version: 1 })],
      nextCursor: null,
    });
    const detail = await http()
      .get(`/api/v1/dlp/policies/${POLICY_ID}`)
      .set(await bearer())
      .expect(200);
    expect(detail.body.rules).toEqual([
      expect.objectContaining({ id: RULE_ID, policyId: POLICY_ID, action: 'quarantine' }),
    ]);
    const missing = await http()
      .get(`/api/v1/dlp/policies/${randomUUID()}`)
      .set(await bearer())
      .expect(404);
    expect(missing.body.code).toBe('dlp_policy_not_found');
    await http()
      .get('/api/v1/dlp/policies/not-a-uuid')
      .set(await bearer())
      .expect(400);
    principalWith([MANAGE]);
    for (const path of [
      'policies',
      'exceptions',
      'patterns',
      'dictionaries',
      'compliance',
      'incidents',
    ]) {
      await http()
        .get(`/api/v1/dlp/${path}`)
        .set(await bearer())
        .expect(403);
    }
  });

  it('writes with dlp:manage only (403 for dlp:read), audited with before-images', async () => {
    principalWith([READ]);
    await http()
      .post('/api/v1/dlp/policies')
      .set(await bearer())
      .send({ name: 'P' })
      .expect(403);
    principalWith([READ, MANAGE]);
    const created = await http()
      .post('/api/v1/dlp/policies')
      .set(await bearer())
      .send({ name: 'Card data outbound' })
      .expect(201);
    expect(created.body).toMatchObject({ id: POLICY_ID, rules: [] });
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'dlp_policy.created', resourceId: POLICY_ID }),
      {},
    );
    await http()
      .patch(`/api/v1/dlp/policies/${POLICY_ID}`)
      .set(await bearer())
      .send({ version: 1, priority: 5 })
      .expect(200);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'dlp_policy.updated',
        metadata: expect.objectContaining({
          before: expect.any(Object),
          after: expect.any(Object),
        }),
      }),
      {},
    );
    await http()
      .delete(`/api/v1/dlp/policies/${POLICY_ID}`)
      .set(await bearer())
      .expect(204);
    expect(actions()).toContain('dlp_policy.deleted');
  });

  it('answers the coded conflicts: exists, version, limit, in use', async () => {
    config.policyByName.mockResolvedValueOnce(policyRow);
    const exists = await http()
      .post('/api/v1/dlp/policies')
      .set(await bearer())
      .send({ name: 'Card data outbound' })
      .expect(409);
    expect(exists.body).toMatchObject({ code: 'dlp_policy_exists', id: POLICY_ID });
    const version = await http()
      .patch(`/api/v1/dlp/policies/${POLICY_ID}`)
      .set(await bearer())
      .send({ version: 7 })
      .expect(409);
    expect(version.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    config.countPolicies.mockResolvedValueOnce(20);
    const limit = await http()
      .post('/api/v1/dlp/policies')
      .set(await bearer())
      .send({ name: 'Another' })
      .expect(409);
    expect(limit.body).toMatchObject({
      code: 'dlp_limit_reached',
      resource: 'policies',
      limit: 20,
    });
    config.countExceptionsTargeting.mockResolvedValueOnce(2);
    const inUse = await http()
      .delete(`/api/v1/dlp/policies/${POLICY_ID}`)
      .set(await bearer())
      .expect(409);
    expect(inUse.body).toMatchObject({ code: 'dlp_policy_in_use', references: 2 });
    const patternInUse = await http()
      .delete(`/api/v1/dlp/patterns/${PATTERN_ID}`)
      .set(await bearer())
      .expect(409);
    expect(patternInUse.body).toMatchObject({ code: 'dlp_pattern_in_use', references: 1 });
    expect(config.deletePattern).not.toHaveBeenCalled();
  });

  it('validates rules: strict conditions, directions within the policy, tenant references', async () => {
    const url = `/api/v1/dlp/policies/${POLICY_ID}/rules`;
    for (const conditions of [
      {},
      { selectors: {} },
      { selectors: { detectors: ['XX9'] } },
      { selectors: { categories: ['credential'] }, minCount: 0 },
      { selectors: { categories: ['credential'] }, sender: { domains: ['co.uk'] } },
      { selectors: { categories: ['credential'] }, unknown: true },
    ]) {
      await http()
        .post(url)
        .set(await bearer())
        .send({ name: 'R', conditions, action: 'block' })
        .expect(400);
    }
    expect(transactions.run).not.toHaveBeenCalled();
    const directions = await http()
      .post(url)
      .set(await bearer())
      .send({
        name: 'R',
        conditions: { selectors: { categories: ['credential'] }, directions: ['inbound'] },
        action: 'block',
      })
      .expect(400);
    expect(directions.body.code).toBe('dlp_directions_invalid');
    const reference = await http()
      .post(url)
      .set(await bearer())
      .send({
        name: 'R',
        conditions: { selectors: { customPatternIds: [PATTERN_ID, randomUUID()] } },
        action: 'block',
      })
      .expect(400);
    expect(reference.body).toMatchObject({
      code: 'dlp_reference_invalid',
      field: 'conditions.selectors.customPatternIds',
      index: 1,
    });
    await http()
      .post(url)
      .set(await bearer())
      .send({
        name: 'Cards to external',
        conditions: {
          selectors: { categories: ['payment_card'] },
          recipients: { externalOnly: true },
        },
        action: 'quarantine',
      })
      .expect(201);
    expect(config.createRule).toHaveBeenCalledTimes(1);
  });

  it('validates patterns with the D9 codes (never echoing the pattern) and dictionaries with the D8 codes', async () => {
    for (const [pattern, code] of [
      [`(${PATTERN_MARKER})\\1`, 'pattern_unsupported'],
      [`(?=${PATTERN_MARKER})x`, 'pattern_unsupported'],
      [`${PATTERN_MARKER}[0-9]{1000}`, 'pattern_too_complex'],
      ['x*', 'pattern_matches_empty'],
      ['[a-z]+', 'pattern_too_broad'],
      [`${PATTERN_MARKER}(`, 'pattern_syntax'],
      ['x'.repeat(300), 'pattern_syntax'],
    ] as const) {
      const res = await http()
        .post('/api/v1/dlp/patterns')
        .set(await bearer())
        .send({ name: 'P', pattern, severity: 'high' })
        .expect(400);
      expect(res.body.code, pattern).toBe(code);
      expect(JSON.stringify(res.body)).not.toContain(PATTERN_MARKER);
    }
    expect(config.createPattern).not.toHaveBeenCalled();
    const ok = await http()
      .post('/api/v1/dlp/patterns')
      .set(await bearer())
      .send({ name: 'Employee id', pattern: 'EMP-[0-9]{6}', severity: 'medium' })
      .expect(201);
    expect(ok.body).toMatchObject({ id: PATTERN_ID, baseConfidence: 0.8 });
    const terms = await http()
      .post('/api/v1/dlp/dictionaries')
      .set(await bearer())
      .send({
        name: 'Projects',
        category: 'confidential',
        severity: 'high',
        terms: ['Falcon', 'x'.repeat(65)],
      })
      .expect(400);
    expect(terms.body).toMatchObject({ code: 'dictionary_term_invalid', index: 1 });
    const dup = await http()
      .post('/api/v1/dlp/dictionaries')
      .set(await bearer())
      .send({
        name: 'Projects',
        category: 'confidential',
        severity: 'high',
        terms: ['Falcon', 'FALCON'],
      })
      .expect(400);
    expect(dup.body).toMatchObject({ code: 'dictionary_term_invalid', index: 1 });
    expect(config.createDictionary).not.toHaveBeenCalled();
  });

  it('tests a pattern: masked matches, nothing persisted, audited or logged, 30 per minute', async () => {
    logLines.length = 0;
    const sample = `${SAMPLE_MARKER} employee EMP-123456 and EMP-654321 ${SAMPLE_MARKER}`;
    const res = await http()
      .post('/api/v1/dlp/patterns/test')
      .set(await bearer())
      .send({ pattern: 'EMP-[0-9]{6}', contextKeywords: ['employee'], sample })
      .expect(200);
    expect(res.body).toMatchObject({ valid: true, code: null });
    expect(res.body.matches).toHaveLength(2);
    expect(res.body.matches[0]).toEqual({
      start: sample.indexOf('EMP-123456'),
      end: sample.indexOf('EMP-123456') + 10,
      masked: '*****3456',
      validated: true,
      contextMatched: true,
    });
    const refused = await http()
      .post('/api/v1/dlp/patterns/test')
      .set(await bearer())
      .send({ pattern: `(${PATTERN_MARKER})\\1`, sample })
      .expect(200);
    expect(refused.body).toMatchObject({ valid: false, code: 'pattern_unsupported', matches: [] });
    const tooLong = await http()
      .post('/api/v1/dlp/patterns/test')
      .set(await bearer())
      .send({ pattern: PATTERN_MARKER, sample: SAMPLE_MARKER.repeat(300) })
      .expect(400);
    const bodies = JSON.stringify([res.body, refused.body, tooLong.body]);
    expect(bodies.replace(/"masked":"[^"]*"/g, '')).not.toContain(SAMPLE_MARKER);
    expect(bodies).not.toContain(PATTERN_MARKER);
    expect(bodies).not.toContain('EMP-123456');
    const logs = logLines.join('\n');
    expect(logs).not.toContain(SAMPLE_MARKER);
    expect(logs).not.toContain(PATTERN_MARKER);
    expect(logs).not.toContain('EMP-');
    expect(audit.record).not.toHaveBeenCalled();
    expect(transactions.run).not.toHaveBeenCalled();
    // 30 per caller per minute (3 used above).
    for (let i = 0; i < 27; i += 1) {
      await http()
        .post('/api/v1/dlp/patterns/test')
        .set(await bearer())
        .send({ pattern: 'EMP-[0-9]{6}', sample: 'x' })
        .expect(200);
    }
    await http()
      .post('/api/v1/dlp/patterns/test')
      .set(await bearer())
      .send({ pattern: 'EMP-[0-9]{6}', sample: 'x' })
      .expect(429);
    principalWith([READ]);
    await http()
      .post('/api/v1/dlp/patterns/test')
      .set(await bearer())
      .send({ pattern: 'x', sample: 'x' })
      .expect(403);
  });

  it('reads evidence: users with dlp:evidence_read and MFA only; audit row before the fetch; no-store', async () => {
    await http().get(evidenceUrl).set(apiKey).expect(403);
    await http()
      .get(evidenceUrl)
      .set(await bearer(['pwd']))
      .expect(403);
    principalWith([READ, MANAGE]);
    await http()
      .get(evidenceUrl)
      .set(await bearer())
      .expect(403);
    expect(store.read).not.toHaveBeenCalled();
    principalWith([EVIDENCE]);
    const res = await http()
      .get(evidenceUrl)
      .set(await bearer())
      .expect(200);
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toMatchObject({ messageId: MESSAGE_ID, scanId: SCAN, matchCount: 1 });
    expect(res.body.evidence).toEqual(evidenceDocument);
    expect(actions()).toEqual(['dlp_evidence.read']);
    expect(audit.record.mock.calls[0]![0]).toMatchObject({
      resourceId: MESSAGE_ID,
      metadata: { messageId: MESSAGE_ID, scanId: SCAN, matchCount: 1 },
    });
    expect(audit.record.mock.invocationCallOrder[0]!).toBeLessThan(
      store.read.mock.invocationCallOrder[0]!,
    );
    expect(logLines.join('\n')).not.toContain('ABCPD1234E');
  });

  it('answers 404 for another message or scan, 410 for purged or expired evidence (no fetch)', async () => {
    principalWith([EVIDENCE]);
    const other = await http()
      .get(`/api/v1/messages/${randomUUID()}/scans/${SCAN}/dlp-evidence`)
      .set(await bearer())
      .expect(404);
    expect(other.body.code).toBe('message_not_found');
    results.scanExists.mockResolvedValueOnce(false);
    expect(
      (
        await http()
          .get(evidenceUrl)
          .set(await bearer())
          .expect(404)
      ).body.code,
    ).toBe('scan_not_found');
    results.evidenceOf.mockResolvedValueOnce(null);
    expect(
      (
        await http()
          .get(evidenceUrl)
          .set(await bearer())
          .expect(404)
      ).body.code,
    ).toBe('dlp_evidence_not_found');
    results.evidenceOf.mockResolvedValueOnce(evidenceRow({ purgedAt: NOW, wrappedKey: null }));
    expect(
      (
        await http()
          .get(evidenceUrl)
          .set(await bearer())
          .expect(410)
      ).body.code,
    ).toBe('evidence_purged');
    results.evidenceOf.mockResolvedValueOnce(
      evidenceRow({ expiresAt: new Date(Date.now() - 1000) }),
    );
    expect(
      (
        await http()
          .get(evidenceUrl)
          .set(await bearer())
          .expect(410)
      ).body.code,
    ).toBe('evidence_expired');
    expect(store.read).not.toHaveBeenCalled();
    expect(audit.record).not.toHaveBeenCalled();
  });

  it('a forced decryption failure leaves both read and read_failed audit rows (500, code only)', async () => {
    principalWith([EVIDENCE]);
    const foreign = sealEvidence({ current: randomBytes(32) }, JSON.stringify(evidenceDocument), {
      organizationId: '1',
      messageId: '77',
      scanId: SCAN,
    });
    results.evidenceOf.mockResolvedValueOnce(
      evidenceRow({
        wrappedKey: foreign.wrappedKey,
        objectSha256: foreign.sha256,
        objectSizeBytes: foreign.size,
      }),
    );
    store.read.mockResolvedValueOnce(Buffer.from(foreign.object));
    const res = await http()
      .get(evidenceUrl)
      .set(await bearer())
      .expect(500);
    expect(res.body.code).toBe('evidence_unreadable');
    expect(actions()).toEqual(['dlp_evidence.read', 'dlp_evidence.read_failed']);
    expect(audit.record.mock.calls[1]![0]).toMatchObject({
      metadata: { messageId: MESSAGE_ID, scanId: SCAN, reason: 'decrypt' },
    });
    // An altered object fails the hash check before decryption.
    store.read.mockResolvedValueOnce(Buffer.from('tampered'));
    expect(
      (
        await http()
          .get(evidenceUrl)
          .set(await bearer())
          .expect(500)
      ).body.code,
    ).toBe('evidence_unreadable');
    expect(audit.record.mock.calls.at(-1)![0]).toMatchObject({
      metadata: expect.objectContaining({ reason: 'object_size' }),
    });
  });

  it('purges evidence with dlp:manage and MFA (crypto-shred first), per round and per organization', async () => {
    principalWith([MANAGE]);
    await http()
      .delete(evidenceUrl)
      .set(await bearer(['pwd']))
      .expect(403);
    await http()
      .delete(evidenceUrl)
      .set(await bearer())
      .expect(204);
    expect(results.shred).toHaveBeenCalledTimes(1);
    expect(results.shred.mock.invocationCallOrder[0]!).toBeLessThan(
      store.delete.mock.invocationCallOrder[0]!,
    );
    expect(results.clearObjectKey).toHaveBeenCalledTimes(1);
    expect(actions()).toEqual(['dlp_evidence.purged']);
    audit.record.mockClear();
    const all = await http()
      .delete('/api/v1/dlp/evidence')
      .set(await bearer())
      .expect(202);
    expect(all.body).toEqual({ purged: 0, objectsDeleted: 0, objectsPending: 0 });
    expect(actions()).toEqual(['dlp_evidence.purged']);
    apiKeyPermissions = new Set([MANAGE]);
    await http().delete('/api/v1/dlp/evidence').set(apiKey).expect(403);
  });

  it('records the Aadhaar basis with dlp:compliance_manage, MFA and users only (audited)', async () => {
    const body = {
      expectedVersion: 0,
      basis: 'regulatory_obligation',
      reference: 'RBI KYC direction 2026/14',
      attested: true,
      reviewDueAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
    };
    principalWith([READ, MANAGE]);
    await http()
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(await bearer())
      .send(body)
      .expect(403);
    principalWith([COMPLIANCE]);
    await http()
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(await bearer(['pwd']))
      .send(body)
      .expect(403);
    apiKeyPermissions = new Set([COMPLIANCE]);
    await http().put('/api/v1/dlp/compliance/aadhaar').set(apiKey).send(body).expect(403);
    for (const bad of [
      { ...body, attested: false },
      { ...body, reviewDueAt: new Date(Date.now() + 400 * 86_400_000).toISOString() },
      { ...body, basis: 'because' },
      { ...body, reference: '' },
    ]) {
      await http()
        .put('/api/v1/dlp/compliance/aadhaar')
        .set(await bearer())
        .send(bad)
        .expect(400);
    }
    config.findComplianceForUpdate.mockResolvedValueOnce({
      id: 1n,
      organizationId: 1n,
      aadhaarEnabled: false,
      version: 3,
    } as never);
    const conflict = await http()
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(await bearer())
      .send(body)
      .expect(409);
    expect(conflict.body).toMatchObject({ code: 'version_conflict', currentVersion: 3 });
  });

  it('withholds the scans read API dlp section without dlp:read (read_only_user) and shows it to analysts', async () => {
    const url = `/api/v1/messages/${MESSAGE_ID}/scans`;
    principalWith(['message:read']);
    const hidden = await http()
      .get(url)
      .set(await bearer())
      .expect(200);
    const entry = hidden.body.data[0].engines[0];
    expect(entry).toMatchObject({
      engine: 'dlp',
      outcome: 'suspicious',
      dlp: null,
      durationMs: null,
    });
    const text = JSON.stringify(hidden.body);
    expect(text).not.toContain('masked');
    expect(text).not.toContain(POLICY_ID);
    expect(text).not.toContain('coverageDetail');
    expect(scanReads.dlpResults).not.toHaveBeenCalled();
    principalWith(['message:read', READ, MANAGE, EVIDENCE]);
    const shown = await http()
      .get(url)
      .set(await bearer())
      .expect(200);
    expect(shown.body.data[0].engines[0].dlp).toMatchObject({
      verdict: 'suspicious',
      action: 'quarantine',
      findings: [{ detector: 'PC1', masked: ['************0366'] }],
      policy: { winner: { policyId: POLICY_ID, ruleId: RULE_ID } },
      evidence: { status: 'stored', purged: false },
    });
  });

  it('serves the dlp scan settings with bounds (422 out of bounds)', async () => {
    principalWith(['policy:read', 'scan:settings_manage']);
    const list = await http()
      .get('/api/v1/scan-settings')
      .set(await bearer())
      .expect(200);
    expect(list.body.data.map((v: { engine: string }) => v.engine)).toContain('dlp');
    for (const [settings, path] of [
      [{ thresholds: { payment_card: 0.3 } }, 'thresholds.payment_card'],
      [{ disabledDetectors: ['PC1'] }, 'disabledDetectors.0'],
      [{ evidence: { retentionDays: 181 } }, 'evidence.retentionDays'],
      [{ contextWindowChars: 32 }, 'contextWindowChars'],
    ] as const) {
      const res = await http()
        .put('/api/v1/scan-settings/dlp')
        .set(await bearer())
        .send({ expectedVersion: 0, settings })
        .expect(422);
      expect(res.body.code).toBe('scan_settings_invalid');
      expect(res.body.violations.map((v: { path: string }) => v.path)).toEqual([path]);
    }
    expect(settingsRows.create).not.toHaveBeenCalled();
    await http()
      .put('/api/v1/scan-settings/dlp')
      .set(await bearer())
      .send({
        expectedVersion: 0,
        settings: { inboundEnabled: true, evidence: { retentionDays: 60 } },
      })
      .expect(200);
    expect(audit.record).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'scan_settings.updated' }),
      {},
    );
  });
});
