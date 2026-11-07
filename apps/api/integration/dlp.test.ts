/**
 * Step 4.5 api routes against the real MySQL writer and replica and MinIO
 * (docs/plan/steps/13-dlp.md D9, D11, D12, D16, D17, D20, D21, §9 "api (WP4)"): policies and
 * rules (permissions, normalization, unique names, optimistic versions, references to the
 * tenant's patterns only, per-tenant caps under concurrency, audit rows with before-images,
 * another tenant's id 404), exceptions, custom patterns (D9 codes, in-use conflicts), the pattern
 * test (masked matches, **sample and pattern never in the logs or the audit trail**),
 * dictionaries (terms never in audit metadata), the Aadhaar compliance basis (MFA, users only),
 * incidents (replica, filters, masked), the scans read API `dlp` section (withheld without
 * `dlp:read`), the `dlp` scan settings, the audited evidence door (audit row committed before
 * the object is read; a forced decryption failure leaves both `dlp_evidence.read` and
 * `read_failed`; 410 purged/expired; no-store), the evidence purge (crypto-shred, object
 * deleted) and the organization purge of every DLP table and evidence object. Result and
 * evidence rows are inserted as the email-worker writes them; evidence objects are sealed with
 * `@email-gateway/dlp` `sealEvidence` and stored in MinIO by the test (no worker involved).
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { sealEvidence } from '@email-gateway/dlp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import {
  DLP_PURGE_ORDER,
  DlpTenantDataRepository,
} from '../src/modules/tenant-data/dlp-tenant-data.repository';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  createFixtures,
  type FixtureOrganization,
  type Fixtures,
  type FixtureUser,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa, uniqueIp } from './support/http';
import {
  deleteLifecycleFixtures,
  insertLifecycleMessage,
  type LifecycleMessage,
} from './support/lifecycle';
import { mailBucketClient, s3Commands } from './support/probe-cleanup';

const POLL = { timeout: 15_000, interval: 200 };
const run = randomBytes(4).toString('hex');
const SAMPLE_MARKER = `SAMPLEMARK${run}`;
const PATTERN_MARKER = `PATMARK${run}`;
const TERM_MARKER = `Projectfalcon${run}`;

let ctx: IntegrationApp;
let fx: Fixtures;
let orgA: FixtureOrganization;
let orgB: FixtureOrganization;
let adminA: Record<string, string>;
let adminB: Record<string, string>;
let analystA: Record<string, string>;
let auditorA: Record<string, string>;
let readOnlyA: Record<string, string>;
let noMfaAdminA: Record<string, string>;
let readerKeyA: Record<string, string>;
const objectKeys: string[] = [];

const headers = (auth: Record<string, string>) => ({ ...auth, 'X-Forwarded-For': uniqueIp() });
const tokenOf = async (user: FixtureUser) =>
  bearer((await loginWithMfa(ctx, fx, user)).accessToken);
const auditOf = (org: FixtureOrganization, action: string, resourceId?: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action, ...(resourceId !== undefined && { resourceId }) },
    orderBy: { id: 'asc' },
  });

async function putObject(key: string, body: Buffer): Promise<void> {
  const { s3, bucket } = mailBucketClient();
  try {
    await s3.send(
      new (s3Commands().PutObjectCommand)({ Bucket: bucket, Key: key, Body: body as never }),
    );
    objectKeys.push(key);
  } finally {
    s3.destroy();
  }
}

async function objectExists(key: string): Promise<boolean> {
  const { s3, bucket } = mailBucketClient();
  try {
    const page = await s3.send(
      new (s3Commands().ListObjectsV2Command)({ Bucket: bucket, Prefix: key }),
    );
    return (page.Contents ?? []).some((item) => item.Key === key);
  } finally {
    s3.destroy();
  }
}

async function deleteObjects(): Promise<void> {
  const { s3, bucket } = mailBucketClient();
  try {
    for (const key of objectKeys) {
      await s3.send(new (s3Commands().DeleteObjectCommand)({ Bucket: bucket, Key: key }));
    }
  } finally {
    s3.destroy();
  }
}

async function purgeDlp(orgIds: bigint[]): Promise<void> {
  const repo = ctx.get(DlpTenantDataRepository);
  for (const id of orgIds) await repo.purgeOrganization(systemScope(id));
  const where = { organizationId: { in: orgIds } };
  await ctx.prisma.scanEngineResult.deleteMany({ where });
  await ctx.prisma.emailScan.deleteMany({ where });
  await ctx.prisma.scanEngineSetting.deleteMany({ where });
}

const FINDINGS = [
  {
    detector: 'PC1',
    code: 'dlp.payment_card.number',
    category: 'payment_card',
    severity: 'high',
    confidence: 0.95,
    count: 2,
    capped: false,
    sources: [{ kind: 'body_text' }, { kind: 'attachment', partIndex: 1, path: '0' }],
    masked: ['************0366', '************1111'],
  },
  {
    detector: 'NI1',
    code: 'dlp.national_id.india_pan',
    category: 'national_id',
    severity: 'high',
    confidence: 0.85,
    count: 1,
    capped: false,
    sources: [{ kind: 'body_text' }],
    masked: ['******234E'],
  },
];

const evidenceDocument = (value = 'ABCPD1234E') => ({
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
      value,
      context: { before: 'PAN: ', after: ' please' },
    },
  ],
  dropped: 0,
});

/**
 * A completed outbound round with a dlp final, its `dlp_scan_results` row and (optionally) its
 * evidence: the object sealed with DLP_EVIDENCE_KEY (or `kek`) and stored in MinIO under
 * `org/<org>/dlp-evidence/`, the row with the wrapped key — as the email-worker writes them.
 */
async function insertDlpRound(
  message: LifecycleMessage,
  options: {
    action?: 'allow' | 'alert' | 'require_approval' | 'quarantine' | 'block';
    /** Internal ids (the `matched_*` columns) and public ids (the policy JSON, as WP3 stores). */
    policy?: {
      policyId: bigint;
      ruleId: bigint;
      publicPolicyId: string;
      publicRuleId: string;
    } | null;
    exceptionIds?: bigint[];
    evidence?: 'stored' | 'none';
    kek?: string;
    expiresAt?: Date;
    direction?: 'outbound' | 'inbound' | 'internal';
  } = {},
): Promise<{ scanId: bigint; objectKey: string | null }> {
  const action = options.action ?? 'quarantine';
  const base = {
    receivedAt: message.receivedAt,
    messageId: message.id,
    organizationId: message.organizationId,
  };
  const startedAt = new Date(message.receivedAt.getTime() + 1_000);
  const completedAt = new Date(startedAt.getTime() + 2_345);
  const scan = await ctx.prisma.emailScan.create({
    data: {
      ...base,
      scanKind: 'initial',
      status: 'completed',
      lifecycleRound: 0,
      scanVerdict: 'suspicious',
      requiredEngines: ['rspamd', 'dlp'],
      reasonCodes: [`dlp.action.${action}`],
      startedAt,
      completedAt,
      deadlineAt: new Date(startedAt.getTime() + 1_800_000),
    },
    select: { id: true },
  });
  await ctx.prisma.scanEngineResult.create({
    data: {
      ...base,
      scanId: scan.id,
      engine: 'dlp',
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      outcome: 'suspicious',
      durationMs: 2345,
      attempt: 1,
      isFinal: true,
      reasonCodes: [`dlp.action.${action}`, 'dlp.payment_card.number', 'dlp.national_id.india_pan'],
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      evidence: { signals: [] },
      completedAt,
    },
  });
  const policy = options.policy ?? null;
  await ctx.prisma.dlpScanResult.create({
    data: {
      ...base,
      scanId: scan.id,
      lifecycleRound: 0,
      direction: options.direction ?? 'outbound',
      engineVersion: 'dlp/1;dict=0123abcd;data=4567ef01;ext=dlp-extract/1',
      rulesVersion: 'dlp-map/1',
      settingsVersion: 'dlp-map/1;p=0123456789ab;t=none',
      policyVersion: 'pol/1;h=0123456789ab',
      extractorVersion: 'dlp-extract/1',
      verdict: 'suspicious',
      action,
      actionSource: policy === null ? 'default_policy' : 'tenant_policy',
      matchedPolicyId: policy?.policyId ?? null,
      matchedRuleId: policy?.ruleId ?? null,
      coverage: 'complete',
      // As the email-worker stores it (§12 WP3): `{ aadhaar, sources }`.
      coverageDetail: {
        aadhaar: 'disabled',
        sources: [
          {
            source: 'subject',
            format: 'text',
            status: 'scanned',
            reasons: [],
            chars: 20,
            truncated: false,
          },
          {
            source: 'body_text',
            format: 'text',
            status: 'scanned',
            reasons: [],
            chars: 400,
            truncated: false,
          },
        ],
      },
      categories: [
        { category: 'payment_card', count: 2, maxSeverity: 'high', maxConfidence: 0.95 },
        { category: 'national_id', count: 1, maxSeverity: 'high', maxConfidence: 0.85 },
      ],
      findings: FINDINGS,
      policy: {
        winner:
          policy === null ? null : { policyId: policy.publicPolicyId, ruleId: policy.publicRuleId },
        matched:
          policy === null
            ? []
            : [
                {
                  policyId: policy.publicPolicyId,
                  ruleId: policy.publicRuleId,
                  action,
                  mode: 'enforce',
                  exceptionIds: [],
                },
              ],
        exceptionsApplied: (options.exceptionIds ?? []).map(String),
      },
      findingCount: 3,
      evidenceStatus: options.evidence === 'none' ? 'none' : 'stored',
      durationMs: 2345,
    },
  });
  if (options.evidence === 'none') return { scanId: scan.id, objectKey: null };
  const sealed = sealEvidence(
    { current: options.kek ?? ctx.config.DLP_EVIDENCE_KEY },
    JSON.stringify(evidenceDocument()),
    {
      organizationId: message.organizationId.toString(),
      messageId: message.id.toString(),
      scanId: scan.id.toString(),
    },
  );
  const objectKey = `org/${message.organizationId.toString()}/dlp-evidence/2026/11/${scan.id.toString()}-${randomUUID()}.bin`;
  await putObject(objectKey, sealed.object);
  await ctx.prisma.dlpEvidence.create({
    data: {
      ...base,
      scanId: scan.id,
      objectKey,
      objectSha256: sealed.sha256,
      objectSizeBytes: sealed.size,
      wrappedKey: sealed.wrappedKey,
      keyId: sealed.keyId,
      algorithm: sealed.algorithm,
      matchCount: 1,
      expiresAt: options.expiresAt ?? new Date(Date.now() + 30 * 86_400_000),
    },
  });
  return { scanId: scan.id, objectKey };
}

const outbound = (org: FixtureOrganization) =>
  insertLifecycleMessage(ctx, org, {
    state: 'scanned',
    direction: 'outbound',
    recipients: [{ address: 'partner@ext-dlp.example', status: 'pending' }],
  });

beforeAll(async () => {
  ctx = await createIntegrationApp({
    DLP_POLICIES_MAX_PER_TENANT: '3',
    DLP_RULES_MAX_PER_POLICY: '2',
    DLP_CUSTOM_PATTERNS_MAX_PER_TENANT: '3',
    DLP_DICTIONARIES_MAX_PER_TENANT: '2',
    DLP_EXCEPTION_MAX_DAYS: '90',
  });
  fx = createFixtures(ctx);
  orgA = await fx.createOrganization();
  orgB = await fx.createOrganization();
  fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgA.id, orgB.id]));
  fx.registerCleanup(() => purgeDlp([orgA.id, orgB.id]));
  fx.registerCleanup(() => deleteObjects());
  adminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'], mfa: true }));
  adminB = await tokenOf(await fx.createUser(orgB, { roles: ['organization_admin'], mfa: true }));
  analystA = await tokenOf(await fx.createUser(orgA, { roles: ['security_analyst'], mfa: true }));
  auditorA = await tokenOf(await fx.createUser(orgA, { roles: ['compliance_auditor'], mfa: true }));
  readOnlyA = await tokenOf(await fx.createUser(orgA, { roles: ['read_only_user'], mfa: true }));
  noMfaAdminA = await tokenOf(await fx.createUser(orgA, { roles: ['organization_admin'] }));
  readerKeyA = apiKeyHeader(await fx.createApiKey(orgA, ['dlp:read', 'message:read']));
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

describe('policies and rules (D11, D21)', () => {
  it('creates, refuses duplicates, caps under concurrency, versions, references and deletes, audited', async () => {
    const created = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminA))
      .send({ name: 'Card data', priority: 10 })
      .expect(201);
    expect(created.body).toMatchObject({
      name: 'Card data',
      mode: 'enforce',
      directions: ['outbound', 'internal'],
      ruleCount: 0,
      version: 1,
      rules: [],
    });
    const policyId = created.body.id as string;
    expect(await auditOf(orgA, 'dlp_policy.created', policyId)).toHaveLength(1);
    const dup = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminA))
      .send({ name: 'CARD DATA' })
      .expect(409);
    expect(dup.body).toMatchObject({ code: 'dlp_policy_exists', id: policyId });
    // The same name in another organization is independent; its id is a 404 here.
    const other = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminB))
      .send({ name: 'Card data' })
      .expect(201);
    await ctx.http.get(`/api/v1/dlp/policies/${other.body.id}`).set(headers(adminA)).expect(404);
    await ctx.http
      .patch(`/api/v1/dlp/policies/${other.body.id}`)
      .set(headers(adminA))
      .send({ version: 1, enabled: false })
      .expect(404);
    await ctx.http.delete(`/api/v1/dlp/policies/${other.body.id}`).set(headers(adminA)).expect(404);

    // Cap of 3 per organization, counted under the organization row lock: 4 concurrent creates
    // leave exactly 3 policies.
    const results = await Promise.all(
      [1, 2, 3, 4].map((i) =>
        ctx.http
          .post('/api/v1/dlp/policies')
          .set(headers(adminA))
          .send({ name: `Concurrent ${i}` }),
      ),
    );
    expect(results.map((r) => r.status).sort()).toEqual([201, 201, 409, 409]);
    expect(
      results.filter((r) => r.status === 409).map((r) => (r.body as { code: string }).code),
    ).toEqual(['dlp_limit_reached', 'dlp_limit_reached']);
    expect(await ctx.prisma.dlpPolicy.count({ where: { organizationId: orgA.id } })).toBe(3);

    // Rules: normalization, directions within the policy, the tenant's patterns only.
    const foreignPattern = await ctx.http
      .post('/api/v1/dlp/patterns')
      .set(headers(adminB))
      .send({ name: 'B pattern', pattern: 'BEMP-[0-9]{6}', severity: 'low' })
      .expect(201);
    const badRef = await ctx.http
      .post(`/api/v1/dlp/policies/${policyId}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Foreign',
        conditions: { selectors: { customPatternIds: [foreignPattern.body.id] } },
        action: 'block',
      })
      .expect(400);
    expect(badRef.body).toMatchObject({ code: 'dlp_reference_invalid', index: 0 });
    const badDir = await ctx.http
      .post(`/api/v1/dlp/policies/${policyId}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Inbound',
        conditions: { selectors: { categories: ['credential'] }, directions: ['inbound'] },
        action: 'block',
      })
      .expect(400);
    expect(badDir.body.code).toBe('dlp_directions_invalid');
    const rule = await ctx.http
      .post(`/api/v1/dlp/policies/${policyId}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Cards to partners',
        priority: 5,
        conditions: {
          selectors: { categories: ['payment_card'] },
          recipients: { domains: ['Partner.Bücher.Example'], externalOnly: true },
          sender: { addresses: ['Finance@Acme.Example'] },
        },
        action: 'quarantine',
      })
      .expect(201);
    expect(rule.body).toMatchObject({
      policyId,
      action: 'quarantine',
      conditions: {
        selectors: { categories: ['payment_card'] },
        recipients: { domains: ['partner.xn--bcher-kva.example'], externalOnly: true },
        sender: { addresses: ['finance@acme.example'] },
      },
      version: 1,
    });
    const ruleId = rule.body.id as string;
    await ctx.http
      .post(`/api/v1/dlp/policies/${policyId}/rules`)
      .set(headers(adminA))
      .send({ name: 'Second', conditions: { selectors: { detectors: ['CR1'] } }, action: 'block' })
      .expect(201);
    const ruleCap = await ctx.http
      .post(`/api/v1/dlp/policies/${policyId}/rules`)
      .set(headers(adminA))
      .send({ name: 'Third', conditions: { selectors: { detectors: ['CR2'] } }, action: 'alert' })
      .expect(409);
    expect(ruleCap.body).toMatchObject({ code: 'dlp_limit_reached', resource: 'rules', limit: 2 });

    // Narrowing the policy's directions below a rule's: refused.
    const narrowed = await ctx.http
      .patch(`/api/v1/dlp/policies/${policyId}/rules/${ruleId}`)
      .set(headers(adminA))
      .send({
        version: 1,
        conditions: { selectors: { categories: ['payment_card'] }, directions: ['outbound'] },
      })
      .expect(200);
    expect(narrowed.body.version).toBe(2);
    const refused = await ctx.http
      .patch(`/api/v1/dlp/policies/${policyId}`)
      .set(headers(adminA))
      .send({ version: 1, directions: ['internal'] })
      .expect(400);
    expect(refused.body.code).toBe('dlp_directions_invalid');
    const stale = await ctx.http
      .patch(`/api/v1/dlp/policies/${policyId}`)
      .set(headers(adminA))
      .send({ version: 9, enabled: false })
      .expect(409);
    expect(stale.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    await ctx.http
      .patch(`/api/v1/dlp/policies/${policyId}`)
      .set(headers(adminA))
      .send({ version: 1, mode: 'monitor' })
      .expect(200);
    const [updatedAudit] = await auditOf(orgA, 'dlp_policy.updated', policyId);
    expect(updatedAudit?.metadata).toMatchObject({
      before: { mode: 'enforce', version: 1 },
      after: { mode: 'monitor', version: 2 },
    });
    const [ruleAudit] = await auditOf(orgA, 'dlp_rule.updated', ruleId);
    expect(ruleAudit?.metadata).toMatchObject({
      before: { version: 1, conditions: { recipients: { externalOnly: true } } },
      after: { version: 2, conditions: { directions: ['outbound'] } },
    });

    // Reads: API key with dlp:read (replica); writes refused for it and for dlp:read holders.
    await expect
      .poll(async () => {
        const res = await ctx.http.get(`/api/v1/dlp/policies/${policyId}`).set(headers(readerKeyA));
        return (res.body.rules as { id: string }[] | undefined)?.map((r) => r.id).sort();
      }, POLL)
      .toHaveLength(2);
    await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(readerKeyA))
      .send({ name: 'X' })
      .expect(403);
    await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(auditorA))
      .send({ name: 'X' })
      .expect(403);
    await ctx.http.get('/api/v1/dlp/policies').set(headers(readOnlyA)).expect(403);

    // Delete the policy with its rules (audited with the before-image incl. the rules).
    await ctx.http
      .delete(`/api/v1/dlp/policies/${policyId}?version=2`)
      .set(headers(adminA))
      .expect(204);
    expect(await ctx.prisma.dlpPolicyRule.count({ where: { organizationId: orgA.id } })).toBe(0);
    const [deleted] = await auditOf(orgA, 'dlp_policy.deleted', policyId);
    expect((deleted?.metadata as { before: { rules: unknown[] } }).before.rules).toHaveLength(2);
  });
});

describe('exceptions (D12)', () => {
  it('normalizes, targets only the tenant’s policies and rules, bounds the expiry and blocks deletes in use', async () => {
    const policy = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminA))
      .send({ name: `Exceptions ${run}` })
      .expect(201);
    const rule = await ctx.http
      .post(`/api/v1/dlp/policies/${policy.body.id}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Cards',
        conditions: { selectors: { categories: ['payment_card'] } },
        action: 'block',
      })
      .expect(201);
    const bPolicy = await ctx.prisma.dlpPolicy.findFirstOrThrow({
      where: { organizationId: orgB.id },
      select: { publicId: true },
    });
    const expiresAt = new Date(Date.now() + 30 * 86_400_000).toISOString();
    const created = await ctx.http
      .post('/api/v1/dlp/exceptions')
      .set(headers(adminA))
      .send({
        scope: 'recipient_domain',
        value: 'Auditor.Bücher.Example',
        ruleId: rule.body.id,
        filters: { categories: ['payment_card'] },
        reason: 'Statutory auditor receives card reconciliations',
        expiresAt,
      })
      .expect(201);
    expect(created.body).toMatchObject({
      value: 'auditor.xn--bcher-kva.example',
      ruleId: rule.body.id,
      policyId: null,
      expired: false,
      version: 1,
    });
    const dup = await ctx.http
      .post('/api/v1/dlp/exceptions')
      .set(headers(adminA))
      .send({
        scope: 'recipient_domain',
        value: 'auditor.xn--bcher-kva.example',
        ruleId: rule.body.id,
        reason: 'x',
        expiresAt,
      })
      .expect(409);
    expect(dup.body).toMatchObject({ code: 'dlp_exception_exists', id: created.body.id });
    const foreign = await ctx.http
      .post('/api/v1/dlp/exceptions')
      .set(headers(adminA))
      .send({
        scope: 'sender_address',
        value: 'a@acme.example',
        policyId: bPolicy.publicId,
        reason: 'x',
        expiresAt,
      })
      .expect(400);
    expect(foreign.body).toMatchObject({ code: 'dlp_reference_invalid', field: 'policyId' });
    for (const bad of [
      { scope: 'sender_domain', value: 'co.uk', reason: 'x', expiresAt },
      { scope: 'sender_address', value: 'nope', reason: 'x', expiresAt },
      {
        scope: 'sender_address',
        value: 'a@acme.example',
        reason: 'x',
        expiresAt: new Date(Date.now() + 91 * 86_400_000).toISOString(),
      },
      {
        scope: 'sender_address',
        value: 'a@acme.example',
        reason: 'x',
        expiresAt: new Date(Date.now() - 1000).toISOString(),
      },
      { scope: 'sender_address', value: 'a@acme.example', reason: 'x' },
      { scope: 'sender_address', value: 'a@acme.example', expiresAt },
    ]) {
      await ctx.http.post('/api/v1/dlp/exceptions').set(headers(adminA)).send(bad).expect(400);
    }
    // The rule (and its policy) cannot be deleted while the exception targets it.
    const ruleInUse = await ctx.http
      .delete(`/api/v1/dlp/policies/${policy.body.id}/rules/${rule.body.id}`)
      .set(headers(adminA))
      .expect(409);
    expect(ruleInUse.body).toMatchObject({ code: 'dlp_rule_in_use', references: 1 });
    const policyInUse = await ctx.http
      .delete(`/api/v1/dlp/policies/${policy.body.id}`)
      .set(headers(adminA))
      .expect(409);
    expect(policyInUse.body.code).toBe('dlp_policy_in_use');
    const updated = await ctx.http
      .patch(`/api/v1/dlp/exceptions/${created.body.id}`)
      .set(headers(adminA))
      .send({ version: 1, enabled: false, filters: null })
      .expect(200);
    expect(updated.body).toMatchObject({ enabled: false, filters: null, version: 2 });
    await expect
      .poll(async () => {
        const res = await ctx.http
          .get('/api/v1/dlp/exceptions?active=false&scope=recipient_domain')
          .set(headers(analystA));
        return (res.body.data as { id: string }[] | undefined)?.map((e) => e.id);
      }, POLL)
      .toEqual([created.body.id]);
    await ctx.http
      .delete(`/api/v1/dlp/exceptions/${created.body.id}`)
      .set(headers(adminB))
      .expect(404);
    await ctx.http
      .delete(`/api/v1/dlp/exceptions/${created.body.id}`)
      .set(headers(adminA))
      .expect(204);
    expect(
      (await auditOf(orgA, 'dlp_exception.deleted', created.body.id))[0]?.metadata,
    ).toMatchObject({
      before: { value: 'auditor.xn--bcher-kva.example', version: 2 },
    });
    await ctx.http
      .delete(`/api/v1/dlp/policies/${policy.body.id}`)
      .set(headers(adminA))
      .expect(204);
  });
});

describe('custom patterns and the pattern test (D9)', () => {
  it('validates with the D9 codes, refuses deletes in use, and never logs or audits the test sample or pattern', async () => {
    const refusals: Array<[string, string]> = [
      [`(${PATTERN_MARKER})\\1`, 'pattern_unsupported'],
      ['[a-z]+', 'pattern_too_broad'],
      [`${PATTERN_MARKER}{1,500}`, 'pattern_too_complex'],
    ];
    for (const [pattern, code] of refusals) {
      const res = await ctx.http
        .post('/api/v1/dlp/patterns')
        .set(headers(adminA))
        .send({ name: `Bad ${code}`, pattern, severity: 'high' })
        .expect(400);
      expect(res.body.code).toBe(code);
      expect(JSON.stringify(res.body)).not.toContain(PATTERN_MARKER);
    }
    const created = await ctx.http
      .post('/api/v1/dlp/patterns')
      .set(headers(adminA))
      .send({
        name: 'Employee id',
        pattern: `EMP${run}-[0-9]{6}`,
        contextKeywords: ['employee'],
        severity: 'medium',
        baseConfidence: 0.75,
      })
      .expect(201);
    expect(created.body).toMatchObject({ baseConfidence: 0.75, maskStyle: 'last4', version: 1 });
    const patternId = created.body.id as string;
    expect((await auditOf(orgA, 'dlp_pattern.created', patternId))[0]?.metadata).toMatchObject({
      after: { pattern: `EMP${run}-[0-9]{6}` },
    });

    const logsBefore = ctx.logs.length;
    const auditsBefore = await ctx.prisma.auditLog.count({ where: { organizationId: orgA.id } });
    const sample = `${SAMPLE_MARKER} employee EMP${run}-123456 ${SAMPLE_MARKER}`;
    const tested = await ctx.http
      .post('/api/v1/dlp/patterns/test')
      .set(headers(adminA))
      .send({ pattern: `EMP${run}-[0-9]{6}`, contextKeywords: ['employee'], sample })
      .expect(200);
    expect(tested.body).toMatchObject({ valid: true, code: null });
    expect(tested.body.matches).toEqual([
      expect.objectContaining({ masked: expect.stringMatching(/^\*+3456$/), contextMatched: true }),
    ]);
    const refused = await ctx.http
      .post('/api/v1/dlp/patterns/test')
      .set(headers(adminA))
      .send({ pattern: `(${PATTERN_MARKER})\\1`, sample })
      .expect(200);
    expect(refused.body).toMatchObject({ valid: false, code: 'pattern_unsupported' });
    await ctx.http
      .post('/api/v1/dlp/patterns/test')
      .set(headers(adminA))
      .send({ pattern: PATTERN_MARKER, sample: SAMPLE_MARKER.repeat(400) })
      .expect(400);
    const logs = ctx.logs.slice(logsBefore).join('\n');
    expect(logs).not.toContain(SAMPLE_MARKER);
    expect(logs).not.toContain(PATTERN_MARKER);
    expect(logs).not.toContain(`EMP${run}`);
    expect(await ctx.prisma.auditLog.count({ where: { organizationId: orgA.id } })).toBe(
      auditsBefore,
    );
    expect(JSON.stringify([tested.body, refused.body])).not.toContain(SAMPLE_MARKER);

    // A rule selecting the pattern blocks its deletion.
    const policy = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminA))
      .send({ name: `Patterns ${run}` })
      .expect(201);
    await ctx.http
      .post(`/api/v1/dlp/policies/${policy.body.id}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Employees',
        conditions: { selectors: { customPatternIds: [patternId] } },
        action: 'alert',
      })
      .expect(201);
    const inUse = await ctx.http
      .delete(`/api/v1/dlp/patterns/${patternId}`)
      .set(headers(adminA))
      .expect(409);
    expect(inUse.body).toMatchObject({ code: 'dlp_pattern_in_use', references: 1 });
    await ctx.http
      .delete(`/api/v1/dlp/policies/${policy.body.id}`)
      .set(headers(adminA))
      .expect(204);
    await ctx.http.delete(`/api/v1/dlp/patterns/${patternId}`).set(headers(adminA)).expect(204);
  });
});

describe('keyword dictionaries (D8)', () => {
  it('validates terms, shows them to dlp:read holders only and never puts them in audit metadata', async () => {
    const bad = await ctx.http
      .post('/api/v1/dlp/dictionaries')
      .set(headers(adminA))
      .send({ name: 'Bad', category: 'confidential', severity: 'high', terms: ['ok', 'OK'] })
      .expect(400);
    expect(bad.body).toMatchObject({ code: 'dictionary_term_invalid', index: 1 });
    const created = await ctx.http
      .post('/api/v1/dlp/dictionaries')
      .set(headers(adminA))
      .send({
        name: 'Projects',
        category: 'confidential',
        severity: 'high',
        terms: [TERM_MARKER, 'Board Pack Q3'],
      })
      .expect(201);
    expect(created.body).toMatchObject({ termCount: 2, terms: [TERM_MARKER, 'Board Pack Q3'] });
    const id = created.body.id as string;
    await ctx.http
      .patch(`/api/v1/dlp/dictionaries/${id}`)
      .set(headers(adminA))
      .send({ version: 1, terms: [TERM_MARKER, 'Board Pack Q4', 'Merger Memo'] })
      .expect(200);
    const audits = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, resourceId: id },
    });
    expect(audits.map((a) => a.action).sort()).toEqual([
      'dlp_dictionary.created',
      'dlp_dictionary.updated',
    ]);
    expect(JSON.stringify(audits.map((a) => a.metadata))).not.toContain(TERM_MARKER);
    expect(audits.find((a) => a.action === 'dlp_dictionary.updated')?.metadata).toMatchObject({
      before: { termCount: 2 },
      after: { termCount: 3 },
      termsChanged: true,
    });
    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/dlp/dictionaries').set(headers(auditorA));
        return res.body.data as unknown[] | undefined;
      }, POLL)
      .toHaveLength(1);
    const list = await ctx.http.get('/api/v1/dlp/dictionaries').set(headers(auditorA)).expect(200);
    expect(JSON.stringify(list.body)).not.toContain(TERM_MARKER);
    await ctx.http.get(`/api/v1/dlp/dictionaries/${id}`).set(headers(readOnlyA)).expect(403);
    expect(ctx.logs.join('\n')).not.toContain(TERM_MARKER);
  });
});

describe('Aadhaar compliance (D17)', () => {
  it('records and disables the basis with dlp:compliance_manage, MFA and users only (audited)', async () => {
    const body = {
      expectedVersion: 0,
      basis: 'uidai_authorised_entity',
      reference: 'UIDAI AUA licence 2026-01',
      attested: true,
      reviewDueAt: new Date(Date.now() + 200 * 86_400_000).toISOString(),
    };
    await ctx.http
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(headers(analystA))
      .send(body)
      .expect(403);
    await ctx.http
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(headers(noMfaAdminA))
      .send(body)
      .expect(403);
    const enabled = await ctx.http
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(headers(adminA))
      .send(body)
      .expect(200);
    expect(enabled.body).toMatchObject({
      aadhaar: { enabled: true, active: true, basis: 'uidai_authorised_entity', attested: true },
      version: 1,
    });
    const conflict = await ctx.http
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(headers(adminA))
      .send(body)
      .expect(409);
    expect(conflict.body).toMatchObject({ code: 'version_conflict', currentVersion: 1 });
    await expect
      .poll(
        async () =>
          (
            (await ctx.http.get('/api/v1/dlp/compliance').set(headers(auditorA))).body as {
              version: number;
            }
          ).version,
        POLL,
      )
      .toBe(1);
    const disabled = await ctx.http
      .delete('/api/v1/dlp/compliance/aadhaar?expectedVersion=1')
      .set(headers(adminA))
      .expect(200);
    expect(disabled.body).toMatchObject({
      aadhaar: { enabled: false, active: false, basis: null },
      version: 2,
    });
    const [on] = await auditOf(orgA, 'dlp_compliance.aadhaar_enabled');
    const [off] = await auditOf(orgA, 'dlp_compliance.aadhaar_disabled');
    expect(on?.metadata).toMatchObject({ before: null, after: { enabled: true, version: 1 } });
    expect(off?.metadata).toMatchObject({
      before: { enabled: true },
      after: { enabled: false, version: 2 },
    });
  });
});

describe('evidence, incidents and the scans read API (D16, D20, D21)', () => {
  it('reads evidence only through the audited door: audit first, no-store, 404/410, forced failure audited twice', async () => {
    const message = await outbound(orgA);
    const { scanId, objectKey } = await insertDlpRound(message);
    const url = `/api/v1/messages/${message.publicId}/scans/${scanId.toString()}/dlp-evidence`;
    await ctx.http.get(url).set(headers(readOnlyA)).expect(403);
    await ctx.http.get(url).set(headers(readerKeyA)).expect(403);
    await ctx.http.get(url).set(headers(noMfaAdminA)).expect(403);
    await ctx.http.get(url).set(headers(adminB)).expect(404);
    const read = await ctx.http.get(url).set(headers(analystA)).expect(200);
    expect(read.headers['cache-control']).toBe('no-store');
    expect(read.body).toMatchObject({
      messageId: message.publicId,
      scanId: scanId.toString(),
      matchCount: 1,
    });
    expect(read.body.evidence).toEqual(evidenceDocument());
    const [audit] = await auditOf(orgA, 'dlp_evidence.read', message.publicId);
    expect(audit?.metadata).toEqual({
      messageId: message.publicId,
      scanId: scanId.toString(),
      matchCount: 1,
    });
    expect(JSON.stringify(audit?.metadata)).not.toContain('ABCPD1234E');
    expect(ctx.logs.join('\n')).not.toContain('ABCPD1234E');
    // The compliance auditor holds dlp:evidence_read too.
    await ctx.http.get(url).set(headers(auditorA)).expect(200);

    // A forced decryption failure (sealed under another key): read + read_failed, 500, no value.
    const broken = await outbound(orgA);
    const failed = await insertDlpRound(broken, { kek: randomBytes(32).toString('hex') });
    const brokenUrl = `/api/v1/messages/${broken.publicId}/scans/${failed.scanId.toString()}/dlp-evidence`;
    const res = await ctx.http.get(brokenUrl).set(headers(analystA)).expect(500);
    expect(res.body.code).toBe('evidence_unreadable');
    const trail = await ctx.prisma.auditLog.findMany({
      where: { organizationId: orgA.id, resourceId: broken.publicId },
      orderBy: { id: 'asc' },
    });
    expect(trail.map((a) => a.action)).toEqual(['dlp_evidence.read', 'dlp_evidence.read_failed']);
    expect(trail[1]?.metadata).toEqual({
      messageId: broken.publicId,
      scanId: failed.scanId.toString(),
      reason: 'decrypt',
    });

    // Expired: 410 and nothing fetched or audited.
    const old = await outbound(orgA);
    const expired = await insertDlpRound(old, { expiresAt: new Date(Date.now() - 60_000) });
    const expiredRes = await ctx.http
      .get(`/api/v1/messages/${old.publicId}/scans/${expired.scanId.toString()}/dlp-evidence`)
      .set(headers(analystA))
      .expect(410);
    expect(expiredRes.body.code).toBe('evidence_expired');
    expect(await auditOf(orgA, 'dlp_evidence.read', old.publicId)).toHaveLength(0);

    // Purge one round: crypto-shred, object deleted, 410 afterwards; analysts cannot purge without MFA.
    await ctx.http.delete(url).set(headers(noMfaAdminA)).expect(403);
    await ctx.http.delete(url).set(headers(analystA)).expect(204);
    const row = await ctx.prisma.dlpEvidence.findFirstOrThrow({
      where: { scanId, receivedAt: message.receivedAt },
    });
    expect(row).toMatchObject({ wrappedKey: null, objectKey: null, purgeReason: 'tenant_request' });
    expect(row.purgedAt).not.toBeNull();
    expect(await objectExists(objectKey!)).toBe(false);
    expect((await ctx.http.get(url).set(headers(analystA)).expect(410)).body.code).toBe(
      'evidence_purged',
    );
    expect(await auditOf(orgA, 'dlp_evidence.purged', message.publicId)).toHaveLength(1);
    // Idempotent.
    await ctx.http.delete(url).set(headers(analystA)).expect(204);
    expect(await auditOf(orgA, 'dlp_evidence.purged', message.publicId)).toHaveLength(1);
  });

  it('lists incidents (replica, filters, masked) and shows the scans read API dlp section only with dlp:read', async () => {
    const policy = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminA))
      .send({ name: `Incidents ${run}` })
      .expect(201);
    const rule = await ctx.http
      .post(`/api/v1/dlp/policies/${policy.body.id}/rules`)
      .set(headers(adminA))
      .send({
        name: 'Cards',
        conditions: { selectors: { categories: ['payment_card'] } },
        action: 'block',
      })
      .expect(201);
    const internal = {
      policyId: (
        await ctx.prisma.dlpPolicy.findFirstOrThrow({ where: { publicId: policy.body.id } })
      ).id,
      ruleId: (
        await ctx.prisma.dlpPolicyRule.findFirstOrThrow({ where: { publicId: rule.body.id } })
      ).id,
      publicPolicyId: policy.body.id as string,
      publicRuleId: rule.body.id as string,
    };
    const blocked = await outbound(orgA);
    const round = await insertDlpRound(blocked, {
      action: 'block',
      policy: internal,
      evidence: 'none',
    });
    const allowed = await outbound(orgA);
    await insertDlpRound(allowed, { action: 'allow', evidence: 'none' });
    const foreign = await outbound(orgB);
    await insertDlpRound(foreign, { action: 'block', evidence: 'none' });

    await expect
      .poll(async () => {
        const res = await ctx.http.get('/api/v1/dlp/incidents?action=block').set(headers(analystA));
        return (res.body.data as { messageId: string }[] | undefined)?.map((i) => i.messageId);
      }, POLL)
      .toContain(blocked.publicId);
    const page = await ctx.http
      .get('/api/v1/dlp/incidents?limit=100')
      .set(headers(auditorA))
      .expect(200);
    const ids = (page.body.data as { messageId: string }[]).map((i) => i.messageId);
    expect(ids).toContain(blocked.publicId);
    expect(ids).not.toContain(allowed.publicId);
    expect(ids).not.toContain(foreign.publicId);
    const incident = (page.body.data as Array<Record<string, unknown>>).find(
      (i) => i.messageId === blocked.publicId,
    )!;
    expect(incident).toMatchObject({
      scanId: round.scanId.toString(),
      action: 'block',
      actionSource: 'tenant_policy',
      direction: 'outbound',
      findings: [
        { detector: 'PC1', count: 2 },
        { detector: 'NI1', count: 1 },
      ],
      policy: { winner: { policyId: policy.body.id, ruleId: rule.body.id } },
    });
    expect(JSON.stringify(page.body)).not.toContain('masked');
    const inbound = await ctx.http
      .get('/api/v1/dlp/incidents?direction=inbound')
      .set(headers(auditorA))
      .expect(200);
    expect((inbound.body.data as { messageId: string }[]).map((i) => i.messageId)).not.toContain(
      blocked.publicId,
    );
    await ctx.http.get('/api/v1/dlp/incidents').set(headers(readOnlyA)).expect(403);
    await ctx.http
      .get('/api/v1/dlp/incidents?from=2026-11-07T00:00:00Z&to=2026-11-06T00:00:00Z')
      .set(headers(auditorA))
      .expect(400);

    // Scans read API: read_only_user (message:read only) gets no dlp section.
    const scansUrl = `/api/v1/messages/${blocked.publicId}/scans`;
    await expect
      .poll(
        async () =>
          ((await ctx.http.get(scansUrl).set(headers(readOnlyA))).body as { data?: unknown[] }).data
            ?.length,
        POLL,
      )
      .toBe(1);
    const hidden = await ctx.http.get(scansUrl).set(headers(readOnlyA)).expect(200);
    const hiddenEntry = (hidden.body.data[0].engines as Array<Record<string, unknown>>).find(
      (e) => e.engine === 'dlp',
    );
    expect(hiddenEntry).toMatchObject({ outcome: 'suspicious', dlp: null, durationMs: null });
    const hiddenText = JSON.stringify(hidden.body);
    for (const absent of ['masked', '0366', policy.body.id, rule.body.id, 'coverageDetail']) {
      expect(hiddenText).not.toContain(absent);
    }
    const shown = await ctx.http.get(scansUrl).set(headers(analystA)).expect(200);
    const entry = (shown.body.data[0].engines as Array<Record<string, unknown>>).find(
      (e) => e.engine === 'dlp',
    );
    expect(entry).toMatchObject({
      durationMs: null,
      dlp: {
        verdict: 'suspicious',
        action: 'block',
        actionSource: 'tenant_policy',
        findings: [
          { detector: 'PC1', masked: ['************0366', '************1111'] },
          { detector: 'NI1', masked: ['******234E'] },
        ],
        policy: {
          winner: { policyId: policy.body.id, ruleId: rule.body.id },
          matched: [
            { policyId: policy.body.id, ruleId: rule.body.id, action: 'block', mode: 'enforce' },
          ],
          exceptionsApplied: [],
        },
        evidence: { status: 'none', expiresAt: null, purged: false },
      },
    });
    // Another organization's message stays a 404.
    await ctx.http
      .get(`/api/v1/messages/${foreign.publicId}/scans`)
      .set(headers(analystA))
      .expect(404);
  });

  it('purges all of the organization’s evidence (202 with the counts), audited', async () => {
    const one = await outbound(orgA);
    const a = await insertDlpRound(one);
    const two = await outbound(orgA);
    const b = await insertDlpRound(two);
    const kept = await outbound(orgB);
    const c = await insertDlpRound(kept);
    await ctx.http.delete('/api/v1/dlp/evidence').set(headers(noMfaAdminA)).expect(403);
    const res = await ctx.http.delete('/api/v1/dlp/evidence').set(headers(adminA)).expect(202);
    expect(res.body.purged).toBeGreaterThanOrEqual(2);
    expect(res.body.objectsPending).toBe(0);
    expect(await objectExists(a.objectKey!)).toBe(false);
    expect(await objectExists(b.objectKey!)).toBe(false);
    expect(await objectExists(c.objectKey!)).toBe(true);
    expect(
      await ctx.prisma.dlpEvidence.count({
        where: { organizationId: orgA.id, wrappedKey: { not: null } },
      }),
    ).toBe(0);
    expect(
      await ctx.prisma.dlpEvidence.count({
        where: { organizationId: orgB.id, wrappedKey: { not: null } },
      }),
    ).toBeGreaterThanOrEqual(1);
    const [audit] = (await auditOf(orgA, 'dlp_evidence.purged')).filter(
      (row) => (row.metadata as { scope?: string }).scope === 'organization',
    );
    expect(audit?.metadata).toMatchObject({ purged: res.body.purged, reason: 'tenant_request' });
  });
});

describe('dlp scan settings (D18)', () => {
  it('stores bounded overrides, refuses out-of-bounds ones (422) and audits', async () => {
    const bad = await ctx.http
      .put('/api/v1/scan-settings/dlp')
      .set(headers(adminA))
      .send({ expectedVersion: 0, settings: { evidence: { retentionDays: 365 } } })
      .expect(422);
    expect(bad.body.code).toBe('scan_settings_invalid');
    const ok = await ctx.http
      .put('/api/v1/scan-settings/dlp')
      .set(headers(adminA))
      .send({
        expectedVersion: 0,
        settings: { inboundEnabled: true, thresholds: { credential: 0.8 } },
      })
      .expect(200);
    expect(ok.body).toMatchObject({
      engine: 'dlp',
      version: 1,
      effective: { inboundEnabled: true, thresholds: { credential: 0.8, payment_card: 0.6 } },
    });
    expect(
      await ctx.prisma.auditLog.count({
        where: {
          organizationId: orgA.id,
          action: 'scan_settings.updated',
          resourceType: 'scan_engine_settings',
        },
      }),
    ).toBeGreaterThanOrEqual(1);
  });
});

describe('organization deletion (D21)', () => {
  it('purges every DLP table and evidence object of the organization, resumably', async () => {
    const orgC = await fx.createOrganization();
    fx.registerCleanup(() => deleteLifecycleFixtures(ctx, [orgC.id]));
    fx.registerCleanup(() => purgeDlp([orgC.id]));
    const adminC = await tokenOf(
      await fx.createUser(orgC, { roles: ['organization_admin'], mfa: true }),
    );
    const policy = await ctx.http
      .post('/api/v1/dlp/policies')
      .set(headers(adminC))
      .send({ name: 'C' })
      .expect(201);
    const pattern = await ctx.http
      .post('/api/v1/dlp/patterns')
      .set(headers(adminC))
      .send({ name: 'C', pattern: `CEMP${run}-[0-9]{6}`, severity: 'low' })
      .expect(201);
    const rule = await ctx.http
      .post(`/api/v1/dlp/policies/${policy.body.id}/rules`)
      .set(headers(adminC))
      .send({
        name: 'C',
        conditions: { selectors: { customPatternIds: [pattern.body.id] } },
        action: 'alert',
      })
      .expect(201);
    await ctx.http
      .post('/api/v1/dlp/exceptions')
      .set(headers(adminC))
      .send({
        scope: 'sender_domain',
        value: 'c.example',
        ruleId: rule.body.id,
        reason: 'x',
        expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
      })
      .expect(201);
    await ctx.http
      .post('/api/v1/dlp/dictionaries')
      .set(headers(adminC))
      .send({ name: 'C', category: 'custom', severity: 'low', terms: ['c term'] })
      .expect(201);
    await ctx.http
      .put('/api/v1/dlp/compliance/aadhaar')
      .set(headers(adminC))
      .send({
        expectedVersion: 0,
        basis: 'other',
        reference: 'C ref',
        attested: true,
        reviewDueAt: new Date(Date.now() + 86_400_000).toISOString(),
      })
      .expect(200);
    const message = await outbound(orgC);
    const { objectKey } = await insertDlpRound(message);
    const otherBefore = await ctx.prisma.dlpEvidence.count({ where: { organizationId: orgA.id } });

    const repo = ctx.get(DlpTenantDataRepository);
    // Batch of 1: the purge is resumable statement by statement.
    const counts = await repo.purgeOrganization(systemScope(orgC.id), 1);
    expect(Object.keys(counts)).toEqual([...DLP_PURGE_ORDER, 'evidenceObjects']);
    expect(counts).toEqual({
      dlp_evidence: 1,
      dlp_scan_results: 1,
      dlp_exceptions: 1,
      dlp_policy_rules: 1,
      dlp_policies: 1,
      dlp_custom_patterns: 1,
      dlp_keyword_dictionaries: 1,
      dlp_compliance_settings: 1,
      evidenceObjects: 1,
    });
    expect(await objectExists(objectKey!)).toBe(false);
    const where = { organizationId: orgC.id };
    expect(
      await Promise.all([
        ctx.prisma.dlpEvidence.count({ where }),
        ctx.prisma.dlpScanResult.count({ where }),
        ctx.prisma.dlpException.count({ where }),
        ctx.prisma.dlpPolicyRule.count({ where }),
        ctx.prisma.dlpPolicy.count({ where }),
        ctx.prisma.dlpCustomPattern.count({ where }),
        ctx.prisma.dlpKeywordDictionary.count({ where }),
        ctx.prisma.dlpComplianceSettings.count({ where }),
      ]),
    ).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
    expect(await ctx.prisma.dlpEvidence.count({ where: { organizationId: orgA.id } })).toBe(
      otherBefore,
    );
    expect(Object.values(await repo.purgeOrganization(systemScope(orgC.id)))).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
  });
});
