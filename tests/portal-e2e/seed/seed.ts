/**
 * Seeds the synthetic tenants of the portal end-to-end run (step 7.1 WP6, design §9):
 * organizations `e2e-portal-alpha` / `e2e-portal-beta`, domains, users of every role, messages
 * over the last 7 days with deliveries, scan rounds and clicks, quarantine entries (one needs an
 * approver), sanitized preview and EML objects in MinIO, audit rows and one beta webhook (created
 * through the api); step 8.1: both tenants on the enterprise plan, archive settings and a
 * retention policy, a beta archive message (seed/archive.ts); step 8.4: `ato_detection` enabled
 * for both e2e tenants with accounts, signals and incidents written through the ATO stores
 * (seed/ato.ts); step AI-1: the assistant tenants `delta` (assistant on, policies and messages)
 * and `epsilon` (feature on, tenant setting off) (seed/assistant.ts). Idempotent: the previous
 * run's data is removed first (cleanup.ts).
 *
 * Rows are written on the writer as the api integration helpers do (preconditions, metadata
 * only; message content lives only in MinIO). Reserved `.test` domains only. Passwords are
 * generated per run and kept in memory and in the git-ignored `.auth/state.json`.
 */
import { createCipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import { PutObjectCommand } from '@aws-sdk/client-s3';
import {
  PLANS,
  PLATFORM_ORGANIZATION_SLUG,
  type PrismaClient,
  type RecipientStatus,
} from '@email-gateway/database';
import * as argon2 from 'argon2';
import { optionalEnv, requireEnv } from '../support/env';
import { base32Encode, freshTotp } from '../support/totp';
import type { E2eState, E2eUser, UserKey } from '../support/state';
import { writeState } from '../support/state';
import { type ApiSession, apiSession } from './api';
import {
  ARCHIVE_CUSTODIAN,
  ARCHIVE_POLICY_NAME,
  alphaArchiveDashboardPlans,
  prepareArchive,
} from './archive';
import {
  DELTA,
  DELTA_DOMAIN,
  EPSILON,
  EPSILON_DOMAIN,
  planDeltaMessages,
  prepareAssistant,
} from './assistant';
import { ALPHA_ATO_PLAN, BETA_ATO_PLAN, expectAtoDashboard, seedAto } from './ato';
import { cleanup } from './cleanup';
import { mailBucket, reader, writer } from './db';
import { historyOf, requiredEnginesOf, scanVerdictOf, writeMessageDetails } from './details';
import {
  DAY,
  type DeliveryPlan,
  type MessagePlan,
  expectDashboard,
  planExplorerAlpha,
  planExplorerBeta,
  planMessages,
  planSpecialAlpha,
  recipientsOf,
} from './plan';
import {
  ALPHA_DLP_POLICY_NAME,
  BETA_POLICY_NAME,
  SEEDED_POLICY_NAME,
  seedPolicies,
} from './policies';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const ALPHA = { slug: 'e2e-portal-alpha', name: 'E2E Portal Alpha' } as const;
export const BETA = { slug: 'e2e-portal-beta', name: 'E2E Portal Beta' } as const;
/** Step 8.6: an organization on the archive-only plan (ADR-0090). */
export const GAMMA = { slug: 'e2e-portal-gamma', name: 'E2E Portal Gamma Archive' } as const;
export const GAMMA_PLAN = 'archive_only';
export const ALPHA_DOMAIN = 'alpha.e2e-portal.test';
export const ALPHA_DELETED_DOMAIN = 'old.alpha.e2e-portal.test';
export const BETA_DOMAIN = 'beta.e2e-portal.test';
export const MEMBER_COUNT = 32;
export const ALPHA_AUDIT_ROWS = 70;
/** Alpha's tenant request budget (the enterprise plan value; standard is 300). */
export const ALPHA_API_REQUESTS_PER_MINUTE = 1_200;
/** Users of the role table below that belong to alpha (every role key starting with `alpha`). */
export const ALPHA_ROLE_USERS = 12;

function generatePassword(): string {
  return `E2e-${randomBytes(12).toString('base64url')}-7a`;
}

/** The api's PasswordHasher: Argon2id with the configured parameters, `m,t,p` order, NFKC. */
async function hashPassword(password: string): Promise<string> {
  const hash = await argon2.hash(password.normalize('NFKC'), {
    type: argon2.argon2id,
    memoryCost: Number(optionalEnv('AUTH_ARGON2_MEMORY_KIB', '19456')),
    timeCost: Number(optionalEnv('AUTH_ARGON2_TIME_COST', '2')),
    parallelism: Number(optionalEnv('AUTH_ARGON2_PARALLELISM', '1')),
  });
  const match = /^(\$argon2id\$v=\d+\$)([^$]+)(\$.*)$/.exec(hash);
  if (!match) return hash;
  const values = new Map(match[2]!.split(',').map((kv) => kv.split('=', 2) as [string, string]));
  return `${match[1]}m=${values.get('m')},t=${values.get('t')},p=${values.get('p')}${match[3]}`;
}

/** The api's SecretBox format (`v1.k1.<iv>.<tag>.<ciphertext>`, AES-256-GCM, AAD bound). */
function sealMfaSecret(secret: string, userId: bigint): string {
  const key = Buffer.from(requireEnv('DATA_ENCRYPTION_KEY'), 'hex');
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(Buffer.from(`mfa:user:${userId.toString()}`, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return [
    'v1',
    'k1',
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

interface Org {
  id: bigint;
  publicId: string;
  slug: string;
  name: string;
}

/**
 * The e2e tenants are on the `enterprise` plan since step 8.1 (design §9.5): it carries the
 * `archiving` feature and the `archive_retention_days` limit the archive pages need.
 */
export const E2E_PLAN = 'enterprise';

async function createOrganization(
  p: PrismaClient,
  slug: string,
  name: string,
  planCode: string = E2E_PLAN,
): Promise<Org> {
  const planDef = PLANS.find((plan) => plan.code === planCode);
  if (!planDef) throw new Error(`${planCode} plan missing`);
  const plan = await p.organizationPlan.findUniqueOrThrow({
    where: { code: planCode },
    select: { id: true },
  });
  const org = await p.organization.create({
    data: {
      slug,
      name,
      kind: 'customer',
      status: 'active',
      planId: plan.id,
      dataRegion: 'ap-south-1',
    },
    select: { id: true, publicId: true, slug: true, name: true },
  });
  await p.organizationSetting.create({ data: { organizationId: org.id, mfaRequired: false } });
  await p.organizationLimit.createMany({
    data: Object.entries(planDef.limits).map(([limitKey, value]) => ({
      organizationId: org.id,
      limitKey,
      limitValue: BigInt(value),
    })),
  });
  await p.organizationFeature.createMany({
    data: Object.entries(planDef.features).map(([featureKey, enabled]) => ({
      organizationId: org.id,
      featureKey,
      enabled: !!enabled,
    })),
  });
  await p.organizationDeployment.create({
    data: {
      organizationId: org.id,
      deploymentMode: 'saas',
      region: 'ap-south-1',
      environment: optionalEnv('APP_ENV', 'local'),
      status: 'active',
    },
  });
  return org;
}

async function createDomain(p: PrismaClient, org: Org, name: string, deleted = false) {
  const now = new Date();
  return p.domain.create({
    data: {
      organizationId: org.id,
      name,
      status: deleted ? 'deleted' : 'active',
      deletedAt: deleted ? now : null,
      statusChangedAt: now,
    },
    select: { id: true, publicId: true, name: true },
  });
}

async function createUser(
  p: PrismaClient,
  org: Org,
  input: { email: string; displayName: string; roles: string[]; passwordHash: string },
): Promise<{ id: bigint; publicId: string }> {
  const user = await p.user.create({
    data: {
      organizationId: org.id,
      email: input.email,
      displayName: input.displayName,
      status: 'active',
      passwordHash: input.passwordHash,
      emailVerifiedAt: new Date(),
    },
    select: { id: true, publicId: true },
  });
  for (const key of input.roles) {
    const role = await p.role.findFirst({
      where: { key, organizationId: null },
      select: { id: true },
    });
    if (!role) throw new Error(`Unknown system role ${key}`);
    await p.userRole.create({
      data: { userId: user.id, roleId: role.id, organizationId: org.id },
    });
  }
  return user;
}

const pad = (n: number) => String(n).padStart(2, '0');
const datePath = (d: Date) =>
  `${d.getUTCFullYear()}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCDate())}`;

export interface SeededMessage {
  plan: MessagePlan;
  id: bigint;
  publicId: string;
  /** Recipient row ids in `rcpt_seq` order. */
  recipientIds: bigint[];
  /** The initial scan round (`email_scans.id`), when the plan has one. */
  scanId: bigint | null;
  emlObjectKey: string;
  entry?: { id: bigint; publicId: string };
}

function messageStatus(plan: MessagePlan) {
  if (plan.action === 'quarantine') return 'quarantined' as const;
  if (plan.action === 'reject' || plan.action === 'discard') return 'rejected' as const;
  return 'delivered' as const;
}

function recipientStatus(plan: MessagePlan, rcptSeq: number): RecipientStatus {
  if (plan.action === 'quarantine') return 'quarantined';
  if (plan.action === 'reject' || plan.action === 'discard') return 'discarded';
  const delivery = plan.deliveries.find((d) => (d.rcptSeq ?? 0) === rcptSeq)?.status;
  if (delivery === 'delivered') return 'delivered';
  if (delivery === 'bounced') return 'bounced';
  if (delivery === 'deferred') return 'deferred';
  if (delivery === 'failed' || delivery === 'expired') return 'failed';
  return 'pending';
}

/** Final SMTP codes per delivery status (fixture values). */
function smtpCodeOf(status: DeliveryPlan['status']): number {
  return status === 'delivered' ? 250 : status === 'deferred' ? 451 : 550;
}

export async function insertMessages(
  p: PrismaClient,
  org: Org,
  plans: readonly MessagePlan[],
  domains: { primary: bigint; deleted: bigint | null },
  users: Map<string, bigint>,
): Promise<SeededMessage[]> {
  const tag = randomUUID().slice(0, 8);
  const keyOf = (plan: MessagePlan) => `v2:${sha(`e2e-portal:${tag}:${plan.key}`)}`;
  await p.messageIdentity.createMany({
    data: plans.map((plan) => ({
      organizationId: org.id,
      ingestKey: keyOf(plan),
      receivedAt: plan.receivedAt,
    })),
  });
  const identities = await p.messageIdentity.findMany({
    where: { organizationId: org.id, ingestKey: { in: plans.map(keyOf) } },
    select: { id: true, publicId: true, ingestKey: true },
  });
  const byKey = new Map(identities.map((row) => [row.ingestKey, row]));
  const rows = plans.map((plan) => {
    const identity = byKey.get(keyOf(plan))!;
    return {
      plan,
      id: identity.id,
      publicId: identity.publicId,
      emlObjectKey: `org/${org.id.toString()}/eml/${datePath(plan.receivedAt)}/${identity.id.toString()}.eml`,
    };
  });
  // Explicit columns only: the generated search keys (subject_key, sender_domain,
  // message_id_key, address_domain) are computed by MySQL and never written (step 7.2 §3.1).
  await p.emailMessage.createMany({
    data: rows.map(({ plan, id, emlObjectKey }) => ({
      id,
      receivedAt: plan.receivedAt,
      organizationId: org.id,
      domainId:
        plan.domain === 'primary'
          ? domains.primary
          : plan.domain === 'deleted'
            ? domains.deleted
            : null,
      direction: plan.direction,
      status: messageStatus(plan),
      statusChangedAt: plan.receivedAt,
      version: historyOf(plan).length - 1,
      lifecycleRound: 0,
      envelopeFrom: plan.envelopeFrom,
      // The address inside <…> of the first From header, as the smtp-adapter stores it.
      headerFrom: plan.headerFrom ?? plan.envelopeFrom,
      subject: plan.subject,
      internetMessageId: plan.internetMessageId ?? `<${randomUUID()}@external.e2e-portal.test>`,
      sizeBytes: 2048 + (plan.attachments ?? []).reduce((sum, a) => sum + a.sizeBytes, 0),
      recipientCount: recipientsOf(plan).length,
      attachmentCount: (plan.attachments ?? []).length,
      emlObjectKey,
      emlSha256: sha(emlObjectKey),
      clientIp: '198.51.100.7',
      clientHelo: 'mx.external.e2e-portal.test',
      finalVerdict: plan.verdict,
      finalAction: plan.action,
      riskScore: plan.riskScore,
    })),
  });
  await p.emailRecipient.createMany({
    data: rows.flatMap(({ plan, id }) =>
      recipientsOf(plan).map((address, rcptSeq) => ({
        receivedAt: plan.receivedAt,
        messageId: id,
        organizationId: org.id,
        rcptSeq,
        address,
        status: recipientStatus(plan, rcptSeq),
        finalAction: plan.action,
        direction: plan.direction,
      })),
    ),
  });
  const recipients = await p.emailRecipient.findMany({
    where: { organizationId: org.id, messageId: { in: rows.map((r) => r.id) } },
    select: { id: true, messageId: true, rcptSeq: true },
    orderBy: [{ messageId: 'asc' }, { rcptSeq: 'asc' }],
  });
  const recipientsOfMessage = new Map<bigint, bigint[]>();
  for (const r of recipients) {
    const list = recipientsOfMessage.get(r.messageId) ?? [];
    list[r.rcptSeq] = r.id;
    recipientsOfMessage.set(r.messageId, list);
  }
  const seeded: SeededMessage[] = rows.map((row) => ({
    ...row,
    recipientIds: recipientsOfMessage.get(row.id)!,
    scanId: null,
  }));

  await p.emailDelivery.createMany({
    data: seeded.flatMap(({ plan, id, recipientIds }) =>
      plan.deliveries.map((d) => ({
        receivedAt: plan.receivedAt,
        messageId: id,
        recipientId: recipientIds[d.rcptSeq ?? 0]!,
        organizationId: org.id,
        deliverySeq: 0,
        status: d.status,
        finalSmtpCode: smtpCodeOf(d.status),
        deliveredAt:
          d.deliveredAfterMs === null
            ? null
            : new Date(plan.receivedAt.getTime() + d.deliveredAfterMs),
        statusChangedAt: plan.receivedAt,
      })),
    ),
  });
  await p.emailScan.createMany({
    data: seeded.flatMap(({ plan, id }) =>
      plan.scan
        ? [
            {
              receivedAt: plan.receivedAt,
              messageId: id,
              organizationId: org.id,
              scanKind: 'initial' as const,
              status: plan.scan.status,
              lifecycleRound: 0,
              scanVerdict: plan.scan.status === 'completed' ? scanVerdictOf(plan) : null,
              requiredEngines: requiredEnginesOf(plan),
              reasonCodes: [],
              startedAt: plan.receivedAt,
              completedAt:
                plan.scan.completedAfterMs === null
                  ? null
                  : new Date(plan.receivedAt.getTime() + plan.scan.completedAfterMs),
              deadlineAt: new Date(plan.receivedAt.getTime() + 1_800_000),
            },
          ]
        : [],
    ),
  });
  const scans = await p.emailScan.findMany({
    where: { organizationId: org.id, messageId: { in: seeded.map((m) => m.id) } },
    select: { id: true, messageId: true },
  });
  const scanOf = new Map(scans.map((scan) => [scan.messageId, scan.id]));
  for (const row of seeded) row.scanId = scanOf.get(row.id) ?? null;
  // A lifecycle history for the special messages (the release executor needs a consistent
  // message, lifecycle.ts insertLifecycleMessage) and for the details messages (step 7.2).
  for (const row of seeded.filter((r) => r.plan.role === 'approval' || r.plan.details)) {
    await p.emailMessageStatusHistory.createMany({
      data: historyOf(row.plan).map((step, version) => ({
        receivedAt: row.plan.receivedAt,
        messageId: row.id,
        organizationId: org.id,
        version,
        fromStatus: step.from,
        toStatus: step.to,
        reasonCode: step.reason,
        changedAt: new Date(row.plan.receivedAt.getTime() + version * 1000),
        actorRole: step.role,
        actorService: step.service,
        actorType: 'system' as const,
        transitionKey: sha(`e2e-portal:${row.id.toString()}:${version}`),
        occurredAt: new Date(row.plan.receivedAt.getTime() + version * 1000),
      })),
    });
  }
  // Quarantine entries (the policy-engine's column set, apps/api/integration/support/quarantine.ts).
  for (const row of seeded) {
    const q = row.plan.quarantine;
    if (!q) continue;
    const quarantinedAt = new Date(row.plan.receivedAt.getTime() + q.afterMs);
    const terminal = q.state === 'released' || q.state === 'rejected' || q.state === 'expired';
    row.entry = await p.quarantineMessage.create({
      data: {
        organizationId: org.id,
        messageId: row.id,
        messageReceivedAt: row.plan.receivedAt,
        lifecycleRound: 0,
        recipientId: row.recipientIds[0]!,
        rcptSeq: 0,
        recipientAddress: row.plan.recipient,
        userId: users.get(row.plan.recipient) ?? null,
        direction: row.plan.direction,
        kind: 'quarantine',
        origin: 'policy',
        reason: q.reason,
        status: q.state,
        envelopeFrom: row.plan.envelopeFrom,
        headerFrom: null,
        hasAttachments: (row.plan.attachments ?? []).length > 0,
        attachmentCount: (row.plan.attachments ?? []).length,
        sizeBytes: 2048,
        riskScore: row.plan.riskScore,
        riskLevel:
          row.plan.riskScore >= 600 ? 'high' : row.plan.riskScore >= 300 ? 'medium' : 'low',
        recommendedAction: 'quarantine',
        riskVerdict: row.plan.verdict,
        hasHardBlock: false,
        hardBlocks: [],
        reasonCodes: ['policy.disposition.quarantine'],
        floorReasons: [],
        primaryEngine: 'rspamd',
        decisionSource: 'platform_default',
        explanation: [{ code: 'summary', params: { disposition: 'quarantine' } }],
        explanationText: 'Final disposition quarantine (e2e seed).',
        emlObjectKey: row.emlObjectKey,
        quarantinedAt,
        expiresAt: new Date(quarantinedAt.getTime() + 30 * DAY),
        stateChangedAt: terminal ? new Date(quarantinedAt.getTime() + 60_000) : quarantinedAt,
        ...(q.state === 'released'
          ? { releasedAt: new Date(quarantinedAt.getTime() + 60_000) }
          : {}),
      },
      select: { id: true, publicId: true },
    });
  }
  return seeded;
}

async function putObject(key: string, body: string, contentType: string): Promise<void> {
  const { s3, bucket } = mailBucket();
  try {
    await s3.send(
      new PutObjectCommand({ Bucket: bucket, Key: key, Body: body, ContentType: contentType }),
    );
  } finally {
    s3.destroy();
  }
}

function syntheticEml(plan: MessagePlan, body: string): string {
  return [
    `From: Sender <${plan.envelopeFrom}>`,
    `To: <${plan.recipient}>`,
    `Subject: ${plan.subject}`,
    `Date: ${plan.receivedAt.toUTCString()}`,
    `Message-ID: <${randomUUID()}@external.e2e-portal.test>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
    '',
  ].join('\r\n');
}

/** Creates a webhook of the session user's tenant through the api. */
async function createWebhook(api: ApiSession, name: string, url: string): Promise<string> {
  const res = await api.call<{ id?: string; webhook?: { id: string } }>(
    'POST',
    '/webhooks',
    { name, url, eventTypes: ['email.quarantined'] },
    { idempotent: true, expect: 201 },
  );
  const id = res.body.webhook?.id ?? res.body.id;
  if (!id) throw new Error('webhook create returned no id');
  return id;
}

async function waitForReplica(
  check: (r: PrismaClient) => Promise<boolean>,
  what: string,
): Promise<void> {
  const r = reader();
  try {
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      if (await check(r)) return;
      await sleep(250);
    }
    throw new Error(`replica did not catch up: ${what}`);
  } finally {
    await r.$disconnect();
  }
}

export interface SeedSummary {
  removed: Awaited<ReturnType<typeof cleanup>>;
  messages: number;
  users: number;
  quarantineEntries: number;
  auditRows: number;
  durationMs: number;
}

export async function seed(): Promise<SeedSummary> {
  const started = Date.now();
  const p = writer();
  try {
    const removed = await cleanup(p);
    const now = Date.now();
    const runId = randomUUID();

    const alpha = await createOrganization(p, ALPHA.slug, ALPHA.name);
    const beta = await createOrganization(p, BETA.slug, BETA.name);
    const gamma = await createOrganization(p, GAMMA.slug, GAMMA.name, GAMMA_PLAN);
    // Step AI-1: the assistant tenants (seed/assistant.ts).
    const delta = await createOrganization(p, DELTA.slug, DELTA.name);
    const epsilon = await createOrganization(p, EPSILON.slug, EPSILON.name);
    // The suite drives alpha's whole traffic through ten users within minutes (step 7.2 adds 14
    // details sections per role): the tenant budget of the standard plan (300 requests per
    // minute for the whole organization) would answer `429` to later specs. Alpha gets the
    // enterprise plan's tenant budget, as a platform operator would raise a tenant's limit; the
    // per-principal, sensitive and expensive limits stay at the shipped defaults, and the tenant
    // limit itself is verified by the api suites (apps/api/integration/conventions.test.ts).
    await p.organizationLimit.updateMany({
      where: { organizationId: alpha.id, limitKey: 'api_requests_per_minute' },
      data: { limitValue: BigInt(ALPHA_API_REQUESTS_PER_MINUTE) },
    });
    const alphaDomain = await createDomain(p, alpha, ALPHA_DOMAIN);
    const alphaDeleted = await createDomain(p, alpha, ALPHA_DELETED_DOMAIN, true);
    const betaDomain = await createDomain(p, beta, BETA_DOMAIN);
    const deltaDomain = await createDomain(p, delta, DELTA_DOMAIN);
    await createDomain(p, epsilon, EPSILON_DOMAIN);

    // Users (one password each; the 32 pagination members share one hash).
    const platform = await p.organization.findUniqueOrThrow({
      where: { slug: PLATFORM_ORGANIZATION_SLUG },
      select: { id: true, publicId: true, slug: true, name: true },
    });
    const spec: Record<
      UserKey,
      {
        email: string;
        roles: string[];
        org: 'alpha' | 'beta' | 'gamma' | 'delta' | 'epsilon' | 'platform';
        name: string;
      }
    > = {
      alphaAdmin: {
        email: `admin@${ALPHA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'alpha',
        name: 'Alpha Admin',
      },
      alphaAnalyst: {
        email: `analyst@${ALPHA_DOMAIN}`,
        roles: ['security_analyst'],
        org: 'alpha',
        name: 'Alpha Analyst',
      },
      alphaReadOnly: {
        email: `readonly@${ALPHA_DOMAIN}`,
        roles: ['read_only_user'],
        org: 'alpha',
        name: 'Alpha Read-only',
      },
      alphaReviewer: {
        email: `reviewer@${ALPHA_DOMAIN}`,
        roles: ['quarantine_reviewer'],
        org: 'alpha',
        name: 'Alpha Reviewer',
      },
      alphaAuditor: {
        email: `auditor@${ALPHA_DOMAIN}`,
        roles: ['compliance_auditor'],
        org: 'alpha',
        name: 'Alpha Auditor',
      },
      alphaDomainAdmin: {
        email: `domains@${ALPHA_DOMAIN}`,
        roles: ['domain_admin'],
        org: 'alpha',
        name: 'Alpha Domain Admin',
      },
      alphaMailbox: {
        email: `mailbox@${ALPHA_DOMAIN}`,
        roles: ['mailbox_user'],
        org: 'alpha',
        name: 'Alpha Mailbox',
      },
      alphaMfaAdmin: {
        email: `mfa-admin@${ALPHA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'alpha',
        name: 'Alpha MFA Admin',
      },
      // Step 8.6: an admin that existed before the split keeps archive access through the
      // migrated compliance_officer assignment (ADR-0089); alphaAdmin is a new admin without it.
      alphaApprover: {
        email: `approver@${ALPHA_DOMAIN}`,
        roles: ['organization_admin', 'compliance_officer'],
        org: 'alpha',
        name: 'Alpha Approver',
      },
      // Step 8.1: a compliance auditor with MFA (case searches, exports and their downloads).
      alphaAuditorMfa: {
        email: `auditor-mfa@${ALPHA_DOMAIN}`,
        roles: ['compliance_auditor'],
        org: 'alpha',
        name: 'Alpha MFA Auditor',
      },
      alphaCompliance: {
        email: `compliance@${ALPHA_DOMAIN}`,
        roles: ['compliance_officer'],
        org: 'alpha',
        name: 'Alpha Compliance Officer',
      },
      alphaAccessAdmin: {
        email: `access-admin@${ALPHA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'alpha',
        name: 'Alpha Access Admin',
      },
      betaAdmin: {
        email: `admin@${BETA_DOMAIN}`,
        roles: ['organization_admin', 'compliance_officer'],
        org: 'beta',
        name: 'Beta Admin',
      },
      gammaAdmin: {
        email: 'admin@gamma.e2e-portal.test',
        roles: ['organization_admin', 'compliance_officer'],
        org: 'gamma',
        name: 'Gamma Archive Admin',
      },
      // Step AI-1: the assistant tenants. The analyst chats (assistant:use + reads), the mailbox
      // user holds no assistant:use; epsilon's admin sees why the assistant is off.
      deltaAdmin: {
        email: `admin@${DELTA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'delta',
        name: 'Delta Admin',
      },
      deltaAnalyst: {
        email: `analyst@${DELTA_DOMAIN}`,
        roles: ['security_analyst'],
        org: 'delta',
        name: 'Delta Analyst',
      },
      deltaMailbox: {
        email: `mailbox@${DELTA_DOMAIN}`,
        roles: ['mailbox_user'],
        org: 'delta',
        name: 'Delta Mailbox',
      },
      // Step AI-2: a delta admin with MFA (re-authentication of high-risk confirmations).
      deltaMfaAdmin: {
        email: `mfa-admin@${DELTA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'delta',
        name: 'Delta MFA Admin',
      },
      epsilonAdmin: {
        email: `admin@${EPSILON_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'epsilon',
        name: 'Epsilon Admin',
      },
      platformAdmin: {
        email: 'platform-admin@e2e-portal.test',
        roles: ['platform_admin'],
        org: 'platform',
        name: 'E2E Platform Admin',
      },
    };
    const orgOf = { alpha, beta, gamma, delta, epsilon, platform } as const;
    const users = {} as Record<UserKey, E2eUser>;
    const userIds = new Map<string, bigint>();
    for (const [key, s] of Object.entries(spec) as Array<[UserKey, (typeof spec)[UserKey]]>) {
      const password = generatePassword();
      const user = await createUser(p, orgOf[s.org], {
        email: s.email,
        displayName: s.name,
        roles: s.roles,
        passwordHash: await hashPassword(password),
      });
      userIds.set(s.email, user.id);
      users[key] = { email: s.email, password, roles: s.roles, organization: s.org };
    }
    // The approver signs in with MFA (approvals and downloads need an MFA session).
    const approverSecret = base32Encode(randomBytes(20));
    const approverId = userIds.get(spec.alphaApprover.email)!;
    await p.user.update({
      where: { id: approverId },
      data: { mfaEnabled: true, mfaSecretCiphertext: sealMfaSecret(approverSecret, approverId) },
    });
    users.alphaApprover.totpSecret = approverSecret;
    const auditorSecret = base32Encode(randomBytes(20));
    const auditorId = userIds.get(spec.alphaAuditorMfa.email)!;
    await p.user.update({
      where: { id: auditorId },
      data: { mfaEnabled: true, mfaSecretCiphertext: sealMfaSecret(auditorSecret, auditorId) },
    });
    users.alphaAuditorMfa.totpSecret = auditorSecret;
    // Step 8.6: the compliance officer signs in with MFA (archive previews and downloads).
    const complianceSecret = base32Encode(randomBytes(20));
    const complianceId = userIds.get(spec.alphaCompliance.email)!;
    await p.user.update({
      where: { id: complianceId },
      data: {
        mfaEnabled: true,
        mfaSecretCiphertext: sealMfaSecret(complianceSecret, complianceId),
      },
    });
    users.alphaCompliance.totpSecret = complianceSecret;
    // Step 8.6 review fix: an organization admin (no archive access) with MFA delegates it.
    const accessSecret = base32Encode(randomBytes(20));
    const accessId = userIds.get(spec.alphaAccessAdmin.email)!;
    await p.user.update({
      where: { id: accessId },
      data: { mfaEnabled: true, mfaSecretCiphertext: sealMfaSecret(accessSecret, accessId) },
    });
    users.alphaAccessAdmin.totpSecret = accessSecret;
    // Step AI-2: the delta admin with MFA (password + code for high-risk confirmations).
    const deltaMfaSecret = base32Encode(randomBytes(20));
    const deltaMfaId = userIds.get(spec.deltaMfaAdmin.email)!;
    await p.user.update({
      where: { id: deltaMfaId },
      data: { mfaEnabled: true, mfaSecretCiphertext: sealMfaSecret(deltaMfaSecret, deltaMfaId) },
    });
    users.deltaMfaAdmin.totpSecret = deltaMfaSecret;

    const memberHash = await hashPassword(generatePassword());
    const memberIds: string[] = [];
    for (let i = 1; i <= MEMBER_COUNT; i++) {
      const member = await createUser(p, alpha, {
        email: `member${String(i).padStart(2, '0')}@${ALPHA_DOMAIN}`,
        displayName: `Alpha Member ${String(i).padStart(2, '0')}`,
        roles: ['read_only_user'],
        passwordHash: memberHash,
      });
      memberIds.push(member.publicId);
    }

    // Messages.
    const mailbox = spec.alphaMailbox.email;
    const alphaPlans = [
      ...planMessages('alpha', ALPHA_DOMAIN, now, mailbox),
      ...planSpecialAlpha(now, ALPHA_DOMAIN, mailbox),
      ...planExplorerAlpha(now, ALPHA_DOMAIN),
    ];
    const betaPlans = [
      ...planMessages('beta', BETA_DOMAIN, now, `user0@${BETA_DOMAIN}`),
      ...planExplorerBeta(now),
    ];
    const alphaMessages = await insertMessages(
      p,
      alpha,
      alphaPlans,
      { primary: alphaDomain.id, deleted: alphaDeleted.id },
      userIds,
    );
    const betaMessages = await insertMessages(
      p,
      beta,
      betaPlans,
      { primary: betaDomain.id, deleted: null },
      userIds,
    );
    // Step AI-1: delta's messages (two held in quarantine today) for the assistant's read tools.
    const deltaPlans = planDeltaMessages(now);
    await insertMessages(p, delta, deltaPlans, { primary: deltaDomain.id, deleted: null }, userIds);

    // Step 7.2: attachments, URLs and the engine rows of the details sections.
    await writeMessageDetails(p, alpha.id, alphaMessages);
    await writeMessageDetails(p, beta.id, betaMessages);
    const byKey = (key: string) => {
      const found = [...alphaMessages, ...betaMessages].find((m) => m.plan.key === key);
      if (!found) throw new Error(`seed plan has no message ${key}`);
      return found;
    };

    // Objects: the EML of the special messages and the decoded HTML part of the preview message
    // (the preview sanitizer drops the script and defangs the link, step 5.3 Q11).
    const preview = alphaMessages.find((m) => m.plan.role === 'preview')!;
    const approval = alphaMessages.find((m) => m.plan.role === 'approval')!;
    const previewMarker = 'E2E-PREVIEW-MARKER quarterly newsletter';
    const htmlKey = `org/${alpha.id.toString()}/part/${datePath(preview.plan.receivedAt)}/${preview.id.toString()}/1.html`;
    const html =
      '<html><head><script>window.__e2eInjected = 1</script></head><body>' +
      `<p>${previewMarker}</p><p>Read it at <a href="http://newsletter.e2e-portal.test/read">the archive</a>.</p>` +
      '<img src="http://tracker.e2e-portal.test/pixel.gif"></body></html>';
    await putObject(htmlKey, html, 'text/html');
    await p.emailMessageParse.create({
      data: {
        receivedAt: preview.plan.receivedAt,
        messageId: preview.id,
        organizationId: alpha.id,
        status: 'parsed',
        parserVersion: 'e2e/1',
        htmlBodyObjectKey: htmlKey,
        htmlBodySizeBytes: Buffer.byteLength(html),
        startedAt: preview.plan.receivedAt,
        completedAt: preview.plan.receivedAt,
      },
    });
    // The details approval target is released by the quarantine executor after the approval
    // in details.spec, like the 7.1 approval message: it needs its EML too.
    for (const m of [preview, approval, byKey('alpha-detail-approval')]) {
      const eml = syntheticEml(
        m.plan,
        `${m.plan.subject}\r\nSynthetic e2e message; no real content.`,
      );
      await putObject(m.emlObjectKey, eml, 'message/rfc822');
      await p.emailMessage.updateMany({
        where: { id: m.id, receivedAt: m.plan.receivedAt },
        data: { sizeBytes: Buffer.byteLength(eml), emlSha256: sha(eml) },
      });
      await p.quarantineMessage.updateMany({
        where: { messageId: m.id, organizationId: alpha.id },
        data: { sizeBytes: Buffer.byteLength(eml) },
      });
    }

    // URL clicks on six alpha messages (URL protection page).
    const clickMessages = alphaMessages.filter((m) => m.plan.direction === 'inbound').slice(0, 6);
    for (const [index, m] of clickMessages.entries()) {
      const url = `https://link${index}.external.e2e-portal.test/landing`;
      await p.messageUrl.create({
        data: {
          receivedAt: m.plan.receivedAt,
          messageId: m.id,
          organizationId: alpha.id,
          urlSeq: 0,
          url,
          urlSha256: sha(url),
          scheme: 'https',
          host: `link${index}.external.e2e-portal.test`,
          registrableDomain: 'e2e-portal.test',
          hostKind: 'domain',
          sources: { html_href: 1 },
          occurrences: 1,
          firstLifecycleRound: 0,
          extractorVersion: 'url-extract/1',
        },
      });
      await p.urlClickEvent.create({
        data: {
          clickedAt: new Date(m.plan.receivedAt.getTime() + 120_000),
          publicId: randomUUID(),
          organizationId: alpha.id,
          messageId: m.id,
          messageReceivedAt: m.plan.receivedAt,
          urlSeq: 0,
          decision: index % 3 === 0 ? 'blocked' : index % 3 === 1 ? 'warned' : 'allowed',
          verdict: index % 3 === 0 ? 'malicious' : index % 3 === 1 ? 'suspicious' : 'clean',
          reasonCodes: index % 3 === 0 ? ['url.feed_malicious'] : [],
          tokenKid: 1,
          clientNetwork: '203.0.113.0/24',
          durationMs: 5,
        },
      });
    }

    // Beta: a pending release request (isolation target for /quarantine/approvals/<id>).
    const betaTarget = betaMessages.find((m) => m.entry && m.plan.quarantine?.state === 'held')!;
    const betaAdminId = userIds.get(spec.betaAdmin.email)!;
    const betaApproval = await p.quarantineApprovalRequest.create({
      data: {
        organizationId: beta.id,
        quarantineMessageId: betaTarget.entry!.id,
        kind: 'release_request',
        approvalReasons: ['no_scan_round'],
        requestedByType: 'user',
        requestedByUserId: betaAdminId,
        expiresAt: new Date(now + DAY),
      },
      select: { id: true, publicId: true },
    });
    await p.quarantineMessage.update({
      where: { id: betaTarget.entry!.id },
      data: { status: 'pending_approval', approvalRequestId: betaApproval.id },
    });

    // Alpha: a pending release request by the reviewer (approvals list and the emailed
    // `/quarantine/approvals/<id>` link). Not the approval-flow entry of quarantine.spec.
    const alphaPendingTarget = alphaMessages.find(
      (m) =>
        m.entry &&
        m.plan.quarantine?.state === 'held' &&
        !m.plan.role &&
        m.plan.recipient !== mailbox,
    )!;
    const alphaPending = await p.quarantineApprovalRequest.create({
      data: {
        organizationId: alpha.id,
        quarantineMessageId: alphaPendingTarget.entry!.id,
        kind: 'release_request',
        approvalReasons: ['no_scan_round'],
        requestedByType: 'user',
        requestedByUserId: userIds.get(spec.alphaReviewer.email)!,
        expiresAt: new Date(now + DAY),
      },
      select: { id: true, publicId: true },
    });
    await p.quarantineMessage.update({
      where: { id: alphaPendingTarget.entry!.id },
      data: { status: 'pending_approval', approvalRequestId: alphaPending.id },
    });

    // Audit rows (append-only; never deleted by the cleanup, as in the integration suites).
    const actions = [
      'domain.updated',
      'user.invited',
      'policy.updated',
      'quarantine.released',
      'webhook.updated',
      'settings.updated',
      'api_key.created',
    ];
    await p.auditLog.createMany({
      data: Array.from({ length: ALPHA_AUDIT_ROWS }, (_, i) => {
        const action = actions[i % actions.length]!;
        return {
          createdAt: new Date(now - 30 * 60_000 - i * Math.floor((5 * DAY) / ALPHA_AUDIT_ROWS)),
          organizationId: alpha.id,
          actorType: 'user' as const,
          actorId: null,
          action,
          resourceType: action.split('.')[0]!,
          resourceId: null,
          correlationId: `e2e-portal-${runId}`,
          sourceIp: '203.0.113.50',
          metadata: { fixture: 'e2e-portal', seq: i },
        };
      }),
    });
    await p.auditLog.createMany({
      data: Array.from({ length: 5 }, (_, i) => ({
        createdAt: new Date(now - 45 * 60_000 - i * 3_600_000),
        organizationId: beta.id,
        actorType: 'user' as const,
        action: 'e2e_beta.marker_event',
        resourceType: 'e2e_beta',
        correlationId: `e2e-portal-${runId}`,
        sourceIp: '203.0.113.60',
        metadata: { fixture: 'e2e-portal' },
      })),
    });

    // Step 7.2: message-resource audit rows of the details phish message (audit history
    // section), and a saved view of the beta administrator (isolation target).
    const phish = byKey('alpha-detail-phish');
    await p.auditLog.createMany({
      data: [
        { action: 'message.rescan_requested', minutesAgo: 19 },
        { action: 'message.revealed', minutesAgo: 18 },
      ].map((row) => ({
        createdAt: new Date(now - row.minutesAgo * 60_000),
        organizationId: alpha.id,
        actorType: 'user' as const,
        actorId: null,
        action: row.action,
        resourceType: 'message',
        resourceId: phish.publicId,
        correlationId: `e2e-portal-${runId}`,
        sourceIp: '203.0.113.50',
        metadata:
          row.action === 'message.revealed'
            ? { fixture: 'e2e-portal', fields: ['subject'], bulk: true }
            : { fixture: 'e2e-portal' },
      })),
    });
    const betaView = await p.savedView.create({
      data: {
        organizationId: beta.id,
        userId: betaAdminId,
        kind: 'message_explorer',
        name: 'Beta inbound (e2e)',
        definition: {
          version: 1,
          filters: { direction: 'inbound' },
          sort: '-receivedAt',
          range: { kind: 'relative', preset: '24h' },
          columns: null,
        },
      },
      select: { publicId: true },
    });

    // Writes through the api, as the seeded administrators (one session each).
    const betaApi = await apiSession(users.betaAdmin.email, users.betaAdmin.password);
    const alphaApi = await apiSession(users.alphaAdmin.email, users.alphaAdmin.password);
    let webhookId: string;
    let alphaWebhookId: string;
    let policies: Awaited<ReturnType<typeof seedPolicies>>;
    let archive: Awaited<ReturnType<typeof prepareArchive>>;
    try {
      webhookId = await createWebhook(
        betaApi,
        'Beta SIEM (e2e)',
        'https://siem.beta.e2e-portal.test/hooks/in',
      );
      alphaWebhookId = await createWebhook(
        alphaApi,
        'Alpha SIEM (e2e)',
        'https://siem.alpha.e2e-portal.test/hooks/in',
      );
      // Step 7.3: departments, policies with versions, DLP/BEC rows (seed/policies.ts).
      policies = await seedPolicies(p, alphaApi, betaApi, {
        alphaOrg: alpha.id,
        betaOrg: beta.id,
        alphaMemberUserId: memberIds[0]!,
        domainName: ALPHA_DOMAIN,
      });
      // Step 8.1: archive tenants (seed/archive.ts). PUT /archive/settings is an MFA route.
      const { code, step } = await freshTotp(approverSecret, undefined);
      users.alphaApprover.lastTotpStep = step;
      const approverApi = await apiSession(
        users.alphaApprover.email,
        users.alphaApprover.password,
        { code },
      );
      try {
        archive = await prepareArchive(p, {
          alphaApprover: approverApi,
          betaOrg: beta.id,
        });
      } finally {
        await approverApi.logout();
      }
    } finally {
      await alphaApi.logout();
      await betaApi.logout();
    }

    // Step AI-1: the assistant on for delta (feature + tenant setting through the api) with its
    // policies, the feature only for epsilon (seed/assistant.ts).
    const deltaApi = await apiSession(users.deltaAdmin.email, users.deltaAdmin.password);
    let deltaPolicies: Awaited<ReturnType<typeof prepareAssistant>>;
    try {
      deltaPolicies = await prepareAssistant(p, {
        deltaOrg: delta.id,
        epsilonOrg: epsilon.id,
        deltaAdmin: deltaApi,
      });
    } finally {
      await deltaApi.logout();
    }

    // Step 8.4: account takeover accounts, signals and incidents of both tenants (seed/ato.ts).
    const ato = await seedAto(p, {
      alpha: { id: alpha.id, domain: ALPHA_DOMAIN },
      beta: { id: beta.id, domain: BETA_DOMAIN },
    });

    // Expected figures for the dashboard's default range (7 days ending at the next full hour).
    const to = Math.ceil(Date.now() / 3_600_000) * 3_600_000;
    // Step 8.1: the alpha archive messages the archive spec inserts during the run count too
    // (the dashboard spec makes sure they exist before it compares).
    const dashboard7d = expectDashboard(
      [...alphaPlans, ...alphaArchiveDashboardPlans(Date.now())],
      { primary: ALPHA_DOMAIN, deleted: ALPHA_DELETED_DOMAIN },
      to - 7 * DAY,
      to,
    );

    // The api reads lists and reports from the replica: wait until it has every row.
    const lastAlpha = alphaMessages.at(-1)!;
    await waitForReplica(async (r) => {
      const [
        messages,
        audits,
        approvalRow,
        members,
        versions,
        suppressions,
        atoAccounts,
        deltaPolicyRows,
        deltaSettings,
        deltaEntries,
      ] = await Promise.all([
        r.emailMessage.count({ where: { organizationId: alpha.id } }),
        r.auditLog.count({
          where: { organizationId: alpha.id, correlationId: `e2e-portal-${runId}` },
        }),
        r.quarantineApprovalRequest.count({ where: { id: betaApproval.id } }),
        r.user.count({ where: { organizationId: alpha.id } }),
        r.policyVersion.count({ where: { organizationId: { in: [alpha.id, beta.id] } } }),
        r.becSuppressionRule.count({ where: { organizationId: { in: [alpha.id, beta.id] } } }),
        r.atoAccount.count({ where: { organizationId: { in: [alpha.id, beta.id] } } }),
        r.emailPolicy.count({ where: { organizationId: delta.id } }),
        r.aiChatSettings.count({ where: { organizationId: delta.id, enabled: true } }),
        r.quarantineMessage.count({ where: { organizationId: delta.id } }),
      ]);
      return (
        messages === alphaMessages.length &&
        audits === ALPHA_AUDIT_ROWS + 2 &&
        approvalRow === 1 &&
        members === MEMBER_COUNT + ALPHA_ROLE_USERS &&
        versions === 4 &&
        suppressions === 2 &&
        atoAccounts === ALPHA_ATO_PLAN.length + BETA_ATO_PLAN.length &&
        deltaPolicyRows === deltaPolicies.length &&
        deltaSettings === 1 &&
        deltaEntries === deltaPlans.filter((m) => m.quarantine).length
      );
    }, `alpha rows (last message ${lastAlpha.publicId})`);

    const state: E2eState = {
      runId,
      seededAt: new Date(now).toISOString(),
      users,
      orgs: {
        alpha: { id: alpha.publicId, name: alpha.name, slug: alpha.slug },
        beta: { id: beta.publicId, name: beta.name, slug: beta.slug },
        gamma: { id: gamma.publicId, name: gamma.name, slug: gamma.slug },
        delta: { id: delta.publicId, name: delta.name, slug: delta.slug },
        epsilon: { id: epsilon.publicId, name: epsilon.name, slug: epsilon.slug },
      },
      alpha: {
        domainId: alphaDomain.publicId,
        domainName: ALPHA_DOMAIN,
        deletedDomainName: ALPHA_DELETED_DOMAIN,
        memberCount: MEMBER_COUNT,
        userCount: MEMBER_COUNT + ALPHA_ROLE_USERS,
        messagesLast24h: alphaPlans.filter((m) => m.receivedAt.getTime() >= now - DAY).length,
        messageId: alphaMessages[0]!.publicId,
        approvalEntryId: approval.entry!.publicId,
        approvalMessageId: approval.publicId,
        previewEntryId: preview.entry!.publicId,
        previewText: previewMarker,
        auditRows: ALPHA_AUDIT_ROWS,
        webhookId: alphaWebhookId,
        pendingApprovalId: alphaPending.publicId,
        memberUserId: memberIds[0]!,
        explorer: Object.fromEntries(
          alphaMessages
            .filter(
              (m) =>
                m.plan.key.startsWith('alpha-search-') || m.plan.key.startsWith('alpha-detail-'),
            )
            .map((m) => [m.plan.key, m.publicId]),
        ),
        previewMessageId: preview.publicId,
        recentReceivedAt: alphaPlans
          .filter((m) => m.receivedAt.getTime() >= now - 2 * 3_600_000)
          .map((m) => m.receivedAt.toISOString())
          .sort(),
      },
      beta: {
        domainId: betaDomain.publicId,
        domainName: BETA_DOMAIN,
        messageId: betaMessages[0]!.publicId,
        entryId: betaTarget.entry!.publicId,
        approvalId: betaApproval.publicId,
        webhookId,
        marker: 'BETA-ONLY',
        twinMessageId: byKey('beta-search-twin').publicId,
        savedViewId: betaView.publicId,
      },
      policies: {
        departments: policies.departments,
        policyId: policies.policyId,
        policyName: SEEDED_POLICY_NAME,
        dlpPolicyId: policies.dlpPolicyId,
        dlpPolicyName: ALPHA_DLP_POLICY_NAME,
        suppressionId: policies.suppressionId,
        beta: {
          policyId: policies.betaPolicyId,
          policyName: BETA_POLICY_NAME,
          ...policies.beta,
        },
      },
      expected: { dashboard7d },
      archive: {
        custodian: ARCHIVE_CUSTODIAN,
        policyId: archive.alphaPolicyId,
        policyName: ARCHIVE_POLICY_NAME,
        betaMessageId: archive.betaMessages[0]!.publicId,
      },
      assistant: {
        delta: {
          policies: deltaPolicies,
          quarantinedSubjects: deltaPlans.filter((m) => m.quarantine).map((m) => m.subject),
        },
      },
      ato: {
        alpha: ato.alpha,
        beta: ato.beta,
        expected: expectAtoDashboard(ALPHA_ATO_PLAN),
      },
    };
    writeState(state);
    return {
      removed,
      messages: alphaMessages.length + betaMessages.length,
      users: Object.keys(users).length + MEMBER_COUNT,
      quarantineEntries: [...alphaMessages, ...betaMessages].filter((m) => m.entry).length,
      auditRows: ALPHA_AUDIT_ROWS + 2 + 5,
      durationMs: Date.now() - started,
    };
  } finally {
    await p.$disconnect();
  }
}

export async function clean(): Promise<Awaited<ReturnType<typeof cleanup>>> {
  const p = writer();
  try {
    return await cleanup(p);
  } finally {
    await p.$disconnect();
  }
}
