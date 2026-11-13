/**
 * Seeds the synthetic tenants of the portal end-to-end run (step 7.1 WP6, design §9):
 * organizations `e2e-portal-alpha` / `e2e-portal-beta`, domains, users of every role, messages
 * over the last 7 days with deliveries, scan rounds and clicks, quarantine entries (one needs an
 * approver), sanitized preview and EML objects in MinIO, audit rows and one beta webhook (created
 * through the api). Idempotent: the previous run's data is removed first (cleanup.ts).
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
import { apiOrigin, optionalEnv, requireEnv } from '../support/env';
import { base32Encode } from '../support/totp';
import type { E2eState, E2eUser, UserKey } from '../support/state';
import { writeState } from '../support/state';
import { cleanup } from './cleanup';
import { mailBucket, reader, writer } from './db';
import { DAY, type MessagePlan, expectDashboard, planMessages, planSpecialAlpha } from './plan';

const sha = (text: string) => createHash('sha256').update(text).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const ALPHA = { slug: 'e2e-portal-alpha', name: 'E2E Portal Alpha' } as const;
export const BETA = { slug: 'e2e-portal-beta', name: 'E2E Portal Beta' } as const;
export const ALPHA_DOMAIN = 'alpha.e2e-portal.test';
export const ALPHA_DELETED_DOMAIN = 'old.alpha.e2e-portal.test';
export const BETA_DOMAIN = 'beta.e2e-portal.test';
export const MEMBER_COUNT = 32;
export const ALPHA_AUDIT_ROWS = 70;

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

async function createOrganization(p: PrismaClient, slug: string, name: string): Promise<Org> {
  const planDef = PLANS.find((plan) => plan.code === 'standard');
  if (!planDef) throw new Error('standard plan missing');
  const plan = await p.organizationPlan.findUniqueOrThrow({
    where: { code: 'standard' },
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

interface SeededMessage {
  plan: MessagePlan;
  id: bigint;
  publicId: string;
  recipientId: bigint;
  emlObjectKey: string;
  entry?: { id: bigint; publicId: string };
}

function messageStatus(plan: MessagePlan) {
  if (plan.action === 'quarantine') return 'quarantined' as const;
  if (plan.action === 'reject' || plan.action === 'discard') return 'rejected' as const;
  return 'delivered' as const;
}

function recipientStatus(plan: MessagePlan): RecipientStatus {
  if (plan.action === 'quarantine') return 'quarantined';
  if (plan.action === 'reject' || plan.action === 'discard') return 'discarded';
  const delivery = plan.deliveries[0]?.status;
  if (delivery === 'delivered') return 'delivered';
  if (delivery === 'bounced') return 'bounced';
  if (delivery === 'deferred') return 'deferred';
  if (delivery === 'failed' || delivery === 'expired') return 'failed';
  return 'pending';
}

async function insertMessages(
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
      version: plan.role === 'approval' ? 2 : 3,
      lifecycleRound: 0,
      envelopeFrom: plan.envelopeFrom,
      headerFrom: `Sender <${plan.envelopeFrom}>`,
      subject: plan.subject,
      internetMessageId: `<${randomUUID()}@external.e2e-portal.test>`,
      sizeBytes: 2048,
      recipientCount: 1,
      attachmentCount: 0,
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
    data: rows.map(({ plan, id }) => ({
      receivedAt: plan.receivedAt,
      messageId: id,
      organizationId: org.id,
      rcptSeq: 0,
      address: plan.recipient,
      status: recipientStatus(plan),
      finalAction: plan.action,
      direction: plan.direction,
    })),
  });
  const recipients = await p.emailRecipient.findMany({
    where: { organizationId: org.id, messageId: { in: rows.map((r) => r.id) } },
    select: { id: true, messageId: true },
  });
  const recipientOf = new Map(recipients.map((r) => [r.messageId, r.id]));
  const seeded: SeededMessage[] = rows.map((row) => ({
    ...row,
    recipientId: recipientOf.get(row.id)!,
  }));

  await p.emailDelivery.createMany({
    data: seeded.flatMap(({ plan, id, recipientId }) =>
      plan.deliveries.map((d, deliverySeq) => ({
        receivedAt: plan.receivedAt,
        messageId: id,
        recipientId,
        organizationId: org.id,
        deliverySeq,
        status: d.status,
        finalSmtpCode: d.status === 'delivered' ? 250 : d.status === 'deferred' ? 451 : 550,
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
              scanVerdict: plan.scan.status === 'completed' ? 'clean' : null,
              requiredEngines: ['rspamd'],
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
  // A lifecycle history for the approval message (received → persisted → quarantined), so the
  // release executor finds a consistent message (lifecycle.ts insertLifecycleMessage).
  for (const row of seeded.filter((r) => r.plan.role === 'approval')) {
    const steps = [
      { from: null, to: 'received' as const, reason: 'smtp_accepted' },
      { from: 'received' as const, to: 'persisted' as const, reason: 'committed' },
      { from: 'persisted' as const, to: 'quarantined' as const, reason: null },
    ];
    await p.emailMessageStatusHistory.createMany({
      data: steps.map((step, version) => ({
        receivedAt: row.plan.receivedAt,
        messageId: row.id,
        organizationId: org.id,
        version,
        fromStatus: step.from,
        toStatus: step.to,
        reasonCode: step.reason,
        changedAt: new Date(row.plan.receivedAt.getTime() + version * 1000),
        actorRole: version < 2 ? 'ingestion' : 'policy',
        actorService: version < 2 ? 'smtp-adapter' : 'policy-engine',
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
        recipientId: row.recipientId,
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
        hasAttachments: false,
        attachmentCount: 0,
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

/** Logs in through the api (as a client would) and creates a webhook of the user's tenant. */
async function createWebhook(
  email: string,
  password: string,
  name: string,
  url: string,
): Promise<string> {
  const base = apiOrigin();
  const login = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  if (!login.ok) throw new Error(`webhook owner login failed: ${login.status}`);
  const { accessToken } = (await login.json()) as { accessToken: string };
  const res = await fetch(`${base}/api/v1/webhooks`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${accessToken}`,
      'idempotency-key': randomUUID(),
    },
    body: JSON.stringify({ name, url, eventTypes: ['email.quarantined'] }),
  });
  if (res.status !== 201) {
    throw new Error(`webhook create failed: ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as { id?: string; webhook?: { id: string } };
  const id = body.webhook?.id ?? body.id;
  if (!id) throw new Error('webhook create returned no id');
  await fetch(`${base}/api/v1/auth/logout`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
    body: '{}',
  }).catch(() => undefined);
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
    const alphaDomain = await createDomain(p, alpha, ALPHA_DOMAIN);
    const alphaDeleted = await createDomain(p, alpha, ALPHA_DELETED_DOMAIN, true);
    const betaDomain = await createDomain(p, beta, BETA_DOMAIN);

    // Users (one password each; the 32 pagination members share one hash).
    const platform = await p.organization.findUniqueOrThrow({
      where: { slug: PLATFORM_ORGANIZATION_SLUG },
      select: { id: true, publicId: true, slug: true, name: true },
    });
    const spec: Record<
      UserKey,
      { email: string; roles: string[]; org: 'alpha' | 'beta' | 'platform'; name: string }
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
      alphaApprover: {
        email: `approver@${ALPHA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'alpha',
        name: 'Alpha Approver',
      },
      betaAdmin: {
        email: `admin@${BETA_DOMAIN}`,
        roles: ['organization_admin'],
        org: 'beta',
        name: 'Beta Admin',
      },
      platformAdmin: {
        email: 'platform-admin@e2e-portal.test',
        roles: ['platform_admin'],
        org: 'platform',
        name: 'E2E Platform Admin',
      },
    };
    const orgOf = { alpha, beta, platform } as const;
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
    ];
    const betaPlans = planMessages('beta', BETA_DOMAIN, now, `user0@${BETA_DOMAIN}`);
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
    for (const m of [preview, approval]) {
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

    const webhookId = await createWebhook(
      users.betaAdmin.email,
      users.betaAdmin.password,
      'Beta SIEM (e2e)',
      'https://siem.beta.e2e-portal.test/hooks/in',
    );
    const alphaWebhookId = await createWebhook(
      users.alphaAdmin.email,
      users.alphaAdmin.password,
      'Alpha SIEM (e2e)',
      'https://siem.alpha.e2e-portal.test/hooks/in',
    );

    // Expected figures for the dashboard's default range (7 days ending at the next full hour).
    const to = Math.ceil(Date.now() / 3_600_000) * 3_600_000;
    const dashboard7d = expectDashboard(
      alphaPlans,
      { primary: ALPHA_DOMAIN, deleted: ALPHA_DELETED_DOMAIN },
      to - 7 * DAY,
      to,
    );

    // The api reads lists and reports from the replica: wait until it has every row.
    const lastAlpha = alphaMessages.at(-1)!;
    await waitForReplica(async (r) => {
      const [messages, audits, approvalRow, members] = await Promise.all([
        r.emailMessage.count({ where: { organizationId: alpha.id } }),
        r.auditLog.count({
          where: { organizationId: alpha.id, correlationId: `e2e-portal-${runId}` },
        }),
        r.quarantineApprovalRequest.count({ where: { id: betaApproval.id } }),
        r.user.count({ where: { organizationId: alpha.id } }),
      ]);
      return (
        messages === alphaMessages.length &&
        audits === ALPHA_AUDIT_ROWS &&
        approvalRow === 1 &&
        members === MEMBER_COUNT + 8
      );
    }, `alpha rows (last message ${lastAlpha.publicId})`);

    const state: E2eState = {
      runId,
      seededAt: new Date(now).toISOString(),
      users,
      orgs: {
        alpha: { id: alpha.publicId, name: alpha.name, slug: alpha.slug },
        beta: { id: beta.publicId, name: beta.name, slug: beta.slug },
      },
      alpha: {
        domainId: alphaDomain.publicId,
        domainName: ALPHA_DOMAIN,
        deletedDomainName: ALPHA_DELETED_DOMAIN,
        memberCount: MEMBER_COUNT,
        userCount: MEMBER_COUNT + 8,
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
      },
      beta: {
        domainId: betaDomain.publicId,
        domainName: BETA_DOMAIN,
        messageId: betaMessages[0]!.publicId,
        entryId: betaTarget.entry!.publicId,
        approvalId: betaApproval.publicId,
        webhookId,
        marker: 'BETA-ONLY',
      },
      expected: { dashboard7d },
    };
    writeState(state);
    return {
      removed,
      messages: alphaMessages.length + betaMessages.length,
      users: Object.keys(users).length + MEMBER_COUNT,
      quarantineEntries: [...alphaMessages, ...betaMessages].filter((m) => m.entry).length,
      auditRows: ALPHA_AUDIT_ROWS + 5,
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
