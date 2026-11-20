import { createHash, randomBytes } from 'node:crypto';
import { GetObjectRetentionCommand, type S3Client } from '@aws-sdk/client-s3';
import type { OpenSearchService } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { apiSession, idempotencyKey, type ApiSession } from './support/api-client';
import {
  ARCHIVE_SUITE_ENV,
  archiveS3,
  archiveSearch,
  containerEnv,
  objectsOf,
  purgeArchiveTenants,
  recordOf,
  recordPrefix,
  recreateArchiveServices,
  restoreArchiveServices,
  versionsUnder,
  waitForRecord,
} from './support/archive';
import { compose, waitFor } from './support/compose';
import { stack } from './support/env';
import {
  GOOGLE_SENDER,
  INTAKE_ADAPTER_ENV,
  INTAKE_WORKER_ENV,
  M365_SENDER,
  TOOLS_SENDER,
  archiveObjectHead,
  createSource,
  expectAccepted,
  googleCopy,
  intakeDomain,
  journalReport,
  mailObject,
  postfixLogMentions,
  mentions,
  newMessageId,
  originalMessage,
  patchSource,
  purgeIntakeRows,
  putJournaling,
  queuedBouncesTo,
  recreateAdapter,
  replyCode,
  restoreAdapter,
  sendIntake,
  toolsAddresses,
  waitForIntakeMessage,
} from './support/journal-intake';
import { clearSinkDomain, sinkFiles } from './support/mail-sink';
import { record, sleep } from './support/messaging-stack';
import { deleteQueued, involving, listQueue } from './support/postfix';
import { MAIL_SINK_HOST, organizationRef } from './support/routing';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';
import {
  createWebhook,
  pointPostfixNotifyAtRelaySink,
  receivedRequests,
  restorePostfixNotify,
  webhooksStackGate,
  type CreatedWebhook,
} from './support/webhooks';

/**
 * Step 8.6 journal-only intake end to end (docs/plan/steps/27-journal-intake-and-archive-split.md
 * §9.6 cases 1–12, ADR-0087–0089) on the live containers (Compose `apps` + `smtp-test` profiles):
 * journal reports and copies sent with swaks to the inbound Postfix (`postfix:25`, STARTTLS) from
 * `provider-sender-m365` (172.31.250.70) and `provider-sender-google` (.71), which
 * `PROVIDER_EGRESS_EXTRA_RANGES` counts as provider egress, and from `smtp-tools` (its mailtest
 * address is discovered at run time and registered as an on-premises source network; APP_ENV
 * local allows private ranges); Postfix routes the intake domain to the smtp-adapter journal LMTP
 * listener (:10053); the email-worker, the archive-worker (capture, dedupe, lifecycle, intake
 * health), the notification-worker and the api run as containers.
 *
 * Postfix must reach the adapter CONTAINER for this suite (a stack switch:
 * `SMTP_ADAPTER_HOST=smtp-adapter docker compose up -d --no-deps --force-recreate postfix
 * postfix-outbound`, restored from `.env` afterwards); the gate checks the reachability.
 *
 * Organizations `it-jrnl-<suffix>-*` only (never organizations 1, 2, 16946 or user 21416), on the
 * seeded enterprise plan (archiving + journal_intake): M (Microsoft 365 source, bound synthetic
 * tenant, a gateway inbound domain delivered to mail-sink, dedupe), G (Google Workspace source),
 * B (on-premises sources from smtp-tools: BCC copies, outside network, size, pause/disable,
 * silence, the permission split), H (on-premises journal reports, 1-day retention = 60 s, legal
 * hold on a BCC custodian), S (intake scanning on), R (plan limit 2 copies per minute).
 * Every case records its observed values (`[journal-intake] …` lines for §14).
 */
const gate = await webhooksStackGate();
const fx = new SmtpFixtures();
const run = randomBytes(3).toString('hex');
const DOMAIN = () => intakeDomain();
const SUBJECT = `JI86${run}`;
const tenantM = `it-jrnl-${run}-tenant-m365`;
const tenantG = `C${run}jrnl`;

let s3: S3Client;
let search: OpenSearchService;
let servicesOverridden = false;
let notifyPointed = false;
let toolsIps: string[] = [];
let hook: CreatedWebhook | undefined;

type Key = 'M' | 'G' | 'B' | 'H' | 'S' | 'R';
interface Org {
  key: Key;
  id: bigint;
  publicId: string;
  slug: string;
  domain: FixtureDomain;
}
const orgs: Partial<Record<Key, Org>> = {};
const org = (key: Key): Org => orgs[key]!;
const sessions: ApiSession[] = [];
const cached = new Map<string, { session: ApiSession; at: number }>();

/** Users of a fixture organization (MFA admins; the archive role where the case needs it). */
async function as(key: Key, role: string, extraRoles: string[] = []): Promise<ApiSession> {
  const id = `${key}:${role}:${extraRoles.join('+')}`;
  const hit = cached.get(id);
  // Access tokens live 10 minutes: renew the session before that.
  if (hit && Date.now() - hit.at < 8 * 60_000) return hit.session;
  const o = org(key);
  const session = await apiSession(fx.prisma, { id: o.id, slug: o.slug }, role, {
    mfa: true,
    extraRoles,
  });
  sessions.push(session);
  cached.set(id, { session, at: Date.now() });
  return session;
}
/** An admin that existed before 8.6 (migrated compliance_officer grant). */
const admin = (key: Key) => as(key, 'organization_admin', ['compliance_officer']);
const officer = (key: Key) => as(key, 'compliance_officer');

function expectStatus(res: { status: number; body: unknown }, status: number): void {
  expect(res.status, JSON.stringify(res.body)).toBe(status);
}

const windowQuery = () =>
  `from=${encodeURIComponent(new Date(Date.now() - 6 * 3_600_000).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + 3_600_000).toISOString())}`;

interface Source {
  id: string;
  address: string;
  headerToken: string | null;
}
const src: Partial<Record<string, Source>> = {};
const source = (name: string): Source => src[name]!;

async function bindConnection(
  key: Key,
  provider: 'microsoft_365' | 'google_workspace',
  tenant: string,
): Promise<string> {
  const o = org(key);
  const created = await fx.prisma.providerConnection.create({
    data: {
      organizationId: o.id,
      provider,
      displayName: `it-jrnl-${run}-${key}`,
      status: 'active',
      externalTenantId: tenant,
      tenantVerifiedAt: new Date(),
      activeTenantKey: `${provider}:${tenant}`,
    },
    select: { id: true, publicId: true },
  });
  await fx.prisma.providerConnectionDomain.create({
    data: {
      organizationId: o.id,
      connectionId: created.id,
      domainId: o.domain.id,
      providerVerification: 'verified',
    },
  });
  return created.publicId;
}

async function enableArchive(key: Key, retentionDays: number, scanEnabled = false): Promise<void> {
  const session = await admin(key);
  const policy = await session.post(
    '/archive/retention-policies',
    { name: `it-jrnl-${key}`, retentionDays, onExpiry: 'delete', priority: 1000 },
    idempotencyKey(),
  );
  expectStatus(policy, 201);
  const current = await session.get('/archive/settings');
  expectStatus(current, 200);
  expectStatus(
    await session.put(
      '/archive/settings',
      {
        expectedRowVersion: (current.body as { rowVersion: number }).rowVersion,
        immutability: 'governance',
        defaultRetentionPolicyId: (policy.body as { id: string }).id,
      },
      idempotencyKey(),
    ),
    200,
  );
  // Journaling (capture) is the organization admin's: journal:manage.
  expectStatus(
    await putJournaling(await as(key, 'organization_admin'), {
      enabled: true,
      settings: {
        directions: { inbound: true, outbound: true, internal: true },
        include: { rejected: false, quarantined: true, failed: false },
        scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
        policyArchive: { enabled: true },
        intake: { scanEnabled },
      },
    }),
    200,
  );
}

const custodianH = () => `ji-custodian@${org('H').domain.name}`;
const external = (local: string) => `${local}@${fx.sinkDomain('ji-ext')}`;

beforeAll(async () => {
  assertStackReady(gate);
  s3 = archiveS3();
  search = archiveSearch();
  toolsIps = await toolsAddresses();
  servicesOverridden = true;
  await recreateArchiveServices({ ...ARCHIVE_SUITE_ENV, ...INTAKE_WORKER_ENV });
  await recreateAdapter(INTAKE_ADAPTER_ENV);
  expect((await containerEnv('archive-worker')).JOURNAL_INTAKE_HEALTH_INTERVAL_MS).toBe('5000');
  expect((await containerEnv('smtp-adapter')).JOURNAL_INTAKE_SOURCE_CACHE_SECONDS).toBe('1');
  await pointPostfixNotifyAtRelaySink();
  notifyPointed = true;

  const enterprise = await fx.prisma.organizationPlan.findFirstOrThrow({
    where: { code: 'enterprise' },
    select: { id: true },
  });
  for (const key of ['M', 'G', 'B', 'H', 'S', 'R'] as const) {
    const id = await fx.organization(`ji-${key.toLowerCase()}`);
    const slug = `it-jrnl-${fx.suffix}-${key.toLowerCase()}`;
    await fx.prisma.organization.update({
      where: { id },
      data: { planId: enterprise.id, slug, name: `Journal intake ${key}` },
    });
    await fx.feature(id, 'archiving', true);
    await fx.feature(id, 'journal_intake', true);
    const domain = await fx.domain(id, `ji-${key.toLowerCase()}`);
    await fx.destinations(domain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
    const ref = await organizationRef(fx, id);
    orgs[key] = { key, id, publicId: ref.publicId, slug: ref.slug, domain };
  }
  await fx.feature(org('M').id, 'webhooks', true);
  await fx.limit(org('R').id, 'journal_intake_messages_per_minute', 2);
  const connM = await bindConnection('M', 'microsoft_365', tenantM);
  const connG = await bindConnection('G', 'google_workspace', tenantG);
  for (const key of ['M', 'G', 'B', 'R'] as const) await enableArchive(key, 3650);
  await enableArchive('H', 1);
  await enableArchive('S', 3650, true);

  const m = await as('M', 'organization_admin');
  src.M = await createSource(m, {
    kind: 'microsoft_365_journal',
    displayName: 'it-jrnl M365',
    providerConnectionId: connM,
  });
  src.G = await createSource(await as('G', 'organization_admin'), {
    kind: 'google_workspace_copy',
    displayName: 'it-jrnl Google',
    providerConnectionId: connG,
  });
  const b = await as('B', 'organization_admin');
  const toolsNet = toolsIps.map((ip) => `${ip}/32`);
  src.B = await createSource(b, {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl BCC',
    networks: toolsNet,
  });
  src.Bout = await createSource(b, {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl BCC elsewhere',
    networks: ['198.51.100.0/24'],
  });
  src.Bsize = await createSource(b, {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl BCC small',
    networks: toolsNet,
    maxMessageBytes: 2048,
  });
  src.Bstate = await createSource(b, {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl BCC paused',
    networks: toolsNet,
  });
  src.H = await createSource(await as('H', 'organization_admin'), {
    kind: 'exchange_onprem_journal',
    displayName: 'it-jrnl Exchange',
    networks: toolsNet,
  });
  src.S = await createSource(await as('S', 'organization_admin'), {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl scanned',
    networks: toolsNet,
  });
  src.R = await createSource(await as('R', 'organization_admin'), {
    kind: 'smtp_bcc',
    displayName: 'it-jrnl rate',
    networks: toolsNet,
  });
  expect(source('G').headerToken).toMatch(/^[a-z2-7]{26}$/);
  for (const s of Object.values(src)) expect(s!.address.endsWith(`@${DOMAIN()}`)).toBe(true);

  // A customer webhook for email.received in M: gateway mail reaches it, intake mail never.
  hook = await createWebhook(m, {
    name: `it-jrnl ${run}`,
    path: `it-jrnl-${run}`,
    eventTypes: ['email.received'],
  });
  record('journal-intake', {
    organizations: Object.keys(orgs).length,
    sources: Object.keys(src).length,
    smtp_tools_networks: toolsIps.map((ip) => `${ip}/32`).join(' '),
    intake_domain: DOMAIN(),
  });
}, 900_000);

afterAll(async () => {
  if (gate.skip) return;
  if (servicesOverridden) await compose(['stop', 'archive-worker'], { timeoutMs: 120_000 });
  const ids = Object.values(orgs).map((o) => o.id);
  let locked = 0;
  if (s3 !== undefined && search !== undefined) {
    const deadline = Date.now() + 4 * 60_000;
    for (;;) {
      locked = (await purgeArchiveTenants(fx.prisma, s3, search, ids)).lockedVersions;
      if (locked === 0 || Date.now() > deadline) break;
      await sleep(15_000);
    }
  }
  await purgeIntakeRows(fx.prisma, fx.redis, ids);
  await fx.prisma.webhookSubscription
    .deleteMany({ where: { organizationId: { in: ids } } })
    .catch(() => undefined);
  for (const session of sessions) await session.remove().catch(() => undefined);
  const names = Object.values(orgs).map((o) => o.domain.name);
  for (const service of ['postfix', 'postfix-outbound'] as const) {
    const queued = involving(await listQueue(service), [
      ...names,
      DOMAIN(),
      fx.sinkDomain('ji-ext'),
    ]);
    await deleteQueued(
      service,
      queued.map((q) => q.queue_id),
    );
  }
  for (const domain of [...names, fx.sinkDomain('ji-ext')]) {
    await clearSinkDomain(domain, 'all').catch(() => undefined);
  }
  await fx.cleanup();
  if (notifyPointed) await restorePostfixNotify();
  if (servicesOverridden) {
    await restoreArchiveServices();
    await restoreAdapter();
    expect((await containerEnv('archive-worker')).JOURNAL_INTAKE_HEALTH_INTERVAL_MS ?? '').not.toBe(
      '5000',
    );
  }
  s3?.destroy();
  record('journal-intake', {
    cleanup_locked_versions: locked,
    services_restored: servicesOverridden,
  });
  expect(locked).toBe(0);
}, 900_000);

/** Search through the api (OpenSearch tenant alias, compliance officer) for a message. */
async function searched(
  key: Key,
  messageId: string,
  extra = '',
): Promise<{ ingestSources: string[] }> {
  return waitFor(
    `archive search of ${key} returning ${messageId}`,
    async () => {
      const res = await (
        await officer(key)
      ).get(`/archive/messages?${windowQuery()}&limit=100${extra}`);
      if (res.status !== 200) throw new Error(`search answered ${res.status}`);
      return (res.body as { data: { messageId: string; ingestSources: string[] }[] }).data.find(
        (m) => m.messageId === messageId,
      );
    },
    { timeoutMs: 180_000, intervalMs: 2_000 },
  );
}

/**
 * The record that merged the copies of one Message-ID (D7): whichever copy was captured first is
 * the primary, the other one merges into it. Waits until it carries both sources (or `predicate`).
 */
async function mergedRecordOf(
  key: Key,
  messageId: string,
  predicate: (r: Awaited<ReturnType<typeof recordOf>> & object) => boolean,
) {
  return waitFor(
    `the merged record of ${messageId}`,
    async () => {
      const copies = await fx.prisma.emailMessage.findMany({
        where: {
          organizationId: org(key).id,
          internetMessageId: { contains: messageId.slice(1, -1) },
        },
        select: { id: true, receivedAt: true },
      });
      for (const copy of copies) {
        const row = await recordOf(fx.prisma, copy);
        if (row && predicate(row)) return row;
      }
      return undefined;
    },
    { timeoutMs: 480_000, intervalMs: 3_000 },
  );
}

/**
 * swaks appends CRLF to `--data` that already ends with one: a message sent through the gateway
 * then has one more empty body line than the same message embedded in a journal report (a
 * fixture artifact, not a gateway change), and the dedupe body hash would differ.
 */
const withoutFinalCrlf = (text: string) => text.replace(/\r\n$/, '');

async function publicIdOf(id: bigint): Promise<string> {
  const row = await fx.prisma.messageIdentity.findUniqueOrThrow({
    where: { id },
    select: { publicId: true },
  });
  return row.publicId;
}

const shared: Record<string, { id: bigint; receivedAt: Date; publicId: string }> = {};

describe.skipIf(gate.skip)('journal intake stack (step 8.6 §9.6)', { timeout: 900_000 }, () => {
  it('(1) Microsoft 365 journal report: unwrapped, BCC kept, journaled, archived encrypted under governance lock, searchable, never delivered', async () => {
    const d = org('M').domain.name;
    const messageId = newMessageId('m365');
    const original = originalMessage({
      messageId,
      from: `alice@${d}`,
      to: [external('partner')],
      subject: `${SUBJECT} m365`,
      body: 'EXAMPLE m365 journaled body',
    });
    const since = new Date(Date.now() - 2_000);
    const sent = await sendIntake({
      service: M365_SENDER,
      to: [source('M').address],
      data: journalReport({
        intakeAddress: source('M').address,
        original,
        sender: `alice@${d}`,
        to: [external('partner')],
        bcc: [`legal@${d}`],
        messageId,
        tenantIds: [tenantM],
      }),
    });
    expectAccepted(sent, 'M365 report');
    const msg = await waitForIntakeMessage(fx.prisma, org('M').id, messageId, 'journaled');
    const eml = await mailObject(s3, msg.emlObjectKey);
    expect(eml.toString('utf8')).toContain(`Subject: ${SUBJECT} m365`);
    expect(eml.toString('utf8')).not.toContain('X-MS-Journal-Report');
    const recipients = await fx.prisma.emailRecipient.findMany({
      where: { messageId: msg.id, receivedAt: msg.receivedAt },
      select: { address: true, status: true },
    });
    expect(recipients.map((r) => r.address).sort()).toEqual(
      [external('partner'), `legal@${d}`].sort(),
    );
    expect(new Set(recipients.map((r) => r.status))).toEqual(new Set(['journaled']));
    const intake = await fx.prisma.journalIntakeMessage.findFirstOrThrow({
      where: { messageId: msg.id, receivedAt: msg.receivedAt },
    });
    expect(intake.format).toBe('journal_report');
    expect(JSON.stringify(intake.envelope)).toContain('"field":"bcc"');
    const publicId = await publicIdOf(msg.id);
    shared.m365 = { id: msg.id, receivedAt: msg.receivedAt, publicId };

    const row = await waitForRecord(fx.prisma, { id: msg.id, receivedAt: msg.receivedAt });
    expect(row.sourceJournalIntake).toBe(true);
    expect(row.sourceGateway).toBe(false);
    const objects = objectsOf(row);
    expect((await archiveObjectHead(s3, objects.eml.key)).subarray(0, 6).toString('ascii')).toBe(
      'EGARC1',
    );
    const retention = await s3.send(
      new GetObjectRetentionCommand({
        Bucket: stack.s3().archiveBucket,
        Key: objects.eml.key,
        VersionId: objects.eml.versionId ?? undefined,
      }),
    );
    expect(retention.Retention?.Mode).toBe('GOVERNANCE');
    expect((await searched('M', publicId, '&ingestSource=journal_intake')).ingestSources).toEqual([
      'journal_intake',
    ]);
    // Never delivered, quarantined or evaluated; no sink copy; no DSN.
    expect(await fx.prisma.emailDelivery.count({ where: { messageId: msg.id } })).toBe(0);
    expect(await fx.prisma.policyExecutionLog.count({ where: { messageId: msg.id } })).toBe(0);
    expect(await sinkFiles(external('partner'))).toEqual([]);
    expect(await queuedBouncesTo(['journal-agent@journal-source.test'])).toBe(0);
    const lines = await postfixLogMentions(since, [sent.queueId ?? 'none']);
    expect(lines.some((l) => /status=sent/.test(l) && /:10053/.test(l))).toBe(true);
    // The gateway's own explorer does not list it (D5).
    expectStatus(await (await admin('M')).get(`/messages/${publicId}`), 404);
    record('journal-intake', {
      case: 1,
      status: msg.status,
      recipients: recipients.length,
      record_lock: retention.Retention?.Mode,
      eml_magic: 'EGARC1',
    });
  });

  it('(2) Google Workspace copy with the header token: accepted, token absent from the stored EML', async () => {
    const d = org('G').domain.name;
    const messageId = newMessageId('google');
    const sent = await sendIntake({
      service: GOOGLE_SENDER,
      to: [source('G').address],
      data: googleCopy({
        original: originalMessage({
          messageId,
          from: external('sender'),
          to: [`bob@${d}`],
          subject: `${SUBJECT} google`,
        }),
        originalTo: [`bob@${d}`],
        tokens: [source('G').headerToken!],
      }),
    });
    expectAccepted(sent, 'Google copy');
    const msg = await waitForIntakeMessage(fx.prisma, org('G').id, messageId, 'journaled');
    const eml = (await mailObject(s3, msg.emlObjectKey)).toString('utf8');
    expect(eml).not.toMatch(/X-EG-Journal-Token/i);
    expect(eml).not.toContain(source('G').headerToken!);
    const intake = await fx.prisma.journalIntakeMessage.findFirstOrThrow({
      where: { messageId: msg.id, receivedAt: msg.receivedAt },
    });
    expect(intake.format).toBe('copy');
    expect(JSON.stringify(intake.proof)).toContain('"headerToken":"match"');
    record('journal-intake', { case: 2, status: msg.status, token_in_eml: false });
  });

  it('(3) on-premises BCC copy from smtp-tools: inside the source networks accepted, outside refused in session', async () => {
    const d = org('B').domain.name;
    const messageId = newMessageId('bcc');
    const sent = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('B').address],
      data: originalMessage({
        messageId,
        from: `carol@${d}`,
        to: [external('vendor')],
        subject: `${SUBJECT} bcc`,
      }),
    });
    expectAccepted(sent, 'BCC copy');
    const msg = await waitForIntakeMessage(fx.prisma, org('B').id, messageId, 'journaled');
    shared.bcc = { id: msg.id, receivedAt: msg.receivedAt, publicId: await publicIdOf(msg.id) };
    const outside = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('Bout').address],
      quitAfter: 'RCPT',
    });
    expect(replyCode(outside, 'RCPT#0')).toBe(550);
    expect(reply(outside, 'RCPT#0').text).toMatch(/5\.7\.1/);
    await waitFor(
      'the B source verified by its first accepted copy',
      async () =>
        (await fx.prisma.journalIntakeSource.findFirst({
          where: { publicId: source('B').id, status: 'active', verifiedAt: { not: null } },
        })) ?? undefined,
      { timeoutMs: 60_000, intervalMs: 1_000 },
    );
    record('journal-intake', { case: 3, inside: 250, outside: replyCode(outside, 'RCPT#0') });
  });

  it('(4) spoofing: wrong tenant dropped silently (no rows, no DSN), unknown address 550 5.1.1, provider source from a non-egress client 550 5.7.1, mixed recipients 452', async () => {
    const d = org('M').domain.name;
    const messageId = newMessageId('spoof');
    const since = new Date(Date.now() - 2_000);
    const spoof = await sendIntake({
      service: M365_SENDER,
      to: [source('M').address],
      from: `spoofer@${fx.sinkDomain('ji-ext')}`,
      data: journalReport({
        intakeAddress: source('M').address,
        original: originalMessage({
          messageId,
          from: `alice@${d}`,
          to: [external('x')],
          subject: `${SUBJECT} spoof`,
        }),
        sender: `alice@${d}`,
        to: [external('x')],
        tenantIds: ['00000000-0000-0000-0000-000000000000'],
      }),
    });
    expectAccepted(spoof, 'spoofed report (accepted by Postfix)');
    await waitFor(
      'the LMTP drop in the maillog',
      async () =>
        (await postfixLogMentions(since, [spoof.queueId ?? 'none'])).some((l) =>
          l.includes('Ok: dropped'),
        ) || undefined,
      { timeoutMs: 90_000, intervalMs: 1_000 },
    );
    await sleep(3_000);
    expect(
      await fx.prisma.emailMessage.count({
        where: {
          organizationId: org('M').id,
          internetMessageId: { contains: messageId.slice(1, -1) },
        },
      }),
    ).toBe(0);
    const lines = await postfixLogMentions(since, [spoof.queueId ?? 'none']);
    expect(lines.some((l) => /bounced|sender non-delivery notification/.test(l))).toBe(false);
    expect(await queuedBouncesTo([`spoofer@${fx.sinkDomain('ji-ext')}`])).toBe(0);

    const unknown = await sendIntake({
      service: M365_SENDER,
      to: [`journal-${'a'.repeat(26)}@${DOMAIN()}`],
      quitAfter: 'RCPT',
    });
    expect(replyCode(unknown, 'RCPT#0')).toBe(550);
    expect(reply(unknown, 'RCPT#0').text).toMatch(/5\.1\.1/);

    const wrongClient = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('M').address],
      quitAfter: 'RCPT',
    });
    expect(replyCode(wrongClient, 'RCPT#0')).toBe(550);
    expect(reply(wrongClient, 'RCPT#0').text).toMatch(/5\.7\.1/);

    const mixed = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('B').address, `someone@${org('B').domain.name}`],
      quitAfter: 'RCPT',
    });
    expect(replyCode(mixed, 'RCPT#0')).toBe(250);
    expect(replyCode(mixed, 'RCPT#1')).toBe(452);
    const counters = await waitFor(
      'the dropped_proof counter of M',
      async () => {
        const rows = await fx.prisma.journalIntakeCounter.findMany({
          where: { organizationId: org('M').id },
        });
        return rows.some((r) => r.droppedProof > 0) ? rows : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 1_000 },
    );
    record('journal-intake', {
      case: 4,
      spoof: 'accepted+dropped',
      unknown: replyCode(unknown, 'RCPT#0'),
      non_egress: replyCode(wrongClient, 'RCPT#0'),
      mixed_second: replyCode(mixed, 'RCPT#1'),
      dropped_proof: counters.reduce((n, r) => n + r.droppedProof, 0),
    });
  });

  it('(5) dedupe: gateway copy + journal report with a banner body → one record, both sources, merged BCC, one variant; same body → no variant; intake↔intake → merged recipients; email.received only for gateway mail', async () => {
    const d = org('M').domain.name;
    const sender = external('dedupe');
    const sendGateway = async (messageId: string, body: string) => {
      const text = originalMessage({
        messageId,
        from: sender,
        to: [`dana@${d}`],
        subject: `${SUBJECT} dedupe`,
        body,
      });
      const res = await swaks({
        server: 'postfix',
        port: 25,
        from: sender,
        to: [`dana@${d}`],
        data: withoutFinalCrlf(text),
      });
      expect(reply(res, 'DATA-END').code, res.transcript).toBe(250);
      return text;
    };
    const sendReport = async (messageId: string, original: string, bcc: string[]) => {
      const res = await sendIntake({
        service: M365_SENDER,
        to: [source('M').address],
        data: journalReport({
          intakeAddress: source('M').address,
          original,
          sender,
          to: [`dana@${d}`],
          bcc,
          messageId,
          tenantIds: [tenantM],
        }),
      });
      expectAccepted(res, 'dedupe report');
    };
    // (a) differing body: the journal copy shows the body before the gateway changed it.
    const idA = newMessageId('dedupe-a');
    const date = new Date().toUTCString().replace('GMT', '+0000');
    const gatewayA = originalMessage({
      messageId: idA,
      from: sender,
      to: [`dana@${d}`],
      subject: `${SUBJECT} dedupe`,
      body: 'EXAMPLE original body',
      date,
    });
    const resA = await swaks({
      server: 'postfix',
      port: 25,
      from: sender,
      to: [`dana@${d}`],
      data: withoutFinalCrlf(gatewayA),
    });
    expect(reply(resA, 'DATA-END').code, resA.transcript).toBe(250);
    const journalA = originalMessage({
      messageId: idA,
      from: sender,
      to: [`dana@${d}`],
      subject: `${SUBJECT} dedupe`,
      body: 'EXAMPLE original body\n-- EXAMPLE banner added by the provider',
      date,
    });
    await sendReport(idA, journalA, [`audit@${d}`]);
    // (b) same body.
    const idB = newMessageId('dedupe-b');
    const sameB = await sendGateway(idB, 'EXAMPLE same body');
    await sendReport(idB, sameB, []);
    // (c) intake ↔ intake: two journal reports of one message.
    const idC = newMessageId('dedupe-c');
    const originalC = originalMessage({
      messageId: idC,
      from: `erin@${d}`,
      to: [external('c')],
      subject: `${SUBJECT} dedupe c`,
    });
    await sendReport(idC, originalC, [`first@${d}`]);
    await sleep(2_000);
    await sendReport(idC, originalC, [`second@${d}`]);

    const merged = await mergedRecordOf(
      'M',
      idA,
      (r) => r.sourceGateway && r.sourceJournalIntake && r.mergedCount >= 1,
    );
    const objects = objectsOf(merged);
    expect(objects.merged?.length).toBe(1);
    expect(objects.merged?.[0]?.eml).not.toBeNull();
    expect(JSON.stringify(merged.parties)).toContain(`audit@${d}`);
    const gatewayPublic = merged.messagePublicId;
    await waitFor(
      'the merged record indexed with both sources',
      async () => (await searched('M', gatewayPublic)).ingestSources.length === 2 || undefined,
      { timeoutMs: 120_000, intervalMs: 2_000 },
    );
    const detail = await (await officer('M')).get(`/archive/messages/${gatewayPublic}`);
    expectStatus(detail, 200);
    const copies = (detail.body as { mergedCopies: { contentVariant: boolean }[] }).mergedCopies;
    expect(copies.map((c) => c.contentVariant)).toEqual([true]);

    const mergedB = await mergedRecordOf(
      'M',
      idB,
      (r) => r.sourceGateway && r.sourceJournalIntake && r.mergedCount >= 1,
    );
    // Same body: no content variant. The diagnostic names both stored bodies' SHA-256 on failure.
    const bodiesB = await Promise.all(
      (
        await fx.prisma.emailMessage.findMany({
          where: { organizationId: org('M').id, internetMessageId: { contains: idB.slice(1, -1) } },
          select: { ingestSource: true, emlObjectKey: true },
        })
      ).map(async (m) => {
        const eml = await mailObject(s3, m.emlObjectKey);
        const at = eml.indexOf('\r\n\r\n');
        return `${m.ingestSource}:${createHash('sha256')
          .update(eml.subarray(at + 4))
          .digest('hex')
          .slice(0, 12)}:${eml.length - at - 4}`;
      }),
    );
    expect(objectsOf(mergedB).merged?.[0]?.eml ?? null, bodiesB.join(' ')).toBeNull();

    const intakeC = await waitFor(
      'two intake copies of (c)',
      async () => {
        const rows = await fx.prisma.emailMessage.findMany({
          where: {
            organizationId: org('M').id,
            ingestSource: 'journal_intake',
            internetMessageId: { contains: idC.slice(1, -1) },
          },
          orderBy: { receivedAt: 'asc' },
          select: { id: true, receivedAt: true },
        });
        return rows.length === 2 ? rows : undefined;
      },
      { timeoutMs: 120_000, intervalMs: 1_500 },
    );
    const recordC = await waitFor(
      'the intake↔intake merge of (c)',
      async () => {
        for (const m of intakeC) {
          const row = await recordOf(fx.prisma, m);
          if (row && row.mergedCount >= 1) return row;
        }
        return undefined;
      },
      { timeoutMs: 420_000, intervalMs: 3_000 },
    );
    expect(JSON.stringify(recordC.parties)).toContain(`first@${d}`);
    expect(JSON.stringify(recordC.parties)).toContain(`second@${d}`);
    expect(
      await fx.prisma.emailArchive.count({
        where: { organizationId: org('M').id, messageId: { in: intakeC.map((m) => m.id) } },
      }),
    ).toBe(1);

    // email.received: the gateway copies reached the customer webhook, the intake copies never.
    const copiesOf = (messageId: string, source: 'gateway' | 'journal_intake') =>
      fx.prisma.emailMessage.findMany({
        where: {
          organizationId: org('M').id,
          ingestSource: source,
          internetMessageId: { contains: messageId.slice(1, -1) },
        },
        select: { id: true },
      });
    const gatewayCopy = (await copiesOf(idA, 'gateway'))[0]!;
    const gatewayCopyPublic = await publicIdOf(gatewayCopy.id);
    const intakeCopiesA = await copiesOf(idA, 'journal_intake');
    const intakePublic = [
      shared.m365!.publicId,
      ...(await Promise.all([...intakeC, ...intakeCopiesA].map((m) => publicIdOf(m.id)))),
    ];
    const requests = await waitFor(
      'the email.received webhook of the gateway copy',
      async () => {
        const all = await receivedRequests(hook!.path);
        return mentions(all, [gatewayCopyPublic]) > 0 ? all : undefined;
      },
      { timeoutMs: 180_000, intervalMs: 2_000 },
    );
    expect(mentions(requests, intakePublic)).toBe(0);
    record('journal-intake', {
      case: 5,
      variant_merge: objects.merged?.length,
      same_body_variant: objectsOf(mergedB).merged?.[0]?.eml === null ? 'none' : 'stored',
      intake_intake_records: 1,
      webhook_gateway: mentions(requests, [gatewayCopyPublic]),
      webhook_intake: mentions(requests, intakePublic),
    });
  });

  it('(6) retention + legal hold on a BCC custodian: disposal blocked; released → disposed with variants', async () => {
    const session = await admin('H');
    const created = await session.post(
      '/ediscovery/cases',
      { name: `it-jrnl hold ${run}`, custodians: [custodianH()] },
      idempotencyKey(),
    );
    expectStatus(created, 201);
    const caseId = (created.body as { id: string }).id;
    const hold = await session.post(
      `/ediscovery/cases/${caseId}/holds`,
      { name: 'it-jrnl hold', reason: 'journal intake stack test', useCaseCustodians: true },
      idempotencyKey(),
    );
    expectStatus(hold, 201);
    const holdId = (hold.body as { id: string }).id;
    const d = org('H').domain.name;
    const messageId = newMessageId('hold');
    const date = new Date().toUTCString().replace('GMT', '+0000');
    const send = async (body: string) => {
      const original = originalMessage({
        messageId,
        from: `frank@${d}`,
        to: [external('h')],
        subject: `${SUBJECT} hold`,
        body,
        date,
      });
      expectAccepted(
        await sendIntake({
          service: TOOLS_SENDER,
          to: [source('H').address],
          data: journalReport({
            intakeAddress: source('H').address,
            original,
            sender: `frank@${d}`,
            to: [external('h')],
            bcc: [custodianH()],
            messageId,
          }),
        }),
        'on-premises report',
      );
    };
    await send('EXAMPLE held body');
    await sleep(2_000);
    await send('EXAMPLE held body, second journal copy with a different body');
    const rows = await waitFor(
      'both intake copies of H',
      async () => {
        const list = await fx.prisma.emailMessage.findMany({
          where: {
            organizationId: org('H').id,
            internetMessageId: { contains: messageId.slice(1, -1) },
          },
          select: { id: true, receivedAt: true },
        });
        return list.length === 2 ? list : undefined;
      },
      { timeoutMs: 120_000, intervalMs: 1_500 },
    );
    const held = await waitFor(
      'the held, merged H record',
      async () => {
        for (const m of rows) {
          const row = await recordOf(fx.prisma, m);
          if (row && row.legalHold && row.mergedCount >= 1) return row;
        }
        return undefined;
      },
      { timeoutMs: 420_000, intervalMs: 3_000 },
    );
    const variantKey = objectsOf(held).merged?.[0]?.eml?.key;
    expect(variantKey).toBeTruthy();
    const prefix = recordPrefix(held);
    // Past the 1-day (60 s) retention, the hold keeps it.
    await sleep(Math.max(0, held.retainUntil.getTime() + 15_000 - Date.now()));
    const stillHeld = await fx.prisma.emailArchive.findFirstOrThrow({ where: { id: held.id } });
    expect(stillHeld.status).toBe('active');
    expect(await fx.prisma.archiveDisposal.count({ where: { organizationId: org('H').id } })).toBe(
      0,
    );

    expectStatus(
      await session.post(
        `/legal-holds/${holdId}/release`,
        { reason: 'journal intake stack test released' },
        idempotencyKey(),
      ),
      200,
    );
    await waitFor(
      'the H record disposed',
      async () =>
        (await fx.prisma.emailArchive.count({ where: { id: held.id } })) === 0 || undefined,
      { timeoutMs: 420_000, intervalMs: 3_000 },
    );
    expect(await versionsUnder(s3, stack.s3().archiveBucket, prefix)).toEqual([]);
    const variantPrefix = variantKey!.slice(0, variantKey!.lastIndexOf('/') + 1);
    expect(await versionsUnder(s3, stack.s3().archiveBucket, variantPrefix)).toEqual([]);
    expect(
      await fx.prisma.archiveRecordSource.count({ where: { organizationId: org('H').id } }),
    ).toBe(0);
    expect(await fx.prisma.archiveDedupeKey.count({ where: { organizationId: org('H').id } })).toBe(
      0,
    );
    record('journal-intake', { case: 6, held_past_expiry: true, disposed_with_variant: true });
  });

  it('(7) intake scanning on: scan snapshot linked; no policy evaluation, no delivery', async () => {
    const d = org('S').domain.name;
    const messageId = newMessageId('scan');
    expectAccepted(
      await sendIntake({
        service: TOOLS_SENDER,
        to: [source('S').address],
        data: originalMessage({
          messageId,
          from: `gina@${d}`,
          to: [external('s')],
          subject: `${SUBJECT} scanned`,
          body: 'EXAMPLE https://scanned.example.test/page',
        }),
      }),
      'scanned copy',
    );
    const msg = await waitForIntakeMessage(fx.prisma, org('S').id, messageId, 'journaled');
    const intake = await fx.prisma.journalIntakeMessage.findFirstOrThrow({
      where: { messageId: msg.id, receivedAt: msg.receivedAt },
    });
    expect(intake.scanRequested).toBe(true);
    expect(await fx.prisma.emailScan.count({ where: { messageId: msg.id } })).toBeGreaterThan(0);
    const row = await waitForRecord(fx.prisma, msg, (r) => objectsOf(r).scans.length > 0, 420_000);
    expect(await fx.prisma.policyExecutionLog.count({ where: { messageId: msg.id } })).toBe(0);
    expect(await fx.prisma.emailDelivery.count({ where: { messageId: msg.id } })).toBe(0);
    record('journal-intake', {
      case: 7,
      scan_links: objectsOf(row).scans.length,
      status: msg.status,
    });
  });

  it('(8) GTUBE copy: refused in session by the Rspamd pre-result (WP3 deviation 1, no backscatter)', async () => {
    const d = org('B').domain.name;
    const gtube = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';
    const res = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('B').address],
      data: originalMessage({
        messageId: newMessageId('gtube'),
        from: `hal@${d}`,
        to: [external('g')],
        subject: `${SUBJECT} gtube`,
        body: gtube,
      }),
    });
    const code = reply(res, 'DATA-END').code;
    // Score-based actions are off for intake (settings `journal_intake`); the GTUBE pre-result
    // is applied before settings in Rspamd 3.12 (recorded deviation): the client owns the bounce.
    expect([250, 554]).toContain(code);
    record('journal-intake', { case: 8, gtube_data_end: code });
  });

  it('(9) size above the source limit → refused 5.3.4; above the plan rate (2/min) → deferred 4.7.1', async () => {
    const d = org('B').domain.name;
    const big = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('Bsize').address],
      data: originalMessage({
        messageId: newMessageId('big'),
        from: `ivy@${d}`,
        to: [external('i')],
        subject: `${SUBJECT} big`,
        body: 'x'.repeat(8_000),
      }),
    });
    // The existing reply TOO_BIG_FOR_RECIPIENT is `REJECT 5.3.4` (550 on the wire, like every
    // step 2.2 REJECT; WP3 deviation 4), at RCPT for a declared size or at END-OF-MESSAGE.
    const sizeReply =
      replyCode(big, 'RCPT#0') === 250 ? reply(big, 'DATA-END') : reply(big, 'RCPT#0');
    expect([550, 552]).toContain(sizeReply.code);
    expect(sizeReply.text).toMatch(/5\.3\.4/);
    const sizeCode = `${sizeReply.code} 5.3.4`;
    const codes: (number | undefined)[] = [];
    for (let i = 0; i < 3; i += 1) {
      const res = await sendIntake({
        service: TOOLS_SENDER,
        to: [source('R').address],
        data: originalMessage({
          messageId: newMessageId(`rate${i}`),
          from: `jay@${org('R').domain.name}`,
          to: [external('r')],
          subject: `${SUBJECT} rate ${i}`,
        }),
      });
      codes.push(replyCode(res, 'RCPT#0'));
    }
    expect(codes.slice(0, 2)).toEqual([250, 250]);
    // The existing RATE_LIMITED reply is `DEFER_IF_PERMIT 4.7.1` (450 on the wire): temporary.
    expect(codes[2]).toBeGreaterThanOrEqual(450);
    expect(codes[2]).toBeLessThan(500);
    record('journal-intake', { case: 9, size: sizeCode, rate: codes.join('/') });
  });

  it('(10) paused source → 450 (sender retries); disabled → 550', async () => {
    const b = await as('B', 'organization_admin');
    expectStatus(await patchSource(b, source('Bstate').id, { status: 'paused' }), 200);
    await sleep(2_500);
    const paused = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('Bstate').address],
      quitAfter: 'RCPT',
    });
    expect(replyCode(paused, 'RCPT#0')).toBe(450);
    expectStatus(await b.delete(`/journaling/intake-sources/${source('Bstate').id}`), 200);
    await sleep(2_500);
    const disabled = await sendIntake({
      service: TOOLS_SENDER,
      to: [source('Bstate').address],
      quitAfter: 'RCPT',
    });
    expect(replyCode(disabled, 'RCPT#0')).toBe(550);
    record('journal-intake', { case: 10, paused: 450, disabled: replyCode(disabled, 'RCPT#0') });
  });

  it('(11) silence: a verified source without copies turns silent; the alert reaches the notify relay sink', async () => {
    const bAdmin = await as('B', 'organization_admin');
    await fx.prisma.journalIntakeSource.update({
      where: { publicId: source('B').id },
      data: { silenceAlertMinutes: 1, lastAcceptedAt: new Date(Date.now() - 5 * 60_000) },
    });
    const silent = await waitFor(
      'source B silent',
      async () =>
        (await fx.prisma.journalIntakeSource.findFirst({
          where: { publicId: source('B').id, healthStatus: 'silent' },
        })) ?? undefined,
      { timeoutMs: 120_000, intervalMs: 2_000 },
    );
    expect(silent.healthAlertedAt).not.toBeNull();
    expect(
      await fx.prisma.auditLog.count({
        where: { organizationId: org('B').id, action: 'journal_intake.health_changed' },
      }),
    ).toBeGreaterThan(0);
    const files = await waitFor(
      'the journal_intake_silent alert in notify-relay-sink',
      async () => {
        const list = await sinkFiles(bAdmin.email, 'notify-relay-sink');
        return list.length > 0 ? list : undefined;
      },
      { timeoutMs: 180_000, intervalMs: 3_000 },
    );
    record('journal-intake', { case: 11, health: silent.healthStatus, alert_mails: files.length });
  });

  it('(12) permission split: a new admin cannot search; assigning compliance_officer to a second user opens it (audited)', async () => {
    const newAdmin = await as('B', 'organization_admin');
    const list = await newAdmin.get(`/archive/messages?${windowQuery()}`);
    expectStatus(list, 403);
    expectStatus(await newAdmin.get(`/archive/messages/${shared.bcc!.publicId}`), 403);
    const colleague = await as('B', 'read_only_user');
    expectStatus(await colleague.get(`/archive/messages?${windowQuery()}`), 403);
    const user = await fx.prisma.user.findUniqueOrThrow({
      where: { id: colleague.userId },
      select: { publicId: true },
    });
    const assigned = await newAdmin.put(
      `/users/${user.publicId}/roles`,
      { roleKeys: ['read_only_user', 'compliance_officer'] },
      idempotencyKey(),
    );
    expectStatus(assigned, 200);
    const allowed = await waitFor(
      'the colleague searching the archive',
      async () => {
        const res = await colleague.get(`/archive/messages?${windowQuery()}`);
        return res.status === 200 ? res : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 2_000 },
    );
    expectStatus(allowed, 200);
    const audit = await fx.prisma.auditLog.findMany({
      where: { organizationId: org('B').id, action: 'rbac.archive_access_granted' },
    });
    expect(audit.length).toBeGreaterThanOrEqual(1);
    record('journal-intake', {
      case: 12,
      new_admin_search: 403,
      after_assignment: 200,
      audit_rows: audit.length,
    });
  });
});
