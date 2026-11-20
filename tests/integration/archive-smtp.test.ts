import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import {
  DeleteObjectCommand,
  GetObjectLegalHoldCommand,
  GetObjectRetentionCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { eicar } from '@email-gateway/attachment-corpus';
import { verifySignedExportManifest, parseExportSigningPublicKey } from '@email-gateway/archive';
import type { OpenSearchService } from '@email-gateway/common';
import { EventTypes, messageArchiveRequestedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  apiSession,
  idempotencyKey,
  type ApiResponse,
  type ApiSession,
} from './support/api-client';
import {
  aliasCount,
  ARCHIVE_LEDGER,
  ARCHIVE_SUITE_DAY_SECONDS,
  archiveS3,
  archiveSearch,
  containerEnv,
  copyToReplica,
  decryptRecordObject,
  intentOf,
  objectsOf,
  purgeArchiveTenants,
  rawIndexCount,
  readZip,
  recordOf,
  recordPrefix,
  recreateArchiveServices,
  replicaBucket,
  restoreArchiveServices,
  versionsUnder,
  waitForIntent,
  waitForRecord,
  type ArchiveRecordRow,
} from './support/archive';
import { attachmentMessage } from './support/attachment-stack';
import { copiesOfEvent, ManagementApi } from './support/broker';
import { compose, composeOk, waitFor } from './support/compose';
import { waitForMessage } from './support/deliveries';
import { stack } from './support/env';
import { waitForLifecycle, type MessageKey } from './support/lifecycle';
import { clearSinkDomain } from './support/mail-sink';
import { envelopeOfRow, LiveBroker, record, sleep } from './support/messaging-stack';
import { createAndPublishPolicy, messageOutboxOf, waitForEvaluation } from './support/policy';
import {
  deleteQueued,
  flushQueue,
  involving,
  listQueue,
  waitForLog,
  waitForQueueDrained,
} from './support/postfix';
import { MAIL_SINK_HOST, organizationRef, sendingDomain } from './support/routing';
import { messagePublicId, scanRoundsOf, scanStackGate } from './support/scan-stack';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Step 8.1 journaling and compliance archiving end to end (docs/plan/steps/
 * 23-journaling-archiving.md §9.4 cases 1–17, A2–A21, ADR-0064–0069): real SMTP into the
 * Compose Postfix, the 2.x–5.x pipeline on the live containers, the archive-worker container
 * (every role: capture, index, lifecycle, ediscovery) capturing into the Object Lock archive
 * bucket of MinIO and the OpenSearch `eg-archive` index, and every human action through the
 * live api (settings, retention, holds, cases, searches, review, exports, previews, grants).
 *
 * The archive-worker and the api are recreated for the run with the overrides of
 * `ARCHIVE_SUITE_ENV` (one archive day = 60 s, the test replica bucket as replica target, faster
 * loops; LOCAL ONLY) and recreated from `.env` in afterAll (checked).
 *
 * Organizations (all on the seeded `enterprise` plan with the `archiving` feature, settings and
 * retention through the api):
 * - A: every direction journaled, no extra category; default policy 2 000 days; a 2-day policy
 *   for the domain `aShort` (cases 11, 12); a tenant policy with ARCHIVE (duplicates) and REJECT.
 * - B: inbound and outbound journaled, internal OFF; rejected, quarantined and failed included;
 *   preview and download on; REJECT rule.
 * - C: journaling OFF in every direction, policy ARCHIVE on (cases 8, 9).
 * - L: immutability `compliance`, default policy 2 days (case 13).
 *
 * Every case records its observed values (`[archive-smtp] …` lines for §14).
 */
const gate = await scanStackGate();
const fx = new SmtpFixtures();
const run = randomBytes(3).toString('hex');
const SUBJECT = `AR8S${run}`;
const DAY_MS = ARCHIVE_SUITE_DAY_SECONDS * 1_000;

let s3: S3Client;
let search: OpenSearchService;
const mgmt = new ManagementApi();
const vhost = stack.rabbitmqVhost();
let servicesOverridden = false;
let minioStopped = false;
let workerStopped = false;

interface Org {
  key: 'A' | 'B' | 'C' | 'L';
  id: bigint;
  publicId: string;
  slug: string;
  inbound: FixtureDomain;
}
const orgs: Partial<Record<Org['key'], Org>> = {};
let outA: FixtureDomain;
let outB: FixtureDomain;
let aShort: FixtureDomain;
let saslA: { username: string; password: string };
let saslB: { username: string; password: string };
const extDomain = () => fx.sinkDomain('ar8-ext');
const senderDomain = () => fx.sinkDomain('ar8-snd');
const SENDER = () => `ext@${senderDomain()}`;

/** Local parts selecting the tenant rules and the cases. */
const LP = {
  dup: 'ar8dup',
  rejA: 'ar8rja',
  rejB: 'ar8rjb',
  c8a: 'ar8c8a',
  c9: 'ar8c09',
  c8b: 'ar8c8b',
} as const;

const all = (): Org[] => Object.values(orgs);
const org = (key: Org['key']): Org => orgs[key]!;

// --- Sessions (renewed before the 10-minute access token expires) ---------------------------------
const sessions: ApiSession[] = [];
const cached = new Map<string, { session: ApiSession; at: number }>();

async function as(
  key: Org['key'],
  role: string,
  mfa = false,
  extraRoles: readonly string[] = [],
): Promise<ApiSession> {
  const id = `${key}:${role}:${mfa}:${extraRoles.join('+')}`;
  const hit = cached.get(id);
  if (hit && Date.now() - hit.at < 8 * 60_000) return hit.session;
  const o = org(key);
  const session = await apiSession(fx.prisma, { id: o.id, slug: o.slug }, role, {
    mfa,
    extraRoles,
  });
  sessions.push(session);
  cached.set(id, { session, at: Date.now() });
  return session;
}
// Step 8.6 (ADR-0089): an organization admin manages journaling only; the archive settings,
// retention, holds and records of this suite need the migrated compliance_officer grant.
const admin = (key: Org['key']) => as(key, 'organization_admin', true, ['compliance_officer']);

function body<T>(res: ApiResponse): T {
  return res.body as T;
}

function expectStatus(res: ApiResponse, status: number): void {
  expect(res.status, JSON.stringify(res.body)).toBe(status);
}

const windowQuery = () => {
  const from = new Date(Date.now() - 6 * 3_600_000).toISOString();
  const to = new Date(Date.now() + 3_600_000).toISOString();
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
};

interface ArchiveItem {
  messageId: string;
  direction: string;
  category: string;
  sources: string[];
  status: string;
  subject: null;
  subjectMasked: boolean;
  recipients: string[];
  attachmentNames: string[];
  malicious: boolean;
  legalHold: boolean;
  lockMode: string;
}

/** Search through the api (OpenSearch tenant alias) until `messageId` shows up. */
async function searchedThroughApi(key: Org['key'], messageId: string): Promise<ArchiveItem> {
  return waitFor(
    `archive search of organization ${key} to return ${messageId}`,
    async () => {
      const res = await (
        await as(key, 'security_analyst')
      ).get(`/archive/messages?${windowQuery()}&limit=100`);
      if (res.status !== 200) throw new Error(`search answered ${res.status}`);
      return body<{ data: ArchiveItem[] }>(res).data.find((m) => m.messageId === messageId);
    },
    { timeoutMs: 120_000, intervalMs: 2_000 },
  );
}

// --- Messages ----------------------------------------------------------------------------------

type Msg = MessageKey & {
  publicId: string;
  emlSha256: string;
  emlObjectKey: string;
  direction: string;
};

async function keyOf(organizationId: bigint, queueId: string): Promise<Msg> {
  const row = await waitForMessage(fx.prisma, organizationId, { mtaQueueId: queueId }, 120_000);
  const message = { id: row.id, receivedAt: row.receivedAt };
  return {
    ...message,
    publicId: await messagePublicId(fx.prisma, message),
    emlSha256: row.emlSha256,
    emlObjectKey: row.emlObjectKey,
    direction: row.direction,
  };
}

/** An inbound message from the external sink sender to the gateway MX (postfix:25). */
async function inbound(
  key: Org['key'],
  rcpts: readonly string[],
  label: string,
  attachments: { filename: string; contentType: string; bytes: Buffer }[] = [],
  extra: string[] = [],
): Promise<Msg> {
  const built = attachmentMessage({
    from: `External <${SENDER()}>`,
    to: [...rcpts],
    subject: `${SUBJECT} ${label}`,
    attachments,
    body: `Archive stack body ${label}.`,
  });
  const sent = await swaks({
    server: 'postfix',
    port: 25,
    from: SENDER(),
    to: [...rcpts],
    data: built.text,
    extra,
    timeoutMs: 300_000,
  });
  // `--suppress-data` (case 17) prints "N lines sent" instead of the data, so the DATA-END reply
  // is read from the transcript directly.
  const queued = /<-\s+250 2\.0\.0 Ok: queued as ([A-Za-z0-9]+)/.exec(sent.transcript)?.[1];
  expect(queued, sent.transcript.slice(0, 4_000)).toBeDefined();
  return keyOf(org(key).id, queued!);
}

/** A submission (587, SASL) of organization A or B. */
async function submitted(
  key: 'A' | 'B',
  from: string,
  rcpts: readonly string[],
  label: string,
): Promise<Msg> {
  const built = attachmentMessage({
    from,
    to: [...rcpts],
    subject: `${SUBJECT} ${label}`,
    attachments: [],
    body: `Archive stack body ${label}.`,
  });
  const sent = await swaks({
    server: 'postfix-outbound',
    port: 587,
    tls: true,
    auth: key === 'A' ? saslA : saslB,
    from,
    to: [...rcpts],
    data: built.text,
  });
  expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
  return keyOf(org(key).id, sent.queueId!);
}

/**
 * The common journaling checks (§9.4 cases 1–3): one record and its intent, the EML copied
 * byte-for-byte (ciphertext ≠ plaintext, decrypts to the original whose SHA-256 is the ingest
 * hash), the journal and scan snapshot objects decrypt, the round linked without a new round, the
 * document searchable through the api (masked). Returns the record.
 */
async function expectJournaled(
  key: Org['key'],
  message: Msg,
  expected: { direction: string; category: string; journal: boolean; policy: boolean },
): Promise<ArchiveRecordRow> {
  const roundsBefore = (await scanRoundsOf(fx.prisma, message)).length;
  // Sources converge: a source that joins after the capture is added by the outcome refresh
  // within seconds (the intent is pulled forward, WP6 fix of the archive-worker).
  const row = await waitForRecord(
    fx.prisma,
    message,
    (r) => r.capturedByJournal === expected.journal && r.capturedByPolicy === expected.policy,
  );
  expect(row).toMatchObject({
    organizationId: org(key).id,
    messagePublicId: message.publicId,
    direction: expected.direction,
    category: expected.category,
    status: 'active',
    capturedByJournal: expected.journal,
    capturedByPolicy: expected.policy,
    sha256: message.emlSha256,
    encryptionFormat: 'archive-object/1',
  });
  expect(row.wrappedDek).not.toBeNull();
  const intent = await intentOf(fx.prisma, message);
  expect(intent).toMatchObject({ archiveId: row.id, sourceJournal: expected.journal });
  expect(['captured_open', 'closed']).toContain(intent!.status);
  // The EML: encrypted, decrypts to the original object of the mail bucket.
  const eml = await decryptRecordObject(fx.prisma, s3, row, 'eml');
  const original = await fx.object(message.emlObjectKey);
  expect(createHash('sha256').update(eml.plaintext).digest('hex')).toBe(message.emlSha256);
  expect(eml.plaintext.equals(original)).toBe(true);
  expect(eml.ciphertext.equals(eml.plaintext)).toBe(false);
  expect(eml.ciphertext.includes(Buffer.from(SUBJECT))).toBe(false);
  expect(eml.ciphertext.subarray(0, 6).toString('latin1')).toBe('EGARC1');
  // The journal report and the frozen scan round.
  const journal = JSON.parse(
    (await decryptRecordObject(fx.prisma, s3, row, 'journal')).plaintext.toString('utf8'),
  ) as { messageId: string; direction: string; message: { emlSha256: string } };
  expect(journal).toMatchObject({
    messageId: message.publicId,
    direction: expected.direction,
    message: { emlSha256: message.emlSha256 },
  });
  const objects = objectsOf(row);
  expect(objects.scans.length).toBeGreaterThanOrEqual(1);
  const snapshot = JSON.parse(
    (await decryptRecordObject(fx.prisma, s3, row, 'scan', 0)).plaintext.toString('utf8'),
  ) as { round: number; rows: { scan: unknown } };
  expect(snapshot.round).toBe(0);
  expect(snapshot.rows.scan).not.toBeNull();
  expect((row.scanRounds as { round: number }[]).map((r) => r.round)).toContain(0);
  expect((await scanRoundsOf(fx.prisma, message)).length).toBe(roundsBefore);
  // OpenSearch through the api: masked, metadata only.
  const item = await searchedThroughApi(key, message.publicId);
  expect(item).toMatchObject({
    direction: expected.direction,
    category: expected.category,
    subject: null,
    subjectMasked: true,
  });
  for (const r of item.recipients) expect(r).toMatch(/\*\*\*@/);
  return row;
}

async function sweptPast(message: MessageKey): Promise<void> {
  await waitFor(
    `the journal sweep cursor past message ${message.id}`,
    async () => {
      const cursor = await fx.prisma.streamCursor.findUnique({
        where: { name: 'archive:journal-sweep' },
      });
      return cursor?.positionId !== null && cursor !== null && cursor.positionId >= message.id;
    },
    { timeoutMs: 240_000, intervalMs: 2_000 },
  );
}

async function disposalOf(message: MessageKey) {
  return fx.prisma.archiveDisposal.findFirst({
    where: { messageId: message.id, messageReceivedAt: message.receivedAt },
  });
}

async function waitForDisposalCompleted(message: MessageKey, timeoutMs = 420_000) {
  return waitFor(
    `the disposal of message ${message.id} completed`,
    async () => {
      const row = await disposalOf(message);
      return row?.state === 'completed' ? row : undefined;
    },
    { timeoutMs, intervalMs: 2_000 },
  );
}

async function startWorker(): Promise<void> {
  await composeOk(['start', 'archive-worker'], { timeoutMs: 120_000 });
  await waitFor(
    'archive-worker ready',
    async () => {
      const res = await fetch(
        `http://${stack.host}:${stack.ports.services['archive-worker']}/health/ready`,
        { signal: AbortSignal.timeout(2_000) },
      );
      return res.ok;
    },
    { timeoutMs: 120_000, intervalMs: 1_000 },
  );
  workerStopped = false;
}

async function settings(
  key: Org['key'],
  change: Record<string, unknown>,
): Promise<{ rowVersion: number }> {
  const session = await admin(key);
  const current = await session.get('/archive/settings');
  expectStatus(current, 200);
  const res = await session.put(
    '/archive/settings',
    { expectedRowVersion: body<{ rowVersion: number }>(current).rowVersion, ...change },
    idempotencyKey(),
  );
  expectStatus(res, 200);
  return body<{ rowVersion: number }>(res);
}

async function retentionPolicy(key: Org['key'], policy: Record<string, unknown>): Promise<string> {
  const res = await (
    await admin(key)
  ).post('/archive/retention-policies', policy, idempotencyKey());
  expectStatus(res, 201);
  return body<{ id: string }>(res).id;
}

beforeAll(async () => {
  assertStackReady(gate);
  s3 = archiveS3();
  search = archiveSearch();
  servicesOverridden = true;
  await recreateArchiveServices();
  const workerEnv = await containerEnv('archive-worker');
  expect(workerEnv.ARCHIVE_TEST_DAY_SECONDS).toBe(String(ARCHIVE_SUITE_DAY_SECONDS));
  expect((await containerEnv('api')).ARCHIVE_TEST_DAY_SECONDS).toBe(
    String(ARCHIVE_SUITE_DAY_SECONDS),
  );

  const enterprise = await fx.prisma.organizationPlan.findFirstOrThrow({
    where: { code: 'enterprise' },
    select: { id: true },
  });
  for (const key of ['A', 'B', 'C', 'L'] as const) {
    const id = await fx.organization(`ar8-${key.toLowerCase()}`);
    await fx.prisma.organization.update({ where: { id }, data: { planId: enterprise.id } });
    await fx.feature(id, 'archiving', true);
    const inboundDomain = await fx.domain(id, `ar8-${key.toLowerCase()}-in`);
    await fx.destinations(inboundDomain, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
    const ref = await organizationRef(fx, id);
    orgs[key] = { key, id, publicId: ref.publicId, slug: ref.slug, inbound: inboundDomain };
  }
  aShort = await fx.domain(org('A').id, 'ar8-a-short');
  await fx.destinations(aShort, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  outA = await sendingDomain(fx, org('A').id, 'ar8-a-out');
  outB = await sendingDomain(fx, org('B').id, 'ar8-b-out');
  for (const d of [outA, outB]) {
    await fx.destinations(d, [{ host: MAIL_SINK_HOST, tlsMode: 'opportunistic' }]);
  }
  saslA = await fx.saslConnector(org('A').id, 'ar8a');
  saslB = await fx.saslConnector(org('B').id, 'ar8b');
  expect(await fx.dkimSync()).toMatch(/published=\d+/);

  // Tenant policies (published through the api like every 5.2 suite).
  await createAndPublishPolicy(await as('A', 'security_analyst'), await admin('A'), 'AR8 A', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'archive-dup',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.dup },
        actions: [{ type: 'ARCHIVE' }],
      },
      {
        id: 'reject-listed',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.rejA },
        actions: [{ type: 'REJECT' }],
      },
    ],
  });
  await createAndPublishPolicy(await as('B', 'security_analyst'), await admin('B'), 'AR8 B', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'reject-listed',
        priority: 20,
        when: { field: 'recipient.local_part', op: 'equals', value: LP.rejB },
        actions: [{ type: 'REJECT' }],
      },
    ],
  });
  await createAndPublishPolicy(await as('C', 'security_analyst'), await admin('C'), 'AR8 C', {
    dslVersion: 'policy-dsl/1',
    direction: 'inbound',
    priority: 100,
    rules: [
      {
        id: 'archive-listed',
        priority: 10,
        when: { field: 'recipient.local_part', op: 'in', value: [LP.c8a, LP.c9, LP.c8b] },
        actions: [{ type: 'ARCHIVE' }],
      },
    ],
  });

  // Archive settings and retention through the api (A11, A22).
  const access = { previewEnabled: true, downloadEnabled: true };
  const defaultA = await retentionPolicy('A', { name: 'default', retentionDays: 2_000 });
  await retentionPolicy('A', {
    name: 'short',
    retentionDays: 2,
    priority: 10,
    criteria: { domainIds: [aShort.publicId] },
  });
  await settings('A', {
    enabled: true,
    defaultRetentionPolicyId: defaultA,
    settings: {
      directions: { inbound: true, outbound: true, internal: true },
      include: { rejected: false, quarantined: false, failed: false },
      access,
    },
  });
  const defaultB = await retentionPolicy('B', { name: 'default', retentionDays: 2_000 });
  await settings('B', {
    enabled: true,
    defaultRetentionPolicyId: defaultB,
    settings: {
      directions: { inbound: true, outbound: true, internal: false },
      include: { rejected: true, quarantined: true, failed: true },
      access,
    },
  });
  const defaultC = await retentionPolicy('C', { name: 'default', retentionDays: 2_000 });
  await settings('C', {
    enabled: true,
    defaultRetentionPolicyId: defaultC,
    settings: {
      directions: { inbound: false, outbound: false, internal: false },
      policyArchive: { enabled: true },
    },
  });
  const defaultL = await retentionPolicy('L', { name: 'default', retentionDays: 2 });
  await settings('L', {
    enabled: true,
    immutability: 'compliance',
    defaultRetentionPolicyId: defaultL,
  });
  const status = await (await admin('L')).get('/archive/status');
  expectStatus(status, 200);
  expect(body<{ objectLock: { available: boolean } }>(status).objectLock.available).toBe(true);
  record('archive-smtp', {
    organizations: all().length,
    day_seconds: ARCHIVE_SUITE_DAY_SECONDS,
    replica_target: replicaBucket(),
  });
}, 900_000);

afterAll(async () => {
  if (gate.skip) return;
  if (minioStopped) {
    await composeOk(['start', 'minio'], { timeoutMs: 120_000 }).catch(() => undefined);
  }
  // Nothing may capture, index or dispose while the fixtures go (only when this suite changed
  // the containers: a gate failure before the overrides leaves the stack as it found it).
  if (servicesOverridden) await compose(['stop', 'archive-worker'], { timeoutMs: 120_000 });
  const ids = all().map((o) => o.id);
  let locked = 0;
  if (s3 !== undefined && search !== undefined) {
    const deadline = Date.now() + 4 * 60_000;
    for (;;) {
      locked = (await purgeArchiveTenants(fx.prisma, s3, search, ids)).lockedVersions;
      if (locked === 0 || Date.now() > deadline) break;
      await sleep(15_000);
    }
  }
  for (const session of sessions) await session.remove().catch(() => undefined);
  const names = [orgs.A?.inbound, orgs.B?.inbound, orgs.C?.inbound, orgs.L?.inbound]
    .concat([aShort, outA, outB])
    .filter((d): d is FixtureDomain => d !== undefined)
    .map((d) => d.name);
  for (const service of ['postfix-outbound', 'postfix'] as const) {
    const queued = involving(await listQueue(service), [...names, extDomain(), senderDomain()]);
    await deleteQueued(
      service,
      queued.map((m) => m.queue_id),
    );
  }
  for (const domain of [extDomain(), senderDomain(), ...names]) {
    await clearSinkDomain(domain, 'all').catch(() => undefined);
  }
  await fx.cleanup();
  if (servicesOverridden) {
    await restoreArchiveServices();
    expect((await containerEnv('archive-worker')).ARCHIVE_TEST_DAY_SECONDS).toBe('');
    expect((await containerEnv('api')).ARCHIVE_TEST_DAY_SECONDS).toBe('');
  }
  s3?.destroy();
  record('archive-smtp', {
    cleanup_locked_versions: locked,
    services_restored: servicesOverridden,
  });
  expect(locked).toBe(0);
}, 900_000);

const shared: Partial<Record<string, Msg>> = {};
const records: Partial<Record<string, ArchiveRecordRow>> = {};

describe.skipIf(gate.skip)('archive stack (step 8.1 §9.4)', { timeout: 900_000 }, () => {
  it('(0) sends the journaled traffic of cases 1–5, 7 and 10', async () => {
    const A = org('A').inbound.name;
    const B = org('B').inbound.name;
    shared.in1 = await inbound('A', [`ar8in1@${A}`], 'inbound', [
      { filename: 'ar8-report.txt', contentType: 'text/plain', bytes: Buffer.from('report\n') },
    ]);
    shared.out2 = await submitted('A', `ar8out@${outA.name}`, [`ar8ext@${extDomain()}`], 'out');
    shared.int3 = await submitted('A', `ar8int@${outA.name}`, [`ar8int3@${A}`], 'internal');
    shared.int4 = await submitted('B', `ar8int@${outB.name}`, [`ar8int4@${B}`], 'internal B');
    shared.in4 = await inbound('B', [`ar8in4@${B}`], 'inbound B');
    shared.rejA = await inbound('A', [`${LP.rejA}@${A}`], 'rejected A');
    shared.rejB = await inbound('B', [`${LP.rejB}@${B}`], 'rejected B');
    shared.fail7 = await inbound('B', [`hard-bounce@${B}`], 'failed');
    shared.dup10 = await inbound('A', [`${LP.dup}@${A}`], 'duplicates');
    expect(shared.int3.direction).toBe('internal');
    expect(shared.out2.direction).toBe('outbound');
    expect(shared.int4.direction).toBe('internal');
  });

  it('(1) inbound journaled: encrypted copy of the original, journal, linked round, searchable', async () => {
    const row = await expectJournaled('A', shared.in1!, {
      direction: 'inbound',
      category: 'delivered',
      journal: true,
      policy: false,
    });
    expect(row.attachmentCount).toBe(1);
    const item = await searchedThroughApi('A', shared.in1!.publicId);
    expect(item.attachmentNames).toEqual(['ar8-report.txt']);
    records.in1 = row;
    record('archive-smtp', {
      case: 1,
      category: row.category,
      key_version: row.keyVersion,
      stored_bytes: row.storedBytes.toString(),
      original_bytes: row.sizeBytes,
      rounds: (row.scanRounds as unknown[]).length,
      capture_s: ((row.archivedAt.getTime() - row.receivedAt.getTime()) / 1000).toFixed(1),
    });
  });

  it('(2) outbound (submission 587) journaled', async () => {
    const row = await expectJournaled('A', shared.out2!, {
      direction: 'outbound',
      category: 'delivered',
      journal: true,
      policy: false,
    });
    records.out2 = row;
    record('archive-smtp', { case: 2, direction: row.direction, category: row.category });
  });

  it('(3) internal journaled', async () => {
    const row = await expectJournaled('A', shared.int3!, {
      direction: 'internal',
      category: 'delivered',
      journal: true,
      policy: false,
    });
    records.int3 = row;
    record('archive-smtp', { case: 3, direction: row.direction, category: row.category });
  });

  it('(4) direction disabled (B internal off): no intent, no record; B inbound journaled', async () => {
    const control = await expectJournaled('B', shared.in4!, {
      direction: 'inbound',
      category: 'delivered',
      journal: true,
      policy: false,
    });
    records.in4 = control;
    await sweptPast(shared.int4!);
    await sleep(5_000);
    expect(await intentOf(fx.prisma, shared.int4!)).toBeNull();
    expect(await recordOf(fx.prisma, shared.int4!)).toBeNull();
    record('archive-smtp', { case: 4, internal_intent: 'none', internal_record: 'none' });
  });

  it('(5) rejected: excluded in A (intent skipped category_excluded), included in B (captured rejected)', async () => {
    // An inbound REJECT after acceptance is a discard (no backscatter): rejected/policy_discard.
    await waitForLifecycle(fx.prisma, shared.rejA!, 'rejected', 'policy_discard');
    const skipped = await waitForIntent(fx.prisma, shared.rejA!, ['skipped']);
    expect(skipped.skipReason).toBe('category_excluded');
    expect(await recordOf(fx.prisma, shared.rejA!)).toBeNull();
    const row = await expectJournaled('B', shared.rejB!, {
      direction: 'inbound',
      category: 'rejected',
      journal: true,
      policy: false,
    });
    expect(row.messageState).toBe('rejected');
    records.rejB = row;
    record('archive-smtp', {
      case: 5,
      a_intent: `${skipped.status}/${skipped.skipReason}`,
      b_category: row.category,
      b_state: `${row.messageState}/${row.messageStateReason}`,
    });
  });

  it('(6) quarantined EICAR (B includes quarantined): captured quarantined and malicious, preview sanitized, download refused', async () => {
    const B = org('B').inbound.name;
    const message = await inbound('B', [`ar8ev@${B}`], 'EICAR', [
      { filename: 'ar8-invoice.txt', contentType: 'text/plain', bytes: eicar() },
    ]);
    const evaluation = await waitForEvaluation(fx.prisma, message, 0, 180_000);
    expect(evaluation.disposition).toBe('reject');
    await waitForLifecycle(fx.prisma, message, 'rejected', 'policy_discard');
    // Manual quarantine (5.3 Q7, E29) before the journal sweep reaches the message.
    const manual = await (
      await as('B', 'security_analyst')
    ).post(
      '/quarantine/entries',
      { messageId: message.publicId, reason: 'archive stack test' },
      idempotencyKey(),
    );
    expectStatus(manual, 201);
    await waitForLifecycle(fx.prisma, message, 'quarantined', 'manual_quarantine');
    const row = await waitForRecord(fx.prisma, message);
    expect(row).toMatchObject({ category: 'quarantined', malicious: true, status: 'active' });
    const intent = await intentOf(fx.prisma, message);
    expect(intent!.status).toBe('captured_open');
    const session = await admin('B');
    const preview = await session.get(`/archive/messages/${message.publicId}/preview`);
    expectStatus(preview, 200);
    const text = JSON.stringify(preview.body);
    expect(body<{ version: string }>(preview).version).toBe('preview/1');
    expect(text).not.toMatch(/<script|<html|EICAR-STANDARD-ANTIVIRUS-TEST-FILE/i);
    expect(preview.headers.get('cache-control')).toContain('no-store');
    const grant = await session.post(
      `/archive/messages/${message.publicId}/download-grants`,
      await session.reauth(),
    );
    expectStatus(grant, 409);
    expect(grant.body).toMatchObject({ code: 'archive_download_blocked' });
    records.eicar = row;
    record('archive-smtp', {
      case: 6,
      category: row.category,
      malicious: row.malicious,
      state: `${row.messageState}/${row.messageStateReason}`,
      preview: preview.status,
      grant: `${grant.status}:${(grant.body as { code: string }).code}`,
    });
  });

  it('(7) failed delivery included (B): permanent 5xx → rejected/delivery_failed → captured failed', async () => {
    await waitForLifecycle(fx.prisma, shared.fail7!, 'rejected', 'delivery_failed', 240_000);
    const row = await expectJournaled('B', shared.fail7!, {
      direction: 'inbound',
      category: 'failed',
      journal: true,
      policy: false,
    });
    expect(row.messageStateReason).toBe('delivery_failed');
    records.fail7 = row;
    record('archive-smtp', {
      case: 7,
      category: row.category,
      state: `${row.messageState}/${row.messageStateReason}`,
    });
  });

  it('(8a) policy ARCHIVE with journaling off (C): consumed from email.archive, captured as policy', async () => {
    const message = await inbound('C', [`${LP.c8a}@${org('C').inbound.name}`], 'policy');
    const evaluation = await waitForEvaluation(fx.prisma, message, 0, 180_000);
    expect(
      (evaluation.actions as { type: string; status: string }[]).find((a) => a.type === 'ARCHIVE'),
    ).toMatchObject({ status: 'requested' });
    const [request] = await messageOutboxOf(
      fx.prisma,
      org('C').id,
      message,
      EventTypes.MessageArchiveRequested,
    );
    expect(request).toBeDefined();
    messageArchiveRequestedV1.parse(request!.payload);
    await waitFor(
      'the archive request in the archive-worker ledger',
      async () =>
        (await fx.prisma.messageIdempotency.count({
          where: { consumer: ARCHIVE_LEDGER, eventId: request!.eventId },
        })) === 1,
      { timeoutMs: 120_000, intervalMs: 1_000 },
    );
    const row = await expectJournaled('C', message, {
      direction: 'inbound',
      category: 'delivered',
      journal: false,
      policy: true,
    });
    expect(row.policyRuleRef).toMatch(/\/archive-listed$/);
    const intent = await intentOf(fx.prisma, message);
    expect(intent).toMatchObject({ sourcePolicy: true, sourceJournal: false });
    records.c8a = row;
    record('archive-smtp', {
      case: '8a',
      sources: 'policy',
      ledger: 'consumed',
      rule: row.policyRuleRef?.split('/').pop(),
    });
  });

  it('(9) queue loss: worker stopped, email.archive purged, the policy reconciler captures it', async () => {
    await composeOk(['stop', 'archive-worker'], { timeoutMs: 120_000 });
    workerStopped = true;
    const message = await inbound('C', [`${LP.c9}@${org('C').inbound.name}`], 'queue loss');
    await waitForEvaluation(fx.prisma, message, 0, 180_000);
    const [request] = await messageOutboxOf(
      fx.prisma,
      org('C').id,
      message,
      EventTypes.MessageArchiveRequested,
    );
    await waitFor(
      'the archive request in email.archive',
      async () => (await copiesOfEvent(mgmt, vhost, 'email.archive', request!.eventId)) === 1,
      { timeoutMs: 120_000, intervalMs: 1_000 },
    );
    const depth = (await mgmt.queue(vhost, 'email.archive')).messages;
    await mgmt.purge(vhost, 'email.archive');
    await waitFor(
      'email.archive empty',
      async () => (await mgmt.queue(vhost, 'email.archive')).messages === 0,
      { timeoutMs: 30_000, intervalMs: 1_000 },
    );
    await startWorker();
    const row = await waitForRecord(fx.prisma, message, () => true, 420_000);
    expect(row).toMatchObject({ capturedByPolicy: true, capturedByJournal: false });
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: ARCHIVE_LEDGER, eventId: request!.eventId },
      }),
    ).toBe(0);
    const capturedAfterS = (row.archivedAt.getTime() - row.receivedAt.getTime()) / 1000;
    record('archive-smtp', {
      case: 9,
      purged_depth: depth,
      ledger: 'none',
      source: 'reconciler',
      capture_s: capturedAfterS.toFixed(0),
    });
  });

  it('(8b) archiving disabled (C): the policy request is skipped (archiving_disabled)', async () => {
    await settings('C', { enabled: false });
    await sleep(3_000);
    const message = await inbound('C', [`${LP.c8b}@${org('C').inbound.name}`], 'disabled');
    const intent = await waitForIntent(fx.prisma, message, ['skipped']);
    expect(intent).toMatchObject({ skipReason: 'archiving_disabled', sourcePolicy: true });
    expect(await recordOf(fx.prisma, message)).toBeNull();
    record('archive-smtp', { case: '8b', intent: `${intent.status}/${intent.skipReason}` });
  });

  it('(10) duplicates: journal + policy sources and a re-published request → one record', async () => {
    const row = await expectJournaled('A', shared.dup10!, {
      direction: 'inbound',
      category: 'delivered',
      journal: true,
      policy: true,
    });
    const [request] = await messageOutboxOf(
      fx.prisma,
      org('A').id,
      shared.dup10!,
      EventTypes.MessageArchiveRequested,
    );
    const broker = await LiveBroker.connect();
    try {
      await broker.publish([envelopeOfRow(request!), envelopeOfRow(request!)]);
    } finally {
      await broker.close();
    }
    await waitFor(
      'the duplicates acked (email.archive drained)',
      async () => (await mgmt.queue(vhost, 'email.archive')).messages === 0,
      { timeoutMs: 60_000, intervalMs: 1_000 },
    );
    await sleep(5_000);
    expect(
      await fx.prisma.emailArchive.count({
        where: { messageId: shared.dup10!.id, receivedAt: shared.dup10!.receivedAt },
      }),
    ).toBe(1);
    expect(
      await fx.prisma.archiveCaptureIntent.count({
        where: { messageId: shared.dup10!.id, receivedAt: shared.dup10!.receivedAt },
      }),
    ).toBe(1);
    expect(
      await fx.prisma.messageIdempotency.count({
        where: { consumer: ARCHIVE_LEDGER, eventId: request!.eventId },
      }),
    ).toBe(1);
    expect((await recordOf(fx.prisma, shared.dup10!))!.id).toBe(row.id);
    const item = await searchedThroughApi('A', shared.dup10!.publicId);
    expect(item.sources.sort()).toEqual(['journal', 'policy']);
    record('archive-smtp', { case: 10, records: 1, intents: 1, ledger_rows: 1, republished: 2 });
  });

  it('(11) retention expiry: disposed consistently across S3 (primary + replica), OpenSearch, MySQL, disposal log, audit', async () => {
    const message = await inbound('A', [`ar8x11@${aShort.name}`], 'expiry');
    const row = await waitForRecord(fx.prisma, message);
    const policy = await fx.prisma.archiveRetentionPolicy.findFirstOrThrow({
      where: { id: row.retentionPolicyId! },
    });
    expect(policy.name).toBe('short');
    expect(row.retainUntil.getTime()).toBe(message.receivedAt.getTime() + 2 * DAY_MS);
    const prefix = recordPrefix(row);
    const copied = await copyToReplica(s3, row);
    expect(copied).toBeGreaterThanOrEqual(3);
    expect((await versionsUnder(s3, replicaBucket(), prefix)).length).toBe(copied);
    await searchedThroughApi('A', message.publicId);
    expect(await rawIndexCount(search, [message.publicId])).toBe(1);

    const disposal = await waitForDisposalCompleted(message);
    expect(disposal.reason).toBe('retention_expired');
    expect(await recordOf(fx.prisma, message)).toBeNull();
    expect(await versionsUnder(s3, stack.s3().archiveBucket, prefix)).toEqual([]);
    expect(await versionsUnder(s3, replicaBucket(), prefix)).toEqual([]);
    await waitFor(
      'the index document gone',
      async () => (await rawIndexCount(search, [message.publicId])) === 0,
      { timeoutMs: 30_000, intervalMs: 1_000 },
    );
    const session = await admin('A');
    expectStatus(await session.get(`/archive/messages/${message.publicId}`), 404);
    const log = await session.get('/archive/disposals?limit=100');
    expectStatus(log, 200);
    const entry = body<{ data: { messageId: string; reason: string; state: string }[] }>(
      log,
    ).data.find((d) => d.messageId === message.publicId);
    expect(entry).toMatchObject({ reason: 'retention_expired', state: 'completed' });
    const runs = await fx.prisma.auditLog.findMany({
      where: { organizationId: org('A').id, action: 'archive.lifecycle_run' },
    });
    expect(runs.some((r) => Number((r.metadata as { disposed?: number }).disposed ?? 0) >= 1)).toBe(
      true,
    );
    record('archive-smtp', {
      case: 11,
      reason: disposal.reason,
      state: disposal.state,
      replica_versions_copied: copied,
      disposed_after_s: (
        (disposal.completedAt!.getTime() - message.receivedAt.getTime()) /
        1000
      ).toFixed(0),
    });
  });

  it('(12) legal hold blocks expiry; release → disposed', async () => {
    const custodian = `ar8x12@${aShort.name}`;
    const session = await admin('A');
    const created = await session.post(
      '/ediscovery/cases',
      { name: `AR8 hold ${run}`, custodians: [custodian] },
      idempotencyKey(),
    );
    expectStatus(created, 201);
    const caseId = body<{ id: string }>(created).id;
    const hold = await session.post(
      `/ediscovery/cases/${caseId}/holds`,
      { name: 'AR8 hold', reason: 'archive stack test', useCaseCustodians: true },
      idempotencyKey(),
    );
    expectStatus(hold, 201);
    const holdId = body<{ id: string }>(hold).id;

    const message = await inbound('A', [custodian], 'held');
    const captured = await waitForRecord(fx.prisma, message);
    const held = await waitForRecord(
      fx.prisma,
      message,
      (r) => r.legalHold && r.retainUntil.getTime() > captured.retainUntil.getTime(),
      360_000,
    );
    expect(held.status).toBe('active');
    expect(await disposalOf(message)).toBeNull();
    const detail = await session.get(`/archive/messages/${message.publicId}`);
    expectStatus(detail, 200);
    expect(detail.body).toMatchObject({ legalHold: true, holds: [{ id: holdId }] });

    const release = await session.post(
      `/legal-holds/${holdId}/release`,
      { reason: 'archive stack test released' },
      idempotencyKey(),
    );
    expectStatus(release, 200);
    const disposal = await waitForDisposalCompleted(message);
    expect(disposal.reason).toBe('retention_expired');
    expect(await recordOf(fx.prisma, message)).toBeNull();
    record('archive-smtp', {
      case: 12,
      held_extension_s: (
        (held.retainUntil.getTime() - captured.retainUntil.getTime()) /
        1000
      ).toFixed(0),
      after_release: disposal.state,
    });
  });

  it('(13) Object Lock compliance: MinIO refuses deleting a locked version; disposed after the lock', async () => {
    const message = await inbound('L', [`ar8x13@${org('L').inbound.name}`], 'locked');
    const row = await waitForRecord(fx.prisma, message);
    expect(row.lockMode).toBe('compliance');
    expect(row.lockUntil).not.toBeNull();
    const eml = objectsOf(row).eml;
    const retention = await s3.send(
      new GetObjectRetentionCommand({
        Bucket: stack.s3().archiveBucket,
        Key: eml.key,
        VersionId: eml.versionId ?? undefined,
      }),
    );
    expect(retention.Retention?.Mode).toBe('COMPLIANCE');
    const legalHold = await s3
      .send(
        new GetObjectLegalHoldCommand({
          Bucket: stack.s3().archiveBucket,
          Key: eml.key,
          VersionId: eml.versionId ?? undefined,
        }),
      )
      .then((r) => r.LegalHold?.Status ?? 'OFF')
      .catch(() => 'OFF');
    expect(legalHold).toBe('OFF');
    const refusals: string[] = [];
    for (const bypass of [false, true]) {
      try {
        await s3.send(
          new DeleteObjectCommand({
            Bucket: stack.s3().archiveBucket,
            Key: eml.key,
            VersionId: eml.versionId ?? undefined,
            BypassGovernanceRetention: bypass,
          }),
        );
        refusals.push('deleted');
      } catch (err) {
        refusals.push((err as { name?: string }).name ?? 'error');
      }
    }
    expect(refusals).not.toContain('deleted');
    // The version is still there and still decrypts.
    const plain = await decryptRecordObject(fx.prisma, s3, row, 'eml');
    expect(createHash('sha256').update(plain.plaintext).digest('hex')).toBe(message.emlSha256);
    const disposal = await waitForDisposalCompleted(message);
    expect(await versionsUnder(s3, stack.s3().archiveBucket, recordPrefix(row))).toEqual([]);
    record('archive-smtp', {
      case: 13,
      mode: retention.Retention?.Mode,
      delete_refused: refusals.join(','),
      disposed: disposal.state,
    });
  });

  it('(14) tenant isolation: search, ids and aliases', async () => {
    const aIds = [shared.in1!, shared.out2!, shared.int3!].map((m) => m.publicId);
    const bIds = [shared.in4!, shared.rejB!, shared.fail7!].map((m) => m.publicId);
    for (const m of [
      shared.in1!,
      shared.out2!,
      shared.int3!,
      shared.in4!,
      shared.rejB!,
      shared.fail7!,
    ]) {
      await waitForRecord(fx.prisma, m);
    }
    const sessionA = await admin('A');
    const sessionB = await admin('B');
    const listA = body<{ data: ArchiveItem[] }>(
      await sessionA.get(`/archive/messages?${windowQuery()}&limit=100`),
    ).data.map((m) => m.messageId);
    expect(listA).toEqual(expect.arrayContaining(aIds));
    for (const id of bIds) expect(listA).not.toContain(id);
    for (const path of ['', '/journal', '/security', '/preview']) {
      expectStatus(await sessionA.get(`/archive/messages/${bIds[0]}${path}`), 404);
      expectStatus(await sessionB.get(`/archive/messages/${aIds[0]}${path}`), 404);
    }
    expectStatus(
      await sessionA.post(`/archive/messages/${bIds[0]}/download-grants`, await sessionA.reauth()),
      404,
    );
    expectStatus(
      await sessionA.post(`/archive/messages/${bIds[0]}/reveal`, { fields: ['subject'] }),
      404,
    );
    // The own record reveals (audited before the response); the foreign one never did.
    const revealed = await sessionA.post(`/archive/messages/${aIds[0]}/reveal`, {
      fields: ['subject', 'recipients'],
    });
    expectStatus(revealed, 200);
    expect(body<{ subject: string }>(revealed).subject).toContain(SUBJECT);
    const reveals = await fx.prisma.auditLog.findMany({
      where: { organizationId: { in: [org('A').id, org('B').id] }, action: 'archive.revealed' },
    });
    expect(reveals).toHaveLength(1);
    expect(reveals[0]!.organizationId).toBe(org('A').id);
    expect(JSON.stringify(reveals[0]!.metadata)).not.toContain(SUBJECT);
    expect(await aliasCount(search, org('A').id, bIds)).toBe(0);
    expect(await aliasCount(search, org('B').id, aIds)).toBe(0);
    expect(await aliasCount(search, org('A').id, aIds)).toBe(aIds.length);
    expect(await rawIndexCount(search, bIds)).toBe(bIds.length);
    // Even a foreign org_id term through A's alias finds nothing (the alias filter is AND-ed).
    expect(
      await aliasCount(search, org('A').id, bIds, { term: { org_id: org('B').id.toString() } }),
    ).toBe(0);
    record('archive-smtp', { case: 14, a_visible: aIds.length, b_through_a: 0, a_through_b: 0 });
  });

  it('(15) eDiscovery end to end: case, custodian, hold, search, review, export, re-auth download, manifest hashes and signature', async () => {
    const custodian = `ar8ed@${org('A').inbound.name}`;
    const m1 = await inbound('A', [custodian], 'ediscovery one');
    const m2 = await inbound(
      'A',
      [custodian, `ar8other@${org('A').inbound.name}`],
      'ediscovery two',
    );
    for (const m of [m1, m2]) {
      await waitForRecord(fx.prisma, m);
      await searchedThroughApi('A', m.publicId);
    }
    const session = await admin('A');
    const C = '/ediscovery/cases';
    const created = await session.post(
      C,
      { name: `AR8 matter ${run}`, matterReference: 'AR8-EXAMPLE', custodians: [custodian] },
      idempotencyKey(),
    );
    expectStatus(created, 201);
    const caseId = body<{ id: string }>(created).id;
    const hold = await session.post(
      `${C}/${caseId}/holds`,
      { name: 'AR8 matter hold', reason: 'archive stack test', useCaseCustodians: true },
      idempotencyKey(),
    );
    expectStatus(hold, 201);
    const today = new Date().toISOString().slice(0, 10);
    const requested = await session.post(
      `${C}/${caseId}/searches`,
      { criteria: { from: today, to: today, custodians: 'case' } },
      idempotencyKey(),
    );
    expectStatus(requested, 202);
    const searchId = body<{ id: string }>(requested).id;
    const done = await waitFor(
      'the case search completed',
      async () => {
        const res = await session.get(`${C}/${caseId}/searches/${searchId}`);
        const s = body<{
          status: string;
          hitCount: number;
          indexComplete: boolean | null;
          incompleteReason: string | null;
        }>(res);
        return s.status === 'completed' || s.status === 'failed' ? s : undefined;
      },
      { timeoutMs: 180_000, intervalMs: 2_000 },
    );
    expect(done).toMatchObject({ status: 'completed', hitCount: 2 });
    const hits = await session.get(`${C}/${caseId}/searches/${searchId}/hits`);
    expectStatus(hits, 200);
    const hitIds = body<{ data: { messageId: string; message: { subject: null } }[] }>(hits).data;
    expect(hitIds.map((h) => h.messageId).sort()).toEqual([m1.publicId, m2.publicId].sort());
    for (const h of hitIds) expect(h.message.subject).toBeNull();
    const review = await session.post(
      `${C}/${caseId}/searches/${searchId}/review`,
      { tag: 'relevant', messageIds: [m1.publicId, m2.publicId] },
      idempotencyKey(),
    );
    expectStatus(review, 200);
    const exp = await session.post(
      `${C}/${caseId}/exports`,
      { searchId, reviewTags: ['relevant'] },
      idempotencyKey(),
    );
    expectStatus(exp, 202);
    const exportId = body<{ id: string }>(exp).id;
    const built = await waitFor(
      'the export completed',
      async () => {
        const e = body<{ status: string; packageSha256: string | null; itemCount: number }>(
          await session.get(`${C}/${caseId}/exports/${exportId}`),
        );
        return e.status === 'completed' || e.status === 'failed' ? e : undefined;
      },
      { timeoutMs: 180_000, intervalMs: 2_000 },
    );
    expect(built.status).toBe('completed');
    const grant = await session.post(
      `${C}/${caseId}/exports/${exportId}/download-grants`,
      await session.reauth(),
    );
    expectStatus(grant, 201);
    const token = body<{ token: string }>(grant).token;
    const download = await session.getRaw(`/archive/downloads/${token}`);
    expect(download.status).toBe(200);
    expect(download.headers.get('content-type')).toContain('application/octet-stream');
    expect(createHash('sha256').update(download.bytes).digest('hex')).toBe(built.packageSha256);
    expect((await session.getRaw(`/archive/downloads/${token}`)).status).toBe(410);
    // Unzip: the manifest, its signature and the two originals.
    const zip = readZip(download.bytes);
    const manifestBytes = zip.get('manifest.json')!;
    const signature = zip.get('manifest.sig')!.toString('utf8').trim();
    const keys = body<{ data: { id: string; publicKey: string; current: boolean }[] }>(
      await session.get('/archive/export-signing-keys'),
    ).data;
    const current = keys.find((k) => k.current)!;
    const independent = verify(
      null,
      manifestBytes,
      createPublicKey({
        key: Buffer.from(current.publicKey, 'base64url'),
        format: 'der',
        type: 'spki',
      }),
      Buffer.from(signature, 'base64url'),
    );
    expect(independent).toBe(true);
    const manifest = verifySignedExportManifest(
      manifestBytes,
      signature,
      parseExportSigningPublicKey(current.publicKey),
    );
    expect(manifest).not.toBeNull();
    expect(manifest!.signingKeyId).toBe(current.id);
    expect(manifest!.items).toHaveLength(2);
    for (const item of manifest!.items) {
      const bytes = zip.get(item.path)!;
      const sha = createHash('sha256').update(bytes).digest('hex');
      expect(sha).toBe(item.sha256);
      const original = [m1, m2].find((m) => m.publicId === item.messageId)!;
      expect(sha).toBe(original.emlSha256);
    }
    // A tampered manifest no longer verifies.
    const tampered = Buffer.from(manifestBytes.toString('utf8').replace(/"items"/, '"itemz"'));
    expect(
      verifySignedExportManifest(
        tampered,
        signature,
        parseExportSigningPublicKey(current.publicKey),
      ),
    ).toBeNull();
    const release = await session.post(
      `/legal-holds/${body<{ id: string }>(hold).id}/release`,
      { reason: 'archive stack test done' },
      idempotencyKey(),
    );
    expectStatus(release, 200);
    record('archive-smtp', {
      case: 15,
      hits: done.hitCount,
      index_complete: done.indexComplete,
      incomplete_reason: done.incompleteReason,
      export_items: manifest!.items.length,
      package_bytes: download.bytes.length,
      signature: 'ed25519-ok',
    });
  });

  it('(16) LMTP temporary failure (S3 down) then success → one message, one record', async () => {
    const since = new Date(Date.now() - 1_000);
    const rcpt = `ar8x16@${org('A').inbound.name}`;
    let queueId = '';
    try {
      await composeOk(['stop', 'minio'], { timeoutMs: 120_000 });
      minioStopped = true;
      const built = attachmentMessage({
        from: `External <${SENDER()}>`,
        to: [rcpt],
        subject: `${SUBJECT} lmtp`,
        attachments: [],
      });
      const sent = await swaks({
        server: 'postfix',
        port: 25,
        from: SENDER(),
        to: [rcpt],
        data: built.text,
      });
      expect(reply(sent, 'DATA-END').code, sent.transcript).toBe(250);
      queueId = sent.queueId!;
      await waitForLog(
        'postfix',
        since,
        new RegExp(`${queueId}: to=<.*status=deferred.*451 4\\.3\\.0`),
        90_000,
      );
      expect(
        await fx.prisma.emailMessage.count({
          where: { organizationId: org('A').id, mtaQueueId: queueId },
        }),
      ).toBe(0);
    } finally {
      await composeOk(['start', 'minio'], { timeoutMs: 120_000 });
      await waitFor(
        'MinIO ready',
        async () => (await fetch(`${process.env.S3_ENDPOINT}/minio/health/ready`)).ok,
        { timeoutMs: 90_000, intervalMs: 1_000 },
      );
      minioStopped = false;
    }
    await flushQueue('postfix');
    const message = await keyOf(org('A').id, queueId);
    await waitForQueueDrained('postfix', [org('A').inbound.name]);
    const row = await waitForRecord(fx.prisma, message);
    expect(
      await fx.prisma.emailMessage.count({
        where: { organizationId: org('A').id, mtaQueueId: queueId },
      }),
    ).toBe(1);
    expect(
      await fx.prisma.emailArchive.count({
        where: { messageId: message.id, receivedAt: message.receivedAt },
      }),
    ).toBe(1);
    expect(row.sha256).toBe(message.emlSha256);
    record('archive-smtp', { case: 16, deferred: '451 4.3.0', messages: 1, records: 1 });
  });

  it('(17) archive-worker killed mid-capture → one record after the restart', async () => {
    const rcpt = `ar8x17@${org('A').inbound.name}`;
    let killedMidCapture = false;
    let message: Msg | undefined;
    for (let attempt = 1; attempt <= 3 && !killedMidCapture; attempt += 1) {
      message = await inbound(
        'A',
        [rcpt],
        `kill ${attempt}`,
        [
          {
            filename: 'ar8-large.bin',
            contentType: 'application/octet-stream',
            bytes: randomBytes(12 * 1024 * 1024),
          },
        ],
        ['--suppress-data'],
      );
      const leased = await waitFor(
        'the capture claim (lease) of the large message',
        async () => {
          const intent = await intentOf(fx.prisma, message!);
          if (intent === null) return undefined;
          if (intent.status !== 'pending') return 'late';
          return intent.leaseUntil !== null && intent.leaseUntil.getTime() > Date.now()
            ? 'leased'
            : undefined;
        },
        { timeoutMs: 300_000, intervalMs: 25 },
      );
      if (leased === 'leased') {
        await composeOk(['kill', '-s', 'SIGKILL', 'archive-worker'], { timeoutMs: 60_000 });
        workerStopped = true;
        killedMidCapture = (await recordOf(fx.prisma, message)) === null;
        await startWorker();
      }
    }
    expect(killedMidCapture).toBe(true);
    const row = await waitForRecord(fx.prisma, message!, () => true, 420_000);
    expect(
      await fx.prisma.emailArchive.count({
        where: { messageId: message!.id, receivedAt: message!.receivedAt },
      }),
    ).toBe(1);
    const intent = await intentOf(fx.prisma, message!);
    expect(intent).toMatchObject({ archiveId: row.id });
    const eml = await decryptRecordObject(fx.prisma, s3, row, 'eml');
    expect(createHash('sha256').update(eml.plaintext).digest('hex')).toBe(message!.emlSha256);
    const versions = await versionsUnder(s3, stack.s3().archiveBucket, recordPrefix(row));
    const captureIds = new Set(versions.map((v) => v.key.split('/').at(-2)));
    record('archive-smtp', {
      case: 17,
      killed_mid_capture: killedMidCapture,
      records: 1,
      attempts: intent!.attempts,
      capture_ids_under_prefix: captureIds.size,
      orphan_versions: versions.filter((v) => !v.key.includes(objectsOf(row).captureId)).length,
    });
    expect(workerStopped).toBe(false);
  });
});
