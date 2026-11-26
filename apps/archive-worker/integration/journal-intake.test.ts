import { createHash, randomBytes } from 'node:crypto';
import {
  archiveJournalSchema,
  archivePartiesSchema,
  archivePrefixOf,
  archiveRecordObjectsSchema,
  canonicalSha256,
  createArchiveDecryptStream,
  decryptArchiveObject,
  exportSigningPublicKeyOf,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  unwrapExportKey,
  verifyManifestSignature,
  verifySignedExportManifest,
} from '@email-gateway/archive';
import { EventTypes, notificationAlertRequestedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { upsertIntents } from '../src/capture/intents';
import { utcDay } from '../src/index/reconcile';
import { type CopySpec, Fixtures, type SeededMessage } from './support/fixtures';
import {
  Clock,
  drainCapture,
  drainIndex,
  harness,
  type Harness,
  testConfig,
} from './support/harness';
import { readZip } from './support/zip';

/**
 * Journal intake capture and cross-source dedupe (step 8.6 §9.3, D6, D7, D9, ADR-0087/0088) on
 * the real MySQL writer, MinIO and OpenSearch: intake capture (sources, intake block, parties
 * with fields), dedupe gateway-first and intake-first, same body (no variant) and different body
 * (variant), the variant and merged-copies limits, intake↔intake, concurrent captures of one key
 * by two schedulers, the refresh of a merged gateway copy, disposal of a merged group, a legal
 * hold on a BCC custodian, pruning, and the intake health job with alert throttling. Intake
 * messages are inserted as the smtp-adapter's `JournalIntakeRepository` commits them.
 */
const fx = new Fixtures();
const clock = new Clock();
let h: Harness;
const DAY_S = 2;
const run = randomBytes(4).toString('hex');
let seq = 0;

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function readAll(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of stream as AsyncIterable<Buffer>) chunks.push(Buffer.from(c));
  return Buffer.concat(chunks);
}

/** Two copies of one message: a shared key (Message-ID, Date, From, To/Cc, attachment). */
function message(over: Partial<CopySpec> = {}): Omit<CopySpec, 'ingestSource'> {
  seq += 1;
  return {
    messageId: `it-dedupe-${run}-${seq}@partner.example`,
    date: 'Fri, 20 Nov 2026 10:00:00 +0000',
    from: `alice${seq}@partner.example`,
    to: [`bob${seq}@corp-it.example`],
    body: 'Synthetic dedupe body.',
    attachment: Buffer.from(`attachment ${run} ${seq}`),
    ...over,
  };
}

async function intend(...messages: SeededMessage[]) {
  await upsertIntents(
    fx.prisma,
    messages.map((m) => ({
      organizationId: m.organizationId,
      messageId: m.id,
      receivedAt: m.receivedAt,
      direction: 'inbound' as const,
      journal: true,
      policy: false,
      policyRuleRef: null,
      settingsGeneration: 1n,
      nextCheckAt: new Date(0),
    })),
  );
}

async function capture(m: SeededMessage, harnessOf: Harness = h) {
  await intend(m);
  await drainCapture(harnessOf, fx, clock.now);
}

const recordOf = (m: SeededMessage) =>
  fx.prisma.emailArchive.findUnique({
    where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
  });

const intentOf = (m: SeededMessage) =>
  fx.prisma.archiveCaptureIntent.findUnique({
    where: { messageId_receivedAt: { messageId: m.id, receivedAt: m.receivedAt } },
  });

const dedupeRows = (archiveId: bigint) =>
  fx.prisma.archiveDedupeKey.findMany({ where: { archiveId } });

async function metric(name: string, labels: Record<string, string>, of: Harness = h) {
  const text = await of.metrics.metrics();
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`)) continue;
    if (Object.entries(labels).every(([k, v]) => line.includes(`${k}="${v}"`))) {
      total += Number(line.split(' ').pop());
    }
  }
  return total;
}

/** The decrypted journal object of a merged copy (record DEK, the copy's own subject). */
async function mergedJournal(recordRow: NonNullable<Awaited<ReturnType<typeof recordOf>>>, i = 0) {
  const objects = archiveRecordObjectsSchema.parse(recordRow.objects);
  const copy = objects.merged![i]!;
  const { dek } = await h.comps.objects.dek(recordRow);
  const sealed = await h.comps.storage.getBuffer(
    fx.archiveBucket,
    copy.journal.key,
    copy.journal.versionId,
  );
  const plain = decryptArchiveObject(sealed, {
    dek,
    kind: 'journal',
    organizationId: recordRow.organizationId,
    subjectId: copy.messageId,
  });
  return archiveJournalSchema.parse(JSON.parse(plain.toString('utf8')));
}

async function indexed(publicId: string): Promise<Record<string, unknown> | null> {
  const res = await fx.search.request<{
    hits: { hits: Array<{ _source: Record<string, unknown> }> };
  }>('POST', `/${fx.prefix}-*/_search`, {
    body: { query: { ids: { values: [publicId] } } },
    allowStatuses: [404],
  });
  return res.body?.hits?.hits?.[0]?._source ?? null;
}

beforeAll(async () => {
  h = await harness(fx, {
    clock,
    config: testConfig(fx, {
      ARCHIVE_TEST_DAY_SECONDS: String(DAY_S),
      ARCHIVE_HOLD_EXTENSION_DAYS: '1',
    }),
  });
  // Initialize the journal sweep cursor at "now" before anything is seeded.
  await h.comps.capture!.journal.runOnce();
}, 180_000);

afterAll(async () => {
  await h?.close();
  const { lockedObjects } = await fx.cleanup();
  expect(lockedObjects).toBe(0);
}, 180_000);

describe('intake capture (D6)', () => {
  it('the journal sweep and the executor archive an intake message: sources, intake block, fields, NULL directions', async () => {
    const org = await fx.organization('intake');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const m = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      bcc: [`carol-${run}@corp-it.example`],
    });
    const sweep = await h.comps.capture!.journal.runOnce();
    expect(sweep.intents).toBeGreaterThanOrEqual(1);
    await drainCapture(h, fx, clock.now);
    const record = await recordOf(m);
    expect(record).toMatchObject({
      category: 'delivered',
      messageState: 'journaled',
      sourceGateway: false,
      sourceJournalIntake: true,
      intakeSourceId: source.id,
      mergedCount: 0,
      finalVerdict: null,
      recipientCount: 2,
    });
    const parties = archivePartiesSchema.parse(record!.parties);
    expect(parties.recipients.map((r) => [r.address, r.field, r.direction, r.status])).toEqual([
      [spec.to[0], 'to', null, 'journaled'],
      [`carol-${run}@corp-it.example`, 'bcc', null, 'journaled'],
    ]);
    const journal = await h.comps.objects.journal(record!);
    expect(journal.intake).toMatchObject({
      sourceId: source.publicId,
      kind: 'microsoft_365_journal',
      format: 'journal_report',
      envelopeMismatch: false,
      proof: { result: 'pass' },
    });
    expect(journal.intake!.envelope.recipients.map((r) => r.field)).toEqual(['to', 'bcc']);
    expect(journal.envelope.recipients[1]).toMatchObject({ field: 'bcc', direction: null });
    // The decrypted original is the stored intake EML; its dedupe row names the record.
    expect((await readAll(await h.comps.objects.emlStream(record!))).equals(m.eml)).toBe(true);
    expect(await dedupeRows(record!.id)).toHaveLength(1);
    await drainIndex(h, fx);
    expect((await indexed(m.publicId))?.ingest_sources).toEqual(['journal_intake']);
  });
});

describe('API-mode copies (step API-1 D7.6)', () => {
  it('a mailbox API copy gets no intent from the journal sweep and a direct intent is skipped (api_copy)', async () => {
    const org = await fx.organization('apicopy');
    const swept = await fx.copy(org.id, { ...message(), ingestSource: 'mailbox_api' });
    // A journal copy of the same organization in the same sweep pass is still captured.
    const source = await fx.intakeSource(org.id);
    const journal = await fx.copy(org.id, {
      ...message(),
      ingestSource: 'journal_intake',
      sourceId: source.id,
    });
    await h.comps.capture!.journal.runOnce();
    expect(await intentOf(swept)).toBeNull();
    expect(await intentOf(journal)).not.toBeNull();
    await drainCapture(h, fx, clock.now);
    expect(await recordOf(swept)).toBeNull();
    expect(await recordOf(journal)).toMatchObject({ sourceJournalIntake: true });

    // Defence in depth: an intent created by any other path is skipped by decideCapture.
    const direct = await fx.copy(org.id, { ...message(), ingestSource: 'mailbox_api' });
    const before = await metric('archive_capture_skipped_total', { reason: 'api_copy' });
    await capture(direct);
    expect(await intentOf(direct)).toMatchObject({ status: 'skipped', skipReason: 'api_copy' });
    expect(await recordOf(direct)).toBeNull();
    expect(await metric('archive_capture_skipped_total', { reason: 'api_copy' })).toBe(before + 1);
  });

  it('journal copies of an API-only organization (journaling off) are never captured', async () => {
    // Archiving entitled but not enabled (API mode entitles the intake, step API-1 D6).
    const off = await fx.organization('apionly-off', { enabled: false, journalEnabledAt: null });
    const offSource = await fx.intakeSource(off.id);
    const offCopy = await fx.copy(off.id, {
      ...message(),
      ingestSource: 'journal_intake',
      sourceId: offSource.id,
      scanRequested: true,
    });
    // Archiving not entitled at all (an API-only plan).
    const none = await fx.organization('apionly-none', {
      entitled: false,
      enabled: false,
      journalEnabledAt: null,
    });
    const noneSource = await fx.intakeSource(none.id);
    const noneCopy = await fx.copy(none.id, {
      ...message(),
      ingestSource: 'journal_intake',
      sourceId: noneSource.id,
      scanRequested: true,
    });
    await h.comps.capture!.journal.runOnce();
    expect(await intentOf(offCopy)).toBeNull();
    expect(await intentOf(noneCopy)).toBeNull();
    // An intent from any other path is skipped by the organization gates.
    await capture(offCopy);
    await capture(noneCopy);
    expect(await intentOf(offCopy)).toMatchObject({
      status: 'skipped',
      skipReason: 'archiving_disabled',
    });
    expect(await intentOf(noneCopy)).toMatchObject({
      status: 'skipped',
      skipReason: 'not_entitled',
    });
    expect(await recordOf(offCopy)).toBeNull();
    expect(await recordOf(noneCopy)).toBeNull();
  });
});

describe('cross-source dedupe (D7, ADR-0088)', () => {
  it('gateway first, same body: the journal copy merges without content (BCC added, one record)', async () => {
    const org = await fx.organization('gw-first');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const g = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'gateway',
      extraHeaders: ['Received: from mx.partner.example by gateway.test'],
    });
    await capture(g);
    const i = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      bcc: [`carol-${run}-gw@corp-it.example`],
      extraHeaders: ['X-MS-Exchange-Organization-Journal: 1'],
    });
    const mergedBefore = await metric('archive_dedupe_total', { result: 'merged' });
    await capture(i);
    expect(await recordOf(i)).toBeNull();
    const record = await recordOf(g);
    expect(record).toMatchObject({
      sourceGateway: true,
      sourceJournalIntake: true,
      intakeSourceId: source.id,
      mergedCount: 1,
      finalVerdict: 'clean',
      messageState: 'delivered',
      recipientCount: 2,
    });
    const parties = archivePartiesSchema.parse(record!.parties);
    expect(parties.recipients).toEqual([
      expect.objectContaining({
        address: spec.to[0],
        status: 'delivered',
        sources: ['gateway', 'journal_intake'],
      }),
      expect.objectContaining({
        address: `carol-${run}-gw@corp-it.example`,
        field: 'bcc',
        sources: ['journal_intake'],
      }),
    ]);
    const objects = archiveRecordObjectsSchema.parse(record!.objects);
    expect(objects.merged).toHaveLength(1);
    expect(objects.merged![0]).toMatchObject({
      messageId: i.publicId,
      source: 'journal_intake',
      eml: null,
    });
    const journal = await mergedJournal(record!);
    expect(journal.mergedFrom).toMatchObject({
      recordMessageId: g.publicId,
      source: 'journal_intake',
      contentVariant: false,
    });
    expect(journal.intake?.sourceId).toBe(source.publicId);
    const sources = await fx.prisma.archiveRecordSource.findMany({
      where: { archiveId: record!.id },
    });
    expect(sources).toHaveLength(1);
    expect(sources[0]).toMatchObject({
      messageId: i.id,
      messagePublicId: i.publicId,
      source: 'journal_intake',
      contentVariant: false,
      emlSha256: i.emlSha256,
      recipientsAdded: 1,
    });
    expect(await intentOf(i)).toMatchObject({
      status: 'captured_open',
      merged: true,
      archiveId: record!.id,
      archiveReceivedAt: g.receivedAt,
    });
    expect(await dedupeRows(record!.id)).toHaveLength(1);
    expect(await metric('archive_dedupe_total', { result: 'merged' })).toBe(mergedBefore + 1);
    await drainIndex(h, fx);
    const doc = await indexed(g.publicId);
    expect(doc?.ingest_sources).toEqual(['gateway', 'journal_intake']);
    expect(await indexed(i.publicId)).toBeNull();
  });

  it('intake first, different body: the gateway copy is a content variant and authoritative for the outcome', async () => {
    const org = await fx.organization('jr-first');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const i = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
    });
    await capture(i);
    const g = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'gateway',
      body: `${spec.body}\r\n-- External sender banner added by the gateway`,
      finalVerdict: 'spam',
      riskScore: 420,
    });
    await capture(g);
    expect(await recordOf(g)).toBeNull();
    const record = await recordOf(i);
    expect(record).toMatchObject({
      sourceGateway: true,
      sourceJournalIntake: true,
      mergedCount: 1,
      messageState: 'delivered',
      finalVerdict: 'spam',
      riskScore: 420,
    });
    const objects = archiveRecordObjectsSchema.parse(record!.objects);
    const variant = objects.merged![0]!.eml!;
    expect(variant).not.toBeNull();
    // The variant decrypts under the record's DEK and the merged message's subject.
    const { dek } = await h.comps.objects.dek(record!);
    const sealed = await h.comps.storage.getStream(
      fx.archiveBucket,
      variant.key,
      variant.versionId,
    );
    const plain = await readAll(
      sealed.pipe(
        createArchiveDecryptStream({
          dek,
          kind: 'eml',
          organizationId: org.id,
          subjectId: g.publicId,
          expectedSha256: g.emlSha256,
        }),
      ),
    );
    expect(sha(plain)).toBe(g.emlSha256);
    const rows = await dedupeRows(record!.id);
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.bodySha256)).size).toBe(2);
    expect(
      await fx.prisma.archiveRecordSource.findFirst({ where: { messageId: g.id } }),
    ).toMatchObject({ source: 'gateway', contentVariant: true });
    // A merged gateway copy refreshes the outcome (A7); the intake primary never overwrites it.
    await fx.prisma.emailMessage.update({
      where: { id_receivedAt: { id: g.id, receivedAt: g.receivedAt } },
      data: { finalVerdict: 'phishing', riskScore: 900 },
    });
    await fx.prisma.archiveCaptureIntent.updateMany({
      where: { messageId: g.id },
      data: { nextCheckAt: new Date(0) },
    });
    await drainCapture(h, fx, clock.now);
    let refreshed = await recordOf(i);
    expect(refreshed).toMatchObject({ finalVerdict: 'phishing', riskScore: 900, malicious: true });
    await fx.prisma.archiveCaptureIntent.updateMany({
      where: { messageId: i.id },
      data: { nextCheckAt: new Date(0) },
    });
    await drainCapture(h, fx, clock.now);
    refreshed = await recordOf(i);
    expect(refreshed).toMatchObject({
      finalVerdict: 'phishing',
      riskScore: 900,
      malicious: true,
      messageState: 'delivered',
      mergedCount: 1,
    });
    expect(archivePartiesSchema.parse(refreshed!.parties).recipients[0]).toMatchObject({
      status: 'delivered',
      sources: ['gateway', 'journal_intake'],
    });
  });

  it('a forged resend through the gateway never merges into a journaled record (direction, inbound order)', async () => {
    const org = await fx.organization('forged');
    const source = await fx.intakeSource(org.id);
    // (a) An organization user's outbound message, journaled; an external recipient resends it
    // with identical headers and another body through the gateway's inbound path.
    const sent = message({
      from: `user-${run}@corp-it.example`,
      to: [`partner-${run}@partner.example`],
    });
    const i = await fx.copy(org.id, {
      ...sent,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      direction: 'outbound',
    });
    await capture(i);
    const mismatchBefore = await metric('archive_dedupe_total', { result: 'direction_mismatch' });
    const forged = await fx.copy(org.id, {
      ...sent,
      ingestSource: 'gateway',
      direction: 'inbound',
      body: 'Forged body: please pay the new account.',
      finalVerdict: 'clean',
      riskScore: 10,
    });
    await capture(forged);
    expect(await recordOf(forged)).toMatchObject({
      sourceGateway: true,
      sourceJournalIntake: false,
      mergedCount: 0,
    });
    expect(await recordOf(i)).toMatchObject({
      mergedCount: 0,
      sourceGateway: false,
      finalVerdict: null,
      riskScore: null,
    });
    expect(await metric('archive_dedupe_total', { result: 'direction_mismatch' })).toBe(
      mismatchBefore + 1,
    );
    expect(await fx.prisma.archiveRecordSource.count({ where: { messageId: forged.id } })).toBe(0);

    // (b) An inbound message journaled an hour ago (it never passed the gateway): a gateway copy
    // received later is a resend, not the same delivery.
    const inbound = message();
    const early = await fx.copy(org.id, {
      ...inbound,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      ageSeconds: 3_600,
    });
    await capture(early);
    const late = await fx.copy(org.id, {
      ...inbound,
      ingestSource: 'gateway',
      body: 'Forged body sent later.',
      ageSeconds: 60,
    });
    await capture(late);
    expect(await recordOf(late)).toMatchObject({ mergedCount: 0, sourceJournalIntake: false });
    expect(await recordOf(early)).toMatchObject({ mergedCount: 0, sourceGateway: false });
  });

  it('intake↔intake merges recipients; the variant limit and the merged-copies limit start a separate record', async () => {
    const org = await fx.organization('limits');
    const source = await fx.intakeSource(org.id);
    const small = await harness(fx, {
      clock,
      config: testConfig(fx, {
        ARCHIVE_MAX_CONTENT_VARIANTS: '1',
        ARCHIVE_MAX_MERGED_COPIES: '3',
      }),
    });
    const tiny = await harness(fx, {
      clock,
      config: testConfig(fx, { ARCHIVE_MAX_CONTENT_VARIANTS: '0', ARCHIVE_MAX_MERGED_COPIES: '1' }),
    });
    try {
      const spec = message();
      const intake = (over: Partial<CopySpec>, base = spec) =>
        fx.copy(org.id, { ...base, ingestSource: 'journal_intake', sourceId: source.id, ...over });
      const first = await intake({});
      await capture(first, small);
      // intake↔intake, same body: merged; the second report names another BCC custodian.
      const second = await intake({ bcc: [`dave-${run}@corp-it.example`] });
      await capture(second, small);
      // A differing body: the one allowed variant.
      const third = await intake({ body: `${spec.body} (edited)` });
      await capture(third, small);
      // Another differing body: variant limit → a record of its own.
      const fourth = await intake({ body: `${spec.body} (edited again)` });
      await capture(fourth, small);

      const record = await recordOf(first);
      expect(record).toMatchObject({ mergedCount: 2, sourceGateway: false, recipientCount: 2 });
      const objects = archiveRecordObjectsSchema.parse(record!.objects);
      expect(objects.merged!.map((c) => c.eml !== null)).toEqual([false, true]);
      expect(archivePartiesSchema.parse(record!.parties).recipients.map((r) => r.address)).toEqual([
        spec.to[0],
        `dave-${run}@corp-it.example`,
      ]);
      expect(await recordOf(second)).toBeNull();
      expect(await recordOf(third)).toBeNull();
      expect(await recordOf(fourth)).toMatchObject({ mergedCount: 0, sourceJournalIntake: true });
      expect(await metric('archive_dedupe_total', { result: 'variant_limit' }, small)).toBe(1);

      // Merged-copies limit (ARCHIVE_MAX_MERGED_COPIES = 1): the third copy is its own record.
      const other = message();
      const a = await intake({}, other);
      await capture(a, tiny);
      const b = await intake({}, other);
      await capture(b, tiny);
      const c = await intake({}, other);
      await capture(c, tiny);
      expect(await recordOf(a)).toMatchObject({ mergedCount: 1 });
      expect(await recordOf(b)).toBeNull();
      expect(await recordOf(c)).toMatchObject({ mergedCount: 0 });
      expect(await metric('archive_dedupe_total', { result: 'merged_limit' }, tiny)).toBe(1);
    } finally {
      await small.close();
      await tiny.close();
    }
  });

  it('concurrent captures of one key by two schedulers end in one record and one merge', async () => {
    const org = await fx.organization('race');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const a = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
    });
    const b = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      bcc: [`erin-${run}@corp-it.example`],
    });
    const other = await harness(fx, { clock });
    try {
      await intend(a, b);
      const [one] = await h.comps.capture!.scheduler.claim(1);
      const [two] = await other.comps.capture!.scheduler.claim(1);
      expect(one).toBeDefined();
      expect(two).toBeDefined();
      await Promise.all([
        h.comps.capture!.scheduler.process(one!),
        other.comps.capture!.scheduler.process(two!),
      ]);
      // A loser (deadlock or changed candidate) is retried as a merge.
      for (let i = 0; i < 20; i += 1) {
        const open = await fx.prisma.archiveCaptureIntent.count({
          where: { organizationId: org.id, status: 'captured_open' },
        });
        if (open === 2) break;
        clock.advance(5_000);
        await drainCapture(h, fx, clock.now);
      }
    } finally {
      await other.close();
    }
    const records = await fx.prisma.emailArchive.findMany({ where: { organizationId: org.id } });
    expect(records).toHaveLength(1);
    expect(records[0]!.mergedCount).toBe(1);
    expect(records[0]!.recipientCount).toBe(2);
    expect(await fx.prisma.archiveRecordSource.count({ where: { organizationId: org.id } })).toBe(
      1,
    );
    expect(
      await fx.prisma.archiveCaptureIntent.count({
        where: { organizationId: org.id, status: 'captured_open' },
      }),
    ).toBe(2);
  });
});

describe('lifecycle of merged records (D7, ADR-0067 amended)', () => {
  it('a BCC custodian hold blocks disposal; released, the group is disposed (variants, sources, dedupe rows)', async () => {
    const org = await fx.organization('dispose', { retentionDays: 1 });
    const source = await fx.intakeSource(org.id);
    const custodian = `frank-${run}@corp-it.example`;
    const spec = message();
    const g = await fx.copy(org.id, { ...spec, ingestSource: 'gateway' });
    await capture(g);
    const i = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      body: `${spec.body} [journal copy]`,
      bcc: [custodian],
    });
    await capture(i);
    const record = (await recordOf(g))!;
    expect(record.mergedCount).toBe(1);
    const mergedPrefix = archivePrefixOf({
      organizationId: org.id,
      receivedAt: i.receivedAt,
      messagePublicId: i.publicId,
    });
    const recordPrefix = archivePrefixOf({
      organizationId: org.id,
      receivedAt: g.receivedAt,
      messagePublicId: g.publicId,
    });
    expect(await fx.countVersions(fx.archiveBucket, mergedPrefix)).toBe(2); // journal + variant
    const hold = await fx.prisma.archiveLegalHold.create({
      data: {
        organizationId: org.id,
        name: 'bcc custodian',
        reason: 'integration',
        criteria: { custodians: [custodian.toUpperCase()] },
        criteriaVersion: 'archive-hold/1',
        status: 'active',
      },
    });
    await sleep(DAY_S * 1000 + 500);
    expect(await h.comps.lifecycle!.expiry.runOrganization(org.id)).toMatchObject({
      held: 1,
      disposed: 0,
    });
    await fx.prisma.archiveLegalHold.update({
      where: { id: hold.id },
      data: { status: 'released' },
    });
    await sleep(DAY_S * 1000 + 500);
    expect((await h.comps.lifecycle!.expiry.runOrganization(org.id)).disposed).toBe(1);
    const disposal = await fx.prisma.archiveDisposal.findFirstOrThrow({
      where: { archiveRecordId: record.id },
    });
    const listed = (disposal.objects as { versions: Array<{ key: string }> }).versions.map(
      (v) => v.key,
    );
    expect(listed.filter((k) => k.startsWith(mergedPrefix))).toHaveLength(2);
    await drainIndex(h, fx);
    for (let n = 0; n < 5; n += 1) {
      await fx.prisma.archiveDisposal.updateMany({
        where: { id: disposal.id },
        data: { nextAttemptAt: new Date(0) },
      });
      await h.comps.lifecycle!.disposal.runOnce();
      const d = await fx.prisma.archiveDisposal.findFirstOrThrow({ where: { id: disposal.id } });
      if (d.state === 'completed') break;
      await drainIndex(h, fx);
    }
    expect(
      await fx.prisma.archiveDisposal.findFirstOrThrow({ where: { archiveRecordId: record.id } }),
    ).toMatchObject({ state: 'completed' });
    expect(await fx.countVersions(fx.archiveBucket, recordPrefix)).toBe(0);
    expect(await fx.countVersions(fx.archiveBucket, mergedPrefix)).toBe(0);
    expect(await fx.countVersions(fx.replicaBucket, mergedPrefix)).toBe(0);
    expect(await fx.prisma.emailArchive.count({ where: { id: record.id } })).toBe(0);
    expect(await fx.prisma.archiveRecordSource.count({ where: { archiveId: record.id } })).toBe(0);
    expect(await fx.prisma.archiveDedupeKey.count({ where: { archiveId: record.id } })).toBe(0);
  });

  it('the orphan reconciliation keeps merged objects and the lifecycle prunes old dedupe rows and counters', async () => {
    const org = await fx.organization('prune');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const g = await fx.copy(org.id, { ...spec, ingestSource: 'gateway' });
    await capture(g);
    const i = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      body: `${spec.body} [variant]`,
    });
    await capture(i);
    const mergedPrefix = archivePrefixOf({
      organizationId: org.id,
      receivedAt: i.receivedAt,
      messagePublicId: i.publicId,
    });
    // Two days later the merged copy's objects are referenced through archive_record_sources.
    const orphans = h.comps.lifecycle!.orphans;
    const report = { days: 0, scanned: 0, deleted: 0, locked: 0, failed: 0 };
    clock.advance(2 * 86_400_000);
    try {
      await orphans.scanDay(org.id, i.receivedAt.toISOString().slice(0, 10), report);
    } finally {
      clock.advance(-2 * 86_400_000);
    }
    expect(report.deleted).toBe(0);
    expect(await fx.countVersions(fx.archiveBucket, mergedPrefix)).toBe(2);

    const record = (await recordOf(g))!;
    const old = new Date(Date.now() - 100 * 3_600_000);
    await fx.prisma.archiveDedupeKey.updateMany({
      where: { archiveId: record.id },
      data: { createdAt: old },
    });
    await fx.prisma.journalIntakeCounter.createMany({
      data: [
        {
          organizationId: org.id,
          sourceId: source.id,
          day: new Date(Date.now() - 401 * 86_400_000),
          accepted: 5,
        },
        { organizationId: org.id, sourceId: source.id, day: new Date(), accepted: 7 },
      ],
    });
    const pruned = await h.comps.lifecycle!.pruner.runOnce();
    expect(pruned.dedupeKeys).toBeGreaterThanOrEqual(2);
    expect(pruned.intakeCounters).toBeGreaterThanOrEqual(1);
    expect(await fx.prisma.archiveDedupeKey.count({ where: { archiveId: record.id } })).toBe(0);
    expect(
      (await fx.prisma.journalIntakeCounter.findMany({ where: { sourceId: source.id } })).map(
        (c) => c.accepted,
      ),
    ).toEqual([7]);
    // Outside the window a new copy of the same key is a record of its own.
    const late = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
    });
    await capture(late);
    expect(await recordOf(late)).toMatchObject({ mergedCount: 0 });
  });
});

describe('index mapping revision (D7 search)', () => {
  it('ensureTemplate adds ingest_sources to an existing index of the version', async () => {
    const index = `${fx.prefix}-v1-2001`;
    await fx.search.request('PUT', `/${index}`, {
      body: { mappings: { dynamic: 'strict', properties: { org_id: { type: 'keyword' } } } },
    });
    const manager = h.comps.index!.manager;
    manager.reset();
    await manager.ensureTemplate();
    const res = await fx.search.request<
      Record<string, { mappings: { properties: Record<string, unknown> } }>
    >('GET', `/${index}/_mapping`);
    expect(res.body?.[index]?.mappings.properties.ingest_sources).toEqual({ type: 'keyword' });
  });
});

describe('eDiscovery export of a merged record (D7)', () => {
  it('exports the variant as an additional file and the merged parties in the signed merged.json', async () => {
    const org = await fx.organization('export');
    const source = await fx.intakeSource(org.id);
    const spec = message();
    const g = await fx.copy(org.id, { ...spec, ingestSource: 'gateway' });
    await capture(g);
    const i = await fx.copy(org.id, {
      ...spec,
      ingestSource: 'journal_intake',
      sourceId: source.id,
      body: `${spec.body} [journal]`,
      bcc: [`grace-${run}@corp-it.example`],
    });
    await capture(i);
    await drainIndex(h, fx);
    const kase = await fx.prisma.ediscoveryCase.create({
      data: { organizationId: org.id, name: 'Merged matter' },
    });
    const criteria = { from: utcDay(new Date(Date.now() - 86_400_000)), to: utcDay(new Date()) };
    const search = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria,
        criteriaSha256: canonicalSha256(criteria),
      },
    });
    await h.comps.ediscovery!.searches.runOnce();
    expect(
      await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: search.id } }),
    ).toMatchObject({ status: 'completed', hitCount: 1 });
    const exp = await fx.prisma.ediscoveryExport.create({
      data: {
        caseId: kase.id,
        searchId: search.id,
        organizationId: org.id,
        reviewTags: ['untagged'],
        acknowledgeMalicious: false,
      },
    });
    await h.comps.ediscovery!.exports.runOnce();
    const row = await fx.prisma.ediscoveryExport.findUniqueOrThrow({ where: { id: exp.id } });
    expect(row).toMatchObject({ status: 'completed', itemCount: 1 });
    const sealed = await h.comps.storage.getBuffer(
      fx.archiveBucket,
      row.objectKey!,
      row.objectVersionId,
    );
    const tenantKey = await h.comps.keys.version(org.id, row.keyVersion!);
    const dek = unwrapExportKey(tenantKey.key, row.wrappedDek!, {
      organizationId: org.id,
      exportPublicId: exp.publicId,
      keyVersion: row.keyVersion!,
    });
    const entries = readZip(
      decryptArchiveObject(sealed, {
        dek,
        kind: 'export',
        organizationId: org.id,
        subjectId: exp.publicId,
      }),
    );
    const publicKey = parseExportSigningPublicKey(
      exportSigningPublicKeyOf(parseExportSigningPrivateKey(h.config.ARCHIVE_EXPORT_SIGNING_KEY)),
    );
    const manifest = verifySignedExportManifest(
      entries.get('manifest.json')!,
      entries.get('manifest.sig')!.toString('utf8'),
      publicKey,
    )!;
    const item = manifest.items[0]!;
    expect(entries.get(item.path)!.equals(g.eml)).toBe(true);
    const mergedBytes = entries.get('merged.json')!;
    expect(
      verifyManifestSignature(mergedBytes, entries.get('merged.sig')!.toString('utf8'), publicKey),
    ).toBe(true);
    const merged = JSON.parse(mergedBytes.toString('utf8')) as {
      version: string;
      records: Array<{
        messageId: string;
        sources: string[];
        parties: { recipients: Array<{ address: string; field?: string }> };
        mergedCopies: Array<{ messageId: string; path: string | null; sha256: string }>;
      }>;
      counts: { variants: number };
    };
    expect(merged.version).toBe('archive-export-merged/1');
    expect(merged.counts.variants).toBe(1);
    const rec = merged.records[0]!;
    expect(rec).toMatchObject({ messageId: g.publicId, sources: ['gateway', 'journal_intake'] });
    expect(rec.parties.recipients).toContainEqual(
      expect.objectContaining({ address: `grace-${run}@corp-it.example`, field: 'bcc' }),
    );
    const copy = rec.mergedCopies[0]!;
    expect(copy).toMatchObject({ messageId: i.publicId, sha256: i.emlSha256 });
    expect(copy.path).toBe(item.path.replace(/\.eml$/, '.variant-1.eml'));
    const variantFile = entries.get(copy.path!)!;
    expect(variantFile.equals(i.eml)).toBe(true);
    expect(sha(variantFile)).toBe(i.emlSha256);
  });
});

describe('intake health job (D9)', () => {
  const sourceOf = (id: bigint) =>
    fx.prisma.journalIntakeSource.findUniqueOrThrow({ where: { id } });
  const outbox = (organizationId: bigint) =>
    fx.prisma.messageOutbox.findMany({
      where: { organizationId, eventType: EventTypes.NotificationAlertRequested },
      orderBy: { id: 'asc' },
    });
  const audits = (resourceId: string) =>
    fx.prisma.auditLog.findMany({
      where: { action: 'journal_intake.health_changed', resourceId },
      orderBy: { id: 'asc' },
    });

  it('silent: audit row and one alert; recovery; silent again within the interval is throttled; failing is high', async () => {
    const org = await fx.organization('health');
    const quiet = await fx.intakeSource(org.id, {
      silenceAlertMinutes: 1,
      lastAcceptedAt: new Date(Date.now() - 10 * 60_000),
      healthStatus: 'healthy',
    });
    const job = h.comps.capture!.intakeHealth;
    await job.runOnce();
    expect(await sourceOf(quiet.id)).toMatchObject({ healthStatus: 'silent' });
    expect((await sourceOf(quiet.id)).healthAlertedAt).not.toBeNull();
    const [audit] = await audits(quiet.publicId);
    expect(audit).toMatchObject({
      organizationId: org.id,
      actorType: 'system',
      resourceType: 'journal_intake_source',
    });
    expect(audit!.metadata).toMatchObject({ from: 'healthy', to: 'silent', reason: 'silent' });
    let alerts = await outbox(org.id);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      aggregateType: 'organization',
      aggregateId: org.id.toString(),
    });
    const payload = notificationAlertRequestedV1.parse(alerts[0]!.payload);
    expect(payload).toMatchObject({
      kind: 'journal_intake_silent',
      severity: 'medium',
      refs: { intakeSourceId: quiet.publicId },
    });
    expect(JSON.stringify(alerts[0]!.payload)).not.toContain('@');
    expect(
      await fx.prisma.notificationAlertWindow.count({
        where: { organizationId: org.id, kind: 'journal_intake_silent', scopeKey: quiet.publicId },
      }),
    ).toBe(1);
    // No change → nothing written.
    await job.runOnce();
    expect(await audits(quiet.publicId)).toHaveLength(1);
    // Recovery (healthy, no alert), then silent again inside the 24 h interval (throttled).
    await fx.prisma.journalIntakeSource.update({
      where: { id: quiet.id },
      data: { lastAcceptedAt: new Date() },
    });
    await job.runOnce();
    expect(await sourceOf(quiet.id)).toMatchObject({ healthStatus: 'healthy' });
    await fx.prisma.journalIntakeSource.update({
      where: { id: quiet.id },
      data: { lastAcceptedAt: new Date(Date.now() - 10 * 60_000) },
    });
    const throttledBefore = await metric('archive_intake_alerts_total', { result: 'throttled' });
    await job.runOnce();
    expect(await sourceOf(quiet.id)).toMatchObject({ healthStatus: 'silent' });
    expect(await audits(quiet.publicId)).toHaveLength(3);
    expect(await outbox(org.id)).toHaveLength(1);
    expect(await metric('archive_intake_alerts_total', { result: 'throttled' })).toBe(
      throttledBefore + 1,
    );
    // A Microsoft 365 source without a bound connection is failing (high).
    const broken = await fx.intakeSource(org.id, { kind: 'microsoft_365_journal' });
    await job.runOnce();
    expect(await sourceOf(broken.id)).toMatchObject({ healthStatus: 'failing' });
    alerts = await outbox(org.id);
    expect(alerts).toHaveLength(2);
    expect(notificationAlertRequestedV1.parse(alerts[1]!.payload)).toMatchObject({
      severity: 'high',
      refs: { intakeSourceId: broken.publicId },
    });
    // Paused and never-verified sources: paused / unknown, no alert.
    const paused = await fx.intakeSource(org.id, { status: 'paused', healthStatus: 'healthy' });
    const fresh = await fx.intakeSource(org.id, {
      status: 'pending_verification',
      verifiedAt: null,
      lastAcceptedAt: null,
      healthStatus: 'healthy',
    });
    await job.runOnce();
    expect(await sourceOf(paused.id)).toMatchObject({ healthStatus: 'paused' });
    expect(await sourceOf(fresh.id)).toMatchObject({ healthStatus: 'unknown' });
    expect(await outbox(org.id)).toHaveLength(2);
    expect(await metric('journal_intake_sources', { health: 'failing' })).toBeGreaterThanOrEqual(1);
  });
});
