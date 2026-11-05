import { createHash, randomBytes } from 'node:crypto';
import { uuidv7 } from '@email-gateway/common';
import { messageScannedV1 } from '@email-gateway/event-contracts';
import { normalizeReply, type RspamdEnvelope } from '@email-gateway/rspamd';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eventually } from './support/broker';
import {
  corpusEml,
  loadCorpus,
  ScanBroker,
  ScanFixtures,
  type ScanMessage,
  ScanPipeline,
  trainingClient,
} from './support/scan';

/**
 * Idempotency per (message, round, engine), rescans, and the shared Bayes / fuzzy state
 * changing later scans (step 4.1 S3, S5, S10, S13, S14, §9). Training uses per-run random
 * tokens, so repeated runs stay valid on the shared statfiles and fuzzy storage.
 */
let fx: ScanFixtures;
let broker: ScanBroker;
let pipeline: ScanPipeline;
let org: bigint;
const run = randomBytes(5).toString('hex');
const clean = loadCorpus().find((f) => f.class === 'clean')!;
const training = trainingClient();

const envelope = {
  direction: 'inbound' as const,
  ip: '198.51.100.61',
  helo: 'mail.spam-sender.scan.test',
  hostname: 'mail.spam-sender.scan.test',
  from: 'trainer@spam-sender.scan.test',
  rcpt: ['bob@customer.scan.test'],
};
const rspamdEnvelope: RspamdEnvelope = {
  direction: 'inbound',
  organizationId: 1n,
  clientIp: envelope.ip,
  clientHelo: envelope.helo,
  clientName: envelope.hostname,
  envelopeFrom: envelope.from,
  recipients: envelope.rcpt,
  queueId: 'ITROUNDS',
};

beforeAll(async () => {
  fx = new ScanFixtures();
  org = await fx.organization('rounds');
  broker = await ScanBroker.start();
  pipeline = await ScanPipeline.start(fx, broker);
});

afterAll(async () => {
  await pipeline?.stop();
  await broker?.close();
  await fx?.cleanup();
});

/** Text over a small per-run vocabulary (the OSB tokenizer hashes word pairs). */
function words(vocabulary: string, count: number, seed: number): string {
  const out: string[] = [];
  let x = seed + 1;
  for (let i = 0; i < count; i += 1) {
    x = (x * 1103515245 + 12345) % 2147483648;
    out.push(`${vocabulary}${'abcdefgh'[(x >> 16) % 8]}`);
  }
  return out.join(' ');
}

function eml(tag: string, body: string): Buffer {
  const id = createHash('sha256').update(tag).digest('hex').slice(0, 24);
  return Buffer.from(
    [
      'From: Trainer <trainer@spam-sender.scan.test>',
      'To: bob@customer.scan.test',
      `Subject: note ${id}`,
      'Date: Sun, 01 Nov 2026 10:00:00 +0000',
      `Message-ID: <${id}@spam-sender.scan.test>`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      '',
      body.replace(/(.{1,72})(\s|$)/g, '$1\r\n'),
    ].join('\r\n'),
  );
}

async function directScan(body: Buffer) {
  const result = await training.check({
    body,
    sizeBytes: body.length,
    envelope: rspamdEnvelope,
    logTag: `itrounds-${run}`,
  });
  return normalizeReply(result.reply);
}

async function finalOfRound(message: ScanMessage, round: number) {
  const state = await fx.state(message);
  const scan = state.scans.find((s) => s.lifecycleRound === round)!;
  const final = state.results.find((r) => r.scanId === scan.id && r.isFinal)!;
  const names = (final.evidence as { signals: { name: string }[] }).signals.map((s) => s.name);
  return { state, scan, final, names, score: Number(final.score) };
}

describe('duplicates (S5, S10)', () => {
  it('the same event id twice: one final row, one transition, then a ledger duplicate', async () => {
    const message = await fx.message(org, { eml: corpusEml(clean), envelope: clean.envelope });
    const event = fx.parsed(message);
    expect(await pipeline.deliver(broker, event)).toBe('handled');
    await broker.publish([event]);
    await pipeline.outcome(event.eventId, 2);
    expect(pipeline.outcomesOf(event.eventId)).toEqual(['handled', 'duplicate']);
    const state = await fx.state(message);
    expect(state.results).toHaveLength(1);
    expect(state.history.filter((h) => h.toStatus === 'scanned')).toHaveLength(1);
    expect(state.scanned).toHaveLength(1);
  });

  it('different event ids for the same message at once converge on one result', async () => {
    const message = await fx.message(org, { eml: corpusEml(clean), envelope: clean.envelope });
    const events = [
      fx.parsed(message, uuidv7()),
      fx.parsed(message, uuidv7()),
      fx.parsed(message, uuidv7()),
    ];
    await broker.publish(events);
    for (const e of events) await pipeline.outcome(e.eventId);
    const state = await fx.state(message);
    expect(state.scans).toHaveLength(1);
    expect(state.results.filter((r) => r.isFinal)).toHaveLength(1);
    expect(state.auth).toHaveLength(1);
    expect(state.history.map((h) => h.toStatus)).toEqual(['scanning', 'scanned']);
    expect(state.scanned).toHaveLength(1);
    expect(
      await fx.ledgerRows(
        pipeline.consumerName,
        events.map((e) => e.eventId),
      ),
    ).toBe(3);
  });
});

describe('rescan (S3, S14)', () => {
  it('opens a new round with its own rows and leaves the old round untouched', async () => {
    const message = await fx.message(org, { eml: corpusEml(clean), envelope: clean.envelope });
    await pipeline.deliver(broker, fx.parsed(message));
    const before = await fx.state(message);
    const rescan = await fx.rescan(message);
    expect(await pipeline.deliver(broker, rescan)).toBe('handled');
    const after = await fx.state(message);
    expect(after.message).toMatchObject({ status: 'scanned', lifecycleRound: 1 });
    expect(after.scans.map((s) => [s.lifecycleRound, s.scanKind, s.status])).toEqual([
      [0, 'initial', 'completed'],
      [1, 'rescan', 'completed'],
    ]);
    // Round 0 rows are byte-for-byte the same.
    expect(after.scans[0]).toEqual(before.scans[0]);
    expect(after.results.filter((r) => r.scanId === before.scans[0]!.id)).toEqual(before.results);
    expect(after.auth.filter((a) => a.scanId === before.scans[0]!.id)).toEqual(before.auth);
    expect(after.results).toHaveLength(2);
    expect(after.auth).toHaveLength(2);
    expect(
      after.scanned
        .map((o) => messageScannedV1.parse(o.payload))
        .map((p) => [p.lifecycleRound, p.scanKind]),
    ).toEqual([
      [0, 'initial'],
      [1, 'rescan'],
    ]);
    // A late copy of the round-0 trigger after the rescan is an older round: nothing changes.
    const late = fx.parsed(message);
    expect(await pipeline.deliver(broker, late)).toBe('handled');
    expect((await fx.state(message)).results).toHaveLength(2);
    expect(await pipeline.text()).toMatch(
      /scan_events_skipped_total\{engine="rspamd",reason="older_round"/,
    );
  });
});

describe('shared classifier state changes later scans (S12, S13)', () => {
  it('Bayes: after learning per-run spam, a similar message gets BAYES_SPAM and a higher score', async () => {
    const spamVocabulary = (i: number) => `zw${run}q${i}x`;
    const hamVocabulary = (i: number) => `kw${run}v${i}x`;
    const mix = (vocabulary: (i: number) => string, seed: number) =>
      Array.from({ length: 10 }, (_, i) => words(vocabulary(i), 12, seed + i)).join(' ');
    const probe = eml(`probe-${run}`, mix(spamVocabulary, 500));
    const message = await fx.message(org, { eml: probe, envelope });
    await pipeline.deliver(broker, fx.parsed(message));
    const round0 = await finalOfRound(message, 0);
    expect(round0.names).not.toContain('BAYES_SPAM');

    for (let i = 0; i < 10; i += 1) {
      const spam = eml(`spam-${run}-${i}`, words(spamVocabulary(i), 80, i));
      expect(await training.learn('spam', spam, spam.length)).toBe('learned');
      const ham = eml(`ham-${run}-${i}`, words(hamVocabulary(i), 80, i + 100));
      expect(await training.learn('ham', ham, ham.length)).toBe('learned');
    }
    await pipeline.deliver(broker, await fx.rescan(message));
    const round1 = await finalOfRound(message, 1);
    expect(round1.names).toContain('BAYES_SPAM');
    expect(round1.final.reasonCodes as string[]).toContain('bayes.spam');
    expect(round1.score).toBeGreaterThan(round0.score);
  });

  it('fuzzy: an added spam hash maps to spam (fuzzy.spam); after delete it is gone', async () => {
    const body = eml(`fuzzy-${run}`, words(`fw${run}f`, 160, 11));
    const message = await fx.message(org, { eml: body, envelope });
    await pipeline.deliver(broker, fx.parsed(message));
    expect((await finalOfRound(message, 0)).names).not.toContain('EG_FUZZY_SPAM');

    await training.fuzzy('add', 11, 10, body, body.length);
    await eventually(
      async () => (await directScan(body)).symbols.some((s) => s.name === 'EG_FUZZY_SPAM'),
      30_000,
      'EG_FUZZY_SPAM after fuzzyadd',
      1_000,
    );
    await pipeline.deliver(broker, await fx.rescan(message));
    const added = await finalOfRound(message, 1);
    expect(added.names).toContain('EG_FUZZY_SPAM');
    expect(added.final.reasonCodes as string[]).toContain('fuzzy.spam');
    expect(added.scan.scanVerdict).toBe('spam');

    await training.fuzzy('delete', 11, 10, body, body.length);
    await eventually(
      async () => !(await directScan(body)).symbols.some((s) => s.name === 'EG_FUZZY_SPAM'),
      30_000,
      'EG_FUZZY_SPAM gone after fuzzydel',
      1_000,
    );
    await pipeline.deliver(broker, await fx.rescan(message));
    const deleted = await finalOfRound(message, 2);
    expect(deleted.names).not.toContain('EG_FUZZY_SPAM');
    expect(deleted.final.reasonCodes as string[]).not.toContain('fuzzy.spam');
  });
});
