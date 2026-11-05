import { randomBytes } from 'node:crypto';
import { messageScannedV1 } from '@email-gateway/event-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { eventually } from './support/broker';
import {
  type CorpusFixture,
  corpusEml,
  loadCorpus,
  rspamdRedis,
  ScanBroker,
  ScanFixtures,
  ScanPipeline,
  type ScanState,
} from './support/scan';

/**
 * The scan stage end to end against the real Rspamd (test RBL profile, dns-sink `scan.test`
 * zones), MySQL writer, MinIO, Redis and RabbitMQ (throwaway vhost): every fixture of the scan
 * corpus (tests/fixtures/scan-corpus/manifest.json, WP2) is uploaded under its organization's
 * prefix, committed as smtp-adapter commits it (`persisted`), published as `parsed.v1` exactly as
 * the event-relay publishes it, and must end with the manifest's verdict and reason codes in
 * `scan_engine_results` / `email_scans`, its auth row, a `scanned.v1` outbox row and the
 * lifecycle `persisted → scanning → scanned` (step 4.1 §9).
 */
let fx: ScanFixtures;
let broker: ScanBroker;
let pipeline: ScanPipeline;
let org: bigint;
const latencies: { file: string; endToEndMs: number; engineMs: number }[] = [];

beforeAll(async () => {
  fx = new ScanFixtures();
  org = await fx.organization('corpus');
  broker = await ScanBroker.start();
  pipeline = await ScanPipeline.start(fx, broker);
});

afterAll(async () => {
  await pipeline?.stop();
  await broker?.close();
  await fx?.cleanup();
  if (latencies.length > 0) {
    const sorted = [...latencies].sort((a, b) => a.endToEndMs - b.endToEndMs);
    const p = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))]!;
    process.stderr.write(
      `[scan-corpus] ${String(latencies.length)} fixtures: end-to-end p50 ${String(p(0.5).endToEndMs)} ms, ` +
        `max ${String(sorted.at(-1)!.endToEndMs)} ms; engine call ${latencies
          .map((l) => `${l.file}=${String(l.engineMs)}ms`)
          .join(', ')}\n`,
    );
  }
});

function authRowMatches(state: ScanState, expected: CorpusFixture['expect']['auth']): void {
  if (!expected) return;
  expect(state.auth).toHaveLength(1);
  const row = state.auth[0]!;
  if (expected.spf) {
    if ('result' in expected.spf) expect(row.spf).toBe(expected.spf.result);
    if ('domain' in expected.spf) expect(row.spfDomain).toBe(expected.spf.domain);
  }
  if (expected.dkim) {
    if ('result' in expected.dkim) expect(row.dkim).toBe(expected.dkim.result);
    if ('signatures' in expected.dkim) expect(row.dkimSignatures).toEqual(expected.dkim.signatures);
  }
  if (expected.dmarc) {
    if ('result' in expected.dmarc) expect(row.dmarc).toBe(expected.dmarc.result);
    if ('policy' in expected.dmarc) expect(row.dmarcPolicy).toBe(expected.dmarc.policy);
    if ('domain' in expected.dmarc) expect(row.dmarcDomain).toBe(expected.dmarc.domain);
  }
  if (expected.arc && 'result' in expected.arc) expect(row.arc).toBe(expected.arc.result);
}

describe('scan corpus through the scan stage (§9)', () => {
  it.each(loadCorpus().map((f) => [f.file, f] as const))('%s', async (file, fixture) => {
    const eml = corpusEml(fixture);
    const message = await fx.message(org, { eml, envelope: fixture.envelope });
    const event = fx.parsed(message);
    const started = Date.now();
    expect(await pipeline.deliver(broker, event)).toBe('handled');
    const endToEndMs = Date.now() - started;

    const state = await fx.state(message);
    // Lifecycle persisted → scanning → scanned, through the transition service.
    expect(state.message).toMatchObject({ status: 'scanned', lifecycleRound: 0, version: 3 });
    expect(state.history.map((h) => [h.fromStatus, h.toStatus, h.reasonCode, h.actorRole])).toEqual(
      [
        ['persisted', 'scanning', 'scan_started', 'scanner'],
        ['scanning', 'scanned', 'scan_complete', 'scanner'],
      ],
    );

    // One round, one final result with the manifest verdict and reason codes.
    expect(state.scans).toHaveLength(1);
    const scan = state.scans[0]!;
    expect(scan).toMatchObject({
      lifecycleRound: 0,
      scanKind: 'initial',
      status: 'completed',
      scanVerdict: fixture.expect.verdict,
      triggerEventId: event.eventId,
    });
    expect(scan.requiredEngines).toEqual(['rspamd']);
    expect(state.results).toHaveLength(1);
    const result = state.results[0]!;
    expect(result).toMatchObject({
      engine: 'rspamd',
      isFinal: true,
      attempt: 1,
      outcome: fixture.expect.verdict,
    });
    expect(result.engineVersion).toMatch(/^3\.12\./);
    expect(result.settingsVersion).toMatch(/^rspamd-map\/2;p=[0-9a-f]{12};t=none$/);
    expect(result.reasonCodes as string[]).toEqual(
      expect.arrayContaining(fixture.expect.reasonCodes),
    );
    expect(scan.reasonCodes as string[]).toEqual(
      expect.arrayContaining(fixture.expect.reasonCodes),
    );
    for (const absent of fixture.expect.absentReasonCodes ?? []) {
      expect(result.reasonCodes as string[], `${file}: no reason ${absent}`).not.toContain(absent);
    }
    const score = Number(result.score);
    expect(score).toBeGreaterThanOrEqual(fixture.expect.scoreRange[0]);
    expect(score).toBeLessThan(fixture.expect.scoreRange[1]);
    const evidence = result.evidence as { signals: { name: string; options: string[] }[] };
    const names = evidence.signals.map((s) => s.name);
    expect(names).toEqual(expect.arrayContaining(fixture.expect.symbols));
    for (const absent of fixture.expect.absentSymbols ?? []) expect(names).not.toContain(absent);
    expect(evidence.signals.length).toBeLessThanOrEqual(200);
    for (const s of evidence.signals) {
      expect(s.options.length).toBeLessThanOrEqual(5);
      for (const o of s.options) expect(o.length).toBeLessThanOrEqual(200);
    }
    authRowMatches(state, fixture.expect.auth);

    // The scanned.v1 outbox row: schema-valid, ids and codes only.
    expect(state.scanned).toHaveLength(1);
    const payload = messageScannedV1.parse(state.scanned[0]!.payload);
    expect(payload).toMatchObject({
      messageId: message.messageId.toString(),
      scanId: scan.id.toString(),
      lifecycleRound: 0,
      scanKind: 'initial',
      outcome: 'scanned',
      verdict: fixture.expect.verdict,
      engines: [{ engine: 'rspamd', required: true, outcome: fixture.expect.verdict, attempts: 1 }],
    });
    expect(state.scanned[0]!.correlationId).toBe(event.correlationId);
    const raw = JSON.stringify(state.scanned[0]!.payload);
    expect(raw).not.toContain('@');
    // No symbol option (domains, URLs, addresses, mechanisms) reaches the event.
    for (const s of evidence.signals) {
      for (const o of s.options) if (/[.:@/]/.test(o)) expect(raw).not.toContain(o);
    }
    expect(raw).not.toContain('scan.test');
    expect(await fx.ledgerRows(pipeline.consumerName, [event.eventId])).toBe(1);
    latencies.push({ file, endToEndMs, engineMs: result.durationMs });
  });
});

describe('per-tenant settings (S8)', () => {
  it('a tenant override changes the verdict of the same message', async () => {
    const corpus = loadCorpus();
    const phishing = corpus.find((f) => f.file === 'phishing/link-mismatch.eml')!;
    const spoofed = corpus.find((f) => f.file === 'spoofed/spf-fail.eml')!;
    const strict = await fx.organization('strict');
    const lenient = await fx.organization('lenient');
    await fx.settings(strict, { phishingVerdict: 'malicious' });
    await fx.settings(lenient, { spamScore: 15, suspiciousScore: 14 });

    const a = await fx.message(strict, { eml: corpusEml(phishing), envelope: phishing.envelope });
    await pipeline.deliver(broker, fx.parsed(a));
    const stateA = await fx.state(a);
    expect(stateA.scans[0]!.scanVerdict).toBe('malicious');
    expect(stateA.results[0]!.reasonCodes as string[]).toContain('phishing.link_mismatch');
    expect(stateA.results[0]!.settingsVersion).toMatch(/;t=1$/);

    const b = await fx.message(lenient, { eml: corpusEml(spoofed), envelope: spoofed.envelope });
    await pipeline.deliver(broker, fx.parsed(b));
    const stateB = await fx.state(b);
    // Platform: spam (score ≥ 6); with spamScore 15 only the DMARC reject rule raises it.
    expect(stateB.scans[0]!.scanVerdict).toBe('suspicious');
    expect(stateB.results[0]!.reasonCodes as string[]).not.toContain('spam.score');
    expect(stateB.results[0]!.reasonCodes as string[]).toContain('auth.dmarc_reject');
  });

  it('an invalid tenant row falls back to the platform settings and is counted', async () => {
    const corpus = loadCorpus();
    const phishing = corpus.find((f) => f.file === 'phishing/link-mismatch.eml')!;
    const broken = await fx.organization('broken');
    // Bypasses the api's validation (as a row saved before the platform bounds tightened).
    await fx.settings(broken, { spamScore: 99, phishingVerdict: 'malicious' });
    const m = await fx.message(broken, { eml: corpusEml(phishing), envelope: phishing.envelope });
    await pipeline.deliver(broker, fx.parsed(m));
    const state = await fx.state(m);
    expect(state.scans[0]!.scanVerdict).toBe('suspicious');
    expect(state.results[0]!.settingsVersion).toMatch(/;t=none$/);
    expect(await pipeline.text()).toMatch(
      /scan_settings_invalid_total\{engine="rspamd"[^}]*\} [1-9]/,
    );
  });
});

describe('Rspamd reputation in Redis (S12, S18)', () => {
  it('reputation keys of a scanned sender exist in Redis DB RSPAMD_REDIS_DB with TTLs', async () => {
    const clean = loadCorpus().find((f) => f.class === 'clean')!;
    // A per-run client address (TEST-NET-2), so the IP reputation bucket is new.
    const ip = `198.51.100.${String(100 + (randomBytes(1)[0]! % 100))}`;
    const m = await fx.message(org, { eml: corpusEml(clean), envelope: { ...clean.envelope, ip } });
    await pipeline.deliver(broker, fx.parsed(m));
    const redis = rspamdRedis();
    try {
      let keys: string[] = [];
      await eventually(
        async () => {
          keys = await redis.client.keys(`RR:i:${ip.split('.').slice(0, 3).join('.')}*`);
          return keys.length > 0;
        },
        15_000,
        'an IP reputation key',
        250,
      );
      for (const key of keys) expect(await redis.client.pttl(key)).toBeGreaterThan(0);
      const domainKeys = await redis.client.keys('RR:clean.scan.test*');
      expect(domainKeys.length).toBeGreaterThan(0);
      expect(await redis.client.pttl(domainKeys[0]!)).toBeGreaterThan(0);
      // Rspamd's state is not in the apps' DB 0.
      expect(redis.client.options.db).not.toBe(0);
    } finally {
      await redis.client.quit();
    }
  });
});
