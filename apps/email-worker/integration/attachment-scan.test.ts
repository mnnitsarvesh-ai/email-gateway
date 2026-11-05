import * as corpus from '@email-gateway/attachment-corpus';
import { attachmentSandboxRequestedV1 } from '@email-gateway/event-contracts';
import { attachmentResultSchema } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type AttachmentFixtures as Fixtures,
  AttachmentFixtures,
  AttachmentPipeline,
  type AttachmentSpec,
  clamdWithOffset,
} from './support/attachments';
import { ScanFixtures } from './support/scan';

/**
 * Package integration of the attachment engine (step 4.2 §9) against the real clamd
 * (clamav/clamav-debian:1.4), the MySQL writer, MinIO and Redis of the local stack: every
 * verdict path of A6 through the 4.1 orchestrator (round, final row, completion), the
 * per-attachment rows, the sandbox submissions, the content cache and the known-hash catalog.
 * Test files come from tests/fixtures/attachment-corpus (EICAR assembled at run time).
 */
const MiB = 1024 * 1024;
let fx: ScanFixtures;
let att: Fixtures;
let pipeline: AttachmentPipeline;
let org: bigint;

beforeAll(async () => {
  fx = new ScanFixtures();
  att = new AttachmentFixtures(fx);
  org = await fx.organization('att');
  pipeline = await AttachmentPipeline.start(fx);
});

afterAll(async () => {
  await pipeline?.stop();
  await att?.cleanup();
  await fx?.cleanup();
});

/** Scans one message through the round service and returns its results. */
async function scan(
  specs: AttachmentSpec[],
  options: {
    parse?: Parameters<Fixtures['message']>[2];
    organizationId?: bigint;
    via?: AttachmentPipeline;
  } = {},
) {
  const message = await att.message(options.organizationId ?? org, specs, options.parse);
  const outcome = await (options.via ?? pipeline).handle(fx.parsed(message));
  const { scan: round, final } = await att.finalOf(message);
  const rows = await att.results(message);
  const state = await fx.state(message);
  return { message, outcome, round, final, rows, state };
}

const codes = (value: unknown): string[] => value as string[];

describe('attachment engine: malware (A6 M2)', () => {
  it('EICAR plain, in zip, nested zip depth 2, gzip and tar → malicious, malware.clamav', async () => {
    const eicar = corpus.eicar();
    const files = [
      eicar,
      await corpus.zip([{ name: 'eicar.txt', data: eicar }]),
      await corpus.nestedZip(2, { name: 'eicar.txt', data: eicar }),
      corpus.gzip(eicar),
      await corpus.tar([{ name: 'eicar.txt', data: eicar }]),
    ];
    await att.uncache(...files);
    for (const bytes of files) {
      const { final, rows, state } = await scan([{ bytes, filename: 'invoice.dat' }]);
      expect(final).toMatchObject({ outcome: 'malicious', isFinal: true });
      expect(codes(final!.reasonCodes)).toContain('malware.clamav');
      expect(rows[0]).toMatchObject({
        verdict: 'malicious',
        clamavSignature: expect.stringMatching(/Eicar/) as string,
      });
      expect(state.message.status).toBe('scanned');
      expect(state.scans[0]).toMatchObject({ status: 'completed', scanVerdict: 'malicious' });
    }
  });

  it('EICAR past the depth limit: limit.archive_depth and still malicious (ClamAV recurses)', async () => {
    const bytes = await corpus.nestedZip(4, { name: 'eicar.txt', data: corpus.eicar() });
    await att.uncache(bytes);
    const { final, rows } = await scan([{ bytes, filename: 'deep.zip' }]);
    expect(final!.outcome).toBe('malicious');
    expect(codes(rows[0]!.reasonCodes)).toEqual(
      expect.arrayContaining(['malware.clamav', 'limit.archive_depth']),
    );
  });
});

describe('attachment engine: archives and limits (A4, A6 S3/S4/S7/U1)', () => {
  it('clean zip, gzip and tar of clean files → clean', async () => {
    const pdf = corpus.pdfLike(32 * 1024, 11);
    for (const bytes of [
      await corpus.zip([{ name: 'a.pdf', data: pdf }]),
      corpus.gzip(pdf),
      await corpus.tar([{ name: 'a.pdf', data: pdf }]),
    ]) {
      await att.uncache(bytes);
      const { final, rows } = await scan([
        { bytes, filename: 'docs.zip', declaredContentType: 'application/zip' },
      ]);
      expect(final!.outcome).toBe('clean');
      expect(codes(rows[0]!.reasonCodes)).toEqual(['clean.no_findings']);
      expect(rows[0]!.clamavSignature).toBeNull();
      expect(rows[0]!.clamavEngineVersion).toMatch(/^1\./);
    }
  });

  it('7z and rar headers → unknown, archive.unsupported_format', async () => {
    for (const [bytes, filename] of [
      [corpus.fake7z(), 'a.7z'],
      [corpus.fakeRar(), 'a.rar'],
    ] as const) {
      await att.uncache(bytes);
      const { final, rows } = await scan([{ bytes, filename }]);
      expect(rows[0]!.verdict).toBe('unknown');
      expect(codes(rows[0]!.reasonCodes)).toContain('archive.unsupported_format');
      expect(final!.outcome).toBe('unknown');
    }
  });

  it('zip bomb → suspicious, compression ratio, inspection stopped early', async () => {
    const bytes = await corpus.zipBomb();
    await att.uncache(bytes);
    const before = await pipeline.counter('scan_attachment_bytes_total', { stage: 'decompressed' });
    const { rows } = await scan([{ bytes, filename: 'bomb.zip' }]);
    expect(rows[0]!.verdict).toBe('suspicious');
    expect(
      codes(rows[0]!.reasonCodes).some(
        (c) => c === 'limit.compression_ratio' || c === 'limit.decompressed_size',
      ),
    ).toBe(true);
    const after = await pipeline.counter('scan_attachment_bytes_total', { stage: 'decompressed' });
    expect(after - before).toBeLessThan(MiB);
  });

  it('encrypted zip → suspicious archive.encrypted; malformed zip and truncated gzip → never clean', async () => {
    const encrypted = corpus.encryptedZip();
    const malformed = await corpus.malformedZip();
    const truncated = corpus.truncatedGzip(corpus.largeFile(64 * 1024, 3));
    await att.uncache(encrypted, malformed, truncated);
    const enc = await scan([{ bytes: encrypted, filename: 'secret.zip' }]);
    expect(enc.rows[0]).toMatchObject({ verdict: 'suspicious' });
    expect(codes(enc.rows[0]!.reasonCodes)).toContain('archive.encrypted');
    for (const bytes of [malformed, truncated]) {
      const { rows } = await scan([{ bytes, filename: 'broken.zip' }]);
      expect(rows[0]!.verdict).not.toBe('clean');
      expect(codes(rows[0]!.reasonCodes)).toContain('archive.malformed');
    }
    const pdf = corpus.truncatedPdf();
    await att.uncache(pdf);
    const truncatedPdf = await scan([{ bytes: pdf, filename: 'cut.pdf' }]);
    expect(truncatedPdf.rows[0]).toMatchObject({ detectedType: 'pdf', verdict: 'clean' });
  });

  it('large attachments: just below ATTACHMENT_MAX_BYTES is scanned; tenant limit and not-stored are not', async () => {
    const big = corpus.largeFile(25 * MiB - 1, 21);
    await att.uncache(big);
    const below = await scan([{ bytes: big, filename: 'big.bin' }]);
    expect(below.rows[0]).toMatchObject({ verdict: 'clean', sizeBytes: 25 * MiB - 1 });
    const tenantOrg = await fx.organization('att-limit');
    await att.tenantSettings(tenantOrg, { maxAttachmentBytes: 2 * MiB });
    const above = await scan([{ bytes: corpus.largeFile(3 * MiB, 22), filename: 'over.bin' }], {
      organizationId: tenantOrg,
    });
    expect(codes(above.rows[0]!.reasonCodes)).toEqual([
      'attachment.not_scanned',
      'limit.attachment_size',
    ]);
    expect(above.rows[0]!.cacheResult).toBe('bypass');
    const notStored = await scan([
      { bytes: corpus.largeFile(1024, 23), stored: false, filename: 'huge.bin' },
    ]);
    expect(notStored.rows[0]).toMatchObject({
      verdict: 'suspicious',
      clamavSignature: null,
      contentVersion: null,
    });
    expect(codes(notStored.rows[0]!.reasonCodes)).toEqual([
      'attachment.not_scanned',
      'limit.attachment_size',
    ]);
    // A not-stored attachment cannot be submitted to the sandbox.
    expect(await att.submissions(notStored.message)).toEqual([]);
  });
});

describe('attachment engine: types and tenant rules (A5, A8, A6 S5/S6)', () => {
  it('an exe renamed to pdf → type.executable_disguised + type.denied; tenant raises to malicious', async () => {
    const pe = corpus.peStub();
    await att.uncache(pe);
    const disguised = await scan([
      { bytes: pe, filename: 'invoice.pdf', declaredContentType: 'application/pdf' },
    ]);
    expect(disguised.rows[0]).toMatchObject({
      verdict: 'suspicious',
      detectedType: 'pe_executable',
      typeMismatch: true,
    });
    expect(codes(disguised.rows[0]!.reasonCodes)).toEqual(
      expect.arrayContaining(['type.executable_disguised', 'type.denied']),
    );
    const strict = await fx.organization('att-strict');
    await att.tenantSettings(strict, { deniedTypeVerdict: 'malicious' });
    const raised = await scan([{ bytes: pe, filename: 'invoice.pdf' }], { organizationId: strict });
    expect(raised.rows[0]!.verdict).toBe('malicious');
    expect(raised.rows[0]!.cacheResult).toBe('hit');
  });

  it('tenant allow list: listed types pass, others are not allowed', async () => {
    const allow = await fx.organization('att-allow');
    await att.tenantSettings(allow, { allowedTypes: ['pdf'] });
    const pdf = corpus.pdfLike(8 * 1024, 31);
    const text = Buffer.from('plain notes\n');
    await att.uncache(pdf, text);
    const ok = await scan([{ bytes: pdf, filename: 'a.pdf' }], { organizationId: allow });
    expect(ok.rows[0]!.verdict).toBe('clean');
    const refused = await scan([{ bytes: text, filename: 'notes.txt' }], { organizationId: allow });
    expect(codes(refused.rows[0]!.reasonCodes)).toEqual(['type.not_allowed']);
  });
});

describe('attachment engine: known hashes and YARA (A3, A6 M1/M3/S2, A17)', () => {
  it('a known-bad hash → malicious; removal → the next scan is not; an inner entry hash too', async () => {
    const file = corpus.pdfLike(16 * 1024, Date.now() % 100_000);
    const digest = await att.knownHash(file, 'high');
    const hit = await scan([{ bytes: file, filename: 'r.pdf' }]);
    expect(hit.rows[0]).toMatchObject({ verdict: 'malicious', knownHashSeverity: 'high' });
    expect(codes(hit.rows[0]!.reasonCodes)).toContain('malware.known_hash');
    await att.removeHash(digest);
    const after = await scan([{ bytes: file, filename: 'r.pdf' }]);
    // The catalog is never cached: the content result is a cache hit, the verdict changes at once.
    expect(after.rows[0]).toMatchObject({
      verdict: 'clean',
      cacheResult: 'hit',
      knownHashSeverity: null,
    });
    const inner = corpus.pdfLike(4 * 1024, (Date.now() + 7) % 100_000);
    await att.knownHash(inner, 'critical');
    const zipped = await scan([
      { bytes: await corpus.zip([{ name: 'in.pdf', data: inner }]), filename: 'z.zip' },
    ]);
    expect(zipped.rows[0]).toMatchObject({ verdict: 'malicious', knownHashSeverity: 'critical' });
    expect(
      (zipped.rows[0]!.archive as { findings: Array<{ reasonCodes: string[] }> }).findings[0]!
        .reasonCodes,
    ).toContain('malware.known_hash');
  });

  it('YARA test rules: high marker → malicious yara.high; medium → suspicious yara.medium', async () => {
    const high = corpus.yaraHigh();
    const medium = corpus.yaraMedium();
    await att.uncache(high, medium);
    const h = await scan([
      { bytes: high, filename: 'report.txt', declaredContentType: 'text/plain' },
    ]);
    expect(h.rows[0]).toMatchObject({
      verdict: 'malicious',
      yaraBundleId: expect.stringMatching(/^yara-1-/) as string,
    });
    expect(codes(h.rows[0]!.reasonCodes)).toEqual(['yara.high']);
    expect(h.rows[0]!.yaraMatches).toEqual([
      { rule: 'EG_Test_Marker_High', severity: 'high', scope: 'attachment' },
    ]);
    const m = await scan([{ bytes: medium, filename: 'notes.txt' }]);
    expect(m.rows[0]!.verdict).toBe('suspicious');
    expect(codes(m.rows[0]!.reasonCodes)).toEqual(['yara.medium']);
  });
});

describe('attachment engine: cache (A9, A10)', () => {
  it('a second scan of the same bytes is a hit without a clamd call; a new database version misses', async () => {
    const offset = { db: 0 };
    const local = await AttachmentPipeline.start(fx, {
      clamd: clamdWithOffset(pipeline.config, offset),
    });
    try {
      const file = corpus.pdfLike(24 * 1024, 4242);
      await att.uncache(file);
      const first = await scan([{ bytes: file, filename: 'c.pdf' }], { via: local });
      expect(first.rows[0]!.cacheResult).toBe('miss');
      const keys = await att.cachedKeys(file);
      expect(keys).toEqual([
        `eg:scan:att:v2:${first.rows[0]!.sha256}:${first.rows[0]!.contentVersion!}`,
      ]);
      // Clean results are never cached for longer than ATTACHMENT_CACHE_CLEAN_TTL_SECONDS.
      const ttl = await att.ttlOf(keys[0]!);
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(local.config.ATTACHMENT_CACHE_CLEAN_TTL_SECONDS);
      const calls = await local.counter('clamav_requests_total', { result: 'ok' });
      const second = await scan([{ bytes: file, filename: 'c.pdf' }], { via: local });
      expect(second.rows[0]!.cacheResult).toBe('hit');
      expect(await local.counter('clamav_requests_total', { result: 'ok' })).toBe(calls);
      // A signature update: the next poll reports a newer database → new content version.
      offset.db = 1;
      await local.engine.signatureSource().current(AbortSignal.timeout(10_000));
      const third = await scan([{ bytes: file, filename: 'c.pdf' }], { via: local });
      expect(third.rows[0]!.cacheResult).toBe('miss');
      expect(third.rows[0]!.contentVersion).not.toBe(first.rows[0]!.contentVersion);
      expect(third.rows[0]!.clamavDbVersion).toBe(first.rows[0]!.clamavDbVersion! + 1);
      expect(await att.cachedKeys(file)).toHaveLength(2);
    } finally {
      await local.stop();
    }
  });
});

describe('attachment engine: cache value authentication (A10, review round 1)', () => {
  it('a clean value planted in the shared Redis for a malicious file is rejected and rescanned', async () => {
    const file = corpus.eicar();
    await att.uncache(file);
    const first = await scan([{ bytes: file, filename: 'planted.txt' }]);
    expect(first.rows[0]).toMatchObject({ verdict: 'malicious', cacheResult: 'miss' });
    const [key] = await att.cachedKeys(file);
    const genuine = (await att.rawCacheValue(key!))!;
    expect(genuine).toMatch(/^[A-Za-z0-9_-]{43}\.\{/);
    const content = JSON.parse(genuine.slice(genuine.indexOf('.') + 1)) as {
      clamav: Record<string, unknown>;
    };
    const clean = JSON.stringify({
      ...content,
      clamav: { ...content.clamav, status: 'clean', signature: null },
    });
    for (const planted of [clean, `${genuine.slice(0, genuine.indexOf('.'))}.${clean}`]) {
      await att.plantCacheValue(key!, planted);
      const again = await scan([{ bytes: file, filename: 'planted.txt' }]);
      expect(again.rows[0]).toMatchObject({ verdict: 'malicious', cacheResult: 'miss' });
      expect(await att.rawCacheValue(key!)).toBe(genuine);
    }
  });
});

describe('attachment engine: engine-level rules and persistence (A0, E1, A11, A12, A18)', () => {
  it('no attachments → skipped attachment.none; the round completes on the skip', async () => {
    const { final, rows, state } = await scan([]);
    expect(final).toMatchObject({ outcome: 'skipped' });
    expect(codes(final!.reasonCodes)).toEqual(['attachment.none']);
    expect(rows).toEqual([]);
    expect(state.message.status).toBe('scanned');
  });

  it.each(['attachment_count', 'header_count', 'header_block_size', 'decoded_ratio'])(
    'an incomplete parse (%s) → suspicious attachment.parse_incomplete',
    async (limit) => {
      const { final } = await scan([], {
        parse: { status: 'parse_limit_exceeded', limitsExceeded: [limit] },
      });
      expect(final!.outcome).toBe('suspicious');
      expect(codes(final!.reasonCodes)).toEqual(['attachment.parse_incomplete']);
    },
  );

  it('writes schema-valid rows without names or content, and sandbox rows with their outbox events', async () => {
    const encrypted = corpus.encryptedZip();
    await att.uncache(encrypted);
    const { message, rows, final } = await scan([
      { bytes: encrypted, filename: 'Board-Minutes-Secret.zip' },
      { bytes: corpus.pdfLike(4 * 1024, 77), filename: 'fine.pdf' },
    ]);
    expect(final!.outcome).toBe('suspicious');
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      const parsed = attachmentResultSchema.safeParse({
        partIndex: row.partIndex,
        sha256: row.sha256,
        sizeBytes: row.sizeBytes,
        detectedType: row.detectedType,
        typeFamily: row.typeFamily,
        typeMismatch: row.typeMismatch,
        verdict: row.verdict,
        reasonCodes: row.reasonCodes,
        clamav: row.clamavEngineVersion
          ? {
              signature: row.clamavSignature,
              engineVersion: row.clamavEngineVersion,
              dbVersion: row.clamavDbVersion,
            }
          : null,
        yara: row.yaraBundleId ? { bundleId: row.yaraBundleId, matches: row.yaraMatches } : null,
        archive: row.archive,
        knownHash: null,
        cache: row.cacheResult,
        durationMs: row.durationMs,
      });
      expect(parsed.success).toBe(true);
      expect(
        JSON.stringify(row, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)),
      ).not.toContain('Board-Minutes');
    }
    const submissions = await att.submissions(message);
    expect(submissions).toHaveLength(1);
    expect(submissions[0]).toMatchObject({
      partIndex: 1,
      attachmentVerdict: 'suspicious',
      status: 'pending',
      detectedType: 'zip',
    });
    const events = (await att.sandboxEvents(org)).filter(
      (e) => e.eventId === submissions[0]!.requestedEventId,
    );
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      aggregateType: 'attachment',
      aggregateId: submissions[0]!.id.toString(),
      publishedAt: null,
    });
    const payload = attachmentSandboxRequestedV1.parse(events[0]!.payload);
    expect(payload).toMatchObject({
      submissionId: submissions[0]!.id.toString(),
      attachment: { partIndex: 1, objectKey: submissions[0]!.objectKey },
    });
    expect(JSON.stringify(events[0]!.payload)).not.toContain('Board-Minutes');
  });

  it('duplicate deliveries and a second event of the same round write one set of rows', async () => {
    const encrypted = corpus.encryptedZip();
    const message = await att.message(org, [{ bytes: encrypted, filename: 'dup.zip' }]);
    const event = fx.parsed(message);
    const other = fx.parsed(message);
    const outcomes = await Promise.all([
      pipeline.handle(event),
      pipeline.handle(event),
      pipeline.handle(other),
    ]);
    expect(outcomes.map((o) => o.outcome).sort()).toEqual(expect.arrayContaining(['handled']));
    await pipeline.handle(event);
    const { rows } = await att.finalOf(message);
    expect(rows.filter((r) => r.isFinal)).toHaveLength(1);
    expect(await att.results(message)).toHaveLength(1);
    const submissions = await att.submissions(message);
    expect(submissions).toHaveLength(1);
    const events = (await att.sandboxEvents(org)).filter(
      (e) => e.aggregateId === submissions[0]!.id.toString(),
    );
    expect(events).toHaveLength(1);
    const scanned = (await fx.state(message)).scanned;
    expect(scanned).toHaveLength(1);
  });

  it('refuses a missing part object (part_unavailable) and a corrupt one (part_integrity), never clean', async () => {
    const missing = await scan([
      { bytes: corpus.pdfLike(2048, 5), filename: 'm.pdf', upload: false },
    ]);
    expect(missing.final).toMatchObject({ outcome: 'error', errorCode: 'part_unavailable' });
    expect(missing.state.message.status).toBe('scan_failed');
    const corrupt = await scan([
      { bytes: corpus.pdfLike(2048, 6), uploadBytes: corpus.pdfLike(2048, 7), filename: 'c.pdf' },
    ]);
    expect(corrupt.final).toMatchObject({ outcome: 'error', errorCode: 'part_integrity' });
    expect(corrupt.rows).toEqual([]);
  });
});
