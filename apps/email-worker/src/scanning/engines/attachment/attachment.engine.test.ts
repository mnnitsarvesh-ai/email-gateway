import { createHash } from 'node:crypto';
import * as corpus from '@email-gateway/attachment-corpus';
import {
  ClamdProtocolError,
  type ClamdScanResult,
  ClamdSizeLimitError,
  ClamdTimeoutError,
  ClamdUnavailableError,
} from '@email-gateway/clamav';
import { MetricsService } from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  resolveAttachmentSettings,
} from '@email-gateway/security-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import type { EngineDefinite, EngineFailure, EngineScanContext } from '../../engine';
import { AttachmentEngine, type ClamdScanner, type Inspector } from './attachment.engine';
import { AttachmentMetrics } from './attachment-metrics';
import {
  type AttachmentRow,
  type AttachmentStore,
  InconsistentAttachmentReadError,
  type ParseRow,
} from './attachment-store';
import { ByteBudget } from './byte-budget';
import { ClamavVersionProvider } from './clamav-versions';
import type { InspectLimits } from './content';
import { cacheKey, ContentCache } from './content-cache';
import { BUNDLED_RULES_DIR } from './inspector/bundle';
import { inspectBytes } from './inspector/inspect';
import type { InspectOutcome } from './inspector/pool';
import { YaraXScanner } from './inspector/yara-scanner';
import type { PartRead, PartSource } from './part-reader';
import type { KnownHashHit } from './verdict-mapper';

const ORG = 7n;
const CACHE_KEY = 'unit-test-content-cache-mac-key-0123456789';
const LIMITS: InspectLimits = {
  archiveMaxDepth: 3,
  archiveMaxEntries: 1000,
  maxEntryBytes: 26_214_400,
  maxDecompressedBytes: 104_857_600,
  maxCompressionRatio: 100,
  maxEntryFindings: 20,
  yaraTimeoutMs: 10_000,
  cpuSeconds: 10,
  maxRssMb: 384,
};
const SETTINGS = (() => {
  const r = resolveAttachmentSettings(ATTACHMENT_PLATFORM_DEFAULTS, null);
  if (!r.ok) throw new Error('x');
  return r.settings;
})();
const logger = createLogger({ service: 'attachment-engine-test', level: 'silent' });
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const v = (db: number) => ({
  engine: '1.4.6',
  dbVersion: db,
  dbTime: new Date('2026-11-05T00:00:00Z'),
});

let yara: YaraXScanner;
beforeAll(() => {
  yara = new YaraXScanner(BUNDLED_RULES_DIR, 10_000);
});

/** A parse row; `attachmentCount` defaults to the rows the store holds (a consistent parse). */
type TestParse = Omit<ParseRow, 'attachmentCount'> & { attachmentCount?: number | null };

class Store implements AttachmentStore {
  parse: TestParse | null = { status: 'parsed', limitsExceeded: [] };
  rows: AttachmentRow[] = [];
  hashes = new Map<string, KnownHashHit>();
  lookups: string[][] = [];
  /** A wrong read of the writer (step 4.2 §13.1.4): rows the read returns instead. */
  wrongRows: AttachmentRow[] | null = null;
  inconsistent: InconsistentAttachmentReadError | null = null;
  loadParse(): Promise<ParseRow | null> {
    if (!this.parse) return Promise.resolve(null);
    const { attachmentCount, ...rest } = this.parse;
    return Promise.resolve({
      ...rest,
      attachmentCount: attachmentCount === undefined ? this.rows.length : attachmentCount,
    });
  }
  loadAttachments(_m: bigint, _r: Date, _o: bigint, limit: number) {
    if (this.inconsistent) return Promise.reject(this.inconsistent);
    return Promise.resolve((this.wrongRows ?? this.rows).slice(0, limit));
  }
  knownHashes(list: readonly string[]) {
    this.lookups.push([...list]);
    return Promise.resolve(new Map([...this.hashes].filter(([k]) => list.includes(k))));
  }
}

class Parts implements PartSource {
  objects = new Map<string, Buffer>();
  reads = 0;
  read(key: string, sizeBytes: number, digest: string): Promise<PartRead> {
    this.reads += 1;
    const bytes = this.objects.get(key);
    if (!bytes) return Promise.resolve({ kind: 'missing' });
    if (bytes.length !== sizeBytes || sha(bytes) !== digest)
      return Promise.resolve({ kind: 'integrity' });
    return Promise.resolve({ kind: 'ok', bytes });
  }
}

class Clamd implements ClamdScanner {
  db = 28174;
  calls = 0;
  next: Error | null = null;
  scan(input: Uint8Array): Promise<ClamdScanResult> {
    this.calls += 1;
    if (this.next) return Promise.reject(this.next);
    const text = Buffer.from(input).toString('latin1');
    // A fragment of the test string (assembled at run time, never committed verbatim).
    const found = text.includes(['EICAR-STANDARD', 'ANTIVIRUS-TEST-FILE'].join('-'));
    const verdict: ClamdScanResult = found
      ? {
          status: 'found',
          signature: 'Eicar-Test-Signature',
          ...v(this.db),
          bytes: input.length,
          durationMs: 1,
        }
      : { status: 'clean', ...v(this.db), bytes: input.length, durationMs: 1 };
    return Promise.resolve(verdict);
  }
  ping() {
    return Promise.resolve();
  }
}

class InProcessInspector implements Inspector {
  readyCount = 2;
  rlimitMode = 'none' as const;
  next: InspectOutcome | null = null;
  start() {
    return Promise.resolve();
  }
  stop() {
    return Promise.resolve();
  }
  async inspect(bytes: Buffer, limits: InspectLimits): Promise<InspectOutcome> {
    if (this.next) return this.next;
    return { kind: 'result', result: await inspectBytes(bytes, limits, yara) };
  }
}

class Redis {
  store = new Map<string, string>();
  fail = false;
  get(key: string) {
    return this.fail
      ? Promise.reject(new Error('down'))
      : Promise.resolve(this.store.get(key) ?? null);
  }
  set(key: string, value: string) {
    if (this.fail) return Promise.reject(new Error('down'));
    this.store.set(key, value);
    return Promise.resolve('OK');
  }
}

function setup(options: { cache?: boolean; maxPerMessage?: number; sandbox?: boolean } = {}) {
  const store = new Store();
  const parts = new Parts();
  const clamd = new Clamd();
  const inspector = new InProcessInspector();
  const redis = new Redis();
  const registry = new MetricsService({ service: `att-${Math.random().toString(16).slice(2, 8)}` });
  const versions = new ClamavVersionProvider(
    { version: () => Promise.resolve(v(clamd.db)) },
    300_000,
  );
  const engine = new AttachmentEngine({
    store,
    parts,
    clamd,
    versions,
    inspector,
    cache:
      options.cache === false
        ? null
        : new ContentCache(
            redis,
            { cleanSeconds: 60, maliciousSeconds: 120, otherSeconds: 30 },
            200,
            CACHE_KEY,
          ),
    budget: new ByteBudget(64 * 1024 * 1024),
    metrics: AttachmentMetrics.for(registry),
    logger,
    bundleId: yara.bundleId,
    yaraXVersion: yara.yaraXVersion,
    limits: LIMITS,
    maxPerMessage: options.maxPerMessage ?? 100,
    parallelism: 2,
    sandbox: { enabled: options.sandbox ?? true, maxPerMessage: 5 },
    poolSize: 2,
  });
  let nextId = 100n;
  const add = (bytes: Buffer, over: Partial<AttachmentRow> = {}): AttachmentRow => {
    const partIndex = store.rows.length + 1;
    const key = `org/${ORG.toString()}/part/2026/11/05/55/${String(partIndex)}.att`;
    parts.objects.set(key, bytes);
    const row: AttachmentRow = {
      id: nextId++,
      partIndex,
      filename: 'file.pdf',
      declaredContentType: 'application/octet-stream',
      sizeBytes: bytes.length,
      sha256: sha(bytes),
      objectKey: key,
      flags: [],
      ...over,
    };
    store.rows.push(row);
    return row;
  };
  return { engine, store, parts, clamd, inspector, redis, registry, versions, add };
}

const ctx = (): EngineScanContext => ({
  organizationId: ORG,
  messageId: 55n,
  receivedAt: new Date('2026-11-05T10:00:00Z'),
  round: 0,
  direction: 'inbound',
  envelope: {
    clientIp: null,
    clientHelo: null,
    clientName: null,
    envelopeFrom: 'a@b.test',
    recipients: ['c@d.test'],
    queueId: null,
  },
  eml: {
    key: `org/${ORG.toString()}/eml/x.eml`,
    sizeBytes: 1,
    open: () => Promise.reject(new Error('not used')),
  },
  settings: SETTINGS,
  settingsVersion: 'attachment-map/1;p=000000000000;t=none',
});
const scan = (s: ReturnType<typeof setup>) => s.engine.scan(ctx(), AbortSignal.timeout(10_000));
const definite = async (s: ReturnType<typeof setup>) => {
  const outcome = await scan(s);
  expect(outcome.kind).toBe('definite');
  return outcome as EngineDefinite;
};
const failure = async (s: ReturnType<typeof setup>) => {
  const outcome = await scan(s);
  expect(outcome.kind).toBe('failure');
  return outcome as EngineFailure;
};

describe('AttachmentEngine (step 4.2 A3)', () => {
  it('A0: no attachments on a complete parse → skipped, no child rows', async () => {
    const s = setup();
    const outcome = await definite(s);
    expect(outcome.result).toMatchObject({
      engine: 'attachment',
      outcome: 'skipped',
      reasonCodes: ['attachment.none'],
      score: null,
      mappingVersion: 'attachment-map/1',
    });
    expect(outcome.childRows).toEqual({});
    // body_size (a body part not stored) never hides an attachment.
    s.store.parse = { status: 'parse_limit_exceeded', limitsExceeded: ['body_size'] };
    expect((await definite(s)).result.outcome).toBe('skipped');
  });

  it.each([
    'attachment_count',
    'attachment_size',
    'message_size',
    'nesting_depth',
    'part_count',
    'header_count',
    'header_line_length',
    'header_block_size',
    'decoded_ratio',
    'total_decoded_size',
    'parse_timeout',
    'a_future_limit',
  ])(
    'E1: %s makes the parse incomplete: suspicious even without attachment rows',
    async (limit) => {
      const s = setup();
      s.store.parse = { status: 'parse_limit_exceeded', limitsExceeded: ['body_size', limit] };
      expect((await definite(s)).result).toMatchObject({
        outcome: 'suspicious',
        reasonCodes: ['attachment.parse_incomplete'],
      });
    },
  );

  it('E1: a structural stop before a later part never lets a clean earlier part make the round clean', async () => {
    const s = setup();
    s.add(corpus.pdfLike());
    s.store.parse = { status: 'parse_limit_exceeded', limitsExceeded: ['header_block_size'] };
    const outcome = await definite(s);
    expect(outcome.result.outcome).toBe('suspicious');
    expect(outcome.result.reasonCodes).toContain('attachment.parse_incomplete');
  });

  it('E1: a parse row that is not final or has no attachment count is never A0', async () => {
    const s = setup();
    for (const parse of [
      { status: 'parsing', limitsExceeded: [], attachmentCount: null },
      { status: 'parse_failed', limitsExceeded: [], attachmentCount: null },
      { status: 'parsed', limitsExceeded: [], attachmentCount: null },
    ]) {
      s.store.parse = parse;
      expect((await definite(s)).result).toMatchObject({
        outcome: 'suspicious',
        reasonCodes: ['attachment.parse_incomplete'],
      });
    }
  });

  it('a row count that differs from the parse row is a retryable inconsistent_read, never skipped', async () => {
    const s = setup();
    s.add(corpus.pdfLike());
    s.add(corpus.pdfLike(4096, 3));
    // The writer returns no rows (a wrong empty result after a stall).
    s.store.wrongRows = [];
    expect(await failure(s)).toMatchObject({
      outcome: 'error',
      errorCode: 'inconsistent_read',
      retryable: true,
      engineFault: false,
    });
    // One row too few.
    s.store.wrongRows = s.store.rows.slice(0, 1);
    expect((await failure(s)).errorCode).toBe('inconsistent_read');
    // Rows of another message (identity echo in the store).
    s.store.wrongRows = null;
    s.store.inconsistent = new InconsistentAttachmentReadError('attachments', 'identity echo');
    expect((await failure(s)).errorCode).toBe('inconsistent_read');
    expect(await s.registry.metrics()).toMatch(
      /scan_attachment_inconsistent_reads_total\{[^}]*read="attachments"[^}]*\} 3/,
    );
    // Consistent again: scanned.
    s.store.inconsistent = null;
    expect((await definite(s)).result.outcome).toBe('clean');
  });

  it('accepts more rows than ATTACHMENT_MAX_PER_MESSAGE when the parse recorded them (count limit)', async () => {
    const s = setup({ maxPerMessage: 1 });
    s.add(corpus.pdfLike());
    s.add(corpus.pdfLike(4096, 3));
    s.add(corpus.pdfLike(4096, 5));
    const outcome = await definite(s);
    expect(outcome.result.reasonCodes).toContain('limit.attachment_count');
  });

  it('E1: an incomplete parse is suspicious even without attachment rows', async () => {
    const s = setup();
    s.store.parse = { status: 'parse_limit_exceeded', limitsExceeded: ['attachment_count'] };
    expect((await definite(s)).result).toMatchObject({
      outcome: 'suspicious',
      reasonCodes: ['attachment.parse_incomplete'],
    });
    s.store.parse = null;
    expect(await failure(s)).toMatchObject({
      errorCode: 'parse_row_missing',
      retryable: false,
      engineFault: false,
    });
  });

  it('scans a clean attachment, writes its row and caches the content result', async () => {
    const s = setup();
    const row = s.add(corpus.pdfLike());
    const outcome = await definite(s);
    expect(outcome.result).toMatchObject({
      outcome: 'clean',
      reasonCodes: ['clean.no_findings'],
      signals: [],
    });
    expect(outcome.result.engineVersion).toBe(
      `clamav/1.4.6/28174;yara-x/0.10.0/${yara.bundleId.slice(-12)}`,
    );
    expect(outcome.childRows!.attachments).toHaveLength(1);
    const first = outcome.childRows!.attachments![0]!;
    expect(first).toMatchObject({
      attachmentId: row.id,
      result: { verdict: 'clean', cache: 'miss', detectedType: 'pdf' },
    });
    expect(first.contentVersion).toMatch(/^[0-9a-f]{16}$/);
    expect(s.redis.store.has(cacheKey(row.sha256, first.contentVersion!))).toBe(true);
    expect(outcome.childRows!.sandbox).toEqual([]);
    // Second scan: a cache hit, no S3 read, no clamd call.
    const reads = s.parts.reads;
    const calls = s.clamd.calls;
    const again = await definite(s);
    expect(again.childRows!.attachments![0]!.result.cache).toBe('hit');
    expect(s.parts.reads).toBe(reads);
    expect(s.clamd.calls).toBe(calls);
    // The catalog is looked up on every scan (never cached).
    expect(s.store.lookups.length).toBe(2);
  });

  it('misses after a signature update and stores under the version that actually scanned', async () => {
    const s = setup();
    const row = s.add(corpus.pdfLike());
    const first = (await definite(s)).childRows!.attachments![0]!;
    // Within SCAN_ENGINE_VERSION_TTL_MS the lookup uses the polled version (A10) ...
    s.clamd.db = 28175;
    expect((await definite(s)).childRows!.attachments![0]!.result.cache).toBe('hit');
    // ... after the poll it misses: the new database changed the content version.
    await s.versions.fetch();
    const second = (await definite(s)).childRows!.attachments![0]!;
    expect(second.result.cache).toBe('miss');
    expect(second.contentVersion).not.toBe(first.contentVersion);
    expect(s.redis.store.has(cacheKey(row.sha256, second.contentVersion!))).toBe(true);
    expect(second.result.clamav!.dbVersion).toBe(28175);
    // A scan by a clamd with a newer database than the poll knows is stored under the version
    // that scanned (not the one used for the lookup).
    const other = s.add(corpus.pdfLike(4096, 5));
    s.clamd.db = 28176;
    const outcome = await definite(s);
    const third = outcome.childRows!.attachments!.find((a) => a.attachmentId === other.id)!;
    expect(third.result.clamav!.dbVersion).toBe(28176);
    expect(s.redis.store.has(cacheKey(other.sha256, third.contentVersion!))).toBe(true);
  });

  it('bypasses an unavailable cache without failing the attempt (never clean by accident)', async () => {
    const s = setup();
    s.add(corpus.pdfLike());
    s.redis.fail = true;
    const outcome = await definite(s);
    expect(outcome.childRows!.attachments![0]!.result).toMatchObject({
      verdict: 'clean',
      cache: 'bypass',
    });
    const off = setup({ cache: false });
    off.add(corpus.pdfLike());
    expect((await definite(off)).childRows!.attachments![0]!.result.cache).toBe('bypass');
  });

  it('M2: EICAR → malicious with a ClamAV signal and no sandbox submission', async () => {
    const s = setup();
    s.add(corpus.eicar(), { filename: 'eicar.txt' });
    const outcome = await definite(s);
    expect(outcome.result).toMatchObject({ outcome: 'malicious', reasonCodes: ['malware.clamav'] });
    expect(outcome.result.signals).toEqual([
      { name: 'clamav:Eicar-Test-Signature', score: 0, options: ['part 1'] },
    ]);
    expect(outcome.childRows!.sandbox).toEqual([]);
  });

  it('a planted or tampered clean cache entry never replaces the scan of a malicious file (A10)', async () => {
    const s = setup();
    s.add(corpus.eicar(), { filename: 'eicar.txt' });
    const first = await definite(s);
    expect(first.result.outcome).toBe('malicious');
    const [key] = [...s.redis.store.keys()];
    const genuine = s.redis.store.get(key!)!;
    const dot = genuine.indexOf('.');
    const content = JSON.parse(genuine.slice(dot + 1)) as Record<string, unknown>;
    const clean = JSON.stringify({
      ...content,
      clamav: { ...(content.clamav as object), status: 'clean', signature: null },
    });
    for (const planted of [clean, `${genuine.slice(0, dot)}.${clean}`]) {
      s.redis.store.set(key!, planted);
      const calls = s.clamd.calls;
      const outcome = await definite(s);
      expect(outcome.result.outcome).toBe('malicious');
      expect(outcome.childRows!.attachments![0]!.result.cache).toBe('miss');
      expect(s.clamd.calls).toBe(calls + 1);
      // Overwritten by an authenticated entry of the real result.
      expect(s.redis.store.get(key!)).toBe(genuine);
    }
    expect(await s.registry.metrics()).toMatch(
      /scan_attachment_cache_total\{[^}]*result="rejected"[^}]*\} 2/,
    );
  });

  it('submits suspicious and unknown attachments with a stored part to the sandbox', async () => {
    const s = setup();
    const encrypted = s.add(corpus.encryptedZip(), { filename: 'secret.zip' });
    s.add(corpus.fake7z(), { filename: 'a.7z' });
    const notStored = s.add(corpus.pdfLike(), {
      objectKey: null,
      flags: ['not_stored_size_limit'],
    });
    const outcome = await definite(s);
    expect(outcome.result.outcome).toBe('suspicious');
    const sandbox = outcome.childRows!.sandbox!;
    expect(sandbox.map((x) => [x.partIndex, x.attachmentVerdict])).toEqual([
      [encrypted.partIndex, 'suspicious'],
      [2, 'unknown'],
    ]);
    expect(sandbox[0]).toMatchObject({
      objectKey: encrypted.objectKey,
      sha256: encrypted.sha256,
      detectedType: 'zip',
    });
    expect(sandbox[0]!.reasonCodes.length).toBeLessThanOrEqual(16);
    expect(
      outcome.childRows!.attachments!.find((a) => a.attachmentId === notStored.id)!.result
        .reasonCodes,
    ).toContain('attachment.not_scanned');
    const off = setup({ sandbox: false });
    off.add(corpus.encryptedZip(), { filename: 'secret.zip' });
    expect((await definite(off)).childRows!.sandbox).toEqual([]);
  });

  it('does not read attachments above the tenant size limit (S3) and reports the count limit', async () => {
    const s = setup({ maxPerMessage: 1 });
    s.add(corpus.pdfLike());
    s.add(corpus.pdfLike(2048));
    const outcome = await definite(s);
    expect(outcome.childRows!.attachments).toHaveLength(1);
    expect(outcome.result.reasonCodes).toEqual(
      expect.arrayContaining(['limit.attachment_count', 'attachment.not_scanned']),
    );
    const tight = setup();
    tight.add(corpus.pdfLike(2 * 1024 * 1024));
    const outcome2 = await tight.engine.scan(
      { ...ctx(), settings: { ...SETTINGS, maxAttachmentBytes: 1_048_576 } },
      AbortSignal.timeout(5_000),
    );
    expect((outcome2 as EngineDefinite).childRows!.attachments![0]!.result.reasonCodes).toEqual([
      'attachment.not_scanned',
      'limit.attachment_size',
    ]);
    expect(tight.parts.reads).toBe(0);
  });

  it('M1: outer and inner known hashes (catalog lookup in the writer)', async () => {
    const s = setup();
    const inner = corpus.pdfLike(2048, 9);
    s.add(await corpus.zip([{ name: 'a.pdf', data: inner }]), { filename: 'a.zip' });
    s.store.hashes.set(sha(inner), { severity: 'high', family: 'Test' });
    const outcome = await definite(s);
    expect(outcome.result).toMatchObject({
      outcome: 'malicious',
      reasonCodes: ['malware.known_hash'],
    });
    expect(outcome.result.signals[0]!.name).toMatch(/^hash:[0-9a-f]{12}$/);
    expect(s.store.lookups.at(-1)).toEqual([sha(inner)]);
  });

  it('refuses a part key outside the organization and reports missing or corrupt objects', async () => {
    const s = setup();
    s.add(corpus.pdfLike(), { objectKey: 'org/8/part/x.att' });
    expect(await failure(s)).toMatchObject({
      errorCode: 'part_key_mismatch',
      retryable: false,
      engineFault: false,
    });
    const missing = setup();
    const row = missing.add(corpus.pdfLike());
    missing.parts.objects.delete(row.objectKey!);
    expect(await failure(missing)).toMatchObject({
      errorCode: 'part_unavailable',
      retryable: false,
      engineFault: false,
    });
    const corrupt = setup();
    const row2 = corrupt.add(corpus.pdfLike());
    corrupt.parts.objects.set(row2.objectKey!, corpus.pdfLike(row2.sizeBytes, 99));
    expect(await failure(corrupt)).toMatchObject({ errorCode: 'part_integrity', retryable: false });
  });

  it('maps clamd failures to retryable attempt failures and a size refusal to limit.clamav', async () => {
    const cases: Array<[Error, string, string]> = [
      [new ClamdUnavailableError('scan', 'ECONNREFUSED'), 'error', 'unavailable'],
      [new ClamdTimeoutError('scan', 60_000), 'timeout', 'timeout'],
      [new ClamdProtocolError('scan', 'unexpected_reply'), 'error', 'protocol_error'],
    ];
    for (const [error, outcome, code] of cases) {
      const s = setup();
      s.add(corpus.pdfLike());
      s.clamd.next = error;
      expect(await failure(s)).toMatchObject({
        outcome,
        errorCode: code,
        retryable: true,
        engineFault: true,
      });
    }
    const s = setup();
    s.add(corpus.pdfLike());
    s.clamd.next = new ClamdSizeLimitError(v(28174), 1000);
    const limited = await definite(s);
    expect(limited.result).toMatchObject({ outcome: 'suspicious', reasonCodes: ['limit.clamav'] });
  });

  it('maps inspector outcomes: kills are definite limits, wall timeouts and crashes are failures', async () => {
    const run = async (next: InspectOutcome) => {
      const s = setup();
      s.add(corpus.pdfLike());
      s.inspector.next = next;
      return scan(s);
    };
    expect(
      ((await run({ kind: 'limit', code: 'limit.cpu_time' })) as EngineDefinite).result,
    ).toMatchObject({ outcome: 'suspicious', reasonCodes: ['limit.cpu_time'] });
    expect(
      ((await run({ kind: 'limit', code: 'limit.memory' })) as EngineDefinite).result.reasonCodes,
    ).toEqual(['limit.memory']);
    expect(await run({ kind: 'failure', reason: 'wall' })).toMatchObject({
      kind: 'failure',
      outcome: 'timeout',
      errorCode: 'inspector_timeout',
      retryable: true,
      engineFault: true,
    });
    expect(await run({ kind: 'failure', reason: 'crash' })).toMatchObject({
      kind: 'failure',
      outcome: 'error',
      errorCode: 'inspector_crash',
      retryable: true,
    });
    expect(await run({ kind: 'failure', reason: 'unavailable' })).toMatchObject({
      kind: 'failure',
      errorCode: 'inspector_crash',
    });
  });

  it('a failure on one attachment discards the others (nothing persisted for the attempt)', async () => {
    const s = setup();
    s.add(corpus.pdfLike());
    const broken = s.add(corpus.pdfLike(2048));
    s.parts.objects.delete(broken.objectKey!);
    const outcome = await failure(s);
    expect(outcome.errorCode).toBe('part_unavailable');
    expect('childRows' in outcome).toBe(false);
  });

  it('counts attachments by verdict and cache result (A19 series)', async () => {
    const s = setup();
    s.add(corpus.eicar());
    await definite(s);
    const text = await s.registry.metrics();
    expect(text).toMatch(
      /scan_attachment_files_total\{[^}]*verdict="malicious"[^}]*cache="miss"[^}]*\} 1/,
    );
    expect(text).toMatch(
      /scan_attachment_detections_total\{[^}]*source="clamav"[^}]*severity="signature"[^}]*\} 1/,
    );
    expect(text).toMatch(/clamav_requests_total\{[^}]*result="found"[^}]*\} 1/);
    expect(text).toMatch(/scan_attachment_findings_total\{[^}]*code="malware.clamav"[^}]*\} 1/);
    expect(text).not.toContain('Eicar-Test-Signature');
  });

  it('reports readiness of clamd and the inspector pool', async () => {
    const s = setup();
    const checks = s.engine.healthChecks();
    expect(checks.map((c) => c.name)).toEqual(['clamav', 'attachment-inspector']);
    await expect(checks[0]!.check()).resolves.toBeUndefined();
    await expect(checks[1]!.check()).resolves.toEqual({
      ready: 2,
      size: 2,
      rlimits: 'none',
      bundleId: yara.bundleId,
    });
    s.inspector.readyCount = 0;
    await expect(checks[1]!.check()).rejects.toThrow();
  });

  it('reports the component versions for the signature watcher', async () => {
    const s = setup();
    const current = await s.engine.signatureSource().current(AbortSignal.timeout(1000));
    expect(current.versions).toEqual([
      { component: 'clamav_db', version: '28174' },
      { component: 'clamav_engine', version: '1.4.6' },
      { component: 'yara_bundle', version: yara.bundleId },
    ]);
  });

  it('rethrows an infrastructure error (transient) after stopping the other attachments', async () => {
    const s = setup();
    s.add(corpus.pdfLike());
    s.add(corpus.pdfLike(2048));
    const outage = Object.assign(new Error('S3 down'), { name: 'S3Stalled' });
    s.parts.read = () => Promise.reject(outage);
    await expect(scan(s)).rejects.toBe(outage);
  });
});
