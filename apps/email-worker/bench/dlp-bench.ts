/**
 * DLP engine benchmark (step 4.5 §9 "Benchmark", docs/performance/dlp.md).
 *
 *   pnpm --filter @email-gateway/email-worker bench:dlp -- [--duration=10] [--concurrency=4]
 *     [--classes=typical,large_text,pdf20,docx200k,xlsx10k,zip20] [--tenant=plain,rich]
 *     [--pool=2] [--child=dist|src]
 *
 * Drives the real components: the DlpEngine adapter (loads, text budget, extraction routing,
 * detect(), classification, policy evaluation, evidence build + seal, metrics) with the real
 * extractor pool (the compiled `dist` child under Node's permission model when built, else the
 * TypeScript source through tsx). Part reads, the tenant store and the evidence bucket are
 * in-memory (S3 and MySQL are not what this measures). Every class runs for a fixed duration at a
 * fixed concurrency (one message per call): `typical` (8 KiB text + 20 KiB HTML, 2 findings),
 * `large_text` (4 MiB body), `pdf20` (20-page PDF), `docx200k` (≈ 200 KiB DOCX), `xlsx10k`
 * (10 000 rows), `zip20` (ZIP of 20 office documents); `--tenant=rich` adds 20 custom patterns
 * and 3 dictionaries. Prints one JSON line per run: messages/s, MiB/s and p50/p95 per stage (ms):
 * read, extract, detect, policy (classification + coverage + evaluation), seal, total.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { cpus, tmpdir, totalmem } from 'node:os';
import { join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { MetricsService } from '@email-gateway/common';
import {
  buildDocx,
  buildPdf,
  buildXlsx,
  buildZip,
  DlpDictionarySet,
  dlpEngineVersion,
  loadTenantPatterns,
  Prng,
  Synthetic,
  type TenantDictionaryInput,
  type TenantPatternInput,
} from '@email-gateway/dlp';
import { createLogger } from '@email-gateway/logger';
import { DLP_PLATFORM_DEFAULTS, resolveDlpSettings } from '@email-gateway/security-contracts';
import type { EngineScanContext } from '../src/scanning/engine';
import { ByteBudget } from '../src/scanning/engines/attachment/byte-budget';
import { DlpEngine } from '../src/scanning/engines/dlp/dlp.engine';
import { DlpMetrics } from '../src/scanning/engines/dlp/dlp-metrics';
import type {
  DlpAttachmentRow,
  DlpParseRow,
  DlpStore,
  DlpTenantRecord,
} from '../src/scanning/engines/dlp/dlp-store';
import type { EvidenceObjects } from '../src/scanning/engines/dlp/evidence-objects';
import { DlpExtractorPool } from '../src/scanning/engines/dlp/extractor/pool';
import type { PartPrefixRead, PartRead } from '../src/scanning/parts/part-reader';

const envFile = resolve(__dirname, '../../../.env');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const MiB = 1024 * 1024;
const ORG = 1n;
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

function arg(name: string, fallback: string): string {
  const hit = process.argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
}

class Timings {
  readonly stages = new Map<string, number[]>();
  add(stage: string, ms: number): void {
    const list = this.stages.get(stage) ?? [];
    list.push(ms);
    this.stages.set(stage, list);
  }
  quantiles(): Record<string, { p50: number; p95: number; n: number }> {
    const out: Record<string, { p50: number; p95: number; n: number }> = {};
    for (const [stage, values] of this.stages) {
      const sorted = [...values].sort((a, b) => a - b);
      const q = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]!;
      out[stage] = {
        p50: Math.round(q(0.5) * 100) / 100,
        p95: Math.round(q(0.95) * 100) / 100,
        n: sorted.length,
      };
    }
    return out;
  }
}

interface MessageFixture {
  text: string | null;
  html: string | null;
  attachments: Array<{ bytes: Buffer; filename: string }>;
}

const FILLER =
  'The quarterly planning notes follow below, with the usual agenda items and room bookings. ';

async function fixtures(): Promise<Record<string, MessageFixture>> {
  const s = new Synthetic(new Prng(4505));
  const group = (d: string) => d.replace(/(.{4})(?=.)/g, '$1 ');
  const filler = (bytes: number) => FILLER.repeat(Math.ceil(bytes / FILLER.length)).slice(0, bytes);
  const typicalText = `${filler(4_000)}\nCard: ${group(s.card('4532'))} exp 09/29\n${filler(4_000)}`;
  const typicalHtml = `<html><body><p>${filler(10_000)}</p><p>Company PAN ${s.pan('C')}</p><p>${filler(10_000)}</p></body></html>`;
  const largeHead = `Card: ${group(s.card('4532'))}\n`;
  const large = largeHead + filler(4 * MiB - largeHead.length);
  const pdf = buildPdf(
    Array.from({ length: 20 }, (_, i) => [
      `Page ${String(i + 1)} of the supplier statement.`,
      ...Array.from({ length: 30 }, () => FILLER.trim()),
      i === 3 ? `Card number ${group(s.card('4916'))}` : FILLER.trim(),
    ]),
    { compress: true },
  );
  // Varied prose (random words): a repeated filler would exceed the 4.2 compression-ratio limit.
  const rng = new Prng(77);
  const sentence = () =>
    Array.from({ length: 14 }, () => rng.letters(rng.int(2, 9), 'abcdefghijklmnopqrstuvwxyz')).join(
      ' ',
    ) + '.';
  const docx = await buildDocx({
    body: [
      ...Array.from({ length: 3_000 }, () => sentence()),
      `Debit card ${group(s.card('4024'))}`,
    ],
  });
  const xlsx = await buildXlsx({
    rows: [
      ['Employee', 'PAN', 'City', 'Salary'],
      ...Array.from({ length: 10_000 }, (_, i) => [
        `Employee ${String(i)}`,
        i % 500 === 0 ? s.pan('P') : `REF${String(100_000 + i)}`,
        'Pune',
        50_000 + i,
      ]),
    ],
  });
  const office = await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      buildDocx({
        body: [
          ...Array.from({ length: 60 }, () => sentence()),
          i === 7 ? `Visa ${group(s.card('4556'))}` : 'end',
        ],
      }),
    ),
  );
  const zip = await buildZip(
    office.map((data, i) => ({ name: `letters/doc-${String(i)}.docx`, data })),
  );
  return {
    typical: { text: typicalText, html: typicalHtml, attachments: [] },
    large_text: { text: large, html: null, attachments: [] },
    pdf20: {
      text: 'See attached.',
      html: null,
      attachments: [{ bytes: pdf, filename: 'statement.pdf' }],
    },
    docx200k: {
      text: 'See attached.',
      html: null,
      attachments: [{ bytes: docx, filename: 'notes.docx' }],
    },
    xlsx10k: {
      text: 'See attached.',
      html: null,
      attachments: [{ bytes: xlsx, filename: 'payroll.xlsx' }],
    },
    zip20: {
      text: 'See attached.',
      html: null,
      attachments: [{ bytes: zip, filename: 'letters.zip' }],
    },
  };
}

function richTenant(): { patterns: TenantPatternInput[]; dictionaries: TenantDictionaryInput[] } {
  const uuid = (n: number) => `0196f3a0-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
  const patterns: TenantPatternInput[] = Array.from({ length: 20 }, (_, i) => ({
    id: uuid(0xc000 + i),
    version: 1,
    pattern: `QX${String.fromCharCode(65 + i)}-[0-9]{6}`,
    caseInsensitive: false,
    validator: 'none',
    contextKeywords: ['employee'],
    requireContext: false,
    severity: 'medium',
    baseConfidence: 0.8,
    maskStyle: 'last4',
  }));
  const dictionaries: TenantDictionaryInput[] = Array.from({ length: 3 }, (_, d) => ({
    id: uuid(0xd000 + d),
    version: 1,
    category: 'confidential',
    terms: Array.from({ length: 100 }, (_, t) => `project codename${String(d)} term${String(t)}`),
    severity: 'medium',
    baseConfidence: 0.7,
    minMatches: 1,
  }));
  return { patterns, dictionaries };
}

class Store implements DlpStore {
  messages = new Map<bigint, { parse: DlpParseRow; attachments: DlpAttachmentRow[] }>();
  constructor(private readonly tenant: DlpTenantRecord) {}
  loadMessage() {
    return Promise.resolve({
      subject: 'Quarterly notes',
      envelopeFrom: 'a@corp.test',
      headerFrom: 'a@corp.test',
      recipientCount: 1,
    });
  }
  loadParse(scope: { messageId: bigint }) {
    return Promise.resolve(this.messages.get(scope.messageId)!.parse);
  }
  loadAttachments(scope: { messageId: bigint }) {
    return Promise.resolve(this.messages.get(scope.messageId)!.attachments);
  }
  tenantData() {
    return Promise.resolve(this.tenant);
  }
}

class Parts {
  readonly objects = new Map<string, Buffer>();
  constructor(private readonly timings: Timings) {}
  read(key: string): Promise<PartRead> {
    const t = performance.now();
    const bytes = this.objects.get(key)!;
    // The hash check of a full read, as S3PartReader does it.
    sha(bytes);
    this.timings.add('read', performance.now() - t);
    return Promise.resolve({ kind: 'ok', bytes });
  }
  readPrefix(key: string, max: number): Promise<PartPrefixRead> {
    return Promise.resolve({ kind: 'ok', bytes: this.objects.get(key)!.subarray(0, max) });
  }
}

const memoryEvidence: EvidenceObjects = {
  put: () => Promise.resolve(),
  delete: () => Promise.resolve(),
};

async function main(): Promise<void> {
  const duration = Number(arg('duration', '10')) * 1000;
  const concurrency = Number(arg('concurrency', '4'));
  const classes = arg('classes', 'typical,large_text,pdf20,docx200k,xlsx10k,zip20').split(',');
  const tenants = arg('tenant', 'plain,rich').split(',');
  const poolSize = Number(arg('pool', '2'));
  const distChild = resolve(__dirname, '../dist/scanning/engines/dlp/extractor/child.js');
  const child = arg('child', existsSync(distChild) ? 'dist' : 'src');
  const logger = createLogger({ service: 'dlp-bench', level: 'warn' });
  const tmp = mkdtempSync(join(tmpdir(), 'eg-dlp-bench-'));
  const pool = new DlpExtractorPool({
    size: poolSize,
    maxJobs: 200,
    heapMb: 256,
    rlimits: process.platform === 'linux' ? 'required' : 'best_effort',
    tmpDir: tmp,
    wallTimeoutMs: 20_000,
    cpuSeconds: 10,
    maxRssMb: 512,
    selftest: false,
    nodeEnv: 'production',
    maxWaiting: 64,
    maxTextChars: 1_000_000,
    logger,
    ...(child === 'dist' ? { childEntry: distChild } : {}),
  });
  const settings = (() => {
    const r = resolveDlpSettings(DLP_PLATFORM_DEFAULTS, null);
    if (!r.ok) throw new Error('platform defaults invalid');
    return r.settings;
  })();
  const all = await fixtures();
  const rich = richTenant();
  const loaded = loadTenantPatterns(rich.patterns);
  if (loaded.invalid.length > 0) throw new Error('bench patterns do not validate');
  await pool.start();
  process.stderr.write(
    `bench: ${cpus()[0]?.model ?? 'cpu'} x${String(cpus().length)}, ${String(Math.round(totalmem() / 1024 ** 3))} GiB, node ${process.version}, pool ${String(poolSize)} (${child}, rlimits ${pool.rlimitMode}, permission model ${String(pool.permissionModel)}), concurrency ${String(concurrency)}, ${String(duration / 1000)} s per run\n`,
  );
  try {
    for (const tenantKind of tenants) {
      const tenant: DlpTenantRecord = {
        tenantDomains: ['corp.test'],
        policies: [],
        internalIds: new Map(),
        exceptions: [],
        patterns: tenantKind === 'rich' ? loaded.loaded : [],
        invalidPatterns: [],
        dictionaries: DlpDictionarySet.create(tenantKind === 'rich' ? rich.dictionaries : []),
        compliance: null,
      };
      for (const name of classes) {
        const fixture = all[name];
        if (!fixture) throw new Error(`unknown class ${name}`);
        const timings = new Timings();
        const store = new Store(tenant);
        const parts = new Parts(timings);
        const registry = new MetricsService({ service: `dlp-bench-${name}` });
        const extractor = {
          start: () => pool.start(),
          stop: () => pool.stop(),
          get readyCount() {
            return pool.readyCount;
          },
          get rlimitMode() {
            return pool.rlimitMode;
          },
          get permissionModel() {
            return pool.permissionModel;
          },
          extract: async (...args: Parameters<DlpExtractorPool['extract']>) => {
            const t = performance.now();
            const out = await pool.extract(...args);
            timings.add('extract', performance.now() - t);
            return out;
          },
        };
        const engine = new DlpEngine({
          store,
          parts,
          extractor,
          budget: new ByteBudget(67_108_864),
          evidence: memoryEvidence,
          kek: { current: 'ab'.repeat(32) },
          engineVersion: dlpEngineVersion(),
          limits: {
            maxAttachments: 50,
            attachmentMaxBytes: 26_214_400,
            bodyMaxBytes: 4_194_304,
            textMaxCharsPerPart: 1_000_000,
            textMaxCharsPerMessage: 4_000_000,
            detectTimeoutMs: 60_000,
            extractConcurrency: 2,
            scanChunkChars: 65_536,
            maxMatchesPerDetector: 1_000,
            maxFindings: 64,
            customScanMaxChars: 1_000_000,
            evidenceMaxBytes: 32_768,
            evidenceMaxMatches: 50,
            walk: {
              archiveMaxDepth: 3,
              archiveMaxEntries: 1_000,
              maxEntryBytes: 26_214_400,
              maxDecompressedBytes: 104_857_600,
              maxCompressionRatio: 100,
              maxEntryFindings: 20,
              yaraTimeoutMs: 10_000,
              cpuSeconds: 10,
              maxRssMb: 512,
            },
            extract: {
              maxTextChars: 1_000_000,
              maxSegments: 200,
              pdfMaxPages: 200,
              maxTableColumns: 64,
              maxXmlBytes: 26_214_400,
            },
          },
          metrics: DlpMetrics.for(registry),
          logger,
          onStage: (stage, ms) => timings.add(stage, ms),
        });
        let next = 0n;
        let count = 0;
        let bytes = 0;
        const verdicts = new Map<string, number>();
        const deadline = performance.now() + duration;
        const worker = async () => {
          while (performance.now() < deadline) {
            const messageId = ++next;
            const prefix = `org/1/part/2026/11/07/${messageId.toString()}/`;
            const body = (key: string, content: string | null) => {
              if (content === null) return { key: null, sha256: null, sizeBytes: null };
              const b = Buffer.from(content, 'utf8');
              parts.objects.set(prefix + key, b);
              return { key: prefix + key, sha256: sha(b), sizeBytes: b.length };
            };
            const attachments = fixture.attachments.map((a, i) => {
              const key = `${prefix}${String(i + 2)}.att`;
              parts.objects.set(key, a.bytes);
              return {
                partIndex: i + 2,
                filename: a.filename,
                declaredContentType: null,
                sizeBytes: a.bytes.length,
                sha256: sha(a.bytes),
                objectKey: key,
                flags: [],
              };
            });
            store.messages.set(messageId, {
              parse: {
                status: 'parsed',
                limitsExceeded: [],
                attachmentCount: attachments.length,
                textBody: body('t.txt', fixture.text),
                htmlBody: body('b.html', fixture.html),
              },
              attachments,
            });
            const size =
              Buffer.byteLength(fixture.text ?? '') +
              Buffer.byteLength(fixture.html ?? '') +
              fixture.attachments.reduce((sum, a) => sum + a.bytes.length, 0);
            const ctx: EngineScanContext = {
              organizationId: ORG,
              messageId,
              receivedAt: new Date(),
              round: 0,
              scanId: messageId,
              scanKind: 'initial',
              direction: 'outbound',
              envelope: {
                clientIp: null,
                clientHelo: null,
                clientName: null,
                envelopeFrom: 'a@corp.test',
                recipients: ['b@partner.test'],
                queueId: null,
              },
              eml: { key: 'x', sizeBytes: 0, open: () => Promise.reject(new Error('unused')) },
              settings,
              settingsVersion: 'dlp-map/1;p=000000000000;t=none',
            };
            const t = performance.now();
            const outcome = await engine.scan(ctx, AbortSignal.timeout(120_000));
            timings.add('total', performance.now() - t);
            for (const key of [...parts.objects.keys()].filter((k) => k.startsWith(prefix)))
              parts.objects.delete(key);
            store.messages.delete(messageId);
            const label =
              outcome.kind === 'definite' ? outcome.result.outcome : `failure:${outcome.errorCode}`;
            verdicts.set(label, (verdicts.get(label) ?? 0) + 1);
            count += 1;
            bytes += size;
          }
        };
        const started = performance.now();
        await Promise.all(Array.from({ length: concurrency }, () => worker()));
        const seconds = (performance.now() - started) / 1000;
        process.stdout.write(
          `${JSON.stringify({
            class: name,
            tenant: tenantKind,
            concurrency,
            messages: count,
            seconds: Math.round(seconds * 100) / 100,
            messagesPerSec: Math.round((count / seconds) * 100) / 100,
            bytesPerMessage: count > 0 ? Math.round(bytes / count) : 0,
            mibPerSec: Math.round((bytes / MiB / seconds) * 100) / 100,
            verdicts: Object.fromEntries(verdicts),
            stagesMs: timings.quantiles(),
          })}\n`,
        );
      }
    }
  } finally {
    await pool.stop();
    rmSync(tmp, { recursive: true, force: true });
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(`bench failed: ${(error as Error).message}\n`);
  process.exit(1);
});
