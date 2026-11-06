import { performance } from 'node:perf_hooks';
import {
  type ClamdScanResult,
  ClamdSizeLimitError,
  ClamdTimeoutError,
  ClamdUnavailableError,
  type ClamdVersion,
  isClamdError,
} from '@email-gateway/clamav';
import type { Logger } from '@email-gateway/logger';
import {
  type AttachmentEffectiveSettings,
  type AttachmentResult,
  attachmentResultSchema,
  fileTypeIdForContentType,
  normalizedEngineResultSchema,
} from '@email-gateway/security-contracts';
import { errorFields } from '../../../mime-ingestion/error-fields';
import type {
  AttachmentResultInput,
  EngineFailure,
  EngineHealthCheck,
  EngineScanContext,
  EngineScanOutcome,
  SandboxSubmissionInput,
  ScanEngineAdapter,
} from '../../engine';
import type { AttachmentMetrics } from './attachment-metrics';
import type { AttachmentRow, AttachmentStore } from './attachment-store';
import { InconsistentAttachmentReadError, limitMayHideAttachments } from './attachment-store';
import type { ByteBudget } from './byte-budget';
import type { ClamavVersionProvider } from './clamav-versions';
import { type ContentResult, INSPECTOR_VERSION, type InspectLimits } from './content';
import { type ContentCache, contentVersion } from './content-cache';
import { extensionTypeOfName } from './inspector/file-type';
import type { InspectOutcome } from './inspector/pool';
import type { PartSource } from '../../parts/part-reader';
import type { VersionSource } from './signature-watcher';
import {
  contentVerdict,
  type KnownHashHit,
  mapAttachment,
  mapEngine,
  MAPPING_VERSION,
  selectSandbox,
} from './verdict-mapper';

/** The parts of `ClamdClient` the engine uses (a fake in unit tests). */
export interface ClamdScanner {
  scan(input: Uint8Array, signal?: AbortSignal): Promise<ClamdScanResult>;
  ping(signal?: AbortSignal): Promise<void>;
}

/** The parts of `InspectorPool` the engine uses (a fake in unit tests). */
export interface Inspector {
  start(): Promise<void>;
  stop(): Promise<void>;
  inspect(bytes: Buffer, limits: InspectLimits, signal: AbortSignal): Promise<InspectOutcome>;
  readonly readyCount: number;
  readonly rlimitMode: 'prlimit' | 'none';
}

export interface AttachmentEngineOptions {
  store: AttachmentStore;
  parts: PartSource;
  clamd: ClamdScanner;
  versions: ClamavVersionProvider;
  inspector: Inspector;
  /** Null when ATTACHMENT_CACHE_ENABLED=false. */
  cache: ContentCache | null;
  budget: ByteBudget;
  metrics: AttachmentMetrics;
  logger: Logger;
  bundleId: string;
  yaraXVersion: string;
  limits: InspectLimits;
  maxPerMessage: number;
  parallelism: number;
  sandbox: { enabled: boolean; maxPerMessage: number };
  /** Inspector pool size (readiness details). */
  poolSize: number;
  now?: () => Date;
}

/** Statuses of a parse row that are complete (A1 rule A0 may apply). */
const COMPLETE_PARSES = new Set(['parsed', 'parsed_with_defects', 'parse_limit_exceeded']);
/** Engine-level failure codes that are not retryable (A6). */
const NOT_RETRYABLE = new Set([
  'part_unavailable',
  'part_integrity',
  'part_key_mismatch',
  'parse_row_missing',
  'result_invalid',
]);
const PING_TIMEOUT_MS = 2_000;

type Scanned =
  | {
      kind: 'ok';
      row: AttachmentRow;
      content: ContentResult | null;
      cache: 'hit' | 'miss' | 'bypass';
      contentVersion: string | null;
      durationMs: number;
    }
  | { kind: 'failure'; outcome: 'timeout' | 'error'; errorCode: string; engineFault: boolean };

const fail = (
  outcome: 'timeout' | 'error',
  errorCode: string,
  engineFault = true,
): Extract<Scanned, { kind: 'failure' }> => ({ kind: 'failure', outcome, errorCode, engineFault });

const seconds = (since: number): number => (performance.now() - since) / 1000;

/** The content result of an inspector CPU/memory kill (A4: definite, rule S3). */
function killedContent(code: 'limit.cpu_time' | 'limit.memory'): Omit<ContentResult, 'clamav'> {
  return {
    inspectorVersion: INSPECTOR_VERSION,
    type: { detected: 'unknown', family: 'other', executable: false, textLike: false },
    yara: null,
    archive: null,
    limits: [code],
    codes: [],
  };
}

/** Runs `task` over `items` with at most `parallelism` at a time; stops starting new ones on `stop()`. */
async function boundedEach<T>(
  items: readonly T[],
  parallelism: number,
  task: (item: T, index: number) => Promise<boolean>,
): Promise<void> {
  let next = 0;
  let halted = false;
  const worker = async () => {
    while (!halted && next < items.length) {
      const index = next;
      next += 1;
      if (!(await task(items[index]!, index))) halted = true;
    }
  };
  await Promise.all(
    Array.from({ length: Math.max(1, Math.min(parallelism, items.length)) }, worker),
  );
}

/**
 * The attachment engine adapter (step 4.2 A3): for one round of one message it loads the parse
 * row and the attachment rows from the writer (organization from the trusted envelope), applies
 * the engine-level rules (A0 no attachments → `skipped`, E1 incomplete parse), looks up the
 * known-threat hashes, then per attachment (bounded parallelism, the byte budget): checks the
 * part key (`org/<id>/part/`), looks up the content cache, otherwise reads the part from S3 in
 * full (size bound, SHA-256 verified) and runs clamd INSTREAM and the inspector child in
 * parallel; inner entry hashes are looked up after inspection; the content result is cached; the
 * verdict mapper (A6) produces the per-attachment rows; the aggregation the engine result; the
 * sandbox submissions (A11) are selected. Nothing is persisted here: the rows travel as
 * `childRows` to the finalize transaction (A12).
 *
 * Failures are attempt failures (A6), never a verdict: clamd unavailable / timeout / protocol
 * error and inspector wall-clock timeout / crash are retryable and count for the breaker; a
 * missing or corrupt part object, a key outside the organization and a missing parse row are
 * not retryable and not the engine's fault. An S3 or MySQL outage is thrown (transient). Logs
 * carry ids, codes and counts only (never filenames, entry names or content).
 */
export class AttachmentEngine implements ScanEngineAdapter {
  readonly name = 'attachment' as const;
  private readonly logger: Logger;
  private readonly now: () => Date;

  constructor(private readonly options: AttachmentEngineOptions) {
    this.logger = options.logger.child({ component: 'attachment-engine' });
    this.now = options.now ?? (() => new Date());
  }

  async start(): Promise<void> {
    await this.options.inspector.start();
    this.options.metrics.signature('yara_bundle', this.options.bundleId);
    // Best effort: the first scans can use the cache at once.
    await this.options.versions.get(AbortSignal.timeout(PING_TIMEOUT_MS)).catch(() => null);
  }

  async stop(): Promise<void> {
    await this.options.inspector.stop();
  }

  /** The component versions of the signature watcher (A13): clamd VERSION and the bundle id. */
  signatureSource(): VersionSource {
    const { versions, bundleId } = this.options;
    return {
      current: async (signal) => {
        const version = await versions.fetch(signal);
        return {
          versions: [
            { component: 'clamav_db', version: String(version.dbVersion) },
            { component: 'clamav_engine', version: version.engine },
            { component: 'yara_bundle', version: bundleId },
          ],
          clamavDbTime: version.dbTime,
        };
      },
    };
  }

  healthChecks(): EngineHealthCheck[] {
    const { options } = this;
    return [
      {
        name: 'clamav',
        check: async () => {
          await options.clamd.ping(AbortSignal.timeout(PING_TIMEOUT_MS));
        },
      },
      {
        name: 'attachment-inspector',
        check: () => {
          const ready = options.inspector.readyCount;
          if (ready === 0) return Promise.reject(new Error('no inspector child is ready'));
          return Promise.resolve({
            ready,
            size: options.poolSize,
            rlimits: options.inspector.rlimitMode,
            bundleId: options.bundleId,
          });
        },
      },
    ];
  }

  /**
   * A writer read that returned rows of another request (`InconsistentAttachmentReadError`,
   * including an attachment-row count that differs from the parse row's `attachment_count`) is
   * a retryable attempt failure `inconsistent_read`, not the engine's fault: never `skipped`,
   * never a verdict built from foreign or missing rows.
   */
  async scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome> {
    const started = performance.now();
    try {
      return await this.scanRound(ctx, signal, started);
    } catch (error) {
      if (!(error instanceof InconsistentAttachmentReadError)) throw error;
      this.options.metrics.inconsistentReads.inc({ read: error.read });
      this.logger.warn(
        {
          messageId: ctx.messageId.toString(),
          round: ctx.round,
          read: error.read,
          check: error.check,
        },
        'attachment engine: inconsistent writer read, attempt retried',
      );
      return {
        kind: 'failure',
        outcome: 'error',
        errorCode: 'inconsistent_read',
        retryable: true,
        engineFault: false,
        durationMs: Math.max(0, Math.round(performance.now() - started)),
        engineVersion: this.engineVersion(this.options.versions.current),
      };
    }
  }

  private async scanRound(
    ctx: EngineScanContext,
    signal: AbortSignal,
    started: number,
  ): Promise<EngineScanOutcome> {
    const { options } = this;
    const settings = ctx.settings as AttachmentEffectiveSettings;
    const ids = { messageId: ctx.messageId.toString(), round: ctx.round };
    const elapsed = () => Math.max(0, Math.round(performance.now() - started));
    const failure = (f: Extract<Scanned, { kind: 'failure' }>): EngineFailure => ({
      kind: 'failure',
      outcome: f.outcome,
      errorCode: f.errorCode,
      retryable: !NOT_RETRYABLE.has(f.errorCode),
      engineFault: f.engineFault,
      durationMs: elapsed(),
      engineVersion: this.engineVersion(options.versions.current),
    });

    // 1. Parse row and attachment rows (writer, the envelope's organization).
    const parse = await options.store.loadParse(ctx.messageId, ctx.receivedAt, ctx.organizationId);
    if (!parse) {
      this.logger.warn(ids, 'attachment engine: the message has no parse row');
      return failure(fail('error', 'parse_row_missing', false));
    }
    // E1: not final, no recorded attachment count, or any limit that may hide a part (every
    // limit but body_size: the structural stops end the parse before later parts get a row).
    const parseIncomplete =
      !COMPLETE_PARSES.has(parse.status) ||
      parse.attachmentCount === null ||
      parse.limitsExceeded.some(limitMayHideAttachments);
    const loaded = await options.store.loadAttachments(
      ctx.messageId,
      ctx.receivedAt,
      ctx.organizationId,
      options.maxPerMessage + 1,
    );
    // The rows must be the ones the parse wrote (a wrong empty result must never become A0).
    if (
      parse.attachmentCount !== null &&
      loaded.length !== Math.min(parse.attachmentCount, options.maxPerMessage + 1)
    ) {
      throw new InconsistentAttachmentReadError('attachments', 'attachment count');
    }
    const countExceeded = loaded.length > options.maxPerMessage;
    const rows = loaded.slice(0, options.maxPerMessage);

    // 2. Part keys: under the organization's part prefix (tenant from trusted context).
    const prefix = `org/${ctx.organizationId.toString()}/part/`;
    for (const row of rows) {
      if (
        row.objectKey !== null &&
        (!row.objectKey.startsWith(prefix) || row.objectKey.includes('..'))
      ) {
        this.logger.warn(
          { ...ids, partIndex: row.partIndex },
          'attachment part key outside the organization',
        );
        return failure(fail('error', 'part_key_mismatch', false));
      }
    }

    // 3. Known-threat hashes of the attachments (authoritative, never cached).
    let hashStarted = performance.now();
    const outerHashes =
      rows.length > 0
        ? await options.store.knownHashes(
            rows.map((r) => r.sha256),
            this.now(),
          )
        : new Map<string, KnownHashHit>();
    options.metrics.stage('hash_lookup', seconds(hashStarted));

    // 4. Per attachment: cache, S3, clamd + inspector in parallel.
    const lookupVersion =
      options.cache && rows.some((r) => r.objectKey !== null)
        ? await options.versions.get(signal)
        : null;
    const results = new Array<Extract<Scanned, { kind: 'ok' }>>(rows.length);
    let firstFailure: Extract<Scanned, { kind: 'failure' }> | null = null;
    const abort = new AbortController();
    const scanSignal = AbortSignal.any([signal, abort.signal]);
    let thrown: { error: unknown } | null = null;
    await boundedEach(rows, options.parallelism, async (row, index) => {
      let scanned: Scanned;
      try {
        scanned = await this.scanOne(row, settings, lookupVersion, scanSignal);
      } catch (error) {
        // Infrastructure (S3, network): stop the siblings, then rethrow (transient, no attempt).
        thrown ??= { error };
        abort.abort();
        return false;
      }
      if (scanned.kind === 'failure') {
        firstFailure ??= scanned;
        abort.abort();
        return false;
      }
      results[index] = scanned;
      return true;
    });
    if (thrown !== null) throw (thrown as { error: unknown }).error;
    if (firstFailure !== null) {
      const f = firstFailure as Extract<Scanned, { kind: 'failure' }>;
      // An attempt failure discards the attachments before it (A3); their content is cached.
      this.logger.debug({ ...ids, errorCode: f.errorCode }, 'attachment engine attempt failed');
      return failure(signal.aborted ? fail('timeout', 'timeout') : f);
    }

    // 5. Inner entry hashes (always, also for cache hits).
    hashStarted = performance.now();
    const innerSha = results.flatMap(
      (r) => r.content?.archive?.entryHashes.map((e) => e.sha256) ?? [],
    );
    const innerHits =
      innerSha.length > 0
        ? await options.store.knownHashes(innerSha, this.now())
        : new Map<string, KnownHashHit>();
    if (innerSha.length > 0) options.metrics.stage('hash_lookup', seconds(hashStarted));

    // 6. Map every attachment (A6) and validate it against the row contract.
    const mapped: Array<{
      row: AttachmentRow;
      result: AttachmentResult;
      contentVersion: string | null;
    }> = [];
    for (const scanned of results) {
      const { row, content } = scanned;
      const inner = new Map<string, KnownHashHit>();
      for (const entry of content?.archive?.entryHashes ?? []) {
        const hit = innerHits.get(entry.sha256);
        if (hit) inner.set(entry.path, hit);
      }
      const result = mapAttachment(
        {
          facts: {
            partIndex: row.partIndex,
            sha256: row.sha256,
            sizeBytes: row.sizeBytes,
            stored: row.objectKey !== null,
            extensionType: row.filename ? extensionTypeOfName(row.filename) : null,
            declaredType: row.declaredContentType
              ? fileTypeIdForContentType(row.declaredContentType)
              : null,
            flags: row.flags,
          },
          content,
          hashes: { outer: outerHashes.get(row.sha256) ?? null, inner },
          cache: scanned.cache,
          durationMs: scanned.durationMs,
        },
        settings,
      );
      const valid = attachmentResultSchema.safeParse(result);
      if (!valid.success) {
        this.logger.error(
          { ...ids, partIndex: row.partIndex },
          'attachment result violates its contract',
        );
        return failure(fail('error', 'result_invalid', false));
      }
      mapped.push({ row, result: valid.data, contentVersion: scanned.contentVersion });
      this.record(valid.data);
    }

    // 7. Engine result, rows and sandbox submissions.
    const engine = mapEngine({
      attachments: mapped.map((m) => m.result),
      parseIncomplete,
      countExceeded,
    });
    const clamav = this.latestClamav(results) ?? options.versions.current;
    const base = {
      engine: this.name,
      engineVersion: this.engineVersion(clamav),
      score: null,
      requiredScore: null,
      action: null,
      reasonCodes: engine.reasonCodes,
      signals: engine.signals,
      durationMs: elapsed(),
      settingsVersion: ctx.settingsVersion,
      mappingVersion: MAPPING_VERSION,
    };
    const attachments: AttachmentResultInput[] = mapped.map((m) => ({
      attachmentId: m.row.id,
      result: m.result,
      contentVersion: m.contentVersion,
    }));
    const sandbox: SandboxSubmissionInput[] = options.sandbox.enabled
      ? selectSandbox(
          mapped.map((m) => ({ result: m.result, stored: m.row.objectKey !== null })),
          options.sandbox.maxPerMessage,
        ).map(({ index, verdict }) => {
          const m = mapped[index]!;
          return {
            attachmentId: m.row.id,
            partIndex: m.result.partIndex,
            sha256: m.result.sha256,
            sizeBytes: m.result.sizeBytes,
            detectedType: m.result.detectedType,
            objectKey: m.row.objectKey!,
            attachmentVerdict: verdict,
            reasonCodes: m.result.reasonCodes.slice(0, 16),
          };
        })
      : [];
    for (const s of sandbox) options.metrics.sandbox(s.attachmentVerdict);

    this.logger.debug(
      {
        ...ids,
        outcome: engine.outcome,
        attachments: mapped.length,
        sandbox: sandbox.length,
        reasonCodes: engine.reasonCodes,
      },
      'attachment engine result',
    );
    if (engine.outcome === 'skipped') {
      return { kind: 'definite', result: { ...base, outcome: 'skipped' }, childRows: {} };
    }
    const parsed = normalizedEngineResultSchema.safeParse({ ...base, outcome: engine.outcome });
    if (!parsed.success) return failure(fail('error', 'result_invalid', false));
    return { kind: 'definite', result: parsed.data, childRows: { attachments, sandbox } };
  }

  /** `clamav/<engine>/<db>;yara-x/<ver>/<bundle12>` (≤ 64 characters, A6). */
  private engineVersion(clamav: Pick<ClamdVersion, 'engine' | 'dbVersion'> | null): string {
    const bundle12 = this.options.bundleId.slice(-12);
    const yara = `yara-x/${this.options.yaraXVersion}/${bundle12}`;
    const text = clamav
      ? `clamav/${clamav.engine}/${String(clamav.dbVersion)};${yara}`
      : `clamav/unknown;${yara}`;
    return text.slice(0, 64);
  }

  private latestClamav(
    results: ReadonlyArray<Extract<Scanned, { kind: 'ok' }>>,
  ): Pick<ClamdVersion, 'engine' | 'dbVersion'> | null {
    for (const r of results) {
      if (r.content && r.content.clamav.engineVersion !== 'unknown') {
        return { engine: r.content.clamav.engineVersion, dbVersion: r.content.clamav.dbVersion };
      }
    }
    return null;
  }

  private versionFor(clamav: { engine: string; dbVersion: number }): string {
    return contentVersion({
      inspectorVersion: INSPECTOR_VERSION,
      clamavEngine: clamav.engine,
      clamavDb: clamav.dbVersion,
      yaraX: this.options.yaraXVersion,
      bundleId: this.options.bundleId,
      limits: this.options.limits,
    });
  }

  /** One attachment: not scanned, cache hit, or S3 + clamd + inspector (A3 step 5). */
  private async scanOne(
    row: AttachmentRow,
    settings: AttachmentEffectiveSettings,
    lookupVersion: ClamdVersion | null,
    signal: AbortSignal,
  ): Promise<Scanned> {
    const { options } = this;
    const started = performance.now();
    const done = (
      content: ContentResult | null,
      cache: 'hit' | 'miss' | 'bypass',
      version: string | null,
    ): Scanned => {
      const durationMs = Math.round(performance.now() - started);
      options.metrics.stage('total', durationMs / 1000);
      return { kind: 'ok', row, content, cache, contentVersion: version, durationMs };
    };

    // S3: not stored, or above the effective size limit → no content scan.
    if (row.objectKey === null || row.sizeBytes > settings.maxAttachmentBytes) {
      return done(null, 'bypass', null);
    }

    // Cache lookup under the version the worker believes is current (A10).
    let cacheLabel: 'miss' | 'bypass' = options.cache ? 'miss' : 'bypass';
    if (options.cache && lookupVersion) {
      const version = this.versionFor(lookupVersion);
      const lookupStarted = performance.now();
      const cached = await options.cache.get(row.sha256, version);
      options.metrics.stage('cache_get', seconds(lookupStarted));
      if (cached.kind === 'hit') {
        options.metrics.cache.inc({ result: 'hit' });
        return done(cached.content, 'hit', version);
      }
      options.metrics.cache.inc({ result: cached.kind });
      if (cached.kind === 'error') cacheLabel = 'bypass';
      if (cached.kind === 'rejected') {
        // Not written by this worker fleet's key: scanned again and overwritten (A10).
        this.logger.warn(
          { contentVersion: version },
          'attachment content cache entry rejected (MAC or shape invalid)',
        );
      }
    }

    let release: () => void;
    try {
      release = await options.budget.acquire(row.sizeBytes, signal);
    } catch {
      return fail('timeout', 'timeout');
    }
    try {
      const readStarted = performance.now();
      const read = await options.parts.read(row.objectKey, row.sizeBytes, row.sha256, signal);
      options.metrics.stage('s3_read', seconds(readStarted));
      if (read.kind === 'missing') return fail('error', 'part_unavailable', false);
      if (read.kind === 'integrity') return fail('error', 'part_integrity', false);
      options.metrics.bytes.inc({ stage: 's3_read' }, read.bytes.length);

      const [clamav, inspected] = await Promise.all([
        this.clamavScan(read.bytes, signal),
        this.inspect(read.bytes, signal),
      ]);
      if (clamav.kind === 'failure') return clamav;
      if (inspected.kind === 'failure') return inspected;
      const content: ContentResult = { ...inspected.content, clamav: clamav.clamav };
      if (content.archive) {
        options.metrics.bytes.inc({ stage: 'decompressed' }, content.archive.decompressedBytes);
      }

      // Stored under the version that actually scanned (A10).
      let version: string | null = null;
      if (clamav.version) {
        version = this.versionFor(clamav.version);
        if (options.cache && cacheLabel !== 'bypass') {
          const setStarted = performance.now();
          const stored = await options.cache.set(
            row.sha256,
            version,
            content,
            contentVerdict(content),
          );
          options.metrics.stage('cache_set', seconds(setStarted));
          options.metrics.cache.inc({ result: stored });
        }
      }
      return done(content, cacheLabel, version);
    } catch (error) {
      if (signal.aborted) return fail('timeout', 'timeout');
      throw error;
    } finally {
      release();
    }
  }

  private async clamavScan(
    bytes: Buffer,
    signal: AbortSignal,
  ): Promise<
    | { kind: 'ok'; clamav: ContentResult['clamav']; version: ClamdVersion | null }
    | Extract<Scanned, { kind: 'failure' }>
  > {
    const { options } = this;
    const started = performance.now();
    try {
      const result = await options.clamd.scan(bytes, signal);
      options.versions.observe(result);
      options.metrics.clamav(result.status === 'found' ? 'found' : 'ok', seconds(started));
      options.metrics.stage('clamav', seconds(started));
      return {
        kind: 'ok',
        version: result,
        clamav: {
          status: result.status,
          signature: result.status === 'found' ? result.signature : null,
          engineVersion: result.engine,
          dbVersion: result.dbVersion,
        },
      };
    } catch (error) {
      if (error instanceof ClamdSizeLimitError) {
        options.metrics.clamav('size_limit', seconds(started));
        this.logger.warn(
          { bytes: bytes.length },
          'clamd refused an attachment above its StreamMaxLength (limit.clamav); check StreamMaxLength > ATTACHMENT_MAX_BYTES',
        );
        const version = error.version ?? options.versions.current;
        return {
          kind: 'ok',
          version,
          clamav: {
            status: 'size_limit',
            signature: null,
            engineVersion: version?.engine ?? 'unknown',
            dbVersion: version?.dbVersion ?? 0,
          },
        };
      }
      if (error instanceof ClamdTimeoutError || signal.aborted) {
        options.metrics.clamav('timeout', null);
        return fail('timeout', 'timeout');
      }
      options.metrics.clamav('error', null);
      if (error instanceof ClamdUnavailableError) return fail('error', 'unavailable');
      if (isClamdError(error)) return fail('error', 'protocol_error');
      this.logger.warn(errorFields(error), 'unexpected clamd client error');
      return fail('error', 'protocol_error');
    }
  }

  private async inspect(
    bytes: Buffer,
    signal: AbortSignal,
  ): Promise<
    { kind: 'ok'; content: Omit<ContentResult, 'clamav'> } | Extract<Scanned, { kind: 'failure' }>
  > {
    const started = performance.now();
    const outcome = await this.options.inspector.inspect(bytes, this.options.limits, signal);
    this.options.metrics.stage('inspect', seconds(started));
    switch (outcome.kind) {
      case 'result':
        return { kind: 'ok', content: outcome.result };
      case 'limit':
        return { kind: 'ok', content: killedContent(outcome.code) };
      case 'failure':
        if (outcome.reason === 'wall') return fail('timeout', 'inspector_timeout');
        if (outcome.reason === 'aborted') return fail('timeout', 'timeout');
        return fail('error', 'inspector_crash');
    }
  }

  /** Per-attachment metrics (A19). */
  private record(result: AttachmentResult): void {
    const { metrics } = this.options;
    metrics.file(result.verdict, result.cache);
    for (const code of result.reasonCodes) metrics.finding(code);
    if (result.clamav?.signature) {
      metrics.detections.inc({ source: 'clamav', severity: 'signature' });
    }
    for (const match of result.yara?.matches ?? []) {
      metrics.detections.inc({ source: 'yara', severity: match.severity });
    }
    if (result.knownHash) {
      const severity =
        result.knownHash.severity === 'critical' ? 'high' : result.knownHash.severity;
      metrics.detections.inc({ source: 'known_hash', severity });
    }
  }
}
