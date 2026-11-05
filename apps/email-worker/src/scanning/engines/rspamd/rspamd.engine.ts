import { performance } from 'node:perf_hooks';
import type { Readable } from 'node:stream';
import {
  isRspamdError,
  normalizeReply,
  type RspamdCheckInput,
  type RspamdCheckResult,
  type RspamdError,
} from '@email-gateway/rspamd';
import {
  normalizedEngineResultSchema,
  type RspamdEffectiveSettings,
} from '@email-gateway/security-contracts';
import {
  EmlUnavailableError,
  type EngineFailure,
  type EngineScanContext,
  type EngineScanOutcome,
  type ScanEngineAdapter,
} from '../../engine';
import { mapRspamdVerdict, RSPAMD_MAPPING_VERSION } from './verdict-mapper';

/** The parts of `RspamdClient` the engine uses (a fake in unit tests). */
export interface RspamdScanClient {
  check(input: RspamdCheckInput, signal?: AbortSignal): Promise<RspamdCheckResult>;
  version(signal?: AbortSignal): Promise<string>;
}

export interface RspamdEngineOptions {
  client: RspamdScanClient;
  /** SCAN_RSPAMD_MAX_BYTES: larger messages are not sent (R1 `engine.too_large`). */
  maxBytes: number;
  /** SCAN_ENGINE_VERSION_TTL_MS. */
  versionTtlMs: number;
  /** Whether the controller (read password) can answer `/stat` for the version. */
  controllerConfigured: boolean;
  /** Monotonic milliseconds (tests). */
  now?: () => number;
}

/** Longest wait for the controller's `/stat` when a reply carried no version. */
const VERSION_LOOKUP_TIMEOUT_MS = 2_000;

/** R0: a typed transport failure of the client → an attempt failure. */
export function failureFromRspamd(
  error: RspamdError,
  durationMs: number,
  engineVersion: string | null,
): EngineFailure {
  const base = { kind: 'failure' as const, durationMs, engineVersion };
  switch (error.kind) {
    case 'timeout':
      return { ...base, outcome: 'timeout', errorCode: 'timeout', retryable: true };
    case 'unavailable':
      return { ...base, outcome: 'error', errorCode: 'unavailable', retryable: true };
    case 'http_error':
      return { ...base, outcome: 'error', errorCode: 'http_error', retryable: error.retryable };
    case 'protocol_error':
      return { ...base, outcome: 'error', errorCode: 'protocol_error', retryable: true };
    case 'soft_reject':
      return { ...base, outcome: 'error', errorCode: 'soft_reject', retryable: true };
    case 'invalid_request':
      // The request cannot be built from this message's envelope: repeating it never helps,
      // and it says nothing about Rspamd's health.
      return {
        ...base,
        outcome: 'error',
        errorCode: 'invalid_request',
        retryable: false,
        engineFault: false,
      };
  }
}

/**
 * The Rspamd engine adapter (step 4.1 S9): builds the request from the trusted envelope of the
 * writer row (S9 headers; `User` only for outbound and internal mail, done by
 * `buildRequestHeaders`), refuses messages above SCAN_RSPAMD_MAX_BYTES without a call (R1
 * `engine.too_large`), streams the EML from S3 to `/checkv2`, normalizes the reply and maps it
 * (S7) into a schema-validated `NormalizedEngineResult` with bounded evidence (≤ 200 signals,
 * ≤ 5 options of ≤ 200 characters each). Transport failures are attempt failures (R0); a
 * missing EML is the non-retryable failure `eml_unavailable`; an S3 outage while opening or
 * streaming is thrown (infrastructure, transient). Symbol options are never logged.
 */
export class RspamdEngine implements ScanEngineAdapter {
  readonly name = 'rspamd' as const;
  private readonly now: () => number;
  private cached: { version: string; at: number } | null = null;

  constructor(private readonly options: RspamdEngineOptions) {
    this.now = options.now ?? (() => performance.now());
  }

  /** The last known engine version (no call). */
  get knownVersion(): string | null {
    return this.cached?.version ?? null;
  }

  async scan(ctx: EngineScanContext, signal: AbortSignal): Promise<EngineScanOutcome> {
    const started = this.now();
    const elapsed = () => Math.max(0, Math.round(this.now() - started));
    const settings = ctx.settings as RspamdEffectiveSettings;

    if (ctx.eml.sizeBytes > this.options.maxBytes) {
      const engineVersion = await this.engineVersion(null, signal);
      return {
        kind: 'definite',
        result: normalizedEngineResultSchema.parse({
          engine: this.name,
          engineVersion: engineVersion ?? 'unknown',
          outcome: 'unknown',
          score: null,
          requiredScore: null,
          action: null,
          reasonCodes: ['engine.too_large'],
          signals: [],
          durationMs: elapsed(),
          settingsVersion: ctx.settingsVersion,
          mappingVersion: RSPAMD_MAPPING_VERSION,
        }),
      };
    }

    let body: Readable;
    try {
      body = await ctx.eml.open(signal);
    } catch (err) {
      if (err instanceof EmlUnavailableError) {
        return {
          kind: 'failure',
          outcome: 'error',
          errorCode: 'eml_unavailable',
          retryable: false,
          engineFault: false,
          durationMs: elapsed(),
          engineVersion: this.knownVersion,
        };
      }
      throw err;
    }

    let checked: RspamdCheckResult;
    try {
      checked = await this.options.client.check(
        {
          body,
          sizeBytes: ctx.eml.sizeBytes,
          envelope: {
            direction: ctx.direction,
            organizationId: ctx.organizationId,
            clientIp: ctx.envelope.clientIp,
            clientHelo: ctx.envelope.clientHelo,
            clientName: ctx.envelope.clientName,
            envelopeFrom: ctx.envelope.envelopeFrom,
            recipients: ctx.envelope.recipients,
            queueId: ctx.envelope.queueId,
          },
          logTag: `m${ctx.messageId.toString()}r${String(ctx.round)}`,
        },
        signal,
      );
    } catch (err) {
      if (!body.destroyed) body.destroy();
      if (isRspamdError(err)) return failureFromRspamd(err, elapsed(), this.knownVersion);
      // An error of the EML stream (S3) is the caller's: infrastructure, transient.
      throw err;
    }

    const engineVersion = await this.engineVersion(checked.serverVersion, signal);
    const normalized = normalizeReply(checked.reply, {
      envelopeFrom: ctx.envelope.envelopeFrom,
      helo: ctx.envelope.clientHelo,
    });
    const mapped = mapRspamdVerdict(normalized, settings);
    const parsed = normalizedEngineResultSchema.safeParse({
      engine: this.name,
      engineVersion: engineVersion ?? 'unknown',
      outcome: mapped.outcome,
      score: normalized.score,
      requiredScore: normalized.requiredScore,
      action: normalized.action.length > 0 ? normalized.action.slice(0, 32) : null,
      reasonCodes: mapped.reasonCodes,
      signals: normalized.symbols,
      auth: normalized.auth,
      durationMs: elapsed(),
      settingsVersion: ctx.settingsVersion,
      mappingVersion: RSPAMD_MAPPING_VERSION,
    });
    if (!parsed.success) {
      // A reply the client accepted but our result contract refuses: never clean (R0).
      return {
        kind: 'failure',
        outcome: 'error',
        errorCode: 'protocol_error',
        retryable: true,
        durationMs: elapsed(),
        engineVersion,
      };
    }
    return {
      kind: 'definite',
      result: parsed.data,
      ...(checked.rcptTruncated ? { evidence: { rcptTruncated: true } } : {}),
    };
  }

  /**
   * The version from the reply's `Server` header when present (no extra call); otherwise the
   * cached one within SCAN_ENGINE_VERSION_TTL_MS, else the controller's `/stat` (best effort).
   */
  private async engineVersion(
    fromReply: string | null,
    signal: AbortSignal,
  ): Promise<string | null> {
    const now = this.now();
    if (fromReply !== null) {
      this.cached = { version: fromReply, at: now };
      return fromReply;
    }
    if (this.cached && now - this.cached.at < this.options.versionTtlMs) return this.cached.version;
    if (!this.options.controllerConfigured || signal.aborted) return this.knownVersion;
    try {
      const version = await this.options.client.version(
        AbortSignal.any([signal, AbortSignal.timeout(VERSION_LOOKUP_TIMEOUT_MS)]),
      );
      this.cached = { version, at: now };
      return version;
    } catch {
      return this.knownVersion;
    }
  }
}
