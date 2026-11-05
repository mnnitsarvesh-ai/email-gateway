import { Readable } from 'node:stream';
import type { ZodType } from 'zod';
import {
  RspamdError,
  RspamdHttpError,
  RspamdProtocolError,
  RspamdRequestError,
  RspamdSoftRejectError,
  RspamdTimeoutError,
  RspamdUnavailableError,
} from './errors';
import { buildRequestHeaders, type RspamdEnvelope } from './headers';
import { InFlightLimiter } from './limiter';
import {
  rspamdCheckReplySchema,
  rspamdStatReplySchema,
  rspamdSuccessReplySchema,
  type RspamdCheckReply,
} from './reply';

/** A message body: streamed when a Readable, sent as is when bytes. Never buffered by the client. */
export type RspamdBody = Readable | Uint8Array;

export interface RspamdClientOptions {
  /** Normal worker (`/checkv2`), e.g. `http://rspamd:11333`. */
  baseUrl: string;
  /** Controller (`/learn*`, `/fuzzy*`, `/stat`), e.g. `http://rspamd:11334`. */
  controllerUrl?: string;
  /** Controller read password (`/stat`). */
  controllerPassword?: string;
  /** Controller enable password (learning, fuzzy add/delete). */
  controllerEnablePassword?: string;
  /** Upper bound of one call, including the wait for an in-flight slot. */
  timeoutMs: number;
  /** Most concurrent HTTP calls of this client (S10); default 8. */
  maxInFlight?: number;
  /** Largest reply body read; default 4 MiB. */
  maxReplyBytes?: number;
  /** Injected fetch (tests); defaults to the Node global fetch. */
  fetch?: typeof fetch;
}

export interface RspamdCheckInput {
  body: RspamdBody;
  /** Exact byte length of the body (sent as Content-Length). */
  sizeBytes: number;
  envelope: RspamdEnvelope;
  /** Ids only, e.g. `m123r0`. */
  logTag: string;
  /** Overrides `eg_inbound` / `eg_outbound` derived from the direction. */
  settingsId?: string;
}

export interface RspamdCheckResult {
  reply: RspamdCheckReply;
  /** Version from the `Server: rspamd/<version>` reply header; null when absent. */
  serverVersion: string | null;
  /** More than RSPAMD_MAX_RCPT_HEADERS recipients: the rest were not sent. */
  rcptTruncated: boolean;
  /** Envelope fields not sent (absent or unsafe values; names only). */
  omittedHeaders: string[];
  durationMs: number;
}

export type RspamdLearnResult = 'learned' | 'already_learned';

export interface RspamdFuzzyResult {
  result: 'added' | 'deleted';
  /** Number of fuzzy hashes Rspamd reported for the message. */
  hashes: number;
}

const DEFAULT_MAX_IN_FLIGHT = 8;
const DEFAULT_MAX_REPLY_BYTES = 4 * 1024 * 1024;
const TIMEOUT_CODES = new Set([
  'ETIMEDOUT',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
]);

/** `rspamd/3.12.1` → `3.12.1`; null for anything else. */
export function parseServerVersion(header: string | null): string | null {
  const match = /^rspamd\/([0-9][0-9A-Za-z.+_-]{0,40})$/.exec(header?.trim() ?? '');
  return match?.[1] ?? null;
}

function errorCode(error: unknown): string | undefined {
  const pick = (value: unknown): string | undefined => {
    if (typeof value !== 'object' || value === null) return undefined;
    const code = (value as { code?: unknown }).code;
    return typeof code === 'string' && /^[A-Z0-9_]{1,48}$/.test(code) ? code : undefined;
  };
  return pick((error as { cause?: unknown } | null)?.cause) ?? pick(error);
}

function isTimeoutReason(reason: unknown): boolean {
  return reason instanceof Error && reason.name === 'TimeoutError';
}

function trimSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

/**
 * HTTP client of Rspamd's own protocol (S9): `/checkv2` on the normal worker and the
 * controller's learning, fuzzy and statistics endpoints. Bodies are streamed with a fixed
 * Content-Length (`duplex: 'half'`), calls are bounded by `timeoutMs` and by an in-flight
 * limiter, and every failure is a typed RspamdError (R0). It decides no platform verdict.
 */
export class RspamdClient {
  private readonly baseUrl: string;
  private readonly controllerUrl: string | null;
  private readonly controllerPassword: string | null;
  private readonly controllerEnablePassword: string | null;
  private readonly timeoutMs: number;
  private readonly maxReplyBytes: number;
  private readonly fetchImpl: typeof fetch;
  private readonly limiter: InFlightLimiter;
  private lastVersion: string | null = null;

  constructor(options: RspamdClientOptions) {
    if (!Number.isInteger(options.timeoutMs) || options.timeoutMs < 1) {
      throw new RangeError('RspamdClient timeoutMs must be a positive integer');
    }
    this.baseUrl = trimSlash(new URL(options.baseUrl).toString());
    this.controllerUrl = options.controllerUrl
      ? trimSlash(new URL(options.controllerUrl).toString())
      : null;
    this.controllerPassword = options.controllerPassword || null;
    this.controllerEnablePassword = options.controllerEnablePassword || null;
    this.timeoutMs = options.timeoutMs;
    this.maxReplyBytes = options.maxReplyBytes ?? DEFAULT_MAX_REPLY_BYTES;
    this.fetchImpl = options.fetch ?? fetch;
    this.limiter = new InFlightLimiter(options.maxInFlight ?? DEFAULT_MAX_IN_FLIGHT);
  }

  /** Version seen in the last `/checkv2` Server header (null before the first call). */
  get lastServerVersion(): string | null {
    return this.lastVersion;
  }

  /** Calls in flight / waiting for a slot (for metrics and tests). */
  get inFlight(): { active: number; waiting: number } {
    return { active: this.limiter.inFlight, waiting: this.limiter.waiting };
  }

  /** Scans one message: `POST /checkv2` with the trusted envelope as request headers. */
  async check(input: RspamdCheckInput, signal?: AbortSignal): Promise<RspamdCheckResult> {
    const built = buildRequestHeaders(input.envelope, {
      logTag: input.logTag,
      ...(input.settingsId === undefined ? {} : { settingsId: input.settingsId }),
    });
    const started = performance.now();
    const { status, headers, json } = await this.request(
      'checkv2',
      `${this.baseUrl}/checkv2`,
      built.headers,
      input.body,
      input.sizeBytes,
      signal,
    );
    if (status !== 200) throw new RspamdProtocolError('checkv2', 'unexpected_reply');
    const reply = this.parse('checkv2', json, rspamdCheckReplySchema);
    if (reply.action === 'soft reject') throw new RspamdSoftRejectError('checkv2');
    const serverVersion = parseServerVersion(headers.get('server'));
    if (serverVersion !== null) this.lastVersion = serverVersion;
    return {
      reply,
      serverVersion,
      rcptTruncated: built.rcptTruncated,
      omittedHeaders: built.omitted,
      durationMs: Math.round(performance.now() - started),
    };
  }

  /** Trains the shared Bayes classifier (controller `/learnspam` or `/learnham`, enable password). */
  async learn(
    kind: 'spam' | 'ham',
    body: RspamdBody,
    sizeBytes: number,
    signal?: AbortSignal,
  ): Promise<RspamdLearnResult> {
    const operation = kind === 'spam' ? 'learnspam' : 'learnham';
    const url = `${this.controller(operation)}/${operation}`;
    const headers = [['Password', this.password(operation, 'enable')]] as Array<[string, string]>;
    const { status, json } = await this.request(operation, url, headers, body, sizeBytes, signal);
    // Rspamd 3.12 answers 208 when this message (by digest) is already learned as that class,
    // and 204 when the learn condition skips it because the classifier already puts it in that
    // class with >= 95% probability (lua_bayes_learn.can_learn).
    if (status === 208 || status === 204) return 'already_learned';
    this.parse(operation, json, rspamdSuccessReplySchema);
    return 'learned';
  }

  /**
   * Adds or deletes the message's fuzzy hashes in the local storage (controller `/fuzzyadd` or
   * `/fuzzydel`, enable password). `flag` selects the list (11 EG_FUZZY_SPAM, 12
   * EG_FUZZY_PHISH); `weight` applies to additions.
   */
  async fuzzy(
    op: 'add' | 'delete',
    flag: number,
    weight: number,
    body: RspamdBody,
    sizeBytes: number,
    signal?: AbortSignal,
  ): Promise<RspamdFuzzyResult> {
    const operation = op === 'add' ? 'fuzzyadd' : 'fuzzydel';
    if (!Number.isInteger(flag) || flag < 1 || flag > 2_147_483_647) {
      throw new RspamdRequestError(operation, 'Flag', 'expected a positive integer');
    }
    if (!Number.isInteger(weight) || weight < 1 || weight > 1_000_000) {
      throw new RspamdRequestError(operation, 'Weight', 'expected an integer 1-1000000');
    }
    const url = `${this.controller(operation)}/${operation}`;
    const headers: Array<[string, string]> = [
      ['Password', this.password(operation, 'enable')],
      ['Flag', String(flag)],
    ];
    if (op === 'add') headers.push(['Weight', String(weight)]);
    const { json } = await this.request(operation, url, headers, body, sizeBytes, signal);
    const reply = this.parse(operation, json, rspamdSuccessReplySchema);
    return { result: op === 'add' ? 'added' : 'deleted', hashes: reply.hashes?.length ?? 0 };
  }

  /** Rspamd version from the controller (`GET /stat`, read password). */
  async version(signal?: AbortSignal): Promise<string> {
    const url = `${this.controller('stat')}/stat`;
    const headers = [['Password', this.password('stat', 'read')]] as Array<[string, string]>;
    const { json } = await this.request('stat', url, headers, null, 0, signal);
    const version = this.parse('stat', json, rspamdStatReplySchema).version;
    this.lastVersion = version;
    return version;
  }

  private controller(operation: string): string {
    if (this.controllerUrl === null) {
      throw new RspamdRequestError(operation, 'controllerUrl', 'not configured');
    }
    return this.controllerUrl;
  }

  private password(operation: string, which: 'read' | 'enable'): string {
    const value = which === 'read' ? this.controllerPassword : this.controllerEnablePassword;
    if (value === null) {
      throw new RspamdRequestError(
        operation,
        which === 'read' ? 'controllerPassword' : 'controllerEnablePassword',
        'not configured',
      );
    }
    return value;
  }

  private parse<T>(operation: string, json: unknown, schema: ZodType<T>): T {
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      const paths = parsed.error.issues.map((issue) => issue.path.join('.') || '(root)');
      throw new RspamdProtocolError(operation, 'schema_mismatch', paths);
    }
    return parsed.data;
  }

  private async request(
    operation: string,
    url: string,
    headerList: Array<[string, string]>,
    body: RspamdBody | null,
    sizeBytes: number,
    signal: AbortSignal | undefined,
  ): Promise<{ status: number; headers: Headers; json: unknown }> {
    if (body !== null) {
      if (!Number.isSafeInteger(sizeBytes) || sizeBytes < 0) {
        throw new RspamdRequestError(operation, 'sizeBytes', 'expected a non-negative integer');
      }
      if (body instanceof Uint8Array && body.byteLength !== sizeBytes) {
        throw new RspamdRequestError(operation, 'sizeBytes', 'does not match the body length');
      }
    }
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;

    // Errors of the caller's stream (e.g. an S3 read failure) are the caller's, not Rspamd's:
    // they are rethrown unchanged so the caller classifies them.
    let sourceError: unknown;
    if (body instanceof Readable) {
      body.once('error', (error) => {
        sourceError = error;
      });
    }

    let release: (() => void) | undefined;
    try {
      release = await this.limiter.acquire(combined);
      const headers = new Headers();
      for (const [name, value] of headerList) headers.append(name, value);
      const init: RequestInit & { duplex?: 'half' } = {
        method: body === null ? 'GET' : 'POST',
        headers,
        signal: combined,
      };
      if (body !== null) {
        headers.set('Content-Length', String(sizeBytes));
        init.body = body;
        init.duplex = 'half';
      }
      const response = await this.fetchImpl(url, init);
      if (response.status >= 400) {
        await response.body?.cancel().catch(() => undefined);
        throw new RspamdHttpError(operation, response.status);
      }
      const text = await this.readText(operation, response);
      let json: unknown;
      try {
        json = text.length === 0 ? null : JSON.parse(text);
      } catch {
        throw new RspamdProtocolError(operation, 'invalid_json');
      }
      return { status: response.status, headers: response.headers, json };
    } catch (error) {
      throw this.classify(operation, error, timeout, signal, sourceError);
    } finally {
      release?.();
      if (body instanceof Readable && !body.destroyed && sourceError === undefined) {
        // A reply before the body was fully sent (e.g. 413): stop reading the source.
        if (!body.readableEnded) body.destroy();
      }
    }
  }

  private async readText(operation: string, response: Response): Promise<string> {
    const declared = Number(response.headers.get('content-length') ?? NaN);
    if (Number.isFinite(declared) && declared > this.maxReplyBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new RspamdProtocolError(operation, 'reply_too_large');
    }
    if (response.body === null) return '';
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > this.maxReplyBytes) {
        await reader.cancel().catch(() => undefined);
        throw new RspamdProtocolError(operation, 'reply_too_large');
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks, total).toString('utf8');
  }

  private classify(
    operation: string,
    error: unknown,
    timeout: AbortSignal,
    signal: AbortSignal | undefined,
    sourceError: unknown,
  ): unknown {
    if (error instanceof RspamdError) return error;
    if (timeout.aborted) return new RspamdTimeoutError(operation, this.timeoutMs);
    if (signal?.aborted) {
      return isTimeoutReason(signal.reason)
        ? new RspamdTimeoutError(operation, null)
        : (signal.reason as unknown);
    }
    if (sourceError !== undefined) return sourceError;
    const code = errorCode(error);
    if (code === 'UND_ERR_REQ_CONTENT_LENGTH_MISMATCH') {
      return new RspamdRequestError(operation, 'sizeBytes', 'does not match the body length');
    }
    if (code !== undefined && TIMEOUT_CODES.has(code)) {
      return new RspamdTimeoutError(operation, this.timeoutMs);
    }
    return new RspamdUnavailableError(operation, code ?? 'fetch_failed');
  }
}
