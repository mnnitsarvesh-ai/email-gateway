import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { Inject, Injectable, Logger, type OnModuleDestroy, Optional } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { API_PREFIX, type OperationTool } from '@email-gateway/assistant';
import { API_CONFIG } from '../../../api-config.token';
import {
  type AssistantConfig,
  EXECUTION_HEADER,
  LOOPBACK_BODY_MAX_BYTES,
  LOOPBACK_USER_AGENT,
} from '../assistant.constants';
import { READ_PRIMARY_HEADER, readPrimaryToken } from './read-primary';

/**
 * The loopback client of the assistant (step AI-1 D2, ADR-0091): a tool is executed by sending the
 * same HTTP request the portal would send to the api's own `/api/v1` pipeline (guards, RBAC,
 * tenant scope, MFA, rate limits, validation, masking, audit), with the turn request's own
 * credential. Nothing in the api trusts a header from here.
 *
 * Headers are exactly: `authorization` (the incoming request's, verbatim), `x-correlation-id`
 * (`<turn correlation>.<seq>`), `x-eg-client-ip` + `x-eg-forwarder-token` (only when
 * API_TRUSTED_FORWARDER_TOKEN is set and the client IP is known), `accept: application/json`,
 * `user-agent: eg-assistant/1`, `x-eg-assistant-execution` (informational), for a confirmed
 * write of an operation with `required`/`legacy` idempotency `idempotency-key` (the confirmation
 * public id, step AI-2 D2 step 13), for a precondition read of a confirmation (GET only)
 * `x-eg-assistant-read-primary` (a server token derived from AUTH_TOKEN_PEPPER; the route then
 * reads the MySQL writer, never a lagging replica: step AI-2 review) and, for a request with a
 * JSON body only, `content-type: application/json` (+ the transport's `content-length`, `host`
 * and `connection`). No header value ever comes from model output.
 */

export type HttpMethod = OperationTool['method'];

export interface LoopbackCall {
  method: HttpMethod;
  /** Path and query below the api origin, already encoded (`/api/v1/...`). */
  path: string;
  /** JSON body (side-effect-free POSTs; writes from AI-2). */
  body?: unknown;
  /** The turn request's `authorization` header, verbatim. */
  authorization: string;
  correlationId: string;
  /** The end user's resolved client IP (`@Client()` of the turn request). */
  clientIp: string | null;
  /** Public id of the execution (informational header); null for internal context reads. */
  executionId: string | null;
  /** Aborts the call (turn cancellation or deadline). */
  signal: AbortSignal;
  /**
   * `Idempotency-Key` of a confirmed write (the confirmation public id; a server value, never
   * model output). Set by the executor only for `required`/`legacy` operations.
   */
  idempotencyKey?: string;
  /**
   * A precondition read of a confirmation (GET only, never set from model output): the route
   * reads the writer (`x-eg-assistant-read-primary`), so replica lag cannot hide a change.
   */
  readPrimary?: boolean;
}

/**
 * True for a path below the api's `/api/v1` prefix (step AI-R D1 defence: native tools have
 * `native:` path templates and are never sent through the loopback).
 */
export function isApiPath(path: string): boolean {
  return path.startsWith(`${API_PREFIX}/`);
}

/** The api's `Idempotency-Key` format (`apps/api/src/http/idempotency/idempotency-key.ts`). */
export const LOOPBACK_IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{1,128}$/;

export type LoopbackResult =
  | { kind: 'response'; status: number; body: unknown }
  | { kind: 'too_large'; status: number }
  | { kind: 'timeout' }
  | { kind: 'aborted' }
  | { kind: 'unavailable' };

/** The transport (tests replace the client with a fake dispatcher). */
export abstract class LoopbackDispatcher {
  abstract send(call: LoopbackCall): Promise<LoopbackResult>;
}

/** The exact header set of a loopback request (D2). */
export function buildLoopbackHeaders(
  call: Pick<
    LoopbackCall,
    | 'authorization'
    | 'correlationId'
    | 'clientIp'
    | 'executionId'
    | 'idempotencyKey'
    | 'readPrimary'
  > & { method?: HttpMethod },
  forwarderToken: string | undefined,
  bodyBytes: number | null,
  readPrimary?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    authorization: call.authorization,
    'x-correlation-id': call.correlationId,
    accept: 'application/json',
    'user-agent': LOOPBACK_USER_AGENT,
  };
  if (forwarderToken && call.clientIp) {
    headers['x-eg-client-ip'] = call.clientIp;
    headers['x-eg-forwarder-token'] = forwarderToken;
  }
  if (call.executionId) headers[EXECUTION_HEADER] = call.executionId;
  if (call.idempotencyKey !== undefined) {
    if (!LOOPBACK_IDEMPOTENCY_KEY.test(call.idempotencyKey)) {
      throw new Error('loopback: the idempotency key is not a valid Idempotency-Key value');
    }
    headers['idempotency-key'] = call.idempotencyKey;
  }
  if (call.readPrimary === true) {
    if (call.method !== 'GET' || !readPrimary) {
      throw new Error('loopback: a read-primary call must be a GET with the server token');
    }
    headers[READ_PRIMARY_HEADER] = readPrimary;
  }
  if (bodyBytes !== null) {
    headers['content-type'] = 'application/json';
    headers['content-length'] = String(bodyBytes);
  }
  return headers;
}

/**
 * The concrete path and query of a tool call from VALIDATED arguments (D2): path parameters are
 * `encodeURIComponent`ed, the query is built from the declared query parameters only
 * (booleans and numbers as text, lists comma-joined), and the JSON body is `arguments.body` for
 * operations that take one. Anything else in the arguments is ignored (the schema forbids it).
 */
export function buildLoopbackRequest(
  tool: Pick<OperationTool, 'method' | 'pathTemplate' | 'pathParams' | 'queryParams' | 'hasBody'>,
  args: Readonly<Record<string, unknown>>,
): { method: HttpMethod; path: string; body?: unknown } {
  if (!isApiPath(tool.pathTemplate)) {
    throw new Error('loopback: the tool path template is not under /api/v1');
  }
  let path = tool.pathTemplate;
  for (const name of tool.pathParams) {
    const value = args[name];
    if (typeof value !== 'string' && typeof value !== 'number') {
      throw new Error(`loopback: path parameter ${name} missing after validation`);
    }
    if (!isSafePathSegment(String(value))) {
      throw new Error(`loopback: path parameter ${name} is not a single path segment`);
    }
    path = path.replace(`{${name}}`, encodeURIComponent(String(value)));
  }
  if (!pathMatchesTemplate(path, tool.pathTemplate)) {
    throw new Error('loopback: the built path does not match the tool path template');
  }
  const query = new URLSearchParams();
  for (const name of tool.queryParams) {
    const value = args[name];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) query.append(name, value.map((v) => scalarText(v)).join(','));
    else query.append(name, scalarText(value));
  }
  const qs = query.toString();
  return {
    method: tool.method,
    path: qs ? `${path}?${qs}` : path,
    ...(tool.hasBody && args.body !== undefined ? { body: args.body } : {}),
  };
}

/**
 * A path parameter value that stays ONE path segment after URL resolution (step AI-1 review):
 * `encodeURIComponent` leaves `.` unescaped, so `''`, `.` and `..` would be collapsed or removed
 * by `new URL()` (e.g. `/grants/..` → the parent route) and the executed route would differ from
 * the registered tool. The schema of many ids is a plain string, so this is checked here.
 */
export function isSafePathSegment(value: string): boolean {
  return value.length > 0 && value !== '.' && value !== '..';
}

/** Names of the path parameters whose values are not a safe single segment. */
export function unsafePathParams(
  tool: Pick<OperationTool, 'pathParams'>,
  args: Readonly<Record<string, unknown>>,
): string[] {
  return tool.pathParams.filter((name) => {
    const value = args[name];
    return (
      (typeof value === 'string' || typeof value === 'number') && !isSafePathSegment(String(value))
    );
  });
}

/**
 * True when `path` (no query) has the template's segments: literal segments equal, each
 * `{param}` segment one non-empty segment other than `.`/`..`.
 */
export function pathMatchesTemplate(path: string, template: string): boolean {
  const actual = path.split('/');
  const expected = template.split('/');
  if (actual.length !== expected.length) return false;
  return expected.every((segment, index) => {
    const value = actual[index]!;
    if (/^\{[^}]+\}$/.test(segment)) return isSafePathSegment(value);
    return value === segment;
  });
}

/** Text of a validated query value (objects as JSON; never `[object Object]`). */
function scalarText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return JSON.stringify(value) ?? '';
}

/** The listening address of this process (`HttpAdapterHost`), resolved lazily. */
export function loopbackBaseUrl(
  configured: string | undefined,
  server: { address(): AddressInfo | string | null } | undefined,
  fallbackPort: number,
): string {
  if (configured) return configured.replace(/\/+$/, '');
  const address = server?.address();
  const port = address && typeof address === 'object' ? address.port : fallbackPort;
  return `http://127.0.0.1:${port}`;
}

@Injectable()
export class LoopbackClient extends LoopbackDispatcher implements OnModuleDestroy {
  private readonly logger = new Logger(LoopbackClient.name);
  private readonly httpAgent: http.Agent;
  private readonly httpsAgent: https.Agent;
  /** Value of `x-eg-assistant-read-primary` (precondition reads of confirmations). */
  private readonly readPrimary: string | undefined;

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    @Optional() private readonly adapterHost?: HttpAdapterHost,
  ) {
    super();
    const maxSockets = Math.max(2, config.ASSISTANT_MAX_CONCURRENT_TURNS * 2);
    this.httpAgent = new http.Agent({ keepAlive: true, maxSockets, maxFreeSockets: maxSockets });
    this.httpsAgent = new https.Agent({ keepAlive: true, maxSockets, maxFreeSockets: maxSockets });
    this.readPrimary = config.AUTH_TOKEN_PEPPER
      ? readPrimaryToken(config.AUTH_TOKEN_PEPPER)
      : undefined;
  }

  onModuleDestroy(): void {
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
  }

  baseUrl(): string {
    const server = this.adapterHost?.httpAdapter?.getHttpServer?.() as
      { address(): AddressInfo | string | null } | undefined;
    return loopbackBaseUrl(this.config.ASSISTANT_LOOPBACK_URL, server, this.config.HTTP_PORT);
  }

  send(call: LoopbackCall): Promise<LoopbackResult> {
    if (call.signal.aborted) return Promise.resolve({ kind: 'aborted' });
    if (!isApiPath(call.path)) {
      this.logger.warn({ message: 'Loopback path outside /api/v1; call refused' });
      return Promise.resolve({ kind: 'unavailable' });
    }
    const url = new URL(call.path, `${this.baseUrl()}/`);
    // Defence in depth: the resolved path must be the one built from the tool's template (no
    // dot-segment collapse, no different route than the one recorded and audited).
    const expectedPath = call.path.split('?')[0]!;
    if (url.pathname !== expectedPath) {
      this.logger.warn({ message: 'Loopback path changed by URL resolution; call refused' });
      return Promise.resolve({ kind: 'unavailable' });
    }
    const payload = call.body === undefined ? null : Buffer.from(JSON.stringify(call.body), 'utf8');
    const headers = buildLoopbackHeaders(
      call,
      this.config.API_TRUSTED_FORWARDER_TOKEN,
      payload === null ? null : payload.byteLength,
      this.readPrimary,
    );
    const secure = url.protocol === 'https:';
    const transport = secure ? https : http;
    const timeoutMs = this.config.ASSISTANT_TOOL_TIMEOUT_MS;

    return new Promise<LoopbackResult>((resolve) => {
      let settled = false;
      const finish = (result: LoopbackResult): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        call.signal.removeEventListener('abort', onAbort);
        resolve(result);
      };
      const req = transport.request(
        url,
        { method: call.method, headers, agent: secure ? this.httpsAgent : this.httpAgent },
        (res) => {
          const status = res.statusCode ?? 0;
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.byteLength;
            if (size > LOOPBACK_BODY_MAX_BYTES) {
              res.destroy();
              finish({ kind: 'too_large', status });
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let body: unknown = null;
            if (text.length > 0) {
              try {
                body = JSON.parse(text);
              } catch {
                body = null;
              }
            }
            finish({ kind: 'response', status, body });
          });
          res.on('error', () => finish({ kind: 'unavailable' }));
        },
      );
      const timer = setTimeout(() => {
        finish({ kind: 'timeout' });
        req.destroy();
      }, timeoutMs);
      const onAbort = (): void => {
        finish({ kind: 'aborted' });
        req.destroy();
      };
      call.signal.addEventListener('abort', onAbort, { once: true });
      req.on('error', (error: NodeJS.ErrnoException) => {
        if (!settled) this.logger.warn({ message: 'Loopback call failed', code: error.code });
        finish({ kind: 'unavailable' });
      });
      if (payload !== null) req.write(payload);
      req.end();
    });
  }
}
