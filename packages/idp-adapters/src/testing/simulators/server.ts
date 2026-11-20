/**
 * HTTP host of the provider simulators (design note D12): `node:http`, bound to 127.0.0.1:0
 * in-process (or 0.0.0.0:8080 standalone), each simulator mounted under its prefix (`/graph`,
 * `/o365`, …). Handles failure injection and the call log for every simulator.
 */
import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http';
import type { AddressInfo } from 'node:net';
import type { SimScript } from './script';

export interface SimRequest {
  method: string;
  /** Path after the simulator prefix (decoded segments are left to the simulator). */
  path: string;
  query: URLSearchParams;
  headers: IncomingHttpHeaders;
  body: unknown;
  /** `http://<host><prefix>` as the client addressed it (for provider-style absolute links). */
  publicBase: string;
}

export interface SimResponse {
  status: number;
  headers?: Record<string, string>;
  body?: unknown;
  /** Token subject for the call log. */
  subject?: string;
}

export interface Simulator {
  readonly name: string;
  readonly prefix: string;
  handle(request: SimRequest): SimResponse | Promise<SimResponse>;
  /** Provider-shaped error body. */
  errorBody(status: number, code: string, reason?: string): unknown;
}

export type SimulatorFactory = (script: SimScript) => Simulator;

const MAX_BODY_BYTES = 1024 * 1024;

export type AdminHandler = (request: SimRequest) => SimResponse | Promise<SimResponse> | null;

export class SimulatorServer {
  private server: Server | null = null;
  private port = 0;

  constructor(
    private readonly simulators: readonly Simulator[],
    private readonly script: SimScript,
    private readonly options: { host?: string; port?: number; admin?: AdminHandler } = {},
  ) {}

  async start(): Promise<number> {
    const server = createServer((req, res) => {
      void this.dispatch(req, res);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(this.options.port ?? 0, this.options.host ?? '127.0.0.1', () => resolve());
    });
    this.port = (server.address() as AddressInfo).port;
    return this.port;
  }

  /** Base URL of a mounted simulator (or of the server when `prefix` is empty). */
  url(prefix = ''): string {
    return `http://127.0.0.1:${this.port}${prefix}`;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    if (!server) return;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private async dispatch(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const url = new URL(req.url ?? '/', 'http://simulator.invalid');
      const method = (req.method ?? 'GET').toUpperCase();
      const raw = await readBody(req);
      if (raw === null) {
        send(res, { status: 413, body: { error: { code: 'RequestTooLarge' } } });
        return;
      }
      let body: unknown = undefined;
      if (raw.length > 0) {
        try {
          body = JSON.parse(raw);
        } catch {
          send(res, {
            status: 400,
            body: { error: { code: 'BadRequest', message: 'invalid json' } },
          });
          return;
        }
      }
      const host = req.headers.host ?? `127.0.0.1:${this.port}`;
      if (url.pathname === '/health') {
        send(res, { status: 200, body: { status: 'ok' } });
        return;
      }
      if (this.options.admin) {
        const adminResponse = await this.options.admin({
          method,
          path: url.pathname,
          query: url.searchParams,
          headers: req.headers,
          body,
          publicBase: `http://${host}`,
        });
        if (adminResponse) {
          send(res, adminResponse);
          return;
        }
      }
      const simulator = this.simulators.find(
        (s) => url.pathname === s.prefix || url.pathname.startsWith(`${s.prefix}/`),
      );
      if (!simulator) {
        send(res, { status: 404, body: { error: { code: 'NotFound' } } });
        return;
      }
      const path = url.pathname.slice(simulator.prefix.length) || '/';
      const injection = this.script.take(simulator.name, method, path);
      let response: SimResponse;
      if (injection) {
        if (injection.redirectTo) {
          response = { status: 302, headers: { Location: injection.redirectTo } };
        } else if (injection.rawBody !== undefined) {
          res.writeHead(injection.status, { 'Content-Type': 'application/json' });
          res.end(injection.rawBody);
          this.script.record({
            simulator: simulator.name,
            method,
            path,
            query: url.search,
            status: injection.status,
          });
          return;
        } else {
          response = {
            status: injection.status,
            headers: injection.retryAfter ? { 'Retry-After': injection.retryAfter } : {},
            body: simulator.errorBody(
              injection.status,
              injection.code ?? defaultCode(injection.status),
              injection.reason,
            ),
          };
        }
      } else {
        response = await simulator.handle({
          method,
          path,
          query: url.searchParams,
          headers: req.headers,
          body,
          publicBase: `http://${host}${simulator.prefix}`,
        });
      }
      this.script.record({
        simulator: simulator.name,
        method,
        path,
        query: url.search,
        status: response.status,
        ...(response.subject ? { subject: response.subject } : {}),
      });
      send(res, response);
    } catch {
      send(res, { status: 500, body: { error: { code: 'InternalServerError' } } });
    }
  }
}

function defaultCode(status: number): string {
  if (status === 429) return 'TooManyRequests';
  if (status === 401) return 'InvalidAuthenticationToken';
  if (status === 403) return 'Authorization_RequestDenied';
  if (status === 404) return 'Request_ResourceNotFound';
  if (status >= 500) return 'ServiceUnavailable';
  return 'BadRequest';
}

function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooLarge = false;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(tooLarge ? null : Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function send(res: ServerResponse, response: SimResponse): void {
  const headers: Record<string, string> = { ...(response.headers ?? {}) };
  if (response.body === undefined) {
    res.writeHead(response.status, headers);
    res.end();
    return;
  }
  const payload = JSON.stringify(response.body);
  headers['Content-Type'] = 'application/json';
  headers['Content-Length'] = String(Buffer.byteLength(payload));
  res.writeHead(response.status, headers);
  res.end(payload);
}

/** JSON answer helper. */
export function json(
  status: number,
  body?: unknown,
  headers?: Record<string, string>,
): SimResponse {
  return { status, body, headers };
}
