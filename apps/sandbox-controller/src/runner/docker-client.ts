import http, { type IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';

/**
 * Minimal Docker Engine API client over the unix socket (step 4.6 X6; docs/plan/steps/14-sandbox.md).
 * Used ONLY by the local/CI `hardened-container` backend, which is NOT a VM boundary. `node:http`
 * with `socketPath`, no dependency (dockerode rejected, §7). Endpoints: `_ping`, `version`,
 * `info`, `images/{name}/json`, `networks/{name}`, `containers/create`, `containers/{id}/json`,
 * `start`, `attach` (hijacked stream: stdin + multiplexed stdout/stderr), `wait`, `kill`,
 * `DELETE ?force=true&v=true`, `containers/json?filters=…`.
 *
 * Version negotiation: the first call reads `/version` (unversioned) and pins
 * `min(server ApiVersion, MAX_API_VERSION)`; a server older than `MIN_API_VERSION` (1.43) or one
 * whose minimum is above the client maximum is refused. Every response body is bounded
 * (`maxResponseBytes`), every request except `wait` and `attach` has a timeout, and the attach
 * stream's stdout is collected up to a cap (the rest is drained and counted, never stored).
 */

export const MIN_API_VERSION = '1.43';
export const MAX_API_VERSION = '1.47';

export class DockerApiError extends Error {
  constructor(
    readonly operation: string,
    readonly statusCode: number | null,
    message: string,
  ) {
    super(`docker ${operation} failed${statusCode === null ? '' : ` (${statusCode})`}: ${message}`);
    this.name = 'DockerApiError';
  }
}

/** The daemon could not be reached at all (socket missing, refused, timed out). */
export class DockerUnreachableError extends Error {
  constructor(
    readonly operation: string,
    readonly causeCode: string,
  ) {
    super(`docker unreachable during ${operation}: ${causeCode}`);
    this.name = 'DockerUnreachableError';
  }
}

export interface DockerVersion {
  Version: string;
  ApiVersion: string;
  MinAPIVersion?: string;
  Os?: string;
  Arch?: string;
  KernelVersion?: string;
}

export interface DockerInfo {
  SecurityOptions?: string[] | null;
  CgroupVersion?: string;
  KernelVersion?: string;
  OperatingSystem?: string;
  ServerVersion?: string;
}

export interface ImageInspect {
  Id: string;
  RepoTags?: string[] | null;
  Size?: number;
}

export interface NetworkInspect {
  Id: string;
  Name: string;
  Internal: boolean;
  Options?: Record<string, string> | null;
  IPAM?: { Config?: Array<{ Subnet?: string; Gateway?: string; IPRange?: string }> | null };
  Containers?: Record<string, { Name?: string; IPv4Address?: string }> | null;
}

/** The subset of `containers/{id}/json` the backend reads (unknown fields are ignored). */
export interface ContainerInspect {
  Id: string;
  Name?: string;
  Image?: string;
  AppArmorProfile?: string;
  Mounts?: unknown[] | null;
  State?: {
    Status?: string;
    Running?: boolean;
    OOMKilled?: boolean;
    ExitCode?: number;
    Error?: string;
    StartedAt?: string;
    FinishedAt?: string;
  };
  Config?: {
    User?: string;
    Image?: string;
    Env?: string[] | null;
    Labels?: Record<string, string> | null;
    Hostname?: string;
    Entrypoint?: string[] | string | null;
    Cmd?: string[] | string | null;
    WorkingDir?: string;
    OpenStdin?: boolean;
    StdinOnce?: boolean;
    Tty?: boolean;
    NetworkDisabled?: boolean;
    ExposedPorts?: Record<string, unknown> | null;
  };
  HostConfig?: Record<string, unknown>;
  NetworkSettings?: {
    Networks?: Record<string, { IPAddress?: string; Gateway?: string; Aliases?: string[] | null }>;
    Ports?: Record<string, unknown> | null;
  };
}

export interface ContainerSummary {
  Id: string;
  Names?: string[];
  Image?: string;
  State?: string;
  Labels?: Record<string, string> | null;
  Created?: number;
}

export interface WaitResult {
  StatusCode: number;
  Error?: { Message?: string } | null;
}

/** What `collect()` of an attach stream returns. */
export interface AttachOutput {
  stdout: Buffer;
  stdoutBytes: number;
  stdoutTruncated: boolean;
  stderrBytes: number;
  /** The multiplexed framing itself was malformed (an unknown stream id). */
  framingError: boolean;
}

export interface AttachStream {
  /** Writes to the container's stdin. */
  write(data: Buffer): Promise<void>;
  /** Half-closes stdin (EOF for the container; `StdinOnce` closes it there). */
  endStdin(): void;
  /** Resolves when the stream ends (container exited or the stream was destroyed). */
  collect(): Promise<AttachOutput>;
  destroy(): void;
}

/** The operations the hardened-container backend needs; the unit tests implement it with a fake. */
export interface DockerApi {
  ping(signal?: AbortSignal): Promise<void>;
  version(signal?: AbortSignal): Promise<DockerVersion>;
  info(signal?: AbortSignal): Promise<DockerInfo>;
  inspectImage(reference: string, signal?: AbortSignal): Promise<ImageInspect | null>;
  inspectNetwork(name: string, signal?: AbortSignal): Promise<NetworkInspect | null>;
  createContainer(spec: object, name: string, signal?: AbortSignal): Promise<{ Id: string }>;
  inspectContainer(id: string, signal?: AbortSignal): Promise<ContainerInspect | null>;
  startContainer(id: string, signal?: AbortSignal): Promise<void>;
  attachContainer(id: string, options: { maxStdoutBytes: number }): Promise<AttachStream>;
  waitContainer(id: string, signal?: AbortSignal): Promise<WaitResult>;
  /** Tolerates an already stopped (409) or removed (404) container. */
  killContainer(id: string, signal?: AbortSignal): Promise<void>;
  /** `DELETE ?force=true&v=true`; false when the container did not exist (404). */
  removeContainer(id: string, signal?: AbortSignal): Promise<boolean>;
  listContainers(labels: readonly string[], signal?: AbortSignal): Promise<ContainerSummary[]>;
}

export interface DockerClientOptions {
  socketPath: string;
  /** Per-request timeout of the short calls (default 15 s). */
  requestTimeoutMs?: number;
  /** Bound of every JSON response body (default 4 MiB). */
  maxResponseBytes?: number;
}

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const IMAGE_REFERENCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$/;

/** Compares dotted API versions numerically (`1.43` < `1.47` < `1.100`). */
export function compareApiVersions(a: string, b: string): number {
  const pa = a.split('.').map((n) => Number.parseInt(n, 10));
  const pb = b.split('.').map((n) => Number.parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

/** The API version the client pins for a server (pure; throws when incompatible). */
export function negotiateApiVersion(server: {
  ApiVersion: string;
  MinAPIVersion?: string;
}): string {
  if (!/^\d+\.\d+$/.test(server.ApiVersion)) {
    throw new DockerApiError('version', null, 'unparseable ApiVersion');
  }
  if (compareApiVersions(server.ApiVersion, MIN_API_VERSION) < 0) {
    throw new DockerApiError(
      'version',
      null,
      `daemon API ${server.ApiVersion} < ${MIN_API_VERSION}`,
    );
  }
  const pinned =
    compareApiVersions(server.ApiVersion, MAX_API_VERSION) < 0
      ? server.ApiVersion
      : MAX_API_VERSION;
  if (server.MinAPIVersion && compareApiVersions(server.MinAPIVersion, pinned) > 0) {
    throw new DockerApiError(
      'version',
      null,
      `daemon minimum API ${server.MinAPIVersion} > client ${pinned}`,
    );
  }
  return pinned;
}

/**
 * Demultiplexes Docker's attach stream (`Tty: false`): frames of
 * `u8 stream | 0 0 0 | u32be length | payload`, stream 1 = stdout, 2 = stderr (0 = stdin echo,
 * ignored). Stdout is kept up to `maxStdoutBytes`; the rest is counted only.
 */
export class DockerStreamDemuxer {
  private pending = Buffer.alloc(0);
  private readonly stdoutChunks: Buffer[] = [];
  private kept = 0;
  private stdoutBytes = 0;
  private stderrBytes = 0;
  private truncated = false;
  private framingError = false;
  private remaining = 0;
  private currentStream = 0;

  constructor(private readonly maxStdoutBytes: number) {}

  push(chunk: Buffer): void {
    if (this.framingError) return;
    let data = this.pending.length > 0 ? Buffer.concat([this.pending, chunk]) : chunk;
    this.pending = Buffer.alloc(0);
    while (data.length > 0) {
      if (this.remaining === 0) {
        if (data.length < 8) {
          this.pending = Buffer.from(data);
          return;
        }
        const stream = data.readUInt8(0);
        if (stream > 2 || data[1] !== 0 || data[2] !== 0 || data[3] !== 0) {
          this.framingError = true;
          return;
        }
        this.currentStream = stream;
        this.remaining = data.readUInt32BE(4);
        data = data.subarray(8);
        continue;
      }
      const take = Math.min(this.remaining, data.length);
      const payload = data.subarray(0, take);
      this.remaining -= take;
      data = data.subarray(take);
      if (this.currentStream === 1) this.onStdout(payload);
      else if (this.currentStream === 2) this.stderrBytes += payload.length;
    }
  }

  private onStdout(payload: Buffer): void {
    this.stdoutBytes += payload.length;
    if (this.kept >= this.maxStdoutBytes) {
      this.truncated = true;
      return;
    }
    const room = this.maxStdoutBytes - this.kept;
    if (payload.length > room) this.truncated = true;
    const part = Buffer.from(payload.subarray(0, room));
    this.stdoutChunks.push(part);
    this.kept += part.length;
  }

  result(): AttachOutput {
    return {
      stdout: Buffer.concat(this.stdoutChunks),
      stdoutBytes: this.stdoutBytes,
      stdoutTruncated: this.truncated,
      stderrBytes: this.stderrBytes,
      framingError: this.framingError || this.pending.length > 0 || this.remaining > 0,
    };
  }
}

const UNREACHABLE_CODES = new Set([
  'ENOENT',
  'ECONNREFUSED',
  'EACCES',
  'ECONNRESET',
  'EPIPE',
  'ETIMEDOUT',
  'ENOTSOCK',
]);

interface RawResponse {
  statusCode: number;
  body: Buffer;
}

export class DockerClient implements DockerApi {
  private apiVersion: string | null = null;
  private negotiating: Promise<string> | null = null;
  private readonly requestTimeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(private readonly options: DockerClientOptions) {
    this.requestTimeoutMs = options.requestTimeoutMs ?? 15_000;
    this.maxResponseBytes = options.maxResponseBytes ?? 4 * 1024 * 1024;
  }

  /** The pinned API version (after the first call). */
  get negotiatedVersion(): string | null {
    return this.apiVersion;
  }

  async ping(signal?: AbortSignal): Promise<void> {
    const res = await this.raw('ping', 'GET', '/_ping', { signal, versioned: false });
    if (res.statusCode !== 200) throw new DockerApiError('ping', res.statusCode, 'not ok');
  }

  async version(signal?: AbortSignal): Promise<DockerVersion> {
    const res = await this.raw('version', 'GET', '/version', { signal, versioned: false });
    return this.json<DockerVersion>('version', res, [200]);
  }

  async info(signal?: AbortSignal): Promise<DockerInfo> {
    return this.json<DockerInfo>('info', await this.raw('info', 'GET', '/info', { signal }), [200]);
  }

  async inspectImage(reference: string, signal?: AbortSignal): Promise<ImageInspect | null> {
    if (!IMAGE_REFERENCE_PATTERN.test(reference)) throw new Error('invalid image reference');
    const res = await this.raw(
      'image inspect',
      'GET',
      `/images/${encodeURIComponent(reference)}/json`,
      { signal },
    );
    if (res.statusCode === 404) return null;
    return this.json<ImageInspect>('image inspect', res, [200]);
  }

  async inspectNetwork(name: string, signal?: AbortSignal): Promise<NetworkInspect | null> {
    assertId(name);
    const res = await this.raw('network inspect', 'GET', `/networks/${encodeURIComponent(name)}`, {
      signal,
    });
    if (res.statusCode === 404) return null;
    return this.json<NetworkInspect>('network inspect', res, [200]);
  }

  async createContainer(spec: object, name: string, signal?: AbortSignal): Promise<{ Id: string }> {
    assertId(name);
    const res = await this.raw(
      'create',
      'POST',
      `/containers/create?name=${encodeURIComponent(name)}`,
      { signal, body: Buffer.from(JSON.stringify(spec), 'utf8') },
    );
    const created = this.json<{ Id?: unknown }>('create', res, [201]);
    if (typeof created.Id !== 'string' || !/^[0-9a-f]{64}$/.test(created.Id)) {
      throw new DockerApiError('create', res.statusCode, 'no container id');
    }
    return { Id: created.Id };
  }

  async inspectContainer(id: string, signal?: AbortSignal): Promise<ContainerInspect | null> {
    assertId(id);
    const res = await this.raw('inspect', 'GET', `/containers/${id}/json`, { signal });
    if (res.statusCode === 404) return null;
    return this.json<ContainerInspect>('inspect', res, [200]);
  }

  async startContainer(id: string, signal?: AbortSignal): Promise<void> {
    assertId(id);
    const res = await this.raw('start', 'POST', `/containers/${id}/start`, { signal });
    if (res.statusCode !== 204 && res.statusCode !== 304) {
      throw new DockerApiError('start', res.statusCode, errorMessage(res.body));
    }
  }

  async waitContainer(id: string, signal?: AbortSignal): Promise<WaitResult> {
    assertId(id);
    const res = await this.raw('wait', 'POST', `/containers/${id}/wait?condition=not-running`, {
      signal,
      timeoutMs: 0,
    });
    const result = this.json<WaitResult>('wait', res, [200]);
    if (typeof result.StatusCode !== 'number') throw new DockerApiError('wait', 200, 'no status');
    return result;
  }

  async killContainer(id: string, signal?: AbortSignal): Promise<void> {
    assertId(id);
    const res = await this.raw('kill', 'POST', `/containers/${id}/kill?signal=SIGKILL`, { signal });
    if (![204, 404, 409].includes(res.statusCode)) {
      throw new DockerApiError('kill', res.statusCode, errorMessage(res.body));
    }
  }

  async removeContainer(id: string, signal?: AbortSignal): Promise<boolean> {
    assertId(id);
    const res = await this.raw('remove', 'DELETE', `/containers/${id}?force=true&v=true`, {
      signal,
    });
    if (res.statusCode === 404) return false;
    if (res.statusCode !== 204) {
      throw new DockerApiError('remove', res.statusCode, errorMessage(res.body));
    }
    return true;
  }

  async listContainers(
    labels: readonly string[],
    signal?: AbortSignal,
  ): Promise<ContainerSummary[]> {
    for (const label of labels) {
      if (!/^[A-Za-z0-9._-]{1,64}(=[A-Za-z0-9._:-]{0,128})?$/.test(label)) {
        throw new Error('invalid label filter');
      }
    }
    const filters = encodeURIComponent(JSON.stringify({ label: labels }));
    const res = await this.raw('list', 'GET', `/containers/json?all=1&filters=${filters}`, {
      signal,
    });
    const list = this.json<unknown>('list', res, [200]);
    if (!Array.isArray(list)) throw new DockerApiError('list', 200, 'not a list');
    return list as ContainerSummary[];
  }

  async attachContainer(id: string, options: { maxStdoutBytes: number }): Promise<AttachStream> {
    assertId(id);
    const version = await this.negotiate();
    return new Promise<AttachStream>((resolve, reject) => {
      const req = http.request({
        socketPath: this.options.socketPath,
        method: 'POST',
        path: `/v${version}/containers/${id}/attach?stream=1&stdin=1&stdout=1&stderr=1`,
        agent: false,
        headers: {
          Host: 'docker',
          Connection: 'Upgrade',
          Upgrade: 'tcp',
          'Content-Type': 'application/vnd.docker.raw-stream',
        },
        timeout: this.requestTimeoutMs,
      });
      req.on('timeout', () => req.destroy(new DockerUnreachableError('attach', 'ETIMEDOUT')));
      req.on('error', (error: NodeJS.ErrnoException) => {
        reject(
          error instanceof DockerUnreachableError
            ? error
            : UNREACHABLE_CODES.has(error.code ?? '')
              ? new DockerUnreachableError('attach', error.code ?? 'error')
              : new DockerApiError('attach', null, error.message),
        );
      });
      req.on('response', (res: IncomingMessage) => {
        res.resume();
        reject(new DockerApiError('attach', res.statusCode ?? null, 'no upgrade'));
      });
      req.on('upgrade', (res: IncomingMessage, socket: Socket, head: Buffer) => {
        req.setTimeout(0);
        socket.setTimeout(0);
        resolve(createAttachStream(socket, head, options.maxStdoutBytes));
      });
      req.end();
    });
  }

  // -------------------------------------------------------------------------------------------

  private async negotiate(): Promise<string> {
    if (this.apiVersion) return this.apiVersion;
    this.negotiating ??= this.version()
      .then((v) => {
        this.apiVersion = negotiateApiVersion(v);
        return this.apiVersion;
      })
      .finally(() => {
        this.negotiating = null;
      });
    return this.negotiating;
  }

  private async raw(
    operation: string,
    method: string,
    path: string,
    options: { signal?: AbortSignal; body?: Buffer; versioned?: boolean; timeoutMs?: number },
  ): Promise<RawResponse> {
    const prefix = options.versioned === false ? '' : `/v${await this.negotiate()}`;
    const timeoutMs = options.timeoutMs ?? this.requestTimeoutMs;
    return new Promise<RawResponse>((resolve, reject) => {
      const headers: Record<string, string | number> = { Host: 'docker' };
      if (options.body) {
        headers['Content-Type'] = 'application/json';
        headers['Content-Length'] = options.body.length;
      }
      // `agent: false`: one connection per request. Node's global agent applies its own idle
      // socket timeout (5 s), which would cut long-polling calls such as `wait`.
      const req = http.request({
        socketPath: this.options.socketPath,
        method,
        path: `${prefix}${path}`,
        headers,
        agent: false,
        ...(timeoutMs > 0 ? { timeout: timeoutMs } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
      });
      if (timeoutMs > 0) {
        req.on('timeout', () => req.destroy(new DockerUnreachableError(operation, 'ETIMEDOUT')));
      } else {
        req.setTimeout(0);
      }
      req.on('error', (error: NodeJS.ErrnoException) => {
        if (error instanceof DockerUnreachableError) reject(error);
        else if (error.name === 'AbortError') reject(error);
        else if (UNREACHABLE_CODES.has(error.code ?? '')) {
          reject(new DockerUnreachableError(operation, error.code ?? 'error'));
        } else reject(new DockerApiError(operation, null, error.message));
      });
      req.on('response', (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > this.maxResponseBytes) {
            res.removeAllListeners('data');
            res.destroy();
            reject(new DockerApiError(operation, res.statusCode ?? null, 'response too large'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () =>
          resolve({ statusCode: res.statusCode ?? 0, body: Buffer.concat(chunks) }),
        );
        res.on('error', (error) => reject(new DockerApiError(operation, null, error.message)));
      });
      req.end(options.body);
    });
  }

  private json<T>(operation: string, res: RawResponse, ok: number[]): T {
    if (!ok.includes(res.statusCode)) {
      throw new DockerApiError(operation, res.statusCode, errorMessage(res.body));
    }
    try {
      return JSON.parse(res.body.toString('utf8')) as T;
    } catch {
      throw new DockerApiError(operation, res.statusCode, 'invalid JSON');
    }
  }
}

function assertId(value: string): void {
  if (!ID_PATTERN.test(value)) throw new Error('invalid docker object name');
}

/** The daemon's `message` (bounded, single line) — never echoed into results, only logs. */
function errorMessage(body: Buffer): string {
  try {
    const parsed = JSON.parse(body.toString('utf8')) as { message?: unknown };
    if (typeof parsed.message === 'string')
      return parsed.message.replace(/\s+/g, ' ').slice(0, 200);
  } catch {
    // Not JSON.
  }
  return body.toString('utf8').replace(/\s+/g, ' ').slice(0, 200) || 'error';
}

function createAttachStream(socket: Socket, head: Buffer, maxStdoutBytes: number): AttachStream {
  const demuxer = new DockerStreamDemuxer(maxStdoutBytes);
  if (head.length > 0) demuxer.push(head);
  let finished = false;
  const done = new Promise<AttachOutput>((resolve) => {
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve(demuxer.result());
    };
    socket.on('data', (chunk: Buffer) => demuxer.push(chunk));
    socket.on('end', finish);
    socket.on('close', finish);
    socket.on('error', finish);
  });
  return {
    write: (data: Buffer) =>
      new Promise<void>((resolve, reject) => {
        if (socket.destroyed) {
          reject(new Error('attach stream closed'));
          return;
        }
        socket.write(data, (error) => (error ? reject(error) : resolve()));
      }),
    endStdin: () => {
      if (!socket.destroyed) socket.end();
    },
    collect: () => done,
    destroy: () => socket.destroy(),
  };
}
