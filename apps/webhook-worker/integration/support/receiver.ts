import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { verifyWebhookSignature } from '@email-gateway/webhooks';

/**
 * The in-process HTTPS webhook receiver of the integration suite (step 6.2 §10.3): a test CA and
 * a leaf for `hooks.receiver.test` generated with the openssl CLI at start (never committed),
 * reached by the worker through the TEST-ONLY dial map (`203.0.113.20:443` → this port) after the
 * SSRF guard validated the documentation address. Records every request per path (headers, raw
 * body, time, and whether `EG-Signature` verifies against the secrets registered for the path);
 * answers per path from a programmed list, then a default status.
 */

export interface RecordedRequest {
  path: string;
  method: string;
  headers: Record<string, string>;
  body: string;
  receivedAt: number;
  signatureValid: boolean | null;
}

export interface ProgrammedResponse {
  status: number;
  retryAfter?: string;
  delayMs?: number;
  body?: string;
}

export interface Pki {
  ca: string;
  key: string;
  cert: string;
}

export function generatePki(names: readonly string[]): Pki {
  const dir = mkdtempSync(join(tmpdir(), 'webhook-worker-pki-'));
  const run = (args: string[]): void => {
    execFileSync('openssl', args, { stdio: 'ignore' });
  };
  try {
    run([
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-sha256',
      '-days',
      '2',
      '-subj',
      '/CN=webhook-worker test CA',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
      '-keyout',
      join(dir, 'ca.key'),
      '-out',
      join(dir, 'ca.pem'),
    ]);
    run([
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-sha256',
      '-subj',
      `/CN=${names[0] ?? 'test'}`,
      '-keyout',
      join(dir, 'leaf.key'),
      '-out',
      join(dir, 'leaf.csr'),
    ]);
    writeFileSync(
      join(dir, 'ext.cnf'),
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${names.map((n) => `DNS:${n}`).join(',')}\n`,
    );
    run([
      'x509',
      '-req',
      '-in',
      join(dir, 'leaf.csr'),
      '-CA',
      join(dir, 'ca.pem'),
      '-CAkey',
      join(dir, 'ca.key'),
      '-CAcreateserial',
      '-days',
      '2',
      '-sha256',
      '-extfile',
      join(dir, 'ext.cnf'),
      '-out',
      join(dir, 'leaf.pem'),
    ]);
    return {
      ca: readFileSync(join(dir, 'ca.pem'), 'utf8'),
      key: readFileSync(join(dir, 'leaf.key'), 'utf8'),
      cert: readFileSync(join(dir, 'leaf.pem'), 'utf8'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export class TestReceiver {
  readonly pki: Pki;
  port = 0;
  /** TCP connections accepted (SSRF tests assert none was made). */
  connections = 0;
  private readonly server: https.Server;
  private readonly requests = new Map<string, RecordedRequest[]>();
  private readonly programs = new Map<string, ProgrammedResponse[]>();
  private readonly defaults = new Map<string, number>();
  private readonly secrets = new Map<string, string[]>();
  private readonly timers = new Set<NodeJS.Timeout>();

  constructor() {
    this.pki = generatePki(['hooks.receiver.test', 'hooks2.receiver.test']);
    this.server = https.createServer({ key: this.pki.key, cert: this.pki.cert }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const path = new URL(req.url ?? '/', 'https://receiver').pathname;
        const body = Buffer.concat(chunks).toString('utf8');
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (typeof v === 'string') headers[k] = v;
        }
        const secrets = this.secrets.get(path);
        const signature = headers['eg-signature'];
        const signatureValid =
          secrets === undefined || signature === undefined
            ? null
            : verifyWebhookSignature({ header: signature, rawBody: body, secrets }).ok;
        const list = this.requests.get(path) ?? [];
        list.push({
          path,
          method: req.method ?? '',
          headers,
          body,
          receivedAt: Date.now(),
          signatureValid,
        });
        this.requests.set(path, list);
        const program = this.programs.get(path);
        const next = program?.shift() ?? { status: this.defaults.get(path) ?? 200 };
        const answer = (): void => {
          res.writeHead(next.status, {
            'content-type': 'text/plain',
            ...(next.retryAfter !== undefined ? { 'retry-after': next.retryAfter } : {}),
          });
          res.end(next.body ?? 'ok');
        };
        if (next.delayMs) {
          const timer = setTimeout(() => {
            this.timers.delete(timer);
            answer();
          }, next.delayMs);
          this.timers.add(timer);
        } else {
          answer();
        }
      });
    });
    this.server.on('connection', () => {
      this.connections += 1;
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve));
    this.port = (this.server.address() as AddressInfo).port;
  }

  async stop(): Promise<void> {
    for (const t of this.timers) clearTimeout(t);
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  /** Responses for the next requests of `path`, then `then` (default 200). */
  program(path: string, responses: ProgrammedResponse[], then = 200): void {
    this.programs.set(path, [...responses]);
    this.defaults.set(path, then);
  }

  /** Secrets the signatures of `path` are verified with (as a receiver would). */
  registerSecrets(path: string, secrets: string[]): void {
    this.secrets.set(path, secrets);
  }

  received(path: string): RecordedRequest[] {
    return this.requests.get(path) ?? [];
  }

  allPaths(): string[] {
    return [...this.requests.keys()];
  }
}
