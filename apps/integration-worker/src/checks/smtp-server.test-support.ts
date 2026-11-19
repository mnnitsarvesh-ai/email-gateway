import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';

/** A throwaway CA and leaf certificate generated at test runtime (never committed). */
export interface TestPki {
  caPem: string;
  keyPem: string;
  certPem: string;
}

/** True when the `openssl` CLI is available (the TLS cases need it to mint certificates). */
export function hasOpenssl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** Generates a CA and a leaf certificate for `names` (SANs; the first is the CN). */
export function generateTestPki(names: readonly string[]): TestPki {
  const dir = mkdtempSync(join(tmpdir(), 'iw-pki-'));
  const run = (args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'ignore' });
  try {
    run(['genrsa', '-out', 'ca.key', '2048']);
    run([
      'req',
      '-x509',
      '-new',
      '-key',
      'ca.key',
      '-sha256',
      '-days',
      '2',
      '-subj',
      '/CN=integration-worker test CA',
      '-out',
      'ca.pem',
    ]);
    run(['genrsa', '-out', 'leaf.key', '2048']);
    run(['req', '-new', '-key', 'leaf.key', '-subj', `/CN=${names[0]}`, '-out', 'leaf.csr']);
    writeFileSync(
      join(dir, 'ext.cnf'),
      `subjectAltName=${names.map((n) => `DNS:${n}`).join(',')}\nextendedKeyUsage=serverAuth\n`,
    );
    run([
      'x509',
      '-req',
      '-in',
      'leaf.csr',
      '-CA',
      'ca.pem',
      '-CAkey',
      'ca.key',
      '-CAcreateserial',
      '-days',
      '2',
      '-sha256',
      '-extfile',
      'ext.cnf',
      '-out',
      'leaf.pem',
    ]);
    return {
      caPem: readFileSync(join(dir, 'ca.pem'), 'utf8'),
      keyPem: readFileSync(join(dir, 'leaf.key'), 'utf8'),
      certPem: readFileSync(join(dir, 'leaf.pem'), 'utf8'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

export interface TestSmtpServerOptions {
  pki?: TestPki;
  /** Offer STARTTLS (default true when `pki` is given). */
  starttls?: boolean;
  /** Reply to RCPT (default `250 2.1.5 Ok`). */
  rcptReply?: string;
  greeting?: string;
  /** Never answer the greeting (timeout case). */
  silent?: boolean;
}

/**
 * An in-process SMTP server for probe tests (§10.3): records every command, upgrades on
 * STARTTLS, answers RCPT as configured, and asserts that the probe never sends DATA
 * (`dataSeen` stays false; a DATA command is answered `503` and recorded).
 */
export class TestSmtpServer {
  readonly commands: string[] = [];
  dataSeen = false;
  private server: net.Server | null = null;
  private readonly sockets = new Set<net.Socket>();

  constructor(private readonly options: TestSmtpServerOptions = {}) {}

  async start(): Promise<number> {
    const server = net.createServer((socket) => this.session(socket));
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    this.server = server;
    return (server.address() as net.AddressInfo).port;
  }

  async stop(): Promise<void> {
    const server = this.server;
    this.server = null;
    for (const socket of this.sockets) socket.destroy();
    if (server) await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private session(socket: net.Socket): void {
    socket.on('error', () => undefined);
    this.sockets.add(socket);
    socket.on('close', () => this.sockets.delete(socket));
    if (this.options.silent) return;
    let current: net.Socket = socket;
    let buffer = '';
    let secure = false;
    const write = (line: string) => current.write(`${line}\r\n`);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString('latin1');
      let index: number;
      while ((index = buffer.indexOf('\r\n')) >= 0) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        handle(line);
      }
    };
    const handle = (line: string) => {
      this.commands.push(line);
      const verb = line.split(' ')[0]!.toUpperCase();
      switch (verb) {
        case 'EHLO': {
          const offer = !secure && (this.options.starttls ?? this.options.pki !== undefined);
          write('250-sink.test');
          if (offer) write('250-STARTTLS');
          write('250 SIZE 10240000');
          return;
        }
        case 'STARTTLS': {
          write('220 2.0.0 Ready to start TLS');
          current.off('data', onData);
          const upgraded = new tls.TLSSocket(current, {
            isServer: true,
            secureContext: tls.createSecureContext({
              key: this.options.pki!.keyPem,
              cert: this.options.pki!.certPem,
            }),
          });
          upgraded.on('error', () => undefined);
          upgraded.on('data', onData);
          current = upgraded;
          secure = true;
          buffer = '';
          return;
        }
        case 'MAIL':
          return write('250 2.1.0 Ok');
        case 'RCPT':
          return write(this.options.rcptReply ?? '250 2.1.5 Ok');
        case 'RSET':
          return write('250 2.0.0 Ok');
        case 'DATA':
          this.dataSeen = true;
          return write('503 5.5.1 DATA is never expected from a probe');
        case 'QUIT':
          write('221 2.0.0 Bye');
          current.end();
          return;
        default:
          return write('502 5.5.2 Unknown command');
      }
    };
    socket.on('data', onData);
    write(this.options.greeting ?? '220 sink.test ESMTP test');
  }
}
