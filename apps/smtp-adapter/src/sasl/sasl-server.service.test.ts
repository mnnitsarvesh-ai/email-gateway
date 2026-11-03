import { createConnection, type Socket } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  metricValue,
  newMetrics,
  silentLogger,
  testConfig,
} from '../../integration/in-session-support/fakes';
import type { AuthResult, ConnectorAuthService } from '../connectors/connector-auth.service';
import { parseNetworkList } from '../shared/internal-networks';
import {
  AuthProtocolError,
  decodePlain,
  LineSplitter,
  MAX_LINE_BYTES,
  parseAuthRequest,
} from './dovecot-auth-protocol';
import { SaslServerService } from './sasl-server.service';

const b64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');
const plain = (authzid: string, user: string, pass: string) => b64(`${authzid}\0${user}\0${pass}`);

describe('Dovecot auth protocol helpers', () => {
  it('splits lines (LF or CRLF) across chunks and caps their length', () => {
    const splitter = new LineSplitter();
    expect(splitter.push(Buffer.from('VERSION\t1\t2\r\nCP'))).toEqual(['VERSION\t1\t2']);
    expect(splitter.push(Buffer.from('ID\t42\n'))).toEqual(['CPID\t42']);
    expect(() => new LineSplitter().push(Buffer.alloc(MAX_LINE_BYTES + 1, 0x61))).toThrow(
      AuthProtocolError,
    );
  });

  it('parses AUTH parameters and flags', () => {
    const request = parseAuthRequest(['1', 'plain', 'service=smtp', 'nologin', 'secured', 'resp=']);
    expect(request.mechanism).toBe('PLAIN');
    expect(request.flags.has('secured')).toBe(true);
    expect(request.params.get('service')).toBe('smtp');
    expect(request.params.get('resp')).toBe('');
    expect(() => parseAuthRequest(['x', 'PLAIN'])).toThrow(AuthProtocolError);
    expect(() => parseAuthRequest(['1'])).toThrow(AuthProtocolError);
  });

  it('decodes PLAIN credentials strictly', () => {
    expect(decodePlain(plain('', 'u', 'p'))).toEqual({ authzid: '', authcid: 'u', password: 'p' });
    expect(decodePlain(plain('z', 'u', 'p'))?.authzid).toBe('z');
    expect(decodePlain(b64('u\0p'))).toBeNull();
    expect(decodePlain(plain('', '', 'p'))).toBeNull();
    expect(decodePlain('!!!')).toBeNull();
    expect(decodePlain('')).toBeNull();
  });
});

/** A line-oriented test client speaking the Postfix side of the protocol. */
class Client {
  private buffer = '';
  private waiters: (() => void)[] = [];
  closed = false;

  constructor(readonly socket: Socket) {
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      this.waiters.splice(0).forEach((w) => w());
    });
    socket.on('close', () => {
      this.closed = true;
      this.waiters.splice(0).forEach((w) => w());
    });
    socket.on('error', () => undefined);
  }

  static async connect(port: number): Promise<Client> {
    const socket = createConnection({ port, host: '127.0.0.1' });
    await new Promise((r) => socket.once('connect', r));
    return new Client(socket);
  }

  async line(): Promise<string | null> {
    for (;;) {
      const newline = this.buffer.indexOf('\n');
      if (newline !== -1) {
        const line = this.buffer.slice(0, newline);
        this.buffer = this.buffer.slice(newline + 1);
        return line;
      }
      if (this.closed) return null;
      await new Promise<void>((r) => this.waiters.push(r));
    }
  }

  /** Reads the handshake through DONE. */
  async handshake(): Promise<string[]> {
    const lines: string[] = [];
    for (;;) {
      const line = await this.line();
      if (line === null) return lines;
      lines.push(line);
      if (line === 'DONE') return lines;
    }
  }

  send(text: string): void {
    this.socket.write(text);
  }

  close(): void {
    this.socket.destroy();
  }
}

const SECURED = 'service=smtp\tnologin\tlip=172.18.0.5\trip=203.0.113.7\tsecured';

describe('SaslServerService', () => {
  let server: SaslServerService | undefined;
  const clients: Client[] = [];

  afterEach(async () => {
    clients.splice(0).forEach((c) => c.close());
    await server?.onModuleDestroy();
    server = undefined;
  });

  async function start(
    authenticate: (user: string, secret: string, ip: string) => Promise<AuthResult>,
    options: { networks?: string; delayMs?: number } = {},
  ) {
    const auth = { authenticate: vi.fn(authenticate) };
    const metrics = newMetrics();
    server = new SaslServerService(
      {
        host: '127.0.0.1',
        port: 0,
        internalNetworks: parseNetworkList(options.networks ?? '127.0.0.0/8'),
      },
      auth as unknown as ConnectorAuthService,
      metrics,
      testConfig({ SMTP_AUTH_FAILURE_DELAY_MS: String(options.delayMs ?? 0) }),
      silentLogger(),
    );
    await server.onModuleInit();
    const port = server.address();
    const connect = async (handshake = true) => {
      const client = await Client.connect(port);
      clients.push(client);
      if (handshake) {
        await client.handshake();
        client.send('VERSION\t1\t0\nCPID\t4242\n');
      }
      return client;
    };
    return { auth, metrics, connect };
  }

  const ok = (): Promise<AuthResult> =>
    Promise.resolve({ result: 'ok', connectorId: 5n, organizationId: 7n });

  it('sends the Dovecot handshake', async () => {
    const s = await start(ok);
    const client = await s.connect(false);
    const lines = await client.handshake();
    expect(lines.slice(0, 3)).toEqual([
      'VERSION\t1\t2',
      'MECH\tPLAIN\tplaintext',
      'MECH\tLOGIN\tplaintext',
    ]);
    expect(lines[3]).toBe(`SPID\t${process.pid}`);
    expect(lines[4]).toMatch(/^CUID\t\d+$/);
    expect(lines[5]).toMatch(/^COOKIE\t[0-9a-f]{32}$/);
    expect(lines[6]).toBe('DONE');
    await expect(server?.checkHealth()).resolves.toBeUndefined();
  });

  it('PLAIN with an initial response: OK with the username', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t1\tPLAIN\t${SECURED}\tresp=${plain('', 'egc-abc', 's3cret')}\n`);
    expect(await client.line()).toBe('OK\t1\tuser=egc-abc');
    expect(s.auth.authenticate).toHaveBeenCalledWith('egc-abc', 's3cret', '203.0.113.7');
    expect(
      await metricValue(s.metrics, 'smtp_sasl_auth_total', { mech: 'plain', result: 'ok' }),
    ).toBe(1);
  });

  it('PLAIN without an initial response: empty CONT, then the credentials', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t7\tPLAIN\t${SECURED}\n`);
    expect(await client.line()).toBe('CONT\t7\t');
    client.send(`CONT\t7\t${plain('egc-abc', 'egc-abc', 's3cret')}\n`);
    expect(await client.line()).toBe('OK\t7\tuser=egc-abc');
  });

  it('PLAIN refuses an authzid different from the authcid', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t2\tPLAIN\t${SECURED}\tresp=${plain('egc-other', 'egc-abc', 's3cret')}\n`);
    expect(await client.line()).toBe('FAIL\t2');
    expect(s.auth.authenticate).not.toHaveBeenCalled();
  });

  it('LOGIN: Username:/Password: challenges', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t3\tLOGIN\t${SECURED}\n`);
    expect(await client.line()).toBe(`CONT\t3\t${b64('Username:')}`);
    client.send(`CONT\t3\t${b64('egc-abc')}\n`);
    expect(await client.line()).toBe(`CONT\t3\t${b64('Password:')}`);
    client.send(`CONT\t3\t${b64('s3cret')}\n`);
    expect(await client.line()).toBe('OK\t3\tuser=egc-abc');
    expect(s.auth.authenticate).toHaveBeenCalledWith('egc-abc', 's3cret', '203.0.113.7');
  });

  it('LOGIN with the username as initial response', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t4\tLOGIN\t${SECURED}\tresp=${b64('egc-abc')}\n`);
    expect(await client.line()).toBe(`CONT\t4\t${b64('Password:')}`);
    client.send(`CONT\t4\t${b64('s3cret')}\n`);
    expect(await client.line()).toBe('OK\t4\tuser=egc-abc');
  });

  it('refuses AUTH without the secured flag (no TLS) and unknown mechanisms', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t5\tPLAIN\tservice=smtp\tresp=${plain('', 'egc-abc', 's3cret')}\n`);
    expect(await client.line()).toBe('FAIL\t5');
    client.send(`AUTH\t6\tCRAM-MD5\t${SECURED}\n`);
    expect(await client.line()).toBe('FAIL\t6');
    expect(s.auth.authenticate).not.toHaveBeenCalled();
  });

  it('wrong credentials: FAIL with the username after the failure delay', async () => {
    const s = await start(() => Promise.resolve({ result: 'fail' }), { delayMs: 150 });
    const client = await s.connect();
    const started = Date.now();
    client.send(`AUTH\t8\tPLAIN\t${SECURED}\tresp=${plain('', 'egc-abc', 'nope')}\n`);
    expect(await client.line()).toBe('FAIL\t8\tuser=egc-abc');
    expect(Date.now() - started).toBeGreaterThanOrEqual(140);
    expect(
      await metricValue(s.metrics, 'smtp_sasl_auth_total', { mech: 'plain', result: 'fail' }),
    ).toBe(1);
  });

  it.each([
    ['temp', 'temp'],
    ['throttled', 'throttled'],
  ] as const)(
    '%s → connection closed without a reply (Postfix: 454 4.7.0)',
    async (result, label) => {
      const s = await start(() => Promise.resolve({ result }));
      const client = await s.connect();
      client.send(`AUTH\t9\tPLAIN\t${SECURED}\tresp=${plain('', 'egc-abc', 'x')}\n`);
      // Postfix 3.7 turns any FAIL line into a permanent 535; only a lost connection is temporary.
      expect(await client.line()).toBeNull();
      expect(
        await metricValue(s.metrics, 'smtp_sasl_auth_total', { mech: 'plain', result: label }),
      ).toBe(1);
    },
  );

  it('an unexpected authentication error closes the connection (temporary failure)', async () => {
    const s = await start(() => Promise.reject(new Error('boom')));
    const client = await s.connect();
    client.send(`AUTH\t10\tPLAIN\t${SECURED}\tresp=${plain('', 'egc-abc', 'x')}\n`);
    expect(await client.line()).toBeNull();
  });

  it.each([
    ['an unsupported major version', 'VERSION\t2\t0\n'],
    ['AUTH before VERSION', `AUTH\t1\tPLAIN\t${SECURED}\n`],
    ['an unknown command', 'VERSION\t1\t0\nHELLO\n'],
    ['CONT for an unknown id', 'VERSION\t1\t0\nCONT\t99\tabc\n'],
    ['a malformed AUTH', 'VERSION\t1\t0\nAUTH\tx\tPLAIN\n'],
  ])('closes the connection on %s', async (_, input) => {
    const s = await start(ok);
    const client = await s.connect(false);
    await client.handshake();
    client.send(input);
    expect(await client.line()).toBeNull();
  });

  it('closes the connection on a line over 64 KiB', async () => {
    const s = await start(ok);
    const client = await s.connect();
    client.send(`AUTH\t1\tPLAIN\t${SECURED}\tresp=${'A'.repeat(MAX_LINE_BYTES)}\n`);
    expect(await client.line()).toBeNull();
  });

  it('refuses peers outside SMTP_INTERNAL_CLIENT_NETWORKS', async () => {
    const s = await start(ok, { networks: '10.0.0.0/8' });
    const client = await s.connect(false);
    expect(await client.line()).toBeNull();
  });
});
