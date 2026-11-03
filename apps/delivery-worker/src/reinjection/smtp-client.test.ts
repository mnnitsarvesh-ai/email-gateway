import { createServer, type AddressInfo, type Server, type Socket } from 'node:net';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import {
  DotStuffer,
  isAmbiguousSmtpError,
  SmtpClient,
  type SmtpClientError,
  SmtpConnectionError,
  SmtpProtocolError,
  SmtpTimeoutError,
  xtext,
} from './smtp-client';

/**
 * A scripted fake SMTP server on node:net: `reply(line)` answers each command line (string =
 * raw bytes to write, null = say nothing); DATA content is collected until the terminator.
 */
interface Script {
  greeting?: string | null;
  reply?: (line: string, session: FakeSession) => string | null;
  /** After the terminator. */
  afterData?: (session: FakeSession) => string | null;
}

interface FakeSession {
  socket: Socket;
  commands: string[];
  data: Buffer;
}

const servers: Server[] = [];
const sockets: Socket[] = [];
afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.destroy();
  await Promise.all(servers.splice(0).map((s) => new Promise((r) => s.close(r))));
});

const EHLO_REPLY =
  '250-out.gateway.local\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-XFORWARD NAME ADDR PROTO HELO SOURCE PORT IDENT\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8\r\n';

function defaultReply(line: string): string | null {
  const verb = line.split(/[ :]/)[0]!.toUpperCase();
  switch (verb) {
    case 'EHLO':
      return EHLO_REPLY;
    case 'XFORWARD':
    case 'MAIL':
    case 'RCPT':
      return '250 2.0.0 Ok\r\n';
    case 'DATA':
      return '354 End data with <CR><LF>.<CR><LF>\r\n';
    case 'QUIT':
      return '221 2.0.0 Bye\r\n';
    default:
      return '502 5.5.2 Error: command not recognized\r\n';
  }
}

async function fakeServer(script: Script = {}): Promise<{ port: number; sessions: FakeSession[] }> {
  const sessions: FakeSession[] = [];
  const server = createServer((socket) => {
    sockets.push(socket);
    const session: FakeSession = { socket, commands: [], data: Buffer.alloc(0) };
    sessions.push(session);
    let buffer = Buffer.alloc(0);
    let inData = false;
    const greeting =
      script.greeting === undefined ? '220 out.gateway.local ESMTP\r\n' : script.greeting;
    if (greeting !== null) socket.write(greeting);
    socket.on('error', () => undefined);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          const startEnd = session.data.length === 0 && buffer.indexOf('.\r\n') === 0 ? 0 : -1;
          if (end === -1 && startEnd === -1) return;
          const cut = startEnd === 0 ? 0 : end + 2;
          session.data = Buffer.concat([session.data, buffer.subarray(0, cut)]);
          buffer = buffer.subarray(cut + 3);
          inData = false;
          const answer = script.afterData
            ? script.afterData(session)
            : '250 2.0.0 Ok: queued as 4jJdlD6Cp2zrsd\r\n';
          if (answer !== null) socket.write(answer);
          continue;
        }
        const lf = buffer.indexOf('\r\n');
        if (lf === -1) return;
        const line = buffer.subarray(0, lf).toString('utf8');
        buffer = buffer.subarray(lf + 2);
        session.commands.push(line);
        const answer = script.reply ? script.reply(line, session) : defaultReply(line);
        if (line.toUpperCase() === 'DATA' && answer?.startsWith('354')) inData = true;
        if (answer !== null) socket.write(answer);
        if (line.toUpperCase() === 'QUIT') socket.end();
      }
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: (server.address() as AddressInfo).port, sessions };
}

const options = (
  port: number,
  overrides: Partial<Parameters<typeof SmtpClient.connect>[0]> = {},
) => ({
  host: '127.0.0.1',
  port,
  commandTimeoutMs: 1000,
  dataTimeoutMs: 1000,
  ...overrides,
});

function chunks(...parts: string[]): AsyncIterable<Uint8Array> {
  return Readable.from(parts.map((part) => Buffer.from(part, 'utf8')));
}

describe('xtext', () => {
  it('encodes +, =, controls, space and non-ASCII bytes as +HH', () => {
    expect(xtext('user@example.com')).toBe('user@example.com');
    expect(xtext('a+b=c d')).toBe('a+2Bb+3Dc+20d');
    expect(xtext('[UNAVAILABLE]')).toBe('[UNAVAILABLE]');
    expect(xtext('ü@x')).toBe('+C3+BC@x');
    expect(xtext('\t')).toBe('+09');
  });
});

describe('DotStuffer', () => {
  const run = (...parts: string[]): string => {
    const stuffer = new DotStuffer();
    const out = parts.map((p) => stuffer.transform(Buffer.from(p, 'latin1')));
    out.push(stuffer.end());
    return Buffer.concat(out).toString('latin1');
  };

  it('normalizes LF to CRLF and keeps CRLF', () => {
    expect(run('a\nb\r\nc\n')).toBe('a\r\nb\r\nc\r\n.\r\n');
  });

  it('doubles dots at line starts, including the first line and across chunk boundaries', () => {
    expect(run('.first\n..two\nmid.dle\n')).toBe('..first\r\n...two\r\nmid.dle\r\n.\r\n');
    expect(run('line\r', '\n.', 'dot\n')).toBe('line\r\n..dot\r\n.\r\n');
    expect(run('line\n', '.', '\n')).toBe('line\r\n..\r\n.\r\n');
  });

  it('guarantees a final CRLF (also after a trailing CR) and passes bare CRs through', () => {
    expect(run('no newline')).toBe('no newline\r\n.\r\n');
    expect(run('ends with cr\r')).toBe('ends with cr\r\n.\r\n');
    expect(run('a\rb\n')).toBe('a\rb\r\n.\r\n');
    expect(run('')).toBe('.\r\n');
  });
});

describe('SmtpClient', () => {
  it('runs a full session: greeting, EHLO capabilities, XFORWARD, MAIL, RCPT, DATA, QUIT', async () => {
    const server = await fakeServer();
    const { client, greeting } = await SmtpClient.connect(options(server.port));
    expect(greeting.code).toBe(220);
    const ehlo = await client.ehlo('delivery.gateway.local');
    expect(ehlo.code).toBe(250);
    expect(ehlo.lines).toHaveLength(8);
    for (const cap of ['XFORWARD', 'SIZE', 'DSN', 'SMTPUTF8', 'PIPELINING'])
      expect(client.has(cap)).toBe(true);
    expect(client.capabilities.get('XFORWARD')).toContain('IDENT');
    expect(
      (
        await client.xforward([
          ['NAME', '[UNAVAILABLE]'],
          ['ADDR', '203.0.113.7'],
          ['HELO', 'mail example'],
          ['PROTO', 'ESMTP'],
        ])
      ).code,
    ).toBe(250);
    expect(
      (
        await client.xforward([
          ['IDENT', 'dw1-0123'],
          ['SOURCE', 'REMOTE'],
        ])
      ).code,
    ).toBe(250);
    expect(
      (
        await client.mail('a@x.test', {
          size: 1234,
          ret: 'HDRS',
          envid: 'dw1-0123',
          smtputf8: true,
        })
      ).code,
    ).toBe(250);
    expect(
      (await client.rcpt('b+tag@y.test', { notify: 'FAILURE,DELAY', orcpt: 'b+tag@y.test' })).code,
    ).toBe(250);
    const data = await client.data(
      'X-Gateway-Trace: v=1; g=gw\r\n',
      chunks('Subject: hi\n\n.body\n'),
    );
    expect(data.start.code).toBe(354);
    expect(data.final?.code).toBe(250);
    expect(data.final?.enhancedStatus).toBe('2.0.0');
    expect(data.final?.text).toContain('queued as 4jJdlD6Cp2zrsd');
    await client.quit();
    const session = server.sessions[0]!;
    expect(session.commands).toEqual([
      'EHLO delivery.gateway.local',
      'XFORWARD NAME=[UNAVAILABLE] ADDR=203.0.113.7 HELO=mail+20example PROTO=ESMTP',
      'XFORWARD IDENT=dw1-0123 SOURCE=REMOTE',
      'MAIL FROM:<a@x.test> SIZE=1234 RET=HDRS ENVID=dw1-0123 SMTPUTF8',
      'RCPT TO:<b+tag@y.test> NOTIFY=FAILURE,DELAY ORCPT=rfc822;b+2Btag@y.test',
      'DATA',
      'QUIT',
    ]);
    expect(session.data.toString('utf8')).toBe(
      'X-Gateway-Trace: v=1; g=gw\r\nSubject: hi\r\n\r\n..body\r\n',
    );
  });

  it('sends the null sender as <> and omits absent parameters', async () => {
    const server = await fakeServer();
    const { client } = await SmtpClient.connect(options(server.port));
    await client.ehlo('h.test');
    await client.mail('');
    await client.rcpt('b@y.test');
    await client.quit();
    expect(server.sessions[0]!.commands.slice(1, 3)).toEqual([
      'MAIL FROM:<>',
      'RCPT TO:<b@y.test>',
    ]);
  });

  it('returns per-recipient 4xx and 5xx replies with enhanced status codes', async () => {
    const server = await fakeServer({
      reply: (line) =>
        line.includes('<soft@')
          ? '450 4.2.1 <soft@y.test>: Mailbox busy\r\n'
          : line.includes('<hard@')
            ? '554 5.7.1 <hard@y.test>: Relay access denied\r\n'
            : defaultReply(line),
    });
    const { client } = await SmtpClient.connect(options(server.port));
    await client.ehlo('h.test');
    await client.mail('a@x.test');
    const ok = await client.rcpt('ok@y.test');
    const soft = await client.rcpt('soft@y.test');
    const hard = await client.rcpt('hard@y.test');
    await client.quit();
    expect([ok.code, soft.code, hard.code]).toEqual([250, 450, 554]);
    expect(soft.enhancedStatus).toBe('4.2.1');
    expect(hard.enhancedStatus).toBe('5.7.1');
    expect(hard.text).toBe('554 5.7.1 <hard@y.test>: Relay access denied');
  });

  it('returns DATA refusals (354 not given) and final 4xx/5xx replies', async () => {
    const refusing = await fakeServer({
      reply: (l) => (l === 'DATA' ? '451 4.3.0 try later\r\n' : defaultReply(l)),
    });
    let session = await SmtpClient.connect(options(refusing.port));
    await session.client.ehlo('h');
    await session.client.mail('a@x.test');
    await session.client.rcpt('b@y.test');
    const refused = await session.client.data('H: v\r\n', chunks('x\n'));
    expect(refused.start.code).toBe(451);
    expect(refused.final).toBeUndefined();
    await session.client.quit();

    const finalReject = await fakeServer({ afterData: () => '554 5.7.1 milter rejected\r\n' });
    session = await SmtpClient.connect(options(finalReject.port));
    await session.client.ehlo('h');
    await session.client.mail('a@x.test');
    await session.client.rcpt('b@y.test');
    const rejected = await session.client.data('H: v\r\n', chunks('x\n'));
    expect(rejected.final?.code).toBe(554);
    await session.client.quit();
  });

  it('parses multi-line replies strictly: inconsistent codes are a protocol error', async () => {
    const server = await fakeServer({
      reply: (l) => (l.startsWith('EHLO') ? '250-a\r\n251 b\r\n' : defaultReply(l)),
    });
    const { client } = await SmtpClient.connect(options(server.port));
    const error = await client.ehlo('h').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SmtpProtocolError);
    expect((error as SmtpClientError).afterDot).toBe(false);
    client.destroy();
  });

  it('refuses malformed reply lines, overlong lines and oversized replies', async () => {
    for (const bad of [
      'hello there\r\n',
      `250 ${'x'.repeat(3000)}\r\n`,
      `${'250-x\r\n'.repeat(12_000)}250 end\r\n`,
      '600 no\r\n',
    ]) {
      const server = await fakeServer({
        reply: (l) => (l.startsWith('EHLO') ? bad : defaultReply(l)),
      });
      const { client } = await SmtpClient.connect(options(server.port));
      await expect(client.ehlo('h')).rejects.toBeInstanceOf(SmtpProtocolError);
      client.destroy();
    }
  });

  it('tolerates reply lines longer than 512 bytes up to the tolerance', async () => {
    const server = await fakeServer({
      reply: (l) => (l.startsWith('EHLO') ? `250 ${'x'.repeat(1500)}\r\n` : defaultReply(l)),
    });
    const { client } = await SmtpClient.connect(options(server.port));
    expect((await client.ehlo('h')).code).toBe(250);
    await client.quit();
  });

  it('accepts LF-only reply terminators and a reply split across packets', async () => {
    const server = await fakeServer({
      reply: (line, session) => {
        if (!line.startsWith('EHLO')) return defaultReply(line);
        session.socket.write('250-out\n250-XFO');
        setTimeout(() => session.socket.write('RWARD NAME ADDR\r\n250 DSN\r\n'), 20);
        return null;
      },
    });
    const { client } = await SmtpClient.connect(options(server.port));
    await client.ehlo('h');
    expect(client.has('XFORWARD')).toBe(true);
    expect(client.has('DSN')).toBe(true);
    await client.quit();
  });

  it('reports a non-220 greeting to the caller', async () => {
    const server = await fakeServer({ greeting: '421 4.3.2 Service not available\r\n' });
    const { client, greeting } = await SmtpClient.connect(options(server.port));
    expect(greeting.code).toBe(421);
    client.destroy();
  });

  it('fails with a connection error when nothing listens', async () => {
    const server = await fakeServer();
    const port = server.port;
    await new Promise((r) => servers.pop()!.close(r));
    const error = await SmtpClient.connect(options(port)).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SmtpConnectionError);
    expect(isAmbiguousSmtpError(error)).toBe(false);
  });

  it('times out before the dot (greeting, command): not ambiguous', async () => {
    const silent = await fakeServer({ greeting: null });
    const greetingError = await SmtpClient.connect(
      options(silent.port, { commandTimeoutMs: 150 }),
    ).catch((e: unknown) => e);
    expect(greetingError).toBeInstanceOf(SmtpTimeoutError);
    expect(isAmbiguousSmtpError(greetingError)).toBe(false);

    const mute = await fakeServer({
      reply: (l) => (l.startsWith('MAIL') ? null : defaultReply(l)),
    });
    const { client } = await SmtpClient.connect(options(mute.port, { commandTimeoutMs: 150 }));
    await client.ehlo('h');
    const error = await client.mail('a@x.test').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SmtpTimeoutError);
    expect(isAmbiguousSmtpError(error)).toBe(false);
    client.destroy();
  });

  it('times out after the dot: ambiguous', async () => {
    const server = await fakeServer({ afterData: () => null });
    const { client } = await SmtpClient.connect(options(server.port, { dataTimeoutMs: 150 }));
    await client.ehlo('h');
    await client.mail('a@x.test');
    await client.rcpt('b@y.test');
    const error = await client.data('H: v\r\n', chunks('body\n')).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SmtpTimeoutError);
    expect((error as SmtpClientError).afterDot).toBe(true);
    expect(isAmbiguousSmtpError(error)).toBe(true);
    client.destroy();
  });

  it('a connection closed after the dot is ambiguous; before the dot it is not', async () => {
    const after = await fakeServer({ afterData: (s) => (s.socket.destroy(), null) });
    let session = await SmtpClient.connect(options(after.port));
    await session.client.ehlo('h');
    await session.client.mail('a@x.test');
    await session.client.rcpt('b@y.test');
    const ambiguous = await session.client
      .data('H: v\r\n', chunks('body\n'))
      .catch((e: unknown) => e);
    expect(ambiguous).toBeInstanceOf(SmtpConnectionError);
    expect(isAmbiguousSmtpError(ambiguous)).toBe(true);

    const before = await fakeServer({
      reply: (l, s) => (l.startsWith('RCPT') ? (s.socket.destroy(), null) : defaultReply(l)),
    });
    session = await SmtpClient.connect(options(before.port));
    await session.client.ehlo('h');
    await session.client.mail('a@x.test');
    const lost = await session.client.rcpt('b@y.test').catch((e: unknown) => e);
    expect(lost).toBeInstanceOf(SmtpConnectionError);
    expect(isAmbiguousSmtpError(lost)).toBe(false);
  });

  it('a body stream error destroys the connection before the dot and is rethrown', async () => {
    const server = await fakeServer();
    const { client } = await SmtpClient.connect(options(server.port));
    await client.ehlo('h');
    await client.mail('a@x.test');
    await client.rcpt('b@y.test');
    async function* broken(): AsyncGenerator<Uint8Array> {
      yield await Promise.resolve(Buffer.from('Subject: x\r\n'));
      throw new Error('S3 stream reset');
    }
    await expect(client.data('H: v\r\n', broken())).rejects.toThrow('S3 stream reset');
    await new Promise((r) => setTimeout(r, 50));
    expect(server.sessions[0]!.data.length).toBe(0); // no terminator ever reached the server
  });

  it('aborting destroys the session', async () => {
    const server = await fakeServer({
      reply: (l) => (l.startsWith('MAIL') ? null : defaultReply(l)),
    });
    const controller = new AbortController();
    const { client } = await SmtpClient.connect(
      options(server.port, { signal: controller.signal }),
    );
    await client.ehlo('h');
    const pending = client.mail('a@x.test').catch((e: unknown) => e);
    controller.abort();
    const error = await pending;
    expect(error).toBeInstanceOf(SmtpConnectionError);
    expect((error as Error).message).toBe('aborted');
  });

  it('refuses CR/LF injection in commands and invalid envelope addresses', async () => {
    const server = await fakeServer();
    const { client } = await SmtpClient.connect(options(server.port));
    await client.ehlo('h');
    await expect(client.ehlo('h\r\nRCPT TO:<x@y>')).rejects.toBeInstanceOf(SmtpProtocolError);
    await expect(client.mail('a b@x.test')).rejects.toBeInstanceOf(SmtpProtocolError);
    await expect(client.rcpt('<x@y.test>')).rejects.toBeInstanceOf(SmtpProtocolError);
    await expect(client.rcpt('')).rejects.toBeInstanceOf(SmtpProtocolError);
    await expect(client.data('Two: lines\r\nInjected: x\r\n', chunks('x'))).rejects.toBeInstanceOf(
      SmtpProtocolError,
    );
    await client.quit();
  });

  it('streams a large body with backpressure and dot-stuffing intact', async () => {
    const server = await fakeServer();
    const { client } = await SmtpClient.connect(
      options(server.port, { commandTimeoutMs: 5000, dataTimeoutMs: 5000 }),
    );
    await client.ehlo('h');
    await client.mail('a@x.test');
    await client.rcpt('b@y.test');
    const line = '.' + 'y'.repeat(998) + '\n';
    async function* big(): AsyncGenerator<Uint8Array> {
      for (let i = 0; i < 4000; i += 1) yield await Promise.resolve(Buffer.from(line));
    }
    const result = await client.data('H: v\r\n', big());
    expect(result.final?.code).toBe(250);
    await client.quit();
    const data = server.sessions[0]!.data;
    expect(data.length).toBe('H: v\r\n'.length + 4000 * (line.length + 2));
  });
});
