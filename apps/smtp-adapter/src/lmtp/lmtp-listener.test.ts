import { createLogger } from '@email-gateway/logger';
import { once } from 'node:events';
import { afterEach, describe, expect, it } from 'vitest';
import { deliver, LmtpTestClient } from '../../integration/support/lmtp-client';
import { parseNetworkList } from '../shared/internal-networks';
import { LMTP_OK, LMTP_TEMPFAIL, LOOP, type SmtpReply } from '../shared/replies';
import {
  type LmtpClientInfo,
  type LmtpHandler,
  LmtpListener,
  xForwardClientName,
} from './lmtp-listener';
import { LmtpReplyException } from './lmtp-reply';

const logger = createLogger({ service: 'smtp-adapter', level: 'silent' });

interface Seen {
  clients: LmtpClientInfo[];
  froms: string[];
  bodies: string[];
}

function recordingHandler(
  seen: Seen,
  overrides: Partial<LmtpHandler<{ from: string }, string>> = {},
): LmtpHandler<{ from: string }, string> {
  return {
    beginTransaction: (client, from) => {
      seen.clients.push(client);
      seen.froms.push(from);
      return Promise.resolve({ from });
    },
    acceptRecipient: (_tx, address) => {
      if (address.startsWith('defer')) return Promise.reject(new Error('db down'));
      if (address.startsWith('loop')) return Promise.reject(new LmtpReplyException(LOOP));
      return Promise.resolve(address);
    },
    handleData: async (_tx, recipients, stream) => {
      const chunks: Buffer[] = [];
      for await (const chunk of stream as AsyncIterable<Buffer>) chunks.push(chunk);
      seen.bodies.push(Buffer.concat(chunks).toString('utf8'));
      return recipients.map((r): SmtpReply => (r.startsWith('fail') ? LMTP_TEMPFAIL : LMTP_OK));
    },
    ...overrides,
  };
}

let listener: LmtpListener<{ from: string }, string> | undefined;

afterEach(async () => {
  await listener?.close();
  listener = undefined;
});

async function start(
  handler: LmtpHandler<{ from: string }, string>,
  networks = '127.0.0.0/8,::1/128',
): Promise<number> {
  listener = new LmtpListener(
    {
      name: 'lmtp-test',
      host: '127.0.0.1',
      port: 0,
      maxClients: 5,
      maxMessageBytes: 1024 * 1024,
      internalNetworks: parseNetworkList(networks),
      drainTimeoutMs: 2_000,
    },
    handler,
    logger,
  );
  await listener.start();
  return listener.port();
}

describe('xForwardClientName', () => {
  it('normalizes the verified host name and keeps Postfix unknown', () => {
    expect(xForwardClientName('Mail.Example.')).toBe('mail.example');
    expect(xForwardClientName('unknown')).toBe('unknown');
    expect(xForwardClientName('UNKNOWN')).toBe('unknown');
  });

  it('maps missing, empty and the unavailable placeholders to null', () => {
    for (const value of [
      undefined,
      null,
      false,
      '',
      '  ',
      '[UNAVAILABLE]',
      '[TEMPUNAVAIL]',
      '[tempunavail]',
    ]) {
      expect(xForwardClientName(value), String(value)).toBeNull();
    }
  });
});

describe('LmtpListener', () => {
  it('answers per recipient after DATA and reports XFORWARD and the LHLO name', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen));
    const result = await deliver({
      port,
      lhlo: 'MX.Gateway.Local',
      xforward: {
        NAME: 'Mail.Example.',
        ADDR: '203.0.113.7',
        HELO: 'client.example',
        IDENT: '4ZbK3B2xyzQ',
      },
      from: 'alice@example.test',
      to: ['ok@a.test', 'fail@a.test', 'defer@a.test', 'loop@a.test', 'ok2@b.test'],
      message: 'Subject: hi\r\n\r\n.leading dot\r\nbody\r\n',
    });
    expect(result.greeting.text).toBe('220 lmtp LMTP ready');
    expect(result.rcpt.map((r) => r.text)).toEqual([
      '250 Accepted',
      '250 Accepted',
      '451 4.3.0 Temporary failure, please retry',
      '554 5.4.6 Routing loop detected',
      '250 Accepted',
    ]);
    expect(result.data.map((r) => r.text)).toEqual([
      '250 2.0.0 Ok',
      '451 4.3.0 Temporary failure, please retry',
      '250 2.0.0 Ok',
    ]);
    expect(seen.clients[0]).toMatchObject({
      lhloName: 'mx.gateway.local',
      queueId: '4ZbK3B2xyzQ',
      clientAddress: '203.0.113.7',
      clientHelo: 'client.example',
      clientName: 'mail.example',
      peerAddress: '127.0.0.1',
    });
    expect(seen.froms).toEqual(['alice@example.test']);
    expect(seen.bodies[0]).toBe('Subject: hi\r\n\r\n.leading dot\r\nbody\r\n');
  });

  it('reports a missing or malformed IDENT as null and the null sender as empty', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen));
    await deliver({ port, from: '', to: ['ok@a.test'], message: 'x\r\n' });
    await deliver({
      port,
      xforward: { IDENT: 'bad.id' },
      from: 'a@b.test',
      to: ['ok@a.test'],
      message: 'x\r\n',
    });
    expect(seen.froms[0]).toBe('');
    expect(seen.clients.map((c) => c.queueId)).toEqual([null, null]);
  });

  it('reports XFORWARD NAME unknown as unknown and an unavailable or missing NAME as null', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen));
    const requests: Record<string, string>[] = [
      { NAME: 'unknown', ADDR: '198.51.100.9' },
      { NAME: '[UNAVAILABLE]', ADDR: '198.51.100.9' },
      { ADDR: '198.51.100.9' },
    ];
    for (const xforward of requests) {
      await deliver({ port, xforward, from: 'a@b.test', to: ['ok@a.test'], message: 'x\r\n' });
    }
    expect(seen.clients.map((c) => c.clientName)).toEqual(['unknown', null, null]);
  });

  it('keeps the LHLO name for every transaction of a cached connection', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen));
    const client = await LmtpTestClient.connect(port);
    await client.read();
    await client.command('LHLO out.gateway.local');
    for (const ident of ['AAA111', 'BBB222']) {
      await client.command(`XFORWARD HELO=tenant-${ident}.example`);
      await client.command(`XFORWARD IDENT=${ident}`);
      expect((await client.command('MAIL FROM:<a@b.test>')).code).toBe(250);
      expect((await client.command('RCPT TO:<ok@a.test>')).code).toBe(250);
      expect((await client.data('Subject: x\r\n\r\nbody\r\n', 1))[0]!.code).toBe(250);
      await client.command('RSET');
    }
    await client.quit();
    expect(seen.clients.map((c) => [c.lhloName, c.queueId, c.clientHelo])).toEqual([
      ['out.gateway.local', 'AAA111', 'tenant-aaa111.example'],
      ['out.gateway.local', 'BBB222', 'tenant-bbb222.example'],
    ]);
  });

  it('drains the message and tempfails everyone when DATA handling throws without reading', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(
      recordingHandler(seen, { handleData: () => Promise.reject(new Error('boom')) }),
    );
    const client = await LmtpTestClient.connect(port);
    await client.read();
    await client.command('LHLO mx.test');
    await client.command('MAIL FROM:<a@b.test>');
    await client.command('RCPT TO:<x@a.test>');
    await client.command('RCPT TO:<y@a.test>');
    const replies = await client.data(`Subject: big\r\n\r\n${'z'.repeat(200_000)}\r\n`, 2);
    expect(replies.map((r) => r.code)).toEqual([451, 451]);
    // The connection is still usable: the rest of the message was consumed.
    expect((await client.command('NOOP')).code).toBe(250);
    await client.quit();
  });

  it('answers one DATA reply per accepted RCPT when RCPTs differ only in letter case', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const handled: string[][] = [];
    const base = recordingHandler(seen);
    const port = await start({
      ...base,
      handleData: (tx, recipients, stream) => {
        handled.push([...recipients]);
        return base.handleData(tx, recipients, stream);
      },
    });
    const client = await LmtpTestClient.connect(port);
    await client.read();
    await client.command('LHLO out.gateway.local');
    await client.command('MAIL FROM:<a@b.test>');
    // Postfix compares addresses exactly, so both case variants reach one LMTP transaction.
    expect((await client.command('RCPT TO:<Bob@t.example>')).code).toBe(250);
    expect((await client.command('RCPT TO:<defer@t.example>')).code).toBe(451);
    expect((await client.command('RCPT TO:<bob@t.example>')).code).toBe(250);
    expect((await client.command('RCPT TO:<fail@t.example>')).code).toBe(250);
    expect((await client.command('RCPT TO:<BOB@T.EXAMPLE>')).code).toBe(250);
    const replies = await client.data('Subject: x\r\n\r\nbody\r\n', 4);
    expect(replies.map((r) => r.code)).toEqual([250, 250, 451, 250]);
    // The handler sees each recipient once, in order of its first accepted RCPT.
    expect(handled).toEqual([['Bob@t.example', 'fail@t.example']]);
    // Nothing is left over: the next command gets its own reply.
    expect((await client.command('NOOP')).code).toBe(250);
    await client.quit();
  });

  it('tempfails everyone when the handler returns the wrong number of replies', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(
      recordingHandler(seen, { handleData: () => Promise.resolve([LMTP_OK]) }),
    );
    const result = await deliver({
      port,
      from: 'a@b.test',
      to: ['x@a.test', 'y@a.test'],
      message: 'x\r\n',
    });
    expect(result.data.map((r) => r.code)).toEqual([451, 451]);
  });

  it('refuses peers outside SMTP_INTERNAL_CLIENT_NETWORKS at connect', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen), '10.0.0.0/8');
    const client = await LmtpTestClient.connect(port);
    const greeting = await client.read();
    expect(greeting.text).toBe('554 5.7.1 Access denied, internal callers only');
    client.destroy();
    expect(seen.clients).toHaveLength(0);
  });

  it('does not offer STARTTLS or AUTH and refuses them', async () => {
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(recordingHandler(seen));
    const client = await LmtpTestClient.connect(port);
    await client.read();
    const lhlo = await client.command('LHLO mx.test');
    expect(lhlo.lines.join('\n')).not.toMatch(/STARTTLS|AUTH/);
    expect(lhlo.lines.join('\n')).toMatch(/XFORWARD/);
    expect((await client.command('STARTTLS')).code).toBeGreaterThanOrEqual(500);
    expect((await client.command('AUTH PLAIN AGFAYg==')).code).toBeGreaterThanOrEqual(500);
    await client.quit();
  });

  it('waits for a transaction in DATA on close, then refuses new connections', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const seen: Seen = { clients: [], froms: [], bodies: [] };
    const port = await start(
      recordingHandler(seen, {
        handleData: async (_tx, recipients, stream) => {
          stream.resume();
          await once(stream, 'end');
          await gate;
          return recipients.map(() => LMTP_OK);
        },
      }),
    );
    const pending = deliver({ port, from: 'a@b.test', to: ['x@a.test'], message: 'x\r\n' });
    await new Promise((resolve) => setTimeout(resolve, 300));
    const closing = listener!.close();
    expect(listener!.accepting).toBe(false);
    setTimeout(release, 200);
    await closing;
    const result = await pending;
    expect(result.data.map((r) => r.code)).toEqual([250]);
    await expect(LmtpTestClient.connect(port)).rejects.toThrow();
    listener = undefined;
  });
});
