import { randomUUID } from 'node:crypto';
import { createConnection } from 'node:net';
import { DEMO } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { adapterRunning, stack } from './support/env';
import { SmtpClient } from './support/smtp-client';

describe('Postfix (inbound MX)', () => {
  it('greets and advertises STARTTLS and SIZE', async () => {
    const { client, banner } = await SmtpClient.connect(stack.host, stack.ports.smtp);
    try {
      expect(banner).toMatch(/^220 /);
      const ehlo = await client.command('EHLO integration.example.test');
      expect(ehlo).toMatch(/^250/);
      expect(ehlo).toContain('STARTTLS');
      expect(ehlo).toMatch(/SIZE 52428800/);
      expect(ehlo).not.toContain('VRFY');
    } finally {
      client.close();
    }
  });

  it('refuses to relay for domains it does not serve (554), or tempfails without the adapter', async () => {
    // Relay domains come from smtp-adapter (socketmap relay_domain, step 2.2 D2). With the adapter
    // up an unknown domain fails reject_unauth_destination permanently; without it the lookup
    // fails and Postfix must answer 451 4.3.0 (fail closed), never 250.
    const adapterUp = await adapterRunning();
    const { client } = await SmtpClient.connect(stack.host, stack.ports.smtp);
    try {
      await client.command('EHLO integration.example.test');
      expect(await client.command('MAIL FROM:<sender@example.org>')).toMatch(/^250/);
      // A never-seen name: smtpd caches address resolutions per process (smtpd_resolve), so a
      // name resolved while the adapter was up would not hit the socketmap again.
      const victim = `victim@not-a-tenant-${randomUUID().slice(0, 8)}.example`;
      expect(await client.command(`RCPT TO:<${victim}>`)).toMatch(
        adapterUp ? /^554 5\.7\.1 .*Relay access denied/ : /^451 4\.3\.0 /,
      );
    } finally {
      client.close();
    }
  });

  it('accepts a tenant domain only through the adapter and fails closed (4xx) without it', async () => {
    const adapterUp = await adapterRunning();
    const { client } = await SmtpClient.connect(stack.host, stack.ports.smtp);
    try {
      await client.command('EHLO integration.example.test');
      await client.command('MAIL FROM:<sender@example.org>');
      const reply = await client.command(`RCPT TO:<user@${DEMO.domain}>`);
      // With smtp-adapter running the seeded demo domain is a relay domain and the policy answers
      // DUNNO (250); without it Postfix must tempfail rather than accept unchecked mail.
      expect(reply).toMatch(adapterUp ? /^250/ : /^4\d\d /);
    } finally {
      client.close();
    }
  });
});

describe('Rspamd', () => {
  const base = () => `http://${stack.host}:${stack.ports.rspamd}`;

  it('answers /ping', async () => {
    expect((await (await fetch(`${base()}/ping`)).text()).trim()).toBe('pong');
  });

  it('scans a message and returns a verdict', async () => {
    const res = await fetch(`${base()}/checkv2`, {
      method: 'POST',
      headers: {
        From: 'sender@example.org',
        Rcpt: `user@${DEMO.domain}`,
        Ip: '192.0.2.10',
      },
      body: 'From: sender@example.org\r\nTo: user@gateway.test\r\nSubject: hello\r\n\r\nplain body\r\n',
    });
    expect(res.ok).toBe(true);
    const verdict = (await res.json()) as { action: string; score: number };
    expect(typeof verdict.score).toBe('number');
    expect(verdict.action).toBeTruthy();
  });
});

describe('ClamAV', () => {
  function clamd(payload: Buffer): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = createConnection({ host: stack.host, port: stack.ports.clamav });
      let reply = '';
      socket.on('data', (d) => (reply += d.toString()));
      socket.on('end', () => resolve(reply.replace(/\0/g, '').trim()));
      socket.on('error', reject);
      socket.end(payload);
    });
  }

  function instream(content: Buffer): Buffer {
    const size = Buffer.alloc(4);
    size.writeUInt32BE(content.length);
    return Buffer.concat([Buffer.from('zINSTREAM\0'), size, content, Buffer.alloc(4)]);
  }

  it('responds to PING', async () => {
    expect(await clamd(Buffer.from('zPING\0'))).toBe('PONG');
  });

  it('detects the EICAR test signature and passes clean content', async () => {
    // Assembled at runtime so the repository never contains the literal test string.
    const eicar = [
      'X5O!P%@AP[4\\PZX54(P^)7CC)7}$',
      'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
    ].join('');
    expect(await clamd(instream(Buffer.from(eicar)))).toMatch(/Eicar.*FOUND$/i);
    expect(await clamd(instream(Buffer.from('hello world')))).toBe('stream: OK');
  });
});
