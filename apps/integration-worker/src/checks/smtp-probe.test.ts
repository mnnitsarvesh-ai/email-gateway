import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { certificateNamesMatch, probeSmtp, type SmtpProbeOptions } from './smtp-probe';
import {
  generateTestPki,
  hasOpenssl,
  TestSmtpServer,
  type TestPki,
} from './smtp-server.test-support';

const M365_NAMES = 'nexthop:mail.protection.outlook.com:.mail.protection.outlook.com';
const HOST = 'contoso-com.mail.protection.outlook.com';

describe('certificateNamesMatch (Postfix match= semantics)', () => {
  it.each([
    [['*.mail.protection.outlook.com'], M365_NAMES, HOST, true],
    [['mail.protection.outlook.com'], M365_NAMES, HOST, true],
    [['contoso-com.mail.protection.outlook.com'], M365_NAMES, HOST, true],
    [['evil.example'], M365_NAMES, HOST, false],
    [['*.outlook.com'], M365_NAMES, HOST, false],
    [['mx.google.com'], 'nexthop:mx.google.com:.aspmx.l.google.com', 'aspmx.l.google.com', true],
    [
      ['alt1.aspmx.l.google.com'],
      'nexthop:mx.google.com:.aspmx.l.google.com',
      'alt1.aspmx.l.google.com',
      true,
    ],
    [
      ['aspmx.l.google.com'],
      'nexthop:mx.google.com:.aspmx.l.google.com',
      'alt2.aspmx.l.google.com',
      false,
    ],
    [[], M365_NAMES, HOST, false],
  ])('%j vs %s for %s → %s', (names, verify, host, expected) => {
    expect(certificateNamesMatch(names, verify, host)).toBe(expected);
  });
});

const openssl = hasOpenssl();

describe.skipIf(!openssl)('probeSmtp against an in-process SMTP server', () => {
  let pki: TestPki;
  let wrongPki: TestPki;
  let server: TestSmtpServer | null = null;

  beforeAll(() => {
    pki = generateTestPki(['*.mail.protection.outlook.com', 'mail.protection.outlook.com']);
    wrongPki = generateTestPki(['unrelated.example']);
  }, 60_000);

  afterEach(async () => {
    if (server) {
      // Never DATA: every case asserts it.
      expect(server.dataSeen).toBe(false);
      expect(server.commands.some((c) => /^DATA/i.test(c))).toBe(false);
      await server.stop();
      server = null;
    }
  });

  const options = (port: number, extra: Partial<SmtpProbeOptions> = {}): SmtpProbeOptions => ({
    host: HOST,
    address: '127.0.0.1',
    port,
    helo: 'out.gateway.local',
    domain: 'contoso.com',
    verifyNames: M365_NAMES,
    timeoutMs: 5_000,
    ca: [pki.caPem],
    ...extra,
  });

  it('passes: STARTTLS, verified certificate, 2xx at RCPT, then RSET and QUIT', async () => {
    server = new TestSmtpServer({ pki });
    const result = await probeSmtp(options(await server.start()));
    expect(result).toMatchObject({ status: 'pass', code: 'ok' });
    expect(result.evidence).toMatchObject({
      banner: 'sink.test',
      namesMatch: true,
      rcptReplyClass: '2xx',
    });
    expect(['TLSv1.2', 'TLSv1.3']).toContain(result.evidence.tlsVersion);
    await new Promise((r) => setTimeout(r, 100));
    expect(server.commands.map((c) => c.split(/[ :]/)[0])).toEqual([
      'EHLO',
      'STARTTLS',
      'EHLO',
      'MAIL',
      'RCPT',
      'RSET',
      'QUIT',
    ]);
    expect(server.commands).toContain('MAIL FROM:<>');
    expect(server.commands).toContain('RCPT TO:<postmaster@contoso.com>');
  });

  it('warns on a 5xx at RCPT (providers may refuse probes from non-gateway addresses)', async () => {
    server = new TestSmtpServer({ pki, rcptReply: '550 5.7.1 Access denied' });
    const result = await probeSmtp(options(await server.start()));
    expect(result).toMatchObject({ status: 'warn', code: 'rcpt_refused' });
    expect(result.evidence.rcptReplyClass).toBe('5xx');
  });

  it('fails without STARTTLS', async () => {
    server = new TestSmtpServer({ starttls: false });
    const result = await probeSmtp(options(await server.start()));
    expect(result).toMatchObject({ status: 'fail', code: 'starttls_unavailable' });
  });

  it('fails on an untrusted certificate', async () => {
    server = new TestSmtpServer({ pki });
    const result = await probeSmtp(options(await server.start(), { ca: [wrongPki.caPem] }));
    expect(result).toMatchObject({ status: 'fail', code: 'certificate_untrusted' });
  });

  it('fails when the certificate names do not match the preset', async () => {
    server = new TestSmtpServer({ pki: wrongPki });
    const result = await probeSmtp(options(await server.start(), { ca: [wrongPki.caPem] }));
    expect(result).toMatchObject({ status: 'fail', code: 'certificate_mismatch' });
    expect(result.evidence.namesMatch).toBe(false);
  });

  it('fails on a refused greeting', async () => {
    server = new TestSmtpServer({ pki, greeting: '554 5.7.1 go away' });
    const result = await probeSmtp(options(await server.start()));
    expect(result).toMatchObject({ status: 'fail', code: 'greeting_refused' });
  });

  it('fails with timeout when the server never answers', async () => {
    server = new TestSmtpServer({ silent: true });
    const result = await probeSmtp(options(await server.start(), { timeoutMs: 300 }));
    expect(result).toMatchObject({ status: 'fail', code: 'timeout' });
  });
});

describe('probeSmtp connection failures', () => {
  it('fails with connect_failed on a closed port', async () => {
    const result = await probeSmtp({
      host: HOST,
      address: '127.0.0.1',
      port: 1,
      helo: 'out.gateway.local',
      domain: 'contoso.com',
      verifyNames: M365_NAMES,
      timeoutMs: 2_000,
    });
    expect(result).toMatchObject({ status: 'fail', code: 'connect_failed' });
  });
});
