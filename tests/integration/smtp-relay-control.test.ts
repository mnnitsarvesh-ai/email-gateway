import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { compose, composeExec } from './support/compose';
import { SmtpFixtures } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import {
  clientCertificate,
  removeToolsFiles,
  reply,
  starttlsProtocol,
  swaks,
  toolsAddresses,
} from './support/smtp-tools';

/**
 * No open relay on any listener and TLS (docs/plan/steps/04-smtp-gateway.md D9, D15; §9 stack
 * suites 3 and 4), against the real postfix and postfix-outbound containers. No connector covers
 * the smtp-tools container in this file, so every relay attempt must be refused.
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
let tenantDomain = '';
let otherTenantSender = '';
const toolFiles: string[] = [];

beforeAll(async () => {
  assertStackReady(gate);
  // Forget any cached connector decision for the smtp-tools addresses (and clean up after).
  for (const ip of await toolsAddresses()) fx.trackClientIp(ip);
  const org = await fx.organization('relay');
  const domain = await fx.domain(org, 'relay', { outboundEnabled: true });
  await fx.dkimKey(domain);
  tenantDomain = domain.name;
  otherTenantSender = `someone@${fx.name('foreign')}`;
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await removeToolsFiles(toolFiles);
  await fx.cleanup();
}, 120_000);

describe.skipIf(gate.skip)('SMTP stack: no open relay (suite 3)', { timeout: 120_000 }, () => {
  it('submission 587: MAIL without STARTTLS is refused with 530', async () => {
    const result = await swaks({
      server: 'postfix-outbound',
      port: 587,
      from: `user@${tenantDomain}`,
      to: ['victim@example.com'],
      quitAfter: 'RCPT',
    });
    expect(reply(result, 'MAIL').text).toMatch(/^530 5\.7\.0 Must issue a STARTTLS command first/);
  });

  it('submission 587: a wrong password or unknown user is refused with 535', async () => {
    const org = fx.organizationIds[0]!;
    const connector = await fx.saslConnector(org, 'wrongpw');
    for (const auth of [
      { username: connector.username, password: `${connector.password}x` },
      { username: `egc-${fx.suffix}unknown`, password: 'not-a-real-secret-value' },
    ]) {
      const result = await swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        auth,
        from: `user@${tenantDomain}`,
        to: ['victim@example.com'],
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'AUTH').text).toMatch(/^535 5\.7\.8 .*[Aa]uthentication failed/);
      expect(result.transcript).not.toContain(auth.password);
      // Unauthenticated after the failure: relaying stays refused.
      expect(result.replies.get('RCPT#0')?.code ?? 0).not.toBe(250);
    }
  });

  it('connector relay 25: an unregistered client IP is refused with 554 5.7.1 Access denied', async () => {
    const plain = await swaks({
      server: 'postfix-outbound',
      port: 25,
      from: `user@${tenantDomain}`,
      to: ['victim@example.com'],
      quitAfter: 'RCPT',
    });
    // The final `reject` of the listener's relay restrictions (no connector matched).
    expect(reply(plain, 'RCPT#0').text).toMatch(/^554 5\.7\.1 .*Access denied/);
  });

  it('connector relay 25: an unregistered client certificate is refused with 554 5.7.1', async () => {
    const cert = await clientCertificate(`unregistered-${fx.suffix}`);
    toolFiles.push(cert.certPath, cert.keyPath);
    const result = await swaks({
      server: 'postfix-outbound',
      port: 25,
      tls: true,
      tlsCert: cert.certPath,
      tlsKey: cert.keyPath,
      from: `user@${tenantDomain}`,
      to: ['victim@example.com'],
      quitAfter: 'RCPT',
    });
    expect(reply(result, 'RCPT#0').text).toMatch(/^554 5\.7\.1 .*Access denied/);
  });

  it('reinject-inbound 10026: a recipient outside the tenant domains is refused', async () => {
    const result = await swaks({
      server: 'postfix-outbound',
      port: 10026,
      from: 'sender@example.org',
      to: ['victim@example.com'],
      quitAfter: 'RCPT',
    });
    // Policy REJECT (context reinject-inbound): permanent 550 5.7.1.
    expect(reply(result, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Relay access denied/);
  });

  it('reinject-outbound 10027: a sender outside the tenant domains is refused', async () => {
    for (const from of [otherTenantSender, 'spoof@example.org']) {
      const result = await swaks({
        server: 'postfix-outbound',
        port: 10027,
        from,
        to: ['victim@example.com'],
        quitAfter: 'RCPT',
      });
      expect(reply(result, 'RCPT#0').text).toMatch(/^550 5\.7\.1 .*Sender address not authorized/);
    }
  });

  it('refuses the reserved bounce-notice address on every outbound listener (D13)', async () => {
    const org = fx.organizationIds[0]!;
    const connector = await fx.saslConnector(org, 'bounce');
    const bounceAddress = `bounce-notices@${process.env.POSTFIX_BOUNCE_DOMAIN ?? 'bounces.gateway.internal'}`;
    const attempts = [{ port: 587, tls: true, auth: connector }, { port: 10027 }, { port: 10026 }];
    for (const attempt of attempts) {
      const result = await swaks({
        server: 'postfix-outbound',
        from: `user@${tenantDomain}`,
        to: [bounceAddress],
        quitAfter: 'RCPT',
        ...attempt,
      });
      if (attempt.auth) expect(reply(result, 'AUTH').code).toBe(235);
      expect(reply(result, 'RCPT#0').text, `port ${attempt.port}`).toMatch(
        /^550 5\.7\.1 .*Relay access denied/,
      );
    }
  });

  it('rspamd-outbound (DKIM signer) is reachable from postfix-outbound only', async () => {
    const probe = ['bash', '-c', 'timeout 5 bash -c "exec 3<>/dev/tcp/rspamd-outbound/11332"'];
    expect((await composeExec('postfix-outbound', probe)).exitCode).toBe(0);
    // Containers of the default and mailtest networks cannot even resolve it.
    for (const service of ['postfix', 'smtp-tools']) {
      expect((await composeExec(service, probe)).exitCode, service).not.toBe(0);
    }
    // Not published (`docker compose port` prints nothing or `:0` on an internal network).
    expect((await compose(['port', 'rspamd-outbound', '11332'])).stdout.trim()).toMatch(/^(:0)?$/);
  });

  it('never publishes the reinjection listeners to the host', async () => {
    for (const port of ['10026', '10027']) {
      const result = await compose(['port', 'postfix-outbound', port]);
      expect(result.stdout.trim()).toBe('');
    }
  });
});

describe.skipIf(gate.skip)(
  'SMTP stack: STARTTLS and AUTH advertisement (suite 4)',
  { timeout: 120_000 },
  () => {
    it.each([
      ['postfix', 25],
      ['postfix-outbound', 587],
      ['postfix-outbound', 25],
    ] as const)('%s:%i negotiates TLSv1.2 or newer', async (server, port) => {
      const result = await starttlsProtocol(server, port);
      expect(result.protocol, result.output).toMatch(/^TLSv1\.[23]$/);
    });

    it.each([
      ['postfix', 25],
      ['postfix-outbound', 587],
      ['postfix-outbound', 25],
    ] as const)('%s:%i refuses TLSv1.1', async (server, port) => {
      const result = await starttlsProtocol(server, port, [
        '-tls1_1',
        '-cipher',
        'DEFAULT@SECLEVEL=0',
      ]);
      expect(result.protocol).toBeUndefined();
    });

    it('submission 587 offers AUTH only after STARTTLS', async () => {
      const result = await swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        quitAfter: 'TLS',
      });
      const before = reply(result, 'EHLO').lines.join('\n');
      expect(before).toContain('STARTTLS');
      expect(before).not.toMatch(/AUTH/);
      const after = await swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        quitAfter: 'HELO',
      });
      const tlsEhlo = reply(after, 'EHLO-TLS').lines.join('\n');
      expect(tlsEhlo).toMatch(/AUTH PLAIN LOGIN|AUTH LOGIN PLAIN/);
    });

    it('never offers AUTH on the inbound MX or the connector relay listener', async () => {
      for (const [server, port] of [
        ['postfix', 25],
        ['postfix-outbound', 25],
      ] as const) {
        const result = await swaks({ server, port, tls: true, quitAfter: 'HELO' });
        expect(reply(result, 'EHLO').lines.join('\n')).not.toMatch(/AUTH/);
        expect(reply(result, 'EHLO-TLS').lines.join('\n')).not.toMatch(/AUTH/);
      }
    });
  },
);
