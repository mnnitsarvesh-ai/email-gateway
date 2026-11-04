import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { purgeDormantQueues } from './support/broker';
import { composeOk, runningServices, waitFor } from './support/compose';
import { stack } from './support/env';
import { SmtpFixtures, type FixtureDomain } from './support/smtp-fixtures';
import { assertStackReady, smtpStackGate } from './support/smtp-stack';
import { reply, swaks } from './support/smtp-tools';

/**
 * Fail closed (docs/plan/steps/04-smtp-gateway.md §2.0 invariant 3; §9 stack suite 12): when the
 * policy service or its state store is unavailable, both Postfix instances answer 4xx, never
 * 250 and never 5xx.
 *
 * - Redis down (works in every mode): the policy's rate limiter cannot count → DEFER 4.3.5 on the
 *   inbound MX and on submission.
 * - smtp-adapter down: only when it runs as the `smtp-adapter` Compose service (CI). An adapter
 *   on the host cannot be stopped from here; mail-plane.test.ts covers that case when the suite
 *   runs without the adapter (recorded in §12 of the step note).
 */
const gate = await smtpStackGate();
const fx = new SmtpFixtures();
let domain: FixtureDomain;
/** Never looked up before the adapter is stopped: long-lived smtpd processes cache resolutions. */
let unresolvedDomain: FixtureDomain;
let sasl: { username: string; password: string };
const adapterIsContainer = gate.skip ? false : (await runningServices()).has('smtp-adapter');

async function adapterReady(): Promise<boolean> {
  try {
    const res = await fetch(
      `http://${stack.host}:${stack.ports.services['smtp-adapter']}/health/ready`,
      { signal: AbortSignal.timeout(2_000) },
    );
    return res.ok;
  } catch {
    return false;
  }
}

async function redisUp(): Promise<void> {
  await composeOk(['start', 'redis'], { timeoutMs: 120_000 });
  await waitFor('smtp-adapter ready again (Redis back)', adapterReady, {
    timeoutMs: 120_000,
    intervalMs: 1_000,
  });
}

beforeAll(async () => {
  assertStackReady(gate);
  const org = await fx.organization('closed');
  domain = await fx.domain(org, 'closed', { outboundEnabled: true });
  unresolvedDomain = await fx.domain(org, 'closed-unresolved');
  await fx.dkimKey(domain);
  sasl = await fx.saslConnector(org, 'closed');
}, 60_000);

afterAll(async () => {
  if (gate.skip) return;
  await redisUp();
  if (adapterIsContainer) {
    await composeOk(['start', 'smtp-adapter'], { timeoutMs: 120_000 });
    await waitFor('smtp-adapter ready', adapterReady, { timeoutMs: 120_000, intervalMs: 1_000 });
  }
  await fx.cleanup();
  await purgeDormantQueues();
}, 300_000);

describe.skipIf(gate.skip)('SMTP stack: fail closed (suite 12)', { timeout: 300_000 }, () => {
  it('defers (4xx) inbound and submission recipients while Redis is down', async () => {
    try {
      await composeOk(['stop', 'redis'], { timeoutMs: 120_000 });
      const inbound = await swaks({
        server: 'postfix',
        port: 25,
        from: 'sender@example.org',
        to: [`user@${domain.name}`],
        quitAfter: 'RCPT',
      });
      expect(reply(inbound, 'RCPT#0').text).toMatch(/^4\d\d 4\.\d\.\d /);

      const submission = await swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        auth: sasl,
        from: `user@${domain.name}`,
        to: ['someone@example.com'],
        quitAfter: 'RCPT',
      });
      // The SASL backend cannot read its failure counter: temporary, never 535 (wrong password).
      expect(reply(submission, 'AUTH').text).toMatch(
        /^454 4\.7\.0 Temporary authentication failure/,
      );
      expect(submission.replies.get('RCPT#0')?.code ?? 0).not.toBe(250);
    } finally {
      await redisUp();
    }
    // Recovery: the temporary SASL failure closed the auth connection; the next session gets a
    // fresh smtpd (max_use=1 on 587) and authenticates again.
    const recovered = await swaks({
      server: 'postfix-outbound',
      port: 587,
      tls: true,
      auth: sasl,
      from: `user@${domain.name}`,
      to: ['someone@example.com'],
      quitAfter: 'AUTH',
    });
    expect(reply(recovered, 'AUTH').code).toBe(235);
  });

  it.skipIf(!adapterIsContainer)(
    'tempfails (451/4xx) every listener while the smtp-adapter container is stopped',
    async () => {
      try {
        await composeOk(['stop', 'smtp-adapter'], { timeoutMs: 120_000 });
        // A domain this suite never sent to: its relay_domain socketmap lookup reaches the
        // stopped adapter (451 4.3.0). An smtpd that resolved `domain` earlier may still pass
        // reject_unauth_destination from its resolve cache; the policy service then defers it.
        const inbound = await swaks({
          server: 'postfix',
          port: 25,
          from: 'sender@example.org',
          to: [`user@${unresolvedDomain.name}`, `user@${domain.name}`],
          quitAfter: 'RCPT',
        });
        expect(reply(inbound, 'RCPT#0').text).toMatch(/^451 4\.3\.0 /);
        expect(reply(inbound, 'RCPT#1').text).toMatch(
          /^(451 4\.3\.0 |450 4\.3\.5 .*Policy service unavailable)/,
        );

        const submission = await swaks({
          server: 'postfix-outbound',
          port: 587,
          tls: true,
          auth: sasl,
          from: `user@${domain.name}`,
          to: ['someone@example.com'],
          quitAfter: 'RCPT',
        });
        // Postfix 3.7 cannot build its AUTH mechanism list without the Dovecot auth server: the
        // submission smtpd logs `fatal: no SASL authentication mechanisms` and drops the session
        // right after STARTTLS (docs/deployment/smtp-gateway.md). Either way nothing is accepted:
        // a 454 temporary AUTH failure or a closed session, never 235/250 and never 5xx.
        const auth = submission.replies.get('AUTH');
        if (auth) {
          expect(auth.text).toMatch(/^454 4\.7\.0 /);
        } else {
          expect(submission.replies.get('STARTTLS')?.code).toBe(220);
          expect(submission.transcript).toMatch(/Remote host closed connection unexpectedly/);
        }
        expect(submission.replies.has('MAIL')).toBe(false);
        expect(submission.replies.has('RCPT#0')).toBe(false);

        // Relay listener (25) and both reinjection listeners: the policy service is unreachable,
        // so every recipient is deferred (4xx), never relayed and never rejected permanently.
        for (const [port, from, to] of [
          [25, `user@${domain.name}`, 'someone@example.com'],
          [10026, 'sender@example.org', `user@${domain.name}`],
          [10027, `user@${domain.name}`, 'someone@example.com'],
        ] as const) {
          const result = await swaks({
            server: 'postfix-outbound',
            port,
            from,
            to: [to],
            quitAfter: 'RCPT',
          });
          expect(reply(result, 'RCPT#0').text, `port ${port}`).toMatch(/^4\d\d 4\.\d\.\d /);
        }
      } finally {
        await composeOk(['start', 'smtp-adapter'], { timeoutMs: 120_000 });
        await waitFor('smtp-adapter ready', adapterReady, {
          timeoutMs: 120_000,
          intervalMs: 1_000,
        });
      }
      // Recovery: a fresh submission smtpd (max_use=1) reaches the restarted auth server at once.
      const recovered = await swaks({
        server: 'postfix-outbound',
        port: 587,
        tls: true,
        auth: sasl,
        from: `user@${domain.name}`,
        to: ['someone@example.com'],
        quitAfter: 'AUTH',
      });
      expect(reply(recovered, 'AUTH').code).toBe(235);
    },
  );
});
