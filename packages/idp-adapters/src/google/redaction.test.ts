import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { GS_USERS } from '../testing/datasets/google';
import { createGoogleTestbed } from '../testing/google-harness';

/**
 * Invariant 2 end to end for Google: after ingestion (Reports, settings sweep), probes, actions and
 * failures (401, 403, 429, 5xx, schema), nothing logged by the adapter stack and no error carries a
 * token, a header, a query string, a response body, an address or a user id.
 */
describe('Google adapter redaction (capturing logger)', () => {
  it('logs path templates only and leaks nothing into errors', async () => {
    const tb = await createGoogleTestbed();
    const signal = new AbortController().signal;
    const outcomes: unknown[] = [];
    const capture = async (work: Promise<unknown>) => {
      try {
        outcomes.push(await work);
      } catch (error) {
        outcomes.push(error);
      }
    };
    try {
      await tb.adapter.probe(signal);
      for (const stream of ['sign_ins', 'oauth_consents', 'forwarding_changes'] as const) {
        await capture(tb.adapter.ingest(stream, null, signal));
      }
      tb.sims.script.inject({ path: '/admin/reports/v1/activity', status: 401, times: 2 });
      await capture(tb.adapter.ingest('sign_ins', null, signal));
      tb.sims.script.inject({
        path: '/admin/reports/v1/activity',
        status: 500,
        rawBody: '{"error":{"message":"EXAMPLE-body-marker alex@fabrikam-it.example"}}',
      });
      await capture(tb.adapter.ingest('sign_ins', null, signal));
      tb.sims.script.inject({
        path: '/admin/reports/v1/activity',
        status: 200,
        rawBody: '{"items":"EXAMPLE-body-marker"}',
      });
      await capture(tb.adapter.ingest('oauth_consents', null, signal));
      tb.sims.script.inject({
        simulator: 'gmail',
        path: /settings/,
        status: 403,
        reason: 'forbidden',
      });
      tb.clock.advance(2 * 86_400_000);
      await capture(tb.adapter.ingest('forwarding_changes', null, signal));
      const identity = { provider: 'google_workspace' as const, externalId: GS_USERS.alex };
      tb.sims.script.inject({ method: 'POST', path: /signOut$/, status: 429, retryAfter: '3' });
      for (const type of ['revoke_sessions', 'suspend_account', 'require_mfa'] as const) {
        const id = randomUUID();
        await capture(
          tb.adapter.execute(
            { actionPublicId: id, idempotencyKey: id, identity, type, params: {} },
            signal,
          ),
        );
      }
      const root = randomUUID();
      await capture(
        tb.adapter.execute(
          {
            actionPublicId: root,
            idempotencyKey: root,
            identity: { provider: 'google_workspace', externalId: GS_USERS.root },
            type: 'suspend_account',
            params: {},
          },
          signal,
        ),
      );
      await capture(tb.adapter.resolveIdentity('erin.alias@fabrikam-it.example', signal));

      expect(tb.sims.tokens.issuedCount()).toBeGreaterThan(0);
      expect(tb.logger.lines.length).toBeGreaterThan(20);
      for (const line of tb.logger.lines) {
        expect(Object.keys(line.obj).sort()).toEqual([
          'durationMs',
          'family',
          'method',
          'path',
          'status',
        ]);
        expect(String(line.obj.path)).not.toMatch(/[?@%]|1000000000|ANe1Bmg|googleusercontent/);
      }
      const errors = outcomes.filter((e): e is Error => e instanceof Error);
      expect(errors.length).toBeGreaterThan(0);
      const errorDump = errors
        .map(
          (e) =>
            `${JSON.stringify(e)} ${String(e)} ${e.stack ?? ''} ${JSON.stringify(Object.entries(e))}`,
        )
        .join('\n');
      const dump = `${tb.logger.text()}\n${errorDump}`;
      for (const leak of [
        'EXAMPLE-sim-token-',
        'Bearer',
        'authorization',
        'startTime',
        'pageToken',
        'EXAMPLE-body-marker',
        '@fabrikam-it.example',
        '@exfil-mail.example',
        tb.sims.baseUrl('google-admin'),
        tb.sims.baseUrl('gmail'),
      ]) {
        expect(dump, leak).not.toContain(leak);
      }
      // Action state never holds an address (D9.3).
      for (const outcome of outcomes) {
        const reference = (outcome as { providerReference?: string }).providerReference;
        if (reference) {
          const id = reference.split(':').at(-1) as string;
          expect(JSON.stringify(tb.actionState.peek(id))).not.toContain('@');
        }
      }
    } finally {
      await tb.stop();
    }
  });
});
