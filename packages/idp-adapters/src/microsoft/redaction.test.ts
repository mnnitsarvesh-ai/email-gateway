import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { MS_USERS } from '../testing/datasets/microsoft';
import { createMicrosoftTestbed } from '../testing/harness';

/**
 * Invariant 2 end to end: after ingestion, probes, actions and failures (401, 403, 429, 5xx,
 * schema), nothing logged by the adapter stack and no error carries a token, a header, a query
 * string, a response body or an address.
 */
describe('Microsoft adapter redaction (capturing logger)', () => {
  it('logs path templates only and leaks nothing into errors', async () => {
    const tb = await createMicrosoftTestbed();
    const signal = new AbortController().signal;
    const errors: unknown[] = [];
    const capture = async (work: Promise<unknown>) => {
      try {
        const result = await work;
        errors.push(result);
      } catch (error) {
        errors.push(error);
      }
    };
    try {
      await tb.adapter.probe(signal);
      for (const stream of [
        'sign_ins',
        'risk_events',
        'oauth_consents',
        'mailbox_audit',
      ] as const) {
        await capture(tb.adapter.ingest(stream, null, signal));
      }
      tb.sims.script.inject({ path: '/v1.0/auditLogs/signIns', status: 401, times: 2 });
      await capture(tb.adapter.ingest('sign_ins', null, signal));
      tb.sims.script.inject({
        path: '/v1.0/auditLogs/signIns',
        status: 500,
        rawBody: '{"error":{"message":"EXAMPLE-body-marker alex@contoso-it.example"}}',
      });
      await capture(tb.adapter.ingest('sign_ins', null, signal));
      tb.sims.script.inject({
        path: '/v1.0/identityProtection/riskDetections',
        status: 200,
        rawBody: '{"value":"EXAMPLE-body-marker"}',
      });
      await capture(tb.adapter.ingest('risk_events', null, signal));
      tb.sims.script.inject({ path: /revokeSignInSessions/, status: 429, retryAfter: '3' });
      const id = randomUUID();
      const request = {
        actionPublicId: id,
        idempotencyKey: id,
        identity: { provider: 'microsoft_entra' as const, externalId: MS_USERS.alex },
      };
      await capture(
        tb.adapter.execute({ ...request, type: 'revoke_sessions', params: {} }, signal),
      );
      await capture(
        tb.adapter.execute(
          { ...request, actionPublicId: randomUUID(), type: 'suspend_account', params: {} },
          signal,
        ),
      );
      await capture(
        tb.adapter.execute(
          { ...request, actionPublicId: randomUUID(), type: 'require_password_reset', params: {} },
          signal,
        ),
      );
      await capture(tb.adapter.resolveIdentity('erin.alias@contoso-it.example', signal));

      expect(tb.sims.tokens.issuedCount()).toBeGreaterThan(0);
      expect(tb.logger.lines.length).toBeGreaterThan(10);
      for (const line of tb.logger.lines) {
        expect(Object.keys(line.obj).sort()).toEqual([
          'durationMs',
          'family',
          'method',
          'path',
          'status',
        ]);
        expect(String(line.obj.path)).not.toMatch(/[?@]|aaaaaaaa-/);
      }
      const errorDump = errors
        .filter((e): e is Error => e instanceof Error)
        .map(
          (e) =>
            `${JSON.stringify(e)} ${String(e)} ${e.stack ?? ''} ${JSON.stringify(Object.entries(e))}`,
        )
        .join('\n');
      expect(errors.some((e) => e instanceof Error)).toBe(true);
      const dump = `${tb.logger.text()}\n${errorDump}`;
      for (const leak of [
        'EXAMPLE-sim-token-',
        'Bearer',
        'authorization',
        '$filter',
        '$skiptoken',
        'EXAMPLE-body-marker',
        '@contoso-it.example',
        tb.sims.baseUrl('graph'),
      ]) {
        expect(dump, leak).not.toContain(leak);
      }
    } finally {
      await tb.stop();
    }
  });
});
