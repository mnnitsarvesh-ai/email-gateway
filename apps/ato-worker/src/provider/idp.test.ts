import { MetricsService } from '@email-gateway/common';
import type { AtoProviderIntegration } from '@email-gateway/database';
import { encodeCursor, MICROSOFT_ADAPTER_VERSION } from '@email-gateway/idp-adapters';
import { describe, expect, it } from 'vitest';
import { IdpMetrics } from '../metrics/idp-metrics';
import { providerParams } from '../respond/idp-actions';
import { selectIntegration } from '../respond/integration-selector';
import {
  adapterIntegrationOf,
  bindingSettingsOf,
  directoryDomainsOf,
  healthDetailOf,
  IdpBindingError,
} from './idp-runtime';
import { storedCapabilities } from './provider-context';
import { isLockConflict, RedisRateBudget, type BudgetPipeline } from './stores';
import { companionsOf, SNAPSHOT_PRIMARY, sweepCompleted } from './stream-runner';

const row = (over: Partial<AtoProviderIntegration> = {}): AtoProviderIntegration =>
  ({
    id: 11n,
    publicId: '0193a1b2-3e4f-7a50-9c6d-7e8f90123456',
    organizationId: 7n,
    provider: 'microsoft_entra',
    connectorRef: '0193a1b2-0000-7000-8000-000000000001',
    settings: {},
    settingsVersion: 1,
    healthDetail: null,
    healthCheckedAt: null,
    directoryRefHash: 'a'.repeat(64),
    directoryDomains: ['contoso-it.example', 'NOT A DOMAIN'],
    status: 'active',
    ...over,
  }) as AtoProviderIntegration;

describe('IdpRuntime row mapping (D1, D10)', () => {
  it('maps an integration row to the adapter view (defaults for 8.4 `{}` settings)', () => {
    const view = adapterIntegrationOf(row());
    expect(view).toMatchObject({
      id: '11',
      organizationId: '7',
      provider: 'microsoft_entra',
      connectionPublicId: '0193a1b2-0000-7000-8000-000000000001',
      directoryDomains: ['contoso-it.example'],
      health: null,
    });
    expect(view.settings.pollIntervalSeconds).toBe(300);
  });

  it('refuses unbound rows, unknown kinds and invalid settings (never a guess)', () => {
    expect(() => adapterIntegrationOf(row({ connectorRef: null }))).toThrow(IdpBindingError);
    expect(() => adapterIntegrationOf(row({ provider: 'fake' }))).toThrow(IdpBindingError);
    expect(() => bindingSettingsOf('microsoft_entra', { pollIntervalSeconds: 5 })).toThrow(
      IdpBindingError,
    );
  });

  it('reads only well-formed probe reports and domain lists', () => {
    expect(healthDetailOf({ checkedAt: 'x' })).toBeNull();
    expect(
      healthDetailOf({
        checkedAt: '2026-11-20T00:00:00.000Z',
        streams: {},
        actions: {},
        grants: [],
      }),
    ).not.toBeNull();
    expect(directoryDomainsOf('contoso-it.example')).toEqual([]);
    expect(directoryDomainsOf(['a.example', 1, 'B.example'])).toEqual(['a.example']);
  });
});

describe('stored effective capabilities (D6) for the detect role', () => {
  it('keeps known streams and action shapes only', () => {
    const caps = storedCapabilities({
      streams: { sign_ins: { supported: true }, bogus: { supported: true } },
      actions: { revoke_sessions: { supported: true, rollback: 'yes', confirmation: 'polling' } },
    });
    expect(caps.streams).toEqual({ sign_ins: { supported: true } });
    expect(caps.actions.revoke_sessions).toEqual({
      supported: true,
      rollback: false,
      confirmation: 'polling',
    });
    expect(storedCapabilities(null)).toEqual({ streams: {}, actions: {} });
  });
});

describe('stream roles and sweeps (D3, D8.3)', () => {
  it('lists the companions of a primary per provider', () => {
    expect(companionsOf('microsoft_entra', 'mailbox_audit').sort()).toEqual([
      'delegation_changes',
      'forwarding_changes',
    ]);
    expect(companionsOf('google_workspace', 'sign_ins')).toEqual(['risk_events']);
    expect(companionsOf('google_workspace', 'oauth_consents')).toEqual([]);
    expect(SNAPSHOT_PRIMARY.google_workspace).toBe('forwarding_changes');
  });

  it('recognises a completed sweep from the cursor (sweep state without continuation)', () => {
    const v = MICROSOFT_ADAPTER_VERSION;
    const at = '2026-11-20T00:00:00.000Z';
    expect(sweepCompleted(encodeCursor({ v: 1, a: v, seq: 3, sw: { at } }), v)).toBe(true);
    expect(sweepCompleted(encodeCursor({ v: 1, a: v, seq: 3, sw: { at, next: 'tok' } }), v)).toBe(
      false,
    );
    expect(sweepCompleted(encodeCursor({ v: 1, a: v, seq: 3, sw: { at }, page: 'u:5' }), v)).toBe(
      false,
    );
    expect(sweepCompleted(encodeCursor({ v: 1, a: v, seq: 3 }), v)).toBe(false);
    expect(sweepCompleted('garbage', v)).toBe(false);
  });
});

describe('RedisRateBudget (D7.5)', () => {
  class FakeRedis {
    readonly counts = new Map<string, number>();
    readonly ttls = new Map<string, number>();
    multi(): BudgetPipeline {
      const ops: Array<() => [null, unknown]> = [];
      const pipeline: BudgetPipeline = {
        incr: (key) => {
          ops.push(() => {
            const n = (this.counts.get(key) ?? 0) + 1;
            this.counts.set(key, n);
            return [null, n];
          });
          return pipeline;
        },
        expire: (key, seconds) => {
          ops.push(() => {
            this.ttls.set(key, seconds);
            return [null, 1];
          });
          return pipeline;
        },
        exec: () => Promise.resolve(ops.map((op) => op())),
      };
      return pipeline;
    }
  }
  const limits = { graph: 2, o365: 1, google_reports: 1, google_directory: 1, gmail: 1 };
  const signal = new AbortController().signal;

  it('allows the per-second limit per integration and family, keyed by epoch second', async () => {
    const redis = new FakeRedis();
    let now = 1_700_000_000_500;
    const budget = new RedisRateBudget(redis, limits, () => now);
    expect(await budget.take('42', 'graph', signal)).toBe('ok');
    expect(await budget.take('42', 'graph', signal)).toBe('ok');
    expect(await budget.take('42', 'graph', signal)).toBe('exhausted');
    expect(await budget.take('43', 'graph', signal)).toBe('ok');
    expect(await budget.take('42', 'o365', signal)).toBe('ok');
    now += 1000;
    expect(await budget.take('42', 'graph', signal)).toBe('ok');
    expect([...redis.ttls.keys()]).toContain('ato:idp:rb:42:graph:s1700000000');
    expect([...redis.ttls.values()].every((t) => t === 5)).toBe(true);
  });

  it('refuses malformed integration ids and unknown families', async () => {
    const budget = new RedisRateBudget(new FakeRedis(), limits);
    await expect(budget.take('x:1', 'graph', signal)).rejects.toThrow('rate_budget_key_invalid');
    await expect(budget.take('1', 'smtp' as never, signal)).rejects.toThrow();
  });
});

describe('lock conflicts', () => {
  it('recognises MySQL deadlocks and lock waits only', () => {
    expect(isLockConflict({ code: 'P2034' })).toBe(true);
    expect(isLockConflict({ code: 'P2010', meta: { code: '1213' } })).toBe(true);
    expect(isLockConflict({ code: 'P2010', message: 'Raw query failed. Code: `1205`.' })).toBe(
      true,
    );
    expect(isLockConflict({ code: 'P2010', message: 'Code: `1064`' })).toBe(false);
    expect(isLockConflict(new Error('x'))).toBe(false);
  });
});

describe('IdpMetrics (D11)', () => {
  it('registers the D11 series and never accepts free-text labels', async () => {
    const service = new MetricsService({ service: 'ato-idp-unit' });
    const m = new IdpMetrics(service);
    const sink = m.sink();
    sink.httpRequest?.({ provider: 'microsoft_entra', family: 'graph', statusClass: '2xx' }, 0.1);
    sink.events?.({ provider: 'google_workspace', stream: 'sign_ins', result: 'Tenant Name' }, 2);
    sink.action?.({ provider: 'microsoft_entra', action: 'revoke_sessions', outcome: 'confirmed' });
    const text = await service.registry.metrics();
    for (const name of [
      'ato_idp_http_requests_total',
      'ato_idp_http_seconds',
      'ato_idp_throttled_total',
      'ato_idp_rate_budget_waits_total',
      'ato_idp_events_total',
      'ato_idp_stream_lag_seconds',
      'ato_idp_integrations',
      'ato_idp_backfills_active',
      'ato_idp_snapshot_items_total',
      'ato_idp_probe_total',
      'ato_idp_actions_total',
      'ato_idp_cursor_resets_total',
    ]) {
      expect(text).toContain(`# TYPE ${name}`);
    }
    expect(text).toContain('result="other"');
    expect(text).not.toContain('Tenant Name');
  });
});

describe('integration selection (D9.2, inv. 4)', () => {
  const integration = (id: bigint, over: Partial<AtoProviderIntegration> = {}) =>
    row({ id, directoryDomains: ['contoso-it.example'], ...over });
  const prisma = (rows: AtoProviderIntegration[], identities: { integrationId: bigint }[] = []) =>
    ({
      atoProviderIntegration: {
        findMany: (args: { where: { id?: bigint | { in: bigint[] } } }) => {
          const w = args.where.id;
          if (w === undefined) return Promise.resolve(rows);
          const ids = typeof w === 'bigint' ? [w] : w.in;
          return Promise.resolve(rows.filter((r) => ids.includes(r.id)));
        },
      },
      atoAccountIdentity: {
        findMany: () =>
          Promise.resolve(
            identities.map((i) => ({ organizationId: 7n, integrationId: i.integrationId })),
          ),
      },
    }) as never;
  const action = { organizationId: 7n, accountId: 3n, integrationId: null };
  const mailbox = {
    organizationId: 7n,
    kind: 'mailbox' as const,
    address: 'alex@contoso-it.example',
  };

  it('refuses non-mailbox accounts and finds nothing without an integration', async () => {
    expect(
      await selectIntegration(prisma([]), action, { ...mailbox, kind: 'gateway_user' }),
    ).toMatchObject({ ok: false, code: 'not_a_mailbox_account' });
    expect(await selectIntegration(prisma([]), action, mailbox)).toMatchObject({
      ok: false,
      outcome: 'unsupported',
      code: 'no_integration',
    });
  });

  it('selects by linked domain; several ⇒ ambiguous; disabled only ⇒ integration_disabled', async () => {
    expect(await selectIntegration(prisma([integration(1n)]), action, mailbox)).toMatchObject({
      ok: true,
      domain: 'contoso-it.example',
    });
    expect(
      await selectIntegration(prisma([integration(1n), integration(2n)]), action, mailbox),
    ).toMatchObject({ ok: false, code: 'ambiguous_integration' });
    expect(
      await selectIntegration(prisma([integration(1n, { status: 'disabled' })]), action, mailbox),
    ).toMatchObject({ ok: false, code: 'integration_disabled' });
  });

  it('prefers the identity mapping, then applies the linked-domain guard and the status', async () => {
    const other = integration(5n, { directoryDomains: ['fabrikam-it.example'] });
    expect(
      await selectIntegration(
        prisma([integration(1n), other], [{ integrationId: 5n }]),
        action,
        mailbox,
      ),
    ).toMatchObject({ ok: false, code: 'domain_not_linked' });
    expect(
      await selectIntegration(
        prisma([integration(1n, { status: 'paused' })], [{ integrationId: 1n }]),
        action,
        mailbox,
      ),
    ).toMatchObject({ ok: false, code: 'integration_paused' });
    expect(
      await selectIntegration(prisma([integration(1n)]), { ...action, integrationId: 9n }, mailbox),
    ).toMatchObject({ ok: false, code: 'integration_disabled' });
  });

  it('echo-checks the account organization', async () => {
    await expect(
      selectIntegration(prisma([]), action, { ...mailbox, organizationId: 8n }),
    ).rejects.toThrow('inconsistent read');
  });
});

describe('provider action parameters (D9.7, WP6)', () => {
  it('defaults remove_forwarding_rule without item or scope to all external forwarding', () => {
    expect(providerParams('remove_forwarding_rule', {})).toEqual({ scope: 'all_external' });
    expect(providerParams('remove_forwarding_rule', null)).toEqual({ scope: 'all_external' });
  });

  it('keeps an explicit item, scope or app hash unchanged', () => {
    const itemId = '0193a1b2-3e4f-7a50-9c6d-7e8f90123456';
    expect(providerParams('remove_forwarding_rule', { itemId })).toEqual({ itemId });
    expect(providerParams('remove_forwarding_rule', { scope: 'all_external' })).toEqual({
      scope: 'all_external',
    });
    expect(providerParams('revoke_oauth_grant', { appIdHash: 'a'.repeat(64) })).toEqual({
      appIdHash: 'a'.repeat(64),
    });
    expect(providerParams('suspend_account', {})).toEqual({});
    expect(providerParams('suspend_account', ['x'])).toEqual({});
  });
});
