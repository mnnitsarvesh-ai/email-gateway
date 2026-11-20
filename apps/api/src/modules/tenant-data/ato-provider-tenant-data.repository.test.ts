import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  ATO_PROVIDER_PURGE_BATCH,
  ATO_PROVIDER_PURGE_ORDER,
  AtoProviderTenantDataRepository,
} from './ato-provider-tenant-data.repository';

const SCOPE = systemScope(42n);
const T0 = new Date('2026-11-20T08:00:00.000Z');

/** A writer stand-in: `$executeRaw` answers from `answers`; model reads from `rows` (once). */
function writerDouble(answers: number[], rows: Record<string, unknown[][]> = {}) {
  const statements: Array<{ sql: string; values: unknown[] }> = [];
  const reads: Array<{ model: string; args: unknown }> = [];
  const model = (name: string) => ({
    findMany: (args: unknown) => {
      reads.push({ model: name, args });
      return Promise.resolve(rows[name]?.shift() ?? []);
    },
  });
  const writer = {
    atoProviderIntegration: model('atoProviderIntegration'),
    atoProviderStream: model('atoProviderStream'),
    atoProviderMailboxItem: model('atoProviderMailboxItem'),
    atoAccount: model('atoAccount'),
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
      return Promise.resolve(answers.shift() ?? 0);
    },
  } as unknown as PrismaService;
  return { writer, statements, reads };
}

describe('AtoProviderTenantDataRepository.purgeOrganization (step 8.5 §4.1)', () => {
  it('deletes mailbox items then streams per integration, then identities and integrations', async () => {
    // Integration 7: items a full batch then a short one; streams one short batch; identities
    // one short batch; integrations one short batch.
    const { writer, statements } = writerDouble([2, 1, 1, 1, 1], {
      atoProviderIntegration: [[{ id: 7n }]],
    });
    const counts = await new AtoProviderTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      ato_provider_mailbox_items: 3,
      ato_provider_streams: 1,
      ato_account_identities: 1,
      ato_provider_integrations: 1,
    });
    const tableOf = (sql: string) => /^DELETE FROM (\w+)/.exec(sql)![1];
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'ato_provider_mailbox_items',
      'ato_provider_mailbox_items',
      'ato_provider_streams',
      'ato_account_identities',
      'ato_provider_integrations',
    ]);
    for (const s of statements.slice(0, 3)) {
      expect(s.sql).toMatch(
        /WHERE integration_id = \? AND organization_id = \? ORDER BY id LIMIT \?$/,
      );
      expect(s.values).toEqual([7n, 42n, 2]);
    }
    for (const s of statements.slice(3)) {
      expect(s.sql).toMatch(/WHERE organization_id = \? ORDER BY id LIMIT \?$/);
      expect(s.values).toEqual([42n, 2]);
    }
  });

  it('runs in the documented order with the default batch and refuses a bad batch', async () => {
    expect(ATO_PROVIDER_PURGE_ORDER).toEqual([
      'ato_provider_mailbox_items',
      'ato_provider_streams',
      'ato_account_identities',
      'ato_provider_integrations',
    ]);
    const { writer, statements } = writerDouble([], { atoProviderIntegration: [[]] });
    const counts = await new AtoProviderTenantDataRepository(writer).purgeOrganization(SCOPE);
    expect(Object.values(counts)).toEqual([0, 0, 0, 0]);
    // No integration left: only the organization-wide statements run.
    expect(statements.map((s) => s.values)).toEqual([
      [42n, ATO_PROVIDER_PURGE_BATCH],
      [42n, ATO_PROVIDER_PURGE_BATCH],
    ]);
    await expect(
      new AtoProviderTenantDataRepository(writer).purgeOrganization(SCOPE, 0),
    ).rejects.toThrow('batch must be positive');
  });
});

describe('AtoProviderTenantDataRepository.exportOrganization (step 8.5 §4.1)', () => {
  it('exports integrations, streams and mailbox items with public ids and no token or address', async () => {
    const integration = {
      id: 7n,
      publicId: 'int-public',
      provider: 'microsoft_entra',
      connectorRef: 'conn-public',
      displayName: 'EXAMPLE',
      status: 'active',
      pausedReason: null,
      disabledReason: null,
      disabledAt: null,
      settings: { pollIntervalSeconds: 300 },
      settingsVersion: 2,
      healthStatus: 'healthy',
      healthCheckedAt: T0,
      grantedPermissions: ['AuditLog.Read.All'],
      directoryDomains: ['contoso-it.example'],
      cursors: { secretish: 'never exported' },
      createdAt: T0,
      updatedAt: T0,
    };
    const stream = {
      integrationId: 7n,
      stream: 'sign_ins',
      role: 'primary',
      enabled: true,
      status: 'active',
      availability: 'available',
      availabilityCode: null,
      cursor: 'opaque-cursor-never-exported',
      watermarkAt: T0,
      backfillFrom: null,
      backfillCompletedAt: null,
      lastSuccessAt: T0,
      lastEventAt: T0,
      lastErrorCode: null,
      eventsTotal: 12n,
      pagesTotal: 3n,
    };
    const item = {
      id: 9n,
      publicId: 'item-public',
      integrationId: 7n,
      accountId: 5n,
      identityExternalIdHash: 'a'.repeat(64),
      itemKind: 'inbox_rule',
      itemHash: 'b'.repeat(64),
      providerItemRef: 'provider-rule-id-never-exported',
      targetDomain: 'external-example.net',
      traits: ['forwards_external'],
      enabled: true,
      state: 'present',
      source: 'snapshot',
      lastChange: 'added',
      firstSeenAt: T0,
      lastSeenAt: T0,
      removedAt: null,
    };
    const { writer } = writerDouble([], {
      atoProviderIntegration: [[integration]],
      atoProviderStream: [[stream]],
      atoProviderMailboxItem: [[item]],
      atoAccount: [[{ id: 5n, publicId: 'account-public' }]],
    });
    const out = await new AtoProviderTenantDataRepository(writer).exportOrganization(SCOPE);
    expect(out.schema).toBe('ato-provider-tenant-export/1');
    expect(out.integrations).toEqual([
      expect.objectContaining({
        id: 'int-public',
        connectionId: 'conn-public',
        grantedPermissions: ['AuditLog.Read.All'],
        healthCheckedAt: T0.toISOString(),
      }),
    ]);
    expect(out.streams).toEqual([
      expect.objectContaining({ integrationId: 'int-public', eventsTotal: '12', pagesTotal: '3' }),
    ]);
    expect(out.mailboxItems).toEqual([
      expect.objectContaining({
        id: 'item-public',
        integrationId: 'int-public',
        accountId: 'account-public',
        targetDomain: 'external-example.net',
      }),
    ]);
    const text = JSON.stringify(out);
    expect(text).not.toContain('never exported');
    expect(text).not.toContain('opaque-cursor');
    expect(text).not.toContain('provider-rule-id');
  });
});
