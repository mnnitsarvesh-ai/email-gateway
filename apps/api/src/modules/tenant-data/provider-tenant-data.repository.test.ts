import type { PrismaService } from '@email-gateway/common';
import { describe, expect, it } from 'vitest';
import { systemScope } from '../../auth-contracts/tenant-scope';
import {
  PROVIDER_PURGE_BATCH,
  PROVIDER_PURGE_ORDER,
  ProviderTenantDataRepository,
} from './provider-tenant-data.repository';

const SCOPE = systemScope(42n);
const T0 = new Date('2026-11-18T08:00:00.000Z');

/** A writer stand-in: `$executeRaw` answers from `answers`; model reads from `rows`. */
function writerDouble(answers: number[], rows: Record<string, unknown[]> = {}) {
  const statements: Array<{ sql: string; values: unknown[] }> = [];
  const reads: Array<{ model: string; args: unknown }> = [];
  const model = (name: string) => ({
    findMany: (args: unknown) => {
      reads.push({ model: name, args });
      const list = rows[name] ?? [];
      rows[name] = [];
      return Promise.resolve(list);
    },
  });
  const writer = {
    providerConnection: model('providerConnection'),
    providerConnectionGrant: model('providerConnectionGrant'),
    providerConnectionDomain: model('providerConnectionDomain'),
    providerValidationRun: model('providerValidationRun'),
    providerHealthEvent: model('providerHealthEvent'),
    $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      statements.push({ sql: strings.join('?').replace(/\s+/g, ' ').trim(), values });
      return Promise.resolve(answers.shift() ?? 0);
    },
  } as unknown as PrismaService;
  return { writer, statements, reads };
}

describe('ProviderTenantDataRepository.purgeOrganization (step 8.2 §3.3)', () => {
  it('deletes per connection in the §3.3 order, detaches relay connectors, then the connections', async () => {
    // Connection 7: counters a full batch then a short one; every other table one short batch.
    const { writer, statements } = writerDouble([2, 1, 0, 1, 1, 0, 2, 0, 1, 1, 1, 1], {
      providerConnection: [{ id: 7n }],
    });
    const counts = await new ProviderTenantDataRepository(writer).purgeOrganization(SCOPE, 2);
    expect(counts).toEqual({
      provider_relay_counters: 3,
      provider_probe_observations: 0,
      provider_health_events: 1,
      provider_health_checks: 1,
      provider_validation_runs: 0,
      provider_consent_states: 2,
      provider_connection_domains: 1,
      provider_connection_grants: 1,
      smtp_connectors_detached: 1,
      provider_connections: 1,
    });
    const tableOf = (sql: string) => /^(?:DELETE FROM|UPDATE) (\w+)/.exec(sql)![1];
    expect(statements.map((s) => tableOf(s.sql))).toEqual([
      'provider_relay_counters',
      'provider_relay_counters',
      'provider_probe_observations',
      'provider_health_events',
      'provider_health_checks',
      'provider_validation_runs',
      'provider_consent_states',
      'provider_consent_states',
      'provider_connection_domains',
      'provider_connection_grants',
      'smtp_connectors',
      'provider_connections',
    ]);
    for (const s of statements.slice(0, 10)) {
      expect(s.sql).toMatch(
        /WHERE connection_id = \? AND organization_id = \? ORDER BY id LIMIT \?$/,
      );
      expect(s.values).toEqual([7n, 42n, 2]);
    }
    expect(statements[10]!.sql).toBe(
      'UPDATE smtp_connectors SET provider_connection_id = NULL WHERE organization_id = ? ' +
        'AND provider_connection_id IS NOT NULL',
    );
    expect(statements[10]!.values).toEqual([42n]);
    expect(statements[11]!.sql).toBe(
      'DELETE FROM provider_connections WHERE organization_id = ? ORDER BY id LIMIT ?',
    );
    expect(statements[11]!.values).toEqual([42n, 2]);
  });

  it('is resumable and idempotent: without connections only the detach and the final delete run', async () => {
    const { writer, statements, reads } = writerDouble([]);
    const counts = await new ProviderTenantDataRepository(writer).purgeOrganization(SCOPE);
    expect(Object.values(counts).every((n) => n === 0)).toBe(true);
    expect(reads).toEqual([
      {
        model: 'providerConnection',
        args: { where: { organizationId: 42n }, select: { id: true }, orderBy: { id: 'asc' } },
      },
    ]);
    expect(statements).toHaveLength(2);
    expect(statements[1]!.values).toEqual([42n, PROVIDER_PURGE_BATCH]);
    await expect(
      new ProviderTenantDataRepository(writer).purgeOrganization(SCOPE, 0),
    ).rejects.toThrow('batch must be positive');
  });

  it('keeps the documented order (children before grants, grants before connections)', () => {
    expect(PROVIDER_PURGE_ORDER).toEqual([
      'provider_relay_counters',
      'provider_probe_observations',
      'provider_health_events',
      'provider_health_checks',
      'provider_validation_runs',
      'provider_consent_states',
      'provider_connection_domains',
      'provider_connection_grants',
    ]);
  });
});

describe('ProviderTenantDataRepository.exportOrganization (step 8.2 §3.3)', () => {
  it('exports connections, grants without credential material, domains, runs and health events', async () => {
    const connection = {
      id: 7n,
      publicId: '0196f0aa-0000-7000-8000-000000000001',
      provider: 'microsoft_365',
      displayName: 'Contoso',
      status: 'active',
      externalTenantId: '11111111-2222-3333-4444-555555555555',
      externalTenantName: 'Contoso',
      tenantVerifiedAt: T0,
      outboundMode: 'probe_only',
      internalRouting: false,
      relayProof: null,
      routeTokenVersion: 1,
      attestations: null,
      healthStatus: 'healthy',
      healthChangedAt: T0,
      disabledAt: null,
      createdAt: T0,
      updatedAt: T0,
    };
    const { writer, reads } = writerDouble([], {
      providerConnection: [connection],
      providerConnectionGrant: [
        {
          publicId: '0196f0aa-0000-7000-8000-000000000002',
          profile: 'm365.mail_flow',
          profileVersion: 1,
          authMethod: 'customer_app_secret',
          status: 'active',
          clientId: '22222222-3333-4444-5555-666666666666',
          subjectEmail: null,
          credentialVersion: 2,
          credentialFingerprint: 'a'.repeat(64),
          credentialSetAt: T0,
          credentialExpiresAt: null,
          requestedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
          observedPermissions: ['Organization.Read.All', 'Domain.Read.All'],
          missingPermissions: [],
          excessPermissions: [],
          consentedAt: null,
          verifiedAt: T0,
          lastErrorCode: null,
          createdAt: T0,
        },
      ],
      providerConnectionDomain: [
        {
          providerVerification: 'verified',
          providerCheckedAt: T0,
          providerMxHost: 'contoso-com.mail.protection.outlook.com',
          inboundAppliedAt: null,
          createdAt: T0,
          domain: { publicId: '0196f0aa-0000-7000-8000-000000000003', name: 'contoso.com' },
        },
      ],
      providerValidationRun: [
        {
          id: 9n,
          publicId: '0196f0aa-0000-7000-8000-000000000004',
          kind: 'full',
          status: 'passed',
          requestedByType: 'user',
          requestedById: '0196f0aa-0000-7000-8000-000000000005',
          results: { schema: 'provider-validation/1', checks: [] },
          summary: { pass: 1, warn: 0, fail: 0, skipped: 0, error: 0 },
          startedAt: T0,
          completedAt: T0,
          createdAt: T0,
        },
      ],
      providerHealthEvent: [
        { id: 3n, fromStatus: 'unknown', toStatus: 'healthy', failingChecks: [], createdAt: T0 },
      ],
    });
    const out = await new ProviderTenantDataRepository(writer).exportOrganization(SCOPE);
    expect(out.schema).toBe('provider-tenant-export/1');
    expect(out.connections).toEqual([
      expect.objectContaining({ id: connection.publicId, provider: 'microsoft_365' }),
    ]);
    expect(out.grants).toEqual([
      expect.objectContaining({
        connectionId: connection.publicId,
        credentialFingerprint: 'aaaaaaaaaaaa',
        authMethod: 'customer_app_secret',
      }),
    ]);
    expect(out.domains[0]).toMatchObject({ name: 'contoso.com', providerVerification: 'verified' });
    expect(out.validationRuns[0]).toMatchObject({ kind: 'full', status: 'passed' });
    expect(out.healthEvents[0]).toMatchObject({ toStatus: 'healthy' });
    // Never the ciphertext, its key id or the probe token hash; every read is the organization's.
    const grantRead = reads.find((r) => r.model === 'providerConnectionGrant')!.args as {
      select: Record<string, boolean>;
      where: unknown;
    };
    expect(grantRead.select.credentialCiphertext).toBeUndefined();
    expect(grantRead.select.credentialKeyId).toBeUndefined();
    const runRead = reads.find((r) => r.model === 'providerValidationRun')!.args as {
      select: Record<string, boolean>;
    };
    expect(runRead.select.probeTokenSha256).toBeUndefined();
    for (const read of reads) {
      expect(
        JSON.stringify(read.args, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}n` : v)),
      ).toContain('"organizationId":"42n"');
    }
    expect(
      JSON.stringify(out, (_k, v: unknown) => (typeof v === 'bigint' ? `${v}` : v)),
    ).not.toMatch(/ciphertext|probeToken/i);
  });
});
