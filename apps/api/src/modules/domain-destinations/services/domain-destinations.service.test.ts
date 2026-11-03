import { ConflictException, NotFoundException, BadRequestException } from '@nestjs/common';
import { MAIL_DESTINATION_PRESETS } from '@email-gateway/database';
import { domainRoutingChangedV1 } from '@email-gateway/event-contracts';
import { mailDestinationPresetSchema } from '@email-gateway/mail-routing';
import { describe, expect, it, vi } from 'vitest';
import type { AuditService } from '../../../audit/audit.service';
import type { ApiKeyPrincipal } from '../../../auth-contracts/principal';
import { systemScope } from '../../../auth-contracts/tenant-scope';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { DomainOutboxRepository } from '../../domains/repositories/domain-outbox.repository';
import type { PlannedServer } from '../domain/destination-plan';
import { DestinationRefusedException } from '../domain-destinations.errors';
import type {
  DestinationDomainRow,
  DestinationServerRow,
  DomainDestinationsRepository,
  SharedDestinationPolicy,
} from '../repositories/domain-destinations.repository';
import {
  type DomainDestinationsConfig,
  DomainDestinationsService,
} from './domain-destinations.service';

const presets = MAIL_DESTINATION_PRESETS.map((preset) =>
  mailDestinationPresetSchema.parse({
    ...preset,
    hostPatterns: [...preset.hostPatterns],
    defaultServers: preset.defaultServers ? [...preset.defaultServers] : null,
  }),
);

const config: DomainDestinationsConfig = {
  GATEWAY_MX_HOSTS: [{ priority: 10, host: 'mx1.mail-gateway.test' }],
  POSTFIX_MYHOSTNAME: 'mx.gateway.local',
  POSTFIX_OUTBOUND_MYHOSTNAME: 'out.gateway.local',
  POSTFIX_BOUNCE_DOMAIN: 'bounces.gateway.internal',
  ROUTING_ALLOW_NON_PUBLIC_DESTINATIONS: false,
  ROUTING_DENIED_DESTINATION_SUFFIXES: [],
  ROUTING_ALLOWED_DESTINATION_PORTS: [25, 587, 2525],
  ROUTING_MAX_DESTINATIONS_PER_DOMAIN: 3,
};

const scope = systemScope(7n);
const principal: ApiKeyPrincipal = {
  kind: 'api_key',
  apiKeyId: 1n,
  apiKeyPublicId: '0195f3c1-7a2b-7c3d-8e4f-5a6b7c8d9e0f',
  organizationId: 7n,
  organizationPublicId: '0195f3c1-7a2b-7c3d-8e4f-000000000007',
  permissions: new Set(['domain:routing_manage']),
};
const client = { ip: '192.0.2.1', userAgent: null };
const DOMAIN_ID = '0195f3c1-7a2b-7c3d-8e4f-0000000000dd';

function harness(
  domain: DestinationDomainRow | null = {
    id: 42n,
    publicId: DOMAIN_ID,
    name: 'acme.test',
    status: 'active',
  },
  shared: SharedDestinationPolicy[] = [],
) {
  let rows: DestinationServerRow[] = [];
  const at = new Date('2026-11-03T00:00:00.000Z');
  const toRows = (servers: readonly PlannedServer[]): DestinationServerRow[] =>
    servers.map((server, index) => ({
      publicId: `0195f3c1-7a2b-7c3d-8e4f-${String(index).padStart(12, '0')}`,
      enabled: true,
      createdAt: at,
      updatedAt: at,
      ...server,
    }));
  const repository = {
    findDomain: vi.fn(() => Promise.resolve(domain)),
    lockDomain: vi.fn(() => Promise.resolve(domain)),
    listServers: vi.fn(() => Promise.resolve([...rows].sort((a, b) => a.priority - b.priority))),
    replaceServers: vi.fn(
      (_tx: unknown, _scope: unknown, _id: bigint, servers: PlannedServer[]) => {
        rows = toRows(servers);
        return Promise.resolve();
      },
    ),
    deleteServers: vi.fn(() => {
      const count = rows.length;
      rows = [];
      return Promise.resolve(count);
    }),
    presets: vi.fn(() => Promise.resolve(presets)),
    lockSharedDestinations: vi.fn(
      (_tx: unknown, _scope: unknown, _hosts: string[]): Promise<SharedDestinationPolicy[]> =>
        Promise.resolve(shared),
    ),
  };
  const audit = {
    record: vi.fn(() => Promise.resolve()),
    actorFrom: vi.fn(() => ({ type: 'api_key', id: principal.apiKeyPublicId })),
  };
  const outbox = { insertRoutingChanged: vi.fn(() => Promise.resolve('e')) };
  const transactions = { run: vi.fn((fn: (tx: unknown) => Promise<unknown>) => fn({})) };
  const service = new DomainDestinationsService(
    config,
    transactions as unknown as TransactionRunner,
    audit as unknown as AuditService,
    repository as unknown as DomainDestinationsRepository,
    outbox as unknown as DomainOutboxRepository,
  );
  return {
    service,
    repository,
    audit,
    outbox,
    setRows: (r: PlannedServer[]) => (rows = toRows(r)),
  };
}

describe('DomainDestinationsService', () => {
  it('replaces the destinations, audits and writes domain.routing.changed.v1 with old and new hosts', async () => {
    const h = harness();
    h.setRows([
      {
        host: 'old.example',
        port: 25,
        priority: 10,
        tlsMode: 'opportunistic',
        tlsVerifyNames: null,
        provider: 'custom',
      },
    ]);
    const view = await h.service.replace(
      principal,
      scope,
      DOMAIN_ID,
      { provider: 'microsoft_365', host: 'acme-test.mail.protection.outlook.com' },
      client,
    );
    expect(view.provider).toBe('microsoft_365');
    expect(view.servers.map((s) => [s.host, s.port, s.tlsMode])).toEqual([
      ['acme-test.mail.protection.outlook.com', 25, 'verify'],
    ]);
    expect(h.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: 7n,
        action: 'domain.destinations_replaced',
        resourceType: 'domain',
        resourceId: DOMAIN_ID,
        sourceIp: '192.0.2.1',
        metadata: {
          name: 'acme.test',
          provider: 'microsoft_365',
          hosts: ['acme-test.mail.protection.outlook.com'],
          count: 1,
          previous: { provider: 'custom', hosts: ['old.example'] },
        },
      }),
      {},
    );
    const event = (h.outbox.insertRoutingChanged.mock.calls[0] as unknown[])[1] as {
      organizationId: bigint;
      payload: unknown;
    };
    expect(event.organizationId).toBe(7n);
    expect(domainRoutingChangedV1.parse(event.payload)).toMatchObject({
      domainId: '42',
      domainPublicId: DOMAIN_ID,
      name: 'acme.test',
      hosts: ['acme-test.mail.protection.outlook.com', 'old.example'],
    });
  });

  it('writes nothing for a body equal to the stored rows', async () => {
    const h = harness();
    const body = {
      provider: 'custom' as const,
      servers: [{ host: 'mx.example' }, { host: 'b.example', priority: 5 }],
    };
    await h.service.replace(principal, scope, DOMAIN_ID, body, client);
    h.audit.record.mockClear();
    h.outbox.insertRoutingChanged.mockClear();
    h.repository.replaceServers.mockClear();
    const view = await h.service.replace(principal, scope, DOMAIN_ID, body, client);
    expect(view.servers.map((s) => s.host)).toEqual(['b.example', 'mx.example']);
    expect(h.repository.replaceServers).not.toHaveBeenCalled();
    expect(h.audit.record).not.toHaveBeenCalled();
    expect(h.outbox.insertRoutingChanged).not.toHaveBeenCalled();
  });

  it('refuses with 422 + reason, 404 for an unknown domain, 409 for a deleted one', async () => {
    const h = harness();
    const refused = h.service.replace(
      principal,
      scope,
      DOMAIN_ID,
      { provider: 'custom', servers: [{ host: 'mx.gateway.local' }] },
      client,
    );
    await expect(refused).rejects.toBeInstanceOf(DestinationRefusedException);
    await expect(refused).rejects.toMatchObject({
      reason: 'gateway_host',
      field: 'servers.0.host',
    });
    await expect(
      h.service.replace(
        principal,
        scope,
        DOMAIN_ID,
        { provider: 'custom', servers: [{ host: 'mx1.mail-gateway.test' }] },
        client,
      ),
    ).rejects.toMatchObject({ reason: 'gateway_host' });
    expect(h.repository.replaceServers).not.toHaveBeenCalled();

    const missing = harness(null);
    await expect(missing.service.get(scope, DOMAIN_ID)).rejects.toBeInstanceOf(NotFoundException);
    await expect(
      missing.service.remove(principal, scope, DOMAIN_ID, client),
    ).rejects.toBeInstanceOf(NotFoundException);

    const deleted = harness({ id: 1n, publicId: DOMAIN_ID, name: 'gone.test', status: 'deleted' });
    await expect(
      deleted.service.replace(
        principal,
        scope,
        DOMAIN_ID,
        { provider: 'google_workspace' },
        client,
      ),
    ).rejects.toBeInstanceOf(ConflictException);
    await expect(
      deleted.service.remove(principal, scope, DOMAIN_ID, client),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('refuses a custom host another organization uses with a different TLS policy (422)', async () => {
    const victim: SharedDestinationPolicy = {
      host: 'mail.victim-b.com',
      port: 25,
      tlsMode: 'opportunistic',
      tlsVerifyNames: null,
      provider: 'custom',
    };
    const h = harness(undefined, [victim]);
    const attack = h.service.replace(
      principal,
      scope,
      DOMAIN_ID,
      {
        provider: 'custom',
        servers: [
          { host: 'own.example' },
          { host: 'MAIL.victim-b.com', tlsMode: 'verify', tlsVerifyNames: 'bogus.invalid' },
        ],
      },
      client,
    );
    await expect(attack).rejects.toMatchObject({
      reason: 'destination_tls_conflict',
      field: 'servers.1.tlsMode',
    });
    // Only the custom hosts are checked, normalized, for the caller's organization.
    expect(h.repository.lockSharedDestinations).toHaveBeenCalledWith({}, scope, [
      'own.example',
      'mail.victim-b.com',
    ]);
    expect(h.repository.replaceServers).not.toHaveBeenCalled();
    expect(h.outbox.insertRoutingChanged).not.toHaveBeenCalled();

    // The same policy (or another port) is accepted: the shared next hop's answer is unchanged.
    await h.service.replace(
      principal,
      scope,
      DOMAIN_ID,
      { provider: 'custom', servers: [{ host: 'mail.victim-b.com' }] },
      client,
    );
    await h.service.replace(
      principal,
      scope,
      DOMAIN_ID,
      {
        provider: 'custom',
        servers: [{ host: 'mail.victim-b.com', port: 587, tlsMode: 'verify' }],
      },
      client,
    );
    expect(h.repository.replaceServers).toHaveBeenCalledTimes(2);

    // verify rows must agree on the match= list too.
    const strict = harness(undefined, [
      { ...victim, tlsMode: 'verify', tlsVerifyNames: 'nexthop' },
    ]);
    await expect(
      strict.service.replace(
        principal,
        scope,
        DOMAIN_ID,
        { provider: 'custom', servers: [{ host: 'mail.victim-b.com', tlsMode: 'verify' }] },
        client,
      ),
    ).rejects.toMatchObject({ reason: 'destination_tls_conflict' });
  });

  it('refuses more custom servers than ROUTING_MAX_DESTINATIONS_PER_DOMAIN (400)', async () => {
    const h = harness();
    const servers = ['a', 'b', 'c', 'd'].map((label) => ({ host: `${label}.example` }));
    await expect(
      h.service.replace(principal, scope, DOMAIN_ID, { provider: 'custom', servers }, client),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(h.repository.lockDomain).not.toHaveBeenCalled();
  });

  it('removes every destination with audit and event; nothing to remove writes nothing', async () => {
    const h = harness();
    await h.service.remove(principal, scope, DOMAIN_ID, client);
    expect(h.audit.record).not.toHaveBeenCalled();
    h.setRows([
      {
        host: 'a.example',
        port: 25,
        priority: 10,
        tlsMode: 'none',
        tlsVerifyNames: null,
        provider: 'custom',
      },
    ]);
    await h.service.remove(principal, scope, DOMAIN_ID, client);
    expect(h.repository.deleteServers).toHaveBeenCalledTimes(1);
    expect(h.audit.record).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'domain.destinations_removed',
        metadata: { name: 'acme.test', provider: 'custom', hosts: ['a.example'], count: 1 },
      }),
      {},
    );
    expect(h.outbox.insertRoutingChanged).toHaveBeenCalledTimes(1);
  });

  it('lists the presets with their patterns as strings', async () => {
    const h = harness();
    const { data } = await h.service.providers();
    expect(data.map((p) => p.provider)).toEqual(['microsoft_365', 'google_workspace']);
    expect(data[0]!.hostPatterns[0]).toContain('mail\\.protection\\.outlook\\.com');
    expect(data[1]!.defaultServers).toHaveLength(5);
  });
});
