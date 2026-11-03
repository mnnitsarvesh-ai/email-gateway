import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ServiceUnavailableException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { describe, expect, it } from 'vitest';
import type { AuditEntry, AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { systemScope, type TenantScope } from '../../../auth-contracts/tenant-scope';
import { PasswordHasher } from '../../../crypto/password-hasher';
import type { TransactionRunner } from '../../../database/transaction-runner';
import type { OrganizationLimitsService } from '../../../tenancy/organization-limits.service';
import { SASL_USERNAME_PATTERN } from '../domain/credentials';
import {
  NON_PUBLIC_NETWORK_MESSAGE,
  networksOverlap,
  type ParsedNetwork,
} from '../domain/networks';
import { CreateConnectorSchema } from '../dto/smtp-connectors.schemas';
import type {
  ConnectorInsert,
  ConnectorRow,
  ConnectorWrite,
  SmtpConnectorsRepository,
} from '../repositories/smtp-connectors.repository';
import { NETWORK_OVERLAP } from '../smtp-connectors.errors';
import { assertUpdateAllowed, SmtpConnectorsService } from './smtp-connectors.service';

interface StoredConnector extends ConnectorInsert {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  status: 'active' | 'disabled';
  createdAt: Date;
  updatedAt: Date;
}

interface StoredNetwork extends ParsedNetwork {
  organizationId: bigint;
  connectorId: bigint;
}

/** In-memory `SmtpConnectorsRepository` (only what the service uses). */
class FakeConnectors {
  connectors: StoredConnector[] = [];
  networks: StoredNetwork[] = [];
  lockHeld = false;
  lockBusy = false;
  locksTaken = 0;
  private nextId = 1n;

  private row(c: StoredConnector): ConnectorRow {
    return {
      id: c.id,
      publicId: c.publicId,
      organizationId: c.organizationId,
      name: c.name,
      authType: c.authType,
      status: c.status,
      saslUsername: c.saslUsername,
      secretSetAt: c.secretSetAt,
      certFingerprintSha256: c.certFingerprintSha256,
      requireTls: c.requireTls,
      createdAt: c.createdAt,
      updatedAt: c.updatedAt,
      networks: this.networks
        .filter((n) => n.connectorId === c.id)
        .map((n, i) => ({ id: BigInt(i + 1), cidr: n.cidr, ipVersion: n.ipVersion })),
    };
  }
  private find(scope: TenantScope, pred: (c: StoredConnector) => boolean) {
    return this.connectors.find((c) => c.organizationId === scope.organizationId && pred(c));
  }

  findByPublicId = (scope: TenantScope, publicId: string) => {
    const c = this.find(scope, (x) => x.publicId === publicId);
    return Promise.resolve(c ? this.row(c) : null);
  };
  lockByPublicId = (_tx: unknown, scope: TenantScope, publicId: string) =>
    this.findByPublicId(scope, publicId);
  count = (_tx: unknown, scope: TenantScope) =>
    Promise.resolve(
      this.connectors.filter((c) => c.organizationId === scope.organizationId).length,
    );
  nameTaken = (_tx: unknown, scope: TenantScope, name: string, exceptId?: bigint) =>
    Promise.resolve(!!this.find(scope, (c) => c.name === name && c.id !== exceptId));
  usernameTaken = (_tx: unknown, username: string) =>
    Promise.resolve(this.connectors.some((c) => c.saslUsername === username));
  fingerprintTaken = (_tx: unknown, fp: string) =>
    Promise.resolve(this.connectors.some((c) => c.certFingerprintSha256 === fp));
  create = (_tx: unknown, scope: TenantScope, data: ConnectorInsert) => {
    const now = new Date();
    const c: StoredConnector = {
      ...data,
      id: this.nextId++,
      publicId: randomUUID(),
      organizationId: scope.organizationId,
      status: 'active',
      createdAt: now,
      updatedAt: now,
    };
    this.connectors.push(c);
    return Promise.resolve({ id: c.id, publicId: c.publicId });
  };
  update = (_tx: unknown, scope: TenantScope, id: bigint, data: ConnectorWrite) => {
    Object.assign(
      this.find(scope, (c) => c.id === id)!,
      data,
      { updatedAt: new Date() },
    );
    return Promise.resolve();
  };
  touch = (_tx: unknown, scope: TenantScope, id: bigint, at: Date) => {
    this.find(scope, (c) => c.id === id)!.updatedAt = at;
    return Promise.resolve();
  };
  setSecret = (_tx: unknown, scope: TenantScope, id: bigint, secretHash: string, at: Date) => {
    Object.assign(
      this.find(scope, (c) => c.id === id)!,
      { secretHash, secretSetAt: at },
    );
    return Promise.resolve();
  };
  delete = (_tx: unknown, scope: TenantScope, id: bigint) => {
    this.connectors = this.connectors.filter(
      (c) => !(c.organizationId === scope.organizationId && c.id === id),
    );
    this.networks = this.networks.filter((n) => n.connectorId !== id);
    return Promise.resolve(true);
  };
  acquireNetworkLock = () => {
    if (this.lockBusy) return Promise.resolve(false);
    this.lockHeld = true;
    this.locksTaken++;
    return Promise.resolve(true);
  };
  releaseNetworkLock = () => {
    this.lockHeld = false;
    return Promise.resolve();
  };
  overlapsExisting = (_tx: unknown, network: ParsedNetwork) => {
    if (!this.lockHeld) throw new Error('overlap checked without the network lock');
    return Promise.resolve(this.networks.some((n) => networksOverlap(n, network)));
  };
  deleteNetworks = (_tx: unknown, scope: TenantScope, connectorId: bigint) => {
    this.networks = this.networks.filter(
      (n) => !(n.organizationId === scope.organizationId && n.connectorId === connectorId),
    );
    return Promise.resolve();
  };
  insertNetworks = (
    _tx: unknown,
    scope: TenantScope,
    connectorId: bigint,
    list: ParsedNetwork[],
  ) => {
    if (!this.lockHeld) throw new Error('networks inserted without the network lock');
    this.networks.push(
      ...list.map((n) => ({ ...n, organizationId: scope.organizationId, connectorId })),
    );
    return Promise.resolve();
  };
}

/** Runs the callback; on a throw, restores the fake's state (a rollback). */
function transactions(repo: FakeConnectors): TransactionRunner {
  return {
    run: async <T>(fn: (tx: never) => Promise<T>) => {
      const snapshot = { c: repo.connectors.map((c) => ({ ...c })), n: [...repo.networks] };
      try {
        return await fn({} as never);
      } catch (err) {
        repo.connectors = snapshot.c;
        repo.networks = snapshot.n;
        throw err;
      }
    },
  } as unknown as TransactionRunner;
}

const hasher = new PasswordHasher({
  AUTH_ARGON2_MEMORY_KIB: 19456,
  AUTH_ARGON2_TIME_COST: 2,
  AUTH_ARGON2_PARALLELISM: 1,
});
const ORG_A = systemScope(1n);
const ORG_B = systemScope(2n);
const principal: UserPrincipal = {
  kind: 'user',
  userId: 7n,
  userPublicId: randomUUID(),
  organizationId: 1n,
  organizationPublicId: randomUUID(),
  organizationKind: 'customer',
  sessionId: randomUUID(),
  mfaAuthenticated: true,
  mfaEnrollmentRequired: false,
  permissions: new Set(['connector:manage']),
};
const client = { ip: '198.51.100.1', userAgent: null } as never;

/**
 * `allowNonPublic` defaults to true here so the overlap and update cases can use readable
 * private/documentation ranges; the public-range rule has its own cases below.
 */
function setup(max = 50, allowNonPublic = true) {
  const repo = new FakeConnectors();
  const audits: AuditEntry[] = [];
  const audit = {
    actorFrom: () => ({ type: 'user', id: principal.userPublicId }),
    record: (entry: AuditEntry) => {
      audits.push(entry);
      return Promise.resolve();
    },
  } as unknown as AuditService;
  const limits = {
    lockOrganization: () => Promise.resolve(),
  } as unknown as OrganizationLimitsService;
  const service = new SmtpConnectorsService(
    {
      SMTP_CONNECTORS_MAX_PER_ORGANIZATION: max,
      SMTP_CONNECTOR_ALLOW_NON_PUBLIC_NETWORKS: allowNonPublic,
    },
    transactions(repo),
    audit,
    hasher,
    limits,
    repo as unknown as SmtpConnectorsRepository,
  );
  const create = (scope: TenantScope, body: Record<string, unknown>) =>
    service.create(principal, scope, CreateConnectorSchema.parse(body), client);
  return { repo, audits, service, create };
}

describe('SmtpConnectorsService.create (D10)', () => {
  it('sasl: generates the username and a one-time password, stores only an Argon2id hash', async () => {
    const { repo, audits, create, service } = setup();
    const created = await create(ORG_A, { name: 'Exchange', authType: 'sasl' });
    expect(created.saslUsername).toMatch(SASL_USERNAME_PATTERN);
    expect(created.credentials?.username).toBe(created.saslUsername);
    const password = created.credentials!.password;
    expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const stored = repo.connectors[0]!;
    expect(stored.secretHash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(await argon2.verify(stored.secretHash!, password)).toBe(true);
    expect(stored.createdByUserId).toBe(7n);
    expect(created).not.toHaveProperty('secretHash');
    // Reads never return the password again.
    expect(await service.get(ORG_A, created.id)).not.toHaveProperty('credentials');
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({ action: 'smtp_connector.created', resourceId: created.id });
    expect(JSON.stringify(audits[0]!.metadata)).not.toContain(password);
  });

  it('source_ip: stores canonical networks under the lock and releases it', async () => {
    const { repo, create } = setup();
    const created = await create(ORG_A, {
      name: 'Relay',
      authType: 'source_ip',
      networks: ['192.0.2.7/24', '2001:db8:5::/48'],
    });
    expect(created.networks).toEqual([
      { cidr: '192.0.2.0/24', ipVersion: 4 },
      { cidr: '2001:db8:5::/48', ipVersion: 6 },
    ]);
    expect(created.credentials).toBeUndefined();
    expect(created.requireTls).toBe(true);
    expect(repo.lockHeld).toBe(false);
  });

  it('refuses non-public networks (400 per index) unless the deployment allows them', async () => {
    const { repo, create, service } = setup(50, false);
    const err = await create(ORG_A, {
      name: 'Private',
      authType: 'source_ip',
      networks: ['45.10.0.0/24', '10.20.0.0/16', '2a10:1:2::/48', 'fd00:1::/48', '172.31.250.7'],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(BadRequestException);
    const messages = (err as BadRequestException).getResponse() as { message: string[] };
    expect(messages.message).toEqual([
      `networks.1: ${NON_PUBLIC_NETWORK_MESSAGE}`,
      `networks.3: ${NON_PUBLIC_NETWORK_MESSAGE}`,
      `networks.4: ${NON_PUBLIC_NETWORK_MESSAGE}`,
    ]);
    expect(repo.connectors).toHaveLength(0);
    const created = await create(ORG_A, {
      name: 'Public',
      authType: 'source_ip',
      networks: ['45.10.0.0/24', '2a10:1:2::/48'],
    });
    await expect(
      service.update(principal, ORG_A, created.id, { networks: ['192.168.1.0/24'] }, client),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect((await service.get(ORG_A, created.id)).networks.map((n) => n.cidr)).toEqual([
      '45.10.0.0/24',
      '2a10:1:2::/48',
    ]);
    // A dedicated deployment relaying from the customer's private networks.
    const dedicated = setup(50, true);
    await expect(
      dedicated.create(ORG_A, { name: 'P', authType: 'source_ip', networks: ['10.20.0.0/16'] }),
    ).resolves.toBeDefined();
  });

  it('refuses a network overlapping another organization’s connector, without details', async () => {
    const { repo, create } = setup();
    await create(ORG_B, { name: 'B', authType: 'source_ip', networks: ['10.20.0.0/16'] });
    const err = await create(ORG_A, {
      name: 'A',
      authType: 'source_ip',
      networks: ['10.30.0.0/24', '10.20.5.0/24'],
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConflictException);
    expect((err as Error).message).toBe(NETWORK_OVERLAP);
    expect(repo.connectors.filter((c) => c.organizationId === 1n)).toHaveLength(0);
    expect(repo.networks).toHaveLength(1);
    expect(repo.lockHeld).toBe(false);
  });

  it('IPv6 overlap across organizations is refused too', async () => {
    const { create } = setup();
    await create(ORG_B, { name: 'B', authType: 'source_ip', networks: ['2001:db8:abcd::/48'] });
    await expect(
      create(ORG_A, { name: 'A', authType: 'source_ip', networks: ['2001:db8:abcd:ff::1'] }),
    ).rejects.toThrow(NETWORK_OVERLAP);
    await expect(
      create(ORG_A, { name: 'A', authType: 'source_ip', networks: ['2001:db8:abce::/48'] }),
    ).resolves.toBeDefined();
  });

  it('answers 503 when the network lock is busy', async () => {
    const { repo, create } = setup();
    repo.lockBusy = true;
    await expect(
      create(ORG_A, { name: 'A', authType: 'source_ip', networks: ['10.1.0.0/16'] }),
    ).rejects.toBeInstanceOf(ServiceUnavailableException);
    expect(repo.connectors).toHaveLength(0);
  });

  it('enforces fingerprint uniqueness globally, names per organization and the limit', async () => {
    const { create } = setup(2);
    const fp = 'cd'.repeat(32);
    await create(ORG_B, {
      name: 'cert',
      authType: 'client_certificate',
      certificateFingerprintSha256: fp,
    });
    await expect(
      create(ORG_A, {
        name: 'cert',
        authType: 'client_certificate',
        certificateFingerprintSha256: fp.toUpperCase(),
      }),
    ).rejects.toThrow('Certificate fingerprint is already registered');
    await create(ORG_A, { name: 'one', authType: 'sasl' });
    await expect(create(ORG_A, { name: 'one', authType: 'sasl' })).rejects.toThrow(
      'SMTP connector name already exists',
    );
    await create(ORG_A, { name: 'two', authType: 'sasl' });
    await expect(create(ORG_A, { name: 'three', authType: 'sasl' })).rejects.toThrow(
      'SMTP connector limit reached: at most 2 per organization',
    );
  });
});

describe('SmtpConnectorsService.update / rotate / remove', () => {
  it('replaces networks atomically, ignoring the connector’s own old networks', async () => {
    const { repo, audits, service, create } = setup();
    const c = await create(ORG_A, { name: 'r', authType: 'source_ip', networks: ['10.5.0.0/16'] });
    const updated = await service.update(
      principal,
      ORG_A,
      c.id,
      { networks: ['10.5.1.0/24', '10.6.0.0/24'], status: 'disabled' },
      client,
    );
    expect(updated.networks.map((n) => n.cidr)).toEqual(['10.5.1.0/24', '10.6.0.0/24']);
    expect(updated.status).toBe('disabled');
    expect(audits.at(-1)).toMatchObject({
      action: 'smtp_connector.updated',
      metadata: {
        changes: {
          status: { from: 'active', to: 'disabled' },
          networks: { from: ['10.5.0.0/16'], to: ['10.5.1.0/24', '10.6.0.0/24'] },
        },
      },
    });
    expect(repo.lockHeld).toBe(false);
  });

  it('keeps the old networks when the replacement overlaps another connector', async () => {
    const { repo, service, create } = setup();
    await create(ORG_B, { name: 'b', authType: 'source_ip', networks: ['10.9.0.0/16'] });
    const c = await create(ORG_A, { name: 'a', authType: 'source_ip', networks: ['10.8.0.0/16'] });
    await expect(
      service.update(principal, ORG_A, c.id, { networks: ['10.9.9.0/24'] }, client),
    ).rejects.toThrow(NETWORK_OVERLAP);
    expect((await service.get(ORG_A, c.id)).networks.map((n) => n.cidr)).toEqual(['10.8.0.0/16']);
    expect(repo.lockHeld).toBe(false);
  });

  it('applies the per-type rules of PATCH', () => {
    expect(() =>
      assertUpdateAllowed({ authType: 'sasl' }, { networks: ['10.0.0.0/24'] }),
    ).toThrow();
    expect(() => assertUpdateAllowed({ authType: 'source_ip' }, { networks: [] })).toThrow();
    expect(() =>
      assertUpdateAllowed({ authType: 'client_certificate' }, { networks: [] }),
    ).not.toThrow();
    expect(() => assertUpdateAllowed({ authType: 'sasl' }, { requireTls: false })).toThrow();
    expect(() =>
      assertUpdateAllowed({ authType: 'source_ip' }, { requireTls: false }),
    ).not.toThrow();
  });

  it('writes nothing and audits nothing for a no-op PATCH', async () => {
    const { audits, service, create } = setup();
    const c = await create(ORG_A, { name: 'same', authType: 'sasl' });
    await service.update(principal, ORG_A, c.id, { name: 'same', status: 'active' }, client);
    expect(audits.map((a) => a.action)).toEqual(['smtp_connector.created']);
  });

  it('rotates sasl secrets only; the old password stops verifying', async () => {
    const { repo, audits, service, create } = setup();
    const c = await create(ORG_A, { name: 's', authType: 'sasl' });
    const rotated = await service.rotateSecret(principal, ORG_A, c.id, client);
    expect(rotated.credentials.username).toBe(c.saslUsername);
    expect(rotated.credentials.password).not.toBe(c.credentials!.password);
    const hash = repo.connectors[0]!.secretHash!;
    expect(await argon2.verify(hash, rotated.credentials.password)).toBe(true);
    expect(await argon2.verify(hash, c.credentials!.password)).toBe(false);
    expect(audits.at(-1)).toMatchObject({ action: 'smtp_connector.secret_rotated' });
    expect(JSON.stringify(audits.at(-1)!.metadata)).not.toContain(rotated.credentials.password);

    const ip = await create(ORG_A, {
      name: 'ip',
      authType: 'source_ip',
      networks: ['10.70.0.0/16'],
    });
    await expect(service.rotateSecret(principal, ORG_A, ip.id, client)).rejects.toThrow(
      'Only sasl connectors have a secret',
    );
  });

  it('never reaches another tenant’s connector (404) and deletes with its networks', async () => {
    const { repo, service, create } = setup();
    const b = await create(ORG_B, { name: 'b', authType: 'source_ip', networks: ['10.40.0.0/16'] });
    await expect(service.get(ORG_A, b.id)).rejects.toThrow('SMTP connector not found');
    await expect(
      service.update(principal, ORG_A, b.id, { status: 'disabled' }, client),
    ).rejects.toThrow('SMTP connector not found');
    await expect(service.rotateSecret(principal, ORG_A, b.id, client)).rejects.toThrow(
      'SMTP connector not found',
    );
    await expect(service.remove(principal, ORG_A, b.id, client)).rejects.toThrow(
      'SMTP connector not found',
    );
    await service.remove(principal, ORG_B, b.id, client);
    expect(repo.connectors).toHaveLength(0);
    expect(repo.networks).toHaveLength(0);
  });
});
