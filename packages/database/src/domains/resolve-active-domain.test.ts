import type { DomainStatus, OrganizationStatus, PrismaClient } from '@prisma/client';
import { describe, expect, it, vi } from 'vitest';
import { resolveActiveDomain } from './resolve-active-domain';

interface Row {
  id: bigint;
  publicId: string;
  organizationId: bigint;
  name: string;
  status: DomainStatus;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  organization: { status: OrganizationStatus };
}

const OWNED: readonly DomainStatus[] = ['verified', 'active', 'suspended'];

/**
 * A fake writer client with MySQL's semantics for `verified_name`: a row is found by
 * `verifiedName` only when its status is verified, active or suspended.
 */
function fakeDb(rows: Row[]) {
  const findUnique = vi.fn(
    (args: { where: { verifiedName: string }; select: Record<string, unknown> }) => {
      const row = rows.find((r) => r.name === args.where.verifiedName && OWNED.includes(r.status));
      return Promise.resolve(row ?? null);
    },
  );
  return { db: { domain: { findUnique } } as unknown as Pick<PrismaClient, 'domain'>, findUnique };
}

const row = (overrides: Partial<Row> = {}): Row => ({
  id: 7n,
  publicId: '01890000-0000-7000-8000-000000000007',
  organizationId: 42n,
  name: 'acme.test',
  status: 'active',
  inboundEnabled: true,
  outboundEnabled: false,
  organization: { status: 'active' },
  ...overrides,
});

describe('resolveActiveDomain', () => {
  it('resolves an active domain of an active organization', async () => {
    const { db, findUnique } = fakeDb([row()]);
    await expect(resolveActiveDomain(db, 'acme.test')).resolves.toEqual({
      domainId: 7n,
      domainPublicId: '01890000-0000-7000-8000-000000000007',
      organizationId: 42n,
      name: 'acme.test',
      inboundEnabled: true,
      outboundEnabled: false,
    });
    expect(findUnique).toHaveBeenCalledTimes(1);
    expect(findUnique.mock.calls[0]![0]).toMatchObject({
      where: { verifiedName: 'acme.test' },
      select: { status: true, organization: { select: { status: true } } },
    });
  });

  it('normalizes the input (case, trailing dot, whitespace, IDN) before the lookup', async () => {
    const { db, findUnique } = fakeDb([row(), row({ id: 8n, name: 'xn--bcher-kva.test' })]);
    expect((await resolveActiveDomain(db, ' ACME.Test. '))?.domainId).toBe(7n);
    expect((await resolveActiveDomain(db, 'Bücher.test'))?.domainId).toBe(8n);
    expect(findUnique.mock.calls.map((c) => c[0].where.verifiedName)).toEqual([
      'acme.test',
      'xn--bcher-kva.test',
    ]);
  });

  it.each<DomainStatus>(['verified', 'suspended', 'disabled', 'failed', 'pending_verification'])(
    'does not resolve a %s domain',
    async (status) => {
      const { db } = fakeDb([row({ status })]);
      await expect(resolveActiveDomain(db, 'acme.test')).resolves.toBeNull();
    },
  );

  it('does not resolve a deleted domain (its verified_name is NULL)', async () => {
    const { db } = fakeDb([row({ status: 'deleted' })]);
    await expect(resolveActiveDomain(db, 'acme.test')).resolves.toBeNull();
  });

  it.each<OrganizationStatus>(['suspended', 'pending_deletion', 'deleted'])(
    'does not resolve a domain of a %s organization',
    async (status) => {
      const { db } = fakeDb([row({ organization: { status } })]);
      await expect(resolveActiveDomain(db, 'acme.test')).resolves.toBeNull();
    },
  );

  it('returns null for unknown names', async () => {
    const { db } = fakeDb([row()]);
    await expect(resolveActiveDomain(db, 'other.test')).resolves.toBeNull();
  });

  it('returns null without a query for input that is not a domain name', async () => {
    const { db, findUnique } = fakeDb([row()]);
    for (const input of ['', 'acme', '*.acme.test', '127.0.0.1', '[::1]', 'localhost', 'a..b']) {
      await expect(resolveActiveDomain(db, input), input).resolves.toBeNull();
    }
    expect(findUnique).not.toHaveBeenCalled();
  });

  it('propagates database errors', async () => {
    const db = {
      domain: { findUnique: vi.fn(() => Promise.reject(new Error('connection lost'))) },
    } as unknown as Pick<PrismaClient, 'domain'>;
    await expect(resolveActiveDomain(db, 'acme.test')).rejects.toThrow('connection lost');
  });
});
