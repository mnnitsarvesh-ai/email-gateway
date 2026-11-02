import { ConflictException, NotFoundException } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { describe, expect, it, vi } from 'vitest';
import { OrganizationLimitsService } from './organization-limits.service';

function fakeTx(limits: Record<string, bigint>, lockedRows: { id: bigint }[] = [{ id: 7n }]) {
  const $queryRaw = vi.fn().mockResolvedValue(lockedRows);
  const findUnique = vi.fn(
    ({ where }: { where: { organizationId_limitKey: { limitKey: string } } }) => {
      const value = limits[where.organizationId_limitKey.limitKey];
      return Promise.resolve(value === undefined ? null : { limitValue: value });
    },
  );
  const tx = {
    $queryRaw,
    organizationLimit: { findUnique },
  } as unknown as Prisma.TransactionClient;
  return { tx, $queryRaw, findUnique };
}

describe('OrganizationLimitsService', () => {
  const limits = new OrganizationLimitsService();

  it('locks the organization row with SELECT … FOR UPDATE', async () => {
    const { tx, $queryRaw } = fakeTx({});
    await limits.lockOrganization(tx, 7n);
    const [strings, id] = $queryRaw.mock.calls[0]! as [TemplateStringsArray, bigint];
    expect(strings.join('?').replace(/\s+/g, ' ').trim()).toBe(
      'SELECT id FROM organizations WHERE id = ? FOR UPDATE',
    );
    expect(id).toBe(7n);
  });

  it('404s when the organization does not exist', async () => {
    const { tx } = fakeTx({}, []);
    await expect(limits.lockOrganization(tx, 9n)).rejects.toThrow(NotFoundException);
  });

  it('reads a limit, or null when the organization has none', async () => {
    const { tx, findUnique } = fakeTx({ max_users: 25n });
    expect(await limits.getLimit(tx, 7n, 'max_users')).toBe(25n);
    expect(await limits.getLimit(tx, 7n, 'max_domains')).toBeNull();
    expect(findUnique).toHaveBeenCalledWith({
      where: { organizationId_limitKey: { organizationId: 7n, limitKey: 'max_users' } },
      select: { limitValue: true },
    });
  });

  it('allows adding while the current count is below the limit', async () => {
    const { tx } = fakeTx({ max_users: 3n });
    await expect(limits.assertWithinLimit(tx, 7n, 'max_users', 2)).resolves.toBeUndefined();
  });

  it('409s when adding one more would exceed the limit (users)', async () => {
    const { tx } = fakeTx({ max_users: 3n });
    await expect(limits.assertWithinLimit(tx, 7n, 'max_users', 3)).rejects.toThrow(
      new ConflictException('Organization limit reached: max_users'),
    );
  });

  it('409s for domains too (step 2.1 uses max_domains)', async () => {
    const { tx } = fakeTx({ max_domains: 0n });
    await expect(limits.assertWithinLimit(tx, 7n, 'max_domains', 0n)).rejects.toThrow(
      'Organization limit reached: max_domains',
    );
  });

  it('treats a missing limit as unlimited', async () => {
    const { tx } = fakeTx({});
    await expect(limits.assertWithinLimit(tx, 7n, 'max_users', 1_000_000)).resolves.toBeUndefined();
  });
});
