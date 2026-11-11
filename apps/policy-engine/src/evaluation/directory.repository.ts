import type { Prisma } from '@email-gateway/database';
import type { DirectoryReferences, PolicyRoundRows } from '@email-gateway/policy-dsl';
import { type InconsistencySink, wrongRead } from './errors';

export type DirectoryMaps = PolicyRoundRows['directory'];

export const EMPTY_DIRECTORY: DirectoryMaps = Object.freeze({
  departmentsByAddress: Object.freeze({}),
  usersByAddress: Object.freeze({}),
});

const addToMap = (map: Map<string, Set<string>>, address: string, id: string): void => {
  const set = map.get(address) ?? new Set<string>();
  set.add(id);
  map.set(address, set);
};

const toRecord = (map: Map<string, Set<string>>): Record<string, string[]> =>
  Object.fromEntries([...map.entries()].map(([address, ids]) => [address, [...ids].sort()]));

/**
 * Directory resolution for one evaluation (P5): only the department and user public ids the
 * compiled snapshot references, only for the given (normalized) addresses — the envelope
 * recipients and the authenticated sender. Organization-scoped and echo-checked (§6).
 *
 * - `departmentsByAddress[address]` = sorted public ids of referenced departments having a member
 *   with that address, or a member `user_id` whose user is active, not deleted and has that
 *   e-mail.
 * - `usersByAddress[address]` = sorted public ids of referenced users that are active, not
 *   deleted and have that e-mail.
 *
 * Reads are bounded by the message's addresses, never by department size: (1) the users with
 * one of the addresses, (2) members of the referenced departments whose address is one of them
 * or whose `user_id` is one of those users (`DEPARTMENT_MAX_MEMBERS` does not reach this path).
 *
 * Membership is live data (a change applies to the next evaluation without a publish); the
 * resolved maps are part of the hashed input.
 */
export class DirectoryRepository {
  constructor(private readonly sink: InconsistencySink) {}

  async resolve(
    tx: Prisma.TransactionClient,
    organizationId: bigint,
    references: DirectoryReferences,
    addresses: readonly string[],
  ): Promise<DirectoryMaps> {
    const wanted = new Set(addresses.map((a) => a.toLowerCase()));
    if (wanted.size === 0) return EMPTY_DIRECTORY;
    if (references.departmentIds.length === 0 && references.userIds.length === 0) {
      return EMPTY_DIRECTORY;
    }
    const list = [...wanted];
    const departmentsByAddress = new Map<string, Set<string>>();
    const usersByAddress = new Map<string, Set<string>>();

    // 1. The organization's active, not deleted users having one of the message's addresses.
    //    Bounded by the address list ((organization_id, email) is unique), never by the size
    //    of a department: user members of a referenced department are matched by these ids
    //    below, so members not involved in the message are never read.
    const users = await tx.user.findMany({
      where: { organizationId, email: { in: list }, status: 'active', deletedAt: null },
      select: {
        id: true,
        publicId: true,
        organizationId: true,
        email: true,
        status: true,
        deletedAt: true,
      },
    });
    const userEmail = new Map<bigint, string>();
    for (const u of users) {
      if (u.organizationId !== organizationId) wrongRead(this.sink, 'users', 'organization echo');
      if (u.status !== 'active' || u.deletedAt !== null) {
        wrongRead(this.sink, 'users', 'status echo');
      }
      // The column collation may match more loosely than the normalized address: filter.
      const address = u.email.toLowerCase();
      if (!wanted.has(address)) continue;
      userEmail.set(u.id, address);
      if (references.userIds.includes(u.publicId)) addToMap(usersByAddress, address, u.publicId);
    }

    // 2. Members of the referenced departments: by stored address, or by one of those users.
    if (references.departmentIds.length > 0) {
      const departments = await tx.tenantDepartment.findMany({
        where: { organizationId, publicId: { in: [...references.departmentIds] } },
        select: { id: true, publicId: true, organizationId: true },
      });
      for (const d of departments) {
        if (d.organizationId !== organizationId) {
          wrongRead(this.sink, 'departments', 'organization echo');
        }
        if (!references.departmentIds.includes(d.publicId)) {
          wrongRead(this.sink, 'departments', 'public id echo');
        }
      }
      const publicIdOf = new Map(departments.map((d) => [d.id, d.publicId]));
      if (departments.length > 0) {
        const members = await tx.tenantDepartmentMember.findMany({
          where: {
            organizationId,
            departmentId: { in: departments.map((d) => d.id) },
            OR: [
              { address: { in: list } },
              ...(userEmail.size > 0 ? [{ userId: { in: [...userEmail.keys()] } }] : []),
            ],
          },
          select: { organizationId: true, departmentId: true, address: true, userId: true },
        });
        for (const m of members) {
          if (m.organizationId !== organizationId) {
            wrongRead(this.sink, 'members', 'organization echo');
          }
          const department = publicIdOf.get(m.departmentId);
          if (department === undefined) wrongRead(this.sink, 'members', 'department echo');
          const address =
            m.address !== null
              ? m.address.toLowerCase()
              : m.userId !== null
                ? userEmail.get(m.userId)
                : undefined;
          if (address !== undefined && wanted.has(address)) {
            addToMap(departmentsByAddress, address, department);
          }
        }
      }
    }

    return {
      departmentsByAddress: toRecord(departmentsByAddress),
      usersByAddress: toRecord(usersByAddress),
    };
  }
}
