import type { ResolvedArchiveSettings, ResolvedJournalScope } from '@email-gateway/archive';
import type { Prisma } from '@email-gateway/database';

type Client = Pick<Prisma.TransactionClient, 'domain' | 'user' | 'tenantDepartment'>;

/** Most member rows read per scope resolution (≤ 50 departments × members). */
const MAX_DEPARTMENT_MEMBERS = 50_000;

/** A resolved journal scope plus the public ids that did not resolve in the organization. */
export interface JournalScopeResolution {
  scope: ResolvedJournalScope;
  unresolved: {
    domainIds: string[];
    departmentIds: string[];
    userIds: string[];
  };
}

/**
 * Resolves the public ids of an `archive-settings/1` scope inside one organization (A4, A22):
 * verified domains (not deleted) by name, users (not deleted) by e-mail, and the member
 * addresses and member users' e-mails of departments. Every query filters by the organization
 * first, so another organization's id never resolves (it is reported as unresolved, which the
 * settings route answers with `422 archive_scope_reference_invalid`). Domains that exist but are
 * not verified resolve (the id is valid) without contributing a name: only verified domains
 * match (A4).
 */
export async function resolveJournalScope(
  client: Client,
  organizationId: bigint,
  scope: ResolvedArchiveSettings['scope'],
): Promise<JournalScopeResolution> {
  const [domains, users, departments] = await Promise.all([
    scope.domainIds.length === 0
      ? Promise.resolve([])
      : client.domain.findMany({
          where: { organizationId, publicId: { in: scope.domainIds }, deletedAt: null },
          select: { publicId: true, name: true, verifiedAt: true, organizationId: true },
        }),
    scope.userIds.length === 0
      ? Promise.resolve([])
      : client.user.findMany({
          where: { organizationId, publicId: { in: scope.userIds }, deletedAt: null },
          select: { publicId: true, email: true, organizationId: true },
        }),
    scope.departmentIds.length === 0
      ? Promise.resolve([])
      : client.tenantDepartment.findMany({
          where: { organizationId, publicId: { in: scope.departmentIds } },
          select: {
            publicId: true,
            organizationId: true,
            members: {
              where: { organizationId },
              select: { address: true, user: { select: { email: true, deletedAt: true } } },
              take: MAX_DEPARTMENT_MEMBERS,
            },
          },
        }),
  ]);
  const own = <R extends { organizationId: bigint }>(rows: readonly R[]) =>
    rows.filter((r) => r.organizationId === organizationId);
  const domainRows = own(domains);
  const userRows = own(users);
  const departmentRows = own(departments);
  const found = (rows: ReadonlyArray<{ publicId: string }>) =>
    new Set(rows.map((r) => r.publicId.toLowerCase()));
  const missing = (ids: readonly string[], have: Set<string>) =>
    ids.filter((id) => !have.has(id.toLowerCase()));
  const departmentAddresses: string[] = [];
  for (const d of departmentRows) {
    for (const m of d.members) {
      if (m.address !== null) departmentAddresses.push(m.address);
      if (m.user !== null && m.user.deletedAt === null) departmentAddresses.push(m.user.email);
    }
  }
  return {
    scope: {
      addresses: [...scope.addresses],
      userEmails: userRows.map((u) => u.email),
      departmentAddresses,
      domains: domainRows.filter((d) => d.verifiedAt !== null).map((d) => d.name),
    },
    unresolved: {
      domainIds: missing(scope.domainIds, found(domainRows)),
      departmentIds: missing(scope.departmentIds, found(departmentRows)),
      userIds: missing(scope.userIds, found(userRows)),
    },
  };
}
