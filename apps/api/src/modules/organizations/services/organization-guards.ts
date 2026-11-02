import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { OrganizationAccess } from '../domain/organization-access';
import type {
  OrganizationsRepository,
  PlanRecord,
  VisibleOrganization,
} from '../organizations.repository';

/** Who made the request, for audit rows. */
export interface RequestOrigin {
  ip: string | null;
}

export const ORGANIZATION_NOT_FOUND = 'Organization not found';

/**
 * The organization if the access allows it. An organization of another tenant and a missing one
 * are the same `404` (D3), so existence is never disclosed.
 */
export async function requireVisible(
  repository: OrganizationsRepository,
  access: OrganizationAccess,
  publicId: string,
  client?: Prisma.TransactionClient,
): Promise<VisibleOrganization> {
  const org = await repository.findVisible(access, publicId, client);
  if (!org) throw new NotFoundException(ORGANIZATION_NOT_FOUND);
  return org;
}

/** Organizations in the deletion workflow are frozen (D12: `409`). */
export function assertMutable(org: VisibleOrganization): void {
  if (org.status === 'pending_deletion' || org.status === 'deleted') {
    throw new ConflictException('The organization is pending deletion or deleted');
  }
}

/** An existing, active plan, else `400`. */
export async function requireActivePlan(
  repository: OrganizationsRepository,
  code: string,
  client?: Prisma.TransactionClient,
): Promise<PlanRecord> {
  const plan = await repository.findPlanByCode(code, client);
  if (!plan || !plan.isActive)
    throw new BadRequestException(['planCode: unknown or inactive plan']);
  return plan;
}
