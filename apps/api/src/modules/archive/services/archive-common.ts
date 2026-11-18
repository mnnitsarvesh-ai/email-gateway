import { BadRequestException } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { OrganizationFeaturesService } from '../../../tenancy/organization-features.service';
import { ARCHIVING_FEATURE } from '../archive.constants';
import { archiveOverrideForbidden, archivingNotEnabled } from '../archive.errors';
import { PublicIdSchema } from '../dto/archive.schemas';

type Tx = Prisma.TransactionClient;

/** A path id (`{messageId}`, `{policyId}`, …): a UUID, `400` before any read; lower-cased. */
export function parsePublicId(raw: unknown, name: string): string {
  const parsed = PublicIdSchema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException([`${name}: must be a UUID`]);
  return parsed.data.toLowerCase();
}

/** The internal user id of a user principal (audit `created_by`/`updated_by`), else null. */
export const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

/**
 * Content routes are customer-only (A20, product-owner decision 5): a platform override session
 * is refused with `403 archive_override_forbidden`, whatever its permissions.
 */
export function refuseOverride(principal: Principal): void {
  if (principal.kind === 'user' && principal.override !== undefined) {
    throw archiveOverrideForbidden();
  }
}

/** The principal of a `@UserOnly()` route (the guard already refused API keys). */
export function asUser(principal: Principal): UserPrincipal {
  if (principal.kind !== 'user') throw archiveOverrideForbidden();
  return principal;
}

/** `403 archiving_not_enabled` without the plan feature (writer read, A20). */
export async function requireArchiving(
  features: OrganizationFeaturesService,
  scope: TenantScope,
  tx?: Tx,
): Promise<void> {
  if (!(await features.isEnabled(scope.organizationId, ARCHIVING_FEATURE, tx))) {
    throw archivingNotEnabled();
  }
}

/** Seconds between two instants, floored at 0. */
export const secondsBetween = (from: Date | null, now: Date): number =>
  from === null ? 0 : Math.max(0, Math.floor((now.getTime() - from.getTime()) / 1000));
