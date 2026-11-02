import { ConflictException } from '@nestjs/common';
import type { DkimAlgorithm, DkimKeyStatus, DomainStatus } from '@email-gateway/database';

/** Domains whose DKIM keys can be rotated (D9). */
export const ROTATABLE_DOMAIN_STATUSES: ReadonlySet<DomainStatus> = new Set([
  'pending_verification',
  'verified',
  'active',
  'suspended',
]);

/** Keys whose DNS record is published (D6). */
export const PUBLISHED_KEY_STATUSES: ReadonlySet<DkimKeyStatus> = new Set([
  'pending',
  'active',
  'rotating',
]);

export const ROTATION_IN_PROGRESS = 'A DKIM rotation is already in progress';

export interface RotationKey {
  id: bigint;
  selector: string;
  algorithm: DkimAlgorithm;
  status: DkimKeyStatus;
}

/**
 * - `replace_pending`: the family's only key is pending (never published): it is revoked and
 *   replaced by the new pending key;
 * - `add`: a new pending key is created next to the active one (`previous`, may be null when
 *   the family has no key yet).
 */
export type RotationPlan<K extends RotationKey = RotationKey> =
  { kind: 'replace_pending'; previous: K } | { kind: 'add'; previous: K | null };

/**
 * Rotation rules (D9), evaluated under the domain row lock. `409` when the domain cannot rotate
 * or a rotation of that algorithm is already in progress (a pending key next to an active one).
 */
export function planRotation<K extends RotationKey>(
  domainStatus: DomainStatus,
  keys: readonly K[],
  algorithm: DkimAlgorithm,
): RotationPlan<K> {
  if (!ROTATABLE_DOMAIN_STATUSES.has(domainStatus)) {
    throw new ConflictException(`Domain is ${domainStatus}`);
  }
  const family = keys.filter((k) => k.algorithm === algorithm);
  const pending = family.find((k) => k.status === 'pending');
  const active = family.find((k) => k.status === 'active');
  if (pending && active) throw new ConflictException(ROTATION_IN_PROGRESS);
  if (pending) return { kind: 'replace_pending', previous: pending };
  return { kind: 'add', previous: active ?? null };
}

/** A rotating key whose overlap has ended (D9 retirement). */
export function isDueForRetirement(
  key: { status: DkimKeyStatus; retireAfter: Date | null },
  now: Date,
): boolean {
  return (
    key.status === 'rotating' &&
    key.retireAfter !== null &&
    key.retireAfter.getTime() <= now.getTime()
  );
}
