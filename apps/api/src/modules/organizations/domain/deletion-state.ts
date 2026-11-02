import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import type { OrganizationKind, OrganizationStatus } from '@email-gateway/database';

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;

/** What the deletion workflow (D12) needs to know about an organization. */
export interface DeletionSubject {
  slug: string;
  kind: OrganizationKind;
  status: OrganizationStatus;
  deletionRequestedAt: Date | null;
  deletionRequestedByUserId: bigint | null;
  purgeAfter: Date | null;
}

export const ACTIVE_LEGAL_HOLD = 'Active legal hold';

function assertNotPlatform(org: DeletionSubject): void {
  if (org.kind === 'platform') {
    throw new ConflictException('The platform organization cannot be deleted');
  }
}

function assertSlug(org: DeletionSubject, confirmSlug: string): void {
  if (confirmSlug !== org.slug) {
    throw new BadRequestException(['confirmSlug: does not match the organization slug']);
  }
}

function assertNoLegalHold(activeLegalHolds: number): void {
  if (activeLegalHolds > 0) throw new ConflictException(ACTIVE_LEGAL_HOLD);
}

/** Step 1: only a suspended customer organization, slug confirmed, no active legal hold. */
export function assertCanRequestDeletion(
  org: DeletionSubject,
  confirmSlug: string,
  activeLegalHolds: number,
): void {
  assertNotPlatform(org);
  if (org.status === 'pending_deletion' || org.status === 'deleted') {
    throw new ConflictException('Deletion has already been requested');
  }
  if (org.status !== 'suspended') {
    throw new ConflictException('The organization must be suspended before deletion');
  }
  assertSlug(org, confirmSlug);
  assertNoLegalHold(activeLegalHolds);
}

/** Latest moment a pending request can be confirmed. */
export function confirmationDeadline(requestedAt: Date, windowHours: number): Date {
  return new Date(requestedAt.getTime() + windowHours * HOUR_MS);
}

/**
 * Step 2: a pending request, confirmed by a different platform user (four-eyes, `403`), within
 * the confirmation window (`409`: cancel and request again), slug confirmed, no legal hold.
 */
export function assertCanConfirmDeletion(
  org: DeletionSubject,
  input: { confirmSlug: string; actorUserId: bigint; now: Date; windowHours: number },
  activeLegalHolds: number,
): void {
  assertNotPlatform(org);
  if (org.status !== 'pending_deletion' || org.deletionRequestedAt === null) {
    throw new ConflictException('There is no pending deletion request');
  }
  if (org.deletionRequestedByUserId === input.actorUserId) {
    throw new ForbiddenException('Deletion must be confirmed by a different platform user');
  }
  assertSlug(org, input.confirmSlug);
  if (input.now > confirmationDeadline(org.deletionRequestedAt, input.windowHours)) {
    throw new ConflictException(
      'The confirmation window has elapsed; cancel the request and request deletion again',
    );
  }
  assertNoLegalHold(activeLegalHolds);
}

/** Step 3: a pending request, or a confirmed deletion whose purge time has not come. */
export function assertCanCancelDeletion(org: DeletionSubject, now: Date): void {
  assertNotPlatform(org);
  if (org.status === 'pending_deletion') return;
  if (org.status === 'deleted' && org.purgeAfter !== null && now < org.purgeAfter) return;
  if (org.status === 'deleted') {
    throw new ConflictException('The deletion can no longer be cancelled (purge time reached)');
  }
  throw new ConflictException('There is no deletion to cancel');
}

/**
 * `purge_after` (D12): the retention period after confirmation, but never before the last
 * archive of the organization may be deleted (`MAX(email_archives.retain_until)`).
 */
export function computePurgeAfter(
  now: Date,
  retentionDays: number,
  latestArchiveRetainUntil: Date | null,
): Date {
  const retention = new Date(now.getTime() + retentionDays * DAY_MS);
  return latestArchiveRetainUntil !== null && latestArchiveRetainUntil > retention
    ? latestArchiveRetainUntil
    : retention;
}

export type DeletionStateName = 'none' | 'pending_deletion' | 'deleted';

export function deletionStateOf(status: OrganizationStatus): DeletionStateName {
  return status === 'pending_deletion' || status === 'deleted' ? status : 'none';
}
