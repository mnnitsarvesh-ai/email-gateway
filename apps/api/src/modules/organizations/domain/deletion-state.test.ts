import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import { describe, expect, it } from 'vitest';
import {
  ACTIVE_LEGAL_HOLD,
  assertCanCancelDeletion,
  assertCanConfirmDeletion,
  assertCanRequestDeletion,
  computePurgeAfter,
  confirmationDeadline,
  type DeletionSubject,
  deletionStateOf,
} from './deletion-state';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const now = new Date('2026-11-02T12:00:00.000Z');

const suspended: DeletionSubject = {
  slug: 'acme',
  kind: 'customer',
  status: 'suspended',
  deletionRequestedAt: null,
  deletionRequestedByUserId: null,
  purgeAfter: null,
};
const pending: DeletionSubject = {
  ...suspended,
  status: 'pending_deletion',
  deletionRequestedAt: new Date(now.getTime() - 2 * HOUR),
  deletionRequestedByUserId: 10n,
};
const confirmInput = { confirmSlug: 'acme', actorUserId: 11n, now, windowHours: 72 };

describe('request (step 1)', () => {
  it('accepts a suspended customer organization with the right slug and no hold', () => {
    expect(() => assertCanRequestDeletion(suspended, 'acme', 0)).not.toThrow();
  });

  it.each(['active'] as const)('refuses a %s organization (409)', (status) => {
    expect(() => assertCanRequestDeletion({ ...suspended, status }, 'acme', 0)).toThrow(
      ConflictException,
    );
  });

  it('refuses a second request (409)', () => {
    expect(() => assertCanRequestDeletion(pending, 'acme', 0)).toThrow(/already/);
    expect(() => assertCanRequestDeletion({ ...pending, status: 'deleted' }, 'acme', 0)).toThrow(
      ConflictException,
    );
  });

  it('refuses the platform organization (409)', () => {
    expect(() =>
      assertCanRequestDeletion({ ...suspended, kind: 'platform', slug: 'platform' }, 'platform', 0),
    ).toThrow(/platform organization/);
  });

  it('requires the slug confirmation (400)', () => {
    expect(() => assertCanRequestDeletion(suspended, 'ACME', 0)).toThrow(BadRequestException);
  });

  it('is blocked by an active legal hold (409)', () => {
    expect(() => assertCanRequestDeletion(suspended, 'acme', 1)).toThrow(ACTIVE_LEGAL_HOLD);
  });
});

describe('confirm (step 2)', () => {
  it('accepts a different platform user within the window', () => {
    expect(() => assertCanConfirmDeletion(pending, confirmInput, 0)).not.toThrow();
  });

  it('enforces four eyes (403)', () => {
    expect(() =>
      assertCanConfirmDeletion(pending, { ...confirmInput, actorUserId: 10n }, 0),
    ).toThrow(ForbiddenException);
  });

  it('needs a pending request (409)', () => {
    expect(() => assertCanConfirmDeletion(suspended, confirmInput, 0)).toThrow(ConflictException);
    expect(() =>
      assertCanConfirmDeletion({ ...pending, status: 'deleted' }, confirmInput, 0),
    ).toThrow(ConflictException);
  });

  it('expires after the confirmation window (409)', () => {
    const old = { ...pending, deletionRequestedAt: new Date(now.getTime() - 72 * HOUR - 1) };
    expect(() => assertCanConfirmDeletion(old, confirmInput, 0)).toThrow(/window/);
    const edge = { ...pending, deletionRequestedAt: new Date(now.getTime() - 72 * HOUR) };
    expect(() => assertCanConfirmDeletion(edge, confirmInput, 0)).not.toThrow();
  });

  it('repeats the slug and legal-hold checks', () => {
    expect(() =>
      assertCanConfirmDeletion(pending, { ...confirmInput, confirmSlug: 'other' }, 0),
    ).toThrow(BadRequestException);
    expect(() => assertCanConfirmDeletion(pending, confirmInput, 2)).toThrow(ACTIVE_LEGAL_HOLD);
  });
});

describe('cancel (step 3)', () => {
  it('cancels a pending request', () => {
    expect(() => assertCanCancelDeletion(pending, now)).not.toThrow();
  });

  it('cancels a confirmed deletion before purge_after only', () => {
    const deleted = {
      ...pending,
      status: 'deleted' as const,
      purgeAfter: new Date(now.getTime() + DAY),
    };
    expect(() => assertCanCancelDeletion(deleted, now)).not.toThrow();
    expect(() => assertCanCancelDeletion(deleted, new Date(now.getTime() + DAY))).toThrow(
      /purge time/,
    );
  });

  it('has nothing to cancel otherwise (409)', () => {
    expect(() => assertCanCancelDeletion(suspended, now)).toThrow(ConflictException);
    expect(() => assertCanCancelDeletion({ ...suspended, status: 'active' }, now)).toThrow(
      ConflictException,
    );
  });
});

describe('computePurgeAfter', () => {
  it('is now + retention without archives', () => {
    expect(computePurgeAfter(now, 30, null)).toEqual(new Date(now.getTime() + 30 * DAY));
  });

  it('waits for the last archive retention when it is later', () => {
    const retainUntil = new Date(now.getTime() + 400 * DAY);
    expect(computePurgeAfter(now, 30, retainUntil)).toEqual(retainUntil);
  });

  it('keeps the retention period when archives expire earlier', () => {
    expect(computePurgeAfter(now, 30, new Date(now.getTime() + DAY))).toEqual(
      new Date(now.getTime() + 30 * DAY),
    );
  });
});

describe('helpers', () => {
  it('computes the confirmation deadline', () => {
    expect(confirmationDeadline(now, 72)).toEqual(new Date(now.getTime() + 72 * HOUR));
  });

  it('names the deletion state', () => {
    expect(deletionStateOf('active')).toBe('none');
    expect(deletionStateOf('suspended')).toBe('none');
    expect(deletionStateOf('pending_deletion')).toBe('pending_deletion');
    expect(deletionStateOf('deleted')).toBe('deleted');
  });
});
