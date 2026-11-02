import { ConflictException } from '@nestjs/common';
import type { DomainStatus } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import {
  canTransition,
  type DomainLifecycleEvent,
  nextStatus,
  statusChangeEvent,
  SUSPEND_BEFORE_DELETE,
} from './state-machine';

const STATUSES: DomainStatus[] = [
  'pending_verification',
  'verified',
  'failed',
  'disabled',
  'active',
  'suspended',
  'deleted',
];

/** The D3 table: every allowed (from, event) → to. */
const ALLOWED: Array<[DomainStatus, DomainLifecycleEvent, DomainStatus]> = [
  ['pending_verification', 'ownership_verified', 'verified'],
  ['pending_verification', 'claim_superseded', 'failed'],
  ['pending_verification', 'verification_expired', 'failed'],
  ['failed', 'verification_restarted', 'pending_verification'],
  ['verified', 'activate', 'active'],
  ['suspended', 'activate', 'active'],
  ['active', 'suspend', 'suspended'],
  ['pending_verification', 'delete', 'deleted'],
  ['verified', 'delete', 'deleted'],
  ['failed', 'delete', 'deleted'],
  ['suspended', 'delete', 'deleted'],
  ['disabled', 'delete', 'deleted'],
];

const EVENTS: DomainLifecycleEvent[] = [
  'ownership_verified',
  'claim_superseded',
  'verification_expired',
  'verification_restarted',
  'activate',
  'suspend',
  'delete',
];

describe('domain state machine (D3)', () => {
  it.each(ALLOWED)('%s --%s--> %s', (from, event, to) => {
    expect(canTransition(from, event)).toBe(true);
    expect(nextStatus(from, event)).toBe(to);
  });

  const forbidden = STATUSES.flatMap((from) =>
    EVENTS.filter((event) => !ALLOWED.some(([f, e]) => f === from && e === event)).map(
      (event) => [from, event] as const,
    ),
  );

  it.each(forbidden)('refuses %s --%s--> with 409', (from, event) => {
    expect(canTransition(from, event)).toBe(false);
    expect(() => nextStatus(from, event)).toThrow(ConflictException);
  });

  it('explains the conflict with the current status', () => {
    expect(() => nextStatus('pending_verification', 'activate')).toThrow(
      'Domain is pending_verification',
    );
    expect(() => nextStatus('verified', 'suspend')).toThrow('Domain is verified');
    expect(() => nextStatus('deleted', 'delete')).toThrow('Domain is deleted');
  });

  it('asks to suspend an active domain before deleting it', () => {
    expect(() => nextStatus('active', 'delete')).toThrow(SUSPEND_BEFORE_DELETE);
  });

  it('never writes the deprecated disabled status', () => {
    for (const [, , to] of ALLOWED) expect(to).not.toBe('disabled');
  });

  it('maps PATCH bodies to events', () => {
    expect(statusChangeEvent('active')).toBe('activate');
    expect(statusChangeEvent('suspended')).toBe('suspend');
  });
});
