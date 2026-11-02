import { ConflictException } from '@nestjs/common';
import type { DkimAlgorithm, DkimKeyStatus } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { isDueForRetirement, planRotation, ROTATION_IN_PROGRESS } from './dkim-rotation';

let id = 0n;
const key = (status: DkimKeyStatus, algorithm: DkimAlgorithm = 'rsa_2048') => ({
  id: ++id,
  selector: `sel${id}`,
  algorithm,
  status,
});

describe('planRotation (D9)', () => {
  it('adds a pending key next to the active one', () => {
    const active = key('active');
    expect(planRotation('active', [active, key('retired')], 'rsa_2048')).toEqual({
      kind: 'add',
      previous: active,
    });
  });

  it('adds a first key to an empty family', () => {
    expect(planRotation('verified', [key('active')], 'ed25519')).toEqual({
      kind: 'add',
      previous: null,
    });
  });

  it('refuses a second rotation while a pending key waits next to an active one', () => {
    expect(() => planRotation('active', [key('active'), key('pending')], 'rsa_2048')).toThrow(
      ROTATION_IN_PROGRESS,
    );
  });

  it('replaces a family whose only key is pending (never published)', () => {
    const pending = key('pending');
    expect(planRotation('pending_verification', [pending], 'rsa_2048')).toEqual({
      kind: 'replace_pending',
      previous: pending,
    });
  });

  it('allows a rotation while the previous key is still in its overlap', () => {
    const active = key('active');
    expect(planRotation('active', [key('rotating'), active], 'rsa_2048')).toEqual({
      kind: 'add',
      previous: active,
    });
  });

  it('treats algorithms as independent families', () => {
    const plan = planRotation(
      'active',
      [key('active'), key('pending'), key('active', 'ed25519')],
      'ed25519',
    );
    expect(plan.kind).toBe('add');
  });

  it('refuses failed and deleted domains', () => {
    for (const status of ['failed', 'deleted', 'disabled'] as const) {
      expect(() => planRotation(status, [], 'rsa_2048')).toThrow(ConflictException);
      expect(() => planRotation(status, [], 'rsa_2048')).toThrow(`Domain is ${status}`);
    }
  });
});

describe('isDueForRetirement', () => {
  const now = new Date('2026-11-10T00:00:00Z');
  it('retires rotating keys once the overlap has ended', () => {
    expect(isDueForRetirement({ status: 'rotating', retireAfter: now }, now)).toBe(true);
    expect(
      isDueForRetirement({ status: 'rotating', retireAfter: new Date(now.getTime() + 1) }, now),
    ).toBe(false);
    expect(isDueForRetirement({ status: 'active', retireAfter: now }, now)).toBe(false);
    expect(isDueForRetirement({ status: 'rotating', retireAfter: null }, now)).toBe(false);
  });
});
