import type { DomainStatus } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { allRecordsValid, groupOf, mailFlowReady, readyForActivation, worstOf } from './readiness';

describe('worstOf (status summary of a group)', () => {
  it('ranks invalid > missing > pending > valid', () => {
    expect(worstOf(['valid', 'valid'])).toBe('valid');
    expect(worstOf(['valid', 'pending'])).toBe('pending');
    expect(worstOf(['pending', 'missing', 'valid'])).toBe('missing');
    expect(worstOf(['missing', 'invalid', 'pending'])).toBe('invalid');
    expect(worstOf(['invalid', 'valid'])).toBe('invalid');
  });

  it('treats an empty group as pending', () => {
    expect(worstOf([])).toBe('pending');
  });
});

describe('readiness', () => {
  const statuses: DomainStatus[] = [
    'pending_verification',
    'verified',
    'failed',
    'disabled',
    'active',
    'suspended',
  ];

  it('is ready for activation only when verified (ownership only, not MX)', () => {
    expect(statuses.filter(readyForActivation)).toEqual(['verified']);
  });

  it('has mail flow only when active and the MX is valid', () => {
    for (const status of statuses) {
      expect(mailFlowReady(status, 'valid')).toBe(status === 'active');
      expect(mailFlowReady(status, 'invalid')).toBe(false);
      expect(mailFlowReady(status, 'pending')).toBe(false);
    }
  });

  it('needs every record valid for a complete configuration', () => {
    expect(allRecordsValid(['valid', 'valid'])).toBe(true);
    expect(allRecordsValid(['valid', 'missing'])).toBe(false);
    expect(allRecordsValid([])).toBe(false);
  });

  it('groups records by purpose', () => {
    expect(groupOf('verification')).toBe('ownership');
    expect(groupOf('mx')).toBe('mx');
    expect(groupOf('dkim')).toBe('dkim');
    expect(groupOf('mta_sts')).toBeNull();
  });
});
