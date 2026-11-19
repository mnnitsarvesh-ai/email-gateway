import { describe, expect, it } from 'vitest';
import {
  SECURITY_INCIDENT_RESOLUTION_CODES,
  SECURITY_INCIDENT_STATUSES,
  type SecurityIncidentStatus,
} from '@email-gateway/security-contracts';
import {
  canTransitionIncident,
  checkTransition,
  INCIDENT_TRANSITIONS,
  isTerminalIncidentStatus,
  isValidFreeNote,
  normalizeNote,
  requiredResolution,
} from './transitions';

const NOTE = 'Reviewed with the account owner.';

const ALLOWED: ReadonlyArray<[SecurityIncidentStatus, SecurityIncidentStatus]> = [
  ['open', 'investigating'],
  ['open', 'confirmed'],
  ['open', 'false_positive'],
  ['open', 'resolved'],
  ['investigating', 'confirmed'],
  ['investigating', 'false_positive'],
  ['investigating', 'resolved'],
  ['confirmed', 'mitigated'],
  ['confirmed', 'resolved'],
  ['mitigated', 'resolved'],
  ['mitigated', 'confirmed'],
];

describe('INCIDENT_TRANSITIONS (D12)', () => {
  it('has an entry for every state', () => {
    expect(Object.keys(INCIDENT_TRANSITIONS).sort()).toEqual(
      [...SECURITY_INCIDENT_STATUSES].sort(),
    );
  });

  for (const from of SECURITY_INCIDENT_STATUSES) {
    for (const to of SECURITY_INCIDENT_STATUSES) {
      const allowed = ALLOWED.some(([f, t]) => f === from && t === to);
      it(`${from} -> ${to} is ${allowed ? 'allowed' : 'refused'}`, () => {
        expect(canTransitionIncident(from, to)).toBe(allowed);
        if (!allowed) {
          expect(checkTransition(from, to, { resolutionCode: 'other', note: NOTE })).toBe(
            'transition_not_allowed',
          );
        }
      });
    }
  }

  it('false_positive and resolved are terminal', () => {
    expect(isTerminalIncidentStatus('false_positive')).toBe(true);
    expect(isTerminalIncidentStatus('resolved')).toBe(true);
    for (const s of ['open', 'investigating', 'confirmed', 'mitigated'] as const) {
      expect(isTerminalIncidentStatus(s)).toBe(false);
    }
    expect(INCIDENT_TRANSITIONS.false_positive).toEqual([]);
    expect(INCIDENT_TRANSITIONS.resolved).toEqual([]);
  });
});

describe('resolution requirements', () => {
  it('false_positive accepts false_positive, benign_activity, duplicate with a note', () => {
    expect(requiredResolution('false_positive')).toEqual({
      codes: ['false_positive', 'benign_activity', 'duplicate'],
      noteRequired: true,
    });
    for (const code of SECURITY_INCIDENT_RESOLUTION_CODES) {
      const ok = ['false_positive', 'benign_activity', 'duplicate'].includes(code);
      expect(checkTransition('open', 'false_positive', { resolutionCode: code, note: NOTE })).toBe(
        ok ? null : 'resolution_invalid',
      );
    }
    expect(checkTransition('open', 'false_positive', { note: NOTE })).toBe('resolution_required');
    expect(checkTransition('open', 'false_positive', { resolutionCode: 'duplicate' })).toBe(
      'note_required',
    );
  });

  it('resolved accepts remediated, benign_activity, duplicate, other with a note', () => {
    for (const code of SECURITY_INCIDENT_RESOLUTION_CODES) {
      const ok = code !== 'false_positive';
      expect(checkTransition('confirmed', 'resolved', { resolutionCode: code, note: NOTE })).toBe(
        ok ? null : 'resolution_invalid',
      );
    }
    expect(checkTransition('mitigated', 'resolved', { resolutionCode: 'other' })).toBe(
      'note_required',
    );
  });

  it('confirmed requires a note and refuses a resolution code', () => {
    expect(checkTransition('open', 'confirmed', {})).toBe('note_required');
    expect(checkTransition('open', 'confirmed', { note: NOTE })).toBeNull();
    expect(checkTransition('open', 'confirmed', { note: NOTE, resolutionCode: 'other' })).toBe(
      'resolution_invalid',
    );
  });

  it('investigating and mitigated take an optional note', () => {
    expect(checkTransition('open', 'investigating', {})).toBeNull();
    expect(checkTransition('confirmed', 'mitigated', { note: NOTE })).toBeNull();
    expect(checkTransition('confirmed', 'mitigated', { note: 'short' })).toBe('note_invalid');
  });

  it('notes are 10-4000 characters after trimming (code points)', () => {
    expect(checkTransition('open', 'confirmed', { note: '   123456789   ' })).toBe('note_invalid');
    expect(checkTransition('open', 'confirmed', { note: '1234567890' })).toBeNull();
    expect(checkTransition('open', 'confirmed', { note: 'x'.repeat(4000) })).toBeNull();
    expect(checkTransition('open', 'confirmed', { note: 'x'.repeat(4001) })).toBe('note_invalid');
    expect(checkTransition('open', 'confirmed', { note: '😀'.repeat(4000) })).toBeNull();
    expect(checkTransition('open', 'confirmed', { note: '   ' })).toBe('note_required');
  });

  it('free notes are 1-4000 characters', () => {
    expect(normalizeNote('  a  ')).toBe('a');
    expect(normalizeNote('   ')).toBeNull();
    expect(normalizeNote(undefined)).toBeNull();
    expect(isValidFreeNote('a')).toBe(true);
    expect(isValidFreeNote('a'.repeat(4001))).toBe(false);
  });
});
