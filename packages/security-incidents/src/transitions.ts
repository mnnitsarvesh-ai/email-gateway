/**
 * The incident state machine of the shared model (D12, D24): six states, two terminal. Enforced by
 * `IncidentStore.transition` under the row lock with a row-version compare-and-set.
 */
import type {
  SecurityIncidentResolutionCode,
  SecurityIncidentStatus,
} from '@email-gateway/security-contracts';
import {
  INCIDENT_FREE_NOTE_MIN_LENGTH,
  INCIDENT_NOTE_MAX_LENGTH,
  INCIDENT_NOTE_MIN_LENGTH,
} from './vocabulary';

/** Allowed transitions (exactly D12). `false_positive` and `resolved` are terminal. */
export const INCIDENT_TRANSITIONS: Readonly<
  Record<SecurityIncidentStatus, readonly SecurityIncidentStatus[]>
> = Object.freeze({
  open: Object.freeze(['investigating', 'confirmed', 'false_positive', 'resolved'] as const),
  investigating: Object.freeze(['confirmed', 'false_positive', 'resolved'] as const),
  confirmed: Object.freeze(['mitigated', 'resolved'] as const),
  mitigated: Object.freeze(['resolved', 'confirmed'] as const),
  false_positive: Object.freeze([] as const),
  resolved: Object.freeze([] as const),
});

export const TERMINAL_INCIDENT_STATUSES: readonly SecurityIncidentStatus[] = Object.freeze([
  'false_positive',
  'resolved',
]);

export const isTerminalIncidentStatus = (status: SecurityIncidentStatus): boolean =>
  TERMINAL_INCIDENT_STATUSES.includes(status);

/** Whether `from → to` is an allowed transition (a state never transitions to itself). */
export function canTransitionIncident(
  from: SecurityIncidentStatus,
  to: SecurityIncidentStatus,
): boolean {
  return INCIDENT_TRANSITIONS[from].includes(to);
}

export interface ResolutionRequirement {
  /** Resolution codes accepted (null = a resolution code is not accepted for this target). */
  codes: readonly SecurityIncidentResolutionCode[] | null;
  /** Whether a note (10–4000 characters) is required. */
  noteRequired: boolean;
}

/**
 * Requirements per target state (D12): `false_positive` needs one of `false_positive`,
 * `benign_activity`, `duplicate`; `resolved` one of `remediated`, `benign_activity`, `duplicate`,
 * `other`; both with a note; `confirmed` needs a note. Other targets take no resolution code and
 * an optional note.
 */
export const RESOLUTION_REQUIREMENTS: Readonly<
  Record<SecurityIncidentStatus, ResolutionRequirement>
> = Object.freeze({
  open: { codes: null, noteRequired: false },
  investigating: { codes: null, noteRequired: false },
  confirmed: { codes: null, noteRequired: true },
  mitigated: { codes: null, noteRequired: false },
  false_positive: {
    codes: Object.freeze(['false_positive', 'benign_activity', 'duplicate'] as const),
    noteRequired: true,
  },
  resolved: {
    codes: Object.freeze(['remediated', 'benign_activity', 'duplicate', 'other'] as const),
    noteRequired: true,
  },
});

/** The requirement of a target state. */
export function requiredResolution(to: SecurityIncidentStatus): ResolutionRequirement {
  return RESOLUTION_REQUIREMENTS[to];
}

export type TransitionRefusal =
  | 'transition_not_allowed'
  | 'resolution_required'
  | 'resolution_invalid'
  | 'note_required'
  | 'note_invalid';

/** Normalizes a note: trimmed; `null` when absent or blank. */
export function normalizeNote(note: string | null | undefined): string | null {
  if (note === null || note === undefined) return null;
  const trimmed = note.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/** Whether a normalized note has a valid length (`min` default 10, max 4000 characters). */
export function isValidNoteLength(note: string, min: number = INCIDENT_NOTE_MIN_LENGTH): boolean {
  const length = [...note].length;
  return length >= min && length <= INCIDENT_NOTE_MAX_LENGTH;
}

/** Whether a free note (`addNote`) is 1–4000 characters after trimming. */
export const isValidFreeNote = (note: string): boolean =>
  isValidNoteLength(note, INCIDENT_FREE_NOTE_MIN_LENGTH);

/**
 * Pure check of a transition request: the edge, the resolution code and the note. Returns `null`
 * when the request is valid, otherwise the refusal reason.
 */
export function checkTransition(
  from: SecurityIncidentStatus,
  to: SecurityIncidentStatus,
  input: { resolutionCode?: SecurityIncidentResolutionCode | null; note?: string | null },
): TransitionRefusal | null {
  if (!canTransitionIncident(from, to)) return 'transition_not_allowed';
  const requirement = RESOLUTION_REQUIREMENTS[to];
  const code = input.resolutionCode ?? null;
  if (requirement.codes === null) {
    if (code !== null) return 'resolution_invalid';
  } else {
    if (code === null) return 'resolution_required';
    if (!requirement.codes.includes(code)) return 'resolution_invalid';
  }
  const note = normalizeNote(input.note);
  if (note === null) return requirement.noteRequired ? 'note_required' : null;
  return isValidNoteLength(note) ? null : 'note_invalid';
}
