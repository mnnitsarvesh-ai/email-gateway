/**
 * Inbound recipient validation of a domain (step 2.2 D3): the API model and its mapping onto
 * the existing `domain_settings` columns, and the normalization of allow-list local parts.
 * Pure (no Nest, no Prisma).
 *
 * | `recipient_validation` | `reject_unknown_recipients` | API                                      |
 * | ---------------------- | --------------------------- | ---------------------------------------- |
 * | `none` (or no row)     | any                         | `mode: accept_all`                       |
 * | `list`                 | true                        | `mode: allow_list, enforcement: reject`  |
 * | `list`                 | false                       | `mode: allow_list, enforcement: monitor` |
 * | `smtp_callout`, `ldap` | any                         | same name, `implemented: false`          |
 */

export type RecipientValidationColumn = 'none' | 'list' | 'smtp_callout' | 'ldap';
export type RecipientValidationMode = 'accept_all' | 'allow_list' | 'smtp_callout' | 'ldap';
export type RecipientEnforcement = 'reject' | 'monitor';

export interface RecipientValidationSettings {
  recipientValidation: RecipientValidationColumn;
  rejectUnknownRecipients: boolean;
}

export interface RecipientValidationState {
  mode: RecipientValidationMode;
  enforcement: RecipientEnforcement;
  /** False for modes the mail path does not implement yet (accept-all at RCPT, D3). */
  implemented: boolean;
}

/** Settings of a domain without a `domain_settings` row (the column defaults). */
export const DEFAULT_RECIPIENT_SETTINGS: RecipientValidationSettings = Object.freeze({
  recipientValidation: 'none',
  rejectUnknownRecipients: false,
});

/** Modes the API can set (D3); the others answer `422 Not implemented`. */
export const IMPLEMENTED_MODES: ReadonlySet<RecipientValidationMode> = new Set([
  'accept_all',
  'allow_list',
]);

export function toRecipientValidationState(
  settings: RecipientValidationSettings | null,
): RecipientValidationState {
  const s = settings ?? DEFAULT_RECIPIENT_SETTINGS;
  const mode: RecipientValidationMode =
    s.recipientValidation === 'none'
      ? 'accept_all'
      : s.recipientValidation === 'list'
        ? 'allow_list'
        : s.recipientValidation;
  return {
    mode,
    enforcement: s.rejectUnknownRecipients ? 'reject' : 'monitor',
    implemented: IMPLEMENTED_MODES.has(mode),
  };
}

/** The columns to store for an implemented mode. */
export function toRecipientValidationSettings(input: {
  mode: 'accept_all' | 'allow_list';
  enforcement: RecipientEnforcement;
}): RecipientValidationSettings {
  return {
    recipientValidation: input.mode === 'accept_all' ? 'none' : 'list',
    rejectUnknownRecipients: input.enforcement === 'reject',
  };
}

/** Maximum UTF-8 length of a local part (RFC 5321 §4.5.3.1.1; the column is VARCHAR(64)). */
export const MAX_LOCAL_PART_OCTETS = 64;

/** A refused local part; the message never echoes the input. */
export class LocalPartError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'LocalPartError';
  }
}

// Whitespace (incl. Unicode spaces), C0/C1 controls, format characters (zero-width, bidi),
// lone surrogates (not encodable as UTF-8).
const FORBIDDEN = /[\s\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

/**
 * Normalizes an allow-list local part the way the smtp-adapter looks it up (D3): Unicode NFC,
 * lower case. Refuses `@`, whitespace, control and format characters, the empty string and
 * anything longer than 64 UTF-8 octets after normalization.
 */
export function normalizeLocalPart(input: string): string {
  const value = input.normalize('NFC').toLowerCase().normalize('NFC');
  if (value.length === 0) throw new LocalPartError('must not be empty');
  if (value.includes('@')) throw new LocalPartError('must be a local part without "@" or domain');
  if (FORBIDDEN.test(value)) {
    throw new LocalPartError('must not contain whitespace or control characters');
  }
  if (Buffer.byteLength(value, 'utf8') > MAX_LOCAL_PART_OCTETS) {
    throw new LocalPartError(`must be at most ${MAX_LOCAL_PART_OCTETS} bytes (UTF-8)`);
  }
  return value;
}
