import type { SearchChipField, SearchValidation } from '@/components/search-chip-input';

/**
 * Search fields of the Email Explorer (step 7.2 §2 E10) and their validators. Each validator
 * mirrors the api's rule for the parameter (`GET /messages`, `MessageListQuerySchema`), so a
 * value is committed (and a request made) only when the api would accept it; the value it
 * returns is what the URL keeps and the request sends.
 */
export const SEARCH_FIELD_IDS = [
  'sender',
  'headerFrom',
  'recipient',
  'subject',
  'subjectPrefix',
  'messageId',
  'senderDomain',
  'recipientDomain',
] as const;
export type SearchFieldId = (typeof SEARCH_FIELD_IDS)[number];

/**
 * Fields that need `message:reveal` (§2 E2, ADR-0062): the subject searches are a content oracle
 * and the exact recipient confirms a masked address. The recipient domain stays open.
 */
export const REVEAL_SEARCH_FIELDS: readonly SearchFieldId[] = [
  'recipient',
  'subject',
  'subjectPrefix',
];

/** Unicode `White_Space` (ICU `[[:space:]]`), as the api's `search-keys.ts`. */
const WS =
  '[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]';
const REPLY_MARKERS = new RegExp(
  `^(?:${WS}*(?:re|fw|fwd|aw|wg|sv|vs|antw|tr|rif|enc|odp)${WS}*(?:\\[[0-9]+\\]${WS}*)?:)+`,
  'iu',
);
const WHITE_SPACE_RUNS = new RegExp(`${WS}+`, 'gu');

/** The api's subject normalization (reply markers removed, white space collapsed, trimmed). */
export function normalizeSubject(value: string): string {
  return value.replace(REPLY_MARKERS, '').replace(WHITE_SPACE_RUNS, ' ').replace(/^ | $/gu, '');
}

const codePoints = (value: string) => Array.from(value).length;

/** The api's `email` filter type: `^[^\s@]+@[^\s@]+$`, 3–320 characters, lower-cased. */
export function validateAddress(raw: string): SearchValidation {
  const value = raw.trim();
  if (value.length < 3 || value.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(value)) {
    return { ok: false, message: 'Enter a complete address, for example name@example.com.' };
  }
  return { ok: true, value: value.toLowerCase() };
}

/** The api's `domain` filter type: trimmed, lower-cased, one leading `@` removed, LDH labels. */
export const DOMAIN_NAME_PATTERN =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

export function validateDomain(raw: string): SearchValidation {
  const lower = raw.trim().toLowerCase();
  const value = lower.startsWith('@') ? lower.slice(1) : lower;
  if (value.length === 0 || value.length > 253 || !DOMAIN_NAME_PATTERN.test(value)) {
    return {
      ok: false,
      message: 'Enter a domain such as example.com (internationalized domains in their xn-- form).',
    };
  }
  return { ok: true, value };
}

/** `subject`: 1–998 characters whose normalized form is not empty. */
export function validateSubject(raw: string): SearchValidation {
  const value = raw.trim();
  if (value.length === 0 || value.length > 998 || normalizeSubject(value) === '') {
    return { ok: false, message: 'Enter the subject (reply markers such as Re: are ignored).' };
  }
  return { ok: true, value };
}

/** `subjectPrefix`: 3–128 characters after normalization. */
export function validateSubjectPrefix(raw: string): SearchValidation {
  const value = raw.trim();
  const length = codePoints(normalizeSubject(value));
  if (value.length > 998 || length < 3 || length > 128) {
    return {
      ok: false,
      message:
        'Enter at least 3 characters of the subject (at most 128; Re: and Fwd: are ignored).',
    };
  }
  return { ok: true, value };
}

/** `internetMessageId`: angle brackets optional; something must remain without them. */
export function validateMessageId(raw: string): SearchValidation {
  const value = raw.trim();
  const key = value
    .replace(/^ +| +$/gu, '')
    .replace(/^<+/u, '')
    .replace(/>+$/u, '');
  if (value.length > 998 || key.length === 0) {
    return { ok: false, message: 'Enter a Message-ID, for example <abc123@mail.example.com>.' };
  }
  return { ok: true, value };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** A gateway message id (UUID): the Message ID field then offers "Open message". */
export function isMessageUuid(value: string): boolean {
  return UUID.test(value.trim());
}

export const VALIDATORS: Readonly<Record<SearchFieldId, (raw: string) => SearchValidation>> = {
  sender: validateAddress,
  headerFrom: validateAddress,
  recipient: validateAddress,
  subject: validateSubject,
  subjectPrefix: validateSubjectPrefix,
  messageId: validateMessageId,
  senderDomain: validateDomain,
  recipientDomain: validateDomain,
};

const AUDITED = 'The search is recorded in the audit log (as a hash).';

export const SEARCH_FIELDS: readonly (SearchChipField & { readonly id: SearchFieldId })[] = [
  {
    id: 'sender',
    label: 'Sender (envelope)',
    placeholder: 'name@example.com',
    inputMode: 'email',
    hint: `The exact envelope sender (MAIL FROM). ${AUDITED}`,
    validate: validateAddress,
  },
  {
    id: 'headerFrom',
    label: 'Sender (From header)',
    placeholder: 'name@example.com',
    inputMode: 'email',
    hint: `The exact address of the From header. ${AUDITED}`,
    validate: validateAddress,
  },
  {
    id: 'recipient',
    label: 'Recipient',
    placeholder: 'name@example.com',
    inputMode: 'email',
    hint: `The exact envelope recipient. ${AUDITED}`,
    validate: validateAddress,
  },
  {
    id: 'subject',
    label: 'Subject',
    placeholder: 'Quarterly report',
    hint: `The whole subject; case, accents and reply markers (Re:, Fwd:) are ignored. ${AUDITED}`,
    validate: validateSubject,
  },
  {
    id: 'subjectPrefix',
    label: 'Subject starts with',
    placeholder: 'Invoice 44',
    hint: `At least 3 characters. A very common beginning is refused: type more of it. ${AUDITED}`,
    validate: validateSubjectPrefix,
  },
  {
    id: 'messageId',
    label: 'Message ID',
    placeholder: '<abc123@mail.example.com>',
    hint: `The Message-ID header, angle brackets optional. ${AUDITED}`,
    validate: validateMessageId,
  },
  {
    id: 'senderDomain',
    label: 'Sender domain',
    placeholder: 'example.com',
    hint: 'The domain of the envelope sender (internationalized domains in their xn-- form).',
    validate: validateDomain,
  },
  {
    id: 'recipientDomain',
    label: 'Recipient domain',
    placeholder: 'example.com',
    hint: 'The domain of any envelope recipient (internationalized domains in their xn-- form).',
    validate: validateDomain,
  },
];
