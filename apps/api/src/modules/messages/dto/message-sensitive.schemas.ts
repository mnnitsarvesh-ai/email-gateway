import { z } from 'zod';
import { CURSOR_MAX_LENGTH } from '../../../http/cursor/cursor-codec';

/**
 * Request and response shapes of the step 7.2 sensitive-metadata routes (§2 E6, E7, §3.3,
 * ADR-0062): `GET /messages/{messageId}/headers` (stored allow-list, safe subset in clear),
 * `POST /messages/reveal` (subjects of a page of messages) and `POST /messages/{messageId}/reveal`
 * (subject, the masked header values and the recipient addresses of one message). Request bodies
 * are strict; no reveal takes an Idempotency-Key.
 */

const IsoDate = z.iso.datetime();

/** v1 cursor resource of the recipients of a single reveal (bound to message + organization). */
export const MESSAGE_RECIPIENTS_REVEAL_RESOURCE = 'message_recipients_reveal';

/** Most ids of one bulk reveal (§2 E6). */
export const MESSAGE_REVEAL_MAX_IDS = 100;
/** Recipients per single-reveal page (§2 E6). */
export const MESSAGE_REVEAL_MAX_RECIPIENTS = 100;
export const MESSAGE_REVEAL_DEFAULT_RECIPIENTS = 100;

/** What a single reveal may return (§2 E6). */
export const REVEAL_FIELDS = ['subject', 'headers', 'recipients'] as const;
export type RevealField = (typeof REVEAL_FIELDS)[number];

const unique = <T>(values: readonly T[]): boolean => new Set(values).size === values.length;

/** `POST /messages/reveal`: 1–100 distinct message public ids (case-insensitive). */
export const RevealManyBodySchema = z.strictObject({
  messageIds: z
    .array(z.uuid().transform((value) => value.toLowerCase()))
    .min(1)
    .max(MESSAGE_REVEAL_MAX_IDS)
    .refine(unique, 'must not contain the same id twice')
    .describe(
      `Message public ids (1-${MESSAGE_REVEAL_MAX_IDS}, distinct), e.g. the ids of one explorer page`,
    ),
});
export type RevealManyBody = z.output<typeof RevealManyBodySchema>;

/**
 * `POST /messages/{messageId}/reveal`: 1–3 distinct fields; `recipientsCursor` and
 * `recipientsLimit` only together with `recipients`.
 */
export const RevealBodySchema = z
  .strictObject({
    fields: z
      .array(z.enum(REVEAL_FIELDS))
      .min(1)
      .max(REVEAL_FIELDS.length)
      .refine(unique, 'must not contain the same field twice')
      .describe('What to reveal: `subject`, `headers` (To, Cc, Subject rows), `recipients`'),
    recipientsCursor: z
      .string()
      .min(1)
      .max(CURSOR_MAX_LENGTH)
      .optional()
      .describe('`recipients.nextCursor` of the previous reveal of this message'),
    recipientsLimit: z
      .number()
      .int()
      .min(1)
      .max(MESSAGE_REVEAL_MAX_RECIPIENTS)
      .optional()
      .describe(
        `Recipients per reveal, 1-${MESSAGE_REVEAL_MAX_RECIPIENTS} ` +
          `(default ${MESSAGE_REVEAL_DEFAULT_RECIPIENTS})`,
      ),
  })
  .superRefine((body, ctx) => {
    if (body.fields.includes('recipients')) return;
    for (const key of ['recipientsCursor', 'recipientsLimit'] as const) {
      if (body[key] !== undefined) {
        ctx.addIssue({ code: 'custom', path: [key], message: "only with the field 'recipients'" });
      }
    }
  });
export type RevealBody = z.output<typeof RevealBodySchema>;

export const RevealedSubjectSchema = z.object({
  id: z.uuid().describe('Message public id'),
  subject: z
    .string()
    .nullable()
    .describe('The stored subject (attacker-controlled text, as stored), or null when none'),
});

export const RevealManyResponseSchema = z.object({
  revealedAt: IsoDate.describe('When the reveal was recorded in the audit log'),
  data: z
    .array(RevealedSubjectSchema)
    .describe(
      'In request order, for the ids found in your organization; unknown and other ' +
        'organizations’ ids are omitted (indistinguishable)',
    ),
});
export type RevealManyResponse = z.output<typeof RevealManyResponseSchema>;

export const RevealedHeaderSchema = z.object({
  seq: z.number().int().min(0).describe('Position among the stored headers'),
  name: z.string().describe('`To`, `Cc` or `Subject`'),
  value: z.string().describe('Decoded value as stored (attacker-controlled text)'),
});

export const RevealedRecipientSchema = z.object({
  rcptSeq: z.number().int().min(0).describe('Position in the RCPT TO list'),
  address: z.string().describe('The envelope recipient address as stored'),
  userId: z.uuid().nullable().describe('Public id of the matched user, or null'),
});

export const RevealResponseSchema = z.object({
  messageId: z.uuid(),
  revealedAt: IsoDate.describe('When the reveal was recorded in the audit log'),
  subject: z
    .string()
    .nullable()
    .optional()
    .describe('With `subject`: the stored subject, or null when none'),
  headers: z
    .array(RevealedHeaderSchema)
    .optional()
    .describe('With `headers`: the stored To, Cc and Subject rows in `seq` order'),
  recipients: z
    .object({
      data: z.array(RevealedRecipientSchema).describe('In RCPT order (keyset `rcptSeq`)'),
      nextCursor: z
        .string()
        .nullable()
        .describe('Pass as `recipientsCursor` to reveal the next recipients; null at the end'),
    })
    .optional()
    .describe('With `recipients`: one page of recipients'),
});
export type RevealResponse = z.output<typeof RevealResponseSchema>;

/** `availability` of the stored headers (§2 E7). */
export const HEADER_AVAILABILITIES = [
  'available',
  'not_parsed',
  'none_stored',
  'retention_expired',
] as const;
export type HeaderAvailability = (typeof HEADER_AVAILABILITIES)[number];

export const MessageHeaderSchema = z.object({
  seq: z.number().int().min(0).describe('Position among the stored headers'),
  name: z.string().describe('Canonical header name (the step 3.1 allow-list)'),
  value: z
    .string()
    .nullable()
    .describe(
      'Decoded value as stored (attacker-controlled text, never parsed by the api) for the safe ' +
        'subset; null when `masked`',
    ),
  masked: z
    .boolean()
    .describe(
      'True for To, Cc, Subject and any name outside the safe subset; reveal with ' +
        '`POST /messages/{messageId}/reveal` (`headers`, `message:reveal`)',
    ),
});

export const MessageHeadersSchema = z.object({
  messageId: z.uuid(),
  availability: z
    .enum(HEADER_AVAILABILITIES)
    .describe(
      '`available` (rows stored), `not_parsed` (the MIME parse did not finish or failed), ' +
        '`none_stored` (parsed, no allow-listed header), `retention_expired` (older than the ' +
        '3-month header retention)',
    ),
  storedHeaderNames: z
    .array(z.string())
    .describe('The allow-list of headers the gateway stores (step 3.1); others are never stored'),
  safeHeaderNames: z.array(z.string()).describe('The names whose values are returned in clear'),
  headers: z.array(MessageHeaderSchema).describe('Stored rows in `seq` order (at most 500)'),
});
export type MessageHeadersView = z.output<typeof MessageHeadersSchema>;
