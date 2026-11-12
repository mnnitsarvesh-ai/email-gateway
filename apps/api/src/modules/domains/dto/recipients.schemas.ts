import { z } from 'zod';
import { PageQuerySchema } from '../../../http/pagination';
import { LocalPartError, normalizeLocalPart } from '../domain/recipient-validation';

/**
 * Request and response shapes of `/domains/{id}/recipient-validation` and
 * `/domains/{id}/recipients` (§4.1 of docs/plan/steps/04-smtp-gateway.md, D3).
 */

export const RecipientValidationModeSchema = z.enum([
  'accept_all',
  'allow_list',
  'smtp_callout',
  'ldap',
]);
export const RecipientEnforcementSchema = z.enum(['reject', 'monitor']);

export const SetRecipientValidationSchema = z
  .strictObject({
    mode: RecipientValidationModeSchema.describe(
      '`accept_all` or `allow_list`; `smtp_callout` and `ldap` are not implemented (`422`)',
    ),
    enforcement: RecipientEnforcementSchema.optional().describe(
      'allow_list only (required there): `reject` refuses unknown recipients with 550 5.1.1; ' +
        '`monitor` accepts them and only counts would-be rejections',
    ),
  })
  .superRefine((value, ctx) => {
    if (value.mode === 'allow_list' && value.enforcement === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['enforcement'],
        message: 'is required for allow_list',
      });
    }
    if (value.mode === 'accept_all' && value.enforcement !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['enforcement'],
        message: 'is only allowed for allow_list',
      });
    }
  });
export type SetRecipientValidationInput = z.output<typeof SetRecipientValidationSchema>;

/** One local part, normalized (NFC, lower case) and checked (D3). */
const LocalPartSchema = z
  .string()
  .max(256)
  .transform((value, ctx) => {
    try {
      return normalizeLocalPart(value);
    } catch (err) {
      if (!(err instanceof LocalPartError)) throw err;
      ctx.addIssue({ code: 'custom', message: err.message });
      return z.NEVER;
    }
  });

export const MAX_RECIPIENTS_PER_REQUEST = 1000;

export const RecipientsBodySchema = z.strictObject({
  localParts: z
    .array(LocalPartSchema)
    .min(1)
    .max(MAX_RECIPIENTS_PER_REQUEST)
    .describe(
      'Local parts (the part before "@"), 1–64 bytes each; stored NFC-normalized and lower-cased. ' +
        'Duplicates in the request count once.',
    ),
});
export type RecipientsBody = z.output<typeof RecipientsBodySchema>;

export const ListRecipientsQuerySchema = PageQuerySchema.extend({
  q: LocalPartSchema.optional().describe('Prefix of the local part (case-insensitive)'),
}).strict();
export type ListRecipientsQuery = z.output<typeof ListRecipientsQuerySchema>;

// ---- Responses ---------------------------------------------------------------------------

export const RecipientValidationSchema = z.object({
  domainId: z.uuid(),
  mode: RecipientValidationModeSchema,
  enforcement: RecipientEnforcementSchema,
  implemented: z
    .boolean()
    .describe('False for modes the mail path does not implement yet (they accept everyone)'),
  addressCount: z.number().int().describe('Local parts on the allow-list'),
});
export type RecipientValidationView = z.output<typeof RecipientValidationSchema>;

export const RecipientSchema = z.object({
  localPart: z.string(),
  createdAt: z.iso.datetime(),
});
export type RecipientView = z.output<typeof RecipientSchema>;

export const RecipientPageSchema = z.object({
  data: z.array(RecipientSchema),
  nextCursor: z.string().nullable(),
});

export const AddRecipientsResultSchema = z.object({
  added: z.number().int(),
  existing: z.number().int().describe('Already on the list (nothing changed for them)'),
});
export type AddRecipientsResult = z.output<typeof AddRecipientsResultSchema>;

export const RemoveRecipientsResultSchema = z.object({
  removed: z.number().int(),
});
export type RemoveRecipientsResult = z.output<typeof RemoveRecipientsResultSchema>;
