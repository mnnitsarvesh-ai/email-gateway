import type { SuppressionReason } from '@email-gateway/database';
import { z } from 'zod';
import { defineListQuery } from '../../http/listing/list-query';

/**
 * Request and response shapes of the recipient suppression list (step 6.1 WP2, §3.3): the
 * organization's `delivery_suppressions`, which the smtp-adapter enforces on outbound mail (an
 * address is suppressed while `expiresAt` is null or in the future; step 2.2 D11).
 */

export const SUPPRESSIONS_RESOURCE = 'recipient_suppressions';

export const SUPPRESSION_REASONS = [
  'hard_bounce',
  'complaint',
  'manual',
  'unsubscribe',
] as const satisfies readonly SuppressionReason[];

/** The reasons a caller may create (the others come from bounces and complaints). */
export const CREATABLE_REASONS = [
  'manual',
  'unsubscribe',
] as const satisfies readonly SuppressionReason[];

/** `delivery_suppressions.source` of rows created through the API. */
export const API_SOURCE = 'api';

/** Longest expiry of a created suppression (§3.3). */
export const MAX_EXPIRY_DAYS = 3650;

export const SuppressionListQuerySchema = defineListQuery({
  filters: {
    reason: { type: 'enum', values: SUPPRESSION_REASONS, maxValues: 4 },
    address: { type: 'email', maxLength: 320 },
    active: { type: 'bool' },
  },
  sorts: ['-id'],
  defaultSort: '-id',
});
export type SuppressionListQuery = z.output<typeof SuppressionListQuerySchema>;

export const SUPPRESSION_LIST_PARAMETERS: Record<string, string> = {
  reason: '`hard_bounce`, `complaint`, `manual`, `unsubscribe`; comma list',
  address: 'Exact address (compared lower-cased; the unique key)',
  active: '`true`: suppressing now (no expiry or a future one); `false`: expired',
  limit: 'Page size, 1-100 (default 25). A page may hold fewer rows (see the scan budget).',
  cursor: '`nextCursor` of the previous page',
  sort: '`-id` (the only order: newest first)',
};

/** `{suppressionId}`: the decimal row id (log-like rows, contracts §10). */
export const SuppressionIdSchema = z
  .string()
  .regex(/^[1-9]\d{0,19}$/, 'must be a decimal id')
  .transform((value) => BigInt(value))
  .refine((value) => value <= 18_446_744_073_709_551_615n, 'must be a decimal id');

const address = z
  .string()
  .trim()
  .min(3)
  .max(320)
  .regex(/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'must be an email address')
  .transform((value) => value.toLowerCase());

export const CreateSuppressionBodySchema = z.strictObject({
  address: address.describe('Recipient address (trimmed and lower-cased)'),
  reason: z.enum(CREATABLE_REASONS).default('manual'),
  expiresAt: z.iso
    .datetime({ offset: true })
    .optional()
    .describe(
      `When the suppression stops applying (future, at most ${MAX_EXPIRY_DAYS} days ahead); none = permanent`,
    ),
});
export type CreateSuppressionBody = z.output<typeof CreateSuppressionBodySchema>;

export const SuppressionSchema = z.object({
  id: z.string().describe('Decimal id'),
  address: z.string(),
  reason: z.enum(SUPPRESSION_REASONS),
  source: z
    .string()
    .nullable()
    .describe('`api` for rows created here; the bounce or complaint source otherwise'),
  expiresAt: z.iso.datetime().nullable(),
  active: z.boolean().describe('True while outbound mail to the address is suppressed'),
  createdAt: z.iso.datetime(),
  createdBy: z.uuid().nullable().describe('Public id of the user who created it, or null'),
});
export type SuppressionView = z.output<typeof SuppressionSchema>;

export const SuppressionPageSchema = z.object({
  data: z.array(SuppressionSchema),
  nextCursor: z.string().nullable(),
});
export type SuppressionPage = z.output<typeof SuppressionPageSchema>;

const example = {
  id: '4711',
  address: 'former.customer@example.com',
  reason: 'manual',
  source: 'api',
  expiresAt: null,
  active: true,
  createdAt: '2026-11-12T10:00:00.000Z',
  createdBy: '0192e111-2a3b-7c4d-8e5f-6a7b8c9d0e1f',
};

export const SUPPRESSION_EXAMPLES = {
  /** Request body of `POST /recipients/suppressions` (step 6.1 D14: request examples). */
  create: { address: 'former.customer@example.org', reason: 'unsubscribe' },
  item: example,
  page: {
    data: [
      example,
      {
        id: '4702',
        address: 'bounced@example.org',
        reason: 'hard_bounce',
        source: 'bounce',
        expiresAt: '2027-02-10T00:00:00.000Z',
        active: true,
        createdAt: '2026-11-10T07:12:44.120Z',
        createdBy: null,
      },
    ],
    nextCursor: null,
  },
} as const;
