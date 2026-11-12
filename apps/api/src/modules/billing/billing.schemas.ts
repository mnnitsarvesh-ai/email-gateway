import { z } from 'zod';
import { BILLING_MONTH_PATTERN } from './domain/billing-month';

/** `/billing/*` (step 6.1 §3.3, D12). */

/** `GET /billing/plan` takes no parameters (strict: unknown ones are `400`). */
export const BillingPlanQuerySchema = z.strictObject({});

export const BillingUsageQuerySchema = z.strictObject({
  month: z
    .string()
    .regex(BILLING_MONTH_PATTERN, 'must be YYYY-MM')
    .optional()
    .describe('Calendar month in UTC (`YYYY-MM`), default the current month'),
});
export type BillingUsageQuery = z.output<typeof BillingUsageQuerySchema>;

const SOURCE = z.enum(['plan', 'override']);

/** Fixed: the platform records no prices, currencies, invoices, payment methods or subscriptions. */
export const BILLING_PRICING_NOTE =
  'No pricing or invoicing data exists on this platform: plans define entitlements only. ' +
  'Prices, invoices, payment methods and subscriptions are not recorded and are not invented.';

export const BillingPlanSchema = z.object({
  organizationId: z.uuid(),
  plan: z.object({ code: z.string(), name: z.string(), description: z.string().nullable() }),
  limits: z.array(
    z.object({
      key: z.string(),
      value: z.number().int(),
      source: SOURCE.describe('`plan` default or a platform `override`'),
    }),
  ),
  features: z.array(z.object({ key: z.string(), enabled: z.boolean(), source: SOURCE })),
  pricing: z.null().describe('Always null: no pricing data exists'),
  note: z.string(),
});
export type BillingPlan = z.output<typeof BillingPlanSchema>;

export const BillingUsageSchema = z.object({
  organizationId: z.uuid(),
  month: z.string().describe('`YYYY-MM` (UTC)'),
  from: z.iso.datetime().describe('Start of the month (UTC)'),
  to: z.iso.datetime().describe('Exclusive end counted: the month end, or the computation time'),
  messages: z
    .object({
      total: z.number().int().nonnegative(),
      inbound: z.number().int().nonnegative(),
      outbound: z.number().int().nonnegative(),
      internal: z.number().int().nonnegative(),
    })
    .describe('Messages received in [from, to) by direction'),
  users: z.number().int().nonnegative().describe('Current non-deleted users'),
  domains: z.number().int().nonnegative().describe('Current non-deleted domains'),
  apiKeys: z.number().int().nonnegative().describe('Current active API keys'),
  limits: z.array(
    z.object({
      key: z.string(),
      value: z.number().int(),
      source: SOURCE,
      used: z
        .number()
        .int()
        .nullable()
        .describe('Current use for max_users and max_domains; null for rate/size limits'),
    }),
  ),
  generatedAt: z.iso.datetime(),
});
export type BillingUsage = z.output<typeof BillingUsageSchema>;

export const BILLING_PLAN_EXAMPLE: BillingPlan = {
  organizationId: '01930c2e-7d1a-7000-8000-000000000001',
  plan: {
    code: 'standard',
    name: 'Standard',
    description: 'Inbound and outbound filtering for small and medium organizations',
  },
  limits: [
    { key: 'max_domains', value: 10, source: 'plan' },
    { key: 'max_users', value: 500, source: 'override' },
    { key: 'messages_per_day', value: 100_000, source: 'plan' },
  ],
  features: [
    { key: 'inbound_filtering', enabled: true, source: 'plan' },
    { key: 'dlp', enabled: false, source: 'plan' },
  ],
  pricing: null,
  note: BILLING_PRICING_NOTE,
};

export const BILLING_USAGE_EXAMPLE: BillingUsage = {
  organizationId: '01930c2e-7d1a-7000-8000-000000000001',
  month: '2026-11',
  from: '2026-11-01T00:00:00.000Z',
  to: '2026-11-12T09:30:00.000Z',
  messages: { total: 18_402, inbound: 14_210, outbound: 4_100, internal: 92 },
  users: 42,
  domains: 3,
  apiKeys: 2,
  limits: [
    { key: 'max_domains', value: 10, source: 'plan', used: 3 },
    { key: 'max_users', value: 250, source: 'plan', used: 42 },
    { key: 'messages_per_day', value: 100_000, source: 'plan', used: null },
  ],
  generatedAt: '2026-11-12T09:30:00.000Z',
};
