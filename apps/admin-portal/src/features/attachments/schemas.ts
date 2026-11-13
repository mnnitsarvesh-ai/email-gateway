import { z } from 'zod';
import type { RequestBody } from '@/lib/api/types';

export const RESCAN_STATES = ['scanned', 'scan_failed', 'quarantined', 'held_for_review'] as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Rescan request (strict, mirrors `AttachmentRescansController_request_v1`). */
export const rescanSchema = z
  .object({
    windowHours: z.coerce
      .number({ message: 'Enter hours' })
      .int('Enter whole hours')
      .min(1, 'At least 1 hour')
      .max(168, 'At most 168 hours'),
    states: z.array(z.enum(RESCAN_STATES)).min(1, 'Choose at least one state').max(4),
    organizationId: z
      .string()
      .trim()
      .refine((v) => v === '' || UUID.test(v), {
        message: 'Enter an organization ID (UUID) or leave it empty',
      }),
    maxMessages: z
      .string()
      .trim()
      .refine((v) => v === '' || (/^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 50_000), {
        message: '1 to 50,000, or empty',
      }),
    reason: z.string().trim().min(1, 'Enter a reason').max(512),
  })
  .strict();

export function rescanBody(
  values: z.output<typeof rescanSchema>,
  dryRun: boolean,
): RequestBody<'AttachmentRescansController_request_v1'> {
  return {
    windowHours: values.windowHours,
    states: values.states,
    ...(values.organizationId ? { organizationId: values.organizationId.toLowerCase() } : {}),
    ...(values.maxMessages ? { maxMessages: Number(values.maxMessages) } : {}),
    reason: values.reason,
    ...(dryRun ? { dryRun: true } : {}),
  };
}
