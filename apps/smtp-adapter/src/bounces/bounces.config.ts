import { z } from 'zod';

/**
 * Configuration of the bounce-notice handler (step 2.2 D13; `.env.example` section "SMTP
 * gateway"). The app merges this raw shape into its config schema.
 */
export const bouncesConfigShape = {
  LMTP_BOUNCE_PORT: z.coerce.number().int().min(1).max(65535).default(10052),
  /** Postmaster copies carry headers only; the cap makes buffering them safe. */
  BOUNCE_MAX_MESSAGE_BYTES: z.coerce.number().int().min(1024).max(52_428_800).default(2_097_152),
  SUPPRESSION_HARD_BOUNCE_DAYS: z.coerce.number().int().min(1).max(3650).default(180),
  /** Domain of the bounce-notice recipient `bounce-notices@<domain>` (postfix-outbound). */
  POSTFIX_BOUNCE_DOMAIN: z
    .string()
    .trim()
    .toLowerCase()
    .regex(
      /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/,
    )
    .default('bounces.gateway.internal'),
};

export type BouncesConfig = z.infer<z.ZodObject<typeof bouncesConfigShape>>;
