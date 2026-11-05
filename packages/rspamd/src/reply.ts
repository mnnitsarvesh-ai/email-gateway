import { z } from 'zod';

/**
 * The `/checkv2` JSON reply of Rspamd 3.12 (verified against rspamd/rspamd:3.12.1, step 4.1
 * §12): `is_skipped`, `score`, `required_score`, `action`, `thresholds`, `symbols` keyed by
 * name (`name`, `score`, `metric_score`, `options`, `description`), `messages`, `milter`
 * (header changes of the milter path), `message-id`, `time_real`, and `passthrough_module` when
 * a pre-filter decided the result (GTUBE: `is_skipped: true`, `passthrough_module: "GTUBE"`,
 * action `reject`). Unknown fields are allowed (permissive), the fields we read are strict.
 */
export const rspamdSymbolSchema = z.looseObject({
  name: z.string().min(1),
  score: z.number().finite(),
  metric_score: z.number().finite().optional(),
  options: z.array(z.string()).optional(),
  description: z.string().optional(),
});
export type RspamdSymbol = z.infer<typeof rspamdSymbolSchema>;

export const rspamdCheckReplySchema = z.looseObject({
  is_skipped: z.boolean().optional(),
  score: z.number().finite(),
  required_score: z.number().finite(),
  action: z.string().min(1).max(64),
  thresholds: z.record(z.string(), z.number()).optional(),
  symbols: z.record(z.string(), rspamdSymbolSchema).optional(),
  messages: z.record(z.string(), z.unknown()).optional(),
  milter: z.unknown().optional(),
  'message-id': z.string().optional(),
  time_real: z.number().optional(),
  passthrough_module: z.string().optional(),
});
export type RspamdCheckReply = z.infer<typeof rspamdCheckReplySchema>;

/** Rspamd action names (Rspamd's own spelling). */
export const RSPAMD_ACTIONS = [
  'no action',
  'greylist',
  'add header',
  'rewrite subject',
  'soft reject',
  'reject',
] as const;

/** Controller `/stat` reply: only the version is read. */
export const rspamdStatReplySchema = z.looseObject({
  version: z.string().min(1).max(64),
});

/** Controller learn/fuzzy success reply. */
export const rspamdSuccessReplySchema = z.looseObject({
  success: z.literal(true),
  hashes: z.array(z.string()).optional(),
});
