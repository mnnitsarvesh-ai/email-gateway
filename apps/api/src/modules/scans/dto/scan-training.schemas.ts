import { z } from 'zod';

/**
 * Body and response of `POST /platform/organizations/{organizationId}/messages/{messageId}/
 * scan-training` (step 4.1 S13).
 */

export const SCAN_TRAINING_OPERATIONS = [
  'learn_spam',
  'learn_ham',
  'fuzzy_add',
  'fuzzy_delete',
] as const;
export type ScanTrainingOperation = (typeof SCAN_TRAINING_OPERATIONS)[number];

export const FUZZY_FLAGS = ['spam', 'phishing'] as const;
export type FuzzyFlagName = (typeof FUZZY_FLAGS)[number];

const isFuzzy = (operation: ScanTrainingOperation) =>
  operation === 'fuzzy_add' || operation === 'fuzzy_delete';

export const ScanTrainingBodySchema = z
  .strictObject({
    operation: z.enum(SCAN_TRAINING_OPERATIONS),
    fuzzyFlag: z
      .enum(FUZZY_FLAGS)
      .optional()
      .describe('Required for fuzzy_add / fuzzy_delete (spam = flag 11, phishing = flag 12)'),
    reason: z
      .string()
      .trim()
      .min(1)
      .max(512)
      .describe('Why the operator trains (audited; never sent to Rspamd)'),
  })
  .superRefine((body, ctx) => {
    if (isFuzzy(body.operation) && body.fuzzyFlag === undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['fuzzyFlag'],
        message: 'Required for fuzzy_add and fuzzy_delete',
      });
    }
    if (!isFuzzy(body.operation) && body.fuzzyFlag !== undefined) {
      ctx.addIssue({
        code: 'custom',
        path: ['fuzzyFlag'],
        message: 'Only allowed for fuzzy_add and fuzzy_delete',
      });
    }
  });
export type ScanTrainingBody = z.output<typeof ScanTrainingBodySchema>;

export const SCAN_TRAINING_RESULTS = ['learned', 'already_learned', 'added', 'deleted'] as const;
export type ScanTrainingResult = (typeof SCAN_TRAINING_RESULTS)[number];

export const ScanTrainingResponseSchema = z.object({
  operation: z.enum(SCAN_TRAINING_OPERATIONS),
  result: z.enum(SCAN_TRAINING_RESULTS),
  engineVersion: z.string().describe('Rspamd version (`unknown` if it could not be read)'),
});
export type ScanTrainingResponse = z.output<typeof ScanTrainingResponseSchema>;
