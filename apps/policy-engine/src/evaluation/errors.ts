import type { PolicyRead } from '../metrics/policy-metrics';

/**
 * A writer read returned rows that do not belong to the request (the Prisma wrong-read defect,
 * step 4.2 §6; step 5.2 §6), or an engine write did not affect exactly the expected row.
 * Retryable: the whole evaluation transaction rolls back and the event is redelivered; nothing is
 * decided from a wrong row. Carries the read name and a fixed check name only (no data).
 */
export class InconsistentPolicyReadError extends Error {
  override readonly name = 'InconsistentPolicyReadError';

  constructor(
    readonly read: PolicyRead,
    readonly check: string,
  ) {
    super(`inconsistent policy ${read} read: ${check}`);
  }
}

/** Reports a failed echo check (metric) before throwing. */
export type InconsistencySink = (read: PolicyRead) => void;

/** Throws `InconsistentPolicyReadError` after counting it. */
export function wrongRead(sink: InconsistencySink, read: PolicyRead, check: string): never {
  sink(read);
  throw new InconsistentPolicyReadError(read, check);
}

/** Dead-letter code of a malformed round (`NonRetryableError`, P13). */
export const POLICY_INPUT_INVALID = 'policy_input_invalid';
