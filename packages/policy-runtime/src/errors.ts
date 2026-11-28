/**
 * Reads echo-checked by the policy runtime (step 5.2 §6); the `read` label of
 * `policy_inconsistent_reads_total` (policy-engine) and of the mailbox-worker's detect-evaluation
 * series. Moved from `apps/policy-engine` (step API-4 A2).
 */
export type PolicyRead =
  | 'message'
  | 'message_update'
  | 'recipients'
  | 'scan'
  | 'parse'
  | 'finals'
  | 'auth'
  | 'bec'
  | 'dlp'
  | 'risk'
  | 'attachments'
  | 'attachment_results'
  | 'urls'
  | 'url_results'
  | 'url_rewrite'
  | 'settings'
  | 'policies'
  | 'versions'
  | 'departments'
  | 'members'
  | 'users'
  | 'lifecycle'
  | 'parse_structure'
  | 'message_urls'
  | 'url_settings'
  | 'ato_settings'
  | 'ato_accounts';

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
