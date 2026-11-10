import { defaultClassify, type FailureClass, NonRetryableError } from '@email-gateway/common';

/**
 * Failure classes of a task (step 4.6 X7, X19). A `TransientTaskError` is an outage (sandbox
 * bucket, backend infrastructure, shutdown) that may pass unchanged: the consumer retries it with
 * the topology's hold policy without consuming an attempt and NO result is published. Codes are
 * bounded tokens (logs, metrics).
 */
export class TransientTaskError extends Error {
  override readonly name = 'TransientTaskError';
  constructor(
    readonly code:
      'storage_unavailable' | 'backend_unavailable' | 'scratch_unavailable' | 'shutdown',
    options?: { cause?: unknown },
  ) {
    super(`transient task failure: ${code}`, options);
  }
}

/** Rejections dead-letter at once (schema, tenant, an unaccepted event). */
export const rejectTask = (code: 'invalid_task' | 'tenant_mismatch'): NonRetryableError =>
  new NonRetryableError(code);

/** The consumer's classifier: transient task errors keep their attempt; the rest as usual. */
export function classifyTaskFailure(error: unknown): FailureClass {
  if (error instanceof TransientTaskError) return 'transient';
  return defaultClassify(error);
}
