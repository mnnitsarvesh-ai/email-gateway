import type { QuarantineRead } from '../metrics/quarantine-metrics';

/**
 * A quarantine read returned rows that do not belong to the request, or a compare-and-set write
 * did not affect exactly the expected rows (the Prisma wrong-read defect, step 4.2 §6; step 5.3
 * §6). Retryable: the transaction rolls back and the work (event, sweep item) is retried. Carries
 * the read name and a fixed check name only (no data).
 */
export class InconsistentQuarantineReadError extends Error {
  override readonly name = 'InconsistentQuarantineReadError';

  constructor(
    readonly read: QuarantineRead,
    readonly check: string,
  ) {
    super(`inconsistent quarantine ${read} read: ${check}`);
  }
}

export type QuarantineInconsistencySink = (read: QuarantineRead) => void;

/** Throws `InconsistentQuarantineReadError` after counting it. */
export function quarantineWrongRead(
  sink: QuarantineInconsistencySink,
  read: QuarantineRead,
  check: string,
): never {
  sink(read);
  throw new InconsistentQuarantineReadError(read, check);
}
