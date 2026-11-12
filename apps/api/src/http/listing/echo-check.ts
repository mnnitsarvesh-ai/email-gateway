import { HttpStatus, Logger } from '@nestjs/common';
import { CodedHttpException } from '../coded-exception';

export const INCONSISTENT_READ = 'inconsistent_read';

/**
 * A read returned a row that does not echo what was asked for (organization or key; the Prisma
 * wrong-read defect of step 4.2 §6, 10-attachment-scanning.md §6). Rendered as
 * `503 inconsistent_read` (retry); the row is never served. Step 6.1 D15.
 */
export class InconsistentReadError extends CodedHttpException {
  override readonly name = 'InconsistentReadError';
  constructor(readonly read: string) {
    super(
      HttpStatus.SERVICE_UNAVAILABLE,
      INCONSISTENT_READ,
      'The database returned an inconsistent read; retry the request',
    );
  }
}

const logger = new Logger('EchoCheck');

type Comparable = bigint | string | number | boolean | Date | null;

function same(a: unknown, b: Comparable): boolean {
  if (b instanceof Date) return a instanceof Date && a.getTime() === b.getTime();
  if (typeof b === 'bigint')
    return (typeof a === 'bigint' || typeof a === 'number') && BigInt(a) === b;
  return a === b;
}

/**
 * Echo check of D15: every returned row must carry the queried `organizationId` and, for each
 * other given key, the queried value (a single value or the allowed set). Throws
 * InconsistentReadError (logged with the read name and field, never values) on a mismatch.
 */
export function assertEcho<R extends { organizationId: bigint }>(
  read: string,
  rows: readonly R[],
  expected: { organizationId: bigint } & {
    [K in keyof R]?: Comparable | readonly Comparable[];
  },
): void {
  for (const row of rows) {
    for (const [field, want] of Object.entries(expected) as [keyof R & string, unknown][]) {
      if (want === undefined) continue;
      const got = row[field];
      const ok = Array.isArray(want)
        ? (want as Comparable[]).some((w) => same(got, w))
        : same(got, want as Comparable);
      if (!ok) {
        logger.warn({ message: 'echo check failed: row not served', read, field });
        throw new InconsistentReadError(read);
      }
    }
  }
}
