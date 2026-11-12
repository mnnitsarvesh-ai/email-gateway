import { HttpStatus } from '@nestjs/common';
import { CodedHttpException } from '../../../http/coded-exception';

/** `503 report_timeout` (step 6.1 D12, §3.2): the report query hit `MAX_EXECUTION_TIME`. */
export const REPORT_TIMEOUT = 'report_timeout';

export const reportTimeout = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.SERVICE_UNAVAILABLE,
    REPORT_TIMEOUT,
    'The report query took too long; narrow the range or retry later',
  );

/** MySQL `ER_QUERY_TIMEOUT`: "Query execution was interrupted, maximum statement execution time exceeded". */
export const MYSQL_QUERY_TIMEOUT_ERRNO = '3024';

/**
 * True for a statement interrupted by `MAX_EXECUTION_TIME` (MySQL error 3024). Prisma reports raw
 * query failures as `PrismaClientKnownRequestError` P2010 with the server code in `meta.code`
 * and the server message in `meta.message`; the message text is checked as a fallback.
 */
export function isQueryTimeout(err: unknown): boolean {
  if (err === null || typeof err !== 'object') return false;
  const e = err as { meta?: { code?: unknown; message?: unknown }; message?: unknown };
  const text = (value: unknown): string =>
    typeof value === 'string' || typeof value === 'number' ? String(value) : '';
  if (text(e.meta?.code) === MYSQL_QUERY_TIMEOUT_ERRNO) return true;
  return /maximum statement execution time exceeded|\b3024\b/i.test(
    `${text(e.meta?.message)} ${text(e.message)}`,
  );
}

/** Thrown by the report repositories on a 3024; ReportExecutor maps it to `report_timeout`. */
export class ReportQueryTimeoutError extends Error {
  override readonly name = 'ReportQueryTimeoutError';
  constructor(readonly query: string) {
    super(`report query ${query} exceeded MAX_EXECUTION_TIME`);
  }
}
