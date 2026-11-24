import { CORRELATION_ID_PATTERN } from '../assistant.constants';

/** The execution's correlation id `<base>.<seq>` within `^[A-Za-z0-9._:-]{8,128}$`. */
export function executionCorrelationId(base: string, seq: number): string {
  const suffix = `.${seq}`;
  const safe = CORRELATION_ID_PATTERN.test(base) ? base : 'assistant';
  const id = `${safe.slice(0, 128 - suffix.length)}${suffix}`;
  return id.length >= 8 ? id : `assistant${suffix}`;
}

/**
 * The correlation id of the n-th source read of a native report execution (step AI-R D2 step 5):
 * `<base>.<seq>.<n>`, within the same pattern (the base is shortened, the tail kept).
 */
export function sourceCorrelationId(base: string, seq: number, n: number): string {
  const tail = `.${seq}.${n}`;
  const safe = CORRELATION_ID_PATTERN.test(base) ? base : 'assistant';
  const id = `${safe.slice(0, 128 - tail.length)}${tail}`;
  return id.length >= 8 ? id : `assistant${tail}`;
}
