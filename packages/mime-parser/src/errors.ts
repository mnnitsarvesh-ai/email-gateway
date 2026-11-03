/**
 * Internal control flow and error classification. Errors are classified by class or `code`,
 * never by their message text (design M4); messages are never logged or returned.
 */

/** Wraps an error thrown by the sink, a stored part's `readRange` or the input stream. */
export class InfrastructureFailure extends Error {
  override readonly name = 'InfrastructureFailure';
  constructor(readonly error: unknown) {
    super('infrastructure failure');
  }
}

/** Unwinds the parse after a structural limit (or a parser error) was recorded. */
export class ParseStop extends Error {
  override readonly name = 'ParseStop';
}

/** Unwinds the parse after the wall-clock signal fired. */
export class ParseTimeout extends Error {
  override readonly name = 'ParseTimeout';
}

/** mailsplit's `EMAXLEN` (maxHeadSize or maxChildNodes exceeded). */
export function isMailsplitLimitError(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'EMAXLEN'
  );
}
