import { type Logger, ServiceUnavailableException } from '@nestjs/common';

/**
 * Runs a key-value store call for an authentication decision. When the store is unavailable the
 * request fails closed with `503` (D6, D9): a check is never skipped.
 */
export async function failClosed<T>(
  logger: Logger,
  operation: string,
  fn: () => Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    logger.error({ message: 'Key-value store unavailable during authentication', operation, err });
    throw new ServiceUnavailableException('Service temporarily unavailable');
  }
}
