/** Metadata key holding the list of `RateLimitOptions` of a route. */
export const RATE_LIMIT_KEY = 'rateLimit:limits';

export interface RateLimitOptions {
  /** Short name of the counter, e.g. `auth-login`. One bucket per endpoint and identifier type. */
  bucket: string;
  /** Requests allowed per window. */
  limit: number;
  windowSeconds: number;
  /** What identifies the caller: client IP, a body field (e.g. the email), or both. */
  by: 'ip' | 'ip+body' | 'body';
  /** Body field for `body` / `ip+body`; compared lower-cased and trimmed, stored as SHA-256. */
  bodyField?: string;
}

export function assertRateLimitOptions(options: RateLimitOptions): void {
  if (!/^[a-z0-9][a-z0-9:_-]{0,63}$/.test(options.bucket)) {
    throw new Error(`Invalid rate-limit bucket name: ${options.bucket}`);
  }
  if (!Number.isSafeInteger(options.limit) || options.limit < 1) {
    throw new Error(`Rate limit ${options.bucket}: limit must be a positive integer`);
  }
  if (!Number.isSafeInteger(options.windowSeconds) || options.windowSeconds < 1) {
    throw new Error(`Rate limit ${options.bucket}: windowSeconds must be a positive integer`);
  }
  if (options.by !== 'ip' && !options.bodyField) {
    throw new Error(`Rate limit ${options.bucket}: by=${options.by} needs bodyField`);
  }
}
