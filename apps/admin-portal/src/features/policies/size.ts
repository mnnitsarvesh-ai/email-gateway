import type { ApiError } from '@/lib/api/errors';

/**
 * Request size of a policy definition (design B16, §14.8). The api accepts JSON bodies up to the
 * DSL's document limit (`catalog.limits.documentBytes`, 256 KiB) plus the request wrapper on
 * every route that carries a definition, so the limit the builder shows is the one that applies:
 * a document above it is refused by the server's validation (`policy_definition_invalid`,
 * `limit_exceeded`), and a body above the route's limit with `413 payload_too_large`.
 */
export const TOO_LARGE_MESSAGE =
  'This policy is larger than the policy document limit; split it into several policies.';

export function formatSize(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
}

/** The document is above the catalogue's document limit (warn before sending). */
export const exceedsDocumentLimit = (documentBytes: number, limit: number | undefined): boolean =>
  limit !== undefined && documentBytes > limit;

/** The `<size> of <limit>` text of a document. */
export function sizeAgainstLimit(documentBytes: number, limit: number | undefined): string {
  return limit === undefined
    ? formatSize(documentBytes)
    : `${formatSize(documentBytes)} of ${formatSize(limit)}`;
}

/** Whether an error of a save, validation, test or dry-run is the api's request size limit. */
export function isTooLarge(error: ApiError | null | undefined): boolean {
  return error?.status === 413;
}
