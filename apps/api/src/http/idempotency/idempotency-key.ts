import { createHash } from 'node:crypto';
import { HttpStatus, Injectable, type PipeTransform } from '@nestjs/common';
import { ApiHeader } from '@nestjs/swagger';
import type { Principal } from '../../auth-contracts/principal';
import { CodedHttpException } from '../coded-exception';

/**
 * The `Idempotency-Key` request header (step 3.3 L11), reusable by every write route that needs
 * exactly-once semantics (6.1): validation, the request fingerprint, the principal key and the
 * OpenAPI header documentation.
 */

/** Request header (Express lower-cases incoming header names). */
export const IDEMPOTENCY_KEY_HEADER = 'idempotency-key';
/** Response header set to `true` when the stored response of an earlier request is replayed. */
export const IDEMPOTENCY_REPLAYED_HEADER = 'Idempotency-Replayed';
/** How long a stored response answers a repeated key (a constant, L11 §5). */
export const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;

export const IDEMPOTENCY_KEY_MAX_LENGTH = 128;
export const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9._:-]+$/;

/** Stable error codes (`code` of the coded error body). */
export const IDEMPOTENCY_KEY_REQUIRED = 'idempotency_key_required';
export const IDEMPOTENCY_KEY_INVALID = 'idempotency_key_invalid';
export const IDEMPOTENCY_KEY_REUSED = 'idempotency_key_reused';

export const idempotencyKeyRequired = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    IDEMPOTENCY_KEY_REQUIRED,
    'The Idempotency-Key header is required',
  );

export const idempotencyKeyInvalid = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.BAD_REQUEST,
    IDEMPOTENCY_KEY_INVALID,
    `The Idempotency-Key header must be 1-${IDEMPOTENCY_KEY_MAX_LENGTH} characters of [A-Za-z0-9._:-]`,
  );

export const idempotencyKeyReused = (): CodedHttpException =>
  new CodedHttpException(
    HttpStatus.UNPROCESSABLE_ENTITY,
    IDEMPOTENCY_KEY_REUSED,
    'The Idempotency-Key was already used for a different request',
  );

/**
 * The validated header value. Missing (or empty) → `400 idempotency_key_required`; repeated,
 * longer than 128 characters or outside `[A-Za-z0-9._:-]` → `400 idempotency_key_invalid`. The
 * value is never echoed.
 */
export function parseIdempotencyKey(raw: unknown): string {
  if (raw === undefined || raw === null || raw === '') throw idempotencyKeyRequired();
  if (
    typeof raw !== 'string' ||
    raw.length > IDEMPOTENCY_KEY_MAX_LENGTH ||
    !IDEMPOTENCY_KEY_PATTERN.test(raw)
  ) {
    throw idempotencyKeyInvalid();
  }
  return raw;
}

/** `@Headers(IDEMPOTENCY_KEY_HEADER, IdempotencyKeyPipe)`: validates the header as a pipe. */
@Injectable()
export class IdempotencyKeyPipe implements PipeTransform<unknown, string> {
  transform(value: unknown): string {
    return parseIdempotencyKey(value);
  }
}

/** JSON with object keys sorted at every depth (arrays keep their order). */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === 'object' && !(value instanceof Date)) {
    return Object.fromEntries(
      Object.keys(value as Record<string, unknown>)
        .sort()
        .filter((key) => (value as Record<string, unknown>)[key] !== undefined)
        .map((key) => [key, sortKeys((value as Record<string, unknown>)[key])]),
    );
  }
  return value;
}

/** Hex SHA-256 of the canonical JSON `{ operation, resourceId, body }` (L11). */
export function requestFingerprint(request: {
  operation: string;
  resourceId: string;
  body: unknown;
}): string {
  return createHash('sha256')
    .update(
      canonicalJson({
        operation: request.operation,
        resourceId: request.resourceId,
        body: request.body,
      }),
      'utf8',
    )
    .digest('hex');
}

/** Hex SHA-256 of the key, for audit metadata and logs (the key itself is never logged). */
export function idempotencyKeyHash(key: string): string {
  return createHash('sha256').update(key, 'utf8').digest('hex');
}

/** `user:<publicId>` | `api_key:<publicId>`: who may replay a stored response. */
export function principalKey(principal: Principal): string {
  return principal.kind === 'api_key'
    ? `api_key:${principal.apiKeyPublicId}`
    : `user:${principal.userPublicId}`;
}

/** Documents the required `Idempotency-Key` header of an operation. */
export const ApiIdempotencyKey = (): MethodDecorator =>
  ApiHeader({
    name: 'Idempotency-Key',
    required: true,
    description:
      `Client-chosen key, 1-${IDEMPOTENCY_KEY_MAX_LENGTH} characters of \`[A-Za-z0-9._:-]\`, ` +
      'unique per organization (case-sensitive). The first successful (2xx) response is stored ' +
      'for 24 hours: repeating the same request with the same key returns it again with the ' +
      'response header `Idempotency-Replayed: true` and changes nothing. The same key with a ' +
      'different request (body, path, operation or caller) is `422 idempotency_key_reused`. ' +
      'Errors (4xx) are not stored: fix the request and retry with the same key.',
    schema: {
      type: 'string',
      minLength: 1,
      maxLength: IDEMPOTENCY_KEY_MAX_LENGTH,
      pattern: IDEMPOTENCY_KEY_PATTERN.source,
    },
  });
