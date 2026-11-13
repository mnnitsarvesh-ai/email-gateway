import {
  assertMetadataOnly,
  ContentGuardError,
  type ContentGuardCode,
} from '@email-gateway/common/dist/messaging/content-guard';

/** Largest serialized envelope (UTF-8 bytes) a webhook carries (W2, §4.2). */
export const WEBHOOK_MAX_PAYLOAD_BYTES = 16_384;
/** Longest string value of an envelope (`assertMetadataOnly` option). */
export const WEBHOOK_MAX_STRING_LENGTH = 1024;

/**
 * Keys (case-insensitive) that never appear in a webhook envelope, whatever their value (W2):
 * message content, raw headers, storage keys, URLs, addresses, file names and secrets.
 * `recipients` is refused only when it carries a string or a list of strings (delivery counts
 * per outcome are an object of numbers).
 */
export const WEBHOOK_DENIED_KEYS: readonly string[] = Object.freeze([
  'subject',
  'body',
  'html',
  'text',
  'content',
  'headers',
  'rawHeaders',
  'eml',
  'emlS3Key',
  's3Key',
  'objectKey',
  'key',
  'url',
  'urls',
  'address',
  'addresses',
  'envelopeFrom',
  'headerFrom',
  'recipients',
  'filename',
  'secret',
  'token',
  'password',
]);
const DENIED = new Set(WEBHOOK_DENIED_KEYS.map((key) => key.toLowerCase()));

export type WebhookPayloadErrorCode =
  | ContentGuardCode
  | 'forbidden_key'
  | 'address_value'
  | 's3_key_value'
  | 'url_value'
  | 'too_large'
  | 'not_serializable';

/**
 * A webhook envelope that would carry content (a programming error: the fanout dead-letters the
 * source event with `webhook_payload_unsafe`). `path` is a JSON path of the node; never a value.
 */
export class WebhookPayloadError extends Error {
  override readonly name = 'WebhookPayloadError';
  constructor(
    readonly code: WebhookPayloadErrorCode,
    readonly path: string,
  ) {
    super(`webhook payload guard: ${code} at ${path}`);
  }
}

/** Only `internetMessageId` (the documented header, §5.1) may contain an `@`. */
const ADDRESS_EXEMPT_KEYS = new Set(['internetmessageid']);
/** `local@domain.tld` anywhere in a string value. */
const ADDRESS_VALUE = /[^\s@<>"',;:]+@[^\s@<>"',;:]+\.[^\s@<>"',;:]+/;
/** An organization-prefixed object key (`org/<id>/…`, ADR-0014). */
const S3_KEY_VALUE = /(?:^|[^a-z0-9])org\/[1-9][0-9]{0,19}\//i;
/** Any absolute URL (`scheme://`). */
const URL_VALUE = /[a-z][a-z0-9+.-]*:\/\//i;

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const childPath = (path: string, key: string | number): string =>
  typeof key === 'number'
    ? `${path}[${key}]`
    : IDENTIFIER.test(key)
      ? `${path}.${key}`
      : `${path}[${JSON.stringify(key)}]`;

const isStringList = (value: unknown): boolean =>
  typeof value === 'string' ||
  (Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'string'));

function checkValue(value: string, key: string | null, path: string): void {
  if (URL_VALUE.test(value)) throw new WebhookPayloadError('url_value', path);
  if (S3_KEY_VALUE.test(value)) throw new WebhookPayloadError('s3_key_value', path);
  if (!(key !== null && ADDRESS_EXEMPT_KEYS.has(key.toLowerCase())) && ADDRESS_VALUE.test(value)) {
    throw new WebhookPayloadError('address_value', path);
  }
}

function walk(node: unknown, key: string | null, path: string): void {
  if (typeof node === 'string') {
    checkValue(node, key, path);
    return;
  }
  if (typeof node !== 'object' || node === null) return;
  if (Array.isArray(node)) {
    node.forEach((item, index) => walk(item, key, childPath(path, index)));
    return;
  }
  for (const [childKey, child] of Object.entries(node as Record<string, unknown>)) {
    const keyPath = childPath(path, childKey);
    const lower = childKey.toLowerCase();
    if (DENIED.has(lower) && (lower !== 'recipients' || isStringList(child))) {
      throw new WebhookPayloadError('forbidden_key', keyPath);
    }
    walk(child, childKey, keyPath);
  }
}

/**
 * The webhook payload guard (W2, W4; §2.0 invariant 1). Throws `WebhookPayloadError` unless the
 * envelope:
 *   1. passes the broker content guard `assertMetadataOnly` with strings ≤ 1024 characters (no
 *      binary, MIME content, base64 blobs, forbidden content fields, excessive nesting);
 *   2. has none of the denied keys (`WEBHOOK_DENIED_KEYS`, case-insensitive, at any depth);
 *   3. has no string value that looks like an address (`local@domain`; only
 *      `internetMessageId` is exempt), an organization-prefixed S3 key or an absolute URL;
 *   4. serializes to at most `WEBHOOK_MAX_PAYLOAD_BYTES` UTF-8 bytes.
 */
export function assertWebhookPayloadSafe(envelope: unknown): void {
  try {
    assertMetadataOnly(envelope, { maxStringLength: WEBHOOK_MAX_STRING_LENGTH });
  } catch (error) {
    if (error instanceof ContentGuardError) throw new WebhookPayloadError(error.code, error.path);
    throw error;
  }
  walk(envelope, null, '$');
  let json: string | undefined;
  try {
    json = JSON.stringify(envelope);
  } catch {
    throw new WebhookPayloadError('not_serializable', '$');
  }
  if (json === undefined) throw new WebhookPayloadError('not_serializable', '$');
  if (Buffer.byteLength(json, 'utf8') > WEBHOOK_MAX_PAYLOAD_BYTES) {
    throw new WebhookPayloadError('too_large', '$');
  }
}
