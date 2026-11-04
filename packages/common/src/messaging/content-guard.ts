/**
 * The content guard (step 3.2 Q7, §2.0.4): messages on the broker carry ids, S3 keys, hashes,
 * codes and counts only. `assertMetadataOnly` walks a value (an event envelope) and refuses
 * anything that looks like message content with a `ContentGuardError(code, path)`. The path is a
 * JSON path of the offending node (`$.payload.recipients[3]`), never a value.
 */
export type ContentGuardCode =
  | 'binary_value'
  | 'oversized_string'
  | 'mime_content'
  | 'base64_blob'
  | 'forbidden_field'
  | 'too_deep'
  | 'message_too_large';

export const CONTENT_GUARD_CODES: readonly ContentGuardCode[] = [
  'binary_value',
  'oversized_string',
  'mime_content',
  'base64_blob',
  'forbidden_field',
  'too_deep',
  'message_too_large',
];

export class ContentGuardError extends Error {
  override readonly name = 'ContentGuardError';
  constructor(
    readonly code: ContentGuardCode,
    readonly path: string,
  ) {
    super(`content guard: ${code} at ${path}`);
  }
}

export interface ContentGuardOptions {
  /** Longest allowed string (default 2 048 characters). */
  maxStringLength?: number;
}

export const DEFAULT_MAX_STRING_LENGTH = 2048;
const MAX_DEPTH = 16;
const MAX_NODES = 10_000;
const BASE64_RUN = 512;

/** A MIME header at the start of the string or after a line break. */
const MIME_HEADER =
  /(?:^|\r?\n)[ \t]*(?:content-(?:type|transfer-encoding|disposition)|mime-version)[ \t]*:/i;
/** A run of ≥ 512 base64 / base64url characters, line breaks allowed inside the run. */
const BASE64_BLOB = new RegExp(`(?:[A-Za-z0-9+/=_-][\\r\\n]*){${BASE64_RUN},}`);

/** Keys (case-insensitive) that may not carry a string, a number array or binary. */
const FORBIDDEN_KEYS = new Set(
  [
    'body',
    'rawBody',
    'raw',
    'html',
    'text',
    'content',
    'contentBase64',
    'data',
    'bytes',
    'eml',
    'mime',
    'attachmentData',
    'attachmentContent',
  ].map((key) => key.toLowerCase()),
);

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function childPath(path: string, key: string | number): string {
  if (typeof key === 'number') return `${path}[${key}]`;
  return IDENTIFIER.test(key) ? `${path}.${key}` : `${path}[${JSON.stringify(key)}]`;
}

function isBinary(value: object): boolean {
  if (Buffer.isBuffer(value) || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    return true;
  }
  if (typeof SharedArrayBuffer !== 'undefined' && value instanceof SharedArrayBuffer) return true;
  const candidate = value as {
    type?: unknown;
    data?: unknown;
    arrayBuffer?: unknown;
    size?: unknown;
    stream?: unknown;
  };
  // JSON-serialized Buffer: { type: 'Buffer', data: [...] }.
  if (candidate.type === 'Buffer' && Array.isArray(candidate.data)) return true;
  // Blob / File-like.
  return (
    typeof candidate.arrayBuffer === 'function' &&
    typeof candidate.size === 'number' &&
    (typeof candidate.stream === 'function' || typeof candidate.type === 'string')
  );
}

function isNumberArray(value: unknown): boolean {
  return Array.isArray(value) && value.length > 0 && value.every((v) => typeof v === 'number');
}

function checkString(value: string, path: string, maxStringLength: number): void {
  if (value.length > maxStringLength) throw new ContentGuardError('oversized_string', path);
  if (MIME_HEADER.test(value)) throw new ContentGuardError('mime_content', path);
  if (value.length >= BASE64_RUN && BASE64_BLOB.test(value)) {
    throw new ContentGuardError('base64_blob', path);
  }
}

/**
 * Throws `ContentGuardError` when `value` carries anything but metadata (Q7): binary values or
 * serialized buffers, strings over `maxStringLength`, MIME headers, base64 runs of ≥ 512
 * characters, forbidden content keys with a string / number array / binary value, nesting
 * deeper than 16 levels or more than 10 000 nodes. `message_too_large` is the publisher's.
 */
export function assertMetadataOnly(value: unknown, options: ContentGuardOptions = {}): void {
  const maxStringLength = options.maxStringLength ?? DEFAULT_MAX_STRING_LENGTH;
  let nodes = 0;
  const visit = (node: unknown, path: string, depth: number): void => {
    nodes += 1;
    if (nodes > MAX_NODES) throw new ContentGuardError('too_deep', path);
    if (typeof node === 'string') {
      checkString(node, path, maxStringLength);
      return;
    }
    if (typeof node !== 'object' || node === null) return;
    if (depth > MAX_DEPTH) throw new ContentGuardError('too_deep', path);
    if (isBinary(node)) throw new ContentGuardError('binary_value', path);
    if (Array.isArray(node)) {
      node.forEach((item, index) => visit(item, childPath(path, index), depth + 1));
      return;
    }
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const keyPath = childPath(path, key);
      // Keys are structure, but an absurd key is content too.
      checkString(key, keyPath, maxStringLength);
      if (
        FORBIDDEN_KEYS.has(key.toLowerCase()) &&
        (typeof child === 'string' ||
          isNumberArray(child) ||
          (typeof child === 'object' && child !== null && isBinary(child)))
      ) {
        throw new ContentGuardError('forbidden_field', keyPath);
      }
      visit(child, keyPath, depth + 1);
    }
  };
  visit(value, '$', 1);
}
