import 'server-only';

/**
 * AES-256-GCM sealing of cookie payloads with Web Crypto (design P2), so the same code runs in
 * route handlers and middleware. Format: `v1.<b64url iv>.<b64url ciphertext+tag>`; random
 * 96-bit IV; the additional authenticated data binds a sealed value to its purpose, so a sealed
 * MFA challenge can never be replayed as a session.
 */

export const SESSION_AAD = 'eg-portal-session/v1';
export const MFA_AAD = 'eg-portal-mfa/v1';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const keyCache = new Map<string, Promise<CryptoKey>>();

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('invalid base64url');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function importKey(hex: string): Promise<CryptoKey> {
  let key = keyCache.get(hex);
  if (!key) {
    key = crypto.subtle.importKey('raw', hexToBytes(hex), { name: 'AES-GCM' }, false, [
      'encrypt',
      'decrypt',
    ]);
    keyCache.set(hex, key);
  }
  return key;
}

export async function seal(value: unknown, keyHex: string, aad: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importKey(keyHex);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(aad) },
    key,
    encoder.encode(JSON.stringify(value)),
  );
  return `v1.${toBase64Url(iv)}.${toBase64Url(new Uint8Array(ciphertext))}`;
}

/**
 * Opens a sealed value with the current key, then the previous key (rotation). Any failure
 * (format, tag, JSON) returns `null`: a tampered cookie means "logged out", never an error.
 */
export async function unseal(
  sealed: string | undefined | null,
  keys: readonly (string | undefined)[],
  aad: string,
): Promise<unknown> {
  if (!sealed) return null;
  const parts = sealed.split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') return null;
  let iv: Uint8Array<ArrayBuffer>;
  let data: Uint8Array<ArrayBuffer>;
  try {
    iv = fromBase64Url(parts[1] ?? '');
    data = fromBase64Url(parts[2] ?? '');
  } catch {
    return null;
  }
  if (iv.length !== 12 || data.length < 17) return null;
  for (const keyHex of keys) {
    if (!keyHex) continue;
    try {
      const key = await importKey(keyHex);
      const plain = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: encoder.encode(aad) },
        key,
        data,
      );
      return JSON.parse(decoder.decode(plain)) as unknown;
    } catch {
      // try the next key
    }
  }
  return null;
}

export function randomToken(bytes = 32): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Constant-time comparison of two strings (CSRF tokens). */
export function timingSafeEqualString(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  let diff = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}
