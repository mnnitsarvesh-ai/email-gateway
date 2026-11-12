import { inlinePgp, signedOrEncrypted } from '@email-gateway/url-security';

/**
 * Signed or encrypted messages (step 5.3 Q22): a body edit would break the signature the
 * recipient relies on, or cannot be made at all. Reuses the 4.3 rules of
 * `@email-gateway/url-security` (`signedOrEncrypted` on the content types of
 * `email_message_parses.structure`, `inlinePgp` on the first bytes of the candidate parts).
 */

export type SignedOrEncrypted = 'skipped_signed' | 'skipped_encrypted';

/** Bytes of each candidate part the inline-PGP check reads (64 KiB). */
export const SIGNATURE_HEAD_BYTES = 65_536;

/**
 * `structure`: the content types of the message in document order (strings or
 * `{ contentType }` rows); `headBytes`: the first bytes of the candidate text parts (decoded or
 * raw; only ASCII armor lines are looked for). Null when neither signed nor encrypted.
 */
export function detectSignedOrEncrypted(
  structure: ReadonlyArray<string | { contentType: string }> | null,
  headBytes: ReadonlyArray<Buffer | string> | Buffer | string | null = null,
): SignedOrEncrypted | null {
  const types = (structure ?? []).map((s) => (typeof s === 'string' ? s : s.contentType));
  const structural = signedOrEncrypted(types);
  if (structural !== null)
    return structural === 'encrypted' ? 'skipped_encrypted' : 'skipped_signed';
  const heads = headBytes === null ? [] : Array.isArray(headBytes) ? headBytes : [headBytes];
  for (const head of heads as Array<Buffer | string>) {
    const text =
      typeof head === 'string'
        ? head.slice(0, SIGNATURE_HEAD_BYTES)
        : head.subarray(0, SIGNATURE_HEAD_BYTES).toString('latin1');
    const pgp = inlinePgp(text);
    if (pgp !== null) return pgp === 'encrypted' ? 'skipped_encrypted' : 'skipped_signed';
  }
  return null;
}
