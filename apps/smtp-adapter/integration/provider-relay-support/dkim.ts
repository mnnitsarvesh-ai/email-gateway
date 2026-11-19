import { generateKeyPairSync } from 'node:crypto';
import { dkimSign } from 'mailauth/lib/dkim/sign';
import type { DkimResolver } from '../../src/provider-relay/proof-verifier';

/**
 * DKIM test keys generated at test runtime (never committed, never secret-shaped literals) and
 * signing through mailauth, for the provider relay suites (step 8.2 §10.2).
 */
export interface DkimTestKey {
  domain: string;
  selector: string;
  algorithm: 'rsa-sha256' | 'ed25519-sha256';
  privateKeyPem: string;
  /** The `<selector>._domainkey.<domain>` TXT value. */
  txt: string;
}

export function generateDkimKey(
  domain: string,
  options: { selector?: string; bits?: number; ed25519?: boolean } = {},
): DkimTestKey {
  const selector = options.selector ?? 's1';
  if (options.ed25519) {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    // RFC 8463: p= is the raw 32-byte public key (the last 32 bytes of the SPKI DER).
    const raw = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
    return {
      domain,
      selector,
      algorithm: 'ed25519-sha256',
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      txt: `v=DKIM1; k=ed25519; p=${raw.toString('base64')}`,
    };
  }
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: options.bits ?? 2048,
  });
  return {
    domain,
    selector,
    algorithm: 'rsa-sha256',
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    txt: `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`,
  };
}

export const keyRecordName = (key: DkimTestKey): string =>
  `${key.selector}._domainkey.${key.domain}`;

/** The message with the DKIM-Signature header(s) prepended. */
export async function signMessage(
  message: string,
  keys: readonly DkimTestKey[],
  options: { signTime?: Date; headerList?: string[]; maxBodyLength?: number } = {},
): Promise<string> {
  const result = await dkimSign(message, {
    canonicalization: 'relaxed/relaxed',
    ...(options.signTime ? { signTime: options.signTime } : {}),
    signatureData: keys.map((key) => ({
      signingDomain: key.domain,
      selector: key.selector,
      privateKey: key.privateKeyPem,
      algorithm: key.algorithm,
      ...(options.headerList ? { headerList: options.headerList } : {}),
      ...(options.maxBodyLength !== undefined ? { maxBodyLength: options.maxBodyLength } : {}),
    })),
  });
  if (result.errors.length > 0) throw new Error('test DKIM signing failed');
  return result.signatures + message;
}

/** An in-memory TXT resolver: unknown names are ENOTFOUND, `fail` names ESERVFAIL. */
export function memoryResolver(
  records: Map<string, string>,
  fail: Set<string> = new Set(),
): DkimResolver {
  return (name, rrtype) => {
    const key = name.toLowerCase();
    if (fail.has(key)) {
      return Promise.reject(Object.assign(new Error('server failure'), { code: 'ESERVFAIL' }));
    }
    const value = rrtype === 'TXT' ? records.get(key) : undefined;
    if (value === undefined) {
      return Promise.reject(Object.assign(new Error('not found'), { code: 'ENOTFOUND' }));
    }
    const chunks: string[] = [];
    for (let i = 0; i < value.length; i += 255) chunks.push(value.slice(i, i + 255));
    return Promise.resolve([chunks]);
  };
}

/** A plain outbound message (CRLF line ends). */
export function testMessage(input: {
  from: string;
  to: string;
  subject?: string;
  extraHeaders?: string[];
  body?: string;
}): string {
  return [
    `From: Sender <${input.from}>`,
    `To: <${input.to}>`,
    `Subject: ${input.subject ?? 'quarterly report'}`,
    'Date: Wed, 18 Nov 2026 10:00:00 +0000',
    `Message-ID: <${Math.random().toString(36).slice(2)}@provider.test>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    ...(input.extraHeaders ?? []),
    '',
    input.body ?? 'Hello,\r\nplease find the report attached.\r\n',
  ].join('\r\n');
}
