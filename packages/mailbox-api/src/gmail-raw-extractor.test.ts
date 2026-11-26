import { describe, expect, it } from 'vitest';
import { MailboxApiError } from './errors';
import { GmailRawExtractor } from './gmail-raw-extractor';

const b64url = (bytes: Buffer, pad = false): string => {
  const text = bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
  return pad ? text : text.replace(/=+$/, '');
};

/** Deterministic PRNG (mulberry32) for the property tests. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function run(chunks: Uint8Array[], maxDecodedBytes = 1 << 20, maxOtherBytes?: number): Buffer {
  const extractor = new GmailRawExtractor({
    maxDecodedBytes,
    ...(maxOtherBytes !== undefined ? { maxOtherBytes } : {}),
  });
  const out: Buffer[] = [];
  for (const chunk of chunks) out.push(Buffer.from(extractor.push(chunk)));
  extractor.end();
  return Buffer.concat(out);
}

function failure(fn: () => unknown): MailboxApiError {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(MailboxApiError);
    return error as MailboxApiError;
  }
  throw new Error('expected a MailboxApiError');
}

const message = Buffer.from(
  'From: a@sender.example\r\nTo: b@example.com\r\nSubject: =?utf-8?q?Gr=C3=BC=C3=9Fe?=\r\n\r\nBody ü ✓ \x00\xff end\r\n',
  'latin1',
);

/** Gmail's order with a snippet that contains the text of a raw field. */
const gmailJson = (raw: string): string =>
  `{"id":"18c0000000000001","threadId":"18c0000000000001","labelIds":["INBOX","UNREAD"],` +
  `"snippet":"He wrote \\"raw\\": \\"QUFB\\" and \\\\ \\u0022raw\\u0022","sizeEstimate":${message.length},` +
  `"raw":"${raw}","historyId":"1201","internalDate":"1794312000000"}`;

describe('GmailRawExtractor', () => {
  it('decodes the raw field of a Gmail answer at every chunk boundary', () => {
    const json = Buffer.from(gmailJson(b64url(message, true)), 'utf8');
    for (let split = 0; split <= json.length; split += 1) {
      const decoded = run([json.subarray(0, split), json.subarray(split)]);
      expect(decoded.equals(message), `split at ${split}`).toBe(true);
    }
    // One byte per chunk.
    const bytes = [...json].map((b) => Uint8Array.of(b));
    expect(run(bytes).equals(message)).toBe(true);
  });

  it('property: random messages, alphabets, padding and chunking decode exactly', () => {
    const random = prng(20261126);
    for (let round = 0; round < 300; round += 1) {
      const length = Math.floor(random() * 700);
      const payload = Buffer.alloc(length);
      for (let i = 0; i < length; i += 1) payload[i] = Math.floor(random() * 256);
      const standard = random() < 0.3;
      let raw = standard ? payload.toString('base64') : b64url(payload, random() < 0.5);
      if (standard) raw = raw.replace(/\//g, '\\/'); // JSON may escape the solidus
      const position = Math.floor(random() * 3);
      const fields = ['"id":"x"', '"labelIds":["INBOX",{"raw":"nested"}]', `"raw":"${raw}"`];
      fields.splice(fields.indexOf(`"raw":"${raw}"`), 1);
      fields.splice(position, 0, `"raw":"${raw}"`);
      const json = Buffer.from(` {${fields.join(' , ')}} \n`, 'utf8');
      const chunks: Uint8Array[] = [];
      for (let offset = 0; offset < json.length;) {
        const size = 1 + Math.floor(random() * 40);
        chunks.push(json.subarray(offset, offset + size));
        offset += size;
      }
      expect(run(chunks).equals(payload), `round ${round}`).toBe(true);
    }
  });

  it('is independent of field order and skips nested raw keys, numbers and literals', () => {
    const raw = b64url(message);
    for (const json of [
      `{"raw":"${raw}","id":"1"}`,
      `{"id":"1","nested":{"raw":"AAAA","deeper":[{"raw":"BBBB"}]},"raw":"${raw}"}`,
      `{"sizeEstimate":12.5e3,"ok":true,"none":null,"arr":[1,2,[3]],"raw":"${raw}"}`,
      `{ "r\\u0061w" : "${raw}" }`,
    ]) {
      expect(run([Buffer.from(json)]).equals(message), json.slice(0, 40)).toBe(true);
    }
  });

  it('decodes escapes and line-wrapped base64 inside the value', () => {
    const raw = message.toString('base64');
    const wrapped = raw.replace(/(.{20})/g, '$1\\r\\n').replace(/\//g, '\\/');
    const unicode = raw.replace(/A/g, '\\u0041');
    expect(run([Buffer.from(`{"raw":"${wrapped}"}`)]).equals(message)).toBe(true);
    expect(run([Buffer.from(`{"raw":"${unicode}"}`)]).equals(message)).toBe(true);
  });

  it('streams with bounded memory: output appears before the input ends', async () => {
    const big = Buffer.alloc(3 * 1024 * 1024, 0x61);
    const json = Buffer.from(gmailJson(b64url(big)), 'utf8');
    let yielded = 0;
    let firstAt = -1;
    let fed = 0;
    async function* source() {
      for (let offset = 0; offset < json.length; offset += 64 * 1024) {
        fed += 1;
        yield await Promise.resolve(json.subarray(offset, offset + 64 * 1024));
      }
    }
    let total = 0;
    for await (const chunk of GmailRawExtractor.extract(source(), {
      maxDecodedBytes: big.length,
    })) {
      yielded += 1;
      total += chunk.length;
      if (firstAt < 0) firstAt = fed;
    }
    expect(total).toBe(big.length);
    expect(yielded).toBeGreaterThan(10);
    expect(firstAt).toBeLessThan(3);
  });

  it('fails response_too_large above the decoded cap and above the other-bytes cap', () => {
    const json = Buffer.from(gmailJson(b64url(message)), 'utf8');
    const decoded = failure(() => run([json], message.length - 1));
    expect(decoded.code).toBe('response_too_large');
    expect(decoded.retryable).toBe(false);
    expect(run([json], message.length).equals(message)).toBe(true);
    const padded = Buffer.from(`{"snippet":"${'x'.repeat(5000)}","raw":"QUFB"}`);
    expect(failure(() => run([padded], 1024, 4096)).code).toBe('response_too_large');
  });

  it.each([
    ['missing raw', '{"id":"1"}'],
    ['raw null', '{"raw":null}'],
    ['raw number', '{"raw":12}'],
    ['raw object', '{"raw":{"a":"b"}}'],
    ['duplicate raw', '{"raw":"QUFB","raw":"QUFB"}'],
    ['truncated', '{"raw":"QUFB"'],
    ['truncated value', '{"raw":"QUF'],
    ['not an object', '["raw","QUFB"]'],
    ['trailing garbage', '{"raw":"QUFB"} x'],
    ['invalid base64 char', '{"raw":"QU*B"}'],
    ['dangling char', '{"raw":"QUFBQ"}'],
    ['data after padding', '{"raw":"QQ==QQ"}'],
    ['bad escape', '{"raw":"QU\\qB"}'],
    ['missing comma', '{"id":"1" "raw":"QUFB"}'],
    ['missing colon', '{"raw" "QUFB"}'],
    ['control char in string', '{"id":"a\u0001b","raw":"QUFB"}'],
    ['mismatched brackets', '{"a":[1,2},"raw":"QUFB"}'],
  ])('fails unexpected_response for %s', (_name, json) => {
    const error = failure(() => run([Buffer.from(json, 'utf8')]));
    expect(error.code).toBe('unexpected_response');
    expect(error.message).toBe('unexpected_response');
  });

  it('accepts unpadded and padded endings of every length', () => {
    for (const text of ['A', 'AB', 'ABC', 'ABCD', 'ABCDE']) {
      const bytes = Buffer.from(text);
      expect(run([Buffer.from(`{"raw":"${b64url(bytes)}"}`)]).toString()).toBe(text);
      expect(run([Buffer.from(`{"raw":"${b64url(bytes, true)}"}`)]).toString()).toBe(text);
    }
    expect(run([Buffer.from('{"raw":""}')]).length).toBe(0);
  });
});
