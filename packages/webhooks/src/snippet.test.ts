import { describe, expect, it } from 'vitest';
import { RESPONSE_SNIPPET_MAX_CHARS, responseSnippet } from './snippet';

const snip = (text: string) => responseSnippet(Buffer.from(text, 'utf8'));

describe('responseSnippet (W2, §9)', () => {
  it('returns null for an empty body and the text of a short one', () => {
    expect(responseSnippet(null)).toBeNull();
    expect(responseSnippet(Buffer.alloc(0))).toBeNull();
    expect(snip('{"ok":true}')).toBe('{"ok":true}');
  });

  it('replaces control characters by spaces', () => {
    expect(snip('a\r\nb\tc\u0000d\u001be\u007ff\u0085g h')).toBe('a  b c d e f g h');
  });

  it('decodes invalid UTF-8 lossily', () => {
    expect(responseSnippet(Buffer.from([0x6f, 0x6b, 0xff, 0xfe]))).toBe('ok��');
  });

  it('redacts secrets, bearer tokens, key=value credentials and long base64/hex runs', () => {
    expect(snip('bad secret whsec_AbC-123_xyz here')).toBe('bad secret [redacted] here');
    expect(snip('Authorization: Bearer eyJhbGciOi.payload.sig rest')).toBe(
      'Authorization: [redacted] rest',
    );
    expect(snip('api_key=abc123 x')).toBe('[redacted] x');
    expect(snip('apiKey: abc')).toBe('[redacted]');
    expect(snip('TOKEN = t0k3n;')).toBe('[redacted]');
    expect(snip('password:hunter2 ok')).toBe('[redacted] ok');
    expect(snip(`hash ${'a'.repeat(64)} end`)).toBe('hash [redacted] end');
    expect(snip(`b64 ${'QUJD'.repeat(8)} end`)).toBe('b64 [redacted] end');
    expect(snip(`short ${'a'.repeat(31)}`)).toBe(`short ${'a'.repeat(31)}`);
  });

  it('cuts to 512 code points after redaction', () => {
    expect(snip('x'.repeat(2000).replace(/(.{10})/g, '$1 '))!.length).toBe(
      RESPONSE_SNIPPET_MAX_CHARS,
    );
    const emoji = '😀'.repeat(600);
    expect(Array.from(snip(emoji)!)).toHaveLength(512);
    // A secret straddling the limit is redacted, never partially kept.
    const straddle = `${'y '.repeat(250)}whsec_${'Z'.repeat(40)}`;
    expect(snip(straddle)).not.toMatch(/whsec_|ZZZ/);
  });
});
