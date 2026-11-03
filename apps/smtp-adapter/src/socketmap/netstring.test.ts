import { describe, expect, it } from 'vitest';
import {
  encodeNetstring,
  MAX_NETSTRING_BYTES,
  NetstringDecoder,
  NetstringError,
} from './netstring';

const decode = (decoder: NetstringDecoder, text: string) =>
  decoder.push(Buffer.from(text)).map((payload) => payload.toString());

describe('netstring codec', () => {
  it('encodes byte lengths (UTF-8)', () => {
    expect(encodeNetstring('OK active').toString()).toBe('9:OK active,');
    expect(encodeNetstring('NOTFOUND ').toString()).toBe('9:NOTFOUND ,');
    expect(encodeNetstring('é').toString()).toBe('2:é,');
    expect(encodeNetstring('').toString()).toBe('0:,');
  });

  it('decodes a complete request', () => {
    expect(decode(new NetstringDecoder(), '24:relay_domain tenant.test,')).toEqual([
      'relay_domain tenant.test',
    ]);
  });

  it('reassembles requests split at any byte', () => {
    const wire = '24:relay_domain tenant.test,';
    for (let cut = 1; cut < wire.length; cut += 1) {
      const decoder = new NetstringDecoder();
      expect(decode(decoder, wire.slice(0, cut))).toEqual([]);
      expect(decode(decoder, wire.slice(cut))).toEqual(['relay_domain tenant.test']);
    }
  });

  it('decodes pipelined requests in one chunk', () => {
    expect(decode(new NetstringDecoder(), '3:a b,3:c d,0:,')).toEqual(['a b', 'c d', '']);
  });

  it.each([
    ['non-digit length', 'x3:abc,'],
    ['leading zero', '03:abc,'],
    ['missing comma', '3:abcX'],
    ['negative length', '-1:a,'],
    ['oversized length', `${MAX_NETSTRING_BYTES + 1}:`],
    ['too many length digits', '1234567'],
  ])('rejects %s', (_, wire) => {
    expect(() => decode(new NetstringDecoder(), wire)).toThrow(NetstringError);
  });

  it('accepts the maximum size', () => {
    const payload = 'a'.repeat(MAX_NETSTRING_BYTES);
    expect(decode(new NetstringDecoder(), `${MAX_NETSTRING_BYTES}:${payload},`)).toEqual([payload]);
  });
});
