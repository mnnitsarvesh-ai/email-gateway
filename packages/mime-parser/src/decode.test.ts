import iconv from 'iconv-lite';
import * as libbase64 from 'libbase64';
import * as libqp from 'libqp';
import { describe, expect, it } from 'vitest';
import {
  Base64Decoder,
  CharsetConverter,
  type ChunkDecoder,
  iconvCharset,
  isKnownWordCharset,
  normalizeCharset,
  PassThroughDecoder,
  QuotedPrintableDecoder,
  transferDecoder,
} from './decode';

function decodeIn(decoder: ChunkDecoder, input: Buffer, splits: number[]): Buffer {
  const out: Buffer[] = [];
  let previous = 0;
  for (const split of [...splits, input.length]) {
    out.push(decoder.write(input.subarray(previous, split)));
    previous = split;
  }
  out.push(decoder.end());
  return Buffer.concat(out);
}

describe('Base64Decoder', () => {
  const payload = Buffer.from(Array.from({ length: 300 }, (_, index) => (index * 37) % 256));
  const encoded = Buffer.from(libbase64.wrap(libbase64.encode(payload), 76).replace(/\n/g, '\r\n'));

  it('decodes like libbase64 at every split point', () => {
    for (let split = 0; split <= encoded.length; split += 7) {
      const decoder = new Base64Decoder();
      expect(decodeIn(decoder, encoded, [split])).toEqual(payload);
      expect(decoder.invalid).toBe(false);
    }
  });

  it('accepts per-line padding and whitespace', () => {
    const decoder = new Base64Decoder();
    expect(decodeIn(decoder, Buffer.from('QQ==\r\nQkM=\r\n\tREVG \r\n'), [3, 9])).toEqual(
      Buffer.from('ABCDEF'),
    );
    expect(decoder.invalid).toBe(false);
  });

  it('flags characters outside the alphabet and skips them as libbase64 does', () => {
    const decoder = new Base64Decoder();
    const input = Buffer.from('SGVs*bG8g!d29y#bGQh');
    expect(decodeIn(decoder, input, [5])).toEqual(libbase64.decode(input.toString()));
    expect(decoder.invalid).toBe(true);
  });

  it('flags a truncated length (bad padding)', () => {
    const decoder = new Base64Decoder();
    expect(decodeIn(decoder, Buffer.from('SGVsbG8gd29ybGQ'), [])).toEqual(
      Buffer.from('Hello world'),
    );
    expect(decoder.invalid).toBe(true);
  });
});

describe('QuotedPrintableDecoder', () => {
  const sample = Buffer.from(
    'caf=C3=A9 au lait =\r\nsoft break, trailing spaces   \r\n=3D=3d equals\r\nlast line=\r\n',
    'latin1',
  );

  it('decodes like libqp.decode at every split point', () => {
    const expected = libqp.decode(sample);
    for (let split = 0; split <= sample.length; split++) {
      const decoder = new QuotedPrintableDecoder();
      expect(decodeIn(decoder, sample, [split])).toEqual(expected);
      expect(decoder.invalid).toBe(false);
    }
  });

  it('decodes a line longer than 64 KiB without buffering it whole, cutting outside escapes', () => {
    const line = `${'ab=3D'.repeat(30_000)}=C3=A9 tail  `;
    const input = Buffer.from(`${line}\r\nnext`, 'latin1');
    const expected = libqp.decode(input);
    for (const size of [1000, 4096, 65_537, 70_001]) {
      const decoder = new QuotedPrintableDecoder();
      const splits: number[] = [];
      for (let offset = size; offset < input.length; offset += size) splits.push(offset);
      expect(decodeIn(decoder, input, splits)).toEqual(expected);
    }
  });

  it('flags = without two hex digits or a soft line break', () => {
    for (const bad of ['a =ZZ b', 'end =4', '=\rx']) {
      const decoder = new QuotedPrintableDecoder();
      decodeIn(decoder, Buffer.from(bad), []);
      expect(decoder.invalid, bad).toBe(true);
    }
    for (const good of [
      'soft =\r\nbreak',
      'padded soft =  \r\nbreak',
      'eof soft =',
      'hex =3d =3D',
    ]) {
      const decoder = new QuotedPrintableDecoder();
      decodeIn(decoder, Buffer.from(good), []);
      expect(decoder.invalid, good).toBe(false);
    }
  });
});

describe('transferDecoder', () => {
  it('passes 7bit, 8bit, binary and unknown encodings through', () => {
    for (const encoding of ['', '7bit', '8bit', 'binary', 'x-uuencode']) {
      expect(transferDecoder(encoding)).toBeInstanceOf(PassThroughDecoder);
    }
    expect(transferDecoder('base64')).toBeInstanceOf(Base64Decoder);
    expect(transferDecoder('quoted-printable')).toBeInstanceOf(QuotedPrintableDecoder);
  });
});

describe('charsets', () => {
  it('normalizes declared charsets', () => {
    expect(normalizeCharset(' "UTF-8" ')).toBe('utf-8');
    expect(normalizeCharset('iso-8859-1*en')).toBe('iso-8859-1');
    expect(normalizeCharset('weird<chars>')).toBe('weirdchars');
    expect(normalizeCharset(false)).toBeNull();
    expect(normalizeCharset('""')).toBeNull();
  });

  it('maps no charset and ASCII to UTF-8 and refuses unknown ones', () => {
    expect(iconvCharset(null)).toBe('utf-8');
    expect(iconvCharset('us-ascii')).toBe('utf-8');
    expect(iconvCharset('koi8-r')).toBe('koi8-r');
    expect(iconvCharset('x-unknown')).toBeNull();
    expect(isKnownWordCharset('iso-2022-jp')).toBe(true);
    expect(isKnownWordCharset('x-unknown')).toBe(false);
  });

  it('converts to UTF-8 incrementally, also across a split multi-byte character', () => {
    const sjis = iconv.encode('日本語のテキスト', 'shift_jis');
    for (let split = 0; split <= sjis.length; split++) {
      const converter = new CharsetConverter('shift_jis');
      const out = Buffer.concat([
        converter.write(sjis.subarray(0, split)),
        converter.write(sjis.subarray(split)),
        converter.end(),
      ]);
      expect(out.toString('utf8')).toBe('日本語のテキスト');
    }
    const utf8 = Buffer.from('añ😀b');
    const converter = new CharsetConverter('utf-8');
    const out = Buffer.concat([
      converter.write(utf8.subarray(0, 4)),
      converter.write(utf8.subarray(4)),
      converter.end(),
    ]);
    expect(out).toEqual(utf8);
  });

  it('replaces invalid UTF-8 with U+FFFD', () => {
    const converter = new CharsetConverter('utf-8');
    const out = Buffer.concat([converter.write(Buffer.from([0x61, 0xff, 0x62])), converter.end()]);
    expect(out.toString('utf8')).toBe('a\uFFFDb');
  });
});
