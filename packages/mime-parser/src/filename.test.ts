import { describe, expect, it } from 'vitest';
import { ORIGINAL_FILENAME_MAX_CHARS, sanitizeFilename } from './filename';

const clean = (raw: string | undefined, max = 200) => sanitizeFilename(raw, max);

describe('sanitizeFilename', () => {
  it('keeps an ordinary name unchanged', () => {
    expect(clean('report.pdf')).toEqual({
      filename: 'report.pdf',
      originalFilename: 'report.pdf',
      flags: [],
    });
  });

  it('1. normalizes to NFC and replaces lone surrogates', () => {
    expect(clean('Cafe\u0301.txt').filename).toBe('Caf\u00E9.txt');
    expect(clean('a\uD800.txt').filename).toBe('a\uFFFD.txt');
  });

  it('2. keeps the last path component and strips a drive prefix', () => {
    expect(clean('../../etc/passwd')).toMatchObject({
      filename: 'passwd',
      flags: ['filename_path_stripped'],
    });
    expect(clean('..\\..\\win.ini')).toMatchObject({
      filename: 'win.ini',
      flags: ['filename_path_stripped'],
    });
    expect(clean('C:x.exe').filename).toBe('x.exe');
    expect(clean('C:x.exe').flags).toContain('filename_path_stripped');
    expect(clean('C:\\x.exe').filename).toBe('x.exe');
  });

  it('3. removes control, bidi and zero-width characters with their flags', () => {
    expect(clean('a\u0000b\u001Fc\u007Fd\u0085.txt')).toMatchObject({
      filename: 'abcd.txt',
      flags: ['filename_control_chars'],
    });
    const rlo = clean('invoice\u202Efdp.exe');
    expect(rlo.filename).toBe('invoicefdp.exe');
    expect(rlo.flags).toEqual(['filename_bidi_control', 'filename_executable_extension']);
    for (const bidi of ['\u061C', '\u200E', '\u200F', '\u202A', '\u202D', '\u2066', '\u2069']) {
      expect(clean(`a${bidi}b.txt`).flags, bidi).toEqual(['filename_bidi_control']);
    }
    expect(clean('re\u200Bpo\u200C\u200Drt\uFEFF.pdf')).toMatchObject({
      filename: 'report.pdf',
      flags: ['filename_zero_width'],
    });
  });

  it('4. replaces reserved characters, collapses whitespace, trims dots and spaces', () => {
    expect(clean('a<b>c:d"e|f?g*h.txt').filename).toBe('a_b_c_d_e_f_g_h.txt');
    expect(clean('  ..my   \t file..txt. .').filename).toBe('my file..txt');
    expect(clean('...').filename).toBeNull();
  });

  it('4. flags whitespace padding before the final extension', () => {
    const padded = clean('invoice.pdf          .exe');
    expect(padded.filename).toBe('invoice.pdf .exe');
    expect(padded.flags).toEqual([
      'filename_whitespace_padding',
      'filename_executable_extension',
      'filename_double_extension',
    ]);
    expect(clean('two  spaces.pdf').flags).toEqual([]);
  });

  it('5. prefixes Windows device names, with any extension', () => {
    for (const name of ['CON', 'con.txt', 'PRN.pdf', 'AUX', 'NUL.tar.gz', 'COM1.txt', 'lpt9']) {
      const result = clean(name);
      expect(result.filename, name).toBe(`_${name}`);
      expect(result.flags, name).toContain('filename_reserved_name');
    }
    expect(clean('CONSOLE.txt').flags).toEqual([]);
    expect(clean('COM0.txt').flags).toEqual([]);
  });

  it('6. truncates to the cap, keeping the final extension', () => {
    const long = clean(`${'a'.repeat(300)}.pdf`, 200);
    expect(long.filename).toBe(`${'a'.repeat(196)}.pdf`);
    expect(long.flags).toEqual(['filename_truncated']);
    expect(clean(`${'a'.repeat(196)}.pdf`, 200).flags).toEqual([]);
    expect(clean(`${'a'.repeat(197)}.pdf`, 200).filename).toHaveLength(200);
    // An extension longer than 16 characters is not kept.
    const longExtension = clean(`name.${'x'.repeat(250)}`, 20);
    expect(longExtension.filename).toBe(`name.${'x'.repeat(15)}`);
    // Code points, not UTF-16 units.
    expect(clean(`${'\uD83D\uDE00'.repeat(30)}.txt`, 20).filename).toBe(
      `${'\uD83D\uDE00'.repeat(16)}.txt`,
    );
  });

  it('7. a name with nothing left, or none at all, is missing', () => {
    expect(clean(undefined)).toEqual({
      filename: null,
      originalFilename: null,
      flags: ['filename_missing'],
    });
    expect(clean('')).toEqual({
      filename: null,
      originalFilename: null,
      flags: ['filename_missing'],
    });
    expect(clean('\u202E\u200B')).toEqual({
      filename: null,
      originalFilename: '\\u{202E}\\u{200B}',
      flags: ['filename_bidi_control', 'filename_zero_width', 'filename_missing'],
    });
  });

  it('flags executable and double extensions', () => {
    expect(clean('setup.EXE').flags).toEqual(['filename_executable_extension']);
    expect(clean('report.pdf.exe').flags).toEqual([
      'filename_executable_extension',
      'filename_double_extension',
    ]);
    expect(clean('photo.jpg.js').flags).toContain('filename_double_extension');
    expect(clean('archive.tar.exe').flags).toEqual(['filename_executable_extension']);
    expect(clean('report.pdf').flags).toEqual([]);
  });

  it('escapes invisible characters and backslashes in the original, capped at 1 024 characters', () => {
    expect(clean('a\\b\u202E\u0007c').originalFilename).toBe('a\\u{005C}b\\u{202E}\\u{0007}c');
    const huge = clean('x'.repeat(2000));
    expect(huge.originalFilename).toHaveLength(ORIGINAL_FILENAME_MAX_CHARS);
    expect(huge.flags).toContain('original_filename_truncated');
    // An escape is never cut in half.
    const escapes = clean(`${'x'.repeat(1020)}\u202E\u202E`).originalFilename ?? '';
    expect(escapes.endsWith('x')).toBe(true);
  });
});
