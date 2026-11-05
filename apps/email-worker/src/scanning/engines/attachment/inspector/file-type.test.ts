import * as corpus from '@email-gateway/attachment-corpus';
import { FILE_TYPE_IDS } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  contentType,
  detectMagic,
  emptyZipNames,
  extensionTypeOfName,
  isPortableExecutable,
  isTextLike,
  noteZipName,
  refineTextType,
  subtypeZip,
} from './file-type';

const pad = (head: Buffer | number[], size = 600): Buffer => {
  const bytes = Buffer.isBuffer(head) ? head : Buffer.from(head);
  return Buffer.concat([bytes, Buffer.alloc(Math.max(0, size - bytes.length))]);
};
const ascii = (text: string, size?: number) => pad(Buffer.from(text, 'latin1'), size);

function ole(clsid: number[] | null): Buffer {
  const bytes = Buffer.alloc(2048);
  Buffer.from(corpus.OLE_MAGIC).copy(bytes, 0);
  bytes.writeUInt16LE(9, 0x1e); // 512-byte sectors
  bytes.writeUInt32LE(0, 0x30); // first directory sector 0 → offset 512
  if (clsid) Buffer.from(clsid).copy(bytes, 512 + 0x50);
  return bytes;
}

function zipNamesOf(names: string[]) {
  const z = emptyZipNames();
  for (const name of names) noteZipName(z, name);
  return z;
}

describe('true file type detection (step 4.2 A5)', () => {
  it('detects every magic-bytes type of the vocabulary', () => {
    const iso = Buffer.alloc(0x9000);
    iso.write('CD001', 0x8001, 'latin1');
    const vhd = Buffer.alloc(1024);
    vhd.write('conectix', 512, 'latin1');
    const tar = Buffer.alloc(1024);
    tar.write('ustar', 257, 'latin1');
    const cab = ascii('MSCF\0\0\0\0', 64);
    const bmp = Buffer.alloc(64);
    bmp.write('BM', 0, 'latin1');
    bmp.writeUInt32LE(64, 2);
    const cases: Array<[string, Buffer]> = [
      ['pdf', ascii('%PDF-1.7\n')],
      ['zip', pad([0x50, 0x4b, 0x03, 0x04])],
      ['zip', pad([0x50, 0x4b, 0x05, 0x06])],
      ['gzip', pad([0x1f, 0x8b, 0x08])],
      ['tar', tar],
      ['7z', corpus.fake7z()],
      ['rar', corpus.fakeRar()],
      ['cab', cab],
      ['bzip2', corpus.fakeBzip2()],
      ['xz', corpus.fakeXz()],
      ['ole_office', ole(null)],
      ['msi', ole([0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46])],
      ['pe_executable', corpus.peStub()],
      ['elf', pad([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1])],
      ['macho', pad([0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1])],
      ['macho', pad([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2])],
      ['lnk', corpus.lnkWithCommandTarget()],
      ['chm', ascii('ITSF\x03\0\0\0')],
      ['rtf', ascii('{\\rtf1\\ansi hello}')],
      ['png', pad([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])],
      ['jpeg', pad([0xff, 0xd8, 0xff, 0xe0])],
      ['gif', ascii('GIF89a')],
      ['webp', ascii('RIFF\0\0\0\0WEBPVP8 ')],
      ['tiff', pad([0x49, 0x49, 0x2a, 0x00])],
      ['bmp', bmp],
      ['iso', iso],
      ['vhd', vhd],
      ['html', Buffer.from('<!DOCTYPE html><html><body>hi</body></html>')],
      ['svg', Buffer.from('<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"></svg>')],
      ['xml', Buffer.from('<?xml version="1.0"?>\n<note>x</note>')],
      ['ics', Buffer.from('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n')],
      ['hta', Buffer.from('<html><head><HTA:APPLICATION ID="x"/></head></html>')],
      ['script_shell', Buffer.from('#!/bin/sh\necho hi\n')],
      ['script_shell', Buffer.from('#!/usr/bin/env bash\necho hi\n')],
      [
        'eml',
        Buffer.from(
          'From: a@b.test\r\nTo: c@d.test\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\r\nbody\r\n',
        ),
      ],
      ['text', Buffer.from('plain words\nsecond line\n')],
      ['unknown', corpus.largeFile(4096)],
      ['unknown', Buffer.alloc(0)],
    ];
    for (const [expected, bytes] of cases) expect(detectMagic(bytes), expected).toBe(expected);
  });

  it('requires a valid e_lfanew pointing at PE\\0\\0 for a PE (A5)', () => {
    expect(isPortableExecutable(corpus.peStub())).toBe(true);
    expect(detectMagic(corpus.mzWithoutPe())).not.toBe('pe_executable');
    const outOfRange = corpus.peStub();
    outOfRange.writeUInt32LE(0xffffff, 0x3c);
    expect(isPortableExecutable(outOfRange)).toBe(false);
    const tooLow = corpus.peStub();
    tooLow.writeUInt32LE(0x10, 0x3c);
    expect(isPortableExecutable(tooLow)).toBe(false);
    // Truncated headers never throw.
    expect(detectMagic(Buffer.from('MZ'))).toBe('text');
    expect(detectMagic(Buffer.from([0x50, 0x4b]))).not.toBe('zip');
    expect(detectMagic(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))).toBe(
      'ole_office',
    );
  });

  it('sub-types zip containers by their entry names (OOXML, macro OOXML, ODF, jar, apk)', () => {
    expect(subtypeZip(zipNamesOf(['[Content_Types].xml', 'word/document.xml']))).toBe('ooxml_word');
    expect(subtypeZip(zipNamesOf(['[Content_Types].xml', 'xl/workbook.xml']))).toBe('ooxml_excel');
    expect(subtypeZip(zipNamesOf(['[Content_Types].xml', 'ppt/presentation.xml']))).toBe(
      'ooxml_powerpoint',
    );
    expect(
      subtypeZip(zipNamesOf(['[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin'])),
    ).toBe('ooxml_macro');
    const odf = zipNamesOf(['mimetype', 'content.xml']);
    odf.odfMimetype = true;
    expect(subtypeZip(odf)).toBe('odf');
    expect(subtypeZip(zipNamesOf(['META-INF/MANIFEST.MF', 'a/B.class']))).toBe('jar');
    expect(
      subtypeZip(zipNamesOf(['AndroidManifest.xml', 'classes.dex', 'META-INF/MANIFEST.MF'])),
    ).toBe('apk');
    expect(subtypeZip(zipNamesOf(['word/document.xml']))).toBe('zip');
    expect(subtypeZip(zipNamesOf(['a.txt']))).toBe('zip');
  });

  it('types scripts by their extension only when the content is text (A5)', () => {
    expect(refineTextType('text', 'script_js')).toBe('script_js');
    expect(refineTextType('text', 'script_batch')).toBe('script_batch');
    expect(refineTextType('text', 'html')).toBe('html');
    expect(refineTextType('text', 'pdf')).toBe('text');
    expect(refineTextType('pe_executable', 'script_js')).toBe('pe_executable');
    expect(refineTextType('text', null)).toBe('text');
    expect(extensionTypeOfName('dir/Invoice.PDF')).toBe('pdf');
    expect(extensionTypeOfName('a\\b\\run.bat')).toBe('script_batch');
    expect(extensionTypeOfName('.hidden')).toBeNull();
    expect(extensionTypeOfName('noext')).toBeNull();
    expect(extensionTypeOfName('trailing.')).toBeNull();
  });

  it('bounds the text check (UTF-8, no NUL, few control characters)', () => {
    expect(isTextLike(Buffer.from('héllo wörld\n'))).toBe(true);
    expect(isTextLike(Buffer.from([0x68, 0x00, 0x69]))).toBe(false);
    expect(isTextLike(Buffer.from([0xc3, 0x28]))).toBe(false);
    expect(isTextLike(Buffer.alloc(0))).toBe(false);
    // A large text file is sampled, not decoded in full; a split multi-byte sequence at the
    // sample edge is not a decoding error.
    const big = Buffer.from('é'.repeat(70_000));
    expect(isTextLike(big)).toBe(true);
  });

  it('reports family and executable from the vocabulary for every id', () => {
    for (const id of FILE_TYPE_IDS) {
      const type = contentType(id, false);
      expect(type.detected).toBe(id);
      expect(typeof type.executable).toBe('boolean');
    }
    expect(contentType('pe_executable', false)).toMatchObject({
      family: 'executable',
      executable: true,
    });
  });
});
