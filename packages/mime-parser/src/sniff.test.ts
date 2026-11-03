import { describe, expect, it } from 'vitest';
import { sniffContentType, sniffFlags } from './sniff';

const bytes = (...values: number[]): Buffer => Buffer.from(values);
const text = (value: string): Buffer => Buffer.from(value, 'latin1');
const tar = (): Buffer => {
  const header = Buffer.alloc(512);
  header.write('ustar', 257, 'latin1');
  return header;
};

describe('sniffContentType (design M9 table)', () => {
  const rows: [string, Buffer][] = [
    ['application/pdf', text('%PDF-1.7\n')],
    ['application/zip', bytes(0x50, 0x4b, 0x03, 0x04, 0x14)],
    ['application/zip', bytes(0x50, 0x4b, 0x05, 0x06)],
    ['application/zip', bytes(0x50, 0x4b, 0x07, 0x08)],
    ['application/gzip', bytes(0x1f, 0x8b, 0x08)],
    ['application/x-bzip2', text('BZh91AY')],
    ['application/x-xz', bytes(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00)],
    ['application/x-7z-compressed', bytes(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00)],
    ['application/vnd.rar', bytes(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00)],
    ['application/vnd.rar', bytes(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00)],
    ['application/x-tar', tar()],
    ['application/vnd.ms-cab-compressed', text('MSCF\0\0\0\0')],
    ['application/x-ole-storage', bytes(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)],
    ['application/x-msdownload', text('MZ\x90\0')],
    ['application/x-elf', bytes(0x7f, 0x45, 0x4c, 0x46, 0x02)],
    ['application/x-mach-binary', bytes(0xfe, 0xed, 0xfa, 0xce)],
    ['application/x-mach-binary', bytes(0xfe, 0xed, 0xfa, 0xcf)],
    ['application/x-mach-binary', bytes(0xce, 0xfa, 0xed, 0xfe)],
    ['application/x-mach-binary', bytes(0xcf, 0xfa, 0xed, 0xfe)],
    ['application/x-mach-binary', bytes(0xca, 0xfe, 0xba, 0xbe)],
    ['application/x-ms-shortcut', bytes(0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00)],
    ['application/x-sh', text('#!/bin/sh\n')],
    ['text/rtf', text('{\\rtf1\\ansi')],
    ['image/png', bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)],
    ['image/jpeg', bytes(0xff, 0xd8, 0xff, 0xe0)],
    ['image/gif', text('GIF87a')],
    ['image/gif', text('GIF89a')],
    ['image/bmp', text('BM6\0')],
    ['image/webp', text('RIFF\x24\0\0\0WEBPVP8 ')],
    ['text/html', text('<!DOCTYPE html><html>')],
    ['text/html', text('\xEF\xBB\xBF \r\n\t<HTML lang="en">')],
    ['text/html', text('\xFF\xFE<html>')],
    ['application/octet-stream', text('plain text')],
    ['application/octet-stream', Buffer.alloc(0)],
    ['application/octet-stream', text('RIFF\x24\0\0\0WAVEfmt ')],
    ['application/octet-stream', text('<head><html>')],
  ];
  it.each(rows)('detects %s', (type, head) => {
    expect(sniffContentType(head)).toBe(type);
  });

  it('never reads beyond the bytes it is given', () => {
    expect(sniffContentType(text('%PD'))).toBe('application/octet-stream');
    expect(sniffContentType(Buffer.alloc(260))).toBe('application/octet-stream');
  });
});

describe('sniffFlags', () => {
  it('flags a mismatch only when the detected type is specific', () => {
    expect(sniffFlags('application/pdf', 'application/x-msdownload', 'a.pdf')).toEqual([
      'content_type_mismatch',
      'executable',
      'filename_extension_mismatch',
    ]);
    expect(sniffFlags('application/pdf', 'application/octet-stream', 'a.pdf')).toEqual([]);
    expect(sniffFlags('application/pdf', 'application/pdf', 'a.pdf')).toEqual([]);
  });

  it('treats container aliases and zip-based office formats as the same type', () => {
    expect(
      sniffFlags(
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/zip',
        'a.docx',
      ),
    ).toEqual(['archive']);
    expect(sniffFlags('application/x-zip-compressed', 'application/zip', 'a.zip')).toEqual([
      'archive',
    ]);
    expect(sniffFlags('application/msword', 'application/x-ole-storage', 'a.doc')).toEqual([]);
    expect(sniffFlags('image/jpg', 'image/jpeg', 'a.jpg')).toEqual([]);
  });

  it('flags executables, shortcuts and shell scripts, and archives', () => {
    for (const type of [
      'application/x-elf',
      'application/x-mach-binary',
      'application/x-ms-shortcut',
      'application/x-sh',
    ]) {
      expect(sniffFlags(type, type, null)).toEqual(['executable']);
    }
    for (const type of [
      'application/gzip',
      'application/x-7z-compressed',
      'application/vnd.rar',
      'application/x-tar',
    ]) {
      expect(sniffFlags(type, type, null)).toEqual(['archive']);
    }
  });

  it('flags an extension that disagrees with an executable or archive type', () => {
    expect(sniffFlags('application/zip', 'application/zip', 'invoice.pdf')).toEqual([
      'archive',
      'filename_extension_mismatch',
    ]);
    expect(sniffFlags('application/zip', 'application/zip', 'book.xlsx')).toEqual(['archive']);
    expect(sniffFlags('application/x-msdownload', 'application/x-msdownload', 'tool.exe')).toEqual([
      'executable',
    ]);
    expect(
      sniffFlags('application/x-ms-shortcut', 'application/x-ms-shortcut', 'photo.jpg'),
    ).toEqual(['executable', 'filename_extension_mismatch']);
    // No extension: nothing to disagree with.
    expect(sniffFlags('application/x-elf', 'application/x-elf', 'run')).toEqual(['executable']);
    // Not an executable or archive: the extension is not judged.
    expect(sniffFlags('image/png', 'image/png', 'a.txt')).toEqual([]);
  });
});
