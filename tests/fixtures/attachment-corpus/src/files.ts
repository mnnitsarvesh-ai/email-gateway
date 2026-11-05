import { zip } from './zip';

/**
 * Single (non-archive) test files: harmless type stubs, YARA markers, size-class files and the
 * samples of the bundled YARA heuristics (apps/email-worker/yara). Nothing here is executable
 * code: the PE stub has headers only, the scripts are inert text.
 */

const PAD = (size: number, fill = 0x00) => Buffer.alloc(Math.max(size, 0), fill);

function sized(header: Buffer, size: number): Buffer {
  if (size < header.length) throw new RangeError(`size must be >= ${header.length}`);
  return Buffer.concat([header, PAD(size - header.length)]);
}

/** 7-Zip signature header (`7z\xBC\xAF\x27\x1C`, version 0.4) and padding: not a usable archive. */
export function fake7z(size = 512): Buffer {
  return sized(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04]), size);
}

/** RAR 5 signature (`Rar!\x1A\x07\x01\x00`) and padding. */
export function fakeRar(size = 512): Buffer {
  return sized(Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00]), size);
}

/** xz stream header magic (`\xFD7zXZ\0`) and padding. */
export function fakeXz(size = 512): Buffer {
  return sized(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04]), size);
}

/** bzip2 stream (`BZh9`) with a block magic (`1AY&SY`) and padding. */
export function fakeBzip2(size = 512): Buffer {
  return sized(Buffer.from('BZh91AY&SY', 'latin1'), size);
}

/** Microsoft Cabinet header (`MSCF`, reserved, size fields) and padding. */
export function fakeCab(size = 512): Buffer {
  const header = Buffer.alloc(36);
  header.write('MSCF', 0, 'latin1');
  header.writeUInt32LE(size, 8);
  header.writeUInt8(3, 24); // version minor
  header.writeUInt8(1, 25); // version major
  header.writeUInt16LE(1, 26); // folders
  header.writeUInt16LE(1, 28); // files
  return sized(header, size);
}

/** Magic of an OLE compound file (legacy Office, MSI, vbaProject.bin). */
export const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);

/**
 * A harmless PE stub: a DOS header (`MZ`) whose `e_lfanew` (0x3C) points at `PE\0\0` and an
 * i386 COFF header with zero sections and no code. Detected as `pe_executable`; used for
 * "exe renamed to pdf" (`type.executable_disguised`).
 */
export function peStub(size = 1024): Buffer {
  const buffer = PAD(Math.max(size, 0x80 + 24));
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt16LE(0x90, 2); // bytes on last page
  buffer.writeUInt16LE(3, 4); // pages
  buffer.writeUInt32LE(0x80, 0x3c); // e_lfanew
  buffer.write('PE\0\0', 0x80, 'latin1');
  buffer.writeUInt16LE(0x014c, 0x84); // machine i386
  buffer.writeUInt16LE(0, 0x86); // number of sections
  buffer.writeUInt16LE(0, 0x94); // size of optional header
  buffer.writeUInt16LE(0x0102, 0x96); // characteristics: executable, 32-bit
  return buffer;
}

/** `MZ` without a valid `PE\0\0` target (must not be detected as a PE). */
export function mzWithoutPe(size = 256): Buffer {
  const buffer = PAD(size);
  buffer.write('MZ', 0, 'latin1');
  buffer.writeUInt32LE(0x40, 0x3c);
  buffer.write('XX\0\0', 0x40, 'latin1');
  return buffer;
}

/** Markers of the bundled YARA test rules (apps/email-worker/yara/rules/eg-test-markers.yar). */
export const YARA_TEST_MARKERS = {
  high: ['EG-YARA-TEST-', 'HIGH-5f0c2e7a'].join(''),
  medium: ['EG-YARA-TEST-', 'MEDIUM-8d41b9c3'].join(''),
} as const;

/** A text file that matches `EG_Test_Marker_High` (severity high → `yara.high`, malicious). */
export function yaraHigh(): Buffer {
  return Buffer.from(`Quarterly figures\n${YARA_TEST_MARKERS.high}\nEnd of report\n`, 'utf8');
}

/** A text file that matches `EG_Test_Marker_Medium` (severity medium → `yara.medium`). */
export function yaraMedium(): Buffer {
  return Buffer.from(`Meeting notes\n${YARA_TEST_MARKERS.medium}\n`, 'utf8');
}

/** Deterministic pseudo-random bytes (xorshift32): incompressible filler, stable hashes. */
export function pseudoRandom(size: number, seed = 0x9e3779b9): Buffer {
  const buffer = Buffer.allocUnsafe(size);
  let x = seed >>> 0 || 1;
  let i = 0;
  for (; i + 4 <= size; i += 4) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    buffer.writeUInt32LE(x, i);
  }
  for (; i < size; i += 1) buffer[i] = (i * 31) & 0xff;
  return buffer;
}

/**
 * A PDF-looking file of exactly `size` bytes: header, one stream object of filler, xref-free
 * trailer and `%%EOF`. Not a renderable PDF; type detection sees `pdf`.
 */
export function pdfLike(size = 64 * 1024, seed = 1): Buffer {
  const head = Buffer.from(
    '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Length 0 >>\nstream\n',
    'latin1',
  );
  const tail = Buffer.from('\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n', 'latin1');
  if (size < head.length + tail.length) {
    throw new RangeError(`size must be >= ${head.length + tail.length}`);
  }
  return Buffer.concat([head, pseudoRandom(size - head.length - tail.length, seed), tail]);
}

/** A PDF-like file cut in the middle (truncated PDF: definite result, ClamAV decides). */
export function truncatedPdf(size = 64 * 1024): Buffer {
  return pdfLike(size).subarray(0, Math.floor(size / 2));
}

/** `size` bytes of incompressible data with no recognizable type (`unknown`). */
export function largeFile(size: number, seed = 7): Buffer {
  return pseudoRandom(size, seed);
}

const CONTENT_TYPES_DOCX =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Default Extension="xml" ContentType="application/xml"/>' +
  '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>' +
  '</Types>';
const CONTENT_TYPES_DOCM =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
  '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>' +
  '<Default Extension="xml" ContentType="application/xml"/>' +
  '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>' +
  '<Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>' +
  '</Types>';
const ROOT_RELS =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
  '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>' +
  '</Relationships>';
const DOCUMENT_XML =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
  '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
  '<w:body><w:p><w:r><w:t>Generated test document</w:t></w:r></w:p></w:body></w:document>';

/** Relationship part of an OOXML external template injection (remote `attachedTemplate`). */
export function ooxmlTemplateInjectionRels(url = 'https://templates.example.test/t.dotm'): Buffer {
  return Buffer.from(
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' +
      '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
      `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="${url}" TargetMode="External"/>` +
      '</Relationships>',
    'utf8',
  );
}

/** A minimal docx-like OOXML zip (`[Content_Types].xml`, `_rels/.rels`, `word/document.xml`). */
export async function docxLike(): Promise<Buffer> {
  return zip([
    { name: '[Content_Types].xml', data: Buffer.from(CONTENT_TYPES_DOCX) },
    { name: '_rels/.rels', data: Buffer.from(ROOT_RELS) },
    { name: 'word/document.xml', data: Buffer.from(DOCUMENT_XML) },
  ]);
}

/** A docm-like OOXML zip with `word/vbaProject.bin` (an OLE header stub, no macro code). */
export async function docmLike(): Promise<Buffer> {
  return zip([
    { name: '[Content_Types].xml', data: Buffer.from(CONTENT_TYPES_DOCM) },
    { name: '_rels/.rels', data: Buffer.from(ROOT_RELS) },
    { name: 'word/document.xml', data: Buffer.from(DOCUMENT_XML) },
    { name: 'word/vbaProject.bin', data: Buffer.concat([OLE_MAGIC, PAD(504)]) },
  ]);
}

/** A docx-like zip whose settings relationships load a remote template (template injection). */
export async function docxTemplateInjection(): Promise<Buffer> {
  return zip([
    { name: '[Content_Types].xml', data: Buffer.from(CONTENT_TYPES_DOCX) },
    { name: '_rels/.rels', data: Buffer.from(ROOT_RELS) },
    { name: 'word/document.xml', data: Buffer.from(DOCUMENT_XML) },
    { name: 'word/_rels/settings.xml.rels', data: ooxmlTemplateInjectionRels() },
  ]);
}

/**
 * An HTML smuggling sample: a script that decodes a large base64 blob and saves it through
 * `msSaveOrOpenBlob` / `URL.createObjectURL` + a download link. The blob is filler, not a payload.
 */
export function htmlSmuggling(blobBytes = 12 * 1024): Buffer {
  const blob = pseudoRandom(blobBytes, 3).toString('base64');
  return Buffer.from(
    '<!doctype html><html><body><script>\n' +
      `var d = "${blob}";\n` +
      'var b = atob(d); var u = new Uint8Array(b.length);\n' +
      'for (var i = 0; i < b.length; i++) { u[i] = b.charCodeAt(i); }\n' +
      'var f = new Blob([u], { type: "application/octet-stream" });\n' +
      'if (window.navigator.msSaveOrOpenBlob) { window.navigator.msSaveOrOpenBlob(f, "invoice.iso"); }\n' +
      'else { var a = document.createElement("a"); a.href = URL.createObjectURL(f);\n' +
      'a.download = "invoice.iso"; document.body.appendChild(a); a.click(); }\n' +
      '</script></body></html>\n',
    'utf8',
  );
}

/** A plain HTML page with a script and no blob saving (must not match the smuggling rule). */
export function cleanHtml(): Buffer {
  return Buffer.from(
    '<!doctype html><html><body><p>Hello</p><script>console.log("ready")</script></body></html>\n',
  );
}

/** An inert batch line launching PowerShell with an encoded command (base64 of UTF-16LE text). */
export function powershellEncoded(): Buffer {
  const command = Buffer.from('Write-Output "eg corpus test"', 'utf16le').toString('base64');
  return Buffer.from(
    `@echo off\r\npowershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand ${command}\r\n`,
    'latin1',
  );
}

/**
 * A Windows shortcut (MS-SHLLINK header: size 0x4C, LinkCLSID 00021401-…-46) whose string data
 * names `C:\Windows\System32\cmd.exe` as target with inert arguments. Not a working shortcut.
 */
export function lnkWithCommandTarget(target = 'C:\\Windows\\System32\\cmd.exe'): Buffer {
  const header = Buffer.alloc(0x4c);
  header.writeUInt32LE(0x4c, 0);
  Buffer.from([
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
  ]).copy(header, 4);
  header.writeUInt32LE(0x000000a0, 0x14); // LinkFlags: HasArguments | IsUnicode (illustrative)
  const strings = Buffer.from(`${target}\0/c echo eg corpus test\0`, 'utf16le');
  return Buffer.concat([header, strings, PAD(64)]);
}
