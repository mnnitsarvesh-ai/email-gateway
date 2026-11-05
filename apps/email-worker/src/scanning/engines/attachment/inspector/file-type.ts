import {
  type FileTypeId,
  fileType,
  fileTypeIdForExtension,
} from '@email-gateway/security-contracts';
import type { ContentType } from '../content';

/**
 * True-type detection of the inspector (step 4.2 A5): magic bytes and structure, most specific
 * first, over an in-memory buffer. Pure functions; nothing here reads a filename except the
 * extension helper used for archive entries (the name itself is never kept).
 *
 * Scripts have no magic: a bounded UTF-8/ASCII check yields `text` (or a markup type), and the
 * verdict mapper refines `text` by the attachment's extension outside the cache (`textLike`).
 */

const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const LNK_HEADER = Buffer.from([
  0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x46,
]);
/** CLSID of a Windows Installer database {000C1084-0000-0000-C000-000000000046} (root entry). */
const MSI_CLSIDS = [
  Buffer.from([
    0x84, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
  ]),
  // Patch package {000C1086-…} and merge module / transform {000C1082-…}.
  Buffer.from([
    0x86, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
  ]),
  Buffer.from([
    0x82, 0x10, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
  ]),
];
/** UTF-16LE `_VBA_PROJECT` (the VBA storage of an OLE Office file). */
const OLE_VBA_MARKER = Buffer.from('_VBA_PROJECT', 'utf16le');
/** Bytes examined by the text check (bounded, A5). */
const TEXT_SAMPLE_BYTES = 65_536;
/** Bytes searched for markup markers. */
const MARKUP_SAMPLE_BYTES = 4_096;

const startsWith = (bytes: Uint8Array, magic: readonly number[], offset = 0): boolean => {
  if (bytes.length < offset + magic.length) return false;
  for (let i = 0; i < magic.length; i += 1) if (bytes[offset + i] !== magic[i]) return false;
  return true;
};

const ascii = (text: string): number[] => [...Buffer.from(text, 'latin1')];

/** `MZ` and a valid `e_lfanew` pointing at `PE\0\0` (A5: `MZ` alone is not a PE). */
export function isPortableExecutable(bytes: Buffer): boolean {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return false;
  const lfanew = bytes.readUInt32LE(0x3c);
  if (lfanew < 0x40 || lfanew > bytes.length - 4 || lfanew > 0x10_0000) return false;
  return startsWith(bytes, [0x50, 0x45, 0x00, 0x00], lfanew);
}

function isMachO(bytes: Buffer): boolean {
  if (bytes.length < 8) return false;
  const magic = bytes.readUInt32BE(0);
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic)) return true;
  // Universal binary (0xCAFEBABE) vs Java class (same magic): a fat header has few archs, a
  // class file has a large major version in the same position.
  return magic === 0xcafebabe && bytes.readUInt32BE(4) > 0 && bytes.readUInt32BE(4) < 30;
}

function isIso(bytes: Buffer): boolean {
  const cd001 = ascii('CD001');
  return [0x8001, 0x8801, 0x9001].some((offset) => startsWith(bytes, cd001, offset));
}

function isVhd(bytes: Buffer): boolean {
  if (startsWith(bytes, ascii('vhdxfile'))) return true;
  if (startsWith(bytes, ascii('conectix'))) return true;
  return bytes.length >= 512 && startsWith(bytes, ascii('conectix'), bytes.length - 512);
}

/** Root directory entry CLSID of an OLE compound file (MSI detection). */
function oleRootClsid(bytes: Buffer): Buffer | null {
  if (bytes.length < 512) return null;
  const sectorShift = bytes.readUInt16LE(0x1e);
  if (sectorShift !== 9 && sectorShift !== 12) return null;
  const sectorSize = 1 << sectorShift;
  const firstDirSector = bytes.readUInt32LE(0x30);
  if (firstDirSector >= 0xfffffffa) return null;
  const offset = (firstDirSector + 1) * sectorSize;
  if (offset + 0x60 > bytes.length) return null;
  return bytes.subarray(offset + 0x50, offset + 0x60);
}

/** OLE compound file with a `_VBA_PROJECT` stream name (A4 office macro marker). */
export function oleHasVba(bytes: Buffer): boolean {
  return bytes.includes(OLE_VBA_MARKER);
}

/** Bounded UTF-8 text check: valid UTF-8, no NUL, few control characters (A5). */
export function isTextLike(bytes: Buffer): boolean {
  if (bytes.length === 0) return false;
  let sample = bytes.subarray(0, TEXT_SAMPLE_BYTES);
  if (bytes.length > TEXT_SAMPLE_BYTES) {
    // Do not cut a multi-byte sequence at the sample edge.
    let end = sample.length;
    while (end > sample.length - 4 && end > 0 && (sample[end - 1]! & 0xc0) === 0x80) end -= 1;
    if (end > 0 && sample[end - 1]! >= 0xc0) end -= 1;
    sample = sample.subarray(0, end);
  }
  let control = 0;
  for (const byte of sample) {
    if (byte === 0) return false;
    if (byte < 0x09 || (byte > 0x0d && byte < 0x20 && byte !== 0x1b)) control += 1;
  }
  if (control * 100 > sample.length) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(sample);
    return true;
  } catch {
    return false;
  }
}

function markupType(bytes: Buffer): FileTypeId | null {
  const head = bytes
    .subarray(0, MARKUP_SAMPLE_BYTES)
    .toString('utf8')
    .replace(/^\uFEFF/, '')
    .toLowerCase();
  const start = head.trimStart();
  if (start.startsWith('#!')) {
    const line = start.slice(0, start.indexOf('\n') >>> 0);
    if (/^#!\s*\/(usr\/)?(local\/)?bin\/(env\s+)?(ba|z|k|da)?sh\b/.test(line))
      return 'script_shell';
  }
  if (head.includes('<hta:application')) return 'hta';
  if (start.startsWith('<!doctype html') || /<html[\s>]/.test(head)) return 'html';
  if (/<svg[\s>]/.test(head)) return 'svg';
  if (start.startsWith('<?xml')) return 'xml';
  if (start.startsWith('begin:vcalendar')) return 'ics';
  if (start.startsWith('{\\rtf')) return 'rtf';
  const headerLines = start
    .split(/\r?\n/, 40)
    .filter((line) =>
      /^(from|to|subject|date|mime-version|message-id|received|return-path):/.test(line),
    );
  if (headerLines.length >= 3 && /\r?\n\r?\n/.test(start)) return 'eml';
  return null;
}

/**
 * The type of `bytes` from its magic numbers alone (zip containers are `zip` here; the walker
 * sub-types them from their entry names, `subtypeZip`).
 */
export function detectMagic(bytes: Buffer): FileTypeId {
  if (bytes.length === 0) return 'unknown';
  // Magic at offset 0 first: a zip or gzip may carry `%PDF-` of a stored member in its first KiB.
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06]))
    return 'zip';
  if (startsWith(bytes, [0x50, 0x4b, 0x07, 0x08])) return 'zip';
  if (startsWith(bytes, [0x1f, 0x8b])) return 'gzip';
  if (startsWith(bytes, ascii('%PDF-'))) return 'pdf';
  if (startsWith(bytes, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return '7z';
  if (startsWith(bytes, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return 'rar';
  if (startsWith(bytes, ascii('MSCF')) && bytes.length >= 36 && bytes.readUInt32LE(4) === 0)
    return 'cab';
  if (startsWith(bytes, ascii('BZh')) && bytes[3]! >= 0x31 && bytes[3]! <= 0x39) return 'bzip2';
  if (startsWith(bytes, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return 'xz';
  if (startsWith(bytes, ascii('ustar'), 257)) return 'tar';
  if (startsWith(bytes, [...OLE_MAGIC])) {
    const clsid = oleRootClsid(bytes);
    return clsid && MSI_CLSIDS.some((c) => c.equals(clsid)) ? 'msi' : 'ole_office';
  }
  if (isPortableExecutable(bytes)) return 'pe_executable';
  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) return 'elf';
  if (isMachO(bytes)) return 'macho';
  if (startsWith(bytes, [...LNK_HEADER])) return 'lnk';
  if (startsWith(bytes, ascii('ITSF'))) return 'chm';
  if (startsWith(bytes, ascii('{\\rtf'))) return 'rtf';
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'png';
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'jpeg';
  if (startsWith(bytes, ascii('GIF87a')) || startsWith(bytes, ascii('GIF89a'))) return 'gif';
  if (startsWith(bytes, ascii('RIFF')) && startsWith(bytes, ascii('WEBP'), 8)) return 'webp';
  if (startsWith(bytes, [0x49, 0x49, 0x2a, 0x00]) || startsWith(bytes, [0x4d, 0x4d, 0x00, 0x2a]))
    return 'tiff';
  if (
    startsWith(bytes, ascii('BM')) &&
    bytes.length >= 26 &&
    bytes.readUInt32LE(6) === 0 &&
    bytes.readUInt32LE(2) === bytes.length
  )
    return 'bmp';
  // PDF readers accept the header anywhere in the first KiB.
  if (bytes.subarray(0, 1024).includes(Buffer.from('%PDF-', 'latin1'))) return 'pdf';
  if (isIso(bytes)) return 'iso';
  if (isVhd(bytes)) return 'vhd';
  if (isTextLike(bytes)) return markupType(bytes) ?? 'text';
  return 'unknown';
}

/** What the walker learned about a zip container's first level (names are not kept). */
export interface ZipNames {
  hasContentTypes: boolean;
  hasWord: boolean;
  hasExcel: boolean;
  hasPowerPoint: boolean;
  hasVbaProject: boolean;
  hasManifest: boolean;
  hasAndroidManifest: boolean;
  /** The stored `mimetype` entry starts with `application/vnd.oasis.opendocument`. */
  odfMimetype: boolean;
  hasOdfBasic: boolean;
}

export const emptyZipNames = (): ZipNames => ({
  hasContentTypes: false,
  hasWord: false,
  hasExcel: false,
  hasPowerPoint: false,
  hasVbaProject: false,
  hasManifest: false,
  hasAndroidManifest: false,
  odfMimetype: false,
  hasOdfBasic: false,
});

/** Records one entry name into `names` (the name itself is dropped by the caller). */
export function noteZipName(names: ZipNames, name: string): void {
  if (name === '[Content_Types].xml') names.hasContentTypes = true;
  else if (name.startsWith('word/')) names.hasWord = true;
  else if (name.startsWith('xl/')) names.hasExcel = true;
  else if (name.startsWith('ppt/')) names.hasPowerPoint = true;
  else if (name === 'META-INF/MANIFEST.MF') names.hasManifest = true;
  else if (name === 'AndroidManifest.xml') names.hasAndroidManifest = true;
  else if (name.startsWith('Basic/')) names.hasOdfBasic = true;
  if (name.endsWith('vbaProject.bin')) names.hasVbaProject = true;
}

/** Zip sub-typing by first-level entry names (A5), most specific first. */
export function subtypeZip(names: ZipNames): FileTypeId {
  if (names.hasAndroidManifest) return 'apk';
  if (names.hasContentTypes && (names.hasWord || names.hasExcel || names.hasPowerPoint)) {
    if (names.hasVbaProject) return 'ooxml_macro';
    if (names.hasWord) return 'ooxml_word';
    if (names.hasExcel) return 'ooxml_excel';
    return 'ooxml_powerpoint';
  }
  if (names.odfMimetype) return 'odf';
  if (names.hasManifest) return 'jar';
  return 'zip';
}

/** The content type facts of a detected id. */
export function contentType(detected: FileTypeId, textLike: boolean): ContentType {
  const definition = fileType(detected);
  return {
    detected,
    family: definition.family,
    executable: definition.executable,
    textLike,
  };
}

/** Types whose content the text check accepted (eligible for refinement by extension). */
export const TEXT_LIKE_TYPES: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'text',
  'html',
  'svg',
  'xml',
  'ics',
  'eml',
  'rtf',
  'hta',
  'script_shell',
]);

/**
 * The extension-implied type of a name (archive entries; the attachment's own extension comes
 * from its sanitized filename in the worker). Lower-case extension of the last segment, or null.
 */
export function extensionTypeOfName(name: string): FileTypeId | null {
  const base = name.slice(Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\')) + 1);
  const dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) return null;
  const extension = base.slice(dot + 1);
  if (extension.length > 16) return null;
  return fileTypeIdForExtension(extension);
}

/**
 * Text refined by an extension (A5: scripts are typed by their extension): a text-like file
 * named `.js`, `.vbs`, `.ps1`, `.bat`, `.sh`, `.hta`, `.html`, … takes that type. Every other
 * detection stays as detected.
 */
export function refineTextType(detected: FileTypeId, extensionType: FileTypeId | null): FileTypeId {
  if (detected !== 'text' || extensionType === null) return detected;
  const family = fileType(extensionType).family;
  return family === 'script' || family === 'markup' ? extensionType : detected;
}
