import type { AttachmentFlag } from './constants';
import { finalExtension } from './filename';
import type { ArchiveSummary } from './types';

/** Bytes of each part kept for sniffing (design M9); the only buffering per part. */
export const SNIFF_BYTES = 4096;

type Signature = { offset: number; bytes: readonly number[] };

const ascii = (text: string): number[] => [...text].map((char) => char.charCodeAt(0));

/** The fixed table of design M9, most specific signatures first. */
const SIGNATURES: readonly { type: string; any: readonly Signature[] }[] = [
  { type: 'application/pdf', any: [{ offset: 0, bytes: ascii('%PDF-') }] },
  {
    type: 'application/zip',
    any: [
      { offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
      { offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
      { offset: 0, bytes: [0x50, 0x4b, 0x07, 0x08] },
    ],
  },
  { type: 'application/gzip', any: [{ offset: 0, bytes: [0x1f, 0x8b] }] },
  { type: 'application/x-bzip2', any: [{ offset: 0, bytes: ascii('BZh') }] },
  { type: 'application/x-xz', any: [{ offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] }] },
  {
    type: 'application/x-7z-compressed',
    any: [{ offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] }],
  },
  {
    type: 'application/vnd.rar',
    any: [
      { offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00] },
      { offset: 0, bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00] },
    ],
  },
  { type: 'application/x-tar', any: [{ offset: 257, bytes: ascii('ustar') }] },
  { type: 'application/vnd.ms-cab-compressed', any: [{ offset: 0, bytes: ascii('MSCF') }] },
  {
    type: 'application/x-ole-storage',
    any: [{ offset: 0, bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] }],
  },
  {
    type: 'application/x-ms-shortcut',
    any: [{ offset: 0, bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] }],
  },
  { type: 'application/x-elf', any: [{ offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] }] },
  {
    type: 'application/x-mach-binary',
    any: [
      { offset: 0, bytes: [0xfe, 0xed, 0xfa, 0xce] },
      { offset: 0, bytes: [0xfe, 0xed, 0xfa, 0xcf] },
      { offset: 0, bytes: [0xce, 0xfa, 0xed, 0xfe] },
      { offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
      { offset: 0, bytes: [0xca, 0xfe, 0xba, 0xbe] },
    ],
  },
  {
    type: 'image/png',
    any: [{ offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] }],
  },
  { type: 'image/jpeg', any: [{ offset: 0, bytes: [0xff, 0xd8, 0xff] }] },
  {
    type: 'image/gif',
    any: [
      { offset: 0, bytes: ascii('GIF87a') },
      { offset: 0, bytes: ascii('GIF89a') },
    ],
  },
  { type: 'text/rtf', any: [{ offset: 0, bytes: ascii('{\\rtf') }] },
  { type: 'application/x-msdownload', any: [{ offset: 0, bytes: ascii('MZ') }] },
  { type: 'application/x-sh', any: [{ offset: 0, bytes: ascii('#!') }] },
  { type: 'image/bmp', any: [{ offset: 0, bytes: ascii('BM') }] },
];

function matches(head: Buffer, signature: Signature): boolean {
  if (head.length < signature.offset + signature.bytes.length) return false;
  return signature.bytes.every((byte, index) => head[signature.offset + index] === byte);
}

function isWebp(head: Buffer): boolean {
  return (
    head.length >= 12 &&
    head.toString('latin1', 0, 4) === 'RIFF' &&
    head.toString('latin1', 8, 12) === 'WEBP'
  );
}

function isHtml(head: Buffer): boolean {
  let text = head.toString('latin1', 0, Math.min(head.length, 1024));
  if (text.startsWith('\xEF\xBB\xBF')) text = text.slice(3);
  else if (text.startsWith('\xFF\xFE') || text.startsWith('\xFE\xFF')) text = text.slice(2);
  text = text.replace(/^[\t\n\f\r ]+/, '').toLowerCase();
  return text.startsWith('<!doctype html') || text.startsWith('<html');
}

/** Content type from magic bytes over the first 4 KiB (design M9); never trusts a declaration. */
export function sniffContentType(head: Buffer): string {
  for (const entry of SIGNATURES) {
    if (entry.any.some((signature) => matches(head, signature))) return entry.type;
  }
  if (isWebp(head)) return 'image/webp';
  if (isHtml(head)) return 'text/html';
  return 'application/octet-stream';
}

export const EXECUTABLE_TYPES: ReadonlySet<string> = new Set([
  'application/x-msdownload',
  'application/x-elf',
  'application/x-mach-binary',
  'application/x-ms-shortcut',
  'application/x-sh',
]);

/** Archive types and their `archive_info.type`. */
export const ARCHIVE_TYPES: ReadonlyMap<string, ArchiveSummary['type']> = new Map([
  ['application/zip', 'zip'],
  ['application/gzip', 'gzip'],
  ['application/x-bzip2', 'bzip2'],
  ['application/x-xz', 'xz'],
  ['application/x-7z-compressed', '7z'],
  ['application/vnd.rar', 'rar'],
  ['application/x-tar', 'tar'],
  ['application/vnd.ms-cab-compressed', 'cab'],
]);

/**
 * Declared types that are the same container as a sniffed type (OOXML and other zip-based
 * formats, OLE documents, common aliases), so `content_type_mismatch` marks real disagreement.
 */
const EQUIVALENT_DECLARED: ReadonlyMap<string, string> = new Map([
  ['application/x-zip-compressed', 'application/zip'],
  ['application/x-zip', 'application/zip'],
  ['application/java-archive', 'application/zip'],
  ['application/x-java-archive', 'application/zip'],
  ['application/epub+zip', 'application/zip'],
  ['application/vnd.android.package-archive', 'application/zip'],
  ['application/x-gzip', 'application/gzip'],
  ['application/gzip-compressed', 'application/gzip'],
  ['application/x-gtar', 'application/x-tar'],
  ['application/x-rar-compressed', 'application/vnd.rar'],
  ['application/x-rar', 'application/vnd.rar'],
  ['application/x-cab-compressed', 'application/vnd.ms-cab-compressed'],
  ['application/msword', 'application/x-ole-storage'],
  ['application/vnd.ms-excel', 'application/x-ole-storage'],
  ['application/vnd.ms-powerpoint', 'application/x-ole-storage'],
  ['application/vnd.ms-outlook', 'application/x-ole-storage'],
  ['application/x-msi', 'application/x-ole-storage'],
  ['application/x-pdf', 'application/pdf'],
  ['application/rtf', 'text/rtf'],
  ['application/x-rtf', 'text/rtf'],
  ['application/x-dosexec', 'application/x-msdownload'],
  ['application/x-msdos-program', 'application/x-msdownload'],
  ['application/x-ms-dos-executable', 'application/x-msdownload'],
  ['application/x-executable', 'application/x-elf'],
  ['application/x-shellscript', 'application/x-sh'],
  ['text/x-shellscript', 'application/x-sh'],
  ['text/x-sh', 'application/x-sh'],
  ['image/jpg', 'image/jpeg'],
  ['image/pjpeg', 'image/jpeg'],
  ['image/x-png', 'image/png'],
  ['image/x-ms-bmp', 'image/bmp'],
  ['image/x-bmp', 'image/bmp'],
]);

function canonicalDeclared(declared: string): string {
  if (
    declared.startsWith('application/vnd.openxmlformats-officedocument.') ||
    declared.startsWith('application/vnd.oasis.opendocument.') ||
    declared.startsWith('application/vnd.ms-excel.sheet.') ||
    declared.startsWith('application/vnd.ms-word.') ||
    declared.startsWith('application/vnd.ms-powerpoint.')
  ) {
    return 'application/zip';
  }
  return EQUIVALENT_DECLARED.get(declared) ?? declared;
}

/** Extensions consistent with an executable or archive type (`filename_extension_mismatch`). */
const EXPECTED_EXTENSIONS: ReadonlyMap<string, ReadonlySet<string>> = new Map(
  (
    [
      [
        'application/zip',
        'zip docx docm dotx xlsx xlsm xltx pptx pptm potx ppsx odt ods odp odg jar apk epub xpi msix appx ipa kmz vsdx war ear aar nupkg whl',
      ],
      ['application/gzip', 'gz tgz gzip'],
      ['application/x-bzip2', 'bz2 bz tbz tbz2'],
      ['application/x-xz', 'xz txz'],
      ['application/x-7z-compressed', '7z'],
      ['application/vnd.rar', 'rar'],
      ['application/x-tar', 'tar'],
      ['application/vnd.ms-cab-compressed', 'cab'],
      ['application/x-msdownload', 'exe dll scr com cpl sys ocx drv efi mui ax'],
      ['application/x-elf', 'so elf bin o out run'],
      ['application/x-mach-binary', 'dylib bundle o class'],
      ['application/x-ms-shortcut', 'lnk'],
      ['application/x-sh', 'sh bash ksh zsh csh command run'],
    ] as const
  ).map(([type, list]) => [type, new Set(list.split(' '))]),
);

/** Sniff flags of design M9 for one attachment. */
export function sniffFlags(
  declared: string,
  detected: string,
  filename: string | null,
): AttachmentFlag[] {
  const flags: AttachmentFlag[] = [];
  if (detected !== 'application/octet-stream' && canonicalDeclared(declared) !== detected) {
    flags.push('content_type_mismatch');
  }
  if (EXECUTABLE_TYPES.has(detected)) flags.push('executable');
  if (ARCHIVE_TYPES.has(detected)) flags.push('archive');
  const expected = EXPECTED_EXTENSIONS.get(detected);
  const extension = finalExtension(filename);
  if (expected !== undefined && extension !== null && !expected.has(extension)) {
    flags.push('filename_extension_mismatch');
  }
  return flags;
}
