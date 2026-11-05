import { z } from 'zod';

/**
 * The true-file-type vocabulary of the attachment engine (docs/plan/steps/10-attachment-scanning.md
 * A5). Data only: the email-worker's inspector detects these ids from magic bytes and structure,
 * the verdict mapper compares them with the declared content type and the filename extension, and
 * the api validates tenant allow/deny lists against them.
 *
 * - `family` drives the mismatch rule (`type.mismatch`: the detected family differs from the
 *   family the extension or a specific declared content type implies);
 * - `executable` marks types that carry code a user can run (executables, installers, scripts,
 *   Java/Android packages, compiled help);
 * - `extensions` (lower-case, without the dot) are the extensions that legitimately carry the
 *   type, `mimeTypes` (lower-case, no parameters) its content types. Every extension and every
 *   content type belongs to at most one type, so each maps back to exactly one id.
 */

export const FILE_TYPE_FAMILIES = [
  'document',
  'archive',
  'executable',
  'script',
  'disk_image',
  'image',
  'markup',
  'text',
  'other',
] as const;
export type FileTypeFamily = (typeof FILE_TYPE_FAMILIES)[number];
export const fileTypeFamilySchema = z.enum(FILE_TYPE_FAMILIES);

export interface FileTypeDefinition {
  readonly id: string;
  readonly family: FileTypeFamily;
  readonly executable: boolean;
  readonly extensions: readonly string[];
  readonly mimeTypes: readonly string[];
  readonly description: string;
}

const type = <const I extends string>(
  id: I,
  family: FileTypeFamily,
  executable: boolean,
  extensions: readonly string[],
  mimeTypes: readonly string[],
  description: string,
) =>
  Object.freeze({
    id,
    family,
    executable,
    extensions: Object.freeze([...extensions]),
    mimeTypes: Object.freeze([...mimeTypes]),
    description,
  });

const OOXML = 'application/vnd.openxmlformats-officedocument';
const ODF = 'application/vnd.oasis.opendocument';

/** The vocabulary, most specific first within each family (the order of `FILE_TYPE_IDS`). */
export const FILE_TYPES = Object.freeze([
  // Documents.
  type('pdf', 'document', false, ['pdf'], ['application/pdf'], 'PDF document'),
  type(
    'ooxml_word',
    'document',
    false,
    ['docx', 'dotx'],
    [`${OOXML}.wordprocessingml.document`, `${OOXML}.wordprocessingml.template`],
    'Office Open XML word processing document (no macros)',
  ),
  type(
    'ooxml_excel',
    'document',
    false,
    ['xlsx', 'xltx'],
    [`${OOXML}.spreadsheetml.sheet`, `${OOXML}.spreadsheetml.template`],
    'Office Open XML spreadsheet (no macros)',
  ),
  type(
    'ooxml_powerpoint',
    'document',
    false,
    ['pptx', 'potx', 'ppsx'],
    [
      `${OOXML}.presentationml.presentation`,
      `${OOXML}.presentationml.template`,
      `${OOXML}.presentationml.slideshow`,
    ],
    'Office Open XML presentation (no macros)',
  ),
  type(
    'ooxml_macro',
    'document',
    false,
    ['docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'potm', 'ppsm'],
    [
      'application/vnd.ms-word.document.macroenabled.12',
      'application/vnd.ms-word.template.macroenabled.12',
      'application/vnd.ms-excel.sheet.macroenabled.12',
      'application/vnd.ms-excel.template.macroenabled.12',
      'application/vnd.ms-excel.addin.macroenabled.12',
      'application/vnd.ms-powerpoint.presentation.macroenabled.12',
      'application/vnd.ms-powerpoint.template.macroenabled.12',
      'application/vnd.ms-powerpoint.slideshow.macroenabled.12',
    ],
    'Office Open XML document with a VBA project (docm, xlsm, pptm)',
  ),
  type(
    'odf',
    'document',
    false,
    ['odt', 'ods', 'odp', 'odg'],
    [`${ODF}.text`, `${ODF}.spreadsheet`, `${ODF}.presentation`, `${ODF}.graphics`],
    'OpenDocument file',
  ),
  type(
    'ole_office',
    'document',
    false,
    ['doc', 'dot', 'xls', 'xlt', 'ppt', 'pot', 'pps', 'msg'],
    [
      'application/msword',
      'application/vnd.ms-excel',
      'application/vnd.ms-powerpoint',
      'application/vnd.ms-outlook',
    ],
    'Legacy OLE compound Office document or Outlook message',
  ),
  type('rtf', 'document', false, ['rtf'], ['application/rtf', 'text/rtf'], 'Rich Text Format'),
  type(
    'chm',
    'document',
    true,
    ['chm'],
    ['application/vnd.ms-htmlhelp'],
    'Compiled HTML Help (can run scripts)',
  ),
  // Archives and packages.
  type(
    'zip',
    'archive',
    false,
    ['zip'],
    ['application/zip', 'application/x-zip-compressed'],
    'ZIP archive',
  ),
  type(
    'gzip',
    'archive',
    false,
    ['gz', 'tgz'],
    ['application/gzip', 'application/x-gzip'],
    'gzip stream',
  ),
  type('tar', 'archive', false, ['tar'], ['application/x-tar'], 'tar archive'),
  type('7z', 'archive', false, ['7z'], ['application/x-7z-compressed'], '7-Zip archive'),
  type(
    'rar',
    'archive',
    false,
    ['rar'],
    ['application/vnd.rar', 'application/x-rar-compressed'],
    'RAR archive',
  ),
  type('cab', 'archive', false, ['cab'], ['application/vnd.ms-cab-compressed'], 'Cabinet archive'),
  type('bzip2', 'archive', false, ['bz2', 'tbz2'], ['application/x-bzip2'], 'bzip2 stream'),
  type('xz', 'archive', false, ['xz', 'txz'], ['application/x-xz'], 'xz stream'),
  type(
    'jar',
    'archive',
    true,
    ['jar'],
    ['application/java-archive', 'application/x-java-archive'],
    'Java archive (executable code)',
  ),
  type(
    'apk',
    'archive',
    true,
    ['apk'],
    ['application/vnd.android.package-archive'],
    'Android package (executable code)',
  ),
  // Executables and installers.
  type(
    'pe_executable',
    'executable',
    true,
    ['exe', 'dll', 'scr', 'sys', 'cpl', 'com', 'ocx', 'efi', 'drv'],
    [
      'application/x-msdownload',
      'application/vnd.microsoft.portable-executable',
      'application/x-dosexec',
      'application/x-msdos-program',
    ],
    'Windows PE executable or library',
  ),
  type(
    'msi',
    'executable',
    true,
    ['msi', 'msp'],
    ['application/x-msi', 'application/x-ms-installer'],
    'Windows Installer package',
  ),
  type(
    'elf',
    'executable',
    true,
    ['elf', 'so'],
    ['application/x-elf', 'application/x-executable', 'application/x-sharedlib'],
    'ELF executable or shared object',
  ),
  type(
    'macho',
    'executable',
    true,
    ['macho', 'dylib'],
    ['application/x-mach-binary'],
    'Mach-O executable or library',
  ),
  type('lnk', 'executable', true, ['lnk'], ['application/x-ms-shortcut'], 'Windows shortcut'),
  // Scripts (no magic bytes: detected as text, then typed by the extension).
  type(
    'script_js',
    'script',
    true,
    ['js', 'jse', 'mjs'],
    ['application/javascript', 'text/javascript', 'application/x-javascript'],
    'JavaScript / JScript',
  ),
  type(
    'script_vbs',
    'script',
    true,
    ['vbs', 'vbe', 'wsf', 'wsh'],
    ['text/vbscript', 'application/x-vbscript'],
    'VBScript or Windows Script File',
  ),
  type(
    'script_ps1',
    'script',
    true,
    ['ps1', 'psm1', 'psd1'],
    ['application/x-powershell'],
    'PowerShell script',
  ),
  type(
    'script_batch',
    'script',
    true,
    ['bat', 'cmd'],
    ['application/x-bat', 'application/bat'],
    'Windows batch file',
  ),
  type(
    'script_shell',
    'script',
    true,
    ['sh', 'bash', 'zsh', 'command'],
    ['application/x-sh', 'text/x-shellscript'],
    'Unix shell script',
  ),
  type('hta', 'script', true, ['hta'], ['application/hta'], 'HTML Application'),
  // Disk images.
  type(
    'iso',
    'disk_image',
    false,
    ['iso', 'img'],
    ['application/x-iso9660-image'],
    'ISO 9660 / UDF disk image',
  ),
  type('vhd', 'disk_image', false, ['vhd', 'vhdx'], ['application/x-vhd'], 'Virtual hard disk'),
  // Markup.
  type(
    'html',
    'markup',
    false,
    ['html', 'htm', 'xhtml', 'shtml'],
    ['text/html', 'application/xhtml+xml'],
    'HTML document',
  ),
  type('svg', 'markup', false, ['svg', 'svgz'], ['image/svg+xml'], 'SVG image (XML, can script)'),
  type('xml', 'markup', false, ['xml'], ['application/xml', 'text/xml'], 'XML document'),
  // Images.
  type('png', 'image', false, ['png'], ['image/png'], 'PNG image'),
  type(
    'jpeg',
    'image',
    false,
    ['jpg', 'jpeg', 'jpe', 'jfif'],
    ['image/jpeg', 'image/pjpeg'],
    'JPEG image',
  ),
  type('gif', 'image', false, ['gif'], ['image/gif'], 'GIF image'),
  type('bmp', 'image', false, ['bmp', 'dib'], ['image/bmp', 'image/x-ms-bmp'], 'BMP image'),
  type('webp', 'image', false, ['webp'], ['image/webp'], 'WebP image'),
  type('tiff', 'image', false, ['tif', 'tiff'], ['image/tiff'], 'TIFF image'),
  // Text and other.
  type(
    'text',
    'text',
    false,
    ['txt', 'csv', 'log', 'md'],
    ['text/plain', 'text/csv', 'text/markdown'],
    'Plain text',
  ),
  type('ics', 'text', false, ['ics', 'ical'], ['text/calendar'], 'iCalendar data'),
  type('eml', 'other', false, ['eml'], ['message/rfc822'], 'Embedded e-mail message'),
  type('unknown', 'other', false, [], [], 'No known type matched'),
] as const);

export type FileTypeId = (typeof FILE_TYPES)[number]['id'];

export const FILE_TYPE_IDS = Object.freeze(FILE_TYPES.map((t) => t.id)) as readonly [
  FileTypeId,
  ...FileTypeId[],
];
export const fileTypeIdSchema = z.enum(FILE_TYPE_IDS);

export const isFileTypeId = (value: string): value is FileTypeId =>
  (FILE_TYPE_IDS as readonly string[]).includes(value);

const BY_ID: ReadonlyMap<string, FileTypeDefinition> = new Map(FILE_TYPES.map((t) => [t.id, t]));
const BY_EXTENSION: ReadonlyMap<string, FileTypeId> = new Map(
  FILE_TYPES.flatMap((t) => t.extensions.map((e) => [e, t.id] as const)),
);
const BY_MIME_TYPE: ReadonlyMap<string, FileTypeId> = new Map(
  FILE_TYPES.flatMap((t) => t.mimeTypes.map((m) => [m, t.id] as const)),
);

/** The definition of `id`. Throws for an id outside the vocabulary. */
export function fileType(id: FileTypeId): FileTypeDefinition {
  const definition = BY_ID.get(id);
  if (!definition) throw new Error('Unknown file type id');
  return definition;
}

/** The family of `id`. */
export const fileTypeFamily = (id: FileTypeId): FileTypeFamily => fileType(id).family;

/**
 * The type a filename extension implies (case-insensitive, with or without the leading dot), or
 * null when no type claims it. Only the extension is passed, never the filename.
 */
export function fileTypeIdForExtension(extension: string): FileTypeId | null {
  const normalized = extension.trim().replace(/^\./, '').toLowerCase();
  return BY_EXTENSION.get(normalized) ?? null;
}

/**
 * Declared content types that carry no type information (A5): ignored by the mismatch rule, so
 * `application/octet-stream` on a PDF is not a mismatch.
 */
export const GENERIC_CONTENT_TYPES = Object.freeze([
  'application/octet-stream',
  'application/x-download',
  'binary/octet-stream',
] as const);

/** `type/subtype` of a content type value: lower-cased, parameters and whitespace removed. */
export function normalizeContentType(contentType: string): string {
  return (contentType.split(';', 1)[0] ?? '').trim().toLowerCase();
}

export const isGenericContentType = (contentType: string): boolean =>
  (GENERIC_CONTENT_TYPES as readonly string[]).includes(normalizeContentType(contentType));

/**
 * The type a declared content type implies (parameters ignored), or null when it is generic
 * (`GENERIC_CONTENT_TYPES`) or not in the vocabulary.
 */
export function fileTypeIdForContentType(contentType: string): FileTypeId | null {
  return BY_MIME_TYPE.get(normalizeContentType(contentType)) ?? null;
}
