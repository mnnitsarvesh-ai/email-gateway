import type { AttachmentFlag } from './constants';
import {
  BIDI_CONTROLS,
  CONTROL_CHARS,
  codePointLength,
  global,
  normalizeText,
  truncateCodePoints,
  ZERO_WIDTH,
} from './text';

export interface SanitizedFilename {
  /** Safe display name, or null when nothing usable is left (`filename_missing`). */
  filename: string | null;
  /** The raw decoded name with invisible characters and `\` escaped (≤ 1 024 characters). */
  originalFilename: string | null;
  flags: AttachmentFlag[];
}

/** Final extensions treated as executable (design M9). */
export const EXECUTABLE_EXTENSIONS: ReadonlySet<string> = new Set(
  (
    'exe scr com bat cmd pif cpl dll msi msp js jse vbs vbe wsf wsh hta ps1 psm1 lnk jar iso img ' +
    'vhd vhdx reg application appx msix appinstaller sh apk scf url'
  ).split(' '),
);

/** Extensions a double-extension lure hides behind (design M9). */
export const DOCUMENT_EXTENSIONS: ReadonlySet<string> = new Set(
  'pdf doc docx docm xls xlsx xlsm ppt pptx txt rtf csv jpg jpeg png gif bmp mp3 mp4 wav zip html htm'.split(
    ' ',
  ),
);

/** Entry or file names that denote an archive (design M10 `archive_nested`). */
export const ARCHIVE_EXTENSIONS: ReadonlySet<string> = new Set(
  'zip rar 7z gz tgz tar bz2 xz cab iso jar arj lzh z ace img'.split(' '),
);

export const ORIGINAL_FILENAME_MAX_CHARS = 1024;
const MAX_KEPT_EXTENSION = 16;

const RESERVED_DEVICE = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
const ESCAPED_IN_ORIGINAL = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}\\]/u;

/** Lower-case final extension of a name (without the dot), or null. */
export function finalExtension(name: string | null): string | null {
  if (!name) return null;
  const dot = name.lastIndexOf('.');
  if (dot < 0 || dot === name.length - 1) return null;
  return name
    .slice(dot + 1)
    .trim()
    .toLowerCase();
}

/**
 * Sanitizes a decoded attachment filename (design M9, rules 1–7 in order) and derives the
 * extension flags. The result is metadata only: never a path and never part of a storage key.
 */
export function sanitizeFilename(raw: string | undefined, maxChars: number): SanitizedFilename {
  const flags = new Set<AttachmentFlag>();
  if (raw === undefined || raw === '') {
    return { filename: null, originalFilename: null, flags: ['filename_missing'] };
  }
  const original = escapeOriginal(raw);
  if (original.truncated) flags.add('original_filename_truncated');

  // 1. NFC, well-formed.
  let name = normalizeText(raw);

  // 2. Last path component, no drive prefix.
  const components = name.split(/[/\\]/);
  if (components.length > 1) {
    flags.add('filename_path_stripped');
    name = components[components.length - 1] ?? '';
  }
  if (/^[A-Za-z]:/.test(name)) {
    flags.add('filename_path_stripped');
    name = name.slice(2);
  }

  // 3. Controls, bidi controls and zero-width characters are removed.
  if (CONTROL_CHARS.test(name)) {
    flags.add('filename_control_chars');
    name = name.replace(global(CONTROL_CHARS), '');
  }
  if (BIDI_CONTROLS.test(name)) {
    flags.add('filename_bidi_control');
    name = name.replace(global(BIDI_CONTROLS), '');
  }
  if (ZERO_WIDTH.test(name)) {
    flags.add('filename_zero_width');
    name = name.replace(global(ZERO_WIDTH), '');
  }

  // 4. Reserved characters, whitespace runs, leading and trailing dots and spaces.
  name = name.replace(/[<>:"|?*]/g, '_');
  if (/\s{3,}\.[^.\s]+\s*$/u.test(name)) flags.add('filename_whitespace_padding');
  name = name
    .replace(/\s+/gu, ' ')
    .replace(/^[. ]+/, '')
    .replace(/[. ]+$/, '');

  // 5. Windows device names, with any extension.
  if (RESERVED_DEVICE.test((name.split('.')[0] ?? '').trim())) {
    flags.add('filename_reserved_name');
    name = `_${name}`;
  }

  // 6. Length cap, keeping the final extension.
  if (codePointLength(name) > maxChars) {
    flags.add('filename_truncated');
    name = truncateKeepingExtension(name, maxChars);
  }

  // 7. Nothing left.
  if (name === '') {
    flags.add('filename_missing');
    return { filename: null, originalFilename: original.value, flags: [...flags] };
  }

  const extensions = name
    .split('.')
    .slice(1)
    .map((part) => part.trim().toLowerCase());
  const last = extensions[extensions.length - 1];
  const previous = extensions[extensions.length - 2];
  if (last !== undefined && EXECUTABLE_EXTENSIONS.has(last)) {
    flags.add('filename_executable_extension');
    if (previous !== undefined && DOCUMENT_EXTENSIONS.has(previous)) {
      flags.add('filename_double_extension');
    }
  }
  return { filename: name, originalFilename: original.value, flags: [...flags] };
}

function truncateKeepingExtension(name: string, maxChars: number): string {
  const dot = name.lastIndexOf('.');
  const extension = dot > 0 ? name.slice(dot) : '';
  const extensionLength = codePointLength(extension);
  if (extension && extensionLength - 1 <= MAX_KEPT_EXTENSION && extensionLength < maxChars) {
    const base = truncateCodePoints(name.slice(0, dot), maxChars - extensionLength).value;
    return `${base.replace(/[. ]+$/, '')}${extension}`;
  }
  return truncateCodePoints(name, maxChars).value.replace(/[. ]+$/, '');
}

/** Escapes invisible, unassigned and private-use code points, bidi and zero-width characters and `\`. */
function escapeOriginal(raw: string): { value: string; truncated: boolean } {
  let value = '';
  let length = 0;
  for (const char of raw) {
    const piece = ESCAPED_IN_ORIGINAL.test(char)
      ? `\\u{${(char.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}}`
      : char;
    const pieceLength = codePointLength(piece);
    if (length + pieceLength > ORIGINAL_FILENAME_MAX_CHARS) return { value, truncated: true };
    value += piece;
    length += pieceLength;
  }
  return { value, truncated: false };
}
