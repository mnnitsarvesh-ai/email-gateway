import { type FileTypeId, fileType } from '@email-gateway/security-contracts';

/**
 * The type comparison rules of step 4.2 A5 (pure; used by the verdict mapper for attachments and
 * by the inspector for archive entries).
 */

/** Zip-based formats: a `zip` claim on one of them is not a mismatch (a docx is a zip). */
const ZIP_CONTAINERS: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
  'jar',
  'apk',
]);

/** Detections that carry no type claim of their own (never a mismatch, A5). */
const WEAK_DETECTIONS: ReadonlySet<FileTypeId> = new Set<FileTypeId>(['unknown', 'text']);

/** Whether a detected type is compatible with a claimed type (extension or declared type). */
export function compatible(detected: FileTypeId, claimed: FileTypeId): boolean {
  if (detected === claimed) return true;
  if (claimed === 'zip' && ZIP_CONTAINERS.has(detected)) return true;
  return fileType(detected).family === fileType(claimed).family;
}

/**
 * `type.mismatch` (A5): the detected type is known (not `unknown`/`text`) and the extension, or
 * a specific declared content type (generic ones are mapped to null by the caller), implies a
 * different family.
 */
export function typeMismatch(
  detected: FileTypeId,
  extensionType: FileTypeId | null,
  declaredType: FileTypeId | null,
): boolean {
  if (WEAK_DETECTIONS.has(detected)) return false;
  if (extensionType !== null && !compatible(detected, extensionType)) return true;
  return declaredType !== null && !compatible(detected, declaredType);
}

/** Families whose content is an executable binary (PE, ELF, Mach-O, MSI, LNK). */
const EXECUTABLE_BINARIES: ReadonlySet<FileTypeId> = new Set<FileTypeId>([
  'pe_executable',
  'elf',
  'macho',
  'msi',
  'lnk',
]);

/**
 * `type.executable_disguised` (A5): an executable binary whose name carries an extension that
 * is not an executable type (`invoice.pdf` that is a PE). A name without a known extension is
 * not "disguised" (it claims nothing); the deny list still applies to the detected type.
 */
export function executableDisguised(
  detected: FileTypeId,
  extensionType: FileTypeId | null,
): boolean {
  if (!EXECUTABLE_BINARIES.has(detected) || extensionType === null) return false;
  return !fileType(extensionType).executable;
}
