import { describe, expect, it } from 'vitest';
import {
  FILE_TYPE_FAMILIES,
  FILE_TYPE_IDS,
  FILE_TYPES,
  fileType,
  fileTypeFamily,
  fileTypeIdForContentType,
  fileTypeIdForExtension,
  fileTypeIdSchema,
  GENERIC_CONTENT_TYPES,
  isFileTypeId,
  isGenericContentType,
  normalizeContentType,
} from './index';

/** The ids A5 lists, in its order. */
const A5_IDS = [
  'pdf',
  'zip',
  'gzip',
  'tar',
  '7z',
  'rar',
  'cab',
  'bzip2',
  'xz',
  'ooxml_word',
  'ooxml_excel',
  'ooxml_powerpoint',
  'ooxml_macro',
  'odf',
  'ole_office',
  'msi',
  'rtf',
  'pe_executable',
  'elf',
  'macho',
  'lnk',
  'jar',
  'apk',
  'iso',
  'vhd',
  'chm',
  'script_js',
  'script_vbs',
  'script_ps1',
  'script_batch',
  'script_shell',
  'hta',
  'html',
  'svg',
  'xml',
  'text',
  'png',
  'jpeg',
  'gif',
  'bmp',
  'webp',
  'tiff',
  'ics',
  'eml',
  'unknown',
];

describe('FILE_TYPES (A5)', () => {
  it('contains exactly the ids of A5, each once, with a family of the vocabulary', () => {
    expect([...FILE_TYPE_IDS].sort()).toEqual([...A5_IDS].sort());
    expect(new Set(FILE_TYPE_IDS).size).toBe(FILE_TYPE_IDS.length);
    for (const t of FILE_TYPES) {
      expect(t.id).toMatch(/^[a-z0-9][a-z0-9_]{0,31}$/);
      expect(FILE_TYPE_FAMILIES).toContain(t.family);
      expect(t.description.length, t.id).toBeGreaterThan(0);
      expect(Object.isFrozen(t)).toBe(true);
    }
    expect([...FILE_TYPE_FAMILIES]).toEqual([
      'document',
      'archive',
      'executable',
      'script',
      'disk_image',
      'image',
      'markup',
      'text',
      'other',
    ]);
  });

  it('fits the attachment_scan_results columns (detected_type VARCHAR(32), type_family VARCHAR(16))', () => {
    for (const id of FILE_TYPE_IDS) expect(id.length).toBeLessThanOrEqual(32);
    for (const family of FILE_TYPE_FAMILIES) expect(family.length).toBeLessThanOrEqual(16);
  });

  it('assigns every extension and every content type to at most one type, lower-case', () => {
    const extensions = FILE_TYPES.flatMap((t) => t.extensions);
    const mimeTypes = FILE_TYPES.flatMap((t) => t.mimeTypes);
    expect(new Set(extensions).size).toBe(extensions.length);
    expect(new Set(mimeTypes).size).toBe(mimeTypes.length);
    for (const e of extensions) expect(e).toMatch(/^[a-z0-9]{1,16}$/);
    for (const m of mimeTypes) expect(m).toMatch(/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/);
    for (const generic of GENERIC_CONTENT_TYPES) expect(mimeTypes).not.toContain(generic);
  });

  it('marks the executable family (PE, ELF, Mach-O, MSI, LNK) and the other code carriers', () => {
    const family = (f: string) =>
      FILE_TYPES.filter((t) => t.family === f)
        .map((t) => t.id)
        .sort();
    expect(family('executable')).toEqual(['elf', 'lnk', 'macho', 'msi', 'pe_executable']);
    expect(family('script')).toEqual([
      'hta',
      'script_batch',
      'script_js',
      'script_ps1',
      'script_shell',
      'script_vbs',
    ]);
    expect(family('archive')).toEqual(
      ['7z', 'apk', 'bzip2', 'cab', 'gzip', 'jar', 'rar', 'tar', 'xz', 'zip'].sort(),
    );
    expect(family('disk_image')).toEqual(['iso', 'vhd']);
    const executable = FILE_TYPES.filter((t) => t.executable)
      .map((t) => t.id)
      .sort();
    expect(executable).toEqual(
      [...family('executable'), ...family('script'), 'jar', 'apk', 'chm'].sort(),
    );
    expect(fileType('unknown')).toMatchObject({ family: 'other', executable: false });
    expect(fileType('unknown').extensions).toEqual([]);
  });

  it('validates ids with the schema and the guard', () => {
    expect(fileTypeIdSchema.parse('pe_executable')).toBe('pe_executable');
    expect(fileTypeIdSchema.safeParse('exe').success).toBe(false);
    expect(fileTypeIdSchema.safeParse('PDF').success).toBe(false);
    expect(isFileTypeId('ooxml_macro')).toBe(true);
    expect(isFileTypeId('clamav')).toBe(false);
    expect(fileTypeFamily('ooxml_macro')).toBe('document');
    expect(() => fileType('nope' as never)).toThrow('Unknown file type id');
  });
});

describe('extension and content type lookups', () => {
  it('maps an extension to its type, ignoring case and a leading dot', () => {
    expect(fileTypeIdForExtension('exe')).toBe('pe_executable');
    expect(fileTypeIdForExtension('.PDF')).toBe('pdf');
    expect(fileTypeIdForExtension(' Docm ')).toBe('ooxml_macro');
    expect(fileTypeIdForExtension('tgz')).toBe('gzip');
    expect(fileTypeIdForExtension('js')).toBe('script_js');
    expect(fileTypeIdForExtension('')).toBeNull();
    expect(fileTypeIdForExtension('weird')).toBeNull();
  });

  it('maps a declared content type, ignoring parameters; generic types imply nothing', () => {
    expect(fileTypeIdForContentType('application/pdf')).toBe('pdf');
    expect(fileTypeIdForContentType('Application/PDF; name="x.pdf"')).toBe('pdf');
    expect(
      fileTypeIdForContentType(
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      ),
    ).toBe('ooxml_word');
    expect(fileTypeIdForContentType('application/x-zip-compressed')).toBe('zip');
    for (const generic of GENERIC_CONTENT_TYPES) {
      expect(fileTypeIdForContentType(generic)).toBeNull();
      expect(isGenericContentType(`${generic.toUpperCase()}; charset=binary`)).toBe(true);
    }
    expect(isGenericContentType('application/pdf')).toBe(false);
    expect(normalizeContentType(' Text/HTML ; charset=utf-8')).toBe('text/html');
  });
});
