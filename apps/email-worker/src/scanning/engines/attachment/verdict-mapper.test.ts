import {
  ATTACHMENT_PLATFORM_DEFAULTS,
  type AttachmentEffectiveSettings,
  attachmentResultSchema,
  type FileTypeId,
  resolveAttachmentSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import type { ArchiveContent, ContentResult } from './content';
import {
  clamavRule,
  contentVerdict,
  type MapInput,
  mapAttachment,
  mapEngine,
  selectSandbox,
} from './verdict-mapper';

const platform = (() => {
  const r = resolveAttachmentSettings(ATTACHMENT_PLATFORM_DEFAULTS, null);
  if (!r.ok) throw new Error('defaults invalid');
  return r.settings;
})();
const tenant = (override: Record<string, unknown>): AttachmentEffectiveSettings => {
  const r = resolveAttachmentSettings(ATTACHMENT_PLATFORM_DEFAULTS, override);
  if (!r.ok) throw new Error(JSON.stringify(r.violations));
  return r.settings;
};

const SHA = 'a'.repeat(64);
const content = (
  over: Partial<ContentResult> = {},
  detected: FileTypeId = 'pdf',
): ContentResult => ({
  inspectorVersion: 'att-inspect/1',
  type: {
    detected,
    family:
      detected === 'zip'
        ? 'archive'
        : detected === 'pe_executable'
          ? 'executable'
          : detected === 'text'
            ? 'text'
            : 'document',
    executable: detected === 'pe_executable',
    textLike: detected === 'text',
  },
  clamav: { status: 'clean', signature: null, engineVersion: '1.4.6', dbVersion: 28174 },
  yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [] },
  archive: null,
  limits: [],
  codes: [],
  ...over,
});
const archive = (over: Partial<ArchiveContent> = {}): ArchiveContent => ({
  format: 'zip',
  supported: true,
  depthReached: 1,
  entries: 1,
  decompressedBytes: 10,
  maxRatio: 1,
  encrypted: false,
  malformed: false,
  findings: [],
  findingCount: 0,
  entryHashes: [{ path: '0', sha256: 'b'.repeat(64), type: 'text', ext: 'text' }],
  ...over,
});

function input(
  over: Partial<MapInput> & {
    ext?: FileTypeId | null;
    declared?: FileTypeId | null;
    flags?: string[];
    stored?: boolean;
  } = {},
): MapInput {
  return {
    facts: {
      partIndex: 1,
      sha256: SHA,
      sizeBytes: 1000,
      stored: over.stored ?? true,
      extensionType: over.ext === undefined ? 'pdf' : over.ext,
      declaredType: over.declared ?? null,
      flags: over.flags ?? [],
    },
    content: over.content === undefined ? content() : over.content,
    hashes: over.hashes ?? { outer: null, inner: new Map() },
    cache: over.cache ?? 'miss',
    durationMs: 12,
  };
}

const map = (i: MapInput, s: AttachmentEffectiveSettings = platform) => {
  const result = mapAttachment(i, s);
  // Every mapped result satisfies the row contract (A16, §2.0 invariant 1).
  expect(attachmentResultSchema.safeParse(result).success).toBe(true);
  return result;
};

describe('attachment verdict mapping attachment-map/1 (step 4.2 A6)', () => {
  it('C1: clean only for a complete inspection with a ClamAV OK and nothing raised', () => {
    const result = map(input());
    expect(result).toMatchObject({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings'],
      detectedType: 'pdf',
      typeFamily: 'document',
      typeMismatch: false,
    });
    expect(result.clamav).toEqual({ signature: null, engineVersion: '1.4.6', dbVersion: 28174 });
    // R codes do not prevent clean.
    expect(map(input({ flags: ['filename_double_extension'] })).reasonCodes).toEqual([
      'clean.no_findings',
      'filename.double_extension',
    ]);
  });

  it('M1 / S2: known hashes (outer and inner) by severity', () => {
    expect(
      map(
        input({ hashes: { outer: { severity: 'critical', family: 'Emotet' }, inner: new Map() } }),
      ),
    ).toMatchObject({
      verdict: 'malicious',
      reasonCodes: ['malware.known_hash'],
      knownHash: { severity: 'critical', family: 'Emotet' },
    });
    expect(
      map(input({ hashes: { outer: { severity: 'medium', family: null }, inner: new Map() } }))
        .reasonCodes,
    ).toEqual(['hash.known_suspicious']);
    const inner = map(
      input({
        content: content({ archive: archive() }, 'zip'),
        ext: 'zip',
        hashes: { outer: null, inner: new Map([['0', { severity: 'high', family: 'X' }]]) },
      }),
    );
    expect(inner.verdict).toBe('malicious');
    expect(inner.archive!.findings).toEqual([
      { path: '0', type: 'text', reasonCodes: ['malware.known_hash'] },
    ]);
    // The catalog applies even when the content was not scanned.
    expect(
      map(
        input({
          content: null,
          hashes: { outer: { severity: 'high', family: null }, inner: new Map() },
        }),
      ).verdict,
    ).toBe('malicious');
  });

  it('M2 / S1: ClamAV signatures, heuristics, PUA, its limits and the size refusal', () => {
    const found = (signature: string) =>
      map(
        input({
          content: content({
            clamav: { status: 'found', signature, engineVersion: '1.4.6', dbVersion: 1 },
          }),
        }),
      );
    expect(found('Eicar-Test-Signature')).toMatchObject({
      verdict: 'malicious',
      reasonCodes: ['malware.clamav'],
    });
    expect(found('Win.Test.EICAR_HDB-1').verdict).toBe('malicious');
    expect(found('Heuristics.OLE2.ContainsMacros')).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['clamav.heuristic'],
    });
    expect(found('PUA.Win.Packer.Upx')).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['clamav.pua'],
    });
    expect(found('Heuristics.Limits.Exceeded.MaxFileSize').reasonCodes).toEqual(['limit.clamav']);
    expect(found('Heuristics.Encrypted.Zip').reasonCodes).toEqual(['archive.encrypted']);
    expect(clamavRule('Heuristics.Encrypted.Zip', 'malicious').verdict).toBe('malicious');
    const refused = map(
      input({
        content: content({
          clamav: { status: 'size_limit', signature: null, engineVersion: '1.4.6', dbVersion: 1 },
        }),
      }),
    );
    expect(refused).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['limit.clamav'],
      clamav: null,
    });
    expect(found('Eicar-Test-Signature').clamav!.signature).toBe('Eicar-Test-Signature');
  });

  it('M3 / S2 / R: YARA by severity, with entry scopes as findings', () => {
    const yara = (severity: 'high' | 'medium' | 'low', scope = 'attachment') =>
      map(
        input({
          content: content(
            {
              yara: { bundleId: 'yara-1-462fab6e5cc4', matches: [{ rule: 'R1', severity, scope }] },
              archive: archive(),
            },
            'zip',
          ),
          ext: 'zip',
        }),
      );
    expect(yara('high')).toMatchObject({ verdict: 'malicious', reasonCodes: ['yara.high'] });
    expect(yara('medium')).toMatchObject({ verdict: 'suspicious', reasonCodes: ['yara.medium'] });
    expect(yara('low')).toMatchObject({
      verdict: 'clean',
      reasonCodes: ['clean.no_findings', 'yara.low'],
    });
    expect(yara('high', '0').archive!.findings).toEqual([
      { path: '0', type: 'text', reasonCodes: ['yara.high'] },
    ]);
  });

  it('S3: not stored / too large, archive limits, inspector kills, YARA timeouts, never clean', () => {
    expect(map(input({ content: null, stored: false }))).toMatchObject({
      verdict: 'suspicious',
      reasonCodes: ['attachment.not_scanned', 'limit.attachment_size'],
      detectedType: 'unknown',
      clamav: null,
      yara: null,
    });
    for (const code of [
      'limit.archive_depth',
      'limit.archive_entries',
      'limit.entry_size',
      'limit.decompressed_size',
      'limit.compression_ratio',
      'limit.cpu_time',
      'limit.memory',
      'limit.yara_timeout',
    ] as const) {
      expect(map(input({ content: content({ limits: [code] }) }))).toMatchObject({
        verdict: 'suspicious',
        reasonCodes: [code],
      });
    }
  });

  it('S4: encrypted archives take the tenant verdict (raise-only)', () => {
    const encrypted = input({
      content: content(
        { codes: ['archive.encrypted'], archive: archive({ encrypted: true }) },
        'zip',
      ),
      ext: 'zip',
    });
    expect(map(encrypted).verdict).toBe('suspicious');
    expect(map(encrypted, tenant({ encryptedArchiveVerdict: 'malicious' })).verdict).toBe(
      'malicious',
    );
  });

  it('S5: deny lists on the detected and the extension type, allow lists, archive entries', () => {
    // A PE named .pdf is caught by detection; a .exe with junk by its extension.
    expect(map(input({ content: content({}, 'pe_executable'), ext: 'pdf' })).reasonCodes).toEqual([
      'type.denied',
      'type.executable_disguised',
      'type.mismatch',
    ]);
    expect(
      map(input({ content: content({}, 'text'), ext: 'pe_executable' })).reasonCodes,
    ).toContain('type.denied');
    expect(map(input({ content: null, ext: 'pe_executable' })).reasonCodes).toContain(
      'type.denied',
    );
    // Scripts are typed by the extension of a text file.
    expect(map(input({ content: content({}, 'text'), ext: 'script_js' }))).toMatchObject({
      detectedType: 'script_js',
      reasonCodes: ['type.denied'],
    });
    // Tenant deny list adds, tenant verdict raises.
    const denyPdf = tenant({ deniedTypes: ['pdf'], deniedTypeVerdict: 'malicious' });
    expect(map(input(), denyPdf)).toMatchObject({
      verdict: 'malicious',
      reasonCodes: ['type.denied'],
    });
    // Allow list: everything else is not allowed.
    const allowPdf = tenant({ allowedTypes: ['pdf', 'zip'] });
    expect(map(input(), allowPdf).verdict).toBe('clean');
    expect(map(input({ content: content({}, 'text'), ext: 'text' }), allowPdf).reasonCodes).toEqual(
      ['type.not_allowed'],
    );
    expect(map(input({ content: null, ext: null }), allowPdf).reasonCodes).toContain(
      'type.not_allowed',
    );
    // Archive entries: deny list always, allow list for plain archives.
    const zipped = (type: FileTypeId, ext: FileTypeId | null) =>
      input({
        content: content(
          { archive: archive({ entryHashes: [{ path: '0', sha256: 'c'.repeat(64), type, ext }] }) },
          'zip',
        ),
        ext: 'zip',
      });
    expect(map(zipped('pe_executable', 'pe_executable')).reasonCodes).toEqual([
      'type.denied_in_archive',
    ]);
    expect(map(zipped('text', 'script_vbs')).archive!.findings).toEqual([
      { path: '0', type: 'text', reasonCodes: ['type.denied_in_archive'] },
    ]);
    expect(map(zipped('text', 'text'), allowPdf).reasonCodes).toEqual(['type.denied_in_archive']);
    expect(map(zipped('pdf', 'pdf'), allowPdf).verdict).toBe('clean');
    // OOXML parts are not checked against the allow list.
    const docx = input({
      content: content(
        {
          archive: archive({
            entryHashes: [{ path: '0', sha256: 'c'.repeat(64), type: 'xml', ext: 'xml' }],
          }),
        },
        'ooxml_word',
      ),
      ext: 'ooxml_word',
    });
    expect(map(docx, tenant({ allowedTypes: ['ooxml_word'] })).verdict).toBe('clean');
  });

  it('S6: mismatch and disguised executables (generic declared types ignored, raise-only)', () => {
    expect(map(input({ content: content({}, 'pdf'), ext: 'text' })).reasonCodes).toEqual([
      'type.mismatch',
    ]);
    expect(
      map(input({ content: content({}, 'pdf'), ext: 'pdf', declared: 'png' })).typeMismatch,
    ).toBe(true);
    // A docx declared as zip is a zip container, not a mismatch; null declared (octet-stream) too.
    expect(
      map(input({ content: content({}, 'ooxml_word'), ext: 'ooxml_word', declared: 'zip' }))
        .verdict,
    ).toBe('clean');
    expect(map(input({ content: content({}, 'pdf'), ext: 'pdf', declared: null })).verdict).toBe(
      'clean',
    );
    // Weak detections claim nothing.
    expect(map(input({ content: content({}, 'text'), ext: 'pdf' })).reasonCodes).toEqual([
      'clean.no_findings',
    ]);
    expect(
      map(
        input({ content: content({}, 'pdf'), ext: 'text' }),
        tenant({ typeMismatchVerdict: 'malicious' }),
      ).verdict,
    ).toBe('malicious');
    // Entry-level disguised executables count for the attachment.
    const entry = input({
      content: content(
        {
          archive: archive({
            findings: [{ path: '0', type: 'pe_executable', codes: ['type.executable_disguised'] }],
            entryHashes: [],
          }),
        },
        'zip',
      ),
      ext: 'zip',
    });
    expect(map(entry).reasonCodes).toContain('type.executable_disguised');
  });

  it('S7 / U1 / R: malformed archives, unsupported formats, macros', () => {
    for (const code of [
      'archive.malformed',
      'archive.path_traversal',
      'archive.overlapping_entries',
    ] as const) {
      expect(
        map(input({ content: content({ codes: [code], archive: archive() }, 'zip'), ext: 'zip' }))
          .verdict,
      ).toBe('suspicious');
    }
    expect(
      map(
        input({
          content: content(
            {
              codes: ['archive.unsupported_format'],
              archive: archive({ format: '7z', supported: false, entries: 0, entryHashes: [] }),
            },
            'zip',
          ),
          ext: null,
        }),
      ).verdict,
    ).toBe('unknown');
    expect(
      map(
        input({
          content: content({ codes: ['office.macros'] }, 'ooxml_macro'),
          ext: 'ooxml_macro',
        }),
      ),
    ).toMatchObject({ verdict: 'clean', reasonCodes: ['clean.no_findings', 'office.macros'] });
  });

  it('orders reason codes by the verdict that raised them, then name, at most 32', () => {
    const result = map(
      input({
        content: content(
          {
            clamav: {
              status: 'found',
              signature: 'Eicar-Test-Signature',
              engineVersion: '1.4.6',
              dbVersion: 1,
            },
            codes: ['archive.unsupported_format', 'office.macros'],
            limits: ['limit.memory'],
            archive: archive(),
          },
          'zip',
        ),
        ext: 'zip',
        flags: ['filename_bidi_control'],
      }),
    );
    expect(result.reasonCodes).toEqual([
      'malware.clamav',
      'limit.memory',
      'archive.unsupported_format',
      'filename.bidi_control',
      'office.macros',
    ]);
    expect(result.reasonCodes.length).toBeLessThanOrEqual(32);
  });

  it('derives the content-only verdict for the cache TTL', () => {
    expect(contentVerdict(content())).toBe('clean');
    expect(contentVerdict(content({ limits: ['limit.cpu_time'] }))).toBe('suspicious');
    expect(
      contentVerdict(
        content({
          clamav: {
            status: 'found',
            signature: 'Eicar-Test-Signature',
            engineVersion: '1',
            dbVersion: 1,
          },
        }),
      ),
    ).toBe('malicious');
    // Content alone: no deny list, so a PE is clean by content (the tenant rules apply later).
    expect(contentVerdict(content({}, 'pe_executable'))).toBe('clean');
  });
});

describe('engine level (A0, E1, aggregation)', () => {
  const clean = map(input());
  const evil = map(
    input({
      content: content({
        clamav: {
          status: 'found',
          signature: 'Eicar-Test-Signature',
          engineVersion: '1.4.6',
          dbVersion: 1,
        },
        yara: {
          bundleId: 'yara-1-462fab6e5cc4',
          matches: [{ rule: 'EG_Test_Marker_High', severity: 'high', scope: 'attachment' }],
        },
      }),
    }),
  );

  it('A0: no attachments and a complete parse → skipped', () => {
    expect(mapEngine({ attachments: [], parseIncomplete: false, countExceeded: false })).toEqual({
      outcome: 'skipped',
      reasonCodes: ['attachment.none'],
      signals: [],
    });
  });

  it('E1: an incomplete parse is at least suspicious, even without rows', () => {
    expect(
      mapEngine({ attachments: [], parseIncomplete: true, countExceeded: false }),
    ).toMatchObject({ outcome: 'suspicious', reasonCodes: ['attachment.parse_incomplete'] });
    expect(
      mapEngine({ attachments: [clean], parseIncomplete: true, countExceeded: false }).outcome,
    ).toBe('suspicious');
    expect(
      mapEngine({ attachments: [clean], parseIncomplete: false, countExceeded: true }).reasonCodes,
    ).toEqual(['attachment.not_scanned', 'limit.attachment_count']);
  });

  it('takes the most severe attachment verdict, keeps clean.no_findings only when all are clean', () => {
    expect(
      mapEngine({ attachments: [clean, clean], parseIncomplete: false, countExceeded: false }),
    ).toMatchObject({ outcome: 'clean', reasonCodes: ['clean.no_findings'], signals: [] });
    const mixed = mapEngine({
      attachments: [clean, evil],
      parseIncomplete: false,
      countExceeded: false,
    });
    expect(mixed.outcome).toBe('malicious');
    expect(mixed.reasonCodes).toEqual(['malware.clamav', 'yara.high']);
    expect(mixed.signals).toEqual([
      { name: 'clamav:Eicar-Test-Signature', score: 0, options: ['part 1'] },
      { name: 'yara:EG_Test_Marker_High', score: 0, options: ['part 1'] },
    ]);
  });

  it('selects sandbox submissions: suspicious/unknown with a stored part, most severe first, bounded', () => {
    const suspicious = map(input({ content: content({ limits: ['limit.memory'] }) }));
    const unknown = {
      ...map(
        input({
          content: content(
            {
              codes: ['archive.unsupported_format'],
              archive: archive({ format: '7z', supported: false, entryHashes: [] }),
            },
            'zip',
          ),
          ext: null,
        }),
      ),
      partIndex: 0,
    };
    const notStored = map(input({ content: null, stored: false }));
    const picked = selectSandbox(
      [
        { result: unknown, stored: true },
        { result: evil, stored: true },
        { result: suspicious, stored: true },
        { result: notStored, stored: false },
        { result: clean, stored: true },
      ],
      5,
    );
    expect(picked).toEqual([
      { index: 2, verdict: 'suspicious' },
      { index: 0, verdict: 'unknown' },
    ]);
    expect(selectSandbox([{ result: suspicious, stored: true }], 0)).toEqual([]);
  });
});
