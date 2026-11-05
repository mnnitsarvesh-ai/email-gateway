import { describe, expect, it } from 'vitest';
import {
  ATTACHMENT_DEFAULT_DENIED_TYPES,
  ATTACHMENT_ENGINE_LEVEL_CODES,
  ATTACHMENT_MAPPING_VERSION,
  ATTACHMENT_MIN_BYTES,
  ATTACHMENT_PLATFORM_DEFAULTS,
  ATTACHMENT_PLATFORM_ENV_KEYS,
  ATTACHMENT_REASON_CODES,
  ATTACHMENT_VERDICTS,
  type AttachmentPlatformSettings,
  attachmentPlatformSettingsFromEnv,
  attachmentPlatformSettingsSchema,
  attachmentReasonCodeSchema,
  attachmentResultSchema,
  attachmentSettingsBounds,
  attachmentTenantSettingsSchema,
  attachmentVerdictRank,
  FILE_TYPE_IDS,
  MAX_ALLOWED_TYPES,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  resolveAttachmentSettings,
  settingsVersion,
} from './index';

const platform: AttachmentPlatformSettings = attachmentPlatformSettingsSchema.parse(
  ATTACHMENT_PLATFORM_DEFAULTS,
);

const violations = (override: unknown, base: AttachmentPlatformSettings = platform) => {
  const resolution = resolveAttachmentSettings(base, override);
  if (resolution.ok) throw new Error('expected violations');
  return resolution.violations.map((v) => [v.path, v.code]);
};

describe('attachment verdicts and reason codes (A6)', () => {
  it('orders the verdicts malicious > suspicious > unknown > clean', () => {
    expect([...ATTACHMENT_VERDICTS]).toEqual(['clean', 'suspicious', 'malicious', 'unknown']);
    const ordered = [...ATTACHMENT_VERDICTS].sort(
      (a, b) => attachmentVerdictRank(a) - attachmentVerdictRank(b),
    );
    expect(ordered).toEqual(['clean', 'unknown', 'suspicious', 'malicious']);
    expect(ATTACHMENT_MAPPING_VERSION).toBe('attachment-map/1');
  });

  it('lists every code of the A6 table, the engine-level codes and the failure codes', () => {
    const a6 = [
      'malware.known_hash',
      'malware.clamav',
      'yara.high',
      'clamav.heuristic',
      'clamav.pua',
      'limit.clamav',
      'archive.encrypted',
      'hash.known_suspicious',
      'yara.medium',
      'limit.attachment_size',
      'attachment.not_scanned',
      'limit.archive_depth',
      'limit.archive_entries',
      'limit.entry_size',
      'limit.decompressed_size',
      'limit.compression_ratio',
      'limit.cpu_time',
      'limit.memory',
      'limit.yara_timeout',
      'limit.attachment_count',
      'type.denied',
      'type.not_allowed',
      'type.denied_in_archive',
      'type.mismatch',
      'type.executable_disguised',
      'archive.malformed',
      'archive.path_traversal',
      'archive.overlapping_entries',
      'archive.unsupported_format',
      'yara.low',
      'office.macros',
      'filename.double_extension',
      'filename.executable_extension',
      'filename.bidi_control',
      'clean.no_findings',
    ];
    const engineLevel = ['attachment.none', 'attachment.parse_incomplete'];
    const failures = [
      'unavailable',
      'timeout',
      'protocol_error',
      'circuit_open',
      'inspector_timeout',
      'inspector_crash',
      'part_unavailable',
      'part_integrity',
      'part_key_mismatch',
      'parse_row_missing',
    ].map((code) => `engine.${code}`);
    for (const code of [...a6, ...engineLevel, ...failures]) {
      expect(ATTACHMENT_REASON_CODES, code).toContain(code);
    }
    expect([...ATTACHMENT_ENGINE_LEVEL_CODES]).toEqual(engineLevel);
    expect(new Set(ATTACHMENT_REASON_CODES).size).toBe(ATTACHMENT_REASON_CODES.length);
    for (const code of ATTACHMENT_REASON_CODES) {
      expect(REASON_CODE_PATTERN.test(code), code).toBe(true);
      expect(code.length).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
    }
    expect(attachmentReasonCodeSchema.safeParse('spam.score').success).toBe(false);
  });
});

describe('platform settings (A8)', () => {
  it('defaults to the §5 values', () => {
    expect(ATTACHMENT_PLATFORM_DEFAULTS).toEqual({
      maxAttachmentBytes: 26_214_400,
      archiveMaxDepth: 3,
      archiveMaxEntries: 1000,
      maxEntryBytes: 26_214_400,
      maxDecompressedBytes: 104_857_600,
      maxCompressionRatio: 100,
      maxEntryFindings: 20,
      deniedTypes: [
        'pe_executable',
        'msi',
        'elf',
        'macho',
        'lnk',
        'script_js',
        'script_vbs',
        'script_ps1',
        'script_batch',
        'hta',
        'jar',
        'apk',
        'iso',
        'vhd',
        'chm',
      ],
      deniedTypeVerdict: 'suspicious',
      typeMismatchVerdict: 'suspicious',
      encryptedArchiveVerdict: 'suspicious',
    });
    expect(Object.isFrozen(ATTACHMENT_PLATFORM_DEFAULTS)).toBe(true);
    expect(Object.isFrozen(ATTACHMENT_DEFAULT_DENIED_TYPES)).toBe(true);
    expect(ATTACHMENT_DEFAULT_DENIED_TYPES).not.toContain('zip');
  });

  it('reads the ATTACHMENT_* keys, empty or unset meaning the default, none an empty list', () => {
    expect(attachmentPlatformSettingsFromEnv({})).toEqual(ATTACHMENT_PLATFORM_DEFAULTS);
    expect(
      attachmentPlatformSettingsFromEnv({
        ATTACHMENT_MAX_BYTES: '10485760',
        ATTACHMENT_ARCHIVE_MAX_DEPTH: ' 5 ',
        ATTACHMENT_ARCHIVE_MAX_ENTRIES: '',
        ATTACHMENT_DENIED_TYPES: 'pe_executable, msi',
        ATTACHMENT_DENIED_TYPE_VERDICT: 'malicious',
      }),
    ).toMatchObject({
      maxAttachmentBytes: 10_485_760,
      archiveMaxDepth: 5,
      archiveMaxEntries: 1000,
      deniedTypes: ['pe_executable', 'msi'],
      deniedTypeVerdict: 'malicious',
      typeMismatchVerdict: 'suspicious',
    });
    expect(
      attachmentPlatformSettingsFromEnv({ ATTACHMENT_DENIED_TYPES: 'none' }).deniedTypes,
    ).toEqual([]);
    expect(
      Object.values(ATTACHMENT_PLATFORM_ENV_KEYS).every((k) => k.startsWith('ATTACHMENT_')),
    ).toBe(true);
  });

  it('refuses invalid platform settings at start', () => {
    const env = (patch: Record<string, string>) => () => attachmentPlatformSettingsFromEnv(patch);
    expect(env({ ATTACHMENT_MAX_BYTES: '1000' })).toThrow(/maxAttachmentBytes/);
    expect(env({ ATTACHMENT_MAX_BYTES: String(31_457_281) })).toThrow(/maxAttachmentBytes/);
    expect(env({ ATTACHMENT_MAX_BYTES: 'big' })).toThrow();
    expect(env({ ATTACHMENT_ARCHIVE_MAX_DEPTH: '0' })).toThrow(/archiveMaxDepth/);
    expect(env({ ATTACHMENT_MAX_COMPRESSION_RATIO: '1' })).toThrow(/maxCompressionRatio/);
    expect(env({ ATTACHMENT_MAX_ENTRY_FINDINGS: '21' })).toThrow(/maxEntryFindings/);
    expect(
      env({ ATTACHMENT_MAX_ENTRY_BYTES: '200000000', ATTACHMENT_MAX_DECOMPRESSED_BYTES: '100' }),
    ).toThrow(/maxEntryBytes/);
    expect(env({ ATTACHMENT_DENIED_TYPES: 'exe' })).toThrow(/deniedTypes/);
    expect(env({ ATTACHMENT_DENIED_TYPES: 'msi,msi' })).toThrow(/Duplicate/);
    expect(env({ ATTACHMENT_DENIED_TYPES: 'unknown' })).toThrow(/unknown cannot be denied/);
    expect(env({ ATTACHMENT_ENCRYPTED_VERDICT: 'clean' })).toThrow();
    expect(env({ ATTACHMENT_TYPE_MISMATCH_VERDICT: 'unknown' })).toThrow();
    expect(() => attachmentPlatformSettingsSchema.parse({ ...platform, extra: 1 })).toThrow();
  });
});

describe('resolveAttachmentSettings (A8)', () => {
  it('returns the platform settings without an override', () => {
    for (const override of [null, undefined]) {
      expect(resolveAttachmentSettings(platform, override)).toEqual({
        ok: true,
        overridden: false,
        settings: {
          maxAttachmentBytes: 26_214_400,
          deniedTypes: [...ATTACHMENT_DEFAULT_DENIED_TYPES].sort(
            (a, b) => FILE_TYPE_IDS.indexOf(a) - FILE_TYPE_IDS.indexOf(b),
          ),
          allowedTypes: null,
          deniedTypeVerdict: 'suspicious',
          typeMismatchVerdict: 'suspicious',
          encryptedArchiveVerdict: 'suspicious',
        },
      });
    }
    expect(resolveAttachmentSettings(platform, {})).toMatchObject({ ok: true, overridden: false });
  });

  it('adds tenant denied types to the platform list (add-only, vocabulary order)', () => {
    const resolution = resolveAttachmentSettings(platform, { deniedTypes: ['zip', 'msi'] });
    expect(resolution).toMatchObject({ ok: true, overridden: true });
    if (!resolution.ok) throw new Error('unreachable');
    expect(resolution.settings.deniedTypes).toContain('zip');
    for (const t of ATTACHMENT_DEFAULT_DENIED_TYPES) {
      expect(resolution.settings.deniedTypes).toContain(t);
    }
    expect(new Set(resolution.settings.deniedTypes).size).toBe(
      resolution.settings.deniedTypes.length,
    );
    expect(resolution.settings.deniedTypes).toEqual(
      FILE_TYPE_IDS.filter((id) => resolution.settings.deniedTypes.includes(id)),
    );
    // An empty tenant list removes nothing.
    const empty = resolveAttachmentSettings(platform, { deniedTypes: [] });
    expect(empty.ok && empty.settings.deniedTypes.length).toBe(
      ATTACHMENT_DEFAULT_DENIED_TYPES.length,
    );
    expect(violations({ deniedTypes: ['unknown'] })).toEqual([['deniedTypes', 'invalid']]);
  });

  it('accepts an allow list without denied types and refuses platform or tenant denied ones', () => {
    expect(
      resolveAttachmentSettings(platform, { allowedTypes: ['png', 'pdf', 'ooxml_word'] }),
    ).toMatchObject({ ok: true, settings: { allowedTypes: ['pdf', 'ooxml_word', 'png'] } });
    expect(violations({ allowedTypes: ['pdf', 'pe_executable'] })).toEqual([
      ['allowedTypes', 'out_of_bounds'],
    ]);
    expect(violations({ allowedTypes: ['pdf', 'zip'], deniedTypes: ['zip'] })).toEqual([
      ['allowedTypes', 'out_of_bounds'],
    ]);
    expect(violations({ allowedTypes: [] })).toEqual([['allowedTypes', 'invalid']]);
    // The cap (64) is above the vocabulary size, so only the schema bound can be shown.
    expect(MAX_ALLOWED_TYPES).toBe(64);
    expect(FILE_TYPE_IDS.length).toBeLessThanOrEqual(MAX_ALLOWED_TYPES);
    expect(violations({ allowedTypes: ['pdf', 'pdf'] })).toEqual([['allowedTypes', 'invalid']]);
    expect(violations({ allowedTypes: ['exe'] })).toEqual([['allowedTypes', 'invalid']]);
  });

  it('only raises the three rule verdicts (suspicious < malicious)', () => {
    expect(
      resolveAttachmentSettings(platform, {
        deniedTypeVerdict: 'malicious',
        typeMismatchVerdict: 'malicious',
        encryptedArchiveVerdict: 'malicious',
      }),
    ).toMatchObject({
      ok: true,
      settings: {
        deniedTypeVerdict: 'malicious',
        typeMismatchVerdict: 'malicious',
        encryptedArchiveVerdict: 'malicious',
      },
    });
    const strict: AttachmentPlatformSettings = {
      ...platform,
      deniedTypeVerdict: 'malicious',
      typeMismatchVerdict: 'malicious',
      encryptedArchiveVerdict: 'malicious',
    };
    expect(
      violations(
        {
          deniedTypeVerdict: 'suspicious',
          typeMismatchVerdict: 'suspicious',
          encryptedArchiveVerdict: 'suspicious',
        },
        strict,
      ),
    ).toEqual([
      ['deniedTypeVerdict', 'severity_lowered'],
      ['typeMismatchVerdict', 'severity_lowered'],
      ['encryptedArchiveVerdict', 'severity_lowered'],
    ]);
    expect(resolveAttachmentSettings(strict, { deniedTypeVerdict: 'malicious' })).toMatchObject({
      ok: true,
    });
    expect(violations({ deniedTypeVerdict: 'clean' })).toEqual([['deniedTypeVerdict', 'invalid']]);
  });

  it('only tightens maxAttachmentBytes within [1 MiB, platform]', () => {
    expect(
      resolveAttachmentSettings(platform, { maxAttachmentBytes: ATTACHMENT_MIN_BYTES }),
    ).toMatchObject({ ok: true, settings: { maxAttachmentBytes: 1_048_576 } });
    expect(resolveAttachmentSettings(platform, { maxAttachmentBytes: 26_214_400 })).toMatchObject({
      ok: true,
    });
    expect(violations({ maxAttachmentBytes: 26_214_401 })).toEqual([
      ['maxAttachmentBytes', 'out_of_bounds'],
    ]);
    expect(violations({ maxAttachmentBytes: 1_048_575 })).toEqual([
      ['maxAttachmentBytes', 'out_of_bounds'],
    ]);
    expect(violations({ maxAttachmentBytes: 2.5 })).toEqual([['maxAttachmentBytes', 'invalid']]);
    // A saved row becomes invalid when the platform limit is lowered later.
    expect(
      violations(
        { maxAttachmentBytes: 20_000_000 },
        { ...platform, maxAttachmentBytes: 10_485_760 },
      ),
    ).toEqual([['maxAttachmentBytes', 'out_of_bounds']]);
  });

  it('refuses unknown keys: platform-only limits and disabling are not tenant settings', () => {
    expect(violations({ enabled: false })).toEqual([['enabled', 'unknown_key']]);
    expect(violations({ archiveMaxDepth: 5, maxCompressionRatio: 1000 })).toEqual([
      ['archiveMaxDepth', 'unknown_key'],
      ['maxCompressionRatio', 'unknown_key'],
    ]);
    expect(attachmentTenantSettingsSchema.safeParse({ removeDeniedTypes: ['msi'] }).success).toBe(
      false,
    );
    expect(violations('strict')).toEqual([['settings', 'invalid']]);
    expect(violations([1])).toEqual([['settings', 'invalid']]);
  });

  it('reports every violation of one override', () => {
    expect(
      violations(
        {
          allowedTypes: ['msi'],
          maxAttachmentBytes: 1,
          deniedTypeVerdict: 'suspicious',
        },
        { ...platform, deniedTypeVerdict: 'malicious' },
      ),
    ).toEqual([
      ['allowedTypes', 'out_of_bounds'],
      ['maxAttachmentBytes', 'out_of_bounds'],
      ['deniedTypeVerdict', 'severity_lowered'],
    ]);
  });
});

describe('attachmentSettingsBounds', () => {
  it('lists the size range, the selectable types and the verdicts at or above the platform', () => {
    const bounds = attachmentSettingsBounds(platform);
    expect(bounds.maxAttachmentBytes).toEqual({ min: 1_048_576, max: 26_214_400 });
    expect(bounds.maxAllowedTypes).toBe(64);
    expect(bounds.deniedTypes).not.toContain('unknown');
    expect(bounds.deniedTypes).toHaveLength(FILE_TYPE_IDS.length - 1);
    expect([...bounds.platformDeniedTypes].sort()).toEqual(
      [...ATTACHMENT_DEFAULT_DENIED_TYPES].sort(),
    );
    for (const t of ATTACHMENT_DEFAULT_DENIED_TYPES) expect(bounds.allowedTypes).not.toContain(t);
    expect(bounds.allowedTypes).toContain('pdf');
    expect(bounds.deniedTypeVerdict).toEqual(['suspicious', 'malicious']);
    expect(
      attachmentSettingsBounds({ ...platform, encryptedArchiveVerdict: 'malicious' })
        .encryptedArchiveVerdict,
    ).toEqual(['malicious']);
  });
});

describe('settingsVersion for the attachment engine (4.1 S8 format)', () => {
  it('hashes the platform attachment settings and fits VARCHAR(96)', () => {
    const version = settingsVersion(ATTACHMENT_MAPPING_VERSION, platform, null);
    expect(version).toMatch(/^attachment-map\/1;p=[0-9a-f]{12};t=none$/);
    expect(settingsVersion(ATTACHMENT_MAPPING_VERSION, platform, 7)).toMatch(/;t=7$/);
    expect(
      settingsVersion(ATTACHMENT_MAPPING_VERSION, { ...platform, archiveMaxDepth: 4 }, null),
    ).not.toBe(version);
    expect(
      settingsVersion(ATTACHMENT_MAPPING_VERSION, platform, 4_294_967_295).length,
    ).toBeLessThanOrEqual(96);
  });
});

const cleanResult = {
  partIndex: 2,
  sha256: 'a'.repeat(64),
  sizeBytes: 1234,
  detectedType: 'pdf',
  typeFamily: 'document',
  typeMismatch: false,
  verdict: 'clean',
  reasonCodes: ['clean.no_findings'],
  clamav: { signature: null, engineVersion: '1.4.6', dbVersion: 28173 },
  yara: { bundleId: 'yara-1-0123456789ab', matches: [] },
  archive: null,
  knownHash: null,
  cache: 'miss',
  durationMs: 12,
};

const maliciousZip = {
  ...cleanResult,
  detectedType: 'zip',
  typeFamily: 'archive',
  verdict: 'malicious',
  reasonCodes: ['malware.clamav', 'yara.high', 'malware.known_hash', 'limit.archive_depth'],
  clamav: { signature: 'Win.Test.EICAR_HDB-1', engineVersion: '1.4.6', dbVersion: 28173 },
  yara: {
    bundleId: 'yara-1-0123456789ab',
    matches: [
      { rule: 'EG_Test_Marker_High', severity: 'high', scope: '0/1' },
      { rule: 'EG_Test_Marker_Medium', severity: 'medium', scope: 'attachment' },
    ],
  },
  archive: {
    format: 'zip',
    supported: true,
    entries: 3,
    depthReached: 2,
    decompressedBytes: 4096,
    maxRatio: 12.5,
    encrypted: false,
    findings: [{ path: '0/1', type: 'pe_executable', reasonCodes: ['type.denied_in_archive'] }],
  },
  knownHash: { severity: 'high', family: 'Eicar' },
  cache: 'hit',
};

describe('attachmentResultSchema (A16, A18)', () => {
  it('accepts a clean and a malicious normalized result', () => {
    expect(attachmentResultSchema.parse(cleanResult)).toEqual(cleanResult);
    expect(attachmentResultSchema.parse(maliciousZip)).toEqual(maliciousZip);
  });

  it('never carries a filename, content or an entry name (strict)', () => {
    for (const extra of [{ filename: 'invoice.pdf' }, { content: 'AAAA' }, { objectKey: 'k' }]) {
      expect(attachmentResultSchema.safeParse({ ...cleanResult, ...extra }).success).toBe(false);
    }
    const named = structuredClone(maliciousZip);
    (named.archive.findings[0] as Record<string, unknown>).name = 'evil.exe';
    expect(attachmentResultSchema.safeParse(named).success).toBe(false);
    const pathByName = structuredClone(maliciousZip);
    pathByName.archive.findings[0]!.path = 'dir/evil.exe';
    expect(attachmentResultSchema.safeParse(pathByName).success).toBe(false);
  });

  it('is clean only with a definite ClamAV OK and clean.no_findings (invariant 1)', () => {
    const bad = (patch: Record<string, unknown>) =>
      attachmentResultSchema.safeParse({ ...cleanResult, ...patch }).success;
    expect(bad({ clamav: null })).toBe(false);
    expect(
      bad({ clamav: { signature: 'Eicar-Signature', engineVersion: '1.4.6', dbVersion: 1 } }),
    ).toBe(false);
    expect(bad({ reasonCodes: ['office.macros'] })).toBe(false);
    expect(bad({ verdict: 'suspicious', reasonCodes: ['clean.no_findings'] })).toBe(false);
    expect(bad({ verdict: 'unknown', reasonCodes: ['archive.unsupported_format'] })).toBe(true);
  });

  it('bounds lists and refuses engine-level codes, unknown codes and wrong families', () => {
    const bad = (patch: Record<string, unknown>) =>
      attachmentResultSchema.safeParse({ ...maliciousZip, ...patch }).success;
    expect(bad({ typeFamily: 'document' })).toBe(false);
    expect(bad({ reasonCodes: ['malware.clamav', 'malware.clamav'] })).toBe(false);
    expect(bad({ reasonCodes: ['malware.clamav', 'attachment.none'] })).toBe(false);
    expect(bad({ reasonCodes: ['malware.clamav', 'engine.timeout'] })).toBe(false);
    expect(bad({ reasonCodes: ['spam.score'] })).toBe(false);
    expect(bad({ reasonCodes: [] })).toBe(false);
    const match = { rule: 'R', severity: 'low', scope: 'attachment' };
    expect(bad({ yara: { bundleId: 'yara-1-0123456789ab', matches: Array(33).fill(match) } })).toBe(
      false,
    );
    expect(bad({ yara: { bundleId: 'yara-1-0123456789ab', matches: Array(32).fill(match) } })).toBe(
      true,
    );
    expect(bad({ yara: { bundleId: 'eg-platform', matches: [] } })).toBe(false);
    expect(
      bad({
        yara: { bundleId: 'yara-1-0123456789ab', matches: [{ ...match, severity: 'critical' }] },
      }),
    ).toBe(false);
    const finding = maliciousZip.archive.findings[0];
    expect(bad({ archive: { ...maliciousZip.archive, findings: Array(21).fill(finding) } })).toBe(
      false,
    );
    expect(bad({ archive: { ...maliciousZip.archive, format: 'pdf' } })).toBe(false);
    expect(bad({ knownHash: { severity: 'severe', family: null } })).toBe(false);
    expect(bad({ cache: 'stale' })).toBe(false);
    expect(bad({ clamav: { signature: 'bad sig', engineVersion: '1.4.6', dbVersion: 1 } })).toBe(
      false,
    );
    expect(bad({ partIndex: 65_536 })).toBe(false);
    expect(bad({ sha256: 'A'.repeat(64) })).toBe(false);
  });
});
