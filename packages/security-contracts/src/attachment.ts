import { z } from 'zod';
import {
  FILE_TYPE_IDS,
  type FileTypeId,
  fileTypeFamilySchema,
  fileTypeIdSchema,
  fileType,
} from './file-types';
import type { SettingsViolation } from './settings';

/**
 * Contracts of the attachment engine (docs/plan/steps/10-attachment-scanning.md A5, A6, A8, A16;
 * ADR-0028): per-attachment verdicts, the bounded reason-code enum (also the metric label set of
 * `scan_attachment_findings_total`), the platform/tenant settings with their pure resolver, and
 * the normalized per-attachment result that `attachment_scan_results` rows and the scans read API
 * carry. Hashes, sizes, type ids, signature and rule names, counts and codes only: never file
 * content, never a filename, never an archive entry name (§2.0 invariant 2).
 */

/** Mapping version of the attachment verdict mapper (A6). */
export const ATTACHMENT_MAPPING_VERSION = 'attachment-map/1';

/** Verdict of one attachment (A6): `malicious > suspicious > unknown > clean`. */
export const ATTACHMENT_VERDICTS = ['clean', 'suspicious', 'malicious', 'unknown'] as const;
export type AttachmentVerdict = (typeof ATTACHMENT_VERDICTS)[number];
export const attachmentVerdictSchema = z.enum(ATTACHMENT_VERDICTS);

const ATTACHMENT_VERDICT_RANK: Readonly<Record<AttachmentVerdict, number>> = Object.freeze({
  clean: 0,
  unknown: 1,
  suspicious: 2,
  malicious: 3,
});

/** Severity rank of an attachment verdict (A6). */
export const attachmentVerdictRank = (verdict: AttachmentVerdict): number =>
  ATTACHMENT_VERDICT_RANK[verdict];

/**
 * The reason codes of the attachment engine (A6), grouped by the rule that raises them. Every
 * code matches `REASON_CODE_PATTERN`.
 */
export const ATTACHMENT_REASON_CODES = [
  // M1–M3: malicious.
  'malware.known_hash',
  'malware.clamav',
  'yara.high',
  // S1: ClamAV heuristics, PUA, its own limits.
  'clamav.heuristic',
  'clamav.pua',
  'limit.clamav',
  // S2: known hash of low/medium severity, YARA medium.
  'hash.known_suspicious',
  'yara.medium',
  // S3: limit breaches.
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
  // S1/S4: encrypted archive or entry.
  'archive.encrypted',
  // S5: type allow/deny.
  'type.denied',
  'type.not_allowed',
  'type.denied_in_archive',
  // S6: type mismatch.
  'type.mismatch',
  'type.executable_disguised',
  // S7: malformed archives.
  'archive.malformed',
  'archive.path_traversal',
  'archive.overlapping_entries',
  // U1: unsupported archive format.
  'archive.unsupported_format',
  // R: informational.
  'yara.low',
  'office.macros',
  'filename.double_extension',
  'filename.executable_extension',
  'filename.bidi_control',
  // C1: clean.
  'clean.no_findings',
  // Engine level: A0 (no attachments), E1 (parse incomplete).
  'attachment.none',
  'attachment.parse_incomplete',
  // Engine attempt failures (4.1 S5 path; never a verdict).
  'engine.timeout',
  'engine.error',
  'engine.unavailable',
  'engine.protocol_error',
  'engine.circuit_open',
  'engine.inspector_timeout',
  'engine.inspector_crash',
  'engine.part_unavailable',
  'engine.part_integrity',
  'engine.part_key_mismatch',
  'engine.parse_row_missing',
  'engine.deadline_exceeded',
  'engine.max_attempts_exceeded',
] as const;
export type AttachmentReasonCode = (typeof ATTACHMENT_REASON_CODES)[number];
export const attachmentReasonCodeSchema = z.enum(ATTACHMENT_REASON_CODES);

export const isAttachmentReasonCode = (value: string): value is AttachmentReasonCode =>
  (ATTACHMENT_REASON_CODES as readonly string[]).includes(value);

// ---------------------------------------------------------------------------------------------
// Settings (A8)
// ---------------------------------------------------------------------------------------------

/** Verdict ladder of the tunable type/encryption verdicts (raise-only for tenants). */
export const ATTACHMENT_RULE_VERDICTS = ['suspicious', 'malicious'] as const;
export type AttachmentRuleVerdict = (typeof ATTACHMENT_RULE_VERDICTS)[number];
const ruleVerdictRank = (value: AttachmentRuleVerdict): number =>
  ATTACHMENT_RULE_VERDICTS.indexOf(value);

/** The smallest per-attachment size limit a tenant may set (A8). */
export const ATTACHMENT_MIN_BYTES = 1_048_576;
/**
 * Upper bound of the platform `maxAttachmentBytes` (30 MiB = clamd `StreamMaxLength` of
 * `infrastructure/clamav/clamd.conf`, A7). Services also check it against
 * `MIME_MAX_ATTACHMENT_BYTES`.
 */
export const ATTACHMENT_MAX_BYTES_CEILING = 31_457_280;
/** At most this many entry findings per attachment result (A4, A16). */
export const MAX_ARCHIVE_FINDINGS = 20;
/** At most this many types in a tenant allow list (A8). */
export const MAX_ALLOWED_TYPES = 64;
/** At most this many YARA matches per attachment result (A4). */
export const MAX_YARA_MATCHES = 32;

const RULE_VERDICT_KEYS = [
  'deniedTypeVerdict',
  'typeMismatchVerdict',
  'encryptedArchiveVerdict',
] as const;

const unique = (values: readonly unknown[]) => new Set(values).size === values.length;

const typeListSchema = (max: number) =>
  z.array(fileTypeIdSchema).max(max).refine(unique, { message: 'Duplicate file type' });

const int = (min: number, max: number) => z.number().int().min(min).max(max);

/**
 * Platform attachment settings (env `ATTACHMENT_*`, read by the api and the email-worker). The
 * archive limits are platform-only: they decide the tenant-independent cached content result
 * (A10), so they must not depend on the tenant.
 */
export const attachmentPlatformSettingsSchema = z
  .strictObject({
    maxAttachmentBytes: int(ATTACHMENT_MIN_BYTES, ATTACHMENT_MAX_BYTES_CEILING),
    archiveMaxDepth: int(1, 16),
    archiveMaxEntries: int(1, 100_000),
    maxEntryBytes: int(1, 1_073_741_824),
    maxDecompressedBytes: int(1, 1_073_741_824),
    maxCompressionRatio: int(2, 10_000),
    maxEntryFindings: int(1, MAX_ARCHIVE_FINDINGS),
    deniedTypes: typeListSchema(FILE_TYPE_IDS.length).readonly(),
    deniedTypeVerdict: z.enum(ATTACHMENT_RULE_VERDICTS),
    typeMismatchVerdict: z.enum(ATTACHMENT_RULE_VERDICTS),
    encryptedArchiveVerdict: z.enum(ATTACHMENT_RULE_VERDICTS),
  })
  .superRefine((s, ctx) => {
    if (s.maxEntryBytes > s.maxDecompressedBytes) {
      ctx.addIssue({
        code: 'custom',
        path: ['maxEntryBytes'],
        message: 'maxEntryBytes must not exceed maxDecompressedBytes',
      });
    }
    if (s.deniedTypes.includes('unknown')) {
      ctx.addIssue({
        code: 'custom',
        path: ['deniedTypes'],
        message: 'unknown cannot be denied (undetectable content would always be denied)',
      });
    }
  });
export type AttachmentPlatformSettings = z.infer<typeof attachmentPlatformSettingsSchema>;

/** Default platform deny list (A5, `ATTACHMENT_DENIED_TYPES`): archives are not denied. */
export const ATTACHMENT_DEFAULT_DENIED_TYPES: readonly FileTypeId[] = Object.freeze([
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
] as const);

/** Platform defaults (`.env.example`, §5). */
export const ATTACHMENT_PLATFORM_DEFAULTS: Readonly<AttachmentPlatformSettings> = Object.freeze({
  maxAttachmentBytes: 26_214_400,
  archiveMaxDepth: 3,
  archiveMaxEntries: 1000,
  maxEntryBytes: 26_214_400,
  maxDecompressedBytes: 104_857_600,
  maxCompressionRatio: 100,
  maxEntryFindings: 20,
  deniedTypes: ATTACHMENT_DEFAULT_DENIED_TYPES,
  deniedTypeVerdict: 'suspicious',
  typeMismatchVerdict: 'suspicious',
  encryptedArchiveVerdict: 'suspicious',
});

/** Environment keys of the platform settings (§5). */
export const ATTACHMENT_PLATFORM_ENV_KEYS = Object.freeze({
  maxAttachmentBytes: 'ATTACHMENT_MAX_BYTES',
  archiveMaxDepth: 'ATTACHMENT_ARCHIVE_MAX_DEPTH',
  archiveMaxEntries: 'ATTACHMENT_ARCHIVE_MAX_ENTRIES',
  maxEntryBytes: 'ATTACHMENT_MAX_ENTRY_BYTES',
  maxDecompressedBytes: 'ATTACHMENT_MAX_DECOMPRESSED_BYTES',
  maxCompressionRatio: 'ATTACHMENT_MAX_COMPRESSION_RATIO',
  maxEntryFindings: 'ATTACHMENT_MAX_ENTRY_FINDINGS',
  deniedTypes: 'ATTACHMENT_DENIED_TYPES',
  deniedTypeVerdict: 'ATTACHMENT_DENIED_TYPE_VERDICT',
  typeMismatchVerdict: 'ATTACHMENT_TYPE_MISMATCH_VERDICT',
  encryptedArchiveVerdict: 'ATTACHMENT_ENCRYPTED_VERDICT',
} as const satisfies Record<keyof AttachmentPlatformSettings, string>);

const NUMERIC_KEYS = [
  'maxAttachmentBytes',
  'archiveMaxDepth',
  'archiveMaxEntries',
  'maxEntryBytes',
  'maxDecompressedBytes',
  'maxCompressionRatio',
  'maxEntryFindings',
] as const;

/**
 * Reads the platform settings from environment variables (unset or empty → default) and
 * validates them. `ATTACHMENT_DENIED_TYPES` is a comma-separated list of `FILE_TYPES` ids; the
 * literal `none` means an empty deny list. Throws a `ZodError` naming the setting on invalid
 * input, so a service refuses to start with inconsistent limits.
 */
export function attachmentPlatformSettingsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
): AttachmentPlatformSettings {
  const read = (key: keyof AttachmentPlatformSettings): string | undefined => {
    const value = env[ATTACHMENT_PLATFORM_ENV_KEYS[key]];
    return value === undefined || value.trim() === '' ? undefined : value.trim();
  };
  const numbers = Object.fromEntries(
    NUMERIC_KEYS.map((key) => {
      const value = read(key);
      return [key, value === undefined ? ATTACHMENT_PLATFORM_DEFAULTS[key] : Number(value)];
    }),
  );
  const denied = read('deniedTypes');
  const deniedTypes =
    denied === undefined
      ? [...ATTACHMENT_PLATFORM_DEFAULTS.deniedTypes]
      : denied === 'none'
        ? []
        : denied
            .split(',')
            .map((t) => t.trim())
            .filter((t) => t.length > 0);
  return attachmentPlatformSettingsSchema.parse({
    ...numbers,
    deniedTypes,
    deniedTypeVerdict: read('deniedTypeVerdict') ?? ATTACHMENT_PLATFORM_DEFAULTS.deniedTypeVerdict,
    typeMismatchVerdict:
      read('typeMismatchVerdict') ?? ATTACHMENT_PLATFORM_DEFAULTS.typeMismatchVerdict,
    encryptedArchiveVerdict:
      read('encryptedArchiveVerdict') ?? ATTACHMENT_PLATFORM_DEFAULTS.encryptedArchiveVerdict,
  });
}

/**
 * A tenant override (`scan_engine_settings.settings` of engine `attachment`, A8): strict, every
 * key optional. `deniedTypes` adds to the platform list (it can never remove a platform entry);
 * `allowedTypes` switches on allow-list mode; the three verdicts may only be raised;
 * `maxAttachmentBytes` may only be tightened. Archive, CPU and memory limits are platform-only
 * (no key here).
 */
export const attachmentTenantSettingsSchema = z.strictObject({
  deniedTypes: typeListSchema(MAX_ALLOWED_TYPES).optional(),
  allowedTypes: typeListSchema(MAX_ALLOWED_TYPES).min(1).optional(),
  deniedTypeVerdict: z.enum(ATTACHMENT_RULE_VERDICTS).optional(),
  typeMismatchVerdict: z.enum(ATTACHMENT_RULE_VERDICTS).optional(),
  encryptedArchiveVerdict: z.enum(ATTACHMENT_RULE_VERDICTS).optional(),
  maxAttachmentBytes: z.number().int().optional(),
});
export type AttachmentTenantSettings = z.infer<typeof attachmentTenantSettingsSchema>;

/** The settings the attachment verdict mapper uses for one tenant (A6, A8). */
export interface AttachmentEffectiveSettings {
  maxAttachmentBytes: number;
  /** Platform plus tenant deny list, in `FILE_TYPE_IDS` order. */
  deniedTypes: FileTypeId[];
  /** Allow list (allow-list mode), in `FILE_TYPE_IDS` order; null = every non-denied type. */
  allowedTypes: FileTypeId[] | null;
  deniedTypeVerdict: AttachmentRuleVerdict;
  typeMismatchVerdict: AttachmentRuleVerdict;
  encryptedArchiveVerdict: AttachmentRuleVerdict;
}

export type AttachmentSettingsResolution =
  | { ok: true; settings: AttachmentEffectiveSettings; overridden: boolean }
  | { ok: false; violations: SettingsViolation[] };

/** The bounds a tenant override must respect (the settings API returns them). */
export interface AttachmentSettingsBounds {
  maxAttachmentBytes: { min: number; max: number };
  /** Types a tenant may add to the deny list (every id but `unknown`). */
  deniedTypes: readonly FileTypeId[];
  /** Platform-denied types: always denied, never removable, never allowed. */
  platformDeniedTypes: readonly FileTypeId[];
  /** Types a tenant may put on an allow list. */
  allowedTypes: readonly FileTypeId[];
  maxAllowedTypes: number;
  deniedTypeVerdict: readonly AttachmentRuleVerdict[];
  typeMismatchVerdict: readonly AttachmentRuleVerdict[];
  encryptedArchiveVerdict: readonly AttachmentRuleVerdict[];
}

const inVocabularyOrder = (types: Iterable<FileTypeId>): FileTypeId[] => {
  const set = new Set(types);
  return FILE_TYPE_IDS.filter((id) => set.has(id));
};

const raisedFrom = (floor: AttachmentRuleVerdict): AttachmentRuleVerdict[] =>
  ATTACHMENT_RULE_VERDICTS.filter((v) => ruleVerdictRank(v) >= ruleVerdictRank(floor));

/** The values a tenant may choose given the platform settings. */
export function attachmentSettingsBounds(
  platform: AttachmentPlatformSettings,
): AttachmentSettingsBounds {
  const platformDenied = inVocabularyOrder(platform.deniedTypes);
  return {
    maxAttachmentBytes: { min: ATTACHMENT_MIN_BYTES, max: platform.maxAttachmentBytes },
    deniedTypes: FILE_TYPE_IDS.filter((id) => id !== 'unknown'),
    platformDeniedTypes: platformDenied,
    allowedTypes: FILE_TYPE_IDS.filter((id) => !platformDenied.includes(id)),
    maxAllowedTypes: MAX_ALLOWED_TYPES,
    deniedTypeVerdict: raisedFrom(platform.deniedTypeVerdict),
    typeMismatchVerdict: raisedFrom(platform.typeMismatchVerdict),
    encryptedArchiveVerdict: raisedFrom(platform.encryptedArchiveVerdict),
  };
}

const platformEffective = (platform: AttachmentPlatformSettings): AttachmentEffectiveSettings => ({
  maxAttachmentBytes: platform.maxAttachmentBytes,
  deniedTypes: inVocabularyOrder(platform.deniedTypes),
  allowedTypes: null,
  deniedTypeVerdict: platform.deniedTypeVerdict,
  typeMismatchVerdict: platform.typeMismatchVerdict,
  encryptedArchiveVerdict: platform.encryptedArchiveVerdict,
});

/**
 * Merges a tenant override (raw JSON from `scan_engine_settings.settings`, or null/undefined for
 * none) into the platform settings (A8). Pure; mirrors `resolveRspamdSettings`. An invalid
 * override yields every violation found; the caller decides what to do (the api answers 422; the
 * worker ignores the row and applies the platform settings).
 */
export function resolveAttachmentSettings(
  platform: AttachmentPlatformSettings,
  override: unknown,
): AttachmentSettingsResolution {
  if (override === null || override === undefined) {
    return { ok: true, settings: platformEffective(platform), overridden: false };
  }
  const parsed = attachmentTenantSettingsSchema.safeParse(override);
  if (!parsed.success) {
    return {
      ok: false,
      violations: parsed.error.issues.flatMap((issue): SettingsViolation[] => {
        if (issue.code === 'unrecognized_keys') {
          return issue.keys.map((key) => ({
            path: key,
            code: 'unknown_key',
            message: `Unknown setting: ${key}`,
          }));
        }
        return [
          {
            path: issue.path.length > 0 ? String(issue.path[0]) : 'settings',
            code: 'invalid',
            message: issue.message,
          },
        ];
      }),
    };
  }
  const tenant = parsed.data;
  const base = platformEffective(platform);
  const violations: SettingsViolation[] = [];

  if (tenant.deniedTypes?.includes('unknown')) {
    violations.push({
      path: 'deniedTypes',
      code: 'invalid',
      message: 'unknown cannot be denied',
    });
  }
  const denied = inVocabularyOrder([...base.deniedTypes, ...(tenant.deniedTypes ?? [])]);

  let allowed: FileTypeId[] | null = null;
  if (tenant.allowedTypes !== undefined) {
    const conflicting = tenant.allowedTypes.filter((t) => denied.includes(t));
    const platformDenied = conflicting.filter((t) => base.deniedTypes.includes(t));
    if (platformDenied.length > 0) {
      violations.push({
        path: 'allowedTypes',
        code: 'out_of_bounds',
        message: `allowedTypes must not contain platform-denied types: ${platformDenied.join(', ')}`,
      });
    }
    const tenantDenied = conflicting.filter((t) => !base.deniedTypes.includes(t));
    if (tenantDenied.length > 0) {
      violations.push({
        path: 'allowedTypes',
        code: 'out_of_bounds',
        message: `allowedTypes must not contain types of deniedTypes: ${tenantDenied.join(', ')}`,
      });
    }
    allowed = inVocabularyOrder(tenant.allowedTypes);
  }

  if (
    tenant.maxAttachmentBytes !== undefined &&
    (tenant.maxAttachmentBytes < ATTACHMENT_MIN_BYTES ||
      tenant.maxAttachmentBytes > platform.maxAttachmentBytes)
  ) {
    violations.push({
      path: 'maxAttachmentBytes',
      code: 'out_of_bounds',
      message: `maxAttachmentBytes must be within [${ATTACHMENT_MIN_BYTES}, ${platform.maxAttachmentBytes}]`,
    });
  }

  for (const key of RULE_VERDICT_KEYS) {
    const value = tenant[key];
    if (value !== undefined && ruleVerdictRank(value) < ruleVerdictRank(platform[key])) {
      violations.push({
        path: key,
        code: 'severity_lowered',
        message: `${key} may only be raised from the platform value ${platform[key]}`,
      });
    }
  }
  if (violations.length > 0) return { ok: false, violations };

  return {
    ok: true,
    overridden: Object.values(tenant).some((value) => value !== undefined),
    settings: {
      maxAttachmentBytes: tenant.maxAttachmentBytes ?? base.maxAttachmentBytes,
      deniedTypes: denied,
      allowedTypes: allowed,
      deniedTypeVerdict: tenant.deniedTypeVerdict ?? base.deniedTypeVerdict,
      typeMismatchVerdict: tenant.typeMismatchVerdict ?? base.typeMismatchVerdict,
      encryptedArchiveVerdict: tenant.encryptedArchiveVerdict ?? base.encryptedArchiveVerdict,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Normalized per-attachment result (A6, A16, A18)
// ---------------------------------------------------------------------------------------------

const sha256Hex = z.string().regex(/^[0-9a-f]{64}$/, 'Expected a lower-case hex SHA-256');

/** A ClamAV signature name (A7: validated before use). */
export const CLAMAV_SIGNATURE_PATTERN = /^[\x21-\x7e]{1,128}$/;
/** A YARA rule identifier. */
export const YARA_RULE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
/** YARA bundle id (A9): `yara-<version>-<12 hex>`. */
export const YARA_BUNDLE_ID_PATTERN = /^yara-(0|[1-9][0-9]{0,8})-[0-9a-f]{12}$/;
/** Index path of an archive entry (A4): `"2/0/5"`, never a name. */
export const ARCHIVE_INDEX_PATH_PATTERN = /^(0|[1-9][0-9]{0,5})(\/(0|[1-9][0-9]{0,5})){0,15}$/;

export const YARA_SEVERITIES = ['high', 'medium', 'low'] as const;
export type YaraSeverity = (typeof YARA_SEVERITIES)[number];

/** Severities of `malware_signatures` (Prisma `Severity`). */
export const KNOWN_HASH_SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
export type KnownHashSeverity = (typeof KNOWN_HASH_SEVERITIES)[number];

export const ATTACHMENT_CACHE_RESULTS = ['hit', 'miss', 'bypass'] as const;
export type AttachmentCacheResult = (typeof ATTACHMENT_CACHE_RESULTS)[number];

const noControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
};

const ENGINE_LEVEL_CODES: ReadonlySet<string> = new Set([
  'attachment.none',
  'attachment.parse_incomplete',
]);

const reasonCodeList = (max: number) =>
  z.array(attachmentReasonCodeSchema).max(max).refine(unique, { message: 'Duplicate reason code' });

export const attachmentClamavResultSchema = z.strictObject({
  /** The signature ClamAV reported (`FOUND`); null for `OK`. */
  signature: z.string().regex(CLAMAV_SIGNATURE_PATTERN).nullable(),
  engineVersion: z.string().min(1).max(32).refine(noControl),
  dbVersion: z.number().int().nonnegative(),
});

export const yaraMatchSchema = z.strictObject({
  rule: z.string().regex(YARA_RULE_PATTERN),
  severity: z.enum(YARA_SEVERITIES),
  /** `attachment` or the index path of the archive entry that matched. */
  scope: z.union([z.literal('attachment'), z.string().regex(ARCHIVE_INDEX_PATH_PATTERN)]),
});
export type YaraMatch = z.infer<typeof yaraMatchSchema>;

export const attachmentYaraResultSchema = z.strictObject({
  bundleId: z.string().max(48).regex(YARA_BUNDLE_ID_PATTERN),
  matches: z.array(yaraMatchSchema).max(MAX_YARA_MATCHES),
});

export const archiveFindingSchema = z.strictObject({
  path: z.string().regex(ARCHIVE_INDEX_PATH_PATTERN),
  type: fileTypeIdSchema,
  reasonCodes: reasonCodeList(16).min(1),
});
export type ArchiveFinding = z.infer<typeof archiveFindingSchema>;

export const attachmentArchiveResultSchema = z.strictObject({
  /** The archive's type id (a type of the `archive` family). */
  format: fileTypeIdSchema.refine((id) => fileType(id).family === 'archive', {
    message: 'Expected an archive type',
  }),
  /** False for formats the inspector does not open (7z, rar, cab, bzip2, xz; rule U1). */
  supported: z.boolean(),
  /** Entries seen, summed over all levels. */
  entries: z.number().int().nonnegative(),
  depthReached: z.number().int().nonnegative(),
  decompressedBytes: z.number().int().nonnegative(),
  maxRatio: z.number().finite().nonnegative(),
  encrypted: z.boolean(),
  findings: z.array(archiveFindingSchema).max(MAX_ARCHIVE_FINDINGS),
});

export const knownHashResultSchema = z.strictObject({
  severity: z.enum(KNOWN_HASH_SEVERITIES),
  family: z.string().min(1).max(128).refine(noControl).nullable(),
});

/**
 * One attachment's normalized result (A6, A16 without `filename` and `sandbox`, A18): the shape
 * of an `attachment_scan_results` row. Strict, so no filename, content or entry name can be
 * added. `clean` (rule C1) requires a definite ClamAV `OK` and the reason code
 * `clean.no_findings`, which no other verdict carries (§2.0 invariant 1).
 */
export const attachmentResultSchema = z
  .strictObject({
    partIndex: z.number().int().min(0).max(65_535),
    sha256: sha256Hex,
    sizeBytes: z.number().int().nonnegative(),
    detectedType: fileTypeIdSchema,
    typeFamily: fileTypeFamilySchema,
    typeMismatch: z.boolean(),
    verdict: attachmentVerdictSchema,
    reasonCodes: reasonCodeList(32).min(1),
    clamav: attachmentClamavResultSchema.nullable(),
    yara: attachmentYaraResultSchema.nullable(),
    archive: attachmentArchiveResultSchema.nullable(),
    knownHash: knownHashResultSchema.nullable(),
    cache: z.enum(ATTACHMENT_CACHE_RESULTS),
    durationMs: z.number().int().nonnegative(),
  })
  .superRefine((result, ctx) => {
    if (fileType(result.detectedType).family !== result.typeFamily) {
      ctx.addIssue({
        code: 'custom',
        path: ['typeFamily'],
        message: 'typeFamily must be the family of detectedType',
      });
    }
    const cleanCode = result.reasonCodes.includes('clean.no_findings');
    if (result.verdict === 'clean') {
      if (!cleanCode) {
        ctx.addIssue({
          code: 'custom',
          path: ['reasonCodes'],
          message: 'clean requires clean.no_findings',
        });
      }
      if (result.clamav === null || result.clamav.signature !== null) {
        ctx.addIssue({
          code: 'custom',
          path: ['clamav'],
          message: 'clean requires a definite ClamAV OK',
        });
      }
    } else if (cleanCode) {
      ctx.addIssue({
        code: 'custom',
        path: ['reasonCodes'],
        message: 'clean.no_findings is reserved for the clean verdict',
      });
    }
    for (const [index, code] of result.reasonCodes.entries()) {
      if (ENGINE_LEVEL_CODES.has(code) || code.startsWith('engine.')) {
        ctx.addIssue({
          code: 'custom',
          path: ['reasonCodes', index],
          message: 'Engine-level code in an attachment result',
        });
      }
    }
  });
export type AttachmentResult = z.infer<typeof attachmentResultSchema>;

/** Codes that describe the engine's result as a whole, never one attachment (A0, E1). */
export const ATTACHMENT_ENGINE_LEVEL_CODES = Object.freeze([
  'attachment.none',
  'attachment.parse_incomplete',
] as const satisfies readonly AttachmentReasonCode[]);
