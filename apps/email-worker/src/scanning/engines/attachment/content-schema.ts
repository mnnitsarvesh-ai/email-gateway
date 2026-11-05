import {
  ARCHIVE_INDEX_PATH_PATTERN,
  CLAMAV_SIGNATURE_PATTERN,
  fileTypeFamilySchema,
  fileTypeIdSchema,
  YARA_BUNDLE_ID_PATTERN,
  yaraMatchSchema,
} from '@email-gateway/security-contracts';
import { z } from 'zod';
import type { ContentResult, InspectorCode } from './content';

/**
 * The runtime schema of a cached content result (step 4.2 A10), worker side only: the inspector
 * child never imports it (its module graph stays minimal, A4).
 */

/** Every `InspectorCode` (its runtime list). */
export const INSPECTOR_CODES = [
  'limit.archive_depth',
  'limit.archive_entries',
  'limit.entry_size',
  'limit.decompressed_size',
  'limit.compression_ratio',
  'limit.cpu_time',
  'limit.memory',
  'limit.yara_timeout',
  'archive.encrypted',
  'archive.malformed',
  'archive.path_traversal',
  'archive.overlapping_entries',
  'archive.unsupported_format',
  'office.macros',
  'type.mismatch',
  'type.executable_disguised',
] as const satisfies readonly InspectorCode[];

const inspectorCode = z.enum(INSPECTOR_CODES);
const indexPath = z.string().regex(ARCHIVE_INDEX_PATH_PATTERN);
const count = z.number().int().nonnegative();
/** Upper bound of every list of a content result (the platform maximum of archive entries). */
const MAX_LIST = 100_000;

/**
 * Strict schema of a `ContentResult` (step 4.2 A10): a cached value is accepted only when it has
 * exactly this shape (after its MAC was verified), so no extra or malformed field reaches the
 * verdict mapper.
 */
export const contentResultSchema = z.strictObject({
  inspectorVersion: z.string().min(1).max(32),
  type: z.strictObject({
    detected: fileTypeIdSchema,
    family: fileTypeFamilySchema,
    executable: z.boolean(),
    textLike: z.boolean(),
  }),
  clamav: z.strictObject({
    status: z.enum(['clean', 'found', 'size_limit']),
    signature: z.string().regex(CLAMAV_SIGNATURE_PATTERN).nullable(),
    engineVersion: z.string().min(1).max(32),
    dbVersion: count,
  }),
  yara: z
    .strictObject({
      bundleId: z.string().max(48).regex(YARA_BUNDLE_ID_PATTERN),
      matches: z.array(yaraMatchSchema).max(32),
    })
    .nullable(),
  archive: z
    .strictObject({
      format: fileTypeIdSchema,
      supported: z.boolean(),
      depthReached: count,
      entries: count,
      decompressedBytes: count,
      maxRatio: z.number().finite().nonnegative(),
      encrypted: z.boolean(),
      malformed: z.boolean(),
      findings: z
        .array(
          z.strictObject({
            path: indexPath,
            type: fileTypeIdSchema,
            codes: z.array(inspectorCode).max(16),
          }),
        )
        .max(MAX_LIST),
      findingCount: count,
      entryHashes: z
        .array(
          z.strictObject({
            path: indexPath,
            sha256: z.string().regex(/^[0-9a-f]{64}$/),
            type: fileTypeIdSchema,
            ext: fileTypeIdSchema.nullable(),
          }),
        )
        .max(MAX_LIST),
    })
    .nullable(),
  limits: z.array(inspectorCode).max(INSPECTOR_CODES.length),
  codes: z.array(inspectorCode).max(INSPECTOR_CODES.length),
}) satisfies z.ZodType<ContentResult>;
