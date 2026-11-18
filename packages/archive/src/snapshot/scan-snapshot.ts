import { z } from 'zod';
import {
  decimalIdSchema,
  isoDateTimeSchema,
  uuidSchema,
  ArchiveDocumentError,
} from '../documents/common';
import { decodeTagged, encodeTagged } from './codec';

/**
 * `archive-scan/1` (§4.2, A5): the frozen read-model rows of one scan round and risk revision,
 * stored as an encrypted object of kind `scan`. Row values use the tagged codec; the columns are
 * those of `packages/database/src/read-models/scan-read-model.ts`, so the api decodes a snapshot
 * back into the same row types and maps it with the live mapper.
 */

export const SCAN_SNAPSHOT_ROW_LISTS = [
  'engines',
  'auth',
  'attachments',
  'attachmentParts',
  'sandboxSubmissions',
  'sandboxAnalyses',
  'sandboxArtifacts',
  'urls',
  'urlResults',
  'urlRewrites',
  'urlInspections',
  'bec',
  'dlp',
  'risk',
] as const;
export type ScanSnapshotRowList = (typeof SCAN_SNAPSHOT_ROW_LISTS)[number];

const taggedRow = z.record(z.string(), z.unknown());
const rowList = z.array(taggedRow).max(100_000);

export const archiveScanSnapshotSchema = z.strictObject({
  version: z.literal('archive-scan/1'),
  organizationId: decimalIdSchema,
  messageId: uuidSchema,
  round: z.number().int().min(0).max(65_535),
  revision: z.number().int().min(0).max(65_535),
  frozenAt: isoDateTimeSchema,
  rows: z.strictObject({
    scan: taggedRow.nullable(),
    engines: rowList,
    auth: rowList,
    attachments: rowList,
    attachmentParts: rowList,
    sandboxSubmissions: rowList,
    sandboxAnalyses: rowList,
    sandboxArtifacts: rowList,
    urls: rowList,
    urlResults: rowList,
    urlRewrites: rowList,
    urlInspections: rowList,
    bec: rowList,
    dlp: rowList,
    risk: rowList,
    policy: taggedRow.nullable(),
  }),
});
export type ArchiveScanSnapshotDocument = z.infer<typeof archiveScanSnapshotSchema>;

/** Decoded rows: BigInt and Date restored. */
export type ScanSnapshotRows = {
  scan: Record<string, unknown> | null;
  policy: Record<string, unknown> | null;
} & Record<ScanSnapshotRowList, Record<string, unknown>[]>;

export interface ScanSnapshotInput {
  organizationId: string;
  messageId: string;
  round: number;
  revision: number;
  frozenAt: Date;
  rows: ScanSnapshotRows;
}

export type ScanSnapshot = ScanSnapshotInput;

/** Builds the document (rows tagged) and its UTF-8 JSON bytes (the plaintext of the object). */
export function buildScanSnapshot(input: ScanSnapshotInput): {
  document: ArchiveScanSnapshotDocument;
  bytes: Buffer;
} {
  const raw = {
    version: 'archive-scan/1' as const,
    organizationId: input.organizationId,
    messageId: input.messageId,
    round: input.round,
    revision: input.revision,
    frozenAt: input.frozenAt.toISOString(),
    rows: encodeTagged(input.rows),
  };
  const parsed = archiveScanSnapshotSchema.safeParse(raw);
  if (!parsed.success) throw new ArchiveDocumentError('archive-scan/1');
  return { document: parsed.data, bytes: Buffer.from(JSON.stringify(parsed.data), 'utf8') };
}

/** Parses the decrypted bytes of a scan object and decodes its rows. */
export function parseScanSnapshot(bytes: Buffer | string): ScanSnapshot {
  let json: unknown;
  try {
    json = JSON.parse(typeof bytes === 'string' ? bytes : bytes.toString('utf8'));
  } catch {
    throw new ArchiveDocumentError('archive-scan/1');
  }
  const parsed = archiveScanSnapshotSchema.safeParse(json);
  if (!parsed.success) throw new ArchiveDocumentError('archive-scan/1');
  const d = parsed.data;
  let rows: ScanSnapshotRows;
  try {
    rows = decodeTagged(d.rows) as ScanSnapshotRows;
  } catch {
    throw new ArchiveDocumentError('archive-scan/1');
  }
  return {
    organizationId: d.organizationId,
    messageId: d.messageId,
    round: d.round,
    revision: d.revision,
    frozenAt: new Date(d.frozenAt),
    rows,
  };
}
