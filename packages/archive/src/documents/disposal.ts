import { z } from 'zod';
import type { NumericId } from '../ids';
import { archivePrefixOf, isKeyOfOrganization } from '../keys';
import { uuidSchema } from './common';
import { archiveRecordObjectsSchema } from './records';

/**
 * `archive_disposals.objects` and `archive_disposals.replica_status` (A14 step 1). Every writer of
 * a disposal decision — the archive-worker's retention expiry and the api's manual dispose and
 * organization purge — builds them here, so the lifecycle pipeline always reads one shape.
 */

const versionRefSchema = z.strictObject({
  key: z.string().min(1).max(1024),
  versionId: z.string().min(1).max(1024).nullable(),
});

/** What a disposal decision recorded: the record prefix and exact versions (no content). */
export const disposalObjectsSchema = z.strictObject({
  captureId: uuidSchema.nullable(),
  /** Prefix of every object of the record (`org/<org>/archive/<yyyy>/<mm>/<dd>/<message>/`). */
  prefix: z.string().min(1).max(1024),
  versions: z.array(versionRefSchema).max(64),
});
export type DisposalObjects = z.infer<typeof disposalObjectsSchema>;

/** Replica targets recorded at the decision and versions still under an object lock. */
export const disposalReplicaStatusSchema = z.strictObject({
  targets: z.array(z.string().min(1).max(255)).max(16),
  pending: z
    .array(
      z.strictObject({
        bucket: z.string().min(1).max(255),
        key: z.string().min(1).max(1024),
        versionId: z.string().min(1).max(1024),
        retainUntil: z.string().nullable(),
      }),
    )
    .max(1_000_000),
});
export type DisposalReplicaStatus = z.infer<typeof disposalReplicaStatusSchema>;

/** The identity of an archive record a disposal is decided for. */
export interface DisposalRecordIds {
  organizationId: NumericId;
  receivedAt: Date;
  messagePublicId: string;
}

/**
 * The versions a record's `objects` column (`archive-record-objects`) names — EML, journal and
 * every scan snapshot — keeping only keys of the record's own organization.
 */
export function recordVersions(record: { objects: unknown; organizationId: NumericId }): Array<{
  key: string;
  versionId: string | null;
}> {
  const parsed = archiveRecordObjectsSchema.safeParse(parseMaybeJson(record.objects));
  if (!parsed.success) return [];
  const o = parsed.data;
  return [o.eml, o.journal, ...o.scans]
    .filter((v) => isKeyOfOrganization(v.key, record.organizationId, 'archive'))
    .map((v) => ({ key: v.key, versionId: v.versionId }));
}

/** `archive_disposals.objects` for a record (its `objects` column and identity). */
export function disposalObjectsOf(
  record: DisposalRecordIds & { objects: unknown },
): DisposalObjects {
  const parsed = archiveRecordObjectsSchema.safeParse(parseMaybeJson(record.objects));
  return {
    captureId: parsed.success ? parsed.data.captureId : null,
    prefix: archivePrefixOf(record),
    versions: recordVersions(record),
  };
}

/** `archive_disposals.replica_status` at the decision: the targets, nothing pending yet. */
export function disposalReplicaStatusOf(targets: readonly string[]): DisposalReplicaStatus {
  return { targets: [...targets], pending: [] };
}

/**
 * Reads a stored `archive_disposals.objects` value. A `disposal-objects` document is returned as
 * is; an `archive-record-objects` document (rows written before the writers shared this builder)
 * is converted with the record identity; anything else falls back to the record prefix with no
 * recorded versions (step 2 still deletes every version under the prefix). `shape` says which.
 */
export function readDisposalObjects(
  value: unknown,
  ids: DisposalRecordIds,
): { objects: DisposalObjects; shape: 'disposal' | 'record' | 'fallback' } {
  const raw = parseMaybeJson(value);
  const direct = disposalObjectsSchema.safeParse(raw);
  if (direct.success && direct.data.prefix === archivePrefixOf(ids)) {
    return { objects: direct.data, shape: 'disposal' };
  }
  if (archiveRecordObjectsSchema.safeParse(raw).success) {
    return { objects: disposalObjectsOf({ ...ids, objects: raw }), shape: 'record' };
  }
  return {
    objects: { captureId: null, prefix: archivePrefixOf(ids), versions: [] },
    shape: 'fallback',
  };
}

/** Reads a stored `archive_disposals.replica_status`; malformed or missing → no targets. */
export function readDisposalReplicaStatus(value: unknown): DisposalReplicaStatus {
  const parsed = disposalReplicaStatusSchema.safeParse(parseMaybeJson(value));
  return parsed.success ? parsed.data : { targets: [], pending: [] };
}

function parseMaybeJson(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
}
