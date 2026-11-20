import {
  type ArchiveMergedCopy,
  archiveRecordObjectsSchema,
  type DisposalObjects,
  disposalObjectsOf,
  isKeyOfOrganization,
  type NumericId,
  recordVersions,
} from '@email-gateway/archive';

/**
 * Every object version an `email_archives` row names (step 8.6 D7, ADR-0088 amends ADR-0067): the
 * 8.1 `recordVersions` (primary EML, journal, scan snapshots) plus each merged copy's journal
 * object and content variant (`objects.merged`). Only keys of the record's own organization.
 * Disposal, the Object Lock pass, the orphan reconciliation and exports use this list, so the
 * objects of merged copies (stored under the merged message's own prefix) are never orphans and
 * are always disposed of with their record.
 */

const parseMaybeJson = (value: unknown): unknown => {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return null;
  }
};

/** The merged copies of a record's `objects` (empty for 8.1 records or an unreadable value). */
export function mergedCopiesOf(objects: unknown): ArchiveMergedCopy[] {
  const parsed = archiveRecordObjectsSchema.safeParse(parseMaybeJson(objects));
  return parsed.success ? (parsed.data.merged ?? []) : [];
}

export function recordVersionsWithMerged(record: {
  objects: unknown;
  organizationId: NumericId;
}): Array<{ key: string; versionId: string | null }> {
  const merged = mergedCopiesOf(record.objects).flatMap((m) =>
    [m.journal, m.eml]
      .filter((v): v is NonNullable<typeof v> => v !== null)
      .filter((v) => isKeyOfOrganization(v.key, record.organizationId, 'archive'))
      .map((v) => ({ key: v.key, versionId: v.versionId })),
  );
  return [...recordVersions(record), ...merged];
}

/**
 * `archive_disposals.objects` of a record including its merged copies' versions (the prefix stays
 * the record's own; merged versions lie under their message's prefix and are deleted by version).
 */
export function disposalObjectsWithMerged(record: {
  organizationId: NumericId;
  receivedAt: Date;
  messagePublicId: string;
  objects: unknown;
}): DisposalObjects {
  const base = disposalObjectsOf(record);
  const known = new Set(base.versions.map((v) => `${v.key}\0${v.versionId ?? ''}`));
  const extra = recordVersionsWithMerged(record).filter(
    (v) => !known.has(`${v.key}\0${v.versionId ?? ''}`),
  );
  return { ...base, versions: [...base.versions, ...extra] };
}
