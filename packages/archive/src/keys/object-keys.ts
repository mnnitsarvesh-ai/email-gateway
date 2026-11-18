import { decimalIdOrNull, isUuid, type NumericId } from '../ids';

/**
 * S3 keys of the archive bucket (§4.1, ADR-0065):
 *
 *     org/{organizationId}/archive/{yyyy}/{mm}/{dd}/{messagePublicId}/{captureId}/eml.bin
 *     …/{captureId}/journal.bin
 *     …/{captureId}/scan-r{round}-v{revision}.bin
 *     org/{organizationId}/exports/{yyyy}/{mm}/{exportPublicId}.bin
 *
 * Dates are the UTC date of `received_at` (exports: of creation). Keys are attempt-scoped
 * (`captureId`), so objects are written once and never overwritten (A6).
 */

export class ArchiveKeyError extends Error {
  constructor() {
    super('Invalid archive object key');
    this.name = 'ArchiveKeyError';
  }
}

const pad = (n: number, width: number) => String(n).padStart(width, '0');

function org(organizationId: NumericId): string {
  const id = decimalIdOrNull(organizationId);
  if (id === null) throw new ArchiveKeyError();
  return id;
}

function uuid(value: string): string {
  if (!isUuid(value)) throw new ArchiveKeyError();
  return value;
}

function utcDate(date: Date): { yyyy: string; mm: string; dd: string } {
  const t = date.getTime();
  if (!Number.isFinite(t)) throw new ArchiveKeyError();
  const y = date.getUTCFullYear();
  if (y < 1970 || y > 9999) throw new ArchiveKeyError();
  return { yyyy: pad(y, 4), mm: pad(date.getUTCMonth() + 1, 2), dd: pad(date.getUTCDate(), 2) };
}

function small(n: number | undefined): number {
  if (n === undefined || !Number.isInteger(n) || n < 0 || n > 65_535) throw new ArchiveKeyError();
  return n;
}

export type ArchiveRecordObjectKind = 'eml' | 'journal' | 'scan';

/** `org/{org}/archive/{yyyy}/{mm}/{dd}/{messagePublicId}/` — every object of a record. */
export function archivePrefixOf(ids: {
  organizationId: NumericId;
  receivedAt: Date;
  messagePublicId: string;
}): string {
  const d = utcDate(ids.receivedAt);
  return `org/${org(ids.organizationId)}/archive/${d.yyyy}/${d.mm}/${d.dd}/${uuid(ids.messagePublicId)}/`;
}

/** The day prefix of an organization's archive objects (orphan reconciliation, A15). */
export function archiveDayPrefixOf(organizationId: NumericId, day: Date): string {
  const d = utcDate(day);
  return `org/${org(organizationId)}/archive/${d.yyyy}/${d.mm}/${d.dd}/`;
}

export function archiveObjectKey(ids: {
  organizationId: NumericId;
  receivedAt: Date;
  messagePublicId: string;
  captureId: string;
  kind: ArchiveRecordObjectKind;
  round?: number;
  revision?: number;
}): string {
  const base = `${archivePrefixOf(ids)}${uuid(ids.captureId)}/`;
  switch (ids.kind) {
    case 'eml':
      return `${base}eml.bin`;
    case 'journal':
      return `${base}journal.bin`;
    case 'scan':
      return `${base}scan-r${small(ids.round)}-v${small(ids.revision)}.bin`;
    default:
      throw new ArchiveKeyError();
  }
}

export function exportObjectKey(ids: {
  organizationId: NumericId;
  createdAt: Date;
  exportPublicId: string;
}): string {
  const d = utcDate(ids.createdAt);
  return `org/${org(ids.organizationId)}/exports/${d.yyyy}/${d.mm}/${uuid(ids.exportPublicId)}.bin`;
}

/** Object tag of export packages (bucket lifecycle backstop, A29). */
export const EXPORT_OBJECT_TAG = Object.freeze({ key: 'eg-object', value: 'archive-export' });

/**
 * Asserts that a key read or written belongs to the organization (invariant 2): it starts with
 * `org/<organizationId>/<prefix>/` and has no empty, `.` or `..` segment. `prefix` is the
 * second-level area (`archive`, `exports`, `eml`, `part`, …).
 */
export function assertKeyOfOrganization(
  key: string,
  organizationId: NumericId,
  prefix: string,
): string {
  if (typeof key !== 'string' || key.length === 0 || key.length > 1024) throw new ArchiveKeyError();
  if (!/^[a-z][a-z0-9-]{0,31}$/.test(prefix)) throw new ArchiveKeyError();
  const expected = `org/${org(organizationId)}/${prefix}/`;
  if (!key.startsWith(expected) || key.length === expected.length) throw new ArchiveKeyError();
  if (key.split('/').some((s) => s === '' || s === '.' || s === '..')) throw new ArchiveKeyError();
  if ([...key].some((ch) => ch.charCodeAt(0) < 0x20 || ch === '\u007f' || ch === '\\')) {
    throw new ArchiveKeyError();
  }
  return key;
}

/** Boolean form of `assertKeyOfOrganization`. */
export function isKeyOfOrganization(
  key: string,
  organizationId: NumericId,
  prefix: string,
): boolean {
  try {
    assertKeyOfOrganization(key, organizationId, prefix);
    return true;
  } catch {
    return false;
  }
}
