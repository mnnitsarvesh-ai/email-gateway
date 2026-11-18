import { hkdfSync, randomBytes } from 'node:crypto';
import { decimalIdOrNull, isPositiveInt, isUuid, type NumericId } from '../ids';
import { ArchiveCryptoError } from './errors';
import type { ArchiveRootKeyProvider, RootUnwrapResult } from './root-keys';
import { DATA_KEY_BYTES, openSecretBox, parseSecretBox, sealSecretBox } from './secret-box';

/**
 * The archive key hierarchy below the root (A8, ADR-0065):
 *
 * - tenant key per (organization, version), wrapped by the root key, AAD
 *   `eg-archive-tenant-key/v1\0<organizationId>\0<version>`;
 * - record data key (DEK) per record, wrapped by the tenant key version, AAD
 *   `eg-archive-dek/v1\0<organizationId>\0<messagePublicId>\0<captureId>\0<keyVersion>`,
 *   format `v1.k<version>.<iv>.<tag>.<ct>`;
 * - export DEK per export, AAD `eg-archive-export-dek/v1\0<organizationId>\0<exportPublicId>\0<keyVersion>`;
 * - object keys derived from a DEK with HKDF-SHA256 (fresh 32-byte salt per object, info
 *   `eg-archive-object/v1\0<kind>\0<organizationId>\0<subjectId>`).
 *
 * `organizationId` is always the internal decimal id (the id in S3 keys and rows).
 */

export const ARCHIVE_OBJECT_KINDS = ['eml', 'journal', 'scan', 'export'] as const;
export type ArchiveObjectKind = (typeof ARCHIVE_OBJECT_KINDS)[number];
export const OBJECT_SALT_BYTES = 32;
export const KEY_VERSION_MAX = 0xffff_ffff;

/** 32 random bytes: a tenant key or a record/export DEK. */
export function generateDataKey(): Buffer {
  return randomBytes(DATA_KEY_BYTES);
}

function org(organizationId: NumericId): string {
  const id = decimalIdOrNull(organizationId);
  if (id === null) throw new ArchiveCryptoError('malformed');
  return id;
}

function version(value: number): number {
  if (!isPositiveInt(value, KEY_VERSION_MAX)) throw new ArchiveCryptoError('malformed');
  return value;
}

function uuid(value: string): string {
  if (!isUuid(value)) throw new ArchiveCryptoError('malformed');
  return value;
}

function key32(key: Buffer): Buffer {
  if (!Buffer.isBuffer(key) || key.length !== DATA_KEY_BYTES) {
    throw new ArchiveCryptoError('malformed');
  }
  return key;
}

export interface TenantKeyIds {
  organizationId: NumericId;
  version: number;
}

export function tenantKeyAad(ids: TenantKeyIds): string {
  return `eg-archive-tenant-key/v1\0${org(ids.organizationId)}\0${version(ids.version)}`;
}

/** Wraps a tenant key version under the current root key (`archive_encryption_keys.wrapped_key`). */
export async function wrapTenantKey(
  provider: ArchiveRootKeyProvider,
  ids: TenantKeyIds,
  tenantKey: Buffer,
): Promise<string> {
  return provider.wrap(key32(tenantKey), tenantKeyAad(ids));
}

/** Unwraps a tenant key version; `usedPreviousKey` asks for a root re-wrap (A9). */
export async function unwrapTenantKey(
  provider: ArchiveRootKeyProvider,
  wrapped: string,
  ids: TenantKeyIds,
): Promise<RootUnwrapResult> {
  return provider.unwrap(wrapped, tenantKeyAad(ids));
}

export interface RecordKeyIds {
  organizationId: NumericId;
  messagePublicId: string;
  captureId: string;
  keyVersion: number;
}

export function recordKeyAad(ids: RecordKeyIds): string {
  return `eg-archive-dek/v1\0${org(ids.organizationId)}\0${uuid(ids.messagePublicId)}\0${uuid(
    ids.captureId,
  )}\0${version(ids.keyVersion)}`;
}

export interface ExportKeyIds {
  organizationId: NumericId;
  exportPublicId: string;
  keyVersion: number;
}

export function exportKeyAad(ids: ExportKeyIds): string {
  return `eg-archive-export-dek/v1\0${org(ids.organizationId)}\0${uuid(ids.exportPublicId)}\0${version(
    ids.keyVersion,
  )}`;
}

const tenantKid = (keyVersion: number): string => `k${version(keyVersion)}`;

function unwrapUnderTenant(
  tenantKey: Buffer,
  wrapped: string,
  keyVersion: number,
  aad: string,
): Buffer {
  const box = parseSecretBox(wrapped);
  if (box.kid !== tenantKid(keyVersion)) throw new ArchiveCryptoError('unauthentic');
  const plain = openSecretBox(key32(tenantKey), box, aad);
  if (plain === null || plain.length !== DATA_KEY_BYTES) {
    throw new ArchiveCryptoError('unauthentic');
  }
  return plain;
}

/** Wraps a record DEK under the tenant key version (`email_archives.wrapped_dek`). */
export function wrapRecordKey(tenantKey: Buffer, ids: RecordKeyIds, dek: Buffer): string {
  return sealSecretBox(key32(tenantKey), tenantKid(ids.keyVersion), key32(dek), recordKeyAad(ids));
}

export function unwrapRecordKey(tenantKey: Buffer, wrapped: string, ids: RecordKeyIds): Buffer {
  return unwrapUnderTenant(tenantKey, wrapped, ids.keyVersion, recordKeyAad(ids));
}

/** Wraps an export DEK under the tenant key version (`ediscovery_exports.wrapped_dek`). */
export function wrapExportKey(tenantKey: Buffer, ids: ExportKeyIds, dek: Buffer): string {
  return sealSecretBox(key32(tenantKey), tenantKid(ids.keyVersion), key32(dek), exportKeyAad(ids));
}

export function unwrapExportKey(tenantKey: Buffer, wrapped: string, ids: ExportKeyIds): Buffer {
  return unwrapUnderTenant(tenantKey, wrapped, ids.keyVersion, exportKeyAad(ids));
}

/** The tenant key version named by a wrapped DEK (`v1.k<version>.…`); throws `malformed`. */
export function keyVersionOfWrapped(wrapped: string): number {
  const { kid } = parseSecretBox(wrapped);
  const match = /^k([1-9][0-9]{0,9})$/.exec(kid);
  const value = match ? Number(match[1]) : NaN;
  if (!isPositiveInt(value, KEY_VERSION_MAX)) throw new ArchiveCryptoError('malformed');
  return value;
}

export interface ObjectKeyContext {
  kind: ArchiveObjectKind;
  organizationId: NumericId;
  /** The message public id (eml, journal, scan) or the export public id (export). */
  subjectId: string;
}

export function objectKeyInfo(context: ObjectKeyContext): string {
  if (!ARCHIVE_OBJECT_KINDS.includes(context.kind)) throw new ArchiveCryptoError('malformed');
  return `eg-archive-object/v1\0${context.kind}\0${org(context.organizationId)}\0${uuid(
    context.subjectId,
  )}`;
}

/** HKDF-SHA256(DEK, salt, info) → the 32-byte AES-256-GCM key of one object. */
export function deriveObjectKey(dek: Buffer, salt: Buffer, context: ObjectKeyContext): Buffer {
  if (!Buffer.isBuffer(salt) || salt.length !== OBJECT_SALT_BYTES) {
    throw new ArchiveCryptoError('malformed');
  }
  return Buffer.from(
    hkdfSync('sha256', key32(dek), salt, Buffer.from(objectKeyInfo(context), 'utf8'), 32),
  );
}
