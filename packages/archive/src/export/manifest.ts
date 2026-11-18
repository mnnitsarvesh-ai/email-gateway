import type { KeyObject } from 'node:crypto';
import { signManifest, verifyManifestSignature } from '../crypto/signing';
import { canonicalJsonBytes, sha256Hex } from '../documents/canonical';
import { ArchiveDocumentError } from '../documents/common';
import { type ArchiveExportManifest, archiveExportManifestSchema } from '../documents/search';
import { isUuid } from '../ids';
import type { EdiscoveryReviewTag, MessageVerdict } from '../vocabulary';

/**
 * Export packages (A18, §4.2): the ZIP entry paths, `manifest.json` (`archive-export-manifest/1`
 * as canonical JSON bytes), `manifest.sig` and the README texts. The ZIP itself is streamed by
 * the worker (yazl); this module only decides names and bytes.
 */

export const EXPORT_MANIFEST_PATH = 'manifest.json';
export const EXPORT_SIGNATURE_PATH = 'manifest.sig';
export const EXPORT_README_PATH = 'README.txt';
export const EXPORT_MALICIOUS_README_PATH = 'malicious/README.txt';
export const EXPORT_DEFAULT_REVIEW_TAGS: readonly EdiscoveryReviewTag[] = Object.freeze([
  'untagged',
  'relevant',
  'privileged',
]);

/**
 * `received_at` in ZIP-safe basic ISO 8601 (`20261116T101500.123Z`): colons are not valid in
 * file names on every platform that unpacks exports.
 */
export function exportTimestamp(receivedAt: Date): string {
  const iso = receivedAt.toISOString();
  return iso.replace(/[-:]/g, '');
}

/** `messages/<receivedAt>_<messageId>.eml`, or under `malicious/` for malicious records. */
export function exportEntryPath(item: {
  receivedAt: Date;
  messageId: string;
  malicious: boolean;
}): string {
  if (!isUuid(item.messageId) || !Number.isFinite(item.receivedAt.getTime())) {
    throw new ArchiveDocumentError('archive-export-manifest/1');
  }
  const folder = item.malicious ? 'malicious' : 'messages';
  return `${folder}/${exportTimestamp(item.receivedAt)}_${item.messageId}.eml`;
}

export const EXPORT_README_TEXT = [
  'Email Security Gateway - eDiscovery export',
  '',
  'Contents',
  '  messages/            original messages (RFC 5322 .eml), byte-for-byte as received',
  '  malicious/           messages classified as malicious (present only when acknowledged)',
  '  manifest.json        archive-export-manifest/1: every item with its SHA-256 and size',
  '  manifest.sig         Ed25519 signature (base64url) over the exact bytes of manifest.json',
  '',
  'Verifying the package',
  '  1. Fetch the public key named by "signingKeyId" from GET /api/v1/archive/export-signing-keys',
  '     (SPKI DER, base64url).',
  '  2. Verify manifest.sig over manifest.json with Ed25519.',
  '  3. For each item, compare the SHA-256 of the file at "path" with "sha256".',
  '',
  'Every export, download and access to this package is recorded in the audit trail.',
  '',
].join('\n');

export const EXPORT_MALICIOUS_README_TEXT = [
  'WARNING - MALICIOUS CONTENT',
  '',
  'The messages in this folder were classified as malicious (malware, phishing or a malicious',
  'URL or attachment). They are included unmodified because the export was requested with an',
  'explicit acknowledgement. Open them only in an isolated analysis environment.',
  '',
].join('\n');

export interface ExportManifestItemInput {
  messageId: string;
  receivedAt: Date;
  internetMessageId: string | null;
  sha256: string;
  sizeBytes: number;
  verdict: MessageVerdict | null;
  malicious: boolean;
}

export interface ExportManifestInput {
  exportId: string;
  caseId: string;
  searchId: string;
  /** Organization public id. */
  organizationId: string;
  generatedAt: Date;
  signingKeyId: string;
  reviewTags: readonly EdiscoveryReviewTag[];
  items: readonly ExportManifestItemInput[];
}

export interface BuiltExportManifest {
  manifest: ArchiveExportManifest;
  /** The exact `manifest.json` bytes (canonical JSON). */
  bytes: Buffer;
  sha256: string;
}

/** Builds and validates the manifest; items keep the given order, counts are computed. */
export function buildExportManifest(input: ExportManifestInput): BuiltExportManifest {
  const items = input.items.map((i) => ({
    messageId: i.messageId,
    receivedAt: i.receivedAt.toISOString(),
    internetMessageId: i.internetMessageId,
    path: exportEntryPath(i),
    sha256: i.sha256,
    sizeBytes: i.sizeBytes,
    verdict: i.verdict,
    malicious: i.malicious,
  }));
  const raw = {
    version: 'archive-export-manifest/1' as const,
    exportId: input.exportId,
    caseId: input.caseId,
    searchId: input.searchId,
    organizationId: input.organizationId,
    generatedAt: input.generatedAt.toISOString(),
    generator: 'archive-worker' as const,
    signingKeyId: input.signingKeyId,
    reviewTags: [...input.reviewTags],
    counts: {
      items: items.length,
      malicious: items.filter((i) => i.malicious).length,
      bytes: items.reduce((sum, i) => sum + i.sizeBytes, 0),
    },
    items,
  };
  const parsed = archiveExportManifestSchema.safeParse(raw);
  if (!parsed.success) throw new ArchiveDocumentError('archive-export-manifest/1');
  if (new Set(items.map((i) => i.path)).size !== items.length) {
    throw new ArchiveDocumentError('archive-export-manifest/1');
  }
  const bytes = canonicalJsonBytes(parsed.data);
  return { manifest: parsed.data, bytes, sha256: sha256Hex(bytes) };
}

/** Builds the manifest and its Ed25519 signature (`manifest.sig` content, base64url). */
export function buildSignedExportManifest(
  input: ExportManifestInput,
  privateKey: KeyObject,
): BuiltExportManifest & { signature: string } {
  const built = buildExportManifest(input);
  return { ...built, signature: signManifest(built.bytes, privateKey) };
}

/** Parses manifest bytes and verifies the signature (verification tooling and tests). */
export function verifySignedExportManifest(
  bytes: Buffer,
  signature: string,
  publicKey: KeyObject,
): ArchiveExportManifest | null {
  if (!verifyManifestSignature(bytes, signature, publicKey)) return null;
  let json: unknown;
  try {
    json = JSON.parse(bytes.toString('utf8'));
  } catch {
    return null;
  }
  const parsed = archiveExportManifestSchema.safeParse(json);
  return parsed.success ? parsed.data : null;
}
