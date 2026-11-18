import { inflateRawSync } from 'node:zlib';
import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  ListObjectVersionsCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import {
  archiveRecordObjectsSchema,
  decryptArchiveObject,
  LocalRootKeyProvider,
  tenantAliasName,
  unwrapRecordKey,
  unwrapTenantKey,
  type ArchiveRecordObjects,
} from '@email-gateway/archive';
import { OpenSearchService } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import { compose, composeOk, waitFor } from './compose';
import { stack } from './env';
import type { MessageKey } from './lifecycle';

/**
 * Readers and controls of the step 8.1 archive (docs/plan/steps/23-journaling-archiving.md §2,
 * §4.1–§4.3, §9.4) for the stack suite `archive-smtp.test.ts`. Everything reads the MySQL WRITER,
 * the MinIO archive bucket and OpenSearch directly, next to the api the suite drives; nothing here
 * writes an archive record, an object or an index document (those are the archive-worker's).
 * Keys come from the same `.env` the containers read and are never printed.
 */

/** Ledger consumer of the `email.archive` work queue (A2 source 2, topology v12). */
export const ARCHIVE_LEDGER = 'archive-worker.archive';

/**
 * Compose overrides of the archive suite (shell environment over `.env`, the precedent of the
 * notification-worker and webhook-worker suites; LOCAL ONLY, both containers run with
 * `APP_ENV=local`): one archive "day" lasts 60 s (`ARCHIVE_TEST_DAY_SECONDS`, A11: worker and api),
 * the replica target is the test-only replica bucket (A14, A29), and the worker's loops run
 * faster so the 17 cases finish in minutes (every value inside its §4.8 / WP3 D24 bounds).
 * `restoreArchiveServices` recreates both containers from `.env` again.
 */
export const ARCHIVE_SUITE_DAY_SECONDS = 60;
export const ARCHIVE_SUITE_ENV: Record<string, string> = {
  ARCHIVE_TEST_DAY_SECONDS: String(ARCHIVE_SUITE_DAY_SECONDS),
  ARCHIVE_REPLICA_TARGETS: process.env.ARCHIVE_TEST_REPLICA_BUCKET || 'gateway-archive-replica',
  ARCHIVE_SWEEP_INTERVAL_MS: '2000',
  // ≥ the time a test needs to act on a fresh message before the sweep sees it (case 6 places a
  // manual quarantine on a rejected EICAR message first).
  ARCHIVE_SWEEP_SAFETY_LAG_SECONDS: '45',
  ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS: '60',
  ARCHIVE_SETTINGS_CACHE_TTL_MS: '1000',
  ARCHIVE_KEY_CACHE_TTL_MS: '1000',
  ARCHIVE_CAPTURE_LEASE_SECONDS: '60',
  ARCHIVE_CAPTURE_RETRY_BASE_MS: '2000',
  ARCHIVE_INDEX_INTERVAL_MS: '500',
  ARCHIVE_RECONCILE_INTERVAL_MS: '10000',
  ARCHIVE_LIFECYCLE_INTERVAL_MS: '5000',
  ARCHIVE_HOLD_EXTENSION_DAYS: '1',
};

/** Recreates the archive-worker and the api with the suite's overrides and waits for both. */
export async function recreateArchiveServices(env: Record<string, string> = ARCHIVE_SUITE_ENV) {
  await composeOk(
    ['up', '-d', '--no-deps', '--force-recreate', '--wait', 'archive-worker', 'api'],
    { timeoutMs: 300_000, env },
  );
}

/** Recreates both containers from `.env` (the resting configuration). */
export async function restoreArchiveServices(): Promise<void> {
  await compose(['up', '-d', '--no-deps', '--force-recreate', '--wait', 'archive-worker', 'api'], {
    timeoutMs: 300_000,
  });
}

/** The environment a container runs with (`docker inspect`), for the restore check. */
export async function containerEnv(service: string): Promise<Record<string, string>> {
  const id = (await composeOk(['ps', '--quiet', service], { timeoutMs: 20_000 })).stdout.trim();
  const { run } = await import('./compose');
  const result = await run('docker', ['inspect', '--format', '{{json .Config.Env}}', id]);
  const out: Record<string, string> = {};
  for (const line of JSON.parse(result.stdout) as string[]) {
    const eq = line.indexOf('=');
    out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

export function archiveS3(): S3Client {
  const s3 = stack.s3();
  return new S3Client({
    region: s3.region,
    endpoint: s3.endpoint,
    forcePathStyle: true,
    credentials: { accessKeyId: s3.accessKeyId, secretAccessKey: s3.secretAccessKey },
  });
}

export function archiveSearch(): OpenSearchService {
  const url = process.env.ARCHIVE_SEARCH_URL;
  if (!url) throw new Error('ARCHIVE_SEARCH_URL is not set (step 8.1 .env keys)');
  return new OpenSearchService({
    url,
    username: process.env.ARCHIVE_SEARCH_USERNAME || undefined,
    password: process.env.ARCHIVE_SEARCH_PASSWORD || undefined,
    timeoutMs: 15_000,
  });
}

export const indexPrefix = () => process.env.ARCHIVE_SEARCH_INDEX_PREFIX || 'eg-archive';
export const replicaBucket = () =>
  process.env.ARCHIVE_TEST_REPLICA_BUCKET || 'gateway-archive-replica';
export const tenantAlias = (organizationId: bigint) =>
  tenantAliasName(indexPrefix(), organizationId);

/** The archive record of a message (writer), or null. */
export function recordOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.emailArchive.findFirst({
    where: { messageId: message.id, receivedAt: message.receivedAt },
  });
}

export type ArchiveRecordRow = NonNullable<Awaited<ReturnType<typeof recordOf>>>;

/** The capture intent of a message (writer), or null. */
export function intentOf(prisma: PrismaClient, message: MessageKey) {
  return prisma.archiveCaptureIntent.findFirst({
    where: { messageId: message.id, receivedAt: message.receivedAt },
  });
}

export type IntentRow = NonNullable<Awaited<ReturnType<typeof intentOf>>>;

/** Waits for the record of a message (and, optionally, for a predicate on it). */
export function waitForRecord(
  prisma: PrismaClient,
  message: MessageKey,
  predicate: (row: ArchiveRecordRow) => boolean = () => true,
  timeoutMs = 240_000,
): Promise<ArchiveRecordRow> {
  return waitFor(
    `archive record of message ${message.id}`,
    async () => {
      const row = await recordOf(prisma, message);
      return row !== null && predicate(row) ? row : undefined;
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Waits until the capture intent of a message is in one of `statuses`. */
export function waitForIntent(
  prisma: PrismaClient,
  message: MessageKey,
  statuses: readonly string[],
  timeoutMs = 240_000,
): Promise<IntentRow> {
  return waitFor(
    `capture intent of message ${message.id} in ${statuses.join('|')}`,
    async () => {
      const row = await intentOf(prisma, message);
      return row !== null && statuses.includes(row.status) ? row : undefined;
    },
    { timeoutMs, intervalMs: 1_000 },
  );
}

/** Parsed `email_archives.objects` (`archive-record-objects`, WP2 D6). */
export const objectsOf = (row: ArchiveRecordRow): ArchiveRecordObjects =>
  archiveRecordObjectsSchema.parse(row.objects);

/** The record's object prefix `org/<org>/archive/<yyyy>/<mm>/<dd>/<messagePublicId>/` (§4.1). */
export function recordPrefix(row: ArchiveRecordRow): string {
  const eml = objectsOf(row).eml.key;
  return eml.slice(0, eml.indexOf(`/${objectsOf(row).captureId}/`) + 1);
}

export async function getObject(s3: S3Client, bucket: string, key: string, versionId?: string) {
  const res = await s3.send(
    new GetObjectCommand({ Bucket: bucket, Key: key, VersionId: versionId }),
  );
  return Buffer.from(await res.Body!.transformToByteArray());
}

/** Every version (not delete markers) under a prefix of a bucket. */
export async function versionsUnder(
  s3: S3Client,
  bucket: string,
  prefix: string,
): Promise<Array<{ key: string; versionId: string }>> {
  const out: Array<{ key: string; versionId: string }> = [];
  let keyMarker: string | undefined;
  let versionMarker: string | undefined;
  do {
    const page = await s3.send(
      new ListObjectVersionsCommand({
        Bucket: bucket,
        Prefix: prefix,
        KeyMarker: keyMarker,
        VersionIdMarker: versionMarker,
      }),
    );
    for (const v of page.Versions ?? []) out.push({ key: v.Key!, versionId: v.VersionId! });
    keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
    versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
  } while (keyMarker !== undefined);
  return out;
}

/**
 * Simulated replication (A29: S3 replication never runs between buckets of the local MinIO in
 * this suite): every version of the record copied into the test replica bucket under the same key.
 */
export async function copyToReplica(s3: S3Client, row: ArchiveRecordRow): Promise<number> {
  const versions = await versionsUnder(s3, stack.s3().archiveBucket, recordPrefix(row));
  for (const v of versions) {
    await s3.send(
      new CopyObjectCommand({
        Bucket: replicaBucket(),
        Key: v.key,
        CopySource: `${stack.s3().archiveBucket}/${encodeURIComponent(v.key).replaceAll('%2F', '/')}?versionId=${encodeURIComponent(v.versionId)}`,
      }),
    );
  }
  return versions.length;
}

/** Deletes every version (and delete marker) under a prefix with governance bypass. */
export async function purgePrefix(
  s3: S3Client,
  bucket: string,
  prefix: string,
): Promise<{ deleted: number; refused: number }> {
  let deleted = 0;
  let refused = 0;
  let keyMarker: string | undefined;
  let versionMarker: string | undefined;
  do {
    const page = await s3.send(
      new ListObjectVersionsCommand({
        Bucket: bucket,
        Prefix: prefix,
        KeyMarker: keyMarker,
        VersionIdMarker: versionMarker,
      }),
    );
    for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
      try {
        await s3.send(
          new DeleteObjectCommand({
            Bucket: bucket,
            Key: v.Key,
            VersionId: v.VersionId,
            BypassGovernanceRetention: true,
          }),
        );
        deleted += 1;
      } catch {
        refused += 1;
      }
    }
    keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
    versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
  } while (keyMarker !== undefined);
  return { deleted, refused };
}

/**
 * Decrypts one object of a record exactly as the api does (A8, ADR-0065): the tenant key version
 * unwrapped under the root key of `.env`, the record DEK unwrapped under it, then
 * `archive-object/1` with the message public id as the subject. Never prints a key.
 */
export async function decryptRecordObject(
  prisma: PrismaClient,
  s3: S3Client,
  row: ArchiveRecordRow,
  kind: 'eml' | 'journal' | 'scan',
  index = 0,
): Promise<{ ciphertext: Buffer; plaintext: Buffer }> {
  const objects = objectsOf(row);
  const ref =
    kind === 'eml' ? objects.eml : kind === 'journal' ? objects.journal : objects.scans[index]!;
  const ciphertext = await getObject(
    s3,
    stack.s3().archiveBucket,
    ref.key,
    ref.versionId ?? undefined,
  );
  const key = await prisma.archiveEncryptionKey.findUniqueOrThrow({
    where: {
      organizationId_version: { organizationId: row.organizationId, version: row.keyVersion },
    },
  });
  const provider = LocalRootKeyProvider.fromConfig({
    ARCHIVE_ROOT_KEY: process.env.ARCHIVE_ROOT_KEY ?? '',
    ARCHIVE_ROOT_KEY_ID: process.env.ARCHIVE_ROOT_KEY_ID || undefined,
    ARCHIVE_ROOT_KEY_PREVIOUS: process.env.ARCHIVE_ROOT_KEY_PREVIOUS || undefined,
    ARCHIVE_ROOT_KEY_PREVIOUS_ID: process.env.ARCHIVE_ROOT_KEY_PREVIOUS_ID || undefined,
  });
  const tenant = await unwrapTenantKey(provider, key.wrappedKey!, {
    organizationId: row.organizationId,
    version: row.keyVersion,
  });
  const dek = unwrapRecordKey(tenant.key, row.wrappedDek!, {
    organizationId: row.organizationId,
    messagePublicId: row.messagePublicId,
    captureId: objects.captureId,
    keyVersion: row.keyVersion,
  });
  const plaintext = decryptArchiveObject(ciphertext, {
    dek,
    kind,
    organizationId: row.organizationId,
    subjectId: row.messagePublicId,
  });
  return { ciphertext, plaintext };
}

/** Documents of the given message ids visible through an organization's tenant alias. */
export async function aliasCount(
  search: OpenSearchService,
  organizationId: bigint,
  messagePublicIds: readonly string[],
  extraFilter?: unknown,
): Promise<number> {
  return search.count(
    tenantAlias(organizationId),
    {
      query: {
        bool: {
          filter: [
            { ids: { values: [...messagePublicIds] } },
            ...(extraFilter ? [extraFilter] : []),
          ],
        },
      },
    },
    { routing: organizationId.toString() },
  );
}

/** Documents of the given ids in every archive index, without an alias (direct check). */
export async function rawIndexCount(
  search: OpenSearchService,
  messagePublicIds: readonly string[],
): Promise<number> {
  return search.count(`${indexPrefix()}-v*`, {
    query: { ids: { values: [...messagePublicIds] } },
  });
}

/** A minimal ZIP reader (stored and deflated entries; the export packages of A18 are yazl ZIPs). */
export function readZip(zip: Buffer): Map<string, Buffer> {
  const EOCD = 0x06054b50;
  let eocd = -1;
  for (let i = zip.length - 22; i >= Math.max(0, zip.length - 65_557); i -= 1) {
    if (zip.readUInt32LE(i) === EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const entries = zip.readUInt16LE(eocd + 10);
  let offset = zip.readUInt32LE(eocd + 16);
  const out = new Map<string, Buffer>();
  for (let n = 0; n < entries; n += 1) {
    if (zip.readUInt32LE(offset) !== 0x02014b50) throw new Error('bad central directory');
    const method = zip.readUInt16LE(offset + 10);
    const compressed = zip.readUInt32LE(offset + 20);
    const nameLen = zip.readUInt16LE(offset + 28);
    const extraLen = zip.readUInt16LE(offset + 30);
    const commentLen = zip.readUInt16LE(offset + 32);
    const local = zip.readUInt32LE(offset + 42);
    const name = zip.subarray(offset + 46, offset + 46 + nameLen).toString('utf8');
    const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const data = zip.subarray(start, start + compressed);
    out.set(name, method === 8 ? inflateRawSync(data) : Buffer.from(data));
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/**
 * Removes every archive row, object version, index document, alias and cursor of the given
 * organizations (the order of the archive-worker suite's cleanup, RESTRICT keys last). Call it
 * with the archive-worker STOPPED, so nothing is captured, indexed or disposed meanwhile.
 * Compliance-locked versions cannot be deleted before their retain-until: they are reported.
 */
export async function purgeArchiveTenants(
  prisma: PrismaClient,
  s3: S3Client,
  search: OpenSearchService,
  organizationIds: readonly bigint[],
): Promise<{ lockedVersions: number }> {
  if (organizationIds.length === 0) return { lockedVersions: 0 };
  const where = { organizationId: { in: [...organizationIds] } };
  await prisma.ediscoverySearchHit.deleteMany({ where });
  await prisma.archiveDownloadGrant.deleteMany({ where });
  await prisma.ediscoveryExport.deleteMany({ where });
  await prisma.ediscoverySearch.deleteMany({ where });
  await prisma.archiveLegalHold.deleteMany({ where });
  await prisma.ediscoveryCustodian.deleteMany({ where });
  await prisma.ediscoveryCase.deleteMany({ where });
  await prisma.archiveIndexQueue.deleteMany({ where });
  await prisma.archiveIndexCheck.deleteMany({ where });
  await prisma.archiveDisposal.deleteMany({ where });
  await prisma.emailArchive.deleteMany({ where });
  await prisma.archiveCaptureIntent.deleteMany({ where });
  await prisma.archiveSetting.deleteMany({ where });
  await prisma.archiveRetentionPolicy.deleteMany({ where });
  await prisma.archiveEncryptionKey.deleteMany({ where });
  await prisma.auditLog.deleteMany({ where });
  await prisma.streamCursor.deleteMany({
    where: {
      OR: organizationIds.flatMap((id) => [
        { name: { endsWith: `:${id.toString()}` } },
        { name: { contains: `:${id.toString()}:` } },
      ]),
    },
  });
  let lockedVersions = 0;
  for (const id of organizationIds) {
    for (const bucket of [stack.s3().archiveBucket, replicaBucket()]) {
      lockedVersions += (await purgePrefix(s3, bucket, `org/${id.toString()}/`)).refused;
    }
    await search
      .request('POST', `/${indexPrefix()}-v*/_delete_by_query`, {
        body: { query: { term: { org_id: id.toString() } } },
        query: { conflicts: 'proceed', refresh: 'true' },
        allowStatuses: [404],
      })
      .catch(() => undefined);
    await search
      .request('DELETE', `/_all/_alias/${tenantAlias(id)}`, { allowStatuses: [404] })
      .catch(() => undefined);
  }
  return { lockedVersions };
}
