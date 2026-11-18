import { S3Client } from '@aws-sdk/client-s3';
import {
  buildArchiveSearchDocument,
  buildIndexTemplate,
  buildOrganizationPurgeQuery,
  indexPattern,
  indexTemplateName,
  isUuid,
  LocalRootKeyProvider,
  removeTenantAliasActions,
  tenantAliasActions,
  yearlyIndexName,
} from '@email-gateway/archive';
import { OpenSearchService } from '@email-gateway/common';
import { type EmailArchive, type Prisma, PrismaClient } from '@email-gateway/database';
import { extraFacts } from '../index/index-sync';
import { IndexManager } from '../index/index-manager';
import { loadWorkerConfig, type WorkerConfig } from '../config';
import { TenantKeyService } from '../keys/tenant-keys';
import { archiveOrganizations } from '../shared/db';
import { ArchiveStorage } from '../storage/archive-storage';
import { RecordObjects } from '../storage/record-objects';

/**
 * Archive search index rebuild (A16; docs/runbooks/archive.md "Rebuild"), run in the worker
 * container: `node dist/cli/reindex.js --organization <publicId> | --all [--version vN]`.
 *
 * - `--organization <publicId>`: the tenant's documents are deleted (`_delete_by_query`, routing
 *   + tenant term) and every live record is re-enqueued (upsert) by `(organization_id,
 *   received_at)` keyset; the running index role re-indexes them (search shows `index_lag` until
 *   the queue drains). The tenant alias is ensured on every index of the active version.
 * - `--all [--version vN]` (default: the active version + 1): the target template is created
 *   marked `building`, every live record of every tenant is indexed into the target's yearly
 *   indices (keyset, `_bulk`), then ONE `_aliases` call moves every tenant alias from the old
 *   indices to the new ones (atomic), the target template becomes active, the old indices and
 *   template are deleted, and records changed or disposed during the rebuild are re-enqueued.
 *
 * Output is counts only (never subjects, addresses or ids). Exit code 0 on success.
 */

export interface ReindexArgs {
  organization: string | null;
  all: boolean;
  version: number | null;
  batch: number;
}

export function parseReindexArgs(argv: readonly string[]): ReindexArgs {
  const args: ReindexArgs = { organization: null, all: false, version: null, batch: 500 };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = (): string => {
      const v = argv[i + 1];
      if (v === undefined) throw new Error(`${a} needs a value`);
      i += 1;
      return v;
    };
    if (a === '--organization') args.organization = next();
    else if (a === '--')
      continue; // `pnpm run reindex -- …` forwards the separator
    else if (a === '--all') args.all = true;
    else if (a === '--version') {
      const m = /^v?([1-9][0-9]{0,2})$/.exec(next());
      if (!m) throw new Error('--version must be vN (1..999)');
      args.version = Number(m[1]);
    } else if (a === '--batch') {
      const n = Number(next());
      if (!Number.isInteger(n) || n < 1 || n > 5_000) throw new Error('--batch must be 1..5000');
      args.batch = n;
    } else throw new Error(`unknown argument ${String(a)}`);
  }
  if (args.all === (args.organization !== null)) {
    throw new Error('use exactly one of --organization <publicId> and --all');
  }
  if (args.organization !== null && !isUuid(args.organization)) {
    throw new Error('--organization must be an organization public id');
  }
  if (args.organization !== null && args.version !== null) {
    throw new Error('--version applies to --all only');
  }
  return args;
}

export interface ReindexDeps {
  prisma: PrismaClient;
  search: OpenSearchService;
  objects: RecordObjects;
  config: Pick<
    WorkerConfig,
    'ARCHIVE_SEARCH_INDEX_PREFIX' | 'ARCHIVE_INDEX_SHARDS' | 'ARCHIVE_INDEX_REPLICAS'
  >;
  log: (line: string) => void;
  /** Integration suites: only these organizations (the CLI itself always takes every one). */
  organizationIds?: readonly bigint[];
  now?: () => Date;
}

export interface ReindexReport {
  mode: 'organization' | 'all';
  fromVersion: number;
  toVersion: number;
  organizations: number;
  enqueued: number;
  indexed: number;
  failed: number;
  deletedIndices: number;
}

const LIVE = { status: { in: ['active', 'expiry_review'] as Array<'active' | 'expiry_review'> } };

/** Every live record of an organization by `(received_at, id)` keyset. */
async function* liveRecords(
  prisma: PrismaClient,
  organizationId: bigint,
  batch: number,
  extra: Prisma.EmailArchiveWhereInput = {},
): AsyncGenerator<EmailArchive[]> {
  let after: { receivedAt: Date; id: bigint } | null = null;
  for (;;) {
    const page: EmailArchive[] = await prisma.emailArchive.findMany({
      where: {
        organizationId,
        ...extra,
        ...(after
          ? {
              OR: [
                { receivedAt: { gt: after.receivedAt } },
                { receivedAt: after.receivedAt, id: { gt: after.id } },
              ],
            }
          : {}),
      },
      orderBy: [{ receivedAt: 'asc' }, { id: 'asc' }],
      take: batch,
    });
    if (page.length === 0) return;
    yield page;
    const last = page[page.length - 1]!;
    after = { receivedAt: last.receivedAt, id: last.id };
    if (page.length < batch) return;
  }
}

async function enqueue(
  prisma: PrismaClient,
  records: readonly EmailArchive[],
  op: 'upsert' | 'delete',
): Promise<number> {
  if (records.length === 0) return 0;
  await prisma.archiveIndexQueue.createMany({
    data: records.map((r) => ({
      organizationId: r.organizationId,
      messageId: r.messageId,
      receivedAt: r.receivedAt,
      messagePublicId: r.messagePublicId,
      op,
    })),
  });
  return records.length;
}

export async function runReindex(args: ReindexArgs, deps: ReindexDeps): Promise<ReindexReport> {
  const prefix = deps.config.ARCHIVE_SEARCH_INDEX_PREFIX;
  const now = deps.now ?? (() => new Date());
  const manager = new IndexManager(deps.search, deps.prisma, {
    prefix,
    shards: deps.config.ARCHIVE_INDEX_SHARDS,
    replicas: deps.config.ARCHIVE_INDEX_REPLICAS,
  });
  const fromVersion = await manager.refreshVersion();
  const report: ReindexReport = {
    mode: args.all ? 'all' : 'organization',
    fromVersion,
    toVersion: fromVersion,
    organizations: 0,
    enqueued: 0,
    indexed: 0,
    failed: 0,
    deletedIndices: 0,
  };

  if (args.organization !== null) {
    const org = await deps.prisma.organization.findUnique({
      where: { publicId: args.organization },
      select: { id: true },
    });
    if (org === null) throw new Error('organization not found');
    report.organizations = 1;
    await manager.ensureTemplate();
    await manager.ensureTenantAlias(org.id);
    await deps.search.deleteByQuery(
      indexPattern(prefix, fromVersion),
      buildOrganizationPurgeQuery(org.id),
      { routing: org.id.toString(), refresh: true },
    );
    for await (const page of liveRecords(deps.prisma, org.id, args.batch, LIVE)) {
      report.enqueued += await enqueue(deps.prisma, page, 'upsert');
    }
    deps.log(`organization rebuild: ${report.enqueued} records re-enqueued`);
    return report;
  }

  const toVersion = args.version ?? fromVersion + 1;
  if (toVersion <= fromVersion) throw new Error('--version must be above the active version');
  report.toVersion = toVersion;
  const startedAt = now();
  const template = buildIndexTemplate({
    prefix,
    version: toVersion,
    shards: deps.config.ARCHIVE_INDEX_SHARDS,
    replicas: deps.config.ARCHIVE_INDEX_REPLICAS,
  });
  const meta = (template._meta ?? {}) as Record<string, unknown>;
  await deps.search.putIndexTemplate(indexTemplateName(prefix, toVersion), {
    ...template,
    _meta: { ...meta, state: 'building' },
  });
  const created = new Set<string>();
  const orgs = await archiveOrganizations(deps.prisma, deps.organizationIds);
  report.organizations = orgs.length;
  for (const org of orgs) {
    for await (const page of liveRecords(deps.prisma, org, args.batch, {
      ...LIVE,
      wrappedDek: { not: null },
    })) {
      const ops = [];
      for (const r of page) {
        try {
          const built = buildArchiveSearchDocument(r, {
            prefix,
            now: now(),
            version: toVersion,
            extra: await extraFacts(deps.objects, r),
          });
          if (!created.has(built.index)) {
            await deps.search.createIndex(built.index, {});
            created.add(built.index);
          }
          ops.push({
            action: 'index' as const,
            index: built.index,
            id: built.id,
            routing: built.routing,
            document: built.document,
          });
        } catch {
          report.failed += 1;
        }
      }
      const result = await deps.search.bulk(ops);
      for (const item of result.items) {
        if (item.ok) report.indexed += 1;
        else report.failed += 1;
      }
    }
  }
  if (created.size === 0) {
    const index = yearlyIndexName(prefix, now(), toVersion);
    await deps.search.createIndex(index, {});
    created.add(index);
  }
  // One atomic alias swap for every tenant: old indices out, new indices in.
  const actions: unknown[] = [];
  const targetIndices = [...created].sort();
  for (const org of orgs) {
    const have = await manager.aliasIndices(org);
    actions.push(...removeTenantAliasActions(prefix, org, have).actions);
    actions.push(...tenantAliasActions(prefix, org, targetIndices).actions);
  }
  await deps.search.updateAliases({ actions });
  await deps.search.putIndexTemplate(indexTemplateName(prefix, toVersion), template);
  for (const index of await manager.indices()) {
    await deps.search.request('DELETE', `/${index}`, { allowStatuses: [404] });
    report.deletedIndices += 1;
  }
  await deps.search.request(
    'DELETE',
    `/_index_template/${indexTemplateName(prefix, fromVersion)}`,
    {
      allowStatuses: [404],
    },
  );
  // Catch-up: records changed (or disposed) while the rebuild ran go through the queue again.
  for (const org of orgs) {
    for await (const page of liveRecords(deps.prisma, org, args.batch, {
      updatedAt: { gte: startedAt },
    })) {
      const live = page.filter((r) => r.status !== 'disposing');
      report.enqueued += await enqueue(deps.prisma, live, 'upsert');
      report.enqueued += await enqueue(
        deps.prisma,
        page.filter((r) => r.status === 'disposing'),
        'delete',
      );
    }
  }
  deps.log(
    `rebuild v${fromVersion} -> v${toVersion}: ${report.indexed} indexed, ${report.failed} failed, ` +
      `${report.deletedIndices} old indices deleted, ${report.enqueued} re-enqueued`,
  );
  return report;
}

async function main(): Promise<void> {
  const args = parseReindexArgs(process.argv.slice(2));
  const config = loadWorkerConfig({ ...process.env, ARCHIVE_WORKER_ROLES: 'index' });
  if (config.ARCHIVE_SEARCH_URL === undefined) throw new Error('ARCHIVE_SEARCH_URL is required');
  const prisma = new PrismaClient({ datasourceUrl: config.DATABASE_URL });
  const s3 = new S3Client({
    region: config.S3_REGION,
    endpoint: config.S3_ENDPOINT,
    forcePathStyle: config.S3_FORCE_PATH_STYLE,
    credentials:
      config.S3_ACCESS_KEY_ID && config.S3_SECRET_ACCESS_KEY
        ? { accessKeyId: config.S3_ACCESS_KEY_ID, secretAccessKey: config.S3_SECRET_ACCESS_KEY }
        : undefined,
  });
  try {
    const search = new OpenSearchService({
      url: config.ARCHIVE_SEARCH_URL,
      username: config.ARCHIVE_SEARCH_USERNAME,
      password: config.ARCHIVE_SEARCH_PASSWORD,
      timeoutMs: config.ARCHIVE_SEARCH_TIMEOUT_MS,
    });
    const storage = new ArchiveStorage(
      s3,
      { mail: config.S3_BUCKET_MAIL, archive: config.S3_BUCKET_ARCHIVE },
      { timeoutMs: config.ARCHIVE_S3_TIMEOUT_MS, partSizeBytes: config.ARCHIVE_S3_PART_SIZE_BYTES },
    );
    const keys = new TenantKeyService(prisma, LocalRootKeyProvider.fromConfig(config), {
      cacheTtlMs: config.ARCHIVE_KEY_CACHE_TTL_MS,
    });
    const report = await runReindex(args, {
      prisma,
      search,
      objects: new RecordObjects(storage, keys),
      config,
      log: (line) => process.stdout.write(`${line}\n`),
    });
    process.stdout.write(`${JSON.stringify(report)}\n`);
  } finally {
    s3.destroy();
    await prisma.$disconnect();
  }
}

if (typeof require !== 'undefined' && require.main === module) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `reindex failed: ${(error as Error).name}: ${(error as Error).message.slice(0, 200)}\n`,
    );
    process.exit(1);
  });
}
