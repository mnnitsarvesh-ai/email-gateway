/**
 * Archive fixtures of the step 8.1 integration suites (docs/plan/steps/23-journaling-archiving.md
 * §9.3): records seeded exactly as the archive-worker writes them — a registry row
 * (`message_identities`), a tenant key version wrapped under the configured root key, the
 * `archive-object/1` objects put into the real archive bucket (MinIO) under the organization's
 * prefix, the `email_archives` row on the writer and the search document indexed into a test-run
 * index prefix (template, yearly index, the tenant's filtered alias) with the library's builders.
 * `cleanup()` removes every row, object version, index, alias and template it created. Never
 * touches anything outside its own organizations and prefix.
 */
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import {
  aliasesForIndexCreation,
  buildArchiveSearchDocument,
  buildIndexTemplate,
  indexPattern,
  indexTemplateName,
  tenantAliasActions,
  yearlyIndexName,
} from '@email-gateway/archive';
import { OpenSearchService, S3Service } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  type SeededRecord,
  type SeedRecordInput,
  seedRecord,
  type SeedTenantKey,
  seedTenantKey,
} from '../../test/support/archive-seed';
import type { IntegrationApp } from './app';
import type { FixtureOrganization } from './fixtures';

interface S3Commands {
  PutObjectCommand: new (input: Record<string, unknown>) => object;
  ListObjectVersionsCommand: new (input: Record<string, unknown>) => object;
  DeleteObjectCommand: new (input: Record<string, unknown>) => object;
}
const s3Commands = (): S3Commands =>
  createRequire(require.resolve('@email-gateway/common'))('@aws-sdk/client-s3') as S3Commands;

/** A unique OpenSearch index prefix per test run (`ARCHIVE_SEARCH_INDEX_PREFIX`). */
export const testIndexPrefix = (): string => `it-arch-${randomBytes(4).toString('hex')}`;

export class ArchiveFixtures {
  readonly search: OpenSearchService;
  private readonly cmd = s3Commands();
  private readonly orgs = new Set<bigint>();
  private readonly keys = new Map<bigint, SeedTenantKey>();
  private readonly templates = new Set<string>();

  constructor(
    private readonly ctx: IntegrationApp,
    readonly prefix: string,
  ) {
    if (!ctx.config.ARCHIVE_SEARCH_URL) throw new Error('ARCHIVE_SEARCH_URL is required');
    this.search = new OpenSearchService({
      url: ctx.config.ARCHIVE_SEARCH_URL,
      username: ctx.config.ARCHIVE_SEARCH_USERNAME,
      password: ctx.config.ARCHIVE_SEARCH_PASSWORD,
      timeoutMs: 10_000,
    });
  }

  private get prisma() {
    return this.ctx.prisma;
  }

  private get s3() {
    return this.ctx.get(S3Service);
  }

  /** Version 1 of the organization's tenant key (row inserted once). */
  async tenantKey(org: FixtureOrganization): Promise<SeedTenantKey> {
    this.orgs.add(org.id);
    const existing = this.keys.get(org.id);
    if (existing) return existing;
    const key = await seedTenantKey(this.ctx.config, org.id, 1);
    await this.prisma.archiveEncryptionKey.create({
      data: {
        organizationId: org.id,
        version: 1,
        status: 'active',
        wrappedKey: key.wrappedKey,
        rootKeyId: key.rootKeyId,
        algorithm: key.algorithm,
        activatedAt: new Date(),
      },
    });
    this.keys.set(org.id, key);
    return key;
  }

  /** The archive settings row of an organization (enabled, defaults, optional document). */
  async settings(
    org: FixtureOrganization,
    data: Partial<Prisma.ArchiveSettingUncheckedCreateInput> = {},
  ): Promise<void> {
    this.orgs.add(org.id);
    await this.prisma.archiveSetting.create({
      data: { organizationId: org.id, enabled: true, rowVersion: 1, generation: 1n, ...data },
    });
  }

  /** One captured record: registry row, objects in the archive bucket, row, search document. */
  async record(
    org: FixtureOrganization,
    input: Omit<SeedRecordInput, 'organizationId' | 'messageId'> = {},
    options: { index?: boolean } = {},
  ): Promise<SeededRecord> {
    const key = await this.tenantKey(org);
    const receivedAt = input.receivedAt ?? new Date(Date.now() - 3_600_000);
    const identity = await this.prisma.messageIdentity.create({
      data: {
        organizationId: org.id,
        ingestKey: `v2:it-archive-${randomBytes(16).toString('hex')}`,
        receivedAt,
      },
      select: { id: true, publicId: true },
    });
    const seeded = seedRecord(key, {
      ...input,
      receivedAt,
      organizationId: org.id,
      messageId: identity.id,
      messagePublicId: identity.publicId,
    });
    for (const [objectKey, body] of seeded.objects) {
      await this.s3.client.send(
        new this.cmd.PutObjectCommand({
          Bucket: this.s3.archiveBucket,
          Key: objectKey,
          Body: body,
          ContentType: 'application/octet-stream',
        }) as never,
      );
    }
    await this.prisma.emailArchive.create({
      data: {
        ...seeded.row,
        parties: seeded.row.parties as Prisma.InputJsonValue,
        objects: seeded.row.objects,
        scanRounds: seeded.row.scanRounds,
      },
    });
    if (options.index !== false) await this.index(seeded);
    return seeded;
  }

  /** Indexes a record into the test prefix (template, yearly index with tenant alias, doc). */
  async index(seeded: SeededRecord): Promise<void> {
    const row = seeded.row;
    const template = indexTemplateName(this.prefix);
    if (!this.templates.has(template)) {
      await this.search.putIndexTemplate(
        template,
        buildIndexTemplate({ prefix: this.prefix, shards: 1, replicas: 0 }),
      );
      this.templates.add(template);
    }
    const index = yearlyIndexName(this.prefix, row.receivedAt);
    await this.search.createIndex(index, {
      aliases: aliasesForIndexCreation(this.prefix, [row.organizationId]),
    });
    await this.search.updateAliases(tenantAliasActions(this.prefix, row.organizationId, [index]));
    const built = buildArchiveSearchDocument(row, {
      prefix: this.prefix,
      now: new Date(),
      extra: { attachmentNames: seeded.journal.attachments.map((a) => a.fileName) },
    });
    const result = await this.search.bulk(
      [
        {
          action: 'index',
          index: built.index,
          id: built.id,
          routing: built.routing,
          document: built.document,
        },
      ],
      { refresh: true },
    );
    if (result.errors) throw new Error(`index failed: ${JSON.stringify(result.items)}`);
  }

  /** Removes every archive row, object version, index, alias and template of this run. */
  async cleanup(): Promise<void> {
    const orgs = [...this.orgs];
    if (orgs.length > 0) {
      const byOrg = { where: { organizationId: { in: orgs } } };
      const p = this.prisma;
      await p.archiveDownloadGrant.deleteMany(byOrg);
      await p.ediscoverySearchHit.deleteMany(byOrg);
      await p.ediscoveryExport.deleteMany(byOrg);
      await p.ediscoverySearch.deleteMany(byOrg);
      await p.ediscoveryCustodian.deleteMany(byOrg);
      await p.archiveLegalHold.deleteMany(byOrg);
      await p.ediscoveryCase.deleteMany(byOrg);
      await p.archiveIndexQueue.deleteMany(byOrg);
      await p.archiveIndexCheck.deleteMany(byOrg);
      await p.archiveDisposal.deleteMany(byOrg);
      await p.archiveCaptureIntent.deleteMany(byOrg);
      await p.emailArchive.deleteMany(byOrg);
      await p.archiveSetting.deleteMany(byOrg);
      await p.archiveRetentionPolicy.deleteMany(byOrg);
      await p.archiveEncryptionKey.deleteMany(byOrg);
      await p.messageIdentity.deleteMany(byOrg);
      for (const org of orgs) await this.deleteObjects(`org/${org.toString()}/`);
    }
    for (const template of this.templates) {
      await this.search.request('DELETE', `/${indexPattern(this.prefix)}`, {
        allowStatuses: [404],
      });
      await this.search.request('DELETE', `/_index_template/${template}`, {
        allowStatuses: [404],
      });
    }
    this.templates.clear();
    this.orgs.clear();
    this.keys.clear();
  }

  private async deleteObjects(prefix: string): Promise<void> {
    let keyMarker: string | undefined;
    let versionMarker: string | undefined;
    do {
      const page = (await this.s3.client.send(
        new this.cmd.ListObjectVersionsCommand({
          Bucket: this.s3.archiveBucket,
          Prefix: prefix,
          KeyMarker: keyMarker,
          VersionIdMarker: versionMarker,
        }) as never,
      )) as {
        Versions?: Array<{ Key?: string; VersionId?: string }>;
        DeleteMarkers?: Array<{ Key?: string; VersionId?: string }>;
        IsTruncated?: boolean;
        NextKeyMarker?: string;
        NextVersionIdMarker?: string;
      };
      for (const v of [...(page.Versions ?? []), ...(page.DeleteMarkers ?? [])]) {
        if (!v.Key?.startsWith(prefix)) continue;
        await this.s3.client.send(
          new this.cmd.DeleteObjectCommand({
            Bucket: this.s3.archiveBucket,
            Key: v.Key,
            VersionId: v.VersionId,
          }) as never,
        );
      }
      keyMarker = page.IsTruncated ? page.NextKeyMarker : undefined;
      versionMarker = page.IsTruncated ? page.NextVersionIdMarker : undefined;
    } while (keyMarker !== undefined);
  }
}

/** Requests as one principal (headers), each from a fresh client IP; keyed when `key` is set. */
export function archiveHttp(ctx: IntegrationApp, headers: Record<string, string>) {
  const ip = () => ({
    'X-Forwarded-For': `10.${randomBytes(1)[0]}.${randomBytes(1)[0]}.${(randomBytes(1)[0]! % 250) + 1}`,
  });
  const send = (
    method: 'post' | 'put' | 'patch' | 'delete',
    path: string,
    body?: unknown,
    key?: string,
  ) => {
    const req = ctx.http[method](path).set(headers).set(ip());
    if (key) req.set('Idempotency-Key', key);
    return body === undefined ? req : req.send(body as object);
  };
  return {
    get: (path: string) => ctx.http.get(path).set(headers).set(ip()),
    post: (path: string, body?: unknown, key?: string) => send('post', path, body, key),
    put: (path: string, body?: unknown, key?: string) => send('put', path, body, key),
    patch: (path: string, body?: unknown, key?: string) => send('patch', path, body, key),
    delete: (path: string, key?: string) => send('delete', path, undefined, key),
  };
}
export type ArchiveHttp = ReturnType<typeof archiveHttp>;

/** Polling of replica reads right after a writer change. */
export const ARCHIVE_POLL = { timeout: 15_000, interval: 200 };
