import { ARCHIVE_PARTIES_EXAMPLE, ARCHIVE_JOURNAL_EXAMPLE } from '@email-gateway/archive';
import type { OpenSearchBulkOperation, OpenSearchService } from '@email-gateway/common';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { metricValue, silentLogger, testMetrics } from '../archive.test-support';
import type { RecordObjects } from '../storage/record-objects';
import { IndexManager, listTemplateVersions } from './index-manager';
import { extraFacts, IndexSync, isIndexable } from './index-sync';
import { IndexReconciler } from './reconcile';

const ORG = 42n;
const PREFIX = 'eg-archive-unit';

/** A fake OpenSearch recording requests; `bulk` answers per op from `failIds`. */
function fakeSearch(
  options: {
    templates?: unknown[];
    indices?: string[];
    aliases?: string[];
    failIds?: string[];
    count?: number;
  } = {},
) {
  const calls: Array<{ method: string; path: string; body?: unknown }> = [];
  const bulks: OpenSearchBulkOperation[][] = [];
  const search = {
    calls,
    bulks,
    request: (method: string, path: string, opts: { body?: unknown } = {}) => {
      calls.push({ method, path, body: opts.body });
      if (path.startsWith('/_index_template/'))
        return Promise.resolve({ status: 200, body: { index_templates: options.templates ?? [] } });
      if (path.startsWith('/_cat/indices/'))
        return Promise.resolve({
          status: 200,
          body: (options.indices ?? []).map((index) => ({ index })),
        });
      if (path.startsWith('/_alias/'))
        return Promise.resolve({
          status: 200,
          body: Object.fromEntries((options.aliases ?? []).map((i) => [i, {}])),
        });
      return Promise.resolve({ status: 200, body: {} });
    },
    putIndexTemplate: (name: string, body: unknown) =>
      Promise.resolve(void calls.push({ method: 'PUT', path: `/_index_template/${name}`, body })),
    indexExists: (index: string) => Promise.resolve((options.indices ?? []).includes(index)),
    createIndex: (index: string, body: unknown) => {
      calls.push({ method: 'PUT', path: `/${index}`, body });
      return Promise.resolve({ created: true });
    },
    updateAliases: (body: unknown) =>
      Promise.resolve(void calls.push({ method: 'POST', path: '/_aliases', body })),
    bulk: (ops: OpenSearchBulkOperation[]) => {
      bulks.push(ops);
      return Promise.resolve({
        errors: false,
        items: ops.map((o) => ({
          action: o.action,
          index: o.index,
          id: o.id,
          status: (options.failIds ?? []).includes(o.id) ? 429 : 200,
          errorType: (options.failIds ?? []).includes(o.id)
            ? 'es_rejected_execution_exception'
            : null,
          ok: !(options.failIds ?? []).includes(o.id),
        })),
      });
    },
    count: () => Promise.resolve(options.count ?? 0),
    search: () => Promise.resolve({ timedOut: false, hits: [] }),
    deleteByQuery: (index: string, body: unknown) => {
      calls.push({ method: 'POST', path: `/${index}/_delete_by_query`, body });
      return Promise.resolve({ deleted: 0 });
    },
  };
  return search;
}

describe('IndexManager (A16)', () => {
  const db = {
    $queryRaw: () => Promise.resolve([{ organization_id: 7n }, { organization_id: ORG }]),
  };

  it('creates a missing yearly index with every known tenant alias, once', async () => {
    const search = fakeSearch();
    const manager = new IndexManager(search as unknown as OpenSearchService, db as never, {
      prefix: PREFIX,
      shards: 1,
      replicas: 0,
    });
    await manager.ensureIndex(`${PREFIX}-v1-2026`, [99n]);
    await manager.ensureIndex(`${PREFIX}-v1-2026`);
    const created = search.calls.filter((c) => c.path === `/${PREFIX}-v1-2026`);
    expect(created).toHaveLength(1);
    expect(
      Object.keys((created[0]!.body as { aliases: Record<string, unknown> }).aliases).sort(),
    ).toEqual([`${PREFIX}-t42`, `${PREFIX}-t7`, `${PREFIX}-t99`]);
    expect(search.calls.some((c) => c.path === `/_index_template/${PREFIX}-v1`)).toBe(true);
  });

  it('adds a tenant alias to the indices that lack it before its first document', async () => {
    const search = fakeSearch({
      indices: [`${PREFIX}-v1-2025`, `${PREFIX}-v1-2026`],
      aliases: [`${PREFIX}-v1-2025`],
    });
    const manager = new IndexManager(search as unknown as OpenSearchService, db as never, {
      prefix: PREFIX,
      shards: 1,
      replicas: 0,
    });
    await manager.ensureTenantAlias(ORG);
    await manager.ensureTenantAlias(ORG);
    const aliasCalls = search.calls.filter((c) => c.path === '/_aliases');
    expect(aliasCalls).toHaveLength(1);
    expect(aliasCalls[0]!.body).toEqual({
      actions: [
        {
          add: {
            index: `${PREFIX}-v1-2026`,
            alias: `${PREFIX}-t42`,
            filter: { term: { org_id: '42' } },
            routing: '42',
          },
        },
      ],
    });
  });

  it('follows the active version: the highest template not marked building', async () => {
    const search = fakeSearch({
      templates: [
        { name: `${PREFIX}-v1`, index_template: { _meta: {} } },
        { name: `${PREFIX}-v2`, index_template: { _meta: { state: 'building' } } },
        { name: 'other-v9' },
      ],
    });
    expect(await listTemplateVersions(search as unknown as OpenSearchService, PREFIX)).toEqual([
      { version: 1, building: false },
      { version: 2, building: true },
    ]);
    const manager = new IndexManager(search as unknown as OpenSearchService, db as never, {
      prefix: PREFIX,
      shards: 1,
      replicas: 0,
    });
    expect(await manager.refreshVersion()).toBe(1);
  });
});

describe('IndexSync (A16)', () => {
  const receivedAt = new Date('2026-11-16T10:00:00.000Z');
  const record = (over: Record<string, unknown> = {}) => ({
    id: 1n,
    receivedAt,
    messageId: 100n,
    organizationId: ORG,
    messagePublicId: '0190a5d0-0000-7000-8000-0000000000aa',
    archivedAt: receivedAt,
    direction: 'inbound',
    category: 'delivered',
    capturedByJournal: true,
    capturedByPolicy: false,
    status: 'active',
    envelopeFrom: 'Sender@Partner.Example',
    headerFrom: null,
    parties: ARCHIVE_PARTIES_EXAMPLE,
    subject: 'Q',
    internetMessageId: '<A@B>',
    sizeBytes: 10,
    attachmentCount: 1,
    finalVerdict: 'clean',
    finalAction: 'deliver',
    riskScore: 5,
    malicious: false,
    retainUntil: new Date('2033-01-01T00:00:00.000Z'),
    legalHold: false,
    lockMode: 'none',
    wrappedDek: 'v1.k1.x',
    deletedAt: null,
    updatedAt: receivedAt,
    objects: {},
    ...over,
  });
  const queueRow = (id: number, messageId: bigint, publicId: string, op = 'upsert') => ({
    id: BigInt(id),
    organization_id: ORG,
    message_id: messageId,
    received_at: receivedAt,
    message_public_id: publicId,
    op,
    attempts: 0,
  });

  function db(rows: unknown[], records: unknown[]) {
    const deleted: bigint[][] = [];
    const executed: Prisma.Sql[] = [];
    return {
      deleted,
      executed,
      $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const sql = Prisma.sql(strings, ...values).sql;
        if (sql.includes('FROM archive_index_queue') && sql.includes('available_at'))
          return Promise.resolve(rows);
        if (sql.includes('COUNT(*)')) return Promise.resolve([{ n: 0 }]);
        return Promise.resolve([]);
      },
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        executed.push(Prisma.sql(strings, ...values));
        return Promise.resolve(1);
      },
      emailArchive: { findMany: () => Promise.resolve(records) },
      archiveIndexQueue: {
        deleteMany: ({ where }: { where: { id: { in: bigint[] } } }) =>
          Promise.resolve(void deleted.push(where.id.in)),
      },
    };
  }
  const objects = {
    journal: () => Promise.resolve(ARCHIVE_JOURNAL_EXAMPLE),
    latestScan: () =>
      Promise.resolve({
        rows: {
          auth: [{ spf: 'pass', dkim: 'fail', dmarc: 'pass' }],
          dlp: [{ matchedRuleId: 3n }],
        },
      }),
  } as unknown as RecordObjects;

  it('coalesces ops per message, indexes live rows and deletes disposing/gone ones, then deletes the queue rows', async () => {
    const live = record();
    const disposing = record({
      id: 2n,
      messageId: 101n,
      messagePublicId: '0190a5d0-0000-7000-8000-0000000000bb',
      status: 'disposing',
      wrappedDek: null,
    });
    const d = db(
      [
        queueRow(1, 100n, live.messagePublicId),
        queueRow(2, 100n, live.messagePublicId),
        queueRow(3, 101n, disposing.messagePublicId, 'delete'),
        queueRow(4, 102n, '0190a5d0-0000-7000-8000-0000000000cc'),
      ],
      [live, disposing],
    );
    const search = fakeSearch();
    const { metrics, service } = testMetrics();
    const manager = new IndexManager(
      search as unknown as OpenSearchService,
      { $queryRaw: () => Promise.resolve([]) } as never,
      { prefix: PREFIX, shards: 1, replicas: 0, version: 1 },
    );
    const sync = new IndexSync(d as never, {
      search: search as unknown as OpenSearchService,
      manager,
      objects,
      metrics,
      logger: silentLogger,
      batchSize: 10,
    });
    const report = await sync.runOnce();
    expect(report).toMatchObject({ claimed: 4, indexed: 1, deleted: 2, failed: 0 });
    const ops = search.bulks[0]!;
    expect(ops.map((o) => `${o.action}:${o.id}`)).toEqual([
      `index:${live.messagePublicId}`,
      `delete:${disposing.messagePublicId}`,
      'delete:0190a5d0-0000-7000-8000-0000000000cc',
    ]);
    const doc = (ops[0] as { document: Record<string, unknown> }).document;
    expect(doc).toMatchObject({
      org_id: '42',
      envelope_from: 'sender@partner.example',
      attachment_names: ['report.pdf'],
      dlp_matched: true,
      spf: 'pass',
      dkim: 'fail',
    });
    expect(ops.every((o) => o.routing === '42' && o.index === `${PREFIX}-v1-2026`)).toBe(true);
    expect(d.deleted[0]!.sort()).toEqual([1n, 2n, 3n, 4n]);
    expect(
      await metricValue(service, 'archive_index_ops_total', { op: 'upsert', result: 'ok' }),
    ).toBe(1);
  });

  it('a failed item backs off its queue rows (status and type logged only)', async () => {
    const live = record();
    const d = db([queueRow(1, 100n, live.messagePublicId)], [live]);
    const search = fakeSearch({ failIds: [live.messagePublicId] });
    const manager = new IndexManager(
      search as unknown as OpenSearchService,
      { $queryRaw: () => Promise.resolve([]) } as never,
      { prefix: PREFIX, shards: 1, replicas: 0, version: 1 },
    );
    const sync = new IndexSync(d as never, {
      search: search as unknown as OpenSearchService,
      manager,
      objects,
      metrics: testMetrics().metrics,
      logger: silentLogger,
      batchSize: 10,
      random: () => 0,
    });
    expect((await sync.runOnce()).failed).toBe(1);
    expect(d.deleted).toHaveLength(0);
    const backoff = d.executed.find((s) => s.sql.includes('UPDATE archive_index_queue'))!;
    expect(backoff.values).toContain('es_rejected_execution_exception');
  });

  it('isIndexable and extraFacts', async () => {
    expect(isIndexable(null)).toBe(false);
    expect(isIndexable({ status: 'active', deletedAt: null, wrappedDek: 'x' })).toBe(true);
    expect(isIndexable({ status: 'expiry_review', deletedAt: null, wrappedDek: 'x' })).toBe(true);
    expect(isIndexable({ status: 'disposing', deletedAt: new Date(), wrappedDek: null })).toBe(
      false,
    );
    const extra = await extraFacts(objects, record() as never);
    expect(extra).toMatchObject({ attachmentNames: ['report.pdf'], dlpMatched: true, spf: 'pass' });
  });
});

describe('IndexReconciler (A15)', () => {
  it('checks the recent days and rotates backwards through older ones; skips days with queued ops', async () => {
    const cursors = new Map<string, Date>();
    const db = {
      $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        const sql = Prisma.sql(strings, ...values).sql;
        if (sql.includes('MIN(received_at)'))
          return Promise.resolve([{ at: new Date('2026-10-01T05:00:00Z') }]);
        if (sql.includes('FROM archive_index_queue')) return Promise.resolve([{ n: 1 }]);
        return Promise.resolve([]);
      },
      streamCursor: {
        findUnique: ({ where }: { where: { name: string } }) =>
          Promise.resolve(
            cursors.has(where.name)
              ? { name: where.name, positionId: null, lastEventAt: cursors.get(where.name) }
              : null,
          ),
        upsert: ({ create }: { create: { name: string; lastEventAt: Date } }) =>
          Promise.resolve(void cursors.set(create.name, create.lastEventAt)),
      },
    };
    const reconciler = new IndexReconciler(db as never, {
      search: fakeSearch() as unknown as OpenSearchService,
      manager: { options: { prefix: PREFIX } } as never,
      metrics: testMetrics().metrics,
      logger: silentLogger,
      recentDays: 2,
      rotatingDays: 3,
      now: () => new Date('2026-11-16T12:00:00Z'),
    });
    expect(await reconciler.daysOf(ORG)).toEqual([
      '2026-11-16',
      '2026-11-15',
      '2026-11-14',
      '2026-11-13',
      '2026-11-12',
    ]);
    expect(await reconciler.daysOf(ORG)).toEqual([
      '2026-11-16',
      '2026-11-15',
      '2026-11-11',
      '2026-11-10',
      '2026-11-09',
    ]);
    expect(await reconciler.checkDay(ORG, '2026-11-16')).toBe('skipped');
  });
});
