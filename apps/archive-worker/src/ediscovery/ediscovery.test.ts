import { createHash, randomBytes } from 'node:crypto';
import {
  ARCHIVE_OBJECT_FORMAT,
  decryptArchiveObject,
  encryptArchiveObject,
  exportSigningPublicKeyOf,
  generateDataKey,
  generateExportSigningKeyPair,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  unwrapExportKey,
  verifySignedExportManifest,
  wrapRecordKey,
} from '@email-gateway/archive';
import { Prisma } from '@email-gateway/database';
import { describe, expect, it } from 'vitest';
import { FakeStorage, readZip, silentLogger, testMetrics } from '../archive.test-support';
import type { TenantKeyService } from '../keys/tenant-keys';
import { RecordObjects } from '../storage/record-objects';
import { ExportBuilder, ExportError } from './exports';
import { searchCompleteness } from './searches';

const ORG = 42n;
const tenantKey = randomBytes(32);
const keys = {
  active: () => Promise.resolve({ organizationId: ORG, version: 1, key: tenantKey }),
  version: () => Promise.resolve({ organizationId: ORG, version: 1, key: tenantKey }),
} as unknown as TenantKeyService;

describe('searchCompleteness (A18)', () => {
  const db = (
    oldestQueued: Date | null,
    states: Array<{ state: string; n: number }>,
    first: Date | null = new Date('2026-11-01T00:00:00Z'),
  ) => ({
    $queryRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = Prisma.sql(strings, ...values).sql;
      if (sql.includes('archive_index_queue')) return Promise.resolve([{ at: oldestQueued }]);
      if (sql.includes('MIN(received_at)')) return Promise.resolve([{ at: first }]);
      return Promise.resolve(states);
    },
  });
  const now = new Date('2026-11-16T12:00:00Z');
  const range = {
    organizationId: ORG,
    from: new Date('2026-10-01T00:00:00Z'),
    to: new Date('2026-11-30T23:59:59Z'),
    now,
  };

  it('index_lag first, then mismatched_days, then unverified_days; only days with records are required', async () => {
    expect(
      await searchCompleteness(db(new Date(now.getTime() - 120_000), []) as never, range),
    ).toEqual({ complete: false, reason: 'index_lag' });
    expect(
      await searchCompleteness(
        db(new Date(now.getTime() - 10_000), [{ state: 'ok', n: 16 }]) as never,
        range,
      ),
    ).toEqual({ complete: true, reason: null });
    expect(
      await searchCompleteness(
        db(null, [
          { state: 'ok', n: 15 },
          { state: 'repairing', n: 1 },
        ]) as never,
        range,
      ),
    ).toEqual({ complete: false, reason: 'mismatched_days' });
    expect(await searchCompleteness(db(null, [{ state: 'ok', n: 15 }]) as never, range)).toEqual({
      complete: false,
      reason: 'unverified_days',
    });
    expect(await searchCompleteness(db(null, [], null) as never, range)).toEqual({
      complete: true,
      reason: null,
    });
  });
});

describe('ExportBuilder (A18)', () => {
  const pair = generateExportSigningKeyPair();
  function record(i: number, storage: FakeStorage, malicious = false) {
    const publicId = `0190a5d0-0000-7000-8000-0000000000${String(10 + i)}`;
    const captureId = '0190a5d0-0000-7000-8000-0000000000ff';
    const eml = Buffer.from(`Subject: ${i}\r\n\r\nbody ${i}`);
    const dek = generateDataKey();
    const sealed = encryptArchiveObject(eml, {
      dek,
      kind: 'eml',
      organizationId: ORG,
      subjectId: publicId,
    });
    const k = `org/${ORG}/archive/2026/11/16/${publicId}/${captureId}/eml.bin`;
    const versionId = storage.seed('archive', k, sealed.object);
    return {
      eml,
      row: {
        id: BigInt(i),
        receivedAt: new Date(`2026-11-16T10:0${i}:00Z`),
        messageId: BigInt(100 + i),
        organizationId: ORG,
        messagePublicId: publicId,
        status: 'active',
        wrappedDek: wrapRecordKey(
          tenantKey,
          { organizationId: ORG, messagePublicId: publicId, captureId, keyVersion: 1 },
          dek,
        ),
        keyVersion: 1,
        sha256: createHash('sha256').update(eml).digest('hex'),
        sizeBytes: eml.length,
        internetMessageId: `<m${i}@x>`,
        finalVerdict: malicious ? 'malware' : 'clean',
        malicious,
        encryptionFormat: ARCHIVE_OBJECT_FORMAT,
        objects: {
          captureId,
          eml: {
            key: k,
            versionId,
            sha256: sealed.summary.ciphertextSha256,
            bytes: sealed.object.length,
          },
          journal: {
            key: k.replace('eml', 'journal'),
            versionId: 'x',
            sha256: 'a'.repeat(64),
            bytes: 1,
          },
          scans: [],
        },
      },
    };
  }

  function builder(
    storage: FakeStorage,
    rows: unknown[],
    over: { maxItems?: number; ack?: boolean; status?: string } = {},
  ) {
    const updates: Prisma.Sql[] = [];
    const audits: unknown[] = [];
    const db = {
      updates,
      audits,
      ediscoverySearch: {
        findUnique: () =>
          Promise.resolve({
            organizationId: ORG,
            caseId: 1n,
            status: over.status ?? 'completed',
            publicId: '0190a5d0-0000-7000-8000-0000000000c2',
          }),
      },
      ediscoverySearchHit: {
        findMany: ({ where }: { where: { id: { gt: bigint } } }) =>
          Promise.resolve(
            where.id.gt === 0n
              ? (rows as Array<{ id: bigint; messageId: bigint; receivedAt: Date }>).map((r) => ({
                  id: r.id,
                  messageId: r.messageId,
                  messageReceivedAt: r.receivedAt,
                }))
              : [],
          ),
      },
      emailArchive: {
        findMany: () => Promise.resolve(rows),
        findUnique: ({ where }: { where: { id_receivedAt: { id: bigint } } }) =>
          Promise.resolve(
            (rows as Array<{ id: bigint }>).find((r) => r.id === where.id_receivedAt.id) ?? null,
          ),
      },
      organization: {
        findUnique: () => Promise.resolve({ publicId: '0190a5d0-0000-7000-8000-0000000000c0' }),
      },
      ediscoveryCase: {
        findUnique: () =>
          Promise.resolve({
            publicId: '0190a5d0-0000-7000-8000-0000000000c1',
            organizationId: ORG,
          }),
      },
      $transaction: (fn: (tx: unknown) => Promise<unknown>) => fn(db),
      $executeRaw: (strings: TemplateStringsArray, ...values: unknown[]) => {
        updates.push(Prisma.sql(strings, ...values));
        return Promise.resolve(1);
      },
      auditLog: { create: (a: unknown) => Promise.resolve(void audits.push(a)) },
    };
    const exports = new ExportBuilder(db as never, {
      storage: storage.asStorage(),
      objects: new RecordObjects(storage.asStorage(), keys),
      keys,
      metrics: testMetrics().metrics,
      logger: silentLogger,
      signingKey: parseExportSigningPrivateKey(pair.privateKey),
      signingKeyId: 'es1',
      maxItems: over.maxItems ?? 100,
      maxBytes: 1_000_000,
      ttlHours: 168,
      chunkBytes: 16_384,
    });
    const claimed = {
      id: 9n,
      publicId: '0190a5d0-0000-7000-8000-0000000000e9',
      caseId: 1n,
      searchId: 2n,
      organizationId: ORG,
      reviewTags: ['relevant', 'untagged'],
      acknowledgeMalicious: over.ack ?? true,
      createdAt: new Date('2026-11-16T12:00:00Z'),
    };
    return { exports, db, claimed };
  }

  it('streams a ZIP of verified originals, a signed manifest and READMEs, encrypted under an export DEK', async () => {
    const storage = new FakeStorage();
    const a = record(1, storage);
    const b = record(2, storage, true);
    const { exports, db, claimed } = builder(storage, [a.row, b.row]);
    expect(await exports.build(claimed as never)).toBe('completed');
    const done = db.updates.find((u) => u.sql.includes("status = 'completed'"))!;
    const [
      items,
      malicious,
      bytes,
      pkgSha,
      manifestSha,
      keyId,
      objectKey,
      versionId,
      keyVersion,
      wrapped,
    ] = done.values as [
      number,
      number,
      bigint,
      string,
      string,
      string,
      string,
      string,
      number,
      string,
    ];
    expect([items, malicious, keyId, keyVersion]).toEqual([2, 1, 'es1', 1]);
    expect(objectKey).toBe(`org/${ORG}/exports/2026/11/${claimed.publicId}.bin`);
    const stored = storage.versions('archive', objectKey)[0]!;
    expect(stored.tagging).toBe('eg-object=archive-export');
    expect(stored.lock).toBeNull();
    expect(stored.versionId).toBe(versionId);
    const dek = unwrapExportKey(tenantKey, wrapped, {
      organizationId: ORG,
      exportPublicId: claimed.publicId,
      keyVersion: 1,
    });
    const zip = decryptArchiveObject(stored.body, {
      dek,
      kind: 'export',
      organizationId: ORG,
      subjectId: claimed.publicId,
    });
    expect(createHash('sha256').update(zip).digest('hex')).toBe(pkgSha);
    expect(BigInt(zip.length)).toBe(bytes);
    const entries = readZip(zip);
    const manifestBytes = entries.get('manifest.json')!;
    expect(createHash('sha256').update(manifestBytes).digest('hex')).toBe(manifestSha);
    const manifest = verifySignedExportManifest(
      manifestBytes,
      entries.get('manifest.sig')!.toString(),
      parseExportSigningPublicKey(
        exportSigningPublicKeyOf(parseExportSigningPrivateKey(pair.privateKey)),
      ),
    )!;
    expect(manifest.items.map((i) => i.path)).toEqual([
      expect.stringMatching(/^messages\//),
      expect.stringMatching(/^malicious\//),
    ]);
    expect(entries.get(manifest.items[0]!.path)!.equals(a.eml)).toBe(true);
    expect(entries.get(manifest.items[1]!.path)!.equals(b.eml)).toBe(true);
    expect([...entries.keys()].sort()).toEqual(
      [
        ...manifest.items.map((i) => i.path),
        'README.txt',
        'malicious/README.txt',
        'manifest.json',
        'manifest.sig',
      ].sort(),
    );
    expect(db.audits).toHaveLength(1);
    expect(db.audits[0]).toMatchObject({
      data: {
        action: 'ediscovery.export_completed',
        resourceType: 'ediscovery_export',
        resourceId: claimed.publicId,
      },
    });
  });

  it('refuses before writing: search not completed, too large, malicious without acknowledgement', async () => {
    const storage = new FakeStorage();
    const a = record(1, storage);
    const b = record(2, storage, true);
    await expect(
      builder(storage, [a.row], { status: 'running' }).exports.select(
        builder(storage, [a.row]).claimed as never,
      ),
    ).rejects.toMatchObject({ code: 'ediscovery_search_not_completed' });
    const tooMany = builder(storage, [a.row, b.row], { maxItems: 1 });
    await expect(tooMany.exports.select(tooMany.claimed as never)).rejects.toBeInstanceOf(
      ExportError,
    );
    const noAck = builder(storage, [a.row, b.row], { ack: false });
    expect(await noAck.exports.build(noAck.claimed as never)).toBe('failed');
    expect(noAck.db.updates.find((u) => u.sql.includes("status = 'failed'"))!.values).toContain(
      'ediscovery_export_malicious_ack_required',
    );
    expect(storage.versions('archive', `org/${ORG}/exports/`)).toHaveLength(0);
  });

  it('fails (and removes the package) when an original no longer matches its SHA-256', async () => {
    const storage = new FakeStorage();
    const a = record(1, storage);
    a.row.sha256 = 'f'.repeat(64);
    const { exports, db, claimed } = builder(storage, [a.row]);
    expect(await exports.build(claimed as never)).toBe('failed');
    expect(db.updates.find((u) => u.sql.includes("status = 'failed'"))!.values).toContain(
      'archive_integrity_failed',
    );
    expect(storage.versions('archive', `org/${ORG}/exports/`)).toHaveLength(0);
  });
});
