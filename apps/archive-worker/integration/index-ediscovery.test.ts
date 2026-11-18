import { createHash } from 'node:crypto';
import {
  canonicalSha256,
  decryptArchiveObject,
  exportSigningPublicKeyOf,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  tenantAliasName,
  unwrapExportKey,
  verifySignedExportManifest,
  yearlyIndexName,
} from '@email-gateway/archive';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { upsertIntents } from '../src/capture/intents';
import { parseReindexArgs, runReindex } from '../src/cli/reindex';
import { listTemplateVersions } from '../src/index/index-manager';
import { utcDay } from '../src/index/reconcile';
import { Fixtures, type SeededMessage } from './support/fixtures';
import { drainCapture, drainIndex, harness, type Harness, testConfig } from './support/harness';
import { readZip } from './support/zip';

const fx = new Fixtures();
let h: Harness;
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

async function capture(messages: SeededMessage[]) {
  await upsertIntents(
    fx.prisma,
    messages.map((m) => ({
      organizationId: m.organizationId,
      messageId: m.id,
      receivedAt: m.receivedAt,
      direction: 'inbound' as const,
      journal: true,
      policy: false,
      policyRuleRef: null,
      settingsGeneration: 1n,
      nextCheckAt: new Date(0),
    })),
  );
  await drainCapture(h, fx);
  await drainIndex(h, fx);
}

async function aliasCount(org: bigint): Promise<number> {
  await fx.search.request('POST', `/${fx.prefix}-*/_refresh`, { allowStatuses: [404] });
  return fx.search.count(
    tenantAliasName(fx.prefix, org),
    { query: { match_all: {} } },
    { routing: org.toString() },
  );
}

beforeAll(async () => {
  h = await harness(fx);
}, 180_000);

afterAll(async () => {
  await h?.close();
  const { lockedObjects } = await fx.cleanup();
  expect(lockedObjects).toBe(0);
}, 180_000);

describe('index reconciliation and rebuild (A15, A16)', () => {
  it('repairs a missing document and deletes a stray one; records archive_index_checks', async () => {
    const org = await fx.organization('reconcile');
    const msgs = [await fx.message(org.id), await fx.message(org.id), await fx.message(org.id)];
    await capture(msgs);
    expect(await aliasCount(org.id)).toBe(3);
    const day = utcDay(msgs[0]!.receivedAt);
    const reconciler = h.comps.index!.reconciler;
    expect(await reconciler.checkDay(org.id, day)).toBe('ok');
    // A lost document (drift): mismatch → the day is re-enqueued.
    await fx.search.bulk(
      [
        {
          action: 'delete',
          index: yearlyIndexName(fx.prefix, msgs[0]!.receivedAt),
          id: msgs[0]!.publicId,
          routing: org.id.toString(),
        },
      ],
      { refresh: true },
    );
    expect(await aliasCount(org.id)).toBe(2);
    expect(await reconciler.checkDay(org.id, day)).toBe('mismatch');
    expect(
      await fx.prisma.archiveIndexCheck.findFirst({ where: { organizationId: org.id } }),
    ).toMatchObject({ state: 'repairing', mysqlCount: 3, indexCount: 2 });
    await drainIndex(h, fx);
    expect(await reconciler.checkDay(org.id, day)).toBe('ok');
    // A stray document (no live record): mismatch → deleted.
    await fx.search.bulk(
      [
        {
          action: 'index',
          index: yearlyIndexName(fx.prefix, msgs[0]!.receivedAt),
          id: '01999999-0000-7000-8000-00000000abcd',
          routing: org.id.toString(),
          document: {
            org_id: org.id.toString(),
            message_id: '01999999-0000-7000-8000-00000000abcd',
            received_at: msgs[0]!.receivedAt.toISOString(),
          },
        },
      ],
      { refresh: true },
    );
    expect(await aliasCount(org.id)).toBe(4);
    expect(await reconciler.checkDay(org.id, day)).toBe('mismatch');
    await drainIndex(h, fx);
    expect(await aliasCount(org.id)).toBe(3);
    expect(await reconciler.checkDay(org.id, day)).toBe('ok');
    expect(
      await fx.prisma.archiveIndexCheck.findFirst({ where: { organizationId: org.id } }),
    ).toMatchObject({ state: 'ok', mysqlCount: 3, indexCount: 3 });
    // A whole run: recent days plus the rotating older days, every result counted.
    const run = await reconciler.runOnce();
    expect(run.mismatch).toBe(0);
    expect(run.ok).toBeGreaterThanOrEqual(1);
  });

  it('rebuilds the index into a new version and swaps every tenant alias atomically (CLI)', async () => {
    const org = await fx.organization('rebuild');
    await capture([await fx.message(org.id), await fx.message(org.id)]);
    const before = await aliasCount(org.id);
    expect(parseReindexArgs(['--all', '--version', 'v2'])).toMatchObject({ all: true, version: 2 });
    expect(() => parseReindexArgs(['--organization', 'nope'])).toThrow();
    const report = await runReindex(
      { organization: null, all: true, version: 2, batch: 100 },
      {
        prisma: fx.prisma,
        search: fx.search,
        objects: h.comps.objects,
        config: h.config,
        log: () => undefined,
        organizationIds: fx.organizationIds,
      },
    );
    expect(report).toMatchObject({ fromVersion: 1, toVersion: 2, failed: 0 });
    expect(report.indexed).toBeGreaterThanOrEqual(before);
    const aliases = await fx.search.request<Record<string, unknown>>(
      'GET',
      `/_alias/${tenantAliasName(fx.prefix, org.id)}`,
    );
    expect(Object.keys(aliases.body).every((i) => i.startsWith(`${fx.prefix}-v2-`))).toBe(true);
    expect(await aliasCount(org.id)).toBe(before);
    expect(await fx.search.indexExists(yearlyIndexName(fx.prefix, new Date(), 1))).toBe(false);
    expect(await listTemplateVersions(fx.search, fx.prefix)).toEqual([
      { version: 2, building: false },
    ]);
    // The index role follows the active version.
    h.comps.index!.manager.reset();
    expect(await h.comps.index!.manager.refreshVersion()).toBe(2);
    await capture([await fx.message(org.id)]);
    expect(await aliasCount(org.id)).toBe(before + 1);
    // Organization rebuild: documents deleted and every live record re-enqueued.
    const orgReport = await runReindex(
      {
        organization: (await fx.prisma.organization.findUniqueOrThrow({ where: { id: org.id } }))
          .publicId,
        all: false,
        version: null,
        batch: 100,
      },
      {
        prisma: fx.prisma,
        search: fx.search,
        objects: h.comps.objects,
        config: h.config,
        log: () => undefined,
      },
    );
    expect(orgReport.enqueued).toBe(before + 1);
    await drainIndex(h, fx);
    expect(await aliasCount(org.id)).toBe(before + 1);
  });
});

describe('eDiscovery (A18)', () => {
  it('runs a case search to completion, verifies hits in MySQL and reports completeness', async () => {
    const org = await fx.organization('case');
    const custodian = 'custodian@corp-it.example';
    const a = await fx.message(org.id, {
      recipients: [{ address: custodian, direction: 'inbound', status: 'delivered' }],
    });
    const b = await fx.message(org.id, {
      recipients: [{ address: custodian, direction: 'inbound', status: 'delivered' }],
    });
    const other = await fx.message(org.id);
    await capture([a, b, other]);
    const kase = await fx.prisma.ediscoveryCase.create({
      data: { organizationId: org.id, name: 'Matter 1' },
    });
    await fx.prisma.ediscoveryCustodian.create({
      data: { caseId: kase.id, organizationId: org.id, address: custodian },
    });
    const criteria = {
      from: utcDay(new Date(Date.now() - 86_400_000)),
      to: utcDay(new Date()),
      custodians: 'case',
    };
    const search = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria,
        criteriaSha256: canonicalSha256(criteria),
      },
    });
    expect(await h.comps.ediscovery!.searches.runOnce()).toBe(true);
    const done = await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: search.id } });
    expect(done).toMatchObject({
      status: 'completed',
      hitCount: 2,
      truncated: false,
      indexComplete: false,
      incompleteReason: 'unverified_days',
    });
    const hits = await fx.prisma.ediscoverySearchHit.findMany({ where: { searchId: search.id } });
    expect(hits.map((x) => x.messagePublicId).sort()).toEqual([a.publicId, b.publicId].sort());
    const audit = await fx.prisma.auditLog.findFirstOrThrow({
      where: { organizationId: org.id, action: 'ediscovery.search_completed' },
    });
    expect(audit).toMatchObject({
      actorType: 'system',
      resourceType: 'ediscovery_search',
      resourceId: search.publicId,
    });
    // Every day of the range verified by the reconciliation → complete.
    for (const day of [criteria.from, criteria.to])
      await h.comps.index!.reconciler.checkDay(org.id, day);
    const again = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria,
        criteriaSha256: canonicalSha256(criteria),
      },
    });
    await h.comps.ediscovery!.searches.runOnce();
    expect(
      await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: again.id } }),
    ).toMatchObject({
      status: 'completed',
      hitCount: 2,
      indexComplete: true,
      incompleteReason: null,
    });
    // Bounded: ARCHIVE_CASE_SEARCH_MAX_HITS → truncated.
    const small = await harness(fx, {
      config: testConfig(fx, { ARCHIVE_CASE_SEARCH_MAX_HITS: '1' }),
    });
    const truncated = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria,
        criteriaSha256: canonicalSha256(criteria),
      },
    });
    await small.comps.ediscovery!.searches.runOnce();
    expect(
      await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: truncated.id } }),
    ).toMatchObject({ status: 'completed', hitCount: 1, truncated: true });
    await small.close();
    // An unresolvable hold → failed with a code and the failure audit row.
    const bad = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria: { ...criteria, holdId: '01999999-0000-7000-8000-000000000001' },
        criteriaSha256: 'e'.repeat(64),
      },
    });
    await h.comps.ediscovery!.searches.runOnce();
    expect(
      await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: bad.id } }),
    ).toMatchObject({ status: 'failed', errorCode: 'hold_unresolved' });
    expect(
      await fx.prisma.auditLog.count({
        where: { organizationId: org.id, action: 'ediscovery.search_failed' },
      }),
    ).toBe(1);
  });

  it('builds a signed, encrypted export: unzip, hashes, signature, malicious folder; bounds; expiry', async () => {
    const org = await fx.organization('export');
    const clean = await fx.message(org.id);
    const bad = await fx.message(org.id, { maliciousUrl: true });
    await capture([clean, bad]);
    const kase = await fx.prisma.ediscoveryCase.create({
      data: { organizationId: org.id, name: 'Matter 2' },
    });
    const criteria = { from: utcDay(new Date(Date.now() - 86_400_000)), to: utcDay(new Date()) };
    const search = await fx.prisma.ediscoverySearch.create({
      data: {
        caseId: kase.id,
        organizationId: org.id,
        criteria,
        criteriaSha256: canonicalSha256(criteria),
      },
    });
    await h.comps.ediscovery!.searches.runOnce();
    expect(
      await fx.prisma.ediscoverySearch.findUniqueOrThrow({ where: { id: search.id } }),
    ).toMatchObject({ status: 'completed', hitCount: 2 });
    await fx.prisma.ediscoverySearchHit.updateMany({
      where: { searchId: search.id },
      data: { reviewTag: 'relevant' },
    });
    const record = await fx.prisma.emailArchive.findFirstOrThrow({ where: { messageId: bad.id } });
    expect(record.malicious).toBe(true);
    // Malicious items need the acknowledgement.
    const refused = await fx.prisma.ediscoveryExport.create({
      data: {
        caseId: kase.id,
        searchId: search.id,
        organizationId: org.id,
        reviewTags: ['relevant'],
        acknowledgeMalicious: false,
      },
    });
    await h.comps.ediscovery!.exports.runOnce();
    expect(
      await fx.prisma.ediscoveryExport.findUniqueOrThrow({ where: { id: refused.id } }),
    ).toMatchObject({ status: 'failed', errorCode: 'ediscovery_export_malicious_ack_required' });
    // Bounds (ARCHIVE_EXPORT_MAX_ITEMS).
    const tiny = await harness(fx, { config: testConfig(fx, { ARCHIVE_EXPORT_MAX_ITEMS: '1' }) });
    const tooLarge = await fx.prisma.ediscoveryExport.create({
      data: {
        caseId: kase.id,
        searchId: search.id,
        organizationId: org.id,
        reviewTags: ['relevant'],
        acknowledgeMalicious: true,
      },
    });
    await tiny.comps.ediscovery!.exports.runOnce();
    expect(
      await fx.prisma.ediscoveryExport.findUniqueOrThrow({ where: { id: tooLarge.id } }),
    ).toMatchObject({ status: 'failed', errorCode: 'ediscovery_export_too_large' });
    await tiny.close();
    // The real export.
    const exp = await fx.prisma.ediscoveryExport.create({
      data: {
        caseId: kase.id,
        searchId: search.id,
        organizationId: org.id,
        reviewTags: ['relevant', 'untagged'],
        acknowledgeMalicious: true,
      },
    });
    await h.comps.ediscovery!.exports.runOnce();
    const row = await fx.prisma.ediscoveryExport.findUniqueOrThrow({ where: { id: exp.id } });
    expect(row).toMatchObject({
      status: 'completed',
      itemCount: 2,
      maliciousCount: 1,
      signingKeyId: h.config.ARCHIVE_EXPORT_SIGNING_KEY_ID,
    });
    expect(row.objectKey).toBe(
      `org/${org.id}/exports/${row.createdAt.getUTCFullYear()}/${String(row.createdAt.getUTCMonth() + 1).padStart(2, '0')}/${exp.publicId}.bin`,
    );
    expect(row.expiresAt!.getTime()).toBeGreaterThan(Date.now() + 160 * 3_600_000);
    // Decrypt the stored package with the export DEK (wrapped under the tenant key).
    const sealed = await h.comps.storage.getBuffer(
      fx.archiveBucket,
      row.objectKey!,
      row.objectVersionId,
    );
    expect(sealed.subarray(0, 6).toString('ascii')).toBe('EGARC1');
    const tenantKey = await h.comps.keys.version(org.id, row.keyVersion!);
    const dek = unwrapExportKey(tenantKey.key, row.wrappedDek!, {
      organizationId: org.id,
      exportPublicId: exp.publicId,
      keyVersion: row.keyVersion!,
    });
    const zip = decryptArchiveObject(sealed, {
      dek,
      kind: 'export',
      organizationId: org.id,
      subjectId: exp.publicId,
    });
    expect(sha(zip)).toBe(row.packageSha256);
    expect(BigInt(zip.length)).toBe(row.packageBytes);
    const entries = readZip(zip);
    const manifestBytes = entries.get('manifest.json')!;
    expect(sha(manifestBytes)).toBe(row.manifestSha256);
    const publicKey = parseExportSigningPublicKey(
      exportSigningPublicKeyOf(parseExportSigningPrivateKey(h.config.ARCHIVE_EXPORT_SIGNING_KEY)),
    );
    const manifest = verifySignedExportManifest(
      manifestBytes,
      entries.get('manifest.sig')!.toString('utf8'),
      publicKey,
    );
    expect(manifest).not.toBeNull();
    expect(manifest!.counts).toMatchObject({ items: 2, malicious: 1 });
    for (const item of manifest!.items) {
      const file = entries.get(item.path)!;
      expect(sha(file)).toBe(item.sha256);
      expect(file.length).toBe(item.sizeBytes);
      expect(item.path.startsWith(item.malicious ? 'malicious/' : 'messages/')).toBe(true);
    }
    expect(entries.get(manifest!.items.find((i) => !i.malicious)!.path)!.equals(clean.eml)).toBe(
      true,
    );
    expect(entries.has('malicious/README.txt')).toBe(true);
    expect(entries.has('README.txt')).toBe(true);
    // A tampered manifest does not verify.
    const tampered = Buffer.from(manifestBytes.toString('utf8').replace('"items"', '"itemz"'));
    expect(
      verifySignedExportManifest(
        tampered,
        entries.get('manifest.sig')!.toString('utf8'),
        publicKey,
      ),
    ).toBeNull();
    const audit = await fx.prisma.auditLog.findMany({
      where: { organizationId: org.id, action: { startsWith: 'ediscovery.export_' } },
    });
    expect(audit.map((x) => x.action).sort()).toEqual([
      'ediscovery.export_completed',
      'ediscovery.export_failed',
      'ediscovery.export_failed',
    ]);
    expect(JSON.stringify(audit.map((x) => x.metadata))).not.toContain('@');
    // Expiry: the object goes, the row says so.
    await fx.prisma.ediscoveryExport.update({
      where: { id: exp.id },
      data: { expiresAt: new Date(Date.now() - 1_000) },
    });
    expect(await h.comps.ediscovery!.exports.expire()).toBe(1);
    expect(
      await fx.prisma.ediscoveryExport.findUniqueOrThrow({ where: { id: exp.id } }),
    ).toMatchObject({ status: 'expired', wrappedDek: null });
    expect(
      await h.comps.storage.exists(fx.archiveBucket, row.objectKey!, row.objectVersionId),
    ).toBe(false);
  });
});
