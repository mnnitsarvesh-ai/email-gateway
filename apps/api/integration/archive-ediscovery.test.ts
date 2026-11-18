/**
 * Legal holds and eDiscovery against the real writer and replica and MinIO (step 8.1 §9.3):
 * cases with custodians (user links), holds created inside a case with the case's custodians
 * snapshotted and released with a reason, case close refused while holds are active, queued case
 * searches, the archive-worker's completion simulated (status, completeness flags and verified
 * hits written on the writer), masked hits, review tags, export requests with the bounds and
 * the malicious acknowledgement, and an export package written like the worker writes it
 * (encrypted under an export DEK into `org/<org>/exports/`, manifest signed with the configured
 * Ed25519 key) downloaded through a single-use grant and verified against its SHA-256 and the
 * published signing key. Audit rows carry ids, counts and hashes only.
 */
// @covers get /api/v1/legal-holds
// @covers get /api/v1/legal-holds/:holdId
// @covers post /api/v1/legal-holds/:holdId/release
// @covers post /api/v1/ediscovery/cases/:caseId/holds
// @covers get /api/v1/ediscovery/cases
// @covers post /api/v1/ediscovery/cases
// @covers get /api/v1/ediscovery/cases/:caseId
// @covers patch /api/v1/ediscovery/cases/:caseId
// @covers post /api/v1/ediscovery/cases/:caseId/close
// @covers post /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId
// @covers get /api/v1/ediscovery/cases/:caseId/searches/:searchId/hits
// @covers post /api/v1/ediscovery/cases/:caseId/searches/:searchId/review
// @covers post /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports
// @covers get /api/v1/ediscovery/cases/:caseId/exports/:exportId
// @covers post /api/v1/ediscovery/cases/:caseId/exports/:exportId/download-grants
import { createHash, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import {
  buildSignedExportManifest,
  encryptArchiveObject,
  exportObjectKey,
  generateDataKey,
  parseExportSigningPrivateKey,
  parseExportSigningPublicKey,
  verifySignedExportManifest,
  wrapExportKey,
} from '@email-gateway/archive';
import { S3Service } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { SeededRecord } from '../test/support/archive-seed';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import {
  ARCHIVE_POLL,
  ArchiveFixtures,
  archiveHttp,
  type ArchiveHttp,
  testIndexPrefix,
} from './support/archive';
import {
  createFixtures,
  type FixtureOrganization,
  type FixtureUser,
  type Fixtures,
} from './support/fixtures';
import { apiKeyHeader, bearer, loginWithMfa } from './support/http';
import { pauseLiveArchiveWorker } from './support/live-archive-worker';

const C = '/api/v1/ediscovery/cases';
const key = () => `it-${randomUUID()}`;

let ctx: IntegrationApp;
let fx: Fixtures;
let ax: ArchiveFixtures;
let org: FixtureOrganization;
let user: FixtureUser;
let admin: ArchiveHttp;
let apiKey: ArchiveHttp;
/** A case manager that may write custodian addresses (needs message:reveal, A17). */
let custodianKey: ArchiveHttp;
let records: SeededRecord[];
let resumeLiveArchiveWorker: (() => Promise<void>) | undefined;

beforeAll(async () => {
  // The suite simulates the worker; a live archive-worker would claim its queued searches and
  // exports (live-archive-worker.ts).
  resumeLiveArchiveWorker = await pauseLiveArchiveWorker();
  ctx = await createIntegrationApp({
    ARCHIVE_SEARCH_INDEX_PREFIX: testIndexPrefix(),
    ARCHIVE_EXPORT_MAX_ITEMS: '2',
  });
  fx = createFixtures(ctx);
  ax = new ArchiveFixtures(ctx, ctx.config.ARCHIVE_SEARCH_INDEX_PREFIX);
  fx.registerCleanup(() => ax.cleanup());
  org = await fx.createOrganization({ planCode: 'enterprise' });
  user = await fx.createUser(org, { roles: ['organization_admin'], mfa: true });
  admin = archiveHttp(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  apiKey = archiveHttp(
    ctx,
    apiKeyHeader(
      await fx.createApiKey(org, ['ediscovery:manage', 'archive:search', 'archive:export']),
    ),
  );
  custodianKey = archiveHttp(
    ctx,
    apiKeyHeader(
      await fx.createApiKey(org, ['ediscovery:manage', 'archive:search', 'message:reveal']),
    ),
  );
  await ax.settings(org);
  records = [
    await ax.record(org, { recipients: [user.email] }, { index: false }),
    await ax.record(org, { recipients: [user.email], malicious: true }, { index: false }),
  ];
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
  await resumeLiveArchiveWorker?.();
}, 180_000);

const audits = (action: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action },
    orderBy: { id: 'asc' },
  });

describe('cases and legal holds', () => {
  let caseId: string;
  let holdId: string;

  it('creates a case with custodians linked to users, then updates them with the CAS', async () => {
    // Custodian addresses need message:reveal (they drive custodians: "case" searches): a case
    // manager without it is refused before anything is written (closing-round fix of 8.1).
    const refused = await apiKey.post(
      C,
      { name: `Matter ${randomUUID()}`, custodians: [user.email] },
      key(),
    );
    expect(refused.status).toBe(403);
    expect(refused.body).toMatchObject({ code: 'archive_filter_forbidden', filter: 'custodians' });
    const res = await custodianKey.post(
      C,
      { name: `Matter ${randomUUID()}`, custodians: [user.email.toUpperCase()] },
      key(),
    );
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    caseId = res.body.id;
    expect(res.body.custodians).toEqual([
      expect.objectContaining({ address: user.email, userId: user.publicId }),
    ]);
    const probe = await apiKey.patch(
      `${C}/${caseId}`,
      { expectedRowVersion: 1, custodians: ['ceo@example.org'] },
      key(),
    );
    expect(probe.body).toMatchObject({ code: 'archive_filter_forbidden', filter: 'custodians' });
    const patched = await custodianKey.patch(
      `${C}/${caseId}`,
      { expectedRowVersion: 1, custodians: [user.email, 'outside@example.org'] },
      key(),
    );
    expect(patched.body).toMatchObject({ rowVersion: 2, counts: { custodians: 2 } });
    const stale = await apiKey.patch(`${C}/${caseId}`, { expectedRowVersion: 1, name: 'x' }, key());
    expect(stale.body).toMatchObject({ code: 'ediscovery_case_conflict', currentRowVersion: 2 });
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`${C}/${caseId}`)).body.rowVersion,
        ARCHIVE_POLL,
      )
      .toBe(2);
    expect((await admin.get(C)).body.data.map((c: { id: string }) => c.id)).toContain(caseId);
  });

  it('places a hold with the case custodians (MFA), refuses the case close, releases it', async () => {
    const res = await admin.post(
      `${C}/${caseId}/holds`,
      { name: 'Litigation', reason: 'Notice received', useCaseCustodians: true },
      key(),
    );
    expect(res.status, JSON.stringify(res.body)).toBe(201);
    holdId = res.body.id;
    const row = await ctx.prisma.archiveLegalHold.findUniqueOrThrow({
      where: { publicId: holdId },
    });
    expect(row).toMatchObject({
      organizationId: org.id,
      criteriaVersion: 'archive-hold/1',
      status: 'active',
    });
    expect((row.criteria as { custodians: string[] }).custodians.sort()).toEqual(
      ['outside@example.org', user.email].sort(),
    );
    const [created] = await audits('legal_hold.created');
    expect(JSON.stringify(created?.metadata)).not.toContain(user.email);
    expect(
      (await apiKey.post(`${C}/${caseId}/holds`, { name: 'x', reason: 'y' }, key())).body.code,
    ).toBe('user_required');
    const close = await admin.post(`${C}/${caseId}/close`, undefined, key());
    expect(close.body).toMatchObject({ code: 'ediscovery_case_has_active_holds', activeHolds: 1 });
    await expect
      .poll(
        async (): Promise<unknown> => (await admin.get(`/api/v1/legal-holds/${holdId}`)).status,
        ARCHIVE_POLL,
      )
      .toBe(200);
    const list = await admin.get(`/api/v1/legal-holds?status=active&caseId=${caseId}`);
    expect(list.body.data.map((h: { id: string }) => h.id)).toEqual([holdId]);
    // The hold shows on the record detail for hold holders.
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`/api/v1/archive/messages/${records[0]!.row.messagePublicId}`)).body
            .holds?.length,
        ARCHIVE_POLL,
      )
      .toBe(1);
    const release = await admin.post(
      `/api/v1/legal-holds/${holdId}/release`,
      { reason: 'Matter settled' },
      key(),
    );
    expect(release.body).toMatchObject({ status: 'released', releaseReason: 'Matter settled' });
    expect(
      (await admin.post(`/api/v1/legal-holds/${holdId}/release`, { reason: 'again' }, key())).body
        .code,
    ).toBe('legal_hold_already_released');
  });

  it('searches, completion by the worker (simulated), masked hits, review, export and download', async () => {
    const queued = await apiKey.post(
      `${C}/${caseId}/searches`,
      { criteria: { from: '2026-01-01', to: '2026-12-31', custodians: 'case' } },
      key(),
    );
    expect(queued.status, JSON.stringify(queued.body)).toBe(202);
    const searchId = queued.body.id as string;
    const busy = await apiKey.post(
      `${C}/${caseId}/searches`,
      { criteria: { from: '2026-01-01', to: '2026-02-01' } },
      key(),
    );
    expect(busy.status).toBe(202);
    const limit = await apiKey.post(
      `${C}/${caseId}/searches`,
      { criteria: { from: '2026-01-01', to: '2026-03-01' } },
      key(),
    );
    expect(limit.status).toBe(202);
    const over = await apiKey.post(
      `${C}/${caseId}/searches`,
      { criteria: { from: '2026-01-01', to: '2026-04-01' } },
      key(),
    );
    expect(over.body.code).toBe('ediscovery_search_limit');
    // The archive-worker's ediscovery role: completes the search with verified hits.
    const search = await ctx.prisma.ediscoverySearch.findUniqueOrThrow({
      where: { publicId: searchId },
    });
    await ctx.prisma.ediscoverySearch.update({
      where: { id: search.id },
      data: {
        status: 'completed',
        hitCount: 2,
        indexComplete: true,
        startedAt: new Date(),
        completedAt: new Date(),
      },
    });
    for (const r of records) {
      await ctx.prisma.ediscoverySearchHit.create({
        data: {
          searchId: search.id,
          organizationId: org.id,
          messageId: r.row.messageId,
          messageReceivedAt: r.row.receivedAt,
          messagePublicId: r.row.messagePublicId,
        },
      });
    }
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`${C}/${caseId}/searches/${searchId}`)).body.status,
        ARCHIVE_POLL,
      )
      .toBe('completed');
    const hits = await admin.get(`${C}/${caseId}/searches/${searchId}/hits`);
    expect(hits.body.data).toHaveLength(2);
    expect(hits.body.data[0].message).toMatchObject({ subject: null, subjectMasked: true });
    expect(JSON.stringify(hits.body)).not.toContain(user.email);
    expect(await audits('ediscovery.hits_viewed')).toHaveLength(1);
    const review = await admin.post(
      `${C}/${caseId}/searches/${searchId}/review`,
      { tag: 'relevant', messageIds: [records[0]!.row.messagePublicId] },
      key(),
    );
    expect(review.body).toMatchObject({ updated: 1, notFound: 0 });
    const ack = await apiKey.post(`${C}/${caseId}/exports`, { searchId }, key());
    expect(ack.body).toMatchObject({
      code: 'ediscovery_export_malicious_ack_required',
      maliciousCount: 1,
    });
    const queuedExport = await apiKey.post(
      `${C}/${caseId}/exports`,
      { searchId, reviewTags: ['relevant'] },
      key(),
    );
    expect(queuedExport.status, JSON.stringify(queuedExport.body)).toBe(202);
    expect(queuedExport.body).toMatchObject({
      status: 'queued',
      itemCount: 1,
      maliciousCount: 0,
      reviewTags: ['relevant'],
    });
    const exportId = queuedExport.body.id as string;

    // The archive-worker builds the package: signed manifest, encrypted under an export DEK.
    const exportRow = await ctx.prisma.ediscoveryExport.findUniqueOrThrow({
      where: { publicId: exportId },
    });
    const tenantKey = await ax.tenantKey(org);
    const signed = buildSignedExportManifest(
      {
        exportId,
        caseId,
        searchId,
        organizationId: org.publicId,
        generatedAt: new Date(),
        signingKeyId: ctx.config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID,
        reviewTags: ['relevant'],
        items: [
          {
            messageId: records[0]!.row.messagePublicId,
            receivedAt: records[0]!.row.receivedAt,
            internetMessageId: records[0]!.row.internetMessageId,
            sha256: records[0]!.row.sha256,
            sizeBytes: records[0]!.row.sizeBytes,
            verdict: 'clean',
            malicious: false,
          },
        ],
      },
      parseExportSigningPrivateKey(process.env.ARCHIVE_EXPORT_SIGNING_KEY),
    );
    const dek = generateDataKey();
    const objectKey = exportObjectKey({
      organizationId: org.id,
      createdAt: exportRow.createdAt,
      exportPublicId: exportId,
    });
    const object = encryptArchiveObject(signed.bytes, {
      dek,
      kind: 'export',
      organizationId: org.id,
      subjectId: exportId,
    });
    const s3 = ctx.get(S3Service);
    const { PutObjectCommand } = createRequire(require.resolve('@email-gateway/common'))(
      '@aws-sdk/client-s3',
    ) as {
      PutObjectCommand: new (input: Record<string, unknown>) => object;
    };
    await s3.client.send(
      new PutObjectCommand({
        Bucket: s3.archiveBucket,
        Key: objectKey,
        Body: object.object,
        Tagging: 'eg-object=archive-export',
      }) as never,
    );
    await ctx.prisma.ediscoveryExport.update({
      where: { id: exportRow.id },
      data: {
        status: 'completed',
        objectKey,
        keyVersion: tenantKey.version,
        wrappedDek: wrapExportKey(
          tenantKey.key,
          { organizationId: org.id, exportPublicId: exportId, keyVersion: tenantKey.version },
          dek,
        ),
        packageBytes: BigInt(signed.bytes.length),
        packageSha256: signed.sha256,
        manifestSha256: signed.sha256,
        signingKeyId: ctx.config.ARCHIVE_EXPORT_SIGNING_PUBLIC_KEY_ID,
        expiresAt: new Date(Date.now() + 3_600_000),
        completedAt: new Date(),
      },
    });
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`${C}/${caseId}/exports/${exportId}`)).body.status,
        ARCHIVE_POLL,
      )
      .toBe('completed');
    expect(
      (await admin.get(`${C}/${caseId}/exports`)).body.data.map((e: { id: string }) => e.id),
    ).toContain(exportId);
    expect(
      (
        await apiKey.post(`${C}/${caseId}/exports/${exportId}/download-grants`, {
          password: user.password,
        })
      ).body.code,
    ).toBe('user_required');
    const grant = await admin.post(`${C}/${caseId}/exports/${exportId}/download-grants`, {
      password: user.password,
      totpCode: await fx.totpNow(user),
    });
    expect(grant.status, JSON.stringify(grant.body)).toBe(201);
    const download = await admin
      .get(`/api/v1/archive/downloads/${grant.body.token}`)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(download.status).toBe(200);
    const bytes = download.body as Buffer;
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(signed.sha256);
    // The manifest verifies against the published public key.
    const published = await admin.get('/api/v1/archive/export-signing-keys');
    const publicKey = parseExportSigningPublicKey(published.body.data[0].publicKey);
    expect(verifySignedExportManifest(bytes, signed.signature, publicKey)).toMatchObject({
      exportId,
      counts: { items: 1 },
    });
    expect((await audits('ediscovery.downloaded')).length).toBe(1);
    expect((await admin.get(`/api/v1/archive/downloads/${grant.body.token}`)).status).toBe(410);
  });
});
