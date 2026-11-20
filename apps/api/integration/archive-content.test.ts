/**
 * Archived message search and content against the real writer and replica, MinIO and OpenSearch
 * (step 8.1 §9.3): records seeded through `@email-gateway/archive` (objects encrypted into the
 * archive bucket, rows on the writer, documents indexed into this run's index prefix behind the
 * tenant's filtered alias). Search through the alias with masking and the reveal-gated filters;
 * detail, journal and frozen security decrypted from MinIO; the reveal audited before values;
 * the sanitized preview; a grant → single-use download whose bytes hash to the original;
 * disposal of a reviewed record and the writer re-check that refuses its content while the
 * replica still shows it; audit rows carry no values.
 */
// @covers get /api/v1/archive/messages
// @covers get /api/v1/archive/messages/:messageId
// @covers get /api/v1/archive/messages/:messageId/journal
// @covers get /api/v1/archive/messages/:messageId/security
// @covers post /api/v1/archive/messages/:messageId/reveal
// @covers get /api/v1/archive/messages/:messageId/preview
// @covers post /api/v1/archive/messages/:messageId/download-grants
// @covers get /api/v1/archive/downloads/:token
// @covers post /api/v1/archive/messages/:messageId/dispose
import { createHash, randomUUID } from 'node:crypto';
import { disposalObjectsOf, readDisposalObjects } from '@email-gateway/archive';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
import type { SeededRecord } from '../test/support/archive-seed';

const BASE = '/api/v1/archive';
const DAY = 86_400_000;
const RANGE = `from=${encodeURIComponent(new Date(Date.now() - 30 * DAY).toISOString())}&to=${encodeURIComponent(new Date(Date.now() + DAY).toISOString())}`;
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

let ctx: IntegrationApp;
let fx: Fixtures;
let ax: ArchiveFixtures;
let org: FixtureOrganization;
let user: FixtureUser;
let admin: ArchiveHttp;
let searcher: ArchiveHttp;
let report: SeededRecord;
let review: SeededRecord;

beforeAll(async () => {
  ctx = await createIntegrationApp({ ARCHIVE_SEARCH_INDEX_PREFIX: testIndexPrefix() });
  fx = createFixtures(ctx);
  ax = new ArchiveFixtures(ctx, ctx.config.ARCHIVE_SEARCH_INDEX_PREFIX);
  fx.registerCleanup(() => ax.cleanup());
  org = await fx.createOrganization({ planCode: 'enterprise' });
  // Step 8.6 (ADR-0089): an organization admin as migrated (archive access through compliance_officer).
  user = await fx.createUser(org, {
    roles: ['organization_admin', 'compliance_officer'],
    mfa: true,
  });
  admin = archiveHttp(ctx, bearer((await loginWithMfa(ctx, fx, user)).accessToken));
  searcher = archiveHttp(
    ctx,
    apiKeyHeader(await fx.createApiKey(org, ['archive:search', 'archive:read'])),
  );
  await ax.settings(org, { settings: { access: { previewEnabled: true, downloadEnabled: true } } });
  report = await ax.record(org, {
    subject: 'Quarterly report',
    recipients: ['alice.recipient@corp.example'],
    attachments: [
      { partIndex: 2, fileName: 'report.pdf', sha256: 'b'.repeat(64), sizeBytes: 1024 },
    ],
  });
  review = await ax.record(org, {
    status: 'expiry_review',
    receivedAt: new Date(Date.now() - 2 * DAY),
    retainUntil: new Date(Date.now() - DAY),
    subject: 'Old notice',
  });
}, 180_000);

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
}, 180_000);

const audits = (action: string) =>
  ctx.prisma.auditLog.findMany({
    where: { organizationId: org.id, action },
    orderBy: { id: 'asc' },
  });

describe('search through the tenant alias', () => {
  it('returns the organization’s masked records with the lag header; the first page is audited', async () => {
    const res = await searcher.get(`${BASE}/messages?${RANGE}&limit=1`);
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.headers['x-eg-index-lag-seconds']).toBe('0');
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0]).toMatchObject({
      messageId: report.row.messagePublicId,
      subject: null,
      subjectMasked: true,
      recipients: ['a***@corp.example'],
      attachmentNames: ['report.pdf'],
    });
    const next = await searcher.get(
      `${BASE}/messages?${RANGE}&limit=1&cursor=${encodeURIComponent(res.body.nextCursor)}`,
    );
    expect(next.body.data[0].messageId).toBe(review.row.messagePublicId);
    expect(await audits('archive.searched')).toHaveLength(1);
    const filtered = await searcher.get(
      `${BASE}/messages?${RANGE}&senderDomain=external.example&hasAttachments=true`,
    );
    expect(filtered.body.data.map((m: { messageId: string }) => m.messageId)).toEqual([
      report.row.messagePublicId,
    ]);
  });

  it('reveal-gated filters need message:reveal; with it the subject filter matches', async () => {
    const forbidden = await searcher.get(`${BASE}/messages?${RANGE}&subject=Quarterly`);
    expect(forbidden.status).toBe(403);
    expect(forbidden.body).toMatchObject({ code: 'archive_filter_forbidden', filter: 'subject' });
    const res = await admin.get(`${BASE}/messages?${RANGE}&subject=Quarterly`);
    expect(res.status).toBe(200);
    expect(res.body.data.map((m: { messageId: string }) => m.messageId)).toEqual([
      report.row.messagePublicId,
    ]);
    const last = (await audits('archive.searched')).at(-1)!;
    expect(JSON.stringify(last.metadata)).not.toContain('Quarterly');
    expect(last.metadata).toMatchObject({ filterNames: expect.arrayContaining(['subject']) });
  });
});

describe('detail and content (writer re-check, audit before content)', () => {
  it('detail, journal and security decrypt from MinIO and stay masked', async () => {
    await expect
      .poll(
        async (): Promise<unknown> =>
          (await admin.get(`${BASE}/messages/${report.row.messagePublicId}`)).status,
        ARCHIVE_POLL,
      )
      .toBe(200);
    const detail = await admin.get(`${BASE}/messages/${report.row.messagePublicId}`);
    expect(detail.body).toMatchObject({
      subject: null,
      integrity: { sha256: report.row.sha256 },
      holds: [],
    });
    const journal = await admin.get(`${BASE}/messages/${report.row.messagePublicId}/journal`);
    expect(journal.status).toBe(200);
    expect(journal.body.envelope.recipients[0].address).toBe('a***@corp.example');
    expect(journal.body.headers).toEqual(
      expect.arrayContaining([{ name: 'Subject', value: null, masked: true }]),
    );
    const security = await admin.get(`${BASE}/messages/${report.row.messagePublicId}/security`);
    expect(security.status).toBe(200);
    expect(security.body.rounds[0]).toMatchObject({ round: 1, scan: { verdict: 'clean' } });
    expect(security.body.rounds[0].scan.engines[0]).toMatchObject({
      engine: 'rspamd',
      score: 1.5,
      requiredScore: 15,
    });
    for (const action of [
      'archive.message_viewed',
      'archive.journal_viewed',
      'archive.security_viewed',
    ]) {
      expect((await audits(action)).length, action).toBeGreaterThan(0);
    }
  });

  it('reveal returns the clear values after its audit row (fields and counts only)', async () => {
    const res = await admin.post(`${BASE}/messages/${report.row.messagePublicId}/reveal`, {
      fields: ['subject', 'recipients', 'headers'],
    });
    expect(res.body).toMatchObject({
      subject: 'Quarterly report',
      recipients: [{ seq: 0, address: 'alice.recipient@corp.example' }],
    });
    const [entry] = await audits('archive.revealed');
    expect(entry?.metadata).toMatchObject({
      fields: ['headers', 'recipients', 'subject'],
      recipientCount: 1,
    });
    expect(JSON.stringify(entry?.metadata)).not.toMatch(/Quarterly|alice/);
  });

  it('preview is sanitized JSON from the journal object', async () => {
    const res = await admin.get(`${BASE}/messages/${report.row.messagePublicId}/preview`);
    expect(res.status).toBe(200);
    expect(res.body.version).toBe('preview/1');
    expect(res.body.body.text).toContain('Hello, the report is attached');
    expect(res.body.attachments[0]).toMatchObject({
      filename: 'report.pdf',
      verdict: 'clean',
      downloadable: false,
    });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(await audits('archive.previewed')).toHaveLength(1);
  });

  it('grant → single-use download streams the original whose SHA-256 matches', async () => {
    const wrong = await admin.post(
      `${BASE}/messages/${report.row.messagePublicId}/download-grants`,
      { password: 'wrong-password', totpCode: await fx.totpNow(user) },
    );
    expect(wrong.body.code).toBe('quarantine_reauth_failed');
    const grant = await admin.post(
      `${BASE}/messages/${report.row.messagePublicId}/download-grants`,
      {
        password: user.password,
        totpCode: await fx.totpNow(user),
      },
    );
    expect(grant.status, JSON.stringify(grant.body)).toBe(201);
    const row = await ctx.prisma.archiveDownloadGrant.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    expect(row).toMatchObject({ kind: 'message', userId: user.id, consumedAt: null });
    const download = await admin
      .get(`${BASE}/downloads/${grant.body.token}`)
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on('data', (c: Buffer) => chunks.push(c));
        r.on('end', () => cb(null, Buffer.concat(chunks)));
      });
    expect(download.status).toBe(200);
    expect(sha(download.body as Buffer)).toBe(report.row.sha256);
    expect((download.body as Buffer).equals(report.eml)).toBe(true);
    expect(download.headers['content-disposition']).toContain('attachment;');
    const again = await admin.get(`${BASE}/downloads/${grant.body.token}`);
    expect(again.status).toBe(410);
    const consumed = await ctx.prisma.archiveDownloadGrant.findFirstOrThrow({
      where: { organizationId: org.id },
    });
    expect(consumed.consumedAt).not.toBeNull();
    const [downloaded] = await audits('archive.downloaded');
    expect(downloaded?.metadata).toMatchObject({ sha256: report.row.sha256 });
    expect(
      JSON.stringify((await audits('archive.download_granted')).map((a) => a.metadata)),
    ).not.toContain(grant.body.token);
  });
});

describe('disposal of a reviewed record and the writer re-check', () => {
  it('crypto-shreds on the writer; content is refused even before the replica catches up', async () => {
    const res = await admin.post(
      `${BASE}/messages/${review.row.messagePublicId}/dispose`,
      { reason: 'Reviewed' },
      `it-${randomUUID()}`,
    );
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const row = await ctx.prisma.emailArchive.findFirstOrThrow({
      where: { organizationId: org.id, messageId: review.row.messageId },
    });
    expect(row).toMatchObject({ status: 'disposing', wrappedDek: null });
    expect(row.deletedAt).not.toBeNull();
    const disposal = await ctx.prisma.archiveDisposal.findFirstOrThrow({
      where: { organizationId: org.id, messageId: review.row.messageId },
    });
    expect(disposal).toMatchObject({
      reason: 'review_disposed',
      state: 'shredded',
      sha256: review.row.sha256,
    });
    // The lifecycle pipeline's shape (prefix + exact versions), not the record's objects column.
    const ids = {
      organizationId: org.id,
      receivedAt: review.row.receivedAt,
      messagePublicId: review.row.messagePublicId,
    };
    expect(readDisposalObjects(disposal.objects, ids).shape).toBe('disposal');
    expect(disposal.objects).toEqual(disposalObjectsOf({ ...ids, objects: review.row.objects }));
    expect(disposal.replicaStatus).toEqual({ targets: [], pending: [] });
    expect(
      await ctx.prisma.archiveIndexQueue.count({ where: { organizationId: org.id, op: 'delete' } }),
    ).toBe(1);
    for (const path of ['journal', 'security', 'preview']) {
      const content = await admin.get(`${BASE}/messages/${review.row.messagePublicId}/${path}`);
      expect(content.status, path).toBe(410);
      expect(content.body.code).toBe('archive_content_unavailable');
    }
    // Simulate a replica that still shows the record active: the content route must still refuse.
    await ctx.prisma.emailArchive.updateMany({
      where: { organizationId: org.id, messageId: report.row.messageId },
      data: { status: 'disposing', wrappedDek: null },
    });
    const stale = await admin.get(`${BASE}/messages/${report.row.messagePublicId}/journal`);
    expect(stale.status).toBe(410);
    const lag = await searcher.get(`${BASE}/messages?${RANGE}`);
    expect(Number(lag.headers['x-eg-index-lag-seconds'])).toBeGreaterThanOrEqual(0);
  });
});
