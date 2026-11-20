/**
 * Step 8.6 changes of the existing archive routes (docs/plan/steps/27-journal-intake-and-archive-
 * split.md D7, D11, D12, §9.4; ADR-0089), over HTTP with the 8.1 `ArchiveWorld`: the role matrix
 * after the split (organization admins without archive access, `compliance_officer` with it,
 * read-only users without record detail), the per-path authorization of PUT /archive/settings,
 * the `ingestSource` search filter, the new list and detail fields (`ingestSources`, `intake`,
 * `mergedCopies`), the journal intake block of the journal view and the download of a stored
 * content variant (decrypted under the record's key and verified against its own SHA-256).
 */
import { createHash, randomUUID } from 'node:crypto';
import { JOURNAL_ENVELOPE_EXAMPLE } from '@email-gateway/archive';
import { SYSTEM_ROLES } from '@email-gateway/database';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import {
  ArchiveWorld,
  overrideArchive,
  RecordingAuditService,
  TEST_REAUTH_PASSWORD,
} from './support/archive-fixtures';

const BASE = '/api/v1/archive';
const DAY = 86_400_000;
const RANGE = (() => {
  const to = new Date(Date.now() + DAY).toISOString();
  const from = new Date(Date.now() - 30 * DAY).toISOString();
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`;
})();

const role = (key: string): string[] => [...SYSTEM_ROLES.find((r) => r.key === key)!.permissions];

describe('archive routes after the Journaling / Archive split (e2e, step 8.6)', () => {
  let api: StubbedApiApp;
  const world = new ArchiveWorld();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      { ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR: '1000' },
      { override: (b) => store.override(overrideArchive(b, world, audit)) },
    );
    org = api.principals.organizationId;
    world.rootKey = api.config;
  });

  afterAll(async () => {
    await api?.close();
  });

  const variantEml = Buffer.from(
    'From: sender@external.example\r\nTo: alice.recipient@corp.example\r\n' +
      'Subject: Quarterly report\r\n\r\nHello, the report is attached. [EXTERNAL banner]\r\n',
  );
  let gateway: string;
  let intake: string;
  let variantId: string;
  let sameBodyId: string;

  beforeEach(async () => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    const policy = world.addPolicy(org, { name: 'Seven years', retentionDays: 2555 });
    world.setSettings(org, {
      enabled: true,
      defaultRetentionPolicyId: policy.id,
      rowVersion: 2,
      settings: { access: { previewEnabled: true, downloadEnabled: true } },
    });
    variantId = randomUUID();
    sameBodyId = randomUUID();
    const g = await world.addRecord(org, {
      sourceJournalIntake: true,
      mergedCopies: [
        {
          messagePublicId: variantId,
          receivedAt: new Date(Date.now() - 3_500_000),
          source: 'journal_intake',
          eml: variantEml,
        },
        {
          messagePublicId: sameBodyId,
          receivedAt: new Date(Date.now() - 3_400_000),
          source: 'journal_intake',
          eml: null,
        },
      ],
    });
    gateway = g.record.messagePublicId;
    const sourceId = world.id();
    world.intakeSources.push({
      id: sourceId,
      organizationId: org,
      publicId: randomUUID(),
      displayName: 'Contoso Microsoft 365',
      kind: 'microsoft_365_journal',
    });
    const i = await world.addRecord(org, {
      sourceGateway: false,
      sourceJournalIntake: true,
      intakeSourceId: sourceId,
      intake: {
        sourceId: world.intakeSources[0]!.publicId,
        kind: 'microsoft_365_journal',
        format: 'journal_report',
        envelope: JOURNAL_ENVELOPE_EXAMPLE,
        envelopeMismatch: false,
        proof: {
          v: 1,
          network: 'provider_egress',
          tls: true,
          clientCert: 'n/a',
          tenantHeader: 'match',
          headerToken: 'n/a',
          dkim: { result: 'n/a', domains: [] },
          result: 'pass',
        },
      },
    });
    intake = i.record.messagePublicId;
  });

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  describe('the D12 role matrix of the record routes', () => {
    it('organization admins cannot search or read records; they read configuration', async () => {
      const auth = await asUser(role('organization_admin'));
      expect((await api.http().get(`${BASE}/messages?${RANGE}`).set(auth)).status).toBe(403);
      for (const path of [
        `${BASE}/messages/${gateway}`,
        `${BASE}/messages/${gateway}/journal`,
        `${BASE}/messages/${gateway}/security`,
      ]) {
        expect((await api.http().get(path).set(auth)).status, path).toBe(403);
      }
      expect(
        (
          await api
            .http()
            .post(`${BASE}/messages/${gateway}/reveal`)
            .set(auth)
            .send({
              fields: ['subject'],
            })
        ).status,
      ).toBe(403);
      expect((await api.http().get(`${BASE}/settings`).set(auth)).status).toBe(200);
      expect((await api.http().get(`${BASE}/status`).set(auth)).status).toBe(200);
    });

    it('compliance officers search, read and reveal records', async () => {
      const auth = await asUser(role('compliance_officer'));
      expect((await api.http().get(`${BASE}/messages?${RANGE}`).set(auth)).status).toBe(200);
      expect((await api.http().get(`${BASE}/messages/${gateway}`).set(auth)).status).toBe(200);
      expect((await api.http().get(`${BASE}/messages/${gateway}/journal`).set(auth)).status).toBe(
        200,
      );
      const reveal = await api
        .http()
        .post(`${BASE}/messages/${gateway}/reveal`)
        .set(auth)
        .send({ fields: ['subject'] });
      expect(reveal.status).toBe(200);
    });

    it('read-only users and platform admins keep configuration but lose record detail', async () => {
      for (const key of ['read_only_user', 'platform_admin']) {
        const auth = await asUser(role(key));
        expect((await api.http().get(`${BASE}/settings`).set(auth)).status, key).toBe(200);
        expect((await api.http().get(`${BASE}/messages/${gateway}`).set(auth)).status, key).toBe(
          403,
        );
      }
    });
  });

  describe('PUT /archive/settings per changed path (D11)', () => {
    const put = async (permissions: string[], body: object) =>
      api
        .http()
        .put(`${BASE}/settings`)
        .set(await asUser(permissions))
        .set('Idempotency-Key', randomUUID())
        .send({ expectedRowVersion: 2, ...body });

    it('journal:manage changes capture paths but not storage or access paths', async () => {
      const refused = await put(['journal:manage'], {
        immutability: 'governance',
        settings: { access: { previewEnabled: true, downloadEnabled: false } },
      });
      expect(refused.status).toBe(403);
      expect(refused.body).toMatchObject({
        code: 'archive_settings_forbidden_path',
        paths: [
          { path: 'immutability', permission: 'archive:manage' },
          { path: 'settings.access', permission: 'archive:manage' },
        ],
      });
      const ok = await put(['journal:manage'], {
        settings: {
          directions: { inbound: true, outbound: false, internal: false },
          access: { previewEnabled: true, downloadEnabled: true },
        },
      });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      const entry = audit.entries.find((e) => e.action === 'archive.settings_updated')!;
      expect(entry.metadata).toMatchObject({
        area: 'archive',
        settingsPaths: ['settings.directions'],
      });
    });

    it('archive:manage changes storage and access paths but cannot stop capture', async () => {
      const refused = await put(['archive:manage'], { enabled: false });
      expect(refused.status).toBe(403);
      expect(refused.body.paths).toEqual([{ path: 'enabled', permission: 'journal:manage' }]);
      const ok = await put(['archive:manage'], {
        settings: { access: { previewEnabled: false, downloadEnabled: true } },
      });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
    });

    it('without either permission the route answers 403 forbidden', async () => {
      const res = await put(['archive:read', 'journal:read'], { enabled: false });
      expect(res.status).toBe(403);
      expect(res.body.code).toBe('forbidden');
    });

    it('GET shows the intake scanning switch (default off)', async () => {
      const res = await api
        .http()
        .get(`${BASE}/settings`)
        .set(await asUser(['journal:read']));
      expect(res.body.settings.intake).toEqual({ scanEnabled: false });
    });
  });

  describe('sources, merged copies and variants (D7)', () => {
    const co = () => asUser([...role('compliance_officer'), 'archive:retrieve']);

    it('search filters on ingestSource and lists ingestSources', async () => {
      const auth = await co();
      const res = await api
        .http()
        .get(`${BASE}/messages?${RANGE}&ingestSource=journal_intake`)
        .set(auth);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(JSON.stringify(world.searchCalls.at(-1)!.body)).toContain(
        '"ingest_sources":"journal_intake"',
      );
      const byId = new Map(
        (res.body.data as Array<{ messageId: string; ingestSources: string[] }>).map((d) => [
          d.messageId,
          d.ingestSources,
        ]),
      );
      expect(byId.get(gateway)).toEqual(['gateway', 'journal_intake']);
      expect(byId.get(intake)).toEqual(['journal_intake']);
      const bad = await api.http().get(`${BASE}/messages?${RANGE}&ingestSource=imap`).set(auth);
      expect(bad.status).toBe(400);
      // The 8.1 capture-source filter keeps its meaning.
      const capture = await api.http().get(`${BASE}/messages?${RANGE}&source=journal`).set(auth);
      expect(capture.status).toBe(200);
    });

    it('detail lists the merged copies and the intake source of an intake record', async () => {
      const auth = await co();
      const g = await api.http().get(`${BASE}/messages/${gateway}`).set(auth);
      expect(g.body).toMatchObject({ ingestSources: ['gateway', 'journal_intake'], intake: null });
      expect(g.body.mergedCopies).toEqual([
        expect.objectContaining({
          id: variantId,
          source: 'journal_intake',
          contentVariant: true,
          sha256: createHash('sha256').update(variantEml).digest('hex'),
        }),
        expect.objectContaining({ id: sameBodyId, contentVariant: false }),
      ]);
      const i = await api.http().get(`${BASE}/messages/${intake}`).set(auth);
      expect(i.body).toMatchObject({
        ingestSources: ['journal_intake'],
        intake: {
          sourceId: world.intakeSources[0]!.publicId,
          sourceDisplayName: 'Contoso Microsoft 365',
          kind: 'microsoft_365_journal',
        },
        mergedCopies: [],
      });
    });

    it('the journal view of an intake record shows the envelope fields (masked) and proof codes', async () => {
      const auth = await co();
      const res = await api.http().get(`${BASE}/messages/${intake}/journal`).set(auth);
      expect(res.status).toBe(200);
      expect(res.body.intake).toMatchObject({
        kind: 'microsoft_365_journal',
        format: 'journal_report',
        envelope: {
          sender: 'alice@example.com',
          truncated: false,
          recipients: expect.arrayContaining([
            { address: 'd***@example.com', field: 'bcc' },
            { address: 'e***@example.com', field: 'to', expandedFrom: 't***@example.com' },
          ]),
        },
        proof: { network: 'provider_egress', tenantHeader: 'match', dkim: 'n/a' },
      });
      expect(JSON.stringify(res.body)).not.toContain('dave@example.com');
      const g = await api.http().get(`${BASE}/messages/${gateway}/journal`).set(auth);
      expect(g.body.intake).toBeNull();
    });

    it('downloads a stored content variant, verified against its own SHA-256', async () => {
      const auth = await co();
      const unknown = await api
        .http()
        .post(`${BASE}/messages/${gateway}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD, variant: sameBodyId });
      expect(unknown.status).toBe(404);
      expect(unknown.body.code).toBe('archive_variant_not_found');
      const grant = await api
        .http()
        .post(`${BASE}/messages/${gateway}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD, variant: variantId });
      expect(grant.status, JSON.stringify(grant.body)).toBe(201);
      expect(grant.body).toMatchObject({
        filename: `message-${gateway}.variant-${variantId}.eml`,
        sizeBytes: variantEml.length,
        sha256: createHash('sha256').update(variantEml).digest('hex'),
      });
      const download = await api
        .http()
        .get(`${BASE}/downloads/${grant.body.token}`)
        .set(auth)
        .buffer(true)
        .parse((res, cb) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => cb(null, Buffer.concat(chunks)));
        });
      expect(download.status).toBe(200);
      expect(Buffer.compare(download.body as Buffer, variantEml)).toBe(0);
      expect(audit.entries.find((e) => e.action === 'archive.downloaded')!.metadata).toMatchObject({
        messageId: gateway,
        variantId,
      });
      // The primary copy still downloads as before.
      const primary = await api
        .http()
        .post(`${BASE}/messages/${gateway}/download-grants`)
        .set(auth)
        .send({ password: TEST_REAUTH_PASSWORD });
      expect(primary.body.filename).toBe(`message-${gateway}.eml`);
    });
  });
});
