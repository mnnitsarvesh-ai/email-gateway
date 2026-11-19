/**
 * Tenant isolation of the step 8.4 security incident routes against the real writer and replica
 * (docs/plan/steps/24-account-takeover-core.md §5.2, D17, §10.4): organization A's users and API
 * keys calling every incident route with organization B's incident ids get 404
 * `incident_not_found` (like an unknown id), B's accounts cannot be the subject of A's manual
 * incident, A's lists never include B's incidents, and nothing of B changes. A principal
 * holding no read permission of the incident's category (here a custom role with an unrelated
 * permission) is refused by the guard; the category filtering itself is covered with a second,
 * test-registered category in test/incidents.e2e.test.ts.
 */
// @covers get /api/v1/incidents
// @covers post /api/v1/incidents
// @covers get /api/v1/incidents/:incidentId
// @covers patch /api/v1/incidents/:incidentId
// @covers post /api/v1/incidents/:incidentId/notes
// @covers get /api/v1/incidents/:incidentId/timeline
// @covers get /api/v1/incidents/:incidentId/messages
// @covers get /api/v1/incidents/:incidentId/report
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { createFixtures, type Fixtures } from './support/fixtures';
import { bearer, idem, loginWithMfa } from './support/http';

const BASE = '/api/v1/incidents';
let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;
let a: { t: AtoTenant; incident: string };
let b: { t: AtoTenant; incident: string; account: string };

beforeAll(async () => {
  ctx = await createIntegrationApp();
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  const ta = await seed.tenant();
  const tb = await seed.tenant();
  a = { t: ta, incident: (await seed.compromised(ta.org.id)).incident.publicId };
  const bb = await seed.compromised(tb.org.id);
  b = { t: tb, incident: bb.incident.publicId, account: (await seed.mailbox(tb.org.id)).publicId };
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const snapshotB = async () =>
  JSON.stringify(
    {
      incidents: await ctx.prisma.securityIncident.findMany({
        where: { organizationId: b.t.org.id },
        orderBy: { id: 'asc' },
      }),
      events: await ctx.prisma.securityIncidentEvent.count({
        where: { organizationId: b.t.org.id },
      }),
    },
    (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
  );

describe('organization A never reaches organization B’s incidents', () => {
  it('every route with B’s incident id answers 404 incident_not_found; nothing of B changes', async () => {
    const before = await snapshotB();
    for (const auth of [a.t.analystAuth, a.t.apiKey]) {
      for (const path of ['', '/timeline', '/messages', '/report']) {
        const res = await ctx.http.get(`${BASE}/${b.incident}${path}`).set(auth);
        expect(res.status, path).toBe(404);
        expect(res.body.code).toBe('incident_not_found');
      }
      const patch = await ctx.http
        .patch(`${BASE}/${b.incident}`)
        .set(auth)
        .set(idem())
        .send({ expectedRowVersion: 1, status: 'investigating' });
      expect(patch.status).toBe(404);
      expect(patch.body.code).toBe('incident_not_found');
      const note = await ctx.http
        .post(`${BASE}/${b.incident}/notes`)
        .set(auth)
        .set(idem())
        .send({ note: 'cross-tenant' });
      expect(note.status).toBe(404);
      const create = await ctx.http
        .post(BASE)
        .set(auth)
        .set(idem())
        .send({
          category: 'account_takeover',
          subject: { type: 'ato_account', id: b.account },
          reason: 'Cross-tenant subject attempt',
        });
      expect(create.status).toBe(404);
      expect(create.body.code).toBe('incident_subject_not_found');
    }
    expect(await snapshotB()).toBe(before);
  });

  it('A’s list and filters never include B’s incidents', async () => {
    const list = await ctx.http.get(`${BASE}?limit=100`).set(a.t.analystAuth);
    const ids = list.body.data.map((i: { id: string }) => i.id);
    expect(ids).toContain(a.incident);
    expect(ids).not.toContain(b.incident);
    const bySubject = await ctx.http.get(`${BASE}?subjectId=${b.account}`).set(a.t.analystAuth);
    expect(bySubject.body).toEqual({ data: [], nextCursor: null });
  });

  it('a principal without any category read permission is refused', async () => {
    const role = await fx.createCustomRole(a.t.org, ['message:read']);
    const user = await fx.createUser(a.t.org, { roles: [role] });
    const auth = bearer((await loginWithMfa(ctx, fx, user)).accessToken);
    const res = await ctx.http.get(`${BASE}/${a.incident}`).set(auth);
    expect(res.status).toBe(403);
    const list = await ctx.http.get(BASE).set(auth);
    expect(list.status).toBe(403);
  });
});
