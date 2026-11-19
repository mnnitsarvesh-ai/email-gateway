/**
 * The generic security incident routes of step 8.4 against the real writer, replica and Redis
 * (docs/plan/steps/24-account-takeover-core.md §5.2, D12, D24, §10.4): ATO incidents opened by
 * the store's incident policy and manually through the API; transitions under the row lock with
 * CAS (409), refused transitions (422 with the reason), assignment, severity, notes, the
 * false-positive feedback (signals dismissed, trusted contexts added, account rescored) through
 * PATCH, the timeline, linked messages and the audited report, the events and audit rows the
 * shared store writes, the feature gate, and the list plans at volume (≥ 10 000 incidents for
 * one organization).
 */
// @covers get /api/v1/incidents
// @covers post /api/v1/incidents
// @covers get /api/v1/incidents/:incidentId
// @covers patch /api/v1/incidents/:incidentId
// @covers post /api/v1/incidents/:incidentId/notes
// @covers get /api/v1/incidents/:incidentId/timeline
// @covers get /api/v1/incidents/:incidentId/messages
// @covers get /api/v1/incidents/:incidentId/report
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIntegrationApp, type IntegrationApp } from './support/app';
import { AtoSeeder, type AtoTenant } from './support/ato';
import { createFixtures, type Fixtures } from './support/fixtures';
import { idem } from './support/http';

const BASE = '/api/v1/incidents';
let ctx: IntegrationApp;
let fx: Fixtures;
let seed: AtoSeeder;
let t: AtoTenant;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function eventually<T extends { body: unknown }>(
  call: () => Promise<T>,
  ok: (res: T) => boolean,
): Promise<T> {
  let last: T | undefined;
  for (let i = 0; i < 50; i += 1) {
    last = await call();
    if (ok(last)) return last;
    await sleep(200);
  }
  return last!;
}

beforeAll(async () => {
  ctx = await createIntegrationApp({ API_ATO_REPORT_MAX_ITEMS: '5' });
  fx = createFixtures(ctx);
  seed = new AtoSeeder(ctx, fx);
  t = await seed.tenant();
});

afterAll(async () => {
  await fx?.cleanup();
  await ctx?.close();
});

const get = (path: string, auth = t.analystAuth) => ctx.http.get(path).set(auth);
const patch = (id: string, body: object, auth = t.analystAuth) =>
  ctx.http.patch(`${BASE}/${id}`).set(auth).set(idem()).send(body);
const version = async (id: string) =>
  (await ctx.prisma.securityIncident.findUniqueOrThrow({ where: { publicId: id } })).rowVersion;

describe('incidents opened by detection', () => {
  it('list, detail with the ATO detail, timeline and report (audited)', async () => {
    const { incident, account } = await seed.compromised(t.org.id);
    const list = await eventually(
      () => get(`${BASE}?category=account_takeover`),
      (r) =>
        (r.body as { data: Array<{ id: string }> }).data?.some((i) => i.id === incident.publicId),
    );
    const item = list.body.data.find((i: { id: string }) => i.id === incident.publicId);
    expect(item).toMatchObject({
      category: 'account_takeover',
      origin: 'detection',
      subject: { type: 'ato_account', id: account.publicId, display: account.address },
    });
    const detail = await get(`${BASE}/${incident.publicId}`);
    expect(detail.status).toBe(200);
    expect(detail.body).toMatchObject({ canManage: true, status: 'open' });
    expect(detail.body.detail.account).toMatchObject({
      id: account.publicId,
      kind: 'mailbox',
      userId: null,
      connectorId: null,
    });
    expect(detail.body.detail.detectionReasonText.length).toBeGreaterThan(0);
    expect(detail.body.detail.responses).toMatchObject({ total: expect.any(Number) });
    expect(detail.body.evidence.ato_signal).toBeGreaterThan(0);
    const auditorView = await get(`${BASE}/${incident.publicId}`, t.auditorAuth);
    expect(auditorView.body).toMatchObject({ canManage: false, allowedTransitions: [] });
    const timeline = await get(`${BASE}/${incident.publicId}/timeline`);
    expect(timeline.body.data[0].type).toBe('created');
    const report = await get(`${BASE}/${incident.publicId}/report`, t.auditorAuth);
    expect(report.status).toBe(200);
    expect(report.body.version).toBe('security-incident-report/1');
    expect(report.body.sections.map((s: { id: string }) => s.id)).toEqual(
      expect.arrayContaining(['ato.detection', 'ato.signals', 'ato.responses']),
    );
    const exported = await ctx.prisma.auditLog.count({
      where: {
        organizationId: t.org.id,
        action: 'security_incident.report_exported',
        resourceId: incident.publicId,
      },
    });
    expect(exported).toBe(1);
    const messages = await get(`${BASE}/${incident.publicId}/messages`);
    expect(messages.body).toEqual({ data: [], nextCursor: null });
  });

  it('transitions: CAS, refused edges with reasons, confirm/mitigate/resolve; events and audit rows', async () => {
    const { incident } = await seed.compromised(t.org.id);
    const id = incident.publicId;
    const stale = await patch(id, { expectedRowVersion: 99, status: 'investigating' });
    expect(stale.status).toBe(409);
    expect(stale.body.code).toBe('incident_conflict');
    const refused = await patch(id, { expectedRowVersion: await version(id), status: 'mitigated' });
    expect(refused.body).toMatchObject({
      code: 'incident_transition_invalid',
      reason: 'transition_not_allowed',
    });
    const assignee = t.analyst2;
    const confirm = await patch(id, {
      expectedRowVersion: await version(id),
      status: 'confirmed',
      note: 'Confirmed with the user by phone.',
      assigneeId: assignee.publicId,
      severity: 'critical',
    });
    expect(confirm.status, JSON.stringify(confirm.body)).toBe(200);
    expect(confirm.body).toMatchObject({
      status: 'confirmed',
      severity: 'critical',
      assigneeId: assignee.publicId,
    });
    // The list is a replica read (§5.2): wait for the assignment to replicate.
    const mine = await eventually(
      () => get(`${BASE}?assignee=me`, t.analyst2Auth),
      (r) => (r.body as { data?: { id: string }[] }).data?.some((i) => i.id === id) ?? false,
    );
    expect(mine.body.data.map((i: { id: string }) => i.id)).toContain(id);
    const mitigate = await patch(id, {
      expectedRowVersion: await version(id),
      status: 'mitigated',
    });
    expect(mitigate.body.status).toBe('mitigated');
    const resolve = await patch(id, {
      expectedRowVersion: await version(id),
      status: 'resolved',
      resolution: { code: 'remediated', note: 'Password reset and sessions revoked.' },
    });
    expect(resolve.body).toMatchObject({ status: 'resolved', resolution: { code: 'remediated' } });
    const closed = await patch(id, { expectedRowVersion: await version(id), assigneeId: null });
    expect(closed.status).toBe(409);
    expect(closed.body.code).toBe('incident_closed');
    const events = await ctx.prisma.messageOutbox.count({
      where: {
        organizationId: t.org.id,
        eventType: 'security.incident.updated.v1',
        aggregateId: incident.id.toString(),
      },
    });
    expect(events).toBeGreaterThanOrEqual(4);
    const audit = await ctx.prisma.auditLog.count({
      where: {
        organizationId: t.org.id,
        resourceId: id,
        action: 'security_incident.status_changed',
      },
    });
    expect(audit).toBe(3);
    const account = await ctx.prisma.atoAccount.findUniqueOrThrow({
      where: { id: incident.subjectRefId },
    });
    expect(account.activeIncidentId).toBeNull();
  });

  it('false positive through PATCH: signals dismissed, trusted contexts added, account rescored', async () => {
    const { incident, account } = await seed.compromised(t.org.id);
    const before = await ctx.prisma.atoAccount.findUniqueOrThrow({ where: { id: account.id } });
    const res = await patch(incident.publicId, {
      expectedRowVersion: await version(incident.publicId),
      status: 'false_positive',
      resolution: { code: 'benign_activity', note: 'Confirmed business trip to Frankfurt.' },
      categoryFeedback: {
        trustedContexts: [
          { kind: 'country', value: 'DE', expiresInDays: 30, reason: 'Business trip' },
        ],
        dismissSignals: true,
      },
    });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const signals = await ctx.prisma.atoRiskSignal.findMany({
      where: { organizationId: t.org.id, incidentId: incident.id },
    });
    expect(signals.length).toBeGreaterThan(0);
    expect(signals.every((s) => s.status === 'dismissed')).toBe(true);
    const contexts = await ctx.prisma.atoTrustedContext.findMany({
      where: { accountId: account.id },
    });
    expect(contexts.map((c) => [c.kind, c.value, c.source])).toEqual([
      ['country', 'DE', 'false_positive_feedback'],
    ]);
    const after = await ctx.prisma.atoAccount.findUniqueOrThrow({ where: { id: account.id } });
    expect(after.riskScore).toBeLessThan(before.riskScore);
    const invalid = await seed.compromised(t.org.id);
    const bad = await patch(invalid.incident.publicId, {
      expectedRowVersion: await version(invalid.incident.publicId),
      status: 'false_positive',
      resolution: { code: 'false_positive', note: 'Not a compromise at all.' },
      categoryFeedback: {
        trustedContexts: [{ kind: 'ip_cidr', value: '10.0.0.0/2', expiresInDays: 3, reason: 'x' }],
      },
    });
    expect(bad.status).toBe(422);
  });
});

describe('manual incidents and notes', () => {
  it('opens one active incident per account; notes are audited by length', async () => {
    const account = await seed.mailbox(t.org.id);
    const created = await ctx.http
      .post(BASE)
      .set(t.apiKey)
      .set(idem())
      .send({
        category: 'account_takeover',
        subject: { type: 'ato_account', id: account.publicId },
        severity: 'high',
        reason: 'User reported sign-in prompts they did not start',
      });
    expect(created.status, JSON.stringify(created.body)).toBe(201);
    expect(created.body).toMatchObject({
      origin: 'manual',
      status: 'open',
      severity: 'high',
      createdBy: { type: 'api_key' },
    });
    const detail = await ctx.prisma.atoIncidentDetail.findUnique({
      where: {
        incidentId: (
          await ctx.prisma.securityIncident.findUniqueOrThrow({
            where: { publicId: created.body.id },
          })
        ).id,
      },
    });
    expect(detail).not.toBeNull();
    const again = await ctx.http
      .post(BASE)
      .set(t.analystAuth)
      .set(idem())
      .send({
        category: 'account_takeover',
        subject: { type: 'ato_account', id: account.publicId },
        reason: 'Second report of the same account',
      });
    expect(again.status).toBe(409);
    expect(again.body).toMatchObject({ code: 'incident_active', incidentId: created.body.id });
    const unknown = await ctx.http
      .post(BASE)
      .set(t.analystAuth)
      .set(idem())
      .send({
        category: 'account_takeover',
        subject: { type: 'ato_account', id: randomUUID() },
        reason: 'Unknown account report',
      });
    expect(unknown.body.code).toBe('incident_subject_not_found');
    const note = await ctx.http
      .post(`${BASE}/${created.body.id}/notes`)
      .set(t.analystAuth)
      .set(idem())
      .send({ note: 'Called the user; not travelling.' });
    expect(note.status).toBe(201);
    expect(note.body).toMatchObject({
      type: 'note_added',
      actor: { type: 'user', id: t.analyst.publicId },
    });
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: {
        organizationId: t.org.id,
        action: 'security_incident.note_added',
        resourceId: created.body.id,
      },
    });
    expect(JSON.stringify(audit.metadata)).not.toContain('travelling');
    const auditor = await ctx.http
      .post(`${BASE}/${created.body.id}/notes`)
      .set(t.auditorAuth)
      .set(idem())
      .send({ note: 'not allowed' });
    expect(auditor.status).toBe(403);
  });

  it('feature off: incidents vanish from reads; mutations are 403 ato_not_enabled', async () => {
    const off = await seed.tenant();
    const { incident } = await seed.compromised(off.org.id);
    await seed.setFeature(off.org.id, false);
    const list = await get(BASE, off.analystAuth);
    expect(list.body).toEqual({ data: [], nextCursor: null });
    expect((await get(`${BASE}/${incident.publicId}`, off.analystAuth)).status).toBe(404);
    const res = await patch(
      incident.publicId,
      { expectedRowVersion: 1, status: 'investigating' },
      off.analystAuth,
    );
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('ato_not_enabled');
  });
});

describe('query plans at volume (Agent 3)', () => {
  it('the incident lists use their indexes with ≥ 10 000 incidents for one organization', async () => {
    const vol = await seed.tenant();
    const account = await seed.mailbox(vol.org.id);
    const d =
      '(SELECT 0 i UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9)';
    await ctx.prisma.$executeRawUnsafe(`
      INSERT INTO security_incidents (public_id, organization_id, category, subject_type, subject_ref_id, subject_public_id, origin, status, severity, reason_codes, detected_at, created_by_type, updated_at)
      SELECT UUID(), ${vol.org.id}, 'account_takeover', 'ato_account', ${account.id} + n, '${account.publicId}', 'detection', ELT(1 + n % 3, 'resolved', 'false_positive', 'resolved'), ELT(1 + n % 4, 'low', 'medium', 'high', 'critical'), JSON_ARRAY(), NOW(3) - INTERVAL n MINUTE, 'system', NOW(3)
      FROM (SELECT a.i + b.i * 10 + c.i * 100 + e.i * 1000 + f.i * 10000 AS n FROM ${d} a, ${d} b, ${d} c, ${d} e, ${d} f) seq WHERE n < 12000`);
    expect(
      await ctx.prisma.securityIncident.count({ where: { organizationId: vol.org.id } }),
    ).toBeGreaterThanOrEqual(10_000);
    await ctx.prisma.$queryRawUnsafe(
      'ANALYZE TABLE security_incidents, security_incident_events, security_incident_links',
    );
    const explain = async (sql: string) => {
      const rows = await ctx.prisma.$queryRawUnsafe<Array<Record<string, unknown>>>(
        `EXPLAIN ${sql}`,
      );
      return rows.map((r) => {
        const v = Object.values(r);
        return {
          type: String(v[4]),
          key: String((v[6] as string | null) ?? ''),
          rows: Number(v[9]),
          extra: String((v[11] as string | null) ?? ''),
        };
      });
    };
    const o = vol.org.id;
    const plans = {
      byDetection: await explain(
        `SELECT id FROM security_incidents WHERE organization_id = ${o} ORDER BY detected_at DESC, id DESC LIMIT 26`,
      ),
      byStatus: await explain(
        `SELECT id FROM security_incidents WHERE organization_id = ${o} AND category = 'account_takeover' AND status = 'open' ORDER BY detected_at DESC, id DESC LIMIT 26`,
      ),
      bySeverity: await explain(
        `SELECT id FROM security_incidents WHERE organization_id = ${o} AND category = 'account_takeover' AND severity = 'critical' ORDER BY detected_at DESC, id DESC LIMIT 26`,
      ),
      assigned: await explain(
        `SELECT id FROM security_incidents WHERE organization_id = ${o} AND assigned_user_id = 1 AND status = 'open'`,
      ),
      timeline: await explain(
        `SELECT id FROM security_incident_events WHERE incident_id = 1 ORDER BY created_at, id LIMIT 26`,
      ),
      links: await explain(
        `SELECT ref_id FROM security_incident_links WHERE organization_id = ${o} AND incident_id = 1 AND link_type = 'message' ORDER BY ref_time DESC, ref_id DESC LIMIT 26`,
      ),
    };
    for (const [name, plan] of Object.entries(plans)) {
      expect(plan[0]!.type, name).not.toBe('ALL');
      expect(plan[0]!.key, name).not.toBe('');
    }
    for (const name of ['byDetection', 'byStatus', 'bySeverity'] as const) {
      expect(plans[name][0]!.extra, name).not.toMatch(/filesort/);
    }
    const started = Date.now();
    const page = await eventually(
      () => get(`${BASE}?limit=100&sort=-severity`, vol.analystAuth),
      (r) => (r.body as { data: unknown[] }).data?.length === 100,
    );
    expect(page.body.data.every((i: { severity: string }) => i.severity === 'critical')).toBe(true);
    const next = await get(
      `${BASE}?limit=100&sort=-severity&cursor=${encodeURIComponent(page.body.nextCursor)}`,
      vol.analystAuth,
    );
    expect(next.status).toBe(200);
    expect(Date.now() - started).toBeLessThan(20_000);
  });
});
