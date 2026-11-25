/**
 * The generic security incident routes of step 8.4 (docs/plan/steps/24-account-takeover-core.md
 * §5.2, D17, D24, §10.4) over HTTP with the dependencies stubbed (the in-memory `AtoWorld`; the
 * shared state machine of `@email-gateway/security-incidents`). For every operation: success
 * with the example and a body that parses with its schema, 401, 403 without any category
 * permission, 404 for another organization's ids, the feature gate, Idempotency-Key replay and
 * reuse; plus transitions (allowed, refused with a reason, CAS conflict), assignment, notes,
 * false-positive feedback, the audited report and the **cross-category** rule: a test-registered
 * second category (`fake_category`, `fake:read`/`fake:manage`) joins the routes' permission
 * lists, and a principal holding only it sees no ATO incident and gets 404 for one.
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
import type { IncidentCategoryHandler } from '@email-gateway/security-incidents';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import { CodedHttpException } from '../src/http/coded-exception';
import {
  type IncidentCategoryDefinition,
  registerIncidentCategory,
} from '../src/modules/incidents/incident-categories';
import type { StubbedApiApp } from './support/api-test-app';
import type { AtoWorld as AtoWorldType } from './support/ato-fixtures';
import type { INCIDENT_EXAMPLES } from '../src/modules/incidents/dto/incidents.examples';
import type * as IncidentSchemaModule from '../src/modules/incidents/dto/incidents.schemas';

type IncidentExamples = typeof INCIDENT_EXAMPLES;
type IncidentSchemas = typeof IncidentSchemaModule;

const R = 'ato:read';
const M = 'ato:manage';
const FR = 'fake:read';
const FM = 'fake:manage';
const OTHER_ORG = 2n;
const BASE = '/api/v1/incidents';

/** The second category (registered before the incident routes load: permission lists grow). */
const fakeHandler: IncidentCategoryHandler = {
  category: 'fake_category' as never,
  subjectTypes: ['fake_subject' as never],
  permissions: { read: FR, manage: FM },
  feedbackSchema: null,
  resolveSubject: () => Promise.resolve(null),
  loadDetail: () => Promise.resolve({ fake: true }),
  reportSections: () => Promise.resolve([]),
};
const FAKE: IncidentCategoryDefinition = {
  category: 'fake_category',
  handler: () => fakeHandler,
  featureKey: 'fake_feature',
  notEnabled: () => new CodedHttpException(403, 'fake_not_enabled', 'off'),
  subjectDisplays: () => Promise.resolve(new Map()),
  openManual: () => Promise.reject(new Error('not used')),
};
registerIncidentCategory(FAKE);

interface Ctx {
  incident: string;
  account: string;
  closed: string;
  fake: string;
  foreign: string;
}

interface Spec {
  id: string;
  method: 'get' | 'post' | 'patch';
  path: (c: Ctx) => string;
  manage?: boolean;
  keyed?: boolean;
  body?: (c: Ctx) => object;
  ok: number;
  schema?: z.ZodType;
  byId?: boolean;
}

describe('security incident routes (e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  let world: AtoWorldType;
  let store: { rows: Map<string, unknown>; override: (b: never) => never };
  let audit: { entries: Array<{ action: string; metadata?: Record<string, unknown> }> };
  let org: bigint;
  let ctx: Ctx;
  let X: IncidentExamples;
  let S: IncidentSchemas;

  beforeAll(async () => {
    const support = await import('./support/api-test-app');
    const fixtures = await import('./support/ato-fixtures');
    X = (await import('../src/modules/incidents/dto/incidents.examples')).INCIDENT_EXAMPLES;
    S = await import('../src/modules/incidents/dto/incidents.schemas');
    world = new fixtures.AtoWorld();
    const recording = new fixtures.RecordingAuditService();
    audit = recording;
    const idempotency = new support.InMemoryIdempotencyStore();
    store = idempotency as never;
    api = await support.createStubbedApiApp(
      {
        API_RATE_SENSITIVE_PER_MINUTE: '600',
        API_RATE_EXPENSIVE_PER_MINUTE: '600',
        API_ATO_REPORT_MAX_ITEMS: '2',
      },
      { override: (b) => idempotency.override(fixtures.overrideAto(b, world, recording, [FAKE])) },
    );
    org = api.principals.organizationId;
    // The dynamic imports build the whole stubbed api; under a loaded parallel turbo run this
    // took longer than the default 10 s hook timeout (a recurring flake, steps AI-4 WP1 / 12.1).
  }, 60_000);

  afterAll(async () => {
    await api?.close();
  });

  beforeEach(() => {
    world.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    const account = world.addAccount(org);
    const incident = world.addIncident(org, account);
    world.addSignal(account);
    const closedAccount = world.addAccount(org);
    const closed = world.addIncident(org, closedAccount, {
      status: 'resolved',
      resolutionCode: 'remediated',
      resolvedAt: new Date(),
      activeMarker: null,
    });
    const fake = world.addIncident(org, world.addAccount(org), {
      category: 'fake_category' as never,
      subjectType: 'fake_subject' as never,
    });
    const foreign = world.addIncident(OTHER_ORG, world.addAccount(OTHER_ORG));
    world.messages.push({
      messageId: 9001n,
      receivedAt: new Date(),
      publicId: randomUUID(),
      direction: 'outbound',
      finalVerdict: 'phishing',
      finalAction: 'quarantine',
      riskScore: 870,
      riskLevel: 'high',
      recipientCount: 3,
      externalDomainCount: 2,
      findingCodes: ['url.phishing.known_bad'],
    });
    world.messageLinks.set(incident.id, [9001n]);
    for (let i = 0; i < 3; i += 1)
      world.event(incident, 'note_added', { type: 'system', id: null }, { note: `note ${i}` });
    ctx = {
      incident: incident.publicId,
      account: account.publicId,
      closed: closed.publicId,
      fake: fake.publicId,
      foreign: foreign.publicId,
    };
  });

  const SPECS = (): Spec[] => [
    { id: 'I1', method: 'get', path: () => BASE, ok: 200, schema: S.IncidentPageSchema },
    {
      id: 'I2',
      method: 'post',
      path: () => BASE,
      manage: true,
      keyed: true,
      body: () => ({
        ...X.create,
        subject: { type: 'ato_account', id: world.addAccount(org).publicId },
      }),
      ok: 201,
      schema: S.IncidentDetailSchema,
    },
    {
      id: 'I3',
      method: 'get',
      path: (c) => `${BASE}/${c.incident}`,
      ok: 200,
      schema: S.IncidentDetailSchema,
      byId: true,
    },
    {
      id: 'I4',
      method: 'patch',
      path: (c) => `${BASE}/${c.incident}`,
      manage: true,
      keyed: true,
      body: () => ({
        expectedRowVersion: world.incidents.find((i) => i.publicId === ctx.incident)!.rowVersion,
        status: 'investigating',
      }),
      ok: 200,
      schema: S.IncidentDetailSchema,
      byId: true,
    },
    {
      id: 'I5',
      method: 'post',
      path: (c) => `${BASE}/${c.incident}/notes`,
      manage: true,
      keyed: true,
      body: () => X.addNote,
      ok: 201,
      schema: S.TimelineEntrySchema,
      byId: true,
    },
    {
      id: 'I6',
      method: 'get',
      path: (c) => `${BASE}/${c.incident}/timeline`,
      ok: 200,
      schema: S.TimelinePageSchema,
      byId: true,
    },
    {
      id: 'I7',
      method: 'get',
      path: (c) => `${BASE}/${c.incident}/messages`,
      ok: 200,
      schema: S.IncidentMessagePageSchema,
      byId: true,
    },
    {
      id: 'I8',
      method: 'get',
      path: (c) => `${BASE}/${c.incident}/report`,
      ok: 200,
      schema: S.IncidentReportSchema,
      byId: true,
    },
  ];

  const asUser = (permissions: string[], mfa = true) =>
    api.principals.user(permissions, { mfaAuthenticated: mfa }).bearer();

  async function send(
    spec: Spec,
    options: {
      auth?: Record<string, string>;
      key?: string | null;
      body?: object;
      path?: string;
    } = {},
  ) {
    const auth = options.auth ?? (await asUser([R, M]));
    let req = api
      .http()
      [spec.method](options.path ?? spec.path(ctx))
      .set(auth);
    if (spec.keyed && options.key !== null)
      req = req.set('Idempotency-Key', options.key ?? randomUUID());
    const body = options.body ?? spec.body?.(ctx);
    return body ? req.send(body) : req;
  }

  it('success with a valid body for each of the 8 operations', async () => {
    for (const spec of SPECS()) {
      const res = await send(spec);
      expect(res.status, `${spec.id} ${JSON.stringify(res.body)}`).toBe(spec.ok);
      const parsed = spec.schema!.safeParse(res.body);
      expect(parsed.success, `${spec.id} ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
    }
  });

  it('401 without credentials; 403 without any category permission; API keys accepted', async () => {
    for (const spec of SPECS()) {
      expect((await api.http()[spec.method](spec.path(ctx))).status, spec.id).toBe(401);
      const forbidden = await send(spec, {
        auth: await asUser(spec.manage ? [R] : ['message:read']),
      });
      expect(forbidden.status, spec.id).toBe(403);
      api.principals.apiKeyWith([R, M]);
      const key = await send(spec, { auth: api.principals.apiKeyHeaders });
      expect(key.status, `${spec.id} ${JSON.stringify(key.body)}`).toBe(spec.ok);
    }
  });

  it('another organization’s incident answers 404 incident_not_found', async () => {
    for (const spec of SPECS().filter((s) => s.byId)) {
      const res = await send(spec, { path: spec.path({ ...ctx, incident: ctx.foreign }) });
      expect(res.status, spec.id).toBe(404);
      expect(res.body.code).toBe('incident_not_found');
    }
    const list = await api
      .http()
      .get(BASE)
      .set(await asUser([R]));
    expect(list.body.data.map((i: { id: string }) => i.id)).not.toContain(ctx.foreign);
  });

  it('cross-category: the permission lists come from the registry; another category’s holder sees no ATO incident', async () => {
    const fakeOnly = await asUser([FR, FM]);
    const list = await api.http().get(BASE).set(fakeOnly);
    expect(list.status).toBe(200);
    expect(list.body.data.map((i: { id: string; category: string }) => i.category)).toEqual([
      'fake_category',
    ]);
    for (const spec of SPECS().filter((s) => s.byId)) {
      const res = await send(spec, { auth: fakeOnly });
      expect(res.status, spec.id).toBe(404);
      expect(res.body.code).toBe('incident_not_found');
    }
    // An ATO reader does not see the fake category's incident either.
    const atoOnly = await api
      .http()
      .get(`${BASE}/${ctx.fake}`)
      .set(await asUser([R]));
    expect(atoOnly.status).toBe(404);
    const ato = await api
      .http()
      .get(BASE)
      .set(await asUser([R]));
    expect(ato.body.data.map((i: { category: string }) => i.category)).not.toContain(
      'fake_category',
    );
    // A category filter cannot widen access.
    const widened = await api
      .http()
      .get(`${BASE}?category=account_takeover`)
      .set(await asUser([FR, FM]));
    expect(widened.body).toEqual({ data: [], nextCursor: null });
  });

  it('feature gate: ATO incidents are invisible and their mutations are 403 ato_not_enabled', async () => {
    world.featureOff.add(org);
    const list = await api
      .http()
      .get(BASE)
      .set(await asUser([R, M]));
    expect(list.body).toEqual({ data: [], nextCursor: null });
    const get = await api
      .http()
      .get(`${BASE}/${ctx.incident}`)
      .set(await asUser([R, M]));
    expect(get.status).toBe(404);
    for (const spec of SPECS().filter((s) => s.keyed)) {
      const res = await send(spec);
      expect(res.status, spec.id).toBe(403);
      expect(res.body.code).toBe('ato_not_enabled');
    }
  });

  it('Idempotency-Key: replay with the header, reuse refused, header required', async () => {
    for (const spec of SPECS().filter((s) => s.keyed)) {
      const key = randomUUID();
      const body = spec.body!(ctx);
      const first = await send(spec, { key, body });
      expect(first.status, spec.id).toBe(spec.ok);
      const replay = await send(spec, { key, body });
      expect(replay.headers['idempotency-replayed'], spec.id).toBe('true');
      expect(replay.body).toEqual(first.body);
      const reused = await send(spec, {
        key,
        body: {
          ...body,
          ...(spec.id === 'I4'
            ? { severity: 'low' }
            : spec.id === 'I2'
              ? { severity: 'low' }
              : { note: 'another note' }),
        },
      });
      expect(reused.status, spec.id).toBe(422);
      expect(reused.body.code).toBe('idempotency_key_reused');
      expect((await send(spec, { key: null })).body.code, spec.id).toBe('idempotency_key_required');
    }
  });

  describe('transitions and updates (D12)', () => {
    const patch = async (id: string, body: object) =>
      api
        .http()
        .patch(`${BASE}/${id}`)
        .set(await asUser([R, M]))
        .set('Idempotency-Key', randomUUID())
        .send(body);
    const version = (id: string) => world.incidents.find((i) => i.publicId === id)!.rowVersion;

    it('refuses invalid transitions with a reason; a stale version is 409 incident_conflict', async () => {
      const stale = await patch(ctx.incident, { expectedRowVersion: 99, status: 'investigating' });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'incident_conflict', currentRowVersion: 1 });
      const toMitigated = await patch(ctx.incident, { expectedRowVersion: 1, status: 'mitigated' });
      expect(toMitigated.status).toBe(422);
      expect(toMitigated.body).toMatchObject({
        code: 'incident_transition_invalid',
        reason: 'transition_not_allowed',
        from: 'open',
        to: 'mitigated',
      });
      const noNote = await patch(ctx.incident, { expectedRowVersion: 1, status: 'confirmed' });
      expect(noNote.body).toMatchObject({
        code: 'incident_transition_invalid',
        reason: 'note_required',
      });
      const noResolution = await patch(ctx.incident, {
        expectedRowVersion: 1,
        status: 'resolved',
        note: 'All cleaned up now.',
      });
      expect(noResolution.body).toMatchObject({
        code: 'incident_transition_invalid',
        reason: 'resolution_required',
      });
      const wrongCode = await patch(ctx.incident, {
        expectedRowVersion: 1,
        status: 'false_positive',
        resolution: { code: 'remediated', note: 'Not a compromise at all.' },
      });
      expect(wrongCode.body).toMatchObject({
        code: 'incident_transition_invalid',
        reason: 'resolution_invalid',
      });
      const closed = await patch(ctx.closed, {
        expectedRowVersion: version(ctx.closed),
        status: 'investigating',
      });
      expect(closed.body.reason).toBe('transition_not_allowed');
      const empty = await patch(ctx.incident, { expectedRowVersion: 1 });
      expect(empty.status).toBe(400);
    });

    it('confirm with a note, assign, raise severity in one change; the detail shows the caller’s transitions', async () => {
      const assignee = world.addUser(org);
      const res = await patch(ctx.incident, {
        expectedRowVersion: 1,
        status: 'confirmed',
        note: 'Confirmed with the user by phone.',
        assigneeId: assignee.publicId,
        severity: 'critical',
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        status: 'confirmed',
        severity: 'critical',
        assigneeId: assignee.publicId,
        canManage: true,
      });
      expect(res.body.allowedTransitions.map((t: { to: string }) => t.to)).toEqual([
        'mitigated',
        'resolved',
      ]);
      const readOnly = await api
        .http()
        .get(`${BASE}/${ctx.incident}`)
        .set(await asUser([R]));
      expect(readOnly.body).toMatchObject({ canManage: false, allowedTransitions: [] });
      const badAssignee = await patch(ctx.incident, {
        expectedRowVersion: version(ctx.incident),
        assigneeId: randomUUID(),
      });
      expect(badAssignee.status).toBe(422);
      expect(badAssignee.body.code).toBe('incident_assignee_invalid');
    });

    it('false positive with category feedback dismisses signals and adds trusted contexts', async () => {
      const res = await patch(ctx.incident, { ...X.update, expectedRowVersion: 1 });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        status: 'false_positive',
        resolution: { code: 'benign_activity' },
      });
      expect(world.signals.every((s) => s.status === 'dismissed')).toBe(true);
      expect(
        world.contexts.some((c) => c.source === 'false_positive_feedback' && c.value === 'DE'),
      ).toBe(true);
      const invalid = await patch(ctx.closed, {
        expectedRowVersion: version(ctx.closed),
        status: 'false_positive',
        resolution: { code: 'false_positive', note: 'Not a compromise.' },
        categoryFeedback: { trustedContexts: 'all' },
      });
      expect(invalid.status).toBe(422);
      const feedbackWithoutFp = await patch(ctx.incident, {
        expectedRowVersion: version(ctx.incident),
        note: 'just a note',
        categoryFeedback: { dismissSignals: true },
      });
      expect(feedbackWithoutFp.body.code).toBe('incident_feedback_invalid');
    });

    it('manual incidents: one active per subject (409 incident_active), unknown subject and category', async () => {
      const auth = await asUser([R, M]);
      const post = (body: object) =>
        api.http().post(BASE).set(auth).set('Idempotency-Key', randomUUID()).send(body);
      const active = await post({ ...X.create, subject: { type: 'ato_account', id: ctx.account } });
      expect(active.status).toBe(409);
      expect(active.body).toMatchObject({ code: 'incident_active', incidentId: ctx.incident });
      const unknown = await post({
        ...X.create,
        subject: { type: 'ato_account', id: randomUUID() },
      });
      expect(unknown.status).toBe(404);
      expect(unknown.body.code).toBe('incident_subject_not_found');
      const category = await post({ ...X.create, category: 'message_threat' });
      expect(category.status).toBe(422);
      expect(category.body.code).toBe('incident_category_unsupported');
      const created = await post({
        ...X.create,
        subject: { type: 'ato_account', id: world.addAccount(org).publicId },
      });
      expect(created.body).toMatchObject({ origin: 'manual', severity: 'high', status: 'open' });
    });
  });

  describe('lists, timeline, messages and the report', () => {
    it('filters by status, severity and assignee; sorts by severity with cursors', async () => {
      const auth = await asUser([R]);
      const open = await api.http().get(`${BASE}?status=resolved`).set(auth);
      expect(open.body.data.map((i: { id: string }) => i.id)).toEqual([ctx.closed]);
      const unassigned = await api
        .http()
        .get(`${BASE}?assignee=unassigned&limit=1&sort=-severity`)
        .set(auth);
      expect(unassigned.body.data).toHaveLength(1);
      const next = await api
        .http()
        .get(
          `${BASE}?assignee=unassigned&limit=1&sort=-severity&cursor=${encodeURIComponent(unassigned.body.nextCursor)}`,
        )
        .set(auth);
      expect(next.status).toBe(200);
      expect(next.body.data[0].id).not.toBe(unassigned.body.data[0].id);
      const mismatch = await api
        .http()
        .get(`${BASE}?limit=1&cursor=${encodeURIComponent(unassigned.body.nextCursor)}`)
        .set(auth);
      expect(mismatch.body.code).toBe('cursor_invalid');
      const badAssignee = await api.http().get(`${BASE}?assignee=someone`).set(auth);
      expect(badAssignee.status).toBe(400);
      const range = await api
        .http()
        .get(`${BASE}?detectedFrom=2020-01-01T00:00:00Z&detectedTo=2021-01-01T00:00:00Z`)
        .set(auth);
      expect(range.status).toBe(200);
      expect(
        range.body.data.find((i: { subject: { display: string | null } }) => i.subject)?.subject,
      ).toBeUndefined();
    });

    it('timeline pages oldest first; messages carry no subject or recipient address', async () => {
      const auth = await asUser([R]);
      const first = await api.http().get(`${BASE}/${ctx.incident}/timeline?limit=2`).set(auth);
      expect(first.body.data.map((e: { type: string }) => e.type)).toEqual([
        'created',
        'note_added',
      ]);
      const rest = await api
        .http()
        .get(
          `${BASE}/${ctx.incident}/timeline?limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`,
        )
        .set(auth);
      expect(rest.body.data).toHaveLength(2);
      const messages = await api.http().get(`${BASE}/${ctx.incident}/messages`).set(auth);
      expect(messages.body.data[0]).toMatchObject({
        direction: 'outbound',
        externalDomainCount: 2,
        recipientCount: 3,
      });
      expect(Object.keys(messages.body.data[0])).not.toContain('subject');
      expect(JSON.stringify(messages.body)).not.toContain('@');
    });

    it('the report is audited, bounded by API_ATO_REPORT_MAX_ITEMS and names messages by public id', async () => {
      const res = await api
        .http()
        .get(`${BASE}/${ctx.incident}/report`)
        .set(await asUser([R]));
      expect(res.status).toBe(200);
      expect(res.body.truncated).toBe(true);
      expect(res.body.timeline).toHaveLength(2);
      expect(res.body.messages[0].messageId).toBe(world.messages[0]!.publicId);
      expect(world.events.some((e) => e.eventType === 'report_exported')).toBe(true);
    });
  });
});
