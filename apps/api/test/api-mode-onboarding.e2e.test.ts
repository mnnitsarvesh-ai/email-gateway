/**
 * The step API-4 API-mode routes (docs/plan/steps/38-api-mode-parity-onboarding.md A10, A12, B6,
 * B7, B8, §10.4) over HTTP with MySQL, Redis and S3 stubbed: `ApiModeWorld` plus the onboarding
 * doubles, the Idempotency-Key store and the audit in memory. New routes: protection by mode
 * (v1 cursor, filter, capability matrix, gaps), the domain onboarding state, the mailbox scope
 * (read, keyed CAS write, every refusal, replay, audit). Changed views and bodies: the overview's
 * policy/outbound/scope blocks, detections' policy fields and filters (`direction=outbound`,
 * `policyDisposition`, `dlpAction`) and the detail's `policy`/`dlp`, the settings flags, the
 * remediation policy's `policyMapping` and detect-only period, decision record `/2`. For every
 * new operation: success, 401, 403 without its permission (a read-only user on the write), 404 for
 * another organization's ids. The real writer and replica run in integration/api-mode-onboarding.test.ts.
 */
// @covers get /api/v1/api-mode/protection-coverage
// @covers get /api/v1/api-mode/domains/:domainId/onboarding
// @covers get /api/v1/api-mode/domains/:domainId/scope
// @covers put /api/v1/api-mode/domains/:domainId/scope
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuditService } from '../src/audit/audit.service';
import { ONBOARDING_EXAMPLES } from '../src/modules/api-mode/dto/api-mode-onboarding.schemas';
import {
  ApiModeWorld,
  overrideApiMode,
  type StoredConnection,
  type StoredMailbox,
} from './support/api-mode-fixtures';
import { OnboardingStore, overrideOnboarding } from './support/api-mode-onboarding-fixtures';
import {
  createStubbedApiApp,
  InMemoryIdempotencyStore,
  type StubbedApiApp,
} from './support/api-test-app';
import { RecordingAuditService } from './support/messages-fixtures';

const READ = 'remediation:read';
const WRITE = 'remediation:write';
const DOMAIN_READ = 'domain:read';
const ALL = [READ, WRITE, DOMAIN_READ];
const BASE = '/api/v1/api-mode';
const OTHER_ORG = 2n;
const REASON = 'Pilot with the finance team first';

type Method = 'get' | 'put';

interface Ctx {
  domain: string;
  inlineDomain: string;
  foreignDomain: string;
  mailbox: string;
  otherMailbox: string;
  foreignMailbox: string;
  department: string;
  foreignDepartment: string;
}

describe('API-mode onboarding routes (step API-4, e2e, dependencies stubbed)', () => {
  let api: StubbedApiApp;
  const world = new ApiModeWorld();
  const onboarding = new OnboardingStore();
  const audit = new RecordingAuditService();
  const store = new InMemoryIdempotencyStore();
  let org: bigint;
  let ctx: Ctx;
  let m365: StoredConnection;
  let alex: StoredMailbox;

  beforeAll(async () => {
    api = await createStubbedApiApp(
      {},
      {
        override: (b) =>
          store.override(
            overrideOnboarding(overrideApiMode(b, world), world, onboarding)
              .overrideProvider(AuditService)
              .useValue(audit),
          ),
      },
    );
    org = api.principals.organizationId;
  });

  afterAll(async () => {
    await api?.close();
  });

  function seed(): Ctx {
    world.addOrganization(org, api.principals.ids.org);
    world.addOrganization(OTHER_ORG, randomUUID());
    world.entitled.add(org);
    m365 = world.addConnection(org, {
      displayName: 'Contoso Microsoft 365',
      grant: {
        profile: 'm365.mailbox_remediation',
        status: 'active',
        authMethod: 'platform_app',
        clientId: null,
        subjectEmail: null,
      },
      journalSources: [
        {
          publicId: randomUUID(),
          displayName: 'Contoso journal',
          kind: 'microsoft_365_journal',
          status: 'active',
          healthStatus: 'healthy',
          verifiedAt: new Date(),
          addressVersion: 1,
        },
      ],
    });
    m365.api = world.apiRow({ healthStatus: 'healthy', inventoryStatus: 'ok', mailboxesTotal: 3 });
    onboarding.mailFlow.set(m365.id, 'active');
    const domain = world.addDomain(org, 'contoso.example', {
      connectionId: m365.id,
      configured: 'api',
    });
    const inlineDomain = world.addDomain(org, 'inline.contoso.example', {
      mxPointsToGateway: true,
    });
    const foreignConn = world.addConnection(OTHER_ORG);
    const foreignDomain = world.addDomain(OTHER_ORG, 'other.example', { configured: 'api' });
    alex = world.addMailbox(m365, 'alex@contoso.example');
    const blair = world.addMailbox(m365, 'blair@contoso.example', { coverageState: 'gap' });
    const foreignMailbox = world.addMailbox(foreignConn, 'eve@other.example');
    const department = randomUUID();
    const foreignDepartment = randomUUID();
    onboarding.departments.push(
      { organizationId: org, publicId: department, name: 'Finance', members: 7 },
      { organizationId: OTHER_ORG, publicId: foreignDepartment, name: 'Other', members: 1 },
    );
    return {
      domain: domain.publicId,
      inlineDomain: inlineDomain.publicId,
      foreignDomain: foreignDomain.publicId,
      mailbox: alex.publicId,
      otherMailbox: blair.publicId,
      foreignMailbox: foreignMailbox.publicId,
      department,
      foreignDepartment,
    };
  }

  beforeEach(() => {
    world.reset();
    onboarding.reset();
    audit.entries.length = 0;
    store.rows.clear();
    api.kv.entries.clear();
    api.principals.apiKeyWith([]);
    ctx = seed();
  });

  const asUser = (permissions: string[]) => api.principals.user(permissions).bearer();

  async function call(
    method: Method,
    path: string,
    options: { perms?: string[] | null; key?: string | null; body?: object } = {},
  ) {
    const req = api.http()[method](path);
    if (options.perms !== null) req.set(await asUser(options.perms ?? ALL));
    if (method === 'put' && options.key !== null) {
      req.set('Idempotency-Key', options.key ?? randomUUID());
    }
    return options.body === undefined ? req : req.send(options.body);
  }

  const scopePath = (domain = ctx.domain) => `${BASE}/domains/${domain}/scope`;
  const putScope = (body: object, options: { perms?: string[]; key?: string } = {}) =>
    call('put', scopePath(), { ...options, body });

  describe('RBAC and tenant isolation', () => {
    const routes = () =>
      [
        ['get', `${BASE}/protection-coverage`, [DOMAIN_READ], 200],
        ['get', `${BASE}/domains/${ctx.domain}/onboarding`, [DOMAIN_READ], 200],
        ['get', scopePath(), [READ], 200],
        [
          'put',
          scopePath(),
          [WRITE],
          200,
          { scope: { kind: 'all' }, reason: REASON, expectedRowVersion: null },
        ],
      ] as const;

    it('each route succeeds with its permission, 401 without credentials, 403 without it', async () => {
      for (const [method, path, perms, ok, body] of routes()) {
        store.rows.clear();
        onboarding.settings.clear();
        const res = await call(method, path, { perms: [...perms], ...(body && { body }) });
        expect(res.status, `${path} ${JSON.stringify(res.body)}`).toBe(ok);
        expect((await call(method, path, { perms: null, ...(body && { body }) })).status).toBe(401);
        const held = ALL.filter((p) => !(perms as readonly string[]).includes(p));
        const denied = await call(method, path, { perms: held, ...(body && { body }) });
        expect(denied.status, path).toBe(403);
        expect(denied.body.code).toBe('forbidden');
      }
    });

    it('a read-only user reads everything and is refused the scope write', async () => {
      const readOnly = [READ, DOMAIN_READ, 'organization:read', 'integration:read'];
      for (const [method, path, , ok, body] of routes()) {
        const res = await call(method, path, { perms: readOnly, ...(body && { body }) });
        expect(res.status, path).toBe(method === 'get' ? ok : 403);
      }
    });

    it('another organization’s domain answers 404 like an unknown id; lists never show it', async () => {
      for (const [method, path] of [
        ['get', `${BASE}/domains/${ctx.foreignDomain}/onboarding`],
        ['get', scopePath(ctx.foreignDomain)],
        ['put', scopePath(ctx.foreignDomain)],
        ['get', `${BASE}/domains/${randomUUID()}/onboarding`],
      ] as const) {
        const res = await call(method, path, {
          ...(method === 'put' && {
            body: { scope: { kind: 'all' }, reason: REASON, expectedRowVersion: null },
          }),
        });
        expect(res.status, path).toBe(404);
        expect(res.body.code).toBe('domain_not_found');
      }
      expect((await call('get', `${BASE}/domains/not-a-uuid/onboarding`)).status).toBe(400);
      const page = await call('get', `${BASE}/protection-coverage`);
      expect(page.body.items.map((i: { domainId: string }) => i.domainId)).not.toContain(
        ctx.foreignDomain,
      );
    });
  });

  describe('GET /api-mode/protection-coverage (A10)', () => {
    it('returns the matrix, totals and each domain’s coverage and gaps (counts only)', async () => {
      const res = await call('get', `${BASE}/protection-coverage`);
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body.capabilities).toHaveLength(12);
      expect(res.body.entitled).toBe(true);
      const api = res.body.items.find((i: { domainId: string }) => i.domainId === ctx.domain);
      expect(api).toMatchObject({
        effectiveMode: 'api',
        inherited: false,
        inline: { applies: false },
        api: {
          connection: { id: m365.publicId, mailboxAccess: 'active', health: 'healthy' },
          intake: { journal: 'verified', feeds: 'off' },
          scope: 'all',
          mailboxes: { inScope: 2, covered: 1, gap: 1, total: 2 },
          remediation: { source: 'platform_default', mode: 'enforce' },
          policyEvaluation: true,
        },
        gaps: ['api_coverage_gaps'],
      });
      const inline = res.body.items.find(
        (i: { domainId: string }) => i.domainId === ctx.inlineDomain,
      );
      expect(inline).toMatchObject({ effectiveMode: 'inline', api: null, gaps: [] });
      expect(JSON.stringify(res.body)).not.toContain('alex@');
    });

    it('pages with a signed v1 cursor and filters by effective mode', async () => {
      const first = await call('get', `${BASE}/protection-coverage?limit=1`);
      expect(first.body.items).toHaveLength(1);
      expect(first.body.nextCursor).toEqual(expect.any(String));
      const second = await call(
        'get',
        `${BASE}/protection-coverage?limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`,
      );
      expect(second.status).toBe(200);
      expect(second.body.items[0].domainId).not.toBe(first.body.items[0].domainId);
      // A cursor is bound to its filters.
      const rebound = await call(
        'get',
        `${BASE}/protection-coverage?limit=1&effectiveMode=api&cursor=${encodeURIComponent(
          first.body.nextCursor,
        )}`,
      );
      expect(rebound.status).toBe(400);
      const apiOnly = await call('get', `${BASE}/protection-coverage?effectiveMode=api`);
      expect(apiOnly.body.items.map((i: { domainId: string }) => i.domainId)).toEqual([ctx.domain]);
      expect((await call('get', `${BASE}/protection-coverage?effectiveMode=nope`)).status).toBe(
        400,
      );
    });

    it('the example validates the documented shape', () => {
      expect(ONBOARDING_EXAMPLES.coverage.items[0].gaps).toContain('api_detect_only');
    });
  });

  describe('GET /api-mode/domains/{domainId}/onboarding (B8)', () => {
    it('computes the steps from server state and the first copy (stored or fallback)', async () => {
      const waiting = await call('get', `${BASE}/domains/${ctx.domain}/onboarding`);
      expect(waiting.status, JSON.stringify(waiting.body)).toBe(200);
      expect(waiting.body).toMatchObject({
        effectiveMode: 'api',
        ownership: { status: 'verified', method: 'dns_txt', providerCheckAvailable: false },
        connection: { id: m365.publicId, bound: true, mailFlowGrant: 'active' },
        scope: { kind: 'all', inScope: 2, excluded: 0 },
        action: { source: 'platform_default', presetKey: 'p1' },
        firstCopy: { status: 'waiting', copy: null, waitingSinceMinutes: 60 },
      });
      expect(waiting.body.steps.map((s: { status: string }) => s.status)).toEqual([
        'done',
        'done',
        'done',
        'done',
        'not_started',
        'in_progress',
      ]);
      expect(waiting.body.firstCopy.hints.at(-1)).toEqual({
        code: 'send_test_message',
        severity: 'info',
        link: null,
      });
      const copy = world.addCopy(alex, { verdict: 'phishing', policyState: 'evaluated' });
      const received = await call('get', `${BASE}/domains/${ctx.domain}/onboarding`);
      expect(received.body.firstCopy).toMatchObject({
        status: 'received',
        copy: { detectionId: copy.publicId, verdict: 'phishing', policyState: 'evaluated' },
        hints: [],
      });
      expect(received.body.steps.at(-1).status).toBe('done');
    });

    it('a pending domain with a bound connection offers the provider check', async () => {
      const domain = world.domains.find((d) => d.publicId === ctx.domain)!;
      onboarding.domainFacts.set(domain.id, {
        status: 'pending_verification',
        ownershipMethod: null,
        activatedAt: null,
      });
      onboarding.capable.set(org, [{ id: m365.id, publicId: m365.publicId }]);
      const res = await call('get', `${BASE}/domains/${ctx.domain}/onboarding`);
      expect(res.body.ownership).toMatchObject({ status: 'pending', providerCheckAvailable: true });
      expect(res.body.steps[0]).toMatchObject({
        key: 'ownership',
        status: 'in_progress',
        nextAction: 'verify_through_provider',
      });
      expect(res.body.steps.at(-1)).toMatchObject({
        status: 'blocked',
        blockers: ['ownership_pending'],
      });
    });

    it('an inline domain skips every step', async () => {
      const res = await call('get', `${BASE}/domains/${ctx.inlineDomain}/onboarding`);
      expect(res.body.steps.every((s: { status: string }) => s.status === 'skipped')).toBe(true);
    });
  });

  describe('GET/PUT /api-mode/domains/{domainId}/scope (B6)', () => {
    it('defaults to all; PUT departments creates the row (audit, recompute requested)', async () => {
      const before = await call('get', scopePath());
      expect(before.body).toMatchObject({
        kind: 'all',
        departments: [],
        rowVersion: null,
        inScope: 2,
        recomputePending: false,
      });
      const res = await putScope({
        scope: { kind: 'departments', departmentIds: [ctx.department] },
        reason: REASON,
        expectedRowVersion: null,
      });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        kind: 'departments',
        departments: [{ id: ctx.department, name: 'Finance', memberCount: 7 }],
        rowVersion: 1,
        recomputePending: true,
        created: true,
        changed: true,
      });
      expect(audit.entries.at(-1)).toMatchObject({
        action: 'api_mode.scope_updated',
        resourceType: 'api_mode_domain_settings',
        resourceId: ctx.domain,
        metadata: {
          domainId: ctx.domain,
          from: 'all',
          to: 'departments',
          departments: 1,
          mailboxes: 0,
          reason: REASON,
        },
      });
    });

    it('mailboxes: selects only this domain’s mailboxes; CAS; replay; refusals', async () => {
      const key = randomUUID();
      const body = {
        scope: { kind: 'mailboxes' },
        mailboxIds: [ctx.mailbox],
        reason: REASON,
        expectedRowVersion: null,
      };
      const first = await putScope(body, { key });
      expect(first.status, JSON.stringify(first.body)).toBe(200);
      expect(first.body).toMatchObject({ kind: 'mailboxes', selectedMailboxes: 1, rowVersion: 1 });
      expect(alex.scopeSelected).toBe(true);
      const replay = await putScope(body, { key });
      expect(replay.status).toBe(200);
      expect(replay.headers['idempotency-replayed']).toBe('true');
      expect(replay.body).toEqual(first.body);
      expect(audit.entries.filter((e) => e.action === 'api_mode.scope_updated')).toHaveLength(1);
      // Stale version → CAS conflict with the current version.
      const stale = await putScope({ ...body, expectedRowVersion: null });
      expect(stale.status).toBe(409);
      expect(stale.body).toMatchObject({ code: 'api_mode_scope_conflict', currentRowVersion: 1 });
      // Another organization's mailbox is not a mailbox of this domain.
      const foreign = await putScope({
        ...body,
        mailboxIds: [ctx.foreignMailbox],
        expectedRowVersion: 1,
      });
      expect(foreign.status).toBe(422);
      expect(foreign.body.code).toBe('api_mode_scope_mailbox_invalid');
      // A department of another organization is invalid.
      const dept = await putScope({
        scope: { kind: 'departments', departmentIds: [ctx.foreignDepartment] },
        reason: REASON,
        expectedRowVersion: 1,
      });
      expect(dept.status).toBe(422);
      expect(dept.body.code).toBe('api_mode_scope_department_invalid');
      // Back to all clears the selection.
      const all = await putScope({ scope: { kind: 'all' }, reason: REASON, expectedRowVersion: 1 });
      expect(all.body).toMatchObject({ kind: 'all', rowVersion: 2, selectedMailboxes: 0 });
      expect(alex.scopeSelected).toBe(false);
    });

    it('validation: strict body, mailboxIds only (and required) for kind mailboxes, the key', async () => {
      for (const body of [
        {
          scope: { kind: 'all' },
          mailboxIds: [ctx.mailbox],
          reason: REASON,
          expectedRowVersion: null,
        },
        { scope: { kind: 'mailboxes' }, reason: REASON, expectedRowVersion: null },
        {
          scope: { kind: 'departments', departmentIds: [] },
          reason: REASON,
          expectedRowVersion: null,
        },
        { scope: { kind: 'all' }, reason: REASON, expectedRowVersion: null, extra: true },
        { scope: { kind: 'groups' }, reason: REASON, expectedRowVersion: null },
        { scope: { kind: 'all' }, reason: '', expectedRowVersion: null },
      ]) {
        const res = await putScope(body);
        expect(res.status, JSON.stringify(body)).toBe(400);
      }
      const noKey = await call('put', scopePath(), {
        key: null,
        body: { scope: { kind: 'all' }, reason: REASON, expectedRowVersion: null },
      });
      expect(noKey.status).toBe(400);
      expect(noKey.body.code).toBe('idempotency_key_required');
    });

    it('an inline domain has no mailbox scope (409)', async () => {
      const res = await call('put', scopePath(ctx.inlineDomain), {
        body: { scope: { kind: 'all' }, reason: REASON, expectedRowVersion: null },
      });
      expect(res.status).toBe(409);
      expect(res.body).toMatchObject({
        code: 'api_mode_scope_domain_not_api',
        effectiveMode: 'inline',
      });
    });
  });

  describe('changed API-mode views (A12)', () => {
    it('overview: policy, outbound and scope blocks', async () => {
      alex.scopeState = 'excluded';
      const res = await call('get', `${BASE}/overview`, { perms: [READ] });
      expect(res.status, JSON.stringify(res.body)).toBe(200);
      expect(res.body).toMatchObject({
        policy: { enabled: true, evaluated24h: 0, errors24h: 0 },
        outbound: { detections24h: 0, enabled: true },
        scope: { excluded: 1 },
      });
    });

    it('detections: policy fields, outbound direction and the new filters; detail policy and dlp', async () => {
      const outbound = world.addCopy(alex, {
        direction: 'outbound',
        policyState: 'evaluated',
        policyDisposition: 'reject',
        dlpAction: 'block',
      });
      const tagged = world.addCopy(alex, {
        policyState: 'evaluated',
        policyDisposition: 'allow',
        policyTagged: true,
      });
      world.dlpResults.set(`${org}:${outbound.messageId}`, {
        action: 'block',
        verdict: 'violation',
        categories: ['payment_card'],
      });
      const list = await call('get', `${BASE}/detections?direction=outbound`, { perms: [READ] });
      expect(list.status, JSON.stringify(list.body)).toBe(200);
      expect(list.body.data).toEqual([
        expect.objectContaining({
          id: outbound.publicId,
          direction: 'outbound',
          policyState: 'evaluated',
          policyDisposition: 'reject',
          policyTagged: false,
          dlpAction: 'block',
        }),
      ]);
      const byDisposition = await call('get', `${BASE}/detections?policyDisposition=allow`, {
        perms: [READ],
      });
      expect(byDisposition.body.data.map((d: { id: string }) => d.id)).toEqual([tagged.publicId]);
      const byDlp = await call('get', `${BASE}/detections?dlpAction=block,quarantine`, {
        perms: [READ],
      });
      expect(byDlp.body.data.map((d: { id: string }) => d.id)).toEqual([outbound.publicId]);
      expect(
        (await call('get', `${BASE}/detections?dlpAction=nope`, { perms: [READ] })).status,
      ).toBe(400);
      const detail = await call('get', `${BASE}/detections/${outbound.publicId}`, {
        perms: [READ],
      });
      expect(detail.status).toBe(200);
      expect(detail.body).toMatchObject({
        policy: null,
        dlp: { action: 'block', verdict: 'violation', categories: ['payment_card'] },
      });
    });

    it('settings: the two step API-4 flags (absent = kept; audited from/to)', async () => {
      const base = {
        internalMailEnabled: true,
        autoClawback: 'enforce',
        autoMaxMailboxes: 500,
        purgeApprovalMailboxes: 50,
        clawbackLookbackDays: 14,
        tiMinConfidence: 80,
        reportAckEnabled: true,
        reportFeedbackEnabled: true,
        reason: REASON,
      };
      const get = await call('get', `${BASE}/settings`, { perms: [READ] });
      expect(get.body.settings).toMatchObject({
        policyEvaluationEnabled: true,
        outboundDetectionEnabled: true,
      });
      const off = await call('put', `${BASE}/settings`, {
        perms: [WRITE],
        body: { ...base, policyEvaluationEnabled: false, expectedRowVersion: null },
      });
      expect(off.status, JSON.stringify(off.body)).toBe(200);
      expect(off.body.settings).toMatchObject({
        policyEvaluationEnabled: false,
        outboundDetectionEnabled: true,
      });
      expect(off.body.changed).toEqual(['policyEvaluationEnabled']);
      expect(audit.entries.at(-1)!.metadata).toMatchObject({
        from: { policyEvaluationEnabled: true },
        to: { policyEvaluationEnabled: false },
      });
      // An API-3 body (no flags) keeps them.
      const kept = await call('put', `${BASE}/settings`, {
        perms: [WRITE],
        body: { ...base, expectedRowVersion: 1 },
      });
      expect(kept.body.settings.policyEvaluationEnabled).toBe(false);
      const overview = await call('get', `${BASE}/overview`, { perms: [READ] });
      expect(overview.body.policy.enabled).toBe(false);
    });

    it('remediation policy: policyMapping and detectOnly over HTTP (422 with enforce)', async () => {
      const until = new Date(Date.now() + 7 * 86_400_000).toISOString();
      const document = {
        v: 1,
        rules: [{ id: 'p1-suspicious', when: { verdicts: ['suspicious'] }, action: 'tag' }],
        policyMapping: { require_approval: 'move_junk' },
      };
      const ok = await call('put', `${BASE}/remediation-policy/domains/${ctx.domain}`, {
        perms: [WRITE],
        body: {
          mode: 'detect_only',
          document,
          detectOnly: { until, then: 'enforce' },
          reason: REASON,
          expectedRowVersion: null,
        },
      });
      expect(ok.status, JSON.stringify(ok.body)).toBe(200);
      expect(ok.body).toMatchObject({
        effectivePolicyMapping: { require_approval: 'move_junk', quarantine: 'move_quarantine' },
        detectOnly: { until, then: 'enforce', ended: false, simulatedSinceStart: 0 },
      });
      const bad = await call('put', `${BASE}/remediation-policy`, {
        perms: [WRITE],
        body: {
          mode: 'enforce',
          document,
          detectOnly: { until, then: 'remind' },
          reason: REASON,
          expectedRowVersion: null,
        },
      });
      expect(bad.status).toBe(422);
      expect(bad.body).toMatchObject({
        code: 'api_mode_detect_only_invalid',
        reason: 'mode_not_detect_only',
      });
      const view = await call('get', `${BASE}/remediation-policy`, { perms: [READ] });
      expect(view.body.domains[0]).toMatchObject({ detectOnly: { until, then: 'enforce' } });
      const onboardingView = await call('get', `${BASE}/domains/${ctx.domain}/onboarding`);
      expect(onboardingView.body.action).toMatchObject({
        source: 'domain',
        mode: 'detect_only',
        detectOnly: { until, then: 'enforce', ended: false },
      });
    });
  });
});
