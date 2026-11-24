/**
 * Step AI-R reports in chat on the real stack (docs/plan/steps/31-ai-chat-reports.md D2–D7, I15,
 * I16, §9 item 5; contracts §35.3; ADR-0095; the `testedBy` of the native tool `report_generate`
 * in docs/assistant/UI_TO_CHAT_CAPABILITY_MATRIX.md): real MySQL writer and replica, Redis and
 * MinIO (the mail bucket) from the local `.env`; the api listens on its ephemeral loopback port,
 * so every source read of a report goes through the real `/api/v1` pipeline with the caller's
 * bearer (guards, RBAC, tenant scope, rate limits, the reports cache); the provider is the
 * deterministic fake (`assertFakeProvider`), never a real LLM, and nothing reaches the internet.
 *
 * Seeded synthetic data across every report source (messages with verdicts and final actions in
 * the window, deliveries, scan rounds, quarantine entries, URL clicks, an attacked domain and an
 * ATO account whose display name holds `<script>` and `<img onerror>` text). Covered: a report
 * turn through a directive and through the demo intent (card, envelope figures equal to the
 * direct API responses of the same window, the object in MinIO with the stored SHA-256, the
 * HTML passes the `parse5` allow-list walk and carries the display name escaped, the audit rows
 * with the source statuses, the loopback reads and their correlation ids); a `report:read`-only
 * user (quarantine and ATO omitted with reason `permission` and NO loopback request to their
 * routes); the ATO feature off (`not_enabled`, the accounts list not read); the daily
 * generation limit (lowered in this suite's app config); a platform user without an override
 * (`denied_guard`); `GET /assistant/reports/{id}` for the owner, another user of the
 * organization and another organization; the retention purge and the conversation delete
 * (row `purged`, object deleted, `html: null`, a queued delivery `failed`); the organization
 * purge (rows and objects gone); the pending sweep. Synthetic `it-*` organizations and `.test`
 * / `.example` addresses only; every row and object version seeded here is removed.
 */
// @covers get /api/v1/assistant/reports/:reportId
// @covers post /api/v1/assistant/conversations/:conversationId/turns
// @covers delete /api/v1/assistant/conversations/:conversationId
// Native tool covered (no route): report_generate (AssistantNative_reportGenerate).
import { createHash } from 'node:crypto';
import {
  escapeHtml,
  parseSource,
  REPORT_SECTIONS,
  type ReportSourceKey,
  summaryCards,
  summaryFigures,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { systemScope } from '../src/auth-contracts/tenant-scope';
import { TransactionRunner } from '../src/database/transaction-runner';
import { ConversationsRepository } from '../src/modules/assistant/repositories/conversations.repository';
import { AssistantRetentionService } from '../src/modules/assistant/services/assistant-retention.service';
import {
  ReportObjectStore,
  reportObjectKey,
} from '../src/modules/assistant/services/reports/report-object-store';
import { IncidentStores } from '../src/modules/incidents/incident-stores';
import { AssistantTenantDataRepository } from '../src/modules/tenant-data/assistant-tenant-data.repository';
import type { IntegrationApp } from './support/app';
import {
  A,
  ALL_TENANT_PERMISSIONS,
  allFeatures,
  call,
  clearAssistantCounters,
  createAssistantApp,
  DAY_MS,
  DirectExecutor,
  directive,
  enableAssistant,
  envelopesOf,
  executionRow,
  generateReport,
  type Member,
  memberWith,
  newConversation,
  platformMember,
  principalOf,
  recordLoopback,
  reportHtmlProblems,
  reportObjectBytes,
  reportObjectExists,
  reportObjectKeys,
  reportObjectVersions,
  reportRow,
  REPORTS,
  seedDeliveries,
  trackReports,
  turn,
} from './support/assistant';
import { deleteAtoRows } from './support/ato';
import { createFixtures, type FixtureOrganization, type Fixtures } from './support/fixtures';
import {
  deleteInsightFixtures,
  HOUR_MS,
  insertClicks,
  insertDeliveries,
  insertDomain,
  insertMessages,
  insertQuarantineEntries,
  insertScanRounds,
  type MessageSpec,
  reader,
  waitFor as waitForCount,
} from './support/insights';

/** The ATO display name of the seeded high-risk account (I16: must reach the HTML escaped). */
const HOSTILE = 'Mallory <script>alert(1)</script> <img src=x onerror=alert(1)>';
/** The lowered daily generation limit of this suite's app (design §9 item 5). */
const PER_DAY = 3;

let ctx: IntegrationApp;
let fx: Fixtures;
let operator: Member;
let org: FixtureOrganization;
let offOrg: FixtureOrganization;
let otherOrg: FixtureOrganization;
let analyst: Member;
let colleague: Member;
let limited: Member;
let offUser: Member;
let foreigner: Member;
const orgIds: bigint[] = [];
let messageCount = 0;

async function enabledOrg(features: Record<string, boolean>): Promise<FixtureOrganization> {
  const created = await fx.createOrganization({ features, planCode: 'enterprise' });
  orgIds.push(created.id);
  return created;
}

beforeAll(async () => {
  ({ ctx } = await createAssistantApp({
    env: { ASSISTANT_REPORTS_PER_USER_PER_DAY: String(PER_DAY) },
  }));
  fx = createFixtures(ctx);
  trackReports(ctx, fx, orgIds);
  // ato_detection is on: the ATO reads and the live ato-worker (sign-ins) write ATO rows.
  fx.registerCleanup(() => deleteAtoRows(ctx.prisma, orgIds), { rerunOnConflict: true });
  fx.registerCleanup(() => deleteInsightFixtures(ctx, orgIds));
  operator = await platformMember(ctx, fx);

  org = await enabledOrg(allFeatures());
  offOrg = await enabledOrg({ ...allFeatures(), ato_detection: false });
  otherOrg = await enabledOrg(allFeatures());
  const all = { permissions: [...ALL_TENANT_PERMISSIONS] };
  analyst = await memberWith(ctx, fx, org, all);
  colleague = await memberWith(ctx, fx, org, all);
  limited = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
  offUser = await memberWith(ctx, fx, offOrg, all);
  foreigner = await memberWith(ctx, fx, otherOrg, all);
  await enableAssistant(ctx, operator, org, analyst);
  await enableAssistant(ctx, operator, offOrg, offUser);
  await enableAssistant(ctx, operator, otherOrg, foreigner);

  // Report sources: messages in the last three days (directions, verdicts, final actions, an
  // attacked domain), deliveries, scan rounds, quarantine entries and URL clicks.
  const domain = await insertDomain(ctx, org, `it-r-${org.slug.slice(3)}.example`);
  const now = Date.now();
  const specs: MessageSpec[] = [];
  const directions = ['inbound', 'outbound', 'internal'] as const;
  const verdicts = ['clean', 'spam', 'phishing', 'malware', 'clean', null] as const;
  const actions = ['deliver', 'quarantine', 'reject', 'deliver', 'deliver', null] as const;
  for (let i = 0; i < 36; i += 1) {
    specs.push({
      receivedAt: new Date(now - (2 * HOUR_MS + i * 3 * HOUR_MS)),
      direction: directions[i % 3]!,
      verdict: verdicts[i % verdicts.length]!,
      action: actions[i % actions.length]!,
      domainId: i % 2 === 0 ? domain.id : null,
    });
  }
  // Outside the 7-day window (must not count).
  specs.push({
    receivedAt: new Date(now - 9 * DAY_MS),
    direction: 'inbound',
    verdict: 'spam',
    action: 'quarantine',
  });
  const messages = await insertMessages(ctx, org, specs);
  messageCount = messages.length;
  const inWindow = messages.slice(0, 36);
  await insertDeliveries(
    ctx,
    org,
    inWindow.slice(0, 24).map((m, i) => ({
      message: m,
      status: i % 6 === 5 ? 'failed' : 'delivered',
      deliveredAfterMs: i % 6 === 5 ? null : 1_000 + i * 250,
    })),
  );
  await insertScanRounds(
    ctx,
    org,
    inWindow.slice(0, 30).map((m, i) => ({
      message: m,
      status: 'completed',
      completedAfterMs: 400 + i * 120,
    })),
  );
  await insertQuarantineEntries(ctx, org, [
    { quarantinedAt: new Date(now - 5 * HOUR_MS), reason: 'phishing', primaryEngine: 'url' },
    { quarantinedAt: new Date(now - 20 * HOUR_MS), reason: 'spam', primaryEngine: 'rspamd' },
    {
      quarantinedAt: new Date(now - 30 * HOUR_MS),
      reason: 'malware',
      primaryEngine: 'attachment',
    },
  ]);
  await insertClicks(ctx, org, [
    { clickedAt: new Date(now - 4 * HOUR_MS), decision: 'allowed' },
    { clickedAt: new Date(now - 6 * HOUR_MS), decision: 'blocked' },
    { clickedAt: new Date(now - 26 * HOUR_MS), decision: 'warned' },
  ]);

  // An ATO account of a gateway user whose display name carries markup (I16).
  const hostile = await fx.createUser(org, { roles: [], displayName: HOSTILE });
  const account = await ctx.prisma.$transaction((tx) =>
    ctx.get(IncidentStores).ato.ensureAccount(tx, {
      organizationId: org.id,
      subject: { kind: 'gateway_user', userId: hostile.id },
      at: new Date(),
    }),
  );
  await ctx.prisma.atoAccount.update({
    where: { id: account.id },
    data: { riskScore: 97, riskLevel: 'critical', riskUpdatedAt: new Date() },
  });

  const read = reader(ctx);
  await waitForCount(
    async () =>
      (await read.emailMessage.count({ where: { organizationId: org.id } })) +
      (await read.quarantineMessage.count({ where: { organizationId: org.id } })) +
      (await read.urlClickEvent.count({ where: { organizationId: org.id } })) +
      (await read.atoAccount.count({ where: { id: account.id, riskScore: 97 } })),
    messageCount + 3 + 3 + 1,
  );
}, 240_000);

afterAll(async () => {
  if (ctx) await clearAssistantCounters(ctx, orgIds);
  await fx?.cleanup();
  if (ctx) {
    // Nothing of this suite is left in the mail bucket.
    for (const id of orgIds) expect(await reportObjectKeys(ctx, id)).toEqual([]);
  }
  await ctx?.close();
});

const q = (path: string, params: Record<string, string>) =>
  `${path}?${new URLSearchParams(params).toString()}`;

/** The direct API responses of the report's window, as the portal's Reports page reads them. */
async function directSources(
  who: Member,
  period: { from: string; to: string; granularity: string; atoRange: string },
): Promise<Partial<Record<ReportSourceKey, unknown>>> {
  const window = { from: period.from, to: period.to };
  const withGranularity = { ...window, granularity: period.granularity };
  const paths: Array<[ReportSourceKey, string]> = [
    ['traffic', q('/api/v1/reports/traffic', withGranularity)],
    ['threats', q('/api/v1/reports/threats', window)],
    ['delivery', q('/api/v1/reports/delivery', withGranularity)],
    ['processing', q('/api/v1/reports/processing', withGranularity)],
    ['url_clicks', q('/api/v1/reports/url-clicks', withGranularity)],
    ['quarantine_summary', q('/api/v1/quarantine/summary', window)],
    ['ato_overview', q('/api/v1/ato/overview', { range: period.atoRange })],
  ];
  const out: Partial<Record<ReportSourceKey, unknown>> = {};
  for (const [key, path] of paths) {
    const res = await call(ctx, who.headers, 'get', path);
    expect(res.status, `${key}: ${JSON.stringify(res.body)}`).toBe(200);
    const parsed = parseSource(key, res.body);
    expect(parsed.ok, key).toBe(true);
    if (parsed.ok) out[key] = parsed.data;
  }
  return out;
}

const envelopeOf = async (turnId: string) =>
  (await envelopesOf(ctx, turnId)).find((e) => e.parsed.tool === 'report_generate')!.parsed;

/** The conversation's internal id and the scoped content purge of the retention job. */
async function purgeConversation(publicId: string, organizationId: bigint, now = new Date()) {
  const row = await ctx.prisma.aiChatConversation.findUniqueOrThrow({ where: { publicId } });
  await ctx.prisma.aiChatConversation.update({
    where: { id: row.id },
    data: { purgeAfter: new Date(now.getTime() - 60_000) },
  });
  const repo = ctx.get(ConversationsRepository);
  return ctx.get(TransactionRunner).run(async (tx) => {
    const still = await repo.lockDueForContentPurge(organizationId, [row.id], now, tx);
    await repo.purgeContent(organizationId, still, now, tx);
    return still;
  });
}

describe('report_generate on the real stack (D2, D3, I15, I16)', () => {
  it('a directive turn builds the report from the API, stores the inert HTML in MinIO and audits it', async () => {
    const conversation = await newConversation(ctx, analyst);
    const recorder = recordLoopback(ctx);
    let generated;
    try {
      generated = await generateReport(ctx, analyst, conversation, { args: { range: '7d' } });
    } finally {
      recorder.restore();
    }
    const { res, execution, report } = generated;
    expect(execution).toMatchObject({
      tool: 'report_generate',
      operationId: 'AssistantNative_reportGenerate',
      decision: 'allowed',
      status: 'succeeded',
      httpStatus: 201,
      card: { kind: 'report', status: 'ok', tool: 'report_generate' },
    });
    expect(report.sections).toEqual([...REPORT_SECTIONS]);
    expect(report.omitted).toEqual([]);
    expect(report.period).toMatchObject({ granularity: 'day', atoRange: '7d' });
    expect(Date.parse(report.period.to) - Date.parse(report.period.from)).toBe(7 * DAY_MS);
    expect(execution.card).toMatchObject({
      portalLinks: [{ label: 'Open full size', href: `/assistant/reports/${report.reportId}` }],
    });
    expect(JSON.stringify(execution.card)).not.toMatch(/<html|<svg/i);

    // The envelope carries the same figures as the card and no HTML (I15).
    const envelope = await envelopeOf(res.body.turn.id as string);
    expect(envelope).toMatchObject({ status: 'ok', httpStatus: 201, returned: 1 });
    const data = envelope.data as Record<string, unknown>;
    expect(data.reportId).toBe(report.reportId);
    expect(data.figures).toEqual(report.figures);
    expect(JSON.stringify(envelope)).not.toMatch(/<html|<svg|<script/i);

    // Every figure equals the direct API responses of the same window.
    const direct = await directSources(analyst, report.period);
    const expected = summaryFigures(summaryCards(direct as Parameters<typeof summaryCards>[0]));
    expect(report.figures).toEqual(expected);
    const traffic = direct.traffic as { totals: { total: number } };
    const quarantine = direct.quarantine_summary as { counts: { held?: number } };
    const figure = (label: string) => report.figures.find((f) => f.label === label)?.value;
    expect(figure('Messages')).toBe(traffic.totals.total.toLocaleString('en-US'));
    expect(traffic.totals.total).toBe(36);
    expect(figure('Held in quarantine')).toBe(String(quarantine.counts.held ?? 0));
    expect(figure('High-risk accounts')).toBeDefined();

    // The sources were read through the loopback with the user's bearer (GETs under /api/v1),
    // each with its own correlation id `<base>.<seq>.<n>`.
    const sources = recorder.calls.filter((c) => c.path !== '/api/v1/auth/me');
    expect(sources.length).toBe(9);
    expect(sources.every((c) => c.method === 'GET' && c.path.startsWith('/api/v1/'))).toBe(true);
    for (const path of [
      '/api/v1/reports/traffic',
      '/api/v1/reports/threats',
      '/api/v1/reports/top-domains',
      '/api/v1/reports/delivery',
      '/api/v1/reports/processing',
      '/api/v1/reports/url-clicks',
      '/api/v1/quarantine/summary',
      '/api/v1/ato/overview',
      '/api/v1/ato/accounts',
    ]) {
      expect(
        sources.some((c) => c.path.startsWith(path)),
        path,
      ).toBe(true);
    }
    expect(new Set(sources.map((c) => c.correlationId)).size).toBe(sources.length);
    expect(sources.every((c) => /\.\d+\.\d+$/.test(c.correlationId))).toBe(true);

    // The row and the object: metadata in MySQL, the HTML in the mail bucket with its SHA-256.
    const row = await reportRow(ctx, report.reportId);
    const executionRowId = (await executionRow(ctx, execution.id)).id;
    expect(row).toMatchObject({
      organizationId: org.id,
      userId: analyst.user.id,
      status: 'available',
      executionId: executionRowId,
      templateVersion: 'assistant-report/1',
      sizeBytes: report.sizeBytes,
      purgedAt: null,
      objectDeletedAt: null,
    });
    expect(row.objectKey).toBe(
      reportObjectKey(org.id, report.reportId, new Date(report.generatedAt)),
    );
    const bytes = await reportObjectBytes(ctx, row.objectKey!);
    expect(bytes.length).toBe(row.sizeBytes);
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(row.sha256);
    const html = bytes.toString('utf8');
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(reportHtmlProblems(html)).toEqual([]);
    // The hostile display name is in the report, escaped, never as markup.
    expect(html).toContain(escapeHtml(HOSTILE));
    expect(html).not.toContain('<script>alert(1)</script>');
    // `onerror=` survives only as escaped text (`&lt;img … onerror=…&gt;`), never as markup.
    expect(html).not.toMatch(/<img|\sonerror="/i);
    expect(html).toContain('Accounts at highest takeover risk');

    // Audit: the tool execution and the report with the source statuses (D11).
    const audit = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, resourceId: { in: [execution.id, report.reportId] } },
      orderBy: { id: 'asc' },
    });
    expect(audit.map((a) => a.action).sort()).toEqual([
      'assistant.report_generated',
      'assistant.tool_executed',
    ]);
    const generatedAudit = audit.find((a) => a.action === 'assistant.report_generated')!;
    expect(generatedAudit.resourceType).toBe('assistant_report');
    const meta = generatedAudit.metadata as Record<string, unknown>;
    expect(meta).toMatchObject({
      reportId: report.reportId,
      conversationId: conversation,
      executionId: execution.id,
      sizeBytes: report.sizeBytes,
      sha256: row.sha256,
      templateVersion: 'assistant-report/1',
      sections: [...REPORT_SECTIONS],
      omitted: [],
    });
    const audited = meta.sources as Array<{ tool: string; outcome: string; httpStatus: number }>;
    expect(audited.map((s) => s.tool).sort()).toEqual(
      [
        'ato_accounts_list',
        'ato_overview_overview',
        'quarantine_tools_summary',
        'reports_delivery',
        'reports_processing',
        'reports_threats',
        'reports_top_domains',
        'reports_traffic',
        'reports_url_clicks',
      ].sort(),
    );
    expect(audited.every((s) => s.outcome === 'ok' && s.httpStatus === 200)).toBe(true);
    // Metadata only: no HTML and no display name in MySQL (I5).
    expect(JSON.stringify(meta)).not.toContain('Mallory');
    expect(
      JSON.stringify({ sections: row.sections, figures: row.figures, title: row.title }),
    ).not.toContain('Mallory');

    // GET as the owner: the view and the same HTML, inside JSON, never cached.
    const view = await call(ctx, analyst.headers, 'get', `${REPORTS}/${report.reportId}`);
    expect(view.status).toBe(200);
    expect(view.headers['cache-control']).toBe('no-store');
    expect(view.headers['content-type']).toMatch(/^application\/json/);
    expect(view.body.html).toBe(html);
    expect(view.body.report).toMatchObject({
      id: report.reportId,
      conversationId: conversation,
      executionId: execution.id,
      status: 'available',
      sections: [...REPORT_SECTIONS],
      omitted: [],
      figures: report.figures,
      sizeBytes: report.sizeBytes,
      sha256: row.sha256,
      templateVersion: 'assistant-report/1',
      deliveries: [],
    });
  });

  it('the demo intent "generate a security report" builds the same report and the fake cites only its figures', async () => {
    const conversation = await newConversation(ctx, colleague);
    const { res, report } = await generateReport(ctx, colleague, conversation, {
      message: 'generate a security report',
    });
    expect(report.period.label).toBe('Last 7 days');
    const messages = report.figures.find((f) => f.label === 'Messages')!.value;
    expect(res.body.message.content).toContain('Your security report for the last 7 days');
    expect(res.body.message.content).toContain(messages);
    const html = (await call(ctx, colleague.headers, 'get', `${REPORTS}/${report.reportId}`)).body
      .html as string;
    expect(reportHtmlProblems(html)).toEqual([]);
    expect(html).toContain(escapeHtml(HOSTILE));
  });

  it('a report:read-only user: quarantine and ATO omitted for permission, their routes never requested', async () => {
    const conversation = await newConversation(ctx, limited);
    const recorder = recordLoopback(ctx);
    let generated;
    try {
      generated = await generateReport(ctx, limited, conversation);
    } finally {
      recorder.restore();
    }
    const { report } = generated;
    expect(report.omitted).toEqual(
      expect.arrayContaining([
        { section: 'quarantine', reason: 'permission', code: 'quarantine:read' },
        { section: 'ato', reason: 'permission', code: 'ato:read' },
      ]),
    );
    expect(report.sections).not.toContain('quarantine');
    expect(report.sections).not.toContain('ato');
    expect(report.sections).toContain('traffic');
    expect(recorder.calls.filter((c) => /^\/api\/v1\/(quarantine|ato)\//.test(c.path))).toEqual([]);
    expect(recorder.calls.some((c) => c.path.startsWith('/api/v1/reports/traffic'))).toBe(true);
    expect(report.figures.map((f) => f.label)).not.toContain('Held in quarantine');
    const html = (await call(ctx, limited.headers, 'get', `${REPORTS}/${report.reportId}`)).body
      .html as string;
    expect(reportHtmlProblems(html)).toEqual([]);
    expect(html).not.toContain('Mallory');
    expect(html).toContain('Not included');
  });

  it('the ATO feature off: the section is omitted as not_enabled and the accounts list is not read', async () => {
    const conversation = await newConversation(ctx, offUser);
    const recorder = recordLoopback(ctx);
    let generated;
    try {
      generated = await generateReport(ctx, offUser, conversation, { args: { range: '24h' } });
    } finally {
      recorder.restore();
    }
    expect(generated.report.omitted).toEqual([{ section: 'ato', reason: 'not_enabled' }]);
    expect(generated.report.period).toMatchObject({ granularity: 'hour', atoRange: '24h' });
    expect(recorder.calls.some((c) => c.path.startsWith('/api/v1/ato/overview'))).toBe(true);
    expect(recorder.calls.some((c) => c.path.startsWith('/api/v1/ato/accounts'))).toBe(false);
  });

  it(`refuses the ${PER_DAY + 1}th report of a user on the same UTC day (denied_budget)`, async () => {
    const user = await memberWith(ctx, fx, org, { permissions: ['report:read'] });
    const conversation = await newConversation(ctx, user);
    for (let i = 0; i < PER_DAY; i += 1) {
      await generateReport(ctx, user, conversation, { args: { sections: ['traffic'] } });
    }
    const res = await turn(
      ctx,
      user.headers,
      conversation,
      directive('report_generate', { sections: ['traffic'] }),
    );
    expect(res.status).toBe(200);
    expect(res.body.executions[0]).toMatchObject({
      tool: 'report_generate',
      decision: 'denied_budget',
      status: 'refused',
      errorCode: 'assistant_report_generation_limit',
      card: null,
    });
    expect(
      await ctx.prisma.aiChatReport.count({
        where: { organizationId: org.id, userId: user.user.id },
      }),
    ).toBe(PER_DAY);
    const denied = await ctx.prisma.auditLog.findMany({
      where: { organizationId: org.id, resourceId: res.body.executions[0].id as string },
    });
    expect(denied.map((a) => a.action)).toEqual(['assistant.tool_denied']);
  });

  it('refuses a platform principal without an override (report_needs_organization)', async () => {
    const admin = await platformMember(ctx, fx, ['super_admin']);
    const executor = new DirectExecutor(ctx, admin, await principalOf(ctx, admin.token), org);
    const outcome = await executor.execute('report_generate', {});
    expect(outcome).toMatchObject({ decision: 'denied_guard', status: 'refused' });
    expect(await ctx.prisma.aiChatReport.count({ where: { userId: admin.user.id } })).toBe(0);
    const audit = await ctx.prisma.auditLog.findFirstOrThrow({
      where: { resourceId: outcome.executionId, action: 'assistant.tool_denied' },
    });
    expect(audit.metadata).toMatchObject({ guard: 'report_needs_organization' });
  });
});

describe('GET /assistant/reports/{reportId} (§4.1, owner only)', () => {
  it('answers the owner only: another user of the organization and another organization get 404', async () => {
    const conversation = await newConversation(ctx, analyst);
    const { report } = await generateReport(ctx, analyst, conversation, {
      args: { sections: ['summary', 'traffic'] },
    });
    const path = `${REPORTS}/${report.reportId}`;
    expect((await call(ctx, analyst.headers, 'get', path)).status).toBe(200);
    for (const who of [colleague, foreigner]) {
      const res = await call(ctx, who.headers, 'get', path);
      expect(res.status).toBe(404);
      expect(res.body.code).toBe('assistant_report_not_found');
      expect(JSON.stringify(res.body)).not.toContain('<!doctype');
    }
    expect((await call(ctx, analyst.headers, 'get', `${REPORTS}/not-a-uuid`)).status).toBe(400);
    expect((await ctx.http.get(path)).status).toBe(401);
  });
});

describe('retention and purge (D7, R-7)', () => {
  it('the content purge marks the report purged, deletes its object and fails its queued delivery', async () => {
    const conversation = await newConversation(ctx, analyst);
    const { report } = await generateReport(ctx, analyst, conversation, {
      args: { sections: ['traffic'] },
    });
    const before = await reportRow(ctx, report.reportId);
    await seedDeliveries(ctx, before, analyst.user.id, 1);
    await ctx.prisma.aiChatReportDelivery.updateMany({
      where: { reportId: before.id },
      data: { status: 'queued', sentAt: null },
    });
    expect(await reportObjectExists(ctx, before.objectKey!)).toBe(true);

    const now = new Date();
    expect(await purgeConversation(conversation, org.id, now)).toHaveLength(1);
    const purged = await reportRow(ctx, report.reportId);
    expect(purged).toMatchObject({ status: 'purged' });
    expect(purged.purgedAt).not.toBeNull();
    const delivery = await ctx.prisma.aiChatReportDelivery.findFirstOrThrow({
      where: { reportId: before.id },
    });
    expect(delivery).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_purged',
      recipientAddress: null,
    });
    // After the commit the job deletes the objects of purged reports.
    await ctx.get(AssistantRetentionService).deletePurgedReportObjects(now);
    const done = await reportRow(ctx, report.reportId);
    expect(done.objectKey).toBeNull();
    expect(done.objectDeletedAt).not.toBeNull();
    expect(await reportObjectExists(ctx, before.objectKey!)).toBe(false);
    expect(await reportObjectVersions(ctx, before.objectKey!)).toBe(0);
    const view = await call(ctx, analyst.headers, 'get', `${REPORTS}/${report.reportId}`);
    expect(view.status).toBe(200);
    expect(view.body.html).toBeNull();
    expect(view.body.report).toMatchObject({ status: 'purged' });
    expect(view.body.report.deliveries).toEqual([
      expect.objectContaining({ to: null, status: 'failed', errorCode: 'assistant_report_purged' }),
    ]);
  });

  it('DELETE of the conversation purges its reports and deletes their objects right away', async () => {
    const conversation = await newConversation(ctx, colleague);
    const { report } = await generateReport(ctx, colleague, conversation, {
      args: { sections: ['threats'] },
    });
    const before = await reportRow(ctx, report.reportId);
    const res = await call(ctx, colleague.headers, 'delete', `${A}/conversations/${conversation}`);
    expect(res.status).toBeLessThan(300);
    const after = await reportRow(ctx, report.reportId);
    expect(after.status).toBe('purged');
    expect(after.objectKey).toBeNull();
    expect(after.objectDeletedAt).not.toBeNull();
    expect(await reportObjectExists(ctx, before.objectKey!)).toBe(false);
    expect(await reportObjectVersions(ctx, before.objectKey!)).toBe(0);
    const view = await call(ctx, colleague.headers, 'get', `${REPORTS}/${report.reportId}`);
    // The row stays (metadata) until the hard delete: the card shows the purged state.
    expect(view.status).toBe(200);
    expect(view.body).toMatchObject({ html: null, report: { status: 'purged' } });
  });

  it('sweeps a pending report older than one hour: object deleted, row failed (abandoned)', async () => {
    const conversation = await newConversation(ctx, analyst);
    await turn(ctx, analyst.headers, conversation, '/text a conversation for the sweep');
    const convo = await ctx.prisma.aiChatConversation.findUniqueOrThrow({
      where: { publicId: conversation },
    });
    const createdAt = new Date(Date.now() - 2 * HOUR_MS);
    const publicId = uuidv7(createdAt.getTime());
    const key = reportObjectKey(org.id, publicId, createdAt);
    const bytes = Buffer.from('<!doctype html><html><body>abandoned</body></html>', 'utf8');
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    await ctx.get(ReportObjectStore).put(org.id, key, bytes, sha256);
    await ctx.prisma.aiChatReport.create({
      data: {
        publicId,
        organizationId: org.id,
        userId: analyst.user.id,
        conversationId: convo.id,
        status: 'pending',
        title: 'Security report: Last 7 days',
        periodFrom: new Date(createdAt.getTime() - 7 * DAY_MS),
        periodTo: createdAt,
        granularity: 'day',
        sections: { included: ['traffic'], omitted: [] },
        figures: [],
        templateVersion: 'assistant-report/1',
        objectKey: key,
        sizeBytes: bytes.length,
        sha256,
        createdAt,
      },
    });
    expect(await reportObjectExists(ctx, key)).toBe(true);
    await ctx.get(AssistantRetentionService).sweepPendingReports(new Date());
    // The Compose api's own retention job may have swept it first: the outcome is the same.
    const row = await reportRow(ctx, publicId);
    expect(row).toMatchObject({ status: 'failed', errorCode: 'assistant_report_abandoned' });
    expect(await reportObjectExists(ctx, key)).toBe(false);
    expect(await reportObjectVersions(ctx, key)).toBe(0);
  });

  it('the organization purge deletes the report rows, the deliveries and the objects', async () => {
    const target = await enabledOrg(allFeatures());
    const admin = await memberWith(ctx, fx, target, { permissions: [...ALL_TENANT_PERMISSIONS] });
    await enableAssistant(ctx, operator, target, admin);
    const conversation = await newConversation(ctx, admin);
    const { report } = await generateReport(ctx, admin, conversation, {
      args: { sections: ['traffic'] },
    });
    const row = await reportRow(ctx, report.reportId);
    await seedDeliveries(ctx, row, admin.user.id, 2);
    expect(await reportObjectKeys(ctx, target.id)).toEqual([row.objectKey]);
    const keptBefore = await ctx.prisma.aiChatReport.count({ where: { organizationId: org.id } });

    const counts = await ctx
      .get(AssistantTenantDataRepository)
      .purgeOrganization(systemScope(target.id));
    expect(counts).toMatchObject({
      ai_chat_report_deliveries: 2,
      ai_chat_reports: 1,
      reportObjects: 1,
    });
    const where = { where: { organizationId: target.id } };
    expect(await ctx.prisma.aiChatReport.count(where)).toBe(0);
    expect(await ctx.prisma.aiChatReportDelivery.count(where)).toBe(0);
    expect(await reportObjectExists(ctx, row.objectKey!)).toBe(false);
    expect(await reportObjectVersions(ctx, row.objectKey!)).toBe(0);
    expect(await reportObjectKeys(ctx, target.id)).toEqual([]);
    // Another organization's reports stay.
    expect(await ctx.prisma.aiChatReport.count({ where: { organizationId: org.id } })).toBe(
      keptBefore,
    );
    const again = await ctx
      .get(AssistantTenantDataRepository)
      .purgeOrganization(systemScope(target.id));
    expect(Object.values(again).every((n) => n === 0)).toBe(true);
  });
});
