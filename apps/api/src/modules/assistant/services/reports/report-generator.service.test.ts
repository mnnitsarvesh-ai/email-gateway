import { findTool, REPORT_SOURCE_DEFS, type ReportSourceKey } from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { testUser } from '../../../../../test/support/assistant-fixtures';
import { reportSourceBodies } from '../../../../../test/support/assistant-report-fixtures';
import { createAssistantHarness } from '../../../../../test/support/assistant-harness';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import { scopeFromPrincipal } from '../../../../auth-contracts/tenant-scope';
import { CORRELATION_ID_PATTERN } from '../../assistant.constants';
import { sourceCorrelationId } from '../../domain/correlation';
import { ownerOf } from '../conversation.service';
import type { ExecutionContext } from '../tool-executor.service';
import { isReportKeyOf } from './report-object-store';

const ALL = ['assistant:use', 'report:read', 'quarantine:read', 'ato:read'];
const NOW = new Date('2026-11-23T09:00:30.000Z');
const WINDOW = { from: '2026-11-16T09:00:00.000Z', to: '2026-11-23T09:00:00.000Z' };

const pathOf = (key: ReportSourceKey): string =>
  findTool(REPORT_SOURCE_DEFS[key].tool)!.pathTemplate;

function setup(
  principal: UserPrincipal = testUser({ permissions: new Set(ALL) }),
  env: Record<string, string> = {},
  bodies: Record<string, unknown> = reportSourceBodies(WINDOW),
) {
  const h = createAssistantHarness(env, undefined, principal);
  h.generator.now = () => NOW;
  const owner = ownerOf(principal, scopeFromPrincipal(principal));
  const conversation = h.world.addConversation(owner);
  for (const key of Object.keys(REPORT_SOURCE_DEFS) as ReportSourceKey[]) {
    h.loopback.on(`GET ${pathOf(key)}`, () => ({
      kind: 'response',
      status: 200,
      body: bodies[key],
    }));
  }
  let seq = 1;
  const ctx = (overrides: Partial<ExecutionContext> = {}): ExecutionContext => ({
    principal,
    owner,
    conversationId: conversation.id,
    conversationPublicId: conversation.publicId,
    turnId: null,
    turnPublicId: null,
    parentExecutionId: null,
    parentExecutionPublicId: null,
    authorization: 'Bearer it-access-token',
    clientIp: '198.51.100.7',
    correlationBase: 'it-corr-0001',
    signal: new AbortController().signal,
    allocateSeq: () => seq++,
    organizationName: 'IT Org <script>',
    ...overrides,
  });
  const generate = (args: Record<string, unknown> = {}, c = ctx()) =>
    h.executor.execute(c, { name: 'report_generate', arguments: args }, 0);
  return { h, owner, conversation, ctx, generate };
}

describe('report_generate (step AI-R D2)', () => {
  it('reads every source internally, stores the HTML and records card, envelope, refs, row and audit', async () => {
    const { h, generate, conversation } = setup();
    const out = await generate();
    expect(out).toMatchObject({ decision: 'allowed', status: 'succeeded', httpStatus: 201 });
    // The card (no HTML), the envelope with the server's figures and the ref r1.1.
    expect(out.card).toMatchObject({ kind: 'report', status: 'ok', refs: ['r1.1'] });
    const report = out.card!.report!;
    expect(report.sections).toContain('traffic');
    expect(report.omitted).toEqual([]);
    expect(JSON.stringify(out.card)).not.toContain('<html');
    expect(out.envelope).toMatchObject({ status: 'ok', httpStatus: 201, ref: 'r1' });
    expect((out.envelope as unknown as { data: { reportId: string } }).data.reportId).toBe(
      report.reportId,
    );
    expect(out.card!.portalLinks).toEqual([
      { label: 'Open full size', href: `/assistant/reports/${report.reportId}` },
    ]);

    // Internal GET reads with the turn's credential, the execution header and <base>.<seq>.<n>.
    const calls = h.loopback.toolCalls;
    expect(calls.length).toBe(9);
    expect(calls.every((c) => c.method === 'GET' && c.executionId === out.executionId)).toBe(true);
    expect(calls.every((c) => c.authorization === 'Bearer it-access-token')).toBe(true);
    const ids = calls.map((c) => c.correlationId);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^it-corr-0001\.1\.\d$/);
      expect(CORRELATION_ID_PATTERN.test(id)).toBe(true);
    }
    expect(calls.some((c) => c.path.startsWith('native:'))).toBe(false);

    // Storage order: pending row → object → available in the persist transaction.
    const rw = h.world.reportWorld;
    expect(rw.log.filter((l) => !l.startsWith('lock'))).toEqual([
      'insertPending',
      expect.stringMatching(
        /^put:org\/7001\/assistant\/report\/2026\/11\/23\/[0-9a-f-]{36}\.html$/,
      ),
      'markAvailable',
    ]);
    const row = rw.reports[0]!;
    expect(row).toMatchObject({
      publicId: report.reportId,
      status: 'available',
      conversationId: conversation.id,
      granularity: 'day',
      templateVersion: 'assistant-report/1',
    });
    expect(row.executionId).toBe(
      h.world.executions.find((e) => e.publicId === out.executionId)!.id,
    );
    expect(isReportKeyOf(row.objectKey!, 7001n)).toBe(true);
    const html = rw.objects.get(row.objectKey!)!.toString('utf8');
    expect(html.startsWith('<!doctype html>')).toBe(true);
    expect(html).not.toContain('<script');
    expect(html).toContain('IT Org &lt;script&gt;');
    expect(row.sizeBytes).toBe(Buffer.byteLength(html));

    // Execution row with the report ref; audits tool_executed then report_generated.
    const stored = h.world.executions.find((e) => e.publicId === out.executionId)!;
    expect(stored).toMatchObject({
      operationId: 'AssistantNative_reportGenerate',
      httpMethod: 'POST',
      httpStatus: 201,
      decision: 'allowed',
      status: 'succeeded',
    });
    expect(stored.resultRefs).toEqual({
      'r1.1': { resourceType: 'assistant_report', publicId: report.reportId },
    });
    expect(h.audit.entries.map((e) => e.action)).toEqual([
      'assistant.tool_executed',
      'assistant.report_generated',
    ]);
    const meta = h.audit.entries[1]!.metadata as Record<string, unknown>;
    expect(h.audit.entries[1]).toMatchObject({
      resourceType: 'assistant_report',
      resourceId: report.reportId,
    });
    expect(meta).toMatchObject({
      reportId: report.reportId,
      conversationId: conversation.publicId,
      executionId: out.executionId,
      sha256: row.sha256,
      sizeBytes: row.sizeBytes,
      templateVersion: 'assistant-report/1',
    });
    // Nine sources read; the step API-3 overview (api_mode section) is recorded as skipped for a
    // principal without remediation:read.
    expect((meta.sources as unknown[]).length).toBe(10);
    expect(report.sections).toContain('api_mode');
    expect(JSON.stringify(meta)).not.toContain('org/7001');
  });

  it('never requests a source the principal may not read (omitted with reason permission)', async () => {
    const { h, generate } = setup(
      testUser({ permissions: new Set(['assistant:use', 'report:read']) }),
    );
    const out = await generate();
    expect(out.status).toBe('succeeded');
    const paths = h.loopback.toolCalls.map((c) => c.path.split('?')[0]);
    expect(paths).not.toContain(pathOf('quarantine_summary'));
    expect(paths).not.toContain(pathOf('ato_overview'));
    expect(paths).not.toContain(pathOf('ato_accounts'));
    expect(out.card!.report!.omitted).toEqual(
      expect.arrayContaining([
        { section: 'quarantine', reason: 'permission', code: 'quarantine:read' },
        { section: 'ato', reason: 'permission', code: 'ato:read' },
      ]),
    );
  });

  it('reads the ATO accounts only when monitoring is on (feature off → not_enabled)', async () => {
    const { h, generate } = setup(undefined, {}, reportSourceBodies(WINDOW, { atoFeature: false }));
    const out = await generate();
    const paths = h.loopback.toolCalls.map((c) => c.path.split('?')[0]);
    expect(paths).toContain(pathOf('ato_overview'));
    expect(paths).not.toContain(pathOf('ato_accounts'));
    expect(out.card!.report!.omitted).toContainEqual({ section: 'ato', reason: 'not_enabled' });
  });

  it('omits a source that answers non-2xx with its code; a 401 ends the turn (no report)', async () => {
    const { h, generate } = setup();
    h.loopback.on(`GET ${pathOf('traffic')}`, () => ({
      kind: 'response',
      status: 503,
      body: { code: 'report_timeout', message: 'x' },
    }));
    const omitted = await generate();
    expect(omitted.card!.report!.omitted).toContainEqual({
      section: 'traffic',
      reason: 'unavailable',
      code: 'report_timeout',
    });

    const second = setup();
    second.h.loopback.on(`GET ${pathOf('threats')}`, () => ({
      kind: 'response',
      status: 401,
      body: { code: 'unauthorized' },
    }));
    const expired = await second.generate();
    expect(expired.sessionExpired).toBe(true);
    expect(expired.httpStatus).toBe(401);
    expect(second.h.world.reportWorld.reports).toHaveLength(0);
  });

  it('a parse failure omits the sections (unexpected_response); every source failing → 503', async () => {
    const { generate } = setup(
      undefined,
      {},
      {
        ...reportSourceBodies(WINDOW),
        delivery: { unexpected: true },
      },
    );
    const out = await generate();
    expect(out.card!.report!.omitted).toContainEqual({
      section: 'delivery',
      reason: 'unexpected_response',
    });

    const none = setup(undefined, {}, {});
    const failed = await none.generate({ sections: ['traffic', 'threats'] });
    expect(failed).toMatchObject({
      decision: 'allowed',
      status: 'failed',
      httpStatus: 503,
      errorCode: 'assistant_report_sources_unavailable',
    });
    expect(none.h.world.reportWorld.reports).toHaveLength(0);
    expect(none.h.world.reportWorld.objects.size).toBe(0);
  });

  it('a failed PutObject fails the execution (502 assistant_report_storage_failed) and the row', async () => {
    const { h, generate } = setup();
    h.world.reportWorld.failNext.put = true;
    const out = await generate();
    expect(out).toMatchObject({
      status: 'failed',
      httpStatus: 502,
      errorCode: 'assistant_report_storage_failed',
    });
    expect(h.world.reportWorld.reports[0]).toMatchObject({
      status: 'failed',
      errorCode: 'assistant_report_storage_failed',
    });
    expect(h.audit.entries.map((e) => e.action)).toEqual(['assistant.tool_executed']);
  });

  it('the per-user daily limit is denied_budget (assistant_report_generation_limit), nothing read', async () => {
    const { h, generate } = setup(undefined, { ASSISTANT_REPORTS_PER_USER_PER_DAY: '1' });
    expect((await generate()).status).toBe('succeeded');
    h.loopback.calls.length = 0;
    const out = await generate();
    expect(out).toMatchObject({
      decision: 'denied_budget',
      status: 'refused',
      errorCode: 'assistant_report_generation_limit',
    });
    expect(out.envelope).toMatchObject({
      status: 'denied',
      code: 'assistant_report_generation_limit',
    });
    expect(h.loopback.toolCalls).toHaveLength(0);
  });

  it('a platform user without an override is denied_guard (report_needs_organization)', async () => {
    const operator = testUser({ organizationKind: 'platform', permissions: new Set(ALL) });
    const { h, generate } = setup(operator);
    const out = await generate();
    expect(out.decision).toBe('denied_guard');
    expect(out.denialMessage).toMatch(/platform override/);
    expect(h.loopback.toolCalls).toHaveLength(0);
    expect(h.audit.entries[0]!.metadata).toMatchObject({ guard: 'report_needs_organization' });
  });

  it('an invalid explicit window is denied_schema; ASSISTANT_REPORTS_ENABLED=false hides the tool', async () => {
    const { generate } = setup();
    const out = await generate({ from: '2026-11-23T00:00:00Z', to: '2026-11-22T00:00:00Z' });
    expect(out.decision).toBe('denied_schema');

    const off = setup(undefined, { ASSISTANT_REPORTS_ENABLED: 'false' });
    expect((await off.generate()).decision).toBe('denied_disabled');
    expect(off.h.conversations.tools(off.h.user).tools.map((t) => t.name)).not.toContain(
      'report_generate',
    );
  });

  it('is offered in the catalogue to report:read holders only', () => {
    const { h } = setup();
    expect(h.conversations.tools(h.user).tools.map((t) => t.name)).toEqual(
      expect.arrayContaining(['report_generate', 'report_send_email']),
    );
    const other = setup(testUser({ permissions: new Set(['assistant:use']) }));
    expect(other.h.conversations.tools(other.h.user).tools.map((t) => t.name)).not.toContain(
      'report_generate',
    );
  });
});

describe('sourceCorrelationId', () => {
  it('keeps the .<seq>.<n> tail within the correlation id pattern', () => {
    expect(sourceCorrelationId('it-corr-0001', 4, 2)).toBe('it-corr-0001.4.2');
    const long = sourceCorrelationId('a'.repeat(128), 123, 9);
    expect(long.length).toBe(128);
    expect(long.endsWith('.123.9')).toBe(true);
    expect(CORRELATION_ID_PATTERN.test(long)).toBe(true);
    expect(sourceCorrelationId('bad id!', 1, 1)).toBe('assistant.1.1');
  });
});
