import { describe, expect, it } from 'vitest';
import { FakeProvider } from '../providers/fake';
import { META_TOOLS, parseMetaToolInput } from '../providers/meta-tools';
import type { LlmRequest, LlmResponse } from '../providers/types';
import { enabledTools, findTool, renderCatalogueIndex } from '../registry/registry';
import {
  REPORT_QUEUED_NOTE,
  reportCard,
  reportQueuedCard,
  reportQueuedEnvelope,
  reportRefs,
} from '../results/card';
import { REPORT_CARD_STATUSES } from '../results/types';
import {
  FIXTURE_GENERATED_AT,
  FIXTURE_ORGANIZATION,
  WINDOW_7D,
  okResults,
} from './fixtures.test-support';
import { buildReportModel, reportDigestOf } from './model';
import { REPORT_SOURCES, reportJobRoutePaths } from './sources';
import { REPORT_SECTIONS } from './types';

/**
 * Step AI-6 D5: background report jobs in the package: the queued card and envelope, the
 * job-token route allow-list derived from the source plan and the fake's queued answer.
 */

const REPORT_ID = '0193aaaa-0000-7000-8000-000000000002';
const PERIOD_30D = {
  from: '2026-10-24T09:00:00.000Z',
  to: '2026-11-23T09:00:00.000Z',
  granularity: 'day' as const,
  atoRange: '30d' as const,
  label: 'Last 30 days',
};
const queuedInput = {
  executionId: '0193aaaa-0000-7000-8000-0000000000e2',
  refSeq: 6,
  report: {
    reportId: REPORT_ID,
    title: 'Security report: Last 30 days',
    period: PERIOD_30D,
    sections: [...REPORT_SECTIONS],
  },
};

describe('queued report card and envelope', () => {
  it('card: kind report, status queued, no figures, the full-size link and the row ref', () => {
    const card = reportQueuedCard(queuedInput);
    expect(card).toMatchSnapshot();
    expect(card.report).toMatchObject({
      status: 'queued',
      figures: [],
      omitted: [],
      sizeBytes: 0,
    });
    expect(card.refs).toEqual(['r6.1']);
    expect(reportRefs(6, REPORT_ID)).toEqual({
      'r6.1': { resourceType: 'assistant_report', publicId: REPORT_ID },
    });
  });

  it('envelope: ok, HTTP 202, data { ref, reportId, status, title, period, sections }, the queued note', () => {
    const envelope = reportQueuedEnvelope(queuedInput);
    expect(envelope).toMatchSnapshot();
    expect(envelope).toMatchObject({
      status: 'ok',
      httpStatus: 202,
      ref: 'r6',
      note: REPORT_QUEUED_NOTE,
    });
    expect(Object.keys(envelope.data as object)).toEqual([
      'ref',
      'reportId',
      'status',
      'title',
      'period',
      'sections',
    ]);
    expect(JSON.stringify(envelope.data)).not.toContain('figures');
    expect(REPORT_QUEUED_NOTE).toBe(
      'The report is being generated in the background and appears in the chat when it is ready. Do not state any figures for it.',
    );
  });

  it('sanitizes strings; synchronous cards are available (or the given status)', () => {
    const card = reportQueuedCard({
      ...queuedInput,
      report: { ...queuedInput.report, title: 'T‮\u0000itle', reportId: 'nope' },
    });
    expect(card.title).toBe('Title');
    expect(card.portalLinks).toEqual([]);
    expect(REPORT_CARD_STATUSES).toEqual(['queued', 'running', 'available', 'failed']);
    const model = buildReportModel(okResults(), {
      window: WINDOW_7D,
      generatedAt: FIXTURE_GENERATED_AT,
      organizationName: FIXTURE_ORGANIZATION,
      sections: REPORT_SECTIONS,
    });
    const data = {
      reportId: REPORT_ID,
      generatedAt: model.generatedAt,
      sizeBytes: 1,
      ...reportDigestOf(model),
    };
    expect(reportCard({ executionId: 'e', refSeq: 1, report: data }).report!.status).toBe(
      'available',
    );
    expect(
      reportCard({ executionId: 'e', refSeq: 1, report: { ...data, status: 'failed' } }).report!
        .status,
    ).toBe('failed');
  });
});

describe('reportJobRoutePaths (I26: the job token allow-list)', () => {
  it('is the sorted, deduplicated /api/v1 GET paths of every report source tool', () => {
    expect(reportJobRoutePaths()).toEqual([
      // Step API-3 C16: the API-mode overview of the `api_mode` section.
      '/api/v1/api-mode/overview',
      '/api/v1/ato/accounts',
      '/api/v1/ato/overview',
      '/api/v1/quarantine/summary',
      '/api/v1/reports/delivery',
      '/api/v1/reports/processing',
      '/api/v1/reports/threats',
      '/api/v1/reports/top-domains',
      '/api/v1/reports/traffic',
      '/api/v1/reports/url-clicks',
    ]);
    expect(Object.isFrozen(reportJobRoutePaths())).toBe(true);
  });

  it('every source of REPORT_SOURCES maps to one of them', () => {
    const paths = new Set(reportJobRoutePaths());
    const keys = new Set(Object.values(REPORT_SOURCES).flat());
    expect(keys.size).toBe(10);
    for (const path of paths) expect(path.startsWith('/api/v1/')).toBe(true);
    expect(findTool('report_generate')!.description).toContain(
      'Windows longer than 7 days are generated in the background.',
    );
  });
});

describe('fake provider: queued report answer (D9)', () => {
  const NOW = new Date('2026-11-23T09:00:00.000Z');
  const system = `PROMPT\n\n# Catalogue index\n\n${renderCatalogueIndex(
    enabledTools(['report:read'], false),
  )}\n`;
  const ask = (provider: FakeProvider, transcript: unknown[]): Promise<LlmResponse> => {
    const request: LlmRequest = { system, transcript, tools: META_TOOLS, maxOutputTokens: 1024 };
    return provider.complete(request, new AbortController().signal, () => undefined);
  };

  it('"report for the last 30 days" still calls report_generate { range: 30d }; a queued result is answered without figures', async () => {
    const provider = new FakeProvider({ nodeEnv: 'test', now: () => NOW });
    const message = 'Generate a security report for the last 30 days';
    const first = await ask(provider, provider.userEntry(message));
    const parsed = parseMetaToolInput('call_tool', first.toolCalls[0]!.input);
    if (!parsed.ok || parsed.meta !== 'call_tool') throw new Error('not a call_tool');
    expect({ name: parsed.name, arguments: parsed.arguments }).toEqual({
      name: 'report_generate',
      arguments: { range: '30d' },
    });
    const answer = await ask(provider, [
      ...provider.userEntry(message),
      ...first.appendToTranscript,
      ...provider.toolResultEntries([
        {
          toolCallId: first.toolCalls[0]!.id,
          content: JSON.stringify(reportQueuedEnvelope(queuedInput)),
          isError: false,
        },
      ]),
    ]);
    expect(answer).toMatchObject({
      stop: 'end_turn',
      toolCalls: [],
      text: 'Your security report for the last 30 days is being generated; it will appear here when it is ready.',
    });
  });
});
