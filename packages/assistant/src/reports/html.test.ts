import fc from 'fast-check';
import { parse } from 'parse5';
import { describe, expect, it } from 'vitest';
import {
  FIXTURE_GENERATED_AT,
  FIXTURE_ORGANIZATION,
  WINDOW_24H,
  WINDOW_7D,
  atoAccountsBody,
  atoOverviewBody,
  okResults,
  quarantineSummaryBody,
  threatsBody,
  topDomainsBody,
  trafficBody,
} from './fixtures.test-support';
import { escapeHtml } from './escape';
import {
  APPENDIX_FALLBACK_ROWS,
  NO_DATA_TEXT,
  REPORT_CSP,
  REPORT_STYLE,
  ReportTooLargeError,
  byteLength,
  omissionText,
  renderReportHtml,
} from './html';
import { buildReportModel, type ReportSourceResults } from './model';
import { REPORT_SECTIONS, type ReportSection, type ReportWindow } from './types';

const ALLOWED_ELEMENTS = new Set(
  'html head meta title style body header main section footer h1 h2 h3 p div span strong small ul li table caption thead tbody tr th td figure figcaption svg g path rect circle line polyline polygon text tspan desc'.split(
    ' ',
  ),
);
const ALLOWED_ATTRIBUTES = new Set(
  'class id lang charset name content http-equiv role aria-label aria-labelledby aria-hidden scope colspan viewBox width height x y x1 y1 x2 y2 cx cy r d points fill stroke stroke-width stroke-dasharray text-anchor dominant-baseline font-size font-weight transform opacity xmlns focusable'.split(
    ' ',
  ),
);

interface Node {
  nodeName: string;
  tagName?: string;
  attrs?: Array<{ name: string; value: string }>;
  childNodes?: Node[];
  value?: string;
}

/**
 * The design D4 allow-list: every element and attribute is listed; no event handler, link,
 * source, `url(`, `javascript:`, comment, script or style attribute; the style block is the
 * constant; the CSP meta is the constant. Returns the problems (empty when the document passes).
 */
function allowListProblems(html: string): string[] {
  const problems: string[] = [];
  const doc = parse(html) as unknown as Node;
  const styles: string[] = [];
  const csp: string[] = [];
  const walk = (node: Node, parent: string) => {
    if (node.nodeName === '#comment') problems.push('comment node');
    if (node.tagName !== undefined) {
      if (!ALLOWED_ELEMENTS.has(node.tagName)) problems.push(`element <${node.tagName}>`);
      for (const attr of node.attrs ?? []) {
        if (!ALLOWED_ATTRIBUTES.has(attr.name))
          problems.push(`attribute ${attr.name} on <${node.tagName}>`);
        if (/^on/i.test(attr.name)) problems.push(`event handler ${attr.name}`);
        if (/url\(|javascript:|data:text|expression\(/i.test(attr.value) && attr.name !== 'content')
          problems.push(`unsafe value in ${attr.name}`);
      }
      if (node.tagName === 'style')
        styles.push((node.childNodes ?? []).map((c) => c.value ?? '').join(''));
      if (node.tagName === 'meta') {
        const equiv = node.attrs?.find((a) => a.name === 'http-equiv');
        if (equiv) csp.push(node.attrs!.find((a) => a.name === 'content')?.value ?? '');
      }
      if (node.tagName === 'style' && parent !== 'head') problems.push('style outside head');
    }
    for (const child of node.childNodes ?? []) walk(child, node.tagName ?? parent);
  };
  walk(doc, '');
  if (styles.length !== 1 || styles[0] !== REPORT_STYLE)
    problems.push('style block is not the constant');
  if (csp.length !== 1 || csp[0] !== REPORT_CSP) problems.push('CSP meta is not the constant');
  if (/<script|<a[\s>]|<img|<iframe|<object|<link|<form|<base|<embed/i.test(html))
    problems.push('forbidden tag text');
  return problems;
}

const model = (
  results: ReportSourceResults = okResults(),
  options: {
    window?: ReportWindow;
    sections?: readonly ReportSection[];
    organizationName?: string;
  } = {},
) =>
  buildReportModel(results, {
    window: options.window ?? WINDOW_7D,
    generatedAt: FIXTURE_GENERATED_AT,
    organizationName: options.organizationName ?? FIXTURE_ORGANIZATION,
    sections: options.sections ?? REPORT_SECTIONS,
  });

const hours = (n: number) =>
  Array.from({ length: n }, (_, i) =>
    new Date(Date.parse('2026-11-20T09:00:00.000Z') + i * 3_600_000).toISOString(),
  );

/** Fixture reports: full, partial (permissions, outages), empty, hourly. */
function fixtureReports(): Array<[string, string]> {
  const partial = okResults({ delivery: { broken: true } });
  partial.quarantine_summary = { status: 'permission' };
  partial.traffic = { status: 'unavailable', httpStatus: 503, code: 'report_timeout' };
  const empty = okResults({
    traffic: { ...trafficBody([]), totals: trafficBody([]).totals },
    ato_overview: atoOverviewBody({ featureEnabled: false }),
  });
  const hourly = okResults({ traffic: trafficBody(hours(24)) });
  return [
    ['full', renderReportHtml(model())],
    ['partial', renderReportHtml(model(partial))],
    ['empty', renderReportHtml(model(empty))],
    ['hourly', renderReportHtml(model(hourly, { window: WINDOW_24H }))],
    ['summary-only', renderReportHtml(model(okResults(), { sections: ['summary'] }))],
  ];
}

describe('renderReportHtml (design D4)', () => {
  it('is byte-stable for the full fixture report (snapshot)', () => {
    const html = renderReportHtml(model());
    expect(renderReportHtml(model())).toBe(html);
    expect(html).toMatchSnapshot();
  });

  it('has the design D4 document skeleton with the constant CSP meta and style', () => {
    const html = renderReportHtml(model());
    expect(
      html.startsWith(
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">' +
          `<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; img-src data:"><meta name="referrer" content="no-referrer"><title>Security report: Last 7 days</title><style>${REPORT_STYLE}</style></head>`,
      ),
    ).toBe(true);
    expect(html.endsWith('</main></body></html>')).toBe(true);
    expect(REPORT_CSP).toBe("default-src 'none'; style-src 'unsafe-inline'; img-src data:");
    expect(REPORT_STYLE).not.toMatch(/url\(|@import|expression|javascript/i);
    expect(REPORT_STYLE).toContain('html{background:#ffffff');
    expect(REPORT_STYLE).toContain('@media (max-width:720px)');
    expect(REPORT_STYLE).toContain('@media print');
    expect(html).toContain('<h1>Security report</h1><p class="org">Example Test Org</p>');
    expect(html).toContain('Period: Last 7 days');
    expect(html).toContain('Generated Nov 23, 2026 09:00 UTC');
    expect(html).toContain(
      'All times are UTC. Generated by the AI assistant from the platform&#39;s report APIs for Example Test Org; numbers are counts of recorded rows, not estimates.',
    );
    expect(html).toContain('<h2>Sources</h2>');
    expect(html).toContain('<h2>Not included</h2><p>Every requested section is included.</p>');
    expect(html).toContain('<h2>Data appendix</h2>');
    // One appendix table per chart (20 charts in the full report: 18 + the 2 of step API-3).
    const appendix = html.slice(html.indexOf('id="section-appendix"'), html.indexOf('<footer'));
    expect([...appendix.matchAll(/<table>/g)]).toHaveLength(20);
    expect([...html.matchAll(/<svg /g)]).toHaveLength(20);
  });

  it('every fixture report passes the parse5 allow-list walk', () => {
    for (const [name, html] of fixtureReports()) expect(allowListProblems(html), name).toEqual([]);
  });

  it('lists omitted sections under "Not included" and renders the no-data placeholder', () => {
    const [, partial] = fixtureReports()[1]!;
    expect(partial).toContain('<li>Mail traffic: unavailable (report_timeout)</li>');
    expect(partial).toContain('<li>Delivery: unexpected response from the report API</li>');
    expect(partial).toContain('<li>Quarantine: missing permission (requires quarantine:read)</li>');
    expect(partial).toContain(
      'Traffic report (reports_traffic): unavailable, code report_timeout, HTTP 503',
    );
    const [, empty] = fixtureReports()[2]!;
    expect(empty).toContain(`<p class="empty">${NO_DATA_TEXT}</p>`);
    expect(empty).toContain('<li>Account takeover: feature not enabled</li>');
    expect(omissionText({ section: 'ato', reason: 'permission' })).toBe(
      'Account takeover: missing permission',
    );
  });

  it('size cap: drops appendix rows beyond 50 per table and retries once, else ReportTooLargeError', () => {
    const big = model(okResults({ traffic: trafficBody(hours(120)) }), {
      window: { ...WINDOW_24H, range: null },
    });
    const full = renderReportHtml(big);
    const capped = renderReportHtml(big, { maxBytes: byteLength(full) - 1 });
    expect(byteLength(capped)).toBeLessThan(byteLength(full));
    expect(capped).toContain(
      `Mail volume by direction (first ${APPENDIX_FALLBACK_ROWS} of 120 rows)`,
    );
    expect(allowListProblems(capped)).toEqual([]);
    expect(renderReportHtml(big, { maxBytes: byteLength(full) })).toBe(full);
    expect(renderReportHtml(big, { maxBytes: byteLength(capped) })).toBe(capped);
    let error: unknown;
    try {
      renderReportHtml(big, { maxBytes: byteLength(capped) - 1 });
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(ReportTooLargeError);
    expect(error).toMatchObject({ code: 'assistant_report_too_large', bytes: byteLength(capped) });
  });

  it('contains no link, script or external resource', () => {
    for (const [, html] of fixtureReports()) {
      expect(html).not.toMatch(/href=|src=|https?:\/\/(?!www\.w3\.org\/2000\/svg")/);
      expect(html).not.toMatch(/<script/i);
    }
  });
});

const HOSTILE = [
  '<script>alert(1)</script>',
  '"><svg onload=alert(1)>',
  "'><img src=x onerror=alert(1)>",
  'javascript:alert(1)',
  '</style><script>x</script>',
  '<a href="https://evil.example">x</a>',
  'url(https://evil.example/x.png)',
  '\u202eevil\u202c\u200b',
  'line\r\nBcc: victim@example.test',
  '&lt;already&gt; &amp;',
  '<!-- comment -->',
  '<![CDATA[x]]>',
  'x'.repeat(10_000),
];

const hostile = fc.oneof(
  fc.constantFrom(...HOSTILE),
  fc.string({ maxLength: 40 }),
  fc
    .tuple(fc.constantFrom(...HOSTILE), fc.string({ maxLength: 20 }), fc.constantFrom(...HOSTILE))
    .map(([a, b, c]) => `${a}${b}${c}`),
);

describe('hostile data strings (property test, design D4)', () => {
  it('a hostile ATO display name and domain appear as escaped text', () => {
    const results = okResults({
      top_domains: topDomainsBody(['<b>x</b>.example.test', 'ok.example.test']),
      ato_accounts: atoAccountsBody([
        { address: 'ada@alpha.example.test', displayName: '<img src=x onerror=alert(1)>' },
      ]),
    });
    const html = renderReportHtml(model(results));
    expect(allowListProblems(html)).toEqual([]);
    expect(html).toContain('<td>&lt;img src=x onerror=alert(1)&gt;</td>');
    expect(html).toContain('&lt;b&gt;x&lt;/b&gt;.example.test');
    expect(html).not.toContain('<img');
  });

  it('never produce a non-allow-listed node or attribute and always appear escaped', () => {
    fc.assert(
      fc.property(
        fc.record({
          domain: hostile,
          status: hostile,
          address: hostile,
          displayName: hostile,
          kind: hostile,
          level: hostile,
          country: hostile,
          organization: hostile,
          code: hostile,
          state: hostile,
          verdict: hostile,
          start: hostile,
        }),
        (h) => {
          const threats = threatsBody();
          const ato = atoOverviewBody({ countries: [h.country, 'IN'] });
          const accounts = atoAccountsBody([
            { address: h.address, displayName: h.displayName },
            { address: null, displayName: h.displayName },
          ]);
          accounts.data[0]!.kind = h.kind;
          accounts.data[0]!.riskLevel = h.level;
          const traffic = trafficBody();
          traffic.buckets[0]!.start = h.start;
          const results = okResults({
            top_domains: {
              ...topDomainsBody([h.domain, 'ok.example.test']),
              domains: topDomainsBody([h.domain, 'ok.example.test']).domains.map((d) => ({
                ...d,
                status: h.status,
              })),
            },
            threats: {
              ...threats,
              outcomes: [{ verdict: h.verdict, action: h.verdict, count: 3 }],
            },
            quarantine_summary: { ...quarantineSummaryBody(), counts: { [h.state]: 4, held: 1 } },
            ato_overview: ato,
            ato_accounts: accounts,
            traffic,
          });
          results.delivery = { status: 'unavailable', httpStatus: 502, code: h.code };
          const report = model(results, { organizationName: h.organization });
          const html = renderReportHtml(report);
          expect(allowListProblems(html)).toEqual([]);
          // The organization name appears exactly as sanitized + escaped.
          expect(html).toContain(`<p class="org">${escapeHtml(report.organizationName)}</p>`);
          // No raw markup from data survives (handler text may remain as escaped, inert text).
          expect(html).not.toMatch(/<script|<img|<a\s|<[a-z]+\s[^>]*\son[a-z]+=/i);
        },
      ),
      { numRuns: 150, seed: 20261123 },
    );
  });
});
