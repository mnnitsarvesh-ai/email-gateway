import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Deadline } from '@email-gateway/bec';
import { DLP_REASON_CODES, dlpCoverageEntrySchema } from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { generateProbeCorpus } from '../scripts/probe-corpus';
import {
  categoryAggregates,
  classifyDetection,
  composeCoverage,
  coverageFromExtraction,
  dlpReasonCodes,
  dlpVerdict,
  policyFindings,
} from './classify';
import { loadTenantPatterns, probeCorpus } from './custom';
import { readDataFile } from './data';
import { detect, insideLongerPhrase, WorkClock, type DlpDetectInput } from './detect';
import { DlpDictionarySet } from './dictionaries';
import { NOW, platformSettings } from './test-support/pipeline.test-support';
import { luhnCheckDigit } from './validators';
import { DLP_EXTRACTOR_VERSION, DLP_TEXT_DERIVATION_VERSION, dlpEngineVersion } from './versions';

const dictionaries = DlpDictionarySet.create();
const card = (n: number) => {
  const body = `4532${String(n).padStart(11, '3')}`;
  return body + String(luhnCheckDigit(body));
};

const run = (text: string, extra: Partial<DlpDetectInput> = {}) =>
  detect({
    segments: [{ source: { kind: 'body_text' }, format: 'text', kind: 'text', text }],
    settings: platformSettings(),
    aadhaarEnabled: false,
    dictionaries,
    now: NOW,
    ...extra,
  });

describe('detect(): chunking (D3 step 5)', () => {
  it('finds a value across a chunk boundary exactly once', async () => {
    const value = `Card ${card(1)}`;
    for (const offset of [0, 90, 95, 98, 100, 101, 105]) {
      const text = `${'x '.repeat(offset / 2)}${'y'.repeat(offset % 2)} ${value} ${'z '.repeat(100)}`;
      const detection = await run(text, { limits: { chunkChars: 100, overlap: 40 } });
      expect(
        detection.candidates.filter((c) => c.detector === 'PC1'),
        String(offset),
      ).toHaveLength(1);
    }
  });

  it('gives the same candidates whatever the chunk size', async () => {
    const text = Array.from(
      { length: 40 },
      (_, i) => `Card ${card(i)} for PAN: ABCPD${1000 + i}E at anita${i}@example.test`,
    ).join('\n');
    const key = (d: Awaited<ReturnType<typeof run>>) =>
      d.candidates.map((c) => `${c.detector}@${c.start}:${c.confidence}`).sort();
    const reference = key(await run(text));
    for (const chunkChars of [64, 257, 1000]) {
      expect(
        key(await run(text, { limits: { chunkChars, overlap: 512 } })),
        String(chunkChars),
      ).toEqual(reference);
    }
  });

  it('stops at the deadline with the retryable extract_timeout error', async () => {
    let t = 0;
    const deadline = new Deadline(10, () => (t += 100));
    await expect(run('x'.repeat(200_000), { deadline })).rejects.toMatchObject({
      code: 'extract_timeout',
    });
  });

  it('a WorkClock deadline does not count time other scans spend on the shared loop', async () => {
    // A fake clock that only moves while a sibling task (another message's chunk) runs: each
    // turn of the sibling takes 1 s. The wall-clock deadline expires; the work clock does not.
    let t = 0;
    const source = () => t;
    const text = 'x '.repeat(100_000);
    const limits = { chunkChars: 4_096 };
    const withSibling = async <T>(work: () => Promise<T>): Promise<T> => {
      let running = true;
      const sibling = (async () => {
        while (running) {
          t += 1_000;
          await nextTurn();
        }
      })();
      try {
        return await work();
      } finally {
        running = false;
        await sibling;
      }
    };
    await expect(
      withSibling(() => run(text, { limits, deadline: Deadline.after(5_000, source) })),
    ).rejects.toMatchObject({ code: 'extract_timeout' });
    const clock = new WorkClock(source);
    const detection = await withSibling(() =>
      run(text, { limits, deadline: Deadline.after(5_000, clock.now), workClock: clock }),
    );
    expect(detection.segments).toHaveLength(1);
    expect(t).toBeGreaterThan(5_000);
    // At most the sibling turn that ran before the first chunk (the clock started earlier).
    expect(clock.now()).toBeLessThanOrEqual(1_000);
  });

  it('WorkClock counts only unpaused time', () => {
    let t = 100;
    const clock = new WorkClock(() => t);
    t += 30;
    clock.pause();
    t += 1_000;
    clock.resume();
    t += 20;
    expect(clock.now()).toBe(50);
    clock.pause();
    clock.pause();
    expect(clock.now()).toBe(50);
  });
});

describe('detect(): sources', () => {
  it('converts HTML with the bec htmlToText; a node cap is a truncated text', async () => {
    const html = `<div>${'<p>a</p>'.repeat(30)}<p>Card ${card(2)}</p></div>`;
    const full = await detect({
      segments: [{ source: { kind: 'body_html' }, format: 'html', kind: 'html', text: html }],
      settings: platformSettings(),
      aadhaarEnabled: false,
      dictionaries,
      now: NOW,
    });
    expect(full.candidates.map((c) => c.detector)).toEqual(['PC1']);
    expect(full.segments[0]!.text).not.toContain('<p>');
    expect(full.coverageCodes).toEqual([]);
    const capped = await detect({
      segments: [{ source: { kind: 'body_html' }, format: 'html', kind: 'html', text: html }],
      settings: platformSettings(),
      aadhaarEnabled: false,
      dictionaries,
      now: NOW,
      limits: { maxHtmlNodes: 10 },
    });
    expect(capped.coverageCodes).toEqual(['dlp.text.truncated']);
  });

  it('attachment names run keyword detectors only', async () => {
    const detection = await detect({
      segments: [
        {
          source: { kind: 'attachment_name', partIndex: 0 },
          format: 'text',
          kind: 'name',
          text: `CONFIDENTIAL term sheet ${card(3)}.pdf`,
        },
      ],
      settings: platformSettings(),
      aadhaarEnabled: false,
      dictionaries,
      now: NOW,
    });
    expect(detection.candidates.map((c) => c.detector).sort()).toEqual(['CF1', 'CF2']);
  });

  it('honours the disableable detectors only', async () => {
    const settings = {
      ...platformSettings(),
      disabledDetectors: ['PI1', 'CF2'] as ('PI1' | 'CF2')[],
    };
    const detection = await run(
      'mail anita@example.test about the term sheet and customer list; PAN: ABCPD1234E',
      { settings },
    );
    expect(detection.candidates.map((c) => c.detector)).toEqual(['NI1']);
  });

  it('caps matches per detector and reports the cap', async () => {
    const text = Array.from({ length: 30 }, (_, i) => `anita${i}@example.test`).join(' ');
    const detection = await run(text, { limits: { maxMatchesPerDetector: 10 } });
    expect(detection.candidates.filter((c) => c.detector === 'PI1')).toHaveLength(10);
    expect([...detection.capped]).toEqual(['PI1']);
    const classification = classifyDetection(detection);
    expect(classification.findings[0]).toMatchObject({ detector: 'PI1', count: 10, capped: true });
    expect(classification.matchCapped).toBe(true);
  });

  it('custom patterns: per-message character budget and invalid stored patterns are coverage codes', async () => {
    const patterns = loadTenantPatterns([
      {
        id: 'p1',
        version: 1,
        pattern: 'EMP-[0-9]{6}',
        caseInsensitive: false,
        validator: 'none',
        contextKeywords: [],
        requireContext: false,
        severity: 'low',
        baseConfidence: 0.7,
        maskStyle: 'full',
      },
      {
        id: 'p2',
        version: 1,
        pattern: '(?=x)',
        caseInsensitive: false,
        validator: 'none',
        contextKeywords: [],
        requireContext: false,
        severity: 'low',
        baseConfidence: 0.7,
        maskStyle: 'full',
      },
    ]);
    const text = `EMP-123456 ${'x'.repeat(100)} EMP-654321`;
    const detection = await run(text, {
      customPatterns: patterns.loaded,
      invalidCustomPatterns: patterns.invalid,
      limits: { customScanMaxChars: 50 },
    });
    expect(detection.candidates.filter((c) => c.detector === 'CU1').map((c) => c.value)).toEqual([
      'EMP-123456',
    ]);
    expect(detection.coverageCodes).toEqual([
      'dlp.custom.pattern_invalid',
      'dlp.custom.scan_truncated',
    ]);
    const masked = classifyDetection(detection).findings[0]!.masked;
    expect(masked).toEqual(['*********']);
  });

  it('DC1 minMatches gates reportability at message level', async () => {
    const tenant = DlpDictionarySet.create([
      {
        id: '0196f3a0-0000-7000-8000-000000000009',
        version: 1,
        category: 'custom',
        terms: ['falcon'],
        severity: 'low',
        baseConfidence: 0.8,
        minMatches: 3,
      },
    ]);
    expect(
      (await run('falcon falcon', { dictionaries: tenant })).candidates.every((c) => !c.reportable),
    ).toBe(true);
    expect(
      (await run('falcon falcon falcon', { dictionaries: tenant })).candidates.every(
        (c) => c.reportable,
      ),
    ).toBe(true);
  });

  it('label containment uses a bounded lookup', () => {
    expect(insideLongerPhrase([{ start: 0, end: 17 }], { start: 4, end: 10 })).toBe(true);
    expect(insideLongerPhrase([{ start: 4, end: 10 }], { start: 4, end: 10 })).toBe(false);
    expect(insideLongerPhrase([], { start: 4, end: 10 })).toBe(false);
  });
});

describe('classification, coverage, verdict and reason codes (D7, D10)', () => {
  it('groups distinct values with ≤ 5 sources and ≤ 3 masked samples', async () => {
    const segments = Array.from({ length: 7 }, (_, i) => ({
      source: { kind: 'attachment' as const, partIndex: i },
      format: 'text' as const,
      kind: 'text' as const,
      text: `Card ${card(10 + i)} and again Card ${card(10 + i)}`,
    }));
    const detection = await detect({
      segments,
      settings: platformSettings(),
      aadhaarEnabled: false,
      dictionaries,
      now: NOW,
    });
    const { findings, categories, findingCount } = classifyDetection(detection);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      detector: 'PC1',
      count: 7,
      attachmentCount: 7,
      confidence: 0.75,
    });
    expect(findings[0]!.sources).toHaveLength(5);
    expect(findings[0]!.masked).toHaveLength(3);
    expect(categories).toEqual([
      { category: 'payment_card', count: 7, maxSeverity: 'high', maxConfidence: 0.75 },
    ]);
    expect(findingCount).toBe(7);
    expect(policyFindings(findings)[0]).toEqual({
      detector: 'PC1',
      category: 'payment_card',
      severity: 'high',
      confidence: 0.75,
      count: 7,
      attachmentCount: 7,
    });
    expect(classifyDetection(detection, 0).findingsDropped).toBe(1);
  });

  it('counts suppressed candidates without values', async () => {
    const detection = await run(`value ${card(20)} here`);
    expect(classifyDetection(detection)).toMatchObject({ findings: [], suppressed: { PC1: 1 } });
  });

  it('composes coverage and the verdict; never clean with a coverage reason', () => {
    expect(composeCoverage([])).toEqual({ coverage: 'complete', reasons: [], detail: [] });
    const entries = coverageFromExtraction(2, {
      extractorVersion: 'dlp-extract/1',
      status: 'partial',
      format: 'zip',
      reasons: ['encrypted'],
      segments: [{ path: '0', format: 'text', kind: 'text', text: 'abc', truncated: true }],
      entriesVisited: 1,
    });
    expect(entries).toEqual([
      {
        source: 'attachment',
        partIndex: 2,
        format: 'zip',
        status: 'partial',
        reasons: ['dlp.not_extracted.encrypted', 'dlp.text.truncated'],
        chars: 3,
        truncated: true,
      },
    ]);
    for (const e of entries) expect(dlpCoverageEntrySchema.safeParse(e).success).toBe(true);
    const composed = composeCoverage(entries, ['dlp.custom.scan_truncated']);
    expect(composed.coverage).toBe('partial');
    expect(composed.reasons).toEqual([
      'dlp.not_extracted.encrypted',
      'dlp.text.truncated',
      'dlp.custom.scan_truncated',
    ]);
    expect(dlpVerdict(0, 'complete')).toBe('clean');
    expect(dlpVerdict(0, 'partial')).toBe('unknown');
    expect(dlpVerdict(1, 'partial')).toBe('suspicious');
  });

  it('orders reason codes: action, policy codes, detectors by severity, cap, coverage; no_findings for clean', () => {
    const codes = dlpReasonCodes({
      verdict: 'suspicious',
      decision: { codes: ['dlp.action.quarantine', 'dlp.exception.applied'] },
      findings: [
        {
          detector: 'NI2',
          code: 'dlp.national_id.india_aadhaar',
          category: 'national_id',
          severity: 'critical',
          confidence: 1,
          count: 1,
          attachmentCount: 0,
          capped: false,
          sources: [],
          masked: [],
        },
        {
          detector: 'PI1',
          code: 'dlp.personal_info.email_address',
          category: 'personal_info',
          severity: 'low',
          confidence: 0.9,
          count: 1,
          attachmentCount: 0,
          capped: true,
          sources: [],
          masked: [],
        },
      ],
      coverageReasons: ['dlp.not_extracted.image'],
      matchCapped: true,
    });
    expect(codes).toEqual([
      'dlp.action.quarantine',
      'dlp.exception.applied',
      'dlp.national_id.india_aadhaar',
      'dlp.personal_info.email_address',
      'dlp.detector.match_cap',
      'dlp.coverage.partial',
      'dlp.not_extracted.image',
    ]);
    for (const code of codes) expect(DLP_REASON_CODES).toContain(code);
    expect(
      dlpReasonCodes({
        verdict: 'clean',
        decision: null,
        findings: [],
        coverageReasons: [],
        matchCapped: false,
      }),
    ).toEqual(['dlp.no_findings']);
    expect(categoryAggregates([])).toEqual([]);
  });
});

describe('versions (D23) and the probe corpus', () => {
  it('builds the engine version', () => {
    const version = dlpEngineVersion();
    expect(version).toMatch(/^dlp\/1;dict=[0-9a-f]{8};data=[0-9a-f]{8};ext=dlp-extract\/1$/);
    expect(version.length).toBeLessThanOrEqual(96);
    expect(DLP_EXTRACTOR_VERSION).toBe('dlp-extract/1');
    expect(DLP_TEXT_DERIVATION_VERSION).toBe('dlp-text/1');
  });

  it('the packaged probe corpus equals the generator output and holds no sensitive value', async () => {
    expect(readDataFile('probe-corpus.txt')).toBe(generateProbeCorpus());
    const detection = await run(probeCorpus(), { aadhaarEnabled: true });
    expect(classifyDetection(detection).findings).toEqual([]);
  });

  it('the generator script check mode passes', () => {
    const root = join(__dirname, '..');
    execFileSync(
      process.execPath,
      [join(root, 'node_modules', 'tsx', 'dist', 'cli.mjs'), 'scripts/probe-corpus.ts', '--check'],
      { cwd: root },
    );
  });
});
