import {
  dlpFindingViewSchema,
  dlpHoldsRawNumber,
  DLP_REASON_CODES,
} from '@email-gateway/security-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import { dlpReasonCodes, dlpVerdict } from '../classify';
import { buildEvidence } from '../evidence/build';
import { findingCounts, runFixture } from '../test-support/pipeline.test-support';
import { buildCorpus, CORPUS_DICTIONARY_ID, CORPUS_PATTERN_ID, type DlpCorpus } from './index';

let corpus: DlpCorpus;
beforeAll(async () => {
  corpus = await buildCorpus();
});

const allValues = (c: DlpCorpus) => c.manifest.entries.map((e) => e.value);

describe('fixture corpus: true positives (step 4.5 §9)', () => {
  it('covers every format of the test plan', () => {
    const ids = corpus.fixtures.map((f) => f.id);
    for (const prefix of [
      'text.',
      'html.',
      'csv.',
      'pdf.',
      'docx.',
      'xlsx.',
      'pptx.',
      'odt.',
      'ods.',
      'zip.docx',
      'zip.nested',
    ]) {
      expect(
        ids.some((id) => id.startsWith(prefix)),
        prefix,
      ).toBe(true);
    }
  });

  it('every fixture yields exactly its expected findings, coverage and masked samples only', async () => {
    for (const fixture of corpus.fixtures) {
      const run = await runFixture(fixture, corpus);
      expect(findingCounts(run.classification), fixture.id).toEqual(fixture.expected.findings);
      expect(run.coverage.coverage, fixture.id).toBe(fixture.expected.coverage);
      if (fixture.kind === 'attachment' && fixture.expected.reasons) {
        expect(run.extraction?.reasons, fixture.id).toEqual(fixture.expected.reasons);
      }
      const verdict = dlpVerdict(run.classification.findingCount, run.coverage.coverage);
      expect(verdict, fixture.id).toBe(
        Object.keys(fixture.expected.findings).length > 0
          ? 'suspicious'
          : fixture.expected.coverage === 'partial'
            ? 'unknown'
            : 'clean',
      );
      const codes = dlpReasonCodes({
        verdict,
        decision: null,
        findings: run.classification.findings,
        coverageReasons: run.coverage.reasons,
        matchCapped: run.classification.matchCapped,
      });
      for (const code of codes) expect(DLP_REASON_CODES, code).toContain(code);
      // Masked samples: valid view entries, no sensitive value of the manifest.
      const values = allValues(corpus).filter((v) => v.length >= 8);
      for (const finding of run.classification.findings) {
        const view = { ...finding, attachmentCount: undefined };
        delete view.attachmentCount;
        expect(
          dlpFindingViewSchema.safeParse(view).success,
          `${fixture.id} ${finding.detector}`,
        ).toBe(true);
        for (const masked of finding.masked) {
          expect(dlpHoldsRawNumber(masked)).toBe(false);
          for (const value of values)
            expect(masked.includes(value), `${fixture.id} ${masked}`).toBe(false);
        }
      }
    }
  });

  it('masked samples of the plain-text fixture are the D15 forms', async () => {
    const run = await runFixture(
      corpus.fixtures.find((f) => f.id === 'text.every-detector')!,
      corpus,
    );
    const masked = Object.fromEntries(
      run.classification.findings.map((f) => [f.detector, f.masked]),
    );
    expect(masked.PC1![0]).toMatch(/^\*{12}[0-9]{4}$/);
    expect(masked.BA1![0]).toMatch(/^GB\*+[0-9]{4}$/);
    expect(masked.NI2![0]).toMatch(/^\*{8}[0-9]{4}$/);
    expect(masked.PI1![0]).toMatch(/^[a-z]\*\*\*@example\.test$/);
    expect(masked.PI3).toEqual(['**/**/****']);
    expect(masked.PP2![0]).toMatch(/^MRZ:\*+[0-9A-Z]{4}$/);
    expect(masked.CR1).toEqual(['[private key: RSA]']);
    expect(masked.CR3).toEqual(['[secret: 40 chars]']);
    expect(masked.CR4).toEqual(['[jwt alg=HS256]']);
    expect(masked.CR5).toEqual(['[token: github]']);
  });

  it('tenant dictionary and custom pattern findings carry their public ids', async () => {
    const run = await runFixture(
      corpus.fixtures.find((f) => f.id === 'text.tenant-dictionary-and-pattern')!,
      corpus,
    );
    const dc1 = run.classification.findings.find((f) => f.detector === 'DC1')!;
    expect(dc1).toMatchObject({
      dictionaryId: CORPUS_DICTIONARY_ID,
      category: 'confidential',
      severity: 'high',
      masked: ['term #0'],
    });
    const cu1 = run.classification.findings.find((f) => f.detector === 'CU1')!;
    expect(cu1).toMatchObject({
      customPatternId: CORPUS_PATTERN_ID,
      category: 'custom',
      severity: 'medium',
      confidence: 0.9,
    });
    expect(cu1.masked[0]).toMatch(/^\*+[0-9]{4}$/);
  });

  it('builds evidence for the reportable findings without a raw card, Aadhaar or secret', async () => {
    const run = await runFixture(
      corpus.fixtures.find((f) => f.id === 'text.every-detector')!,
      corpus,
    );
    const evidence = buildEvidence({
      matches: run.detection.candidates,
      credentialCandidates: run.detection.credentialCandidates,
      segments: run.detection.segments,
      aadhaarEnabled: true,
      maxMatches: 50,
      maxBytes: 32_768,
    })!;
    const raw = corpus.manifest.entries
      .filter((e) => ['PC1', 'NI2', 'CR1', 'CR3', 'CR4', 'CR5'].includes(e.detector))
      .map((e) => e.value);
    for (const value of raw) expect(evidence.json.includes(value), value.slice(0, 6)).toBe(false);
    expect(evidence.document.matches.length).toBeGreaterThanOrEqual(19);
  });
});

describe('not extracted: never clean', () => {
  it('encrypted ZIP, password PDF, image-only PDF, PNG, OLE .doc, archive limit → unknown with codes', async () => {
    expect(corpus.notExtracted.map((f) => f.id)).toEqual([
      'zip.encrypted',
      'pdf.password',
      'pdf.image-only',
      'png.image',
      'doc.ole',
      'zip.over-entry-limit',
    ]);
    for (const fixture of corpus.notExtracted) {
      const run = await runFixture(fixture, corpus);
      expect(run.extraction!.reasons, fixture.id).toEqual(fixture.expected.reasons);
      expect(run.coverage.coverage, fixture.id).toBe('partial');
      expect(dlpVerdict(run.classification.findingCount, run.coverage.coverage), fixture.id).toBe(
        'unknown',
      );
      expect(run.coverage.reasons, fixture.id).toEqual(
        fixture.expected.reasons!.map((r) => `dlp.not_extracted.${r}`),
      );
    }
  });
});

describe('false-positive set (no reportable finding)', () => {
  it('lists the cases of the test plan', () => {
    expect(corpus.falsePositives.length).toBeGreaterThanOrEqual(24);
  });
  it('every case yields zero reportable findings, even with Aadhaar enabled', async () => {
    for (const fp of corpus.falsePositives) {
      const run = await runFixture(
        {
          id: fp.id,
          kind: 'text',
          source: 'body_text',
          format: 'text',
          segmentKind: 'text',
          text: fp.text,
          aadhaarEnabled: true,
          expected: { findings: {}, coverage: 'complete' },
        },
        corpus,
      );
      expect(run.classification.findings, `${fp.id} (${fp.confusable})`).toEqual([]);
    }
  });
});

describe('the corpus is synthetic by construction', () => {
  it('is deterministic for a seed', async () => {
    const again = await buildCorpus();
    expect(allValues(again)).toEqual(allValues(corpus));
    expect(allValues(await buildCorpus(7))).not.toEqual(allValues(corpus));
  });
  it('every reportable value found in the corpus is listed in the manifest', async () => {
    for (const fixture of corpus.fixtures) {
      const run = await runFixture(fixture, corpus);
      for (const c of run.detection.candidates.filter((x) => x.reportable)) {
        if (['CF1', 'CF2', 'FI1', 'SC1', 'DC1', 'PP2'].includes(c.detector)) continue; // keyword / structure detectors
        const listed = corpus.manifest.entries.some(
          (e) =>
            e.value === c.compact ||
            e.value === c.value ||
            c.value.includes(e.value) ||
            e.value.includes(c.compact),
        );
        expect(listed, `${fixture.id} ${c.detector}`).toBe(true);
      }
    }
    expect(corpus.manifest.entries.some((e) => e.detector === 'PP2')).toBe(true);
  });
  it('uses example.test e-mail domains only', () => {
    for (const e of corpus.manifest.entries.filter((x) => x.detector === 'PI1'))
      expect(e.value.endsWith('@example.test')).toBe(true);
  });
});
