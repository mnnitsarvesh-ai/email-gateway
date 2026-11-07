import {
  DLP_PLATFORM_DEFAULTS,
  resolveDlpSettings,
  type DlpEffectiveSettings,
} from '@email-gateway/security-contracts';
import {
  classifyDetection,
  composeCoverage,
  coverageFromExtraction,
  type DlpClassification,
} from '../classify';
import type { AttachmentFixture, CorpusFixture, DlpCorpus } from '../corpus';
import { loadTenantPatterns } from '../custom';
import { detect, type DlpDetection, type DlpTextSegment } from '../detect';
import { DlpDictionarySet } from '../dictionaries';
import { ExtractionSession } from '../extract/session';
import type { DlpExtraction } from '../extract/types';
import { testWalk } from './walker.test-support';

/** Test support: the corpus through extraction (test walker) + detect + classification. */

export const NOW = new Date('2026-11-07T06:00:00Z');

export function platformSettings(): DlpEffectiveSettings {
  const resolved = resolveDlpSettings(DLP_PLATFORM_DEFAULTS, null);
  if (!resolved.ok) throw new Error('platform settings');
  return resolved.settings;
}

export async function extractFixture(
  fixture: Pick<AttachmentFixture, 'bytes' | 'filenameExt' | 'declaredContentType'>,
  limits = { maxDepth: 3, maxEntries: 1000 },
): Promise<DlpExtraction> {
  const session = new ExtractionSession({
    declaredContentType: fixture.declaredContentType,
    filenameExt: fixture.filenameExt,
  });
  const { detected, walk } = await testWalk(fixture.bytes, session.visitor, limits);
  return session.finish(fixture.bytes, detected, walk);
}

export const segmentsOfExtraction = (
  partIndex: number,
  extraction: DlpExtraction,
): DlpTextSegment[] =>
  extraction.segments.map((s) => ({
    source: { kind: 'attachment', partIndex, ...(s.path === 'attachment' ? {} : { path: s.path }) },
    format: s.format,
    kind: s.kind,
    text: s.text,
    ...(s.headers ? { headers: s.headers } : {}),
  }));

export interface FixtureRun {
  detection: DlpDetection;
  classification: DlpClassification;
  coverage: ReturnType<typeof composeCoverage>;
  extraction: DlpExtraction | null;
}

export async function runFixture(
  fixture: CorpusFixture,
  corpus: DlpCorpus,
  settings = platformSettings(),
): Promise<FixtureRun> {
  let segments: DlpTextSegment[];
  let extraction: DlpExtraction | null = null;
  if (fixture.kind === 'text') {
    segments = [
      {
        source: {
          kind: fixture.source,
          ...(fixture.source === 'attachment' ? { partIndex: 0 } : {}),
        },
        format: fixture.format,
        kind: fixture.segmentKind,
        text: fixture.text,
      },
    ];
  } else {
    extraction = await extractFixture(
      fixture,
      fixture.id === 'zip.over-entry-limit' ? { maxDepth: 3, maxEntries: 3 } : undefined,
    );
    segments = segmentsOfExtraction(0, extraction);
  }
  const patterns = loadTenantPatterns(corpus.tenantPatterns);
  const detection = await detect({
    segments,
    settings,
    aadhaarEnabled: fixture.aadhaarEnabled ?? false,
    dictionaries: DlpDictionarySet.create(corpus.tenantDictionaries),
    customPatterns: patterns.loaded,
    invalidCustomPatterns: patterns.invalid,
    envelopeAddresses: fixture.kind === 'text' ? (fixture.envelopeAddresses ?? []) : [],
    now: NOW,
  });
  const classification = classifyDetection(detection);
  const coverage = composeCoverage(
    extraction ? coverageFromExtraction(0, extraction) : [],
    detection.coverageCodes,
  );
  return { detection, classification, coverage, extraction };
}

export const findingCounts = (classification: DlpClassification): Record<string, number> =>
  Object.fromEntries(classification.findings.map((f) => [f.detector, f.count]));
