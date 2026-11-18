import type { Prisma } from '@prisma/client';
import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  SCAN_READ_MODEL_SELECTS,
  attachmentResultSelect,
  becResultSelect,
  dlpEvidenceStateSelect,
  dlpResultSelect,
  evaluationSelect,
  riskScoreSelect,
  sandboxAnalysisSelect,
  urlResultSelect,
  type AttachmentPartRow,
  type DlpResultRow,
  type EngineResultRow,
  type EvaluationRow,
  type RiskScoreRow,
  type ScanReadModelRows,
  type ScanRoundRow,
} from './scan-read-model';

const keys = (select: Record<string, unknown>) => Object.keys(select).sort();

describe('scan read model (step 8.1 A5)', () => {
  it('has one select per archive-scan/1 row key (§4.2), every column selected with true', () => {
    expect(Object.keys(SCAN_READ_MODEL_SELECTS)).toEqual([
      'scan',
      'engines',
      'auth',
      'attachments',
      'attachmentParts',
      'sandboxSubmissions',
      'sandboxAnalyses',
      'sandboxArtifacts',
      'urls',
      'urlResults',
      'urlRewrites',
      'urlInspections',
      'bec',
      'dlp',
      'risk',
      'policy',
    ]);
    for (const [name, select] of Object.entries(SCAN_READ_MODEL_SELECTS)) {
      expect(
        Object.values(select).every((v) => v === true),
        name,
      ).toBe(true);
    }
    expect(Object.isFrozen(SCAN_READ_MODEL_SELECTS)).toBe(true);
  });

  it('never selects the columns the api keeps from tenants (cross-tenant caches, internal ids, durations)', () => {
    expect(keys(attachmentResultSelect)).not.toEqual(
      expect.arrayContaining(['cacheResult', 'durationMs']),
    );
    expect(Object.keys(attachmentResultSelect)).not.toContain('cacheResult');
    expect(Object.keys(urlResultSelect)).not.toContain('fetchCache');
    expect(Object.keys(urlResultSelect)).not.toContain('durationMs');
    for (const hidden of ['identity', 'features', 'durationMs', 'textVersion']) {
      expect(Object.keys(becResultSelect), hidden).not.toContain(hidden);
    }
    expect(Object.keys(dlpResultSelect)).not.toContain('durationMs');
    for (const hidden of ['organizationId', 'dedupeKey', 'reuseUntil', 'sampleKey']) {
      expect(Object.keys(sandboxAnalysisSelect), hidden).not.toContain(hidden);
    }
    for (const hidden of ['id', 'profileVersionId', 'durationUs']) {
      expect(Object.keys(riskScoreSelect), hidden).not.toContain(hidden);
    }
    // DLP evidence: state only, never the object key, hash or wrapped key; not frozen at all.
    expect(keys(dlpEvidenceStateSelect)).toEqual(['expiresAt', 'purgedAt', 'scanId']);
    expect(Object.values(SCAN_READ_MODEL_SELECTS)).not.toContain(dlpEvidenceStateSelect);
  });

  it('pins the policy evaluation columns the api maps (rowToEvaluationView)', () => {
    expect(keys(evaluationSelect)).toHaveLength(40);
    for (const column of ['actions', 'recipientDecisions', 'explanationText', 'evaluatedAt']) {
      expect(evaluationSelect, column).toHaveProperty(column, true);
    }
  });

  it('types every row from its select (compile-level)', () => {
    expectTypeOf<ScanRoundRow>().toEqualTypeOf<
      Prisma.EmailScanGetPayload<{ select: typeof SCAN_READ_MODEL_SELECTS.scan }>
    >();
    expectTypeOf<ScanRoundRow['id']>().toEqualTypeOf<bigint>();
    expectTypeOf<ScanRoundRow['completedAt']>().toEqualTypeOf<Date | null>();
    expectTypeOf<EngineResultRow['isFinal']>().toEqualTypeOf<boolean>();
    expectTypeOf<keyof EngineResultRow>().toEqualTypeOf<
      keyof typeof SCAN_READ_MODEL_SELECTS.engines
    >();
    expectTypeOf<keyof DlpResultRow>().toEqualTypeOf<keyof typeof dlpResultSelect>();
    expectTypeOf<keyof RiskScoreRow>().toEqualTypeOf<keyof typeof riskScoreSelect>();
    expectTypeOf<keyof EvaluationRow>().toEqualTypeOf<keyof typeof evaluationSelect>();
    expectTypeOf<AttachmentPartRow>().toEqualTypeOf<{
      partIndex: number;
      filename: string | null;
      declaredContentType: string | null;
    }>();
    expectTypeOf<ScanReadModelRows['policy']>().toEqualTypeOf<EvaluationRow | null>();
    expectTypeOf<ScanReadModelRows['engines']>().toEqualTypeOf<EngineResultRow[]>();
  });
});
