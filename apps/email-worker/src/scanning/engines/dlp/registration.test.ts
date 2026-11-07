import { MetricsService } from '@email-gateway/common';
import {
  DlpAction,
  DlpActionSource,
  DlpAadhaarBasis,
  DlpCoverage,
  DlpDictionaryCategory,
  DlpEvidencePurgeReason,
  DlpEvidenceStatus,
  DlpExceptionScope,
  DlpMaskStyle,
  DlpPatternValidator,
  DlpPolicyMode,
  DlpSeverity,
  DlpVerdict,
} from '@email-gateway/database';
import {
  buildCorpus,
  classifyDetection,
  composeCoverage,
  coverageFromExtraction,
  detect,
  DlpDictionarySet,
  dlpReasonCodes,
  dlpVerdict,
  ExtractionSession,
  loadTenantPatterns,
} from '@email-gateway/dlp';
import { createLogger } from '@email-gateway/logger';
import {
  DLP_AADHAAR_BASES,
  DLP_ACTION_SOURCES,
  DLP_ACTIONS,
  DLP_COVERAGE_CODES,
  DLP_COVERAGES,
  DLP_DETECTOR_CODES,
  DLP_DETECTORS,
  DLP_DICTIONARY_CATEGORIES,
  DLP_EVIDENCE_PURGE_REASONS,
  DLP_EVIDENCE_STATUSES,
  DLP_EXCEPTION_SCOPES,
  DLP_MASK_STYLES,
  DLP_PATTERN_VALIDATORS,
  DLP_POLICY_MODES,
  DLP_REASON_CODES,
  DLP_TENANT_SEVERITIES,
  DLP_VERDICTS,
  engineCatalogEntry,
  REASON_CODE_PATTERN,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { loadWorkerConfig } from '../../../config';
import { ENGINE_REGISTRY, enabledRegistrations } from '../../registry';
import { ScanMetrics } from '../../scan-metrics';
import { inspectBytes } from '../attachment/inspector/inspect';
import { NOOP_YARA_ENGINE } from '../attachment/inspector/yara-engine';
import { LIMITS, platformSettings } from './dlp.test-support';
import { walkSummaryOf } from './extractor/extraction';
import {
  createDlpEngine,
  DLP_CONSUMER,
  dlpLimitsFromConfig,
  dlpRegistration,
  dlpSettingsFor,
  evidenceKekFromConfig,
} from './registration';

const base = {
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  RABBITMQ_SCANNER_URL: 'amqp://sc:scanner-pw@localhost:5672/email-gateway',
  MIME_INGESTION_ENABLED: 'false',
  REDIS_URL: 'redis://localhost:6379',
  SCAN_ENGINES: 'dlp',
  DLP_EVIDENCE_KEY: 'ab'.repeat(32),
  S3_REGION: 'ap-south-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
};
const load = (env: Record<string, string> = {}) => loadWorkerConfig({ ...base, ...env });

describe('dlp engine registration (step 4.5 D1, D18)', () => {
  it('is registered after bec on scan.dlp as a required stage-1 engine with its ledger consumer', () => {
    expect(ENGINE_REGISTRY.map((r) => r.catalog.name)).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
      'dlp',
    ]);
    expect(dlpRegistration.consumerName).toBe('email-worker.scan.dlp');
    expect(DLP_CONSUMER).toBe('email-worker.scan.dlp');
    expect(dlpRegistration.catalog).toBe(engineCatalogEntry('dlp'));
    expect(dlpRegistration.catalog).toMatchObject({
      queue: 'scan.dlp',
      requiredByDefault: true,
      tenantMayDisable: false,
    });
    expect(dlpRegistration.catalog.dependsOn ?? []).toEqual([]);
    expect(enabledRegistrations(['dlp']).map((r) => r.catalog.name)).toEqual(['dlp']);
    expect(dlpRegistration.budget(load())).toEqual({
      concurrency: 4,
      timeoutMs: 120_000,
      maxAttempts: 3,
    });
  });

  it('resolves tenant settings within the bounds; an invalid row falls back to the platform', () => {
    const config = load();
    const none = dlpSettingsFor(config, null);
    expect(none.settingsVersion).toMatch(/^dlp-map\/1;p=[0-9a-f]{12};t=none$/);
    expect(none.settings).toEqual(platformSettings());
    const row = dlpSettingsFor(config, { settings: { inboundEnabled: true }, version: 3 });
    expect(row.settingsVersion).toMatch(/;t=3$/);
    expect(row.settings).toMatchObject({ inboundEnabled: true });
    const invalid = dlpSettingsFor(config, {
      settings: { thresholds: { payment_card: 0.1 }, bogus: 1 },
      version: 4,
    });
    expect(invalid.invalidRow).toBe(true);
    expect(invalid.violations).toEqual(['unknown_key']);
    expect(invalid.settingsVersion).toMatch(/;t=none$/);
  });

  it('derives the walker limits from the 4.2 platform limits and the extraction bounds', () => {
    const limits = dlpLimitsFromConfig(load({ ATTACHMENT_ARCHIVE_MAX_ENTRIES: '77' }));
    expect(limits.walk).toMatchObject({ archiveMaxEntries: 77, cpuSeconds: 10, maxRssMb: 512 });
    expect(limits.extract).toMatchObject({
      maxTextChars: 1_000_000,
      pdfMaxPages: 200,
      maxSegments: 200,
    });
  });

  it('builds the evidence KEK only with a 64-hex key; null when evidence is disabled', () => {
    expect(evidenceKekFromConfig(load())).toEqual({ current: 'ab'.repeat(32), previous: null });
    expect(evidenceKekFromConfig(load({ DLP_EVIDENCE_ENABLED: 'false' }))).toBeNull();
    expect(() => evidenceKekFromConfig({ ...load(), DLP_EVIDENCE_KEY: undefined })).toThrow(
      /DLP_EVIDENCE_KEY is required/,
    );
  });

  it('creates the engine with its readiness checks (dlp-engine, dlp-extractor)', () => {
    const registry = new MetricsService({ service: 'dlp-registration-test' });
    const engine = createDlpEngine({
      config: load(),
      logger: createLogger({ service: 'dlp-registration-test', level: 'silent' }),
      prisma: {} as never,
      s3: { client: {} as never, mailBucket: 'test-mail' },
      redis: null,
      metrics: new ScanMetrics(registry),
      registry,
    });
    expect(engine.engineVersion).toMatch(
      /^dlp\/1;dict=[0-9a-f]{8};data=[0-9a-f]{8};ext=dlp-extract\/1$/,
    );
    expect(engine.healthChecks().map((c) => c.name)).toEqual(['dlp-engine', 'dlp-extractor']);
  });
});

describe('dlp contract literals (step 4.5 §3, §4)', () => {
  it('the Prisma DLP enums equal the security-contracts lists', () => {
    expect(Object.values(DlpVerdict)).toEqual([...DLP_VERDICTS]);
    expect(Object.values(DlpAction)).toEqual([...DLP_ACTIONS]);
    expect(Object.values(DlpActionSource)).toEqual([...DLP_ACTION_SOURCES]);
    expect(Object.values(DlpCoverage)).toEqual([...DLP_COVERAGES]);
    expect(Object.values(DlpEvidenceStatus)).toEqual([...DLP_EVIDENCE_STATUSES]);
    expect(Object.values(DlpEvidencePurgeReason)).toEqual([...DLP_EVIDENCE_PURGE_REASONS]);
    expect(Object.values(DlpPolicyMode)).toEqual([...DLP_POLICY_MODES]);
    expect(Object.values(DlpExceptionScope)).toEqual([...DLP_EXCEPTION_SCOPES]);
    expect(Object.values(DlpPatternValidator)).toEqual([...DLP_PATTERN_VALIDATORS]);
    expect(Object.values(DlpSeverity)).toEqual([...DLP_TENANT_SEVERITIES]);
    expect(Object.values(DlpMaskStyle)).toEqual([...DLP_MASK_STYLES]);
    expect(Object.values(DlpDictionaryCategory)).toEqual([...DLP_DICTIONARY_CATEGORIES]);
    expect(Object.values(DlpAadhaarBasis)).toEqual([...DLP_AADHAAR_BASES]);
  });

  it('every code the dlp package emits on the corpus is a DLP_REASON_CODES code', async () => {
    for (const code of DLP_REASON_CODES) {
      expect(code).toMatch(REASON_CODE_PATTERN);
      expect(code.length).toBeLessThanOrEqual(64);
    }
    expect(Object.values(DLP_DETECTORS).map((d) => d.code)).toEqual([...DLP_DETECTOR_CODES]);
    const corpus = await buildCorpus();
    const patterns = loadTenantPatterns(corpus.tenantPatterns);
    const emitted = new Set<string>();
    for (const fixture of [...corpus.fixtures, ...corpus.notExtracted]) {
      let segments;
      let entries: ReturnType<typeof coverageFromExtraction> = [];
      if (fixture.kind === 'text') {
        segments = [
          {
            source: {
              kind: fixture.source,
              ...(fixture.source === 'attachment' ? { partIndex: 1 } : {}),
            },
            format: fixture.format,
            kind: fixture.segmentKind,
            text: fixture.text,
          },
        ];
      } else {
        const session = new ExtractionSession(
          { declaredContentType: fixture.declaredContentType, filenameExt: fixture.filenameExt },
          LIMITS.extract,
        );
        const inspection = await inspectBytes(fixture.bytes, LIMITS.walk, NOOP_YARA_ENGINE, {
          onEntry: session.visitor,
        });
        const extraction = await session.finish(
          fixture.bytes,
          inspection.type.detected,
          walkSummaryOf(inspection),
        );
        entries = coverageFromExtraction(1, extraction);
        segments = extraction.segments.map((s) => ({
          source: {
            kind: 'attachment' as const,
            partIndex: 1,
            ...(s.path === 'attachment' ? {} : { path: s.path }),
          },
          format: s.format,
          kind: s.kind,
          text: s.text,
          ...(s.headers ? { headers: s.headers } : {}),
        }));
      }
      const detection = await detect({
        segments,
        settings: platformSettings(),
        aadhaarEnabled: true,
        dictionaries: DlpDictionarySet.create(corpus.tenantDictionaries),
        customPatterns: patterns.loaded,
        now: new Date('2026-11-07T06:00:00Z'),
      });
      const classification = classifyDetection(detection);
      const coverage = composeCoverage(entries, detection.coverageCodes);
      for (const code of coverage.reasons) expect(DLP_COVERAGE_CODES).toContain(code);
      for (const code of dlpReasonCodes({
        verdict: dlpVerdict(classification.findings.length, coverage.coverage),
        decision: null,
        findings: classification.findings,
        coverageReasons: coverage.reasons,
        matchCapped: classification.matchCapped,
      }))
        emitted.add(code);
    }
    for (const code of emitted) expect(DLP_REASON_CODES).toContain(code);
    expect(emitted.size).toBeGreaterThan(20);
  });
});
