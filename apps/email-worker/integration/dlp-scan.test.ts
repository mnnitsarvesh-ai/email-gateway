import { encryptedZip } from '@email-gateway/attachment-corpus';
import {
  buildCorpus,
  type AttachmentFixture,
  type DlpCorpus,
  openEvidence,
  TINY_PNG,
  type TextFixture,
} from '@email-gateway/dlp';
import { messageDlpIncidentV1 } from '@email-gateway/event-contracts';
import { dlpEvidenceDocumentSchema } from '@email-gateway/security-contracts';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaDlpStore } from '../src/scanning/engines/dlp/dlp-store';
import type { DlpExtractor } from '../src/scanning/engines/dlp/extractor/pool';
import { createDlpJobs } from '../src/scanning/scanning.module';
import { DlpFixtures, DlpPipeline, type DlpMessageSpec } from './support/dlp';
import { requireEnv } from './support/fixtures';
import { testLocks } from './support/attachments';
import { ScanFixtures, type ScanMessage } from './support/scan';
import { silentLogger } from './support/fixtures';

/**
 * The dlp engine against the real stack (step 4.5 §9 "email-worker package integration"): MySQL
 * writer, MinIO, the real extractor child pool (TypeScript child in source runs), the round
 * service and the repository's finalize transaction with the dlp child rows (results, evidence,
 * incident outbox row). Fixtures are synthetic (`@email-gateway/dlp` corpus); every row and
 * object of the run is removed afterwards.
 */

const fx = new ScanFixtures();
const dfx = new DlpFixtures(fx);
let corpus: DlpCorpus;
let pipeline: DlpPipeline;
const KEY = requireEnv('DLP_EVIDENCE_KEY');

const text = (id: string) => (corpus.fixtures.find((f) => f.id === id) as TextFixture).text;
const att = (id: string) => {
  const f = [...corpus.fixtures, ...corpus.notExtracted].find(
    (x) => x.id === id,
  ) as AttachmentFixture;
  return {
    bytes: f.bytes,
    filename: `document.${f.filenameExt ?? 'bin'}`,
    declaredContentType: f.declaredContentType,
  };
};

beforeAll(async () => {
  corpus = await buildCorpus();
  pipeline = await DlpPipeline.start(fx);
});

afterAll(async () => {
  await pipeline?.close();
  await dfx.cleanup();
  await fx.cleanup();
});

const domains = new Map<bigint, string>();
async function tenant(label: string): Promise<bigint> {
  const org = await fx.organization(label);
  const domain = `it-dlp-${fx.suffix}-${label}.test`;
  await dfx.domain(org, domain);
  domains.set(org, domain);
  return org;
}
const sender = (org: bigint) => `alice@${domains.get(org)!}`;

async function scan(org: bigint, spec: DlpMessageSpec, p = pipeline) {
  const message = await dfx.message(org, {
    from: sender(org),
    rcpt: ['bob@partner.example.org'],
    ...spec,
  });
  expect(await p.deliver(fx.parsed(message))).toBe('handled');
  return { message, ...(await state(message)) };
}

async function state(message: ScanMessage) {
  const [results, evidence, incidents, { finals, attempts }, scanState] = await Promise.all([
    dfx.results(message),
    dfx.evidenceRows(message),
    dfx.incidents(message),
    dfx.finals(message),
    fx.state(message),
  ]);
  return { results, evidence, incidents, finals, attempts, scanState };
}

const codes = (final: { reasonCodes: unknown }) => final.reasonCodes as string[];
/** The row as JSON without its UUIDs (public ids hold digit groups that are not values). */
const dlpColumns = (row: Record<string, unknown>) =>
  JSON.stringify(row, (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v)).replace(
    /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    '<uuid>',
  );

describe('dlp engine package integration (step 4.5 §9)', () => {
  it('outbound card numbers in body and DOCX/XLSX/PDF/ZIP: suspicious, masked only, encrypted evidence, the rule action and one incident', async () => {
    const org = await tenant('cards');
    await dfx.compliance(org, true);
    const rule = await dfx.policy(org, {
      conditions: {
        selectors: { categories: ['payment_card'] },
        recipients: { externalOnly: true },
      },
      action: 'quarantine',
    });
    const { message, results, evidence, incidents, finals, scanState } = await scan(org, {
      text: text('text.every-detector'),
      attachments: [
        att('docx.body-header-footnote'),
        att('xlsx.shared-numeric-header'),
        att('pdf.text-layer'),
        att('zip.docx-and-csv'),
      ],
    });
    expect(finals).toHaveLength(1);
    expect(finals[0]!.outcome).toBe('suspicious');
    expect(codes(finals[0]!)[0]).toBe('dlp.action.quarantine');
    expect(scanState.message.status).toBe('scanned');
    expect(results).toHaveLength(1);
    const result = results[0]!;
    expect(result).toMatchObject({
      verdict: 'suspicious',
      action: 'quarantine',
      actionSource: 'tenant_policy',
      matchedPolicyId: rule.internalPolicyId,
      matchedRuleId: rule.internalRuleId,
      coverage: 'complete',
      evidenceStatus: 'stored',
      direction: 'outbound',
    });
    const findings = result.findings as Array<{
      detector: string;
      masked: string[];
      sources: Array<{ kind: string }>;
    }>;
    expect(findings.map((f) => f.detector)).toEqual(
      expect.arrayContaining(['PC1', 'NI1', 'BA1', 'NI2', 'CR1', 'CR3']),
    );
    const pc1 = findings.find((f) => f.detector === 'PC1')!;
    expect(pc1.sources.some((s) => s.kind === 'attachment')).toBe(true);
    expect(pc1.masked.every((m) => /^\*+[0-9]{4}$/.test(m))).toBe(true);
    // No 13–19 digit run, no Aadhaar digits, no secret in any DLP column.
    const columns = dlpColumns(result);
    expect(columns.match(/\d(?:[ -]?\d){12,18}/g)).toBeNull();
    for (const entry of corpus.manifest.entries) {
      if (entry.value.length >= 8) expect(columns).not.toContain(entry.value);
    }
    expect(result.policy).toMatchObject({
      winner: { policyId: rule.policyId, ruleId: rule.ruleId },
    });
    // Evidence row + object encrypted at rest; opened with the key it is the expected document.
    expect(evidence).toHaveLength(1);
    const row = evidence[0]!;
    expect(row.objectKey).toMatch(new RegExp(`^org/${org.toString()}/dlp-evidence/`));
    expect(row.wrappedKey).toMatch(/^v1\.k1\./);
    const object = await dfx.object(row.objectKey!);
    expect(object.subarray(0, 6).toString()).toBe('EGDLP1');
    for (const entry of corpus.manifest.entries) {
      if (entry.value.length >= 8) expect(object.includes(Buffer.from(entry.value))).toBe(false);
    }
    const opened = openEvidence({ current: KEY }, object, row.wrappedKey!, {
      organizationId: org.toString(),
      messageId: message.messageId.toString(),
      scanId: row.scanId.toString(),
    });
    const document = dlpEvidenceDocumentSchema.parse(JSON.parse(opened.plaintext.toString('utf8')));
    expect(document.matches.length).toBe(row.matchCount);
    expect(document.aadhaar).toBe('enabled');
    // PC1 evidence keeps first 6 + last 4 only.
    for (const m of document.matches.filter((x) => x.detector === 'PC1')) {
      expect(m.value).toMatch(/^[0-9]{6}\*+[0-9]{4}$/);
    }
    // Exactly one incident with public ids.
    expect(incidents).toHaveLength(1);
    expect(messageDlpIncidentV1.parse(incidents[0]!.payload)).toMatchObject({
      action: 'quarantine',
      actionSource: 'tenant_policy',
      policyId: rule.policyId,
      ruleId: rule.ruleId,
      evidenceAvailable: true,
    });
  });

  it('a recipient-domain exception lets the same message pass (allow, exception applied, no incident)', async () => {
    const org = await tenant('exception');
    await dfx.policy(org, {
      conditions: { selectors: { categories: ['payment_card'] } },
      action: 'block',
    });
    const exceptionId = await dfx.exception(org, 'recipient_domain', 'partner.example.org');
    const { results, incidents, finals } = await scan(org, {
      attachments: [att('pdf.text-layer')],
    });
    expect(results[0]).toMatchObject({ action: 'allow', verdict: 'suspicious' });
    expect(results[0]!.policy).toMatchObject({ exceptionsApplied: [exceptionId] });
    expect(codes(finals[0]!)).toContain('dlp.exception.applied');
    expect(incidents).toHaveLength(0);
  });

  it('duplicate events are idempotent: one final, one dlp row, one evidence row and object, one incident', async () => {
    const org = await tenant('dup');
    const message = await dfx.message(org, {
      from: sender(org),
      rcpt: ['bob@partner.example.org'],
      attachments: [att('pdf.text-layer')],
    });
    const event = fx.parsed(message);
    const outcomes = await Promise.all([
      pipeline.deliver(event),
      pipeline.deliver(event),
      pipeline.deliver(event),
    ]);
    expect(outcomes.filter((o) => o === 'handled').length).toBeGreaterThanOrEqual(1);
    // The reconciler's re-drive under a new delivery id finds the final row (already final).
    expect(['handled', 'duplicate']).toContain(await pipeline.deliver(fx.parsed(message)));
    const s = await state(message);
    expect(s.finals).toHaveLength(1);
    expect(s.results).toHaveLength(1);
    expect(s.evidence).toHaveLength(1);
    expect(s.incidents).toHaveLength(1);
    // Orphan objects of the losing attempts were deleted: exactly the committed one is left.
    expect(await dfx.evidenceObjects(org)).toEqual([s.evidence[0]!.objectKey]);
  });

  it('a rescan creates a new round with new rows; the old rows are untouched', async () => {
    const org = await tenant('rescan');
    const first = await scan(org, { attachments: [att('pdf.text-layer')] });
    const rescan = await fx.rescan(first.message);
    expect(await pipeline.deliver(rescan)).toBe('handled');
    const s = await state(first.message);
    expect(s.results).toHaveLength(2);
    expect(new Set(s.results.map((r) => r.scanId.toString())).size).toBe(2);
    expect(s.results.map((r) => r.lifecycleRound)).toEqual([0, 1]);
    expect(s.results[0]).toEqual(first.results[0]);
    expect(s.evidence).toHaveLength(2);
    expect(s.incidents).toHaveLength(2);
  });

  it('a coverage-only ALERT rule (encrypted archive) writes an incident without a category', async () => {
    const org = await tenant('coverage-alert');
    const rule = await dfx.policy(org, {
      conditions: { selectors: { coverageReasons: ['dlp.not_extracted.encrypted'] } },
      action: 'alert',
    });
    const { results, incidents, finals } = await scan(org, {
      text: 'Please see attached.',
      attachments: [
        { bytes: encryptedZip(), filename: 'archive.zip', declaredContentType: 'application/zip' },
      ],
    });
    expect(finals[0]!.outcome).toBe('unknown');
    expect(results[0]).toMatchObject({
      verdict: 'unknown',
      action: 'alert',
      actionSource: 'tenant_policy',
      coverage: 'partial',
    });
    expect(incidents).toHaveLength(1);
    const payload = messageDlpIncidentV1.parse(incidents[0]!.payload);
    expect(payload).toMatchObject({
      action: 'alert',
      policyId: rule.policyId,
      ruleId: rule.ruleId,
      categories: [],
      coverage: 'partial',
      evidenceAvailable: false,
    });
    expect(payload.detectorCodes).toContain('dlp.not_extracted.encrypted');
  });

  it('extraction failures are unknown with their codes, never clean', async () => {
    const org = await tenant('failures');
    const cases: Array<[DlpMessageSpec['attachments'], string]> = [
      [
        [
          {
            bytes: encryptedZip(),
            filename: 'archive.zip',
            declaredContentType: 'application/zip',
          },
        ],
        'dlp.not_extracted.encrypted',
      ],
      [[att('pdf.image-only')], 'dlp.not_extracted.no_text_layer'],
      [
        [{ bytes: TINY_PNG, filename: 'logo.png', declaredContentType: 'image/png' }],
        'dlp.not_extracted.image',
      ],
      [
        [{ bytes: Buffer.alloc(30_000_000, 65), filename: 'big.txt' }],
        'dlp.not_extracted.oversize',
      ],
      [
        [{ bytes: Buffer.from('plain'), filename: 'a.txt', stored: false }],
        'dlp.not_extracted.not_stored',
      ],
    ];
    for (const [attachments, code] of cases) {
      const { finals, results } = await scan(org, { text: 'Please see attached.', attachments });
      expect(finals[0]!.outcome, code).toBe('unknown');
      expect(codes(finals[0]!), code).toContain(code);
      expect(results[0]).toMatchObject({ verdict: 'unknown', coverage: 'partial' });
    }
  });

  it('a CPU kill of the real extractor child (selftest) is a definite resource_limit', async () => {
    const selftest = await DlpPipeline.start(fx, {
      overrides: { EG_INSPECTOR_SELFTEST: '1', DLP_EXTRACT_CPU_SECONDS: '1' },
    });
    try {
      const inner = (
        selftest.engine as unknown as {
          options: {
            extractor: DlpExtractor & {
              selftest(m: 'cpu', s: AbortSignal): ReturnType<DlpExtractor['extract']>;
            };
          };
        }
      ).options.extractor;
      const original = inner.extract.bind(inner);
      let first = true;
      inner.extract = (bytes, limits, hint, signal) => {
        if (!first) return original(bytes, limits, hint, signal);
        first = false;
        return inner.selftest('cpu', signal);
      };
      const org = await tenant('selftest');
      const { finals } = await scan(org, { attachments: [att('pdf.text-layer')] }, selftest);
      expect(finals[0]!.outcome).toBe('unknown');
      expect(codes(finals[0]!)).toContain('dlp.not_extracted.resource_limit');
      expect(await selftest.text()).toMatch(/dlp_extractor_kills_total\{reason="cpu"[^}]*\} 1/);
    } finally {
      await selftest.close();
    }
  });

  it('Aadhaar detection is off without the compliance row and on with it', async () => {
    const org = await tenant('aadhaar');
    const body = text('text.aadhaar-gated-off');
    const off = await scan(org, { text: body });
    expect(
      (off.results[0]!.findings as Array<{ detector: string }>).map((f) => f.detector),
    ).not.toContain('NI2');
    expect(off.results[0]!.coverageDetail).toMatchObject({ aadhaar: 'disabled' });
    await dfx.compliance(org, true);
    const on = await scan(org, { text: body });
    expect(
      (on.results[0]!.findings as Array<{ detector: string }>).map((f) => f.detector),
    ).toContain('NI2');
    expect(dlpColumns(on.results[0] as unknown as Record<string, unknown>)).not.toMatch(
      /\d{4}[ -]?\d{4}[ -]?\d{4}/,
    );
  });

  it('the evidence sweeper crypto-shreds expired rows and deletes their objects', async () => {
    const org = await tenant('sweeper');
    const { message, evidence } = await scan(org, { attachments: [att('pdf.text-layer')] });
    const key = evidence[0]!.objectKey!;
    await fx.prisma.dlpEvidence.updateMany({
      where: { messageId: message.messageId, receivedAt: message.receivedAt },
      data: { expiresAt: new Date(Date.now() - 60_000) },
    });
    const locks = testLocks();
    try {
      const { sweeper } = createDlpJobs({
        config: pipeline.config,
        prisma: fx.prisma,
        s3: fx.s3,
        locks,
        registry: pipeline.registry,
        logger: silentLogger,
        lockName: `it-dlp-evidence-${fx.suffix}`,
        organizationIds: [org],
      });
      const report = await sweeper.sweepOnce();
      expect(report).toMatchObject({
        outcome: 'swept',
        shredded: 1,
        objectsDeleted: 1,
        expiredUnpurged: 0,
      });
    } finally {
      await locks.close();
    }
    const after = await dfx.evidenceRows(message);
    expect(after[0]).toMatchObject({ wrappedKey: null, objectKey: null, purgeReason: 'retention' });
    expect(after[0]!.purgedAt).not.toBeNull();
    expect(await dfx.evidenceObjects(org)).not.toContain(key);
  });

  it('a forged attachment read (another organization echoed) is an inconsistent_read attempt, then succeeds', async () => {
    let forged = 0;
    const forging = new Proxy(fx.prisma, {
      get(target, prop, receiver) {
        if (prop !== 'emailAttachment') return Reflect.get(target, prop, receiver) as unknown;
        const delegate = target.emailAttachment;
        return {
          findMany: async (args: Parameters<typeof delegate.findMany>[0]) => {
            const rows = await delegate.findMany(args);
            if (forged > 0) return rows;
            forged += 1;
            return rows.map((r) => ({ ...r, organizationId: r.organizationId + 1000n }));
          },
        };
      },
    });
    const config = pipeline.config;
    const forgedPipeline = await DlpPipeline.start(fx, {
      dlp: {
        store: new PrismaDlpStore(
          forging,
          {
            policies: 20,
            rulesPerPolicy: 50,
            exceptions: 500,
            patterns: 50,
            dictionaries: 20,
            dictionaryMaxTerms: 1000,
            patternMaxLength: config.DLP_CUSTOM_PATTERN_MAX_LENGTH,
          },
          { ttlMs: 0 },
        ),
      },
    });
    try {
      const org = await tenant('forged');
      const message = await dfx.message(org, {
        from: sender(org),
        attachments: [att('pdf.text-layer')],
      });
      await expect(forgedPipeline.handle(fx.parsed(message))).rejects.toThrow(/inconsistent_read/);
      expect(await forgedPipeline.text()).toMatch(
        /scan_dlp_inconsistent_reads_total\{read="attachments"[^}]*\} 1/,
      );
      expect(await forgedPipeline.deliver(fx.parsed(message))).toBe('handled');
      const s = await state(message);
      expect(s.attempts.map((a) => a.errorCode)).toEqual(['inconsistent_read']);
      expect(s.finals[0]!.outcome).toBe('suspicious');
    } finally {
      await forgedPipeline.close();
    }
  });
});
