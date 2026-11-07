import { Writable } from 'node:stream';
import {
  buildCorpus,
  type AttachmentFixture,
  CORPUS_DICTIONARY_ID,
  CORPUS_PATTERN_ID,
  DlpDictionarySet,
  type DlpCorpus,
  loadTenantPatterns,
  openEvidence,
  type TextFixture,
} from '@email-gateway/dlp';
import { createLogger } from '@email-gateway/logger';
import {
  DLP_REASON_CODES,
  dlpEvidenceDocumentSchema,
  dlpFindingViewSchema,
} from '@email-gateway/security-contracts';
import { messageDlpIncidentV1 } from '@email-gateway/event-contracts';
import { beforeAll, describe, expect, it } from 'vitest';
import type { EngineDefinite, EngineFailure, EngineScanOutcome } from '../../engine';
import {
  context,
  emptyTenant,
  harness,
  messageWith,
  ORG,
  platformSettings,
  TEST_KEK,
} from './dlp.test-support';

let corpus: DlpCorpus;
beforeAll(async () => {
  corpus = await buildCorpus();
});

const text = (id: string): string => (corpus.fixtures.find((f) => f.id === id) as TextFixture).text;
const att = (id: string): AttachmentFixture =>
  [...corpus.fixtures, ...corpus.notExtracted].find((f) => f.id === id) as AttachmentFixture;
const attachment = (id: string) => {
  const f = att(id);
  return {
    bytes: f.bytes,
    filename: f.filenameExt ? `file.${f.filenameExt}` : 'file',
    declaredContentType: f.declaredContentType,
  };
};

const definite = (outcome: EngineScanOutcome): EngineDefinite => {
  if (outcome.kind !== 'definite') throw new Error(`expected definite, got ${outcome.errorCode}`);
  return outcome;
};
const failed = (outcome: EngineScanOutcome): EngineFailure => {
  if (outcome.kind !== 'failure') throw new Error('expected a failure');
  return outcome;
};
const signal = () => AbortSignal.timeout(60_000);
const aadhaarOn = () =>
  emptyTenant({
    compliance: {
      aadhaarEnabled: true,
      aadhaarBasis: 'regulatory_obligation',
      aadhaarReference: 'REF-1',
      aadhaarAttested: true,
      aadhaarReviewDueAt: new Date('2027-06-01T00:00:00Z'),
    },
  });

/** Every 13–19 digit run (with or without separators) of a JSON text. */
const digitRuns = (value: string): string[] =>
  [...value.matchAll(/\d(?:[ -]?\d){12,18}/g)].map((m) => m[0]);

describe('dlp engine: direction rule (D1)', () => {
  it('inbound without inboundEnabled is a fast skipped final with dlp.not_inbound (no read)', async () => {
    const h = harness((p) => messageWith(p, { text: text('text.every-detector') }));
    const out = definite(await h.engine.scan(context({ direction: 'inbound' }), signal()));
    expect(out.result.outcome).toBe('skipped');
    expect(out.result.reasonCodes).toEqual(['dlp.not_inbound']);
    expect(h.store.calls).toEqual([]);
    expect(h.parts.reads).toBe(0);
    expect(out.childRows?.dlp?.result).toMatchObject({
      verdict: 'skipped',
      action: 'allow',
      actionSource: 'none',
      findings: [],
      evidenceStatus: 'none',
    });
    expect(out.childRows?.dlp?.incident).toBeNull();
  });

  it('inbound is scanned when the tenant enabled it; outbound and internal always', async () => {
    for (const [direction, settings] of [
      ['inbound', platformSettings({ inboundEnabled: true })],
      ['outbound', platformSettings()],
      ['internal', platformSettings()],
    ] as const) {
      const h = harness((p) => messageWith(p, { text: 'Hello, see you tomorrow.' }));
      const out = definite(await h.engine.scan(context({ direction, settings }), signal()));
      expect(out.result.outcome).toBe('clean');
      expect(out.result.reasonCodes).toEqual(['dlp.no_findings']);
    }
  });
});

describe('dlp engine: full message on the corpus (D3–D16)', () => {
  it('outbound body + PDF/DOCX/XLSX/ZIP attachments: suspicious, masked only, sealed evidence, default alert incident', async () => {
    const h = harness((p) =>
      messageWith(p, {
        text: text('text.every-detector'),
        attachments: [
          attachment('pdf.text-layer'),
          attachment('docx.body-header-footnote'),
          attachment('xlsx.shared-numeric-header'),
          attachment('zip.docx-and-csv'),
        ],
      }),
    );
    h.store.tenant = aadhaarOn();
    const ctx = context();
    const out = definite(await h.engine.scan(ctx, signal()));
    expect(out.result.outcome).toBe('suspicious');
    expect(out.result.action).toBe('alert');
    expect(out.result.reasonCodes[0]).toBe('dlp.action.alert');
    for (const code of out.result.reasonCodes) expect(DLP_REASON_CODES).toContain(code);
    const rows = out.childRows!.dlp!;
    expect(rows.result.verdict).toBe('suspicious');
    expect(rows.result.actionSource).toBe('default_policy');
    expect(rows.result.coverage).toBe('complete');
    expect(rows.result.coverageDetail).toMatchObject({ aadhaar: 'enabled' });
    const detectors = rows.result.findings.map((f) => f.detector);
    expect(detectors).toEqual(expect.arrayContaining(['PC1', 'NI1', 'BA1', 'BA2', 'NI2', 'CR1']));
    for (const f of rows.result.findings)
      expect(dlpFindingViewSchema.safeParse(f).success).toBe(true);
    const stored = JSON.stringify(rows.result);
    expect(digitRuns(stored)).toEqual([]);
    for (const entry of corpus.manifest.entries) {
      if (entry.value.length >= 8) expect(stored).not.toContain(entry.value);
    }
    // Evidence: sealed object at rest, the row's wrapped key opens it to the document.
    expect(rows.result.evidenceStatus).toBe('stored');
    const evidence = rows.evidence!;
    expect(evidence.objectKey).toMatch(
      new RegExp(`^org/${ORG.toString()}/dlp-evidence/2026/11/77-[0-9a-f-]{36}\\.bin$`),
    );
    const object = h.evidence.objects.get(evidence.objectKey)!;
    for (const entry of corpus.manifest.entries) {
      if (entry.value.length >= 8) expect(object.includes(Buffer.from(entry.value))).toBe(false);
    }
    const opened = openEvidence({ current: TEST_KEK }, object, evidence.wrappedKey, {
      organizationId: ORG.toString(),
      messageId: ctx.messageId.toString(),
      scanId: ctx.scanId.toString(),
    });
    const document = dlpEvidenceDocumentSchema.parse(JSON.parse(opened.plaintext.toString('utf8')));
    expect(document.matches.length).toBe(evidence.matchCount);
    expect(evidence.expiresAt.getTime() - ctx.receivedAt.getTime()).toBe(30 * 86_400_000);
    // The incident event payload validates against the contract.
    const incident = messageDlpIncidentV1.parse(rows.incident!.payload);
    expect(incident).toMatchObject({
      action: 'alert',
      actionSource: 'default_policy',
      policyId: null,
    });
    expect(incident.evidenceAvailable).toBe(true);
  });

  it('Aadhaar is off without the compliance row (no NI2, coverage detail says disabled)', async () => {
    const h = harness((p) => messageWith(p, { text: text('text.every-detector') }));
    const out = definite(await h.engine.scan(context(), signal()));
    const rows = out.childRows!.dlp!;
    expect(rows.result.findings.map((f) => f.detector)).not.toContain('NI2');
    expect(rows.result.coverageDetail).toMatchObject({ aadhaar: 'disabled' });
  });

  it('an expired compliance review turns Aadhaar off again (D17)', async () => {
    const h = harness((p) => messageWith(p, { text: text('text.every-detector') }));
    h.store.tenant = emptyTenant({
      compliance: {
        aadhaarEnabled: true,
        aadhaarBasis: 'other',
        aadhaarReference: 'R',
        aadhaarAttested: true,
        aadhaarReviewDueAt: new Date('2026-11-01T00:00:00Z'),
      },
    });
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.childRows!.dlp!.result.findings.map((f) => f.detector)).not.toContain('NI2');
  });

  it('tenant dictionaries and patterns are applied with public ids', async () => {
    const h = harness((p) => messageWith(p, { text: text('text.tenant-dictionary-and-pattern') }));
    const patterns = loadTenantPatterns(corpus.tenantPatterns);
    h.store.tenant = emptyTenant({
      patterns: patterns.loaded,
      dictionaries: DlpDictionarySet.create(corpus.tenantDictionaries),
    });
    const out = definite(await h.engine.scan(context(), signal()));
    const findings = out.childRows!.dlp!.result.findings;
    expect(findings.find((f) => f.detector === 'CU1')).toMatchObject({
      customPatternId: CORPUS_PATTERN_ID,
    });
    expect(findings.find((f) => f.detector === 'DC1')).toMatchObject({
      dictionaryId: CORPUS_DICTIONARY_ID,
    });
  });
});

describe('dlp engine: coverage, never clean by accident (§2.0-1, D10)', () => {
  const unknownWith = async (spec: Parameters<typeof messageWith>[1], code: string) => {
    const h = harness((p) => messageWith(p, spec));
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.result.outcome).toBe('unknown');
    expect(out.result.reasonCodes).toContain('dlp.coverage.partial');
    expect(out.result.reasonCodes).toContain(code);
    return { h, out };
  };

  it('encrypted ZIP, password PDF, image-only PDF, PNG and OLE are unknown with their codes', async () => {
    for (const [id, code] of [
      ['zip.encrypted', 'dlp.not_extracted.encrypted'],
      ['pdf.password', 'dlp.not_extracted.encrypted'],
      ['pdf.image-only', 'dlp.not_extracted.no_text_layer'],
      ['png.image', 'dlp.not_extracted.image'],
      ['doc.ole', 'dlp.not_extracted.unsupported_type'],
    ] as const) {
      await unknownWith({ text: 'Please find attached.', attachments: [attachment(id)] }, code);
    }
  });

  it('a part that is not stored, an oversize part and the attachment cap are decided without a child', async () => {
    const small = { bytes: Buffer.from('plain words only'), filename: 'a.txt' };
    const { h } = await unknownWith(
      { attachments: [{ ...small, stored: false }] },
      'dlp.not_extracted.not_stored',
    );
    expect(h.extractor.jobs).toBe(0);
    const big = harness((p) =>
      messageWith(p, { attachments: [{ bytes: Buffer.alloc(2_000_000, 97) }] }),
    );
    const out = definite(await big.engine.scan(context(), signal()));
    expect(out.result.reasonCodes).toContain('dlp.not_extracted.oversize');
    expect(big.extractor.jobs).toBe(0);
    const many = harness((p) =>
      messageWith(p, { attachments: Array.from({ length: 6 }, () => small) }),
    );
    const capped = definite(await many.engine.scan(context(), signal()));
    expect(capped.result.reasonCodes).toContain('dlp.not_extracted.attachment_cap');
    expect(many.extractor.jobs).toBe(5);
  });

  it('a body above the byte cap, a body not stored and an incomplete parse are partial', async () => {
    const h = harness((p) => messageWith(p, { text: 'hello '.repeat(200) }), {
      limits: { bodyMaxBytes: 100 },
    });
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.result.reasonCodes).toContain('dlp.text.truncated');
    await unknownWith({ text: 'hi', limitsExceeded: ['body_size'] }, 'dlp.text.body_not_stored');
    await unknownWith({ text: 'hi', limitsExceeded: ['part_count'] }, 'dlp.parse.incomplete');
  });

  it('a CPU/RSS kill is a definite resource_limit of that attachment', async () => {
    const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    h.extractor.outcomes.push({ kind: 'limit', code: 'limit.cpu_time' });
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.result.outcome).toBe('unknown');
    expect(out.result.reasonCodes).toContain('dlp.not_extracted.resource_limit');
  });
});

describe('dlp engine: failure classes (D3)', () => {
  it('extractor wall clock and crash are retryable reused codes', async () => {
    for (const [reason, code, outcome] of [
      ['wall', 'inspector_timeout', 'timeout'],
      ['crash', 'inspector_crash', 'error'],
      ['unavailable', 'inspector_crash', 'error'],
    ] as const) {
      const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
      h.extractor.outcomes.push({ kind: 'failure', reason });
      const f = failed(await h.engine.scan(context(), signal()));
      expect(f).toMatchObject({ outcome, errorCode: code, retryable: true });
    }
  });

  it('missing parse row, missing / tampered part and a foreign key are not retryable', async () => {
    const noParse = harness((p) => ({ ...messageWith(p, { text: 'x' }), parse: null }));
    expect(failed(await noParse.engine.scan(context(), signal()))).toMatchObject({
      errorCode: 'parse_row_missing',
      retryable: false,
    });
    const missing = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    missing.parts.objects.clear();
    expect(failed(await missing.engine.scan(context(), signal())).errorCode).toBe(
      'part_unavailable',
    );
    const tampered = harness((p) =>
      messageWith(p, { attachments: [attachment('pdf.text-layer')] }),
    );
    for (const key of tampered.parts.objects.keys())
      tampered.parts.objects.set(key, Buffer.from('x'));
    expect(failed(await tampered.engine.scan(context(), signal())).errorCode).toBe(
      'part_integrity',
    );
    const foreign = harness((p) => {
      const m = messageWith(p, { attachments: [attachment('pdf.text-layer')] });
      m.attachments[0]!.objectKey = 'org/999/part/x.att';
      return m;
    });
    expect(failed(await foreign.engine.scan(context(), signal())).errorCode).toBe(
      'part_key_mismatch',
    );
  });

  it('a wrong attachment count read is inconsistent_read (retryable), counted by read', async () => {
    const h = harness((p) => {
      const m = messageWith(p, { attachments: [attachment('pdf.text-layer')] });
      m.parse!.attachmentCount = 3;
      return m;
    });
    expect(failed(await h.engine.scan(context(), signal()))).toMatchObject({
      errorCode: 'inconsistent_read',
      retryable: true,
    });
    expect(await h.registry.metrics()).toMatch(
      /scan_dlp_inconsistent_reads_total\{[^}]*read="attachments"[^}]*\} 1/,
    );
  });

  it('attachments are extracted up to extractConcurrency at a time; results stay in part order (closer review)', async () => {
    const files = [
      'pdf.text-layer',
      'docx.body-header-footnote',
      'xlsx.shared-numeric-header',
      'zip.docx-and-csv',
    ];
    const sequentialOrder = async (concurrency: number) => {
      const h = harness((p) => messageWith(p, { attachments: files.map((id) => attachment(id)) }), {
        limits: { extractConcurrency: concurrency },
      });
      h.extractor.delayMs = 40;
      const started = performance.now();
      const out = definite(await h.engine.scan(context(), signal()));
      return { h, out, ms: performance.now() - started };
    };
    const one = await sequentialOrder(1);
    const two = await sequentialOrder(2);
    expect(one.h.extractor.maxInFlight).toBe(1);
    expect(two.h.extractor.maxInFlight).toBe(2);
    expect(two.h.extractor.jobs).toBe(files.length);
    // 4 jobs of 40 ms: about 160 ms one at a time, about 80 ms two at a time.
    expect(two.ms).toBeLessThan(one.ms);
    // Same result whatever the concurrency (segments are consumed in part order).
    const stored = (o: EngineDefinite) => {
      const row = o.childRows!.dlp!.result;
      return JSON.stringify([row.verdict, row.action, row.findings, row.coverageDetail]);
    };
    expect(stored(two.out)).toBe(stored(one.out));
    expect(two.out.result.reasonCodes).toEqual(one.out.result.reasonCodes);
  });

  it('a slow extractor across many attachments: the first failure aborts the rest and is reported once', async () => {
    const h = harness(
      (p) =>
        messageWith(p, {
          attachments: Array.from({ length: 5 }, () => attachment('pdf.text-layer')),
        }),
      { limits: { extractConcurrency: 2 } },
    );
    h.extractor.delayMs = 20;
    h.extractor.outcomes.push({ kind: 'failure', reason: 'wall' });
    expect(failed(await h.engine.scan(context(), signal()))).toMatchObject({
      outcome: 'timeout',
      errorCode: 'inspector_timeout',
      retryable: true,
    });
    // No new job starts after the failure: at most the one already running in the other lane.
    expect(h.extractor.jobs).toBeLessThanOrEqual(3);
    expect(h.extractor.inFlight).toBe(0);
  });

  it('concurrent large messages complete under the work-time detection deadline', async () => {
    // Three concurrent messages on one loop with the work-time deadline (the deterministic proof
    // that yielded time is not counted is the WorkClock test of @email-gateway/dlp detect()).
    const big = text('text.every-detector').repeat(100);
    const run = () => {
      const h = harness((p) => messageWith(p, { text: big }), {
        limits: { detectTimeoutMs: 30_000 },
      });
      return h.engine.scan(context(), signal());
    };
    const outs = await Promise.all([run(), run(), run()]);
    for (const out of outs) expect(definite(out).result.outcome).toBe('suspicious');
  }, 60_000);

  it('the detection deadline is extract_timeout (retryable)', async () => {
    const h = harness((p) => messageWith(p, { text: text('text.every-detector').repeat(50) }), {
      limits: { detectTimeoutMs: -1 },
    });
    expect(failed(await h.engine.scan(context(), signal()))).toMatchObject({
      outcome: 'timeout',
      errorCode: 'extract_timeout',
      retryable: true,
    });
  });
});

describe('dlp engine: policy and evidence (D11–D16)', () => {
  const policyTenant = () =>
    emptyTenant({
      policies: [
        {
          id: '0196f3a0-0000-7000-8000-0000000000a1',
          version: 1,
          enabled: true,
          mode: 'enforce',
          priority: 10,
          directions: ['outbound'],
          rules: [
            {
              id: '0196f3a0-0000-7000-8000-0000000000b1',
              version: 1,
              enabled: true,
              priority: 1,
              conditions: {
                selectors: { categories: ['payment_card'] },
                recipients: { externalOnly: true },
              },
              action: 'quarantine',
            },
          ],
        },
      ],
      internalIds: new Map([
        ['0196f3a0-0000-7000-8000-0000000000a1', 5n],
        ['0196f3a0-0000-7000-8000-0000000000b1', 6n],
      ]),
    });

  it('a tenant rule yields its action with public ids in JSON and internal ids in the columns', async () => {
    const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    h.store.tenant = policyTenant();
    const out = definite(await h.engine.scan(context(), signal()));
    const rows = out.childRows!.dlp!;
    expect(rows.result).toMatchObject({
      action: 'quarantine',
      actionSource: 'tenant_policy',
      matchedPolicyId: 5n,
      matchedRuleId: 6n,
    });
    expect(rows.result.policy).toMatchObject({
      winner: {
        policyId: '0196f3a0-0000-7000-8000-0000000000a1',
        ruleId: '0196f3a0-0000-7000-8000-0000000000b1',
      },
    });
    expect(messageDlpIncidentV1.parse(rows.incident!.payload)).toMatchObject({
      action: 'quarantine',
      policyId: '0196f3a0-0000-7000-8000-0000000000a1',
    });
  });

  it('a coverage-only ALERT rule writes an incident without a category (D14, closer review)', async () => {
    const h = harness((p) =>
      messageWith(p, { text: 'Please find attached.', attachments: [attachment('zip.encrypted')] }),
    );
    const base = policyTenant();
    const policy = base.policies[0]!;
    const tenant = {
      ...base,
      policies: [
        {
          ...policy,
          rules: [
            {
              ...policy.rules[0]!,
              conditions: {
                selectors: { coverageReasons: ['dlp.not_extracted.encrypted' as const] },
              },
              action: 'alert' as const,
            },
          ],
        },
      ],
    };
    h.store.tenant = tenant;
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.result.outcome).toBe('unknown');
    expect(out.result.action).toBe('alert');
    const incident = messageDlpIncidentV1.parse(out.childRows!.dlp!.incident!.payload);
    expect(incident).toMatchObject({
      action: 'alert',
      actionSource: 'tenant_policy',
      ruleId: '0196f3a0-0000-7000-8000-0000000000b1',
      categories: [],
      coverage: 'partial',
      evidenceAvailable: false,
    });
    expect(incident.detectorCodes).toContain('dlp.not_extracted.encrypted');
  });

  it('a recipient exception lets the message pass and is recorded', async () => {
    const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    h.store.tenant = {
      ...policyTenant(),
      exceptions: [
        {
          id: '0196f3a0-0000-7000-8000-0000000000c1',
          version: 1,
          scope: 'recipient_domain',
          value: 'partner.example.org',
          policyId: null,
          ruleId: null,
          filters: null,
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          enabled: true,
        },
      ],
    };
    const out = definite(await h.engine.scan(context(), signal()));
    const rows = out.childRows!.dlp!;
    expect(rows.result.action).toBe('allow');
    expect(rows.result.policy).toMatchObject({
      exceptionsApplied: ['0196f3a0-0000-7000-8000-0000000000c1'],
    });
    expect(out.result.reasonCodes).toContain('dlp.exception.applied');
    expect(rows.incident).toBeNull();
  });

  it('a truncated recipient list never applies recipient exceptions (D11)', async () => {
    const h = harness((p) =>
      messageWith(p, { attachments: [attachment('pdf.text-layer')], recipientCount: 5 }),
    );
    h.store.tenant = {
      ...policyTenant(),
      exceptions: [
        {
          id: '0196f3a0-0000-7000-8000-0000000000c1',
          version: 1,
          scope: 'recipient_domain',
          value: 'partner.example.org',
          policyId: null,
          ruleId: null,
          filters: null,
          expiresAt: new Date('2027-01-01T00:00:00Z'),
          enabled: true,
        },
      ],
    };
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.childRows!.dlp!.result.action).toBe('quarantine');
  });

  it('evidence disabled by the tenant or the platform: status disabled, no object', async () => {
    const tenantOff = harness((p) =>
      messageWith(p, { attachments: [attachment('pdf.text-layer')] }),
    );
    const out = definite(
      await tenantOff.engine.scan(
        context({ settings: platformSettings({ evidence: { enabled: false } }) }),
        signal(),
      ),
    );
    expect(out.childRows!.dlp!.result.evidenceStatus).toBe('disabled');
    expect(out.childRows!.dlp!.evidence).toBeNull();
    const platformOff = harness(
      (p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }),
      {
        kek: null,
      },
    );
    const off = definite(await platformOff.engine.scan(context(), signal()));
    expect(off.childRows!.dlp!.result.evidenceStatus).toBe('disabled');
    expect(platformOff.evidence.objects.size).toBe(0);
  });

  it('an evidence write failure is recorded as failed (the result stands)', async () => {
    const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    h.evidence.failPut = true;
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.childRows!.dlp!.result.evidenceStatus).toBe('failed');
    expect(out.childRows!.dlp!.evidence).toBeNull();
    expect(await h.registry.metrics()).toMatch(
      /dlp_evidence_writes_total\{result="failed"[^}]*\} 1/,
    );
  });

  it('deleteOrphan removes an uncommitted object and counts it', async () => {
    const h = harness((p) => messageWith(p, { attachments: [attachment('pdf.text-layer')] }));
    const out = definite(await h.engine.scan(context(), signal()));
    const key = out.childRows!.dlp!.evidence!.objectKey;
    await h.engine.deleteOrphan(key, ORG);
    expect(h.evidence.objects.has(key)).toBe(false);
    h.evidence.failDelete = true;
    await h.engine.deleteOrphan(key, ORG);
    await h.engine.deleteOrphan('org/1/part/x', ORG);
    const text = await h.registry.metrics();
    expect(text).toMatch(/dlp_evidence_writes_total\{result="orphan_deleted"[^}]*\} 1/);
    expect(text).toMatch(/dlp_evidence_writes_total\{result="orphan_left"[^}]*\} 2/);
  });
});

describe('dlp engine: logs carry no value (§2.0-2, D22)', () => {
  it('a full corpus run logs ids, codes and counts only', async () => {
    const lines: string[] = [];
    const sink = new Writable({
      write(chunk: Buffer, _enc, done) {
        lines.push(chunk.toString('utf8'));
        done();
      },
    });
    const logger = createLogger({ service: 'dlp-log-test', level: 'trace', destination: sink });
    const attachments = [...corpus.fixtures, ...corpus.notExtracted]
      .filter((f): f is AttachmentFixture => f.kind === 'attachment')
      .map((f) => ({
        bytes: f.bytes,
        filename: `doc.${f.filenameExt ?? 'bin'}`,
        declaredContentType: f.declaredContentType,
      }));
    const texts = corpus.fixtures.filter((f): f is TextFixture => f.kind === 'text');
    const h = harness(
      (p) =>
        messageWith(p, {
          subject: 'Card 4532 0151 1283 0366',
          text: texts
            .filter((t) => t.format !== 'html')
            .map((t) => t.text)
            .join('\n\n'),
          html: texts.find((t) => t.format === 'html')?.text ?? null,
          attachments: attachments.slice(0, 5),
        }),
      { logger, limits: { maxAttachments: 3 } },
    );
    h.store.tenant = aadhaarOn();
    const out = definite(await h.engine.scan(context(), signal()));
    expect(out.result.outcome).toBe('suspicious');
    // A failing run logs too.
    h.extractor.outcomes.push({ kind: 'failure', reason: 'crash' });
    await h.engine.scan(context(), signal());
    const log = lines.join('');
    expect(log).toContain('dlp incident');
    const masked = (out.childRows!.dlp!.result.findings as Array<{ masked: string[] }>).flatMap(
      (f) => f.masked,
    );
    for (const entry of corpus.manifest.entries) {
      if (entry.value.length >= 6) expect(log).not.toContain(entry.value);
    }
    for (const m of masked) if (m.length >= 6) expect(log).not.toContain(m);
    expect(log).not.toContain('4532 0151 1283 0366');
    expect(digitRuns(log)).toEqual([]);
  });
});
