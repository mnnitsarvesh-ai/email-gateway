import {
  buildScoringInput,
  canonicalJson,
  resolveProfile,
  riskResultToRowJson,
  scoreRisk,
  scoringErrorResult,
  type RoundRows,
} from '@email-gateway/risk-scoring';
import { describe, expect, it } from 'vitest';
import { evaluatePolicy } from './evaluate';
import { DEPT, snapshotOf } from './fixtures.test-support';
import {
  buildPolicyInput,
  PolicyInputError,
  policyInputSchema,
  type PolicyRoundRows,
} from './input';
import { POLICY_LIMITS } from './vocabulary';

const COMPLETED = new Date('2026-11-10T10:00:00.000Z');
type Final = RoundRows['finals'][number];

function final(engine: string, outcome: Final['outcome'], reasonCodes: string[]): Final {
  return {
    engine,
    outcome,
    errorCode: outcome === 'timeout' || outcome === 'error' ? 'engine.timeout' : null,
    reasonCodes,
    score: engine === 'rspamd' ? '1.5' : null,
    engineVersion: `${engine}/1`,
    settingsVersion: `${engine}-map/1`,
    attempt: 1,
    completedAt: COMPLETED,
  };
}

/** A clean inbound round as 5.1 `RoundRows` (the scorer's input rows). */
function cleanRound(): RoundRows {
  return {
    scan: {
      requiredEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp'],
      scanKind: 'initial',
      lifecycleRound: 0,
      status: 'completed',
    },
    message: { direction: 'inbound', attachmentCount: 1, recipientCount: 2 },
    finals: [
      final('rspamd', 'clean', ['clean.below_threshold']),
      final('attachment', 'clean', ['clean.no_findings']),
      final('url', 'clean', ['clean.no_findings']),
      final('bec', 'clean', ['clean.below_threshold']),
      final('dlp', 'clean', ['dlp.no_findings']),
    ],
    auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
    bec: { deterministicVerdict: 'clean', verdict: 'clean', rules: [] },
    dlp: { action: 'allow', verdict: 'clean', coverage: 'complete', categories: [] },
  };
}

const withFinal = (r: RoundRows, f: Final): RoundRows => ({
  ...r,
  finals: [...r.finals.filter((x) => x.engine !== f.engine), f],
});

/** A real 5.1 risk row (scoreRisk + riskResultToRowJson) for the round. */
function riskRow(
  round: RoundRows,
  revision: 0 | 1 = 0,
  error = false,
): PolicyRoundRows['risk'][number] {
  const resolved = resolveProfile('rsk-default/1', null);
  const result = error
    ? scoringErrorResult(null, resolved, 'scorer_exception')
    : scoreRisk(buildScoringInput(round, revision), resolved);
  const row = riskResultToRowJson(result);
  return {
    revision,
    status: row.status,
    score: row.score,
    level: row.level,
    verdict: row.verdict,
    recommendedAction: row.recommendedAction,
    hardBlocks: row.hardBlocks,
    reasonCodes: row.reasonCodes,
    failures: row.failures,
    engines: row.engines,
    evidence: row.evidence,
  };
}

/** Policy rows of a round (inbound, two recipients, one attachment, one URL). */
function policyRows(
  round: RoundRows = cleanRound(),
  extra: Partial<PolicyRoundRows> = {},
): PolicyRoundRows {
  return {
    trigger: round.scan.status === 'completed' ? 'scanned' : 'scan_failed',
    message: {
      direction: round.message.direction,
      envelopeFrom: 'Alice@Partner.Example',
      headerFrom: 'alice@partner.example',
      clientIp: '::ffff:198.51.100.7',
      clientName: 'MX1.Partner.Example',
      sizeBytes: 12345,
      recipientCount: 2,
      attachmentCount: 1,
      lifecycleRound: 0,
    },
    recipients: [
      { rcptSeq: 1, address: 'Bob@Corp.Example' },
      { rcptSeq: 0, address: 'carol@corp.example' },
    ],
    scan: {
      scanId: 4242n,
      lifecycleRound: 0,
      scanKind: 'initial',
      status: round.scan.status,
      scanVerdict: round.scan.status === 'completed' ? 'clean' : 'error',
      reasonCodes: [],
      requiredEngines: round.scan.requiredEngines,
      completedAt: COMPLETED,
    },
    parseFailedAt: null,
    finals: round.finals.map((f) => ({
      engine: f.engine,
      outcome: f.outcome,
      reasonCodes: f.reasonCodes,
    })),
    auth: round.auth,
    bec: round.bec,
    dlp: round.dlp,
    risk: [riskRow(round)],
    attachments: [
      {
        partIndex: 2,
        filename: 'Report.ZIP',
        declaredContentType: 'Application/Zip; name="x"',
        detectedContentType: 'application/zip',
        sizeBytes: 2048,
        sha256: 'A'.repeat(64),
        archiveInfo: { type: 'zip', encryptedEntries: 1 },
      },
    ],
    attachmentResults: [
      {
        partIndex: 2,
        detectedType: 'zip',
        typeFamily: 'archive',
        typeMismatch: false,
        verdict: 'suspicious',
        reasonCodes: ['archive.encrypted', 'archive.depth'],
        archive: { encrypted: true },
      },
    ],
    urls: [
      {
        urlSeq: 0,
        host: 'Login.Example.COM',
        registrableDomain: 'example.com',
        scheme: 'https',
        hostKind: 'domain',
        truncated: false,
      },
    ],
    urlResults: [{ urlSeq: 0, verdict: 'clean', reasonCodes: [], rewritten: true }],
    urlRewrite: { status: 'rewritten', skipReason: null },
    directory: {
      departmentsByAddress: { 'bob@corp.example': [DEPT.sales, DEPT.finance] },
      usersByAddress: {},
    },
    ...extra,
  };
}

const evaluate = (rows: PolicyRoundRows) => evaluatePolicy(buildPolicyInput(rows), snapshotOf([]));

describe('buildPolicyInput: field mapping', () => {
  it('maps every row field (clean inbound round)', () => {
    const i = buildPolicyInput(policyRows());
    expect(policyInputSchema.parse(i)).toEqual(i);
    expect(i).toMatchObject({
      version: 'policy-input/1',
      trigger: 'scanned',
      evaluationTime: '2026-11-10T10:00:00.000Z',
      direction: 'inbound',
      round: { lifecycleRound: 0, scanId: '4242', scanKind: 'initial' },
      message: { sizeBytes: 12345, recipientCount: 2, attachmentCount: 1 },
      sender: {
        envelope: {
          address: 'alice@partner.example',
          domain: 'partner.example',
          localPart: 'alice',
        },
        headerFrom: {
          address: 'alice@partner.example',
          domain: 'partner.example',
          localPart: 'alice',
        },
        authenticated: {
          address: 'alice@partner.example',
          domain: 'partner.example',
          localPart: 'alice',
        },
        trusted: false,
        departments: [],
        users: [],
      },
      recipients: [
        {
          rcptSeq: 0,
          address: 'carol@corp.example',
          domain: 'corp.example',
          localPart: 'carol',
          departments: [],
          users: [],
        },
        {
          rcptSeq: 1,
          address: 'bob@corp.example',
          domain: 'corp.example',
          localPart: 'bob',
          departments: [DEPT.finance, DEPT.sales],
          users: [],
        },
      ],
      recipientsTruncated: false,
      client: { ip: '198.51.100.7', hostname: 'mx1.partner.example' },
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'pass', dmarcPolicy: 'reject', arc: 'none' },
      attachments: {
        count: 1,
        totalBytes: 2048,
        truncated: false,
        items: [
          {
            partIndex: 2,
            extension: 'zip',
            filename: 'Report.ZIP',
            declaredType: 'application/zip',
            detectedType: 'zip',
            typeFamily: 'archive',
            sizeBytes: 2048,
            sha256: 'a'.repeat(64),
            verdict: 'suspicious',
            reasonCodes: ['archive.depth', 'archive.encrypted'],
            isArchive: true,
            encrypted: true,
            typeMismatch: false,
          },
        ],
      },
      urls: {
        count: 1,
        truncated: false,
        rewriteStatus: 'rewritten',
        rewriteSkipReason: null,
        items: [
          {
            urlSeq: 0,
            host: 'login.example.com',
            domain: 'example.com',
            scheme: 'https',
            hostKind: 'domain',
            verdict: 'clean',
            reasonCodes: [],
          },
        ],
      },
      scan: {
        outcome: 'scanned',
        verdict: 'clean',
        reasonCodes: [],
        engines: [
          { engine: 'attachment', required: true, outcome: 'clean' },
          { engine: 'bec', required: true, outcome: 'clean' },
          { engine: 'dlp', required: true, outcome: 'clean' },
          { engine: 'rspamd', required: true, outcome: 'clean' },
          { engine: 'url', required: true, outcome: 'clean' },
        ],
      },
      dlp: {
        action: 'allow',
        verdict: 'clean',
        coverage: 'complete',
        categories: [],
        maxSeverity: null,
        detectorCodes: ['dlp.no_findings'],
      },
      dlpFinal: 'definite',
      bec: {
        deterministicVerdict: 'clean',
        verdict: 'clean',
        aiRaised: false,
        ruleCodes: [],
        trustedCode: 'none',
      },
      becFinal: 'definite',
    });
    expect(i.risk.rev0).toMatchObject({
      status: 'scored',
      levelOnly: true,
      aiRaiseOnly: false,
      failureStatuses: [],
      sandboxOutcome: null,
    });
    expect(i.risk.rev1).toBeNull();
  });
  it('authenticated sender and trust (inbound)', () => {
    const failing = policyRows(
      withFinal(cleanRound(), final('rspamd', 'clean', ['auth.spf_fail'])),
    );
    expect(buildPolicyInput(failing).sender.authenticated).toBeNull();
    const noDmarc = policyRows({
      ...cleanRound(),
      auth: { spf: 'pass', dkim: 'pass', dmarc: 'fail', dmarcPolicy: 'none', arc: 'none' },
    });
    expect(buildPolicyInput(noDmarc).sender.authenticated).toBeNull();
    const noAuth = policyRows({ ...cleanRound(), auth: null });
    expect(buildPolicyInput(noAuth).sender).toMatchObject({ authenticated: null, trusted: null });
    const trusted = policyRows(
      withFinal(cleanRound(), final('bec', 'clean', ['bec.trusted_sender'])),
    );
    expect(buildPolicyInput(trusted).sender.trusted).toBe(true);
    const trustedFailing = policyRows(
      withFinal(
        withFinal(cleanRound(), final('bec', 'clean', ['bec.trusted_sender'])),
        final('rspamd', 'clean', ['auth.dmarc_quarantine']),
      ),
    );
    expect(buildPolicyInput(trustedFailing).sender.trusted).toBe(false);
    expect(buildPolicyInput(policyRows({ ...cleanRound(), bec: null })).sender.trusted).toBeNull();
  });
  it('outbound: the organization-authenticated envelope sender and its directory', () => {
    const round = {
      ...cleanRound(),
      message: { ...cleanRound().message, direction: 'outbound' as const },
    };
    const rows = policyRows(round, {
      directory: {
        departmentsByAddress: { 'alice@partner.example': [DEPT.legal] },
        usersByAddress: { 'alice@partner.example': ['01930000-0000-7000-8000-0000000000e1'] },
      },
    });
    const i = buildPolicyInput(rows);
    expect(i.sender.authenticated?.address).toBe('alice@partner.example');
    expect(i.sender.trusted).toBe(false);
    expect(i.sender.departments).toEqual([DEPT.legal]);
    expect(i.sender.users).toEqual(['01930000-0000-7000-8000-0000000000e1']);
  });
  it('normalizes addresses; invalid senders become null', () => {
    const base = policyRows();
    const i = buildPolicyInput({
      ...base,
      message: {
        ...base.message,
        envelopeFrom: 'Foo@Bücher.Example',
        headerFrom: 'not an address',
        clientName: 'unknown',
        clientIp: null,
      },
    });
    expect(i.sender.envelope).toEqual({
      address: 'foo@xn--bcher-kva.example',
      domain: 'xn--bcher-kva.example',
      localPart: 'foo',
    });
    expect(i.sender.headerFrom).toBeNull();
    expect(i.sender.authenticated).toBeNull();
    expect(i.client).toEqual({ ip: null, hostname: null });
    expect(
      buildPolicyInput({ ...base, message: { ...base.message, envelopeFrom: '' } }).sender.envelope,
    ).toBeNull();
  });
  it('results missing for an attachment or URL are unknown, not clean', () => {
    const i = buildPolicyInput(
      policyRows(undefined, { attachmentResults: [], urlResults: [], urlRewrite: null }),
    );
    expect(i.attachments.items[0]).toMatchObject({
      verdict: null,
      reasonCodes: null,
      typeFamily: null,
      detectedType: null,
      typeMismatch: null,
      encrypted: true,
    });
    expect(i.urls.items[0]).toMatchObject({ verdict: null, reasonCodes: null });
    expect(i.urls.rewriteStatus).toBe('none');
  });
  it('parse failures: no scan, evaluation time from the parse row', () => {
    const base = policyRows();
    const i = buildPolicyInput({
      ...base,
      trigger: 'parse_failed',
      scan: null,
      parseFailedAt: new Date('2026-11-10T09:00:00.000Z'),
      finals: [],
      risk: [],
      auth: null,
      bec: null,
      dlp: null,
      attachments: [],
      attachmentResults: [],
      urls: [],
      urlResults: [],
      urlRewrite: null,
    });
    expect(i).toMatchObject({
      trigger: 'parse_failed',
      evaluationTime: '2026-11-10T09:00:00.000Z',
      round: { scanId: null, scanKind: null },
      scan: { outcome: 'not_scanned', engines: [] },
    });
    expect(evaluatePolicy(i, snapshotOf([])).disposition).toBe('quarantine');
  });
});

describe('buildPolicyInput: levelOnly / aiRaiseOnly from real 5.1 rows', () => {
  const cases: Array<{
    name: string;
    round: RoundRows;
    rows?: (r: PolicyRoundRows) => PolicyRoundRows;
    levelOnly: boolean;
    aiRaiseOnly?: boolean;
    disposition: string;
    failures?: string[];
  }> = [
    { name: 'clean', round: cleanRound(), levelOnly: true, disposition: 'allow' },
    {
      name: 'tag level (spam score)',
      round: withFinal(cleanRound(), final('rspamd', 'spam', ['spam.score'])),
      levelOnly: true,
      disposition: 'allow',
    },
    {
      name: 'quarantine level (GTUBE)',
      round: withFinal(cleanRound(), final('rspamd', 'spam', ['spam.gtube'])),
      levelOnly: true,
      disposition: 'quarantine',
    },
    {
      name: 'hard block (malware attachment)',
      round: withFinal(cleanRound(), final('attachment', 'malicious', ['malware.clamav'])),
      levelOnly: false,
      disposition: 'reject',
    },
    {
      name: 'engine failure',
      round: {
        ...withFinal(cleanRound(), final('url', 'timeout', ['engine.timeout'])),
        scan: { ...cleanRound().scan, status: 'failed' },
      },
      levelOnly: false,
      disposition: 'quarantine',
      failures: ['timeout'],
    },
    {
      name: 'unknown engine',
      round: withFinal(cleanRound(), final('url', 'unknown', ['url.unknown'])),
      levelOnly: false,
      disposition: 'allow',
      failures: ['unknown'],
    },
    {
      name: 'missing child row',
      round: { ...cleanRound(), dlp: null },
      levelOnly: false,
      disposition: 'quarantine',
      failures: ['row_missing'],
    },
    {
      name: 'AI-only raise',
      round: {
        ...withFinal(cleanRound(), final('bec', 'suspicious', ['bec.ai.flagged'])),
        bec: { deterministicVerdict: 'clean', verdict: 'suspicious', rules: [] },
      },
      levelOnly: true,
      aiRaiseOnly: true,
      disposition: 'allow',
    },
    {
      name: 'scoring error row',
      round: cleanRound(),
      rows: (r) => ({ ...r, risk: [riskRow(cleanRound(), 0, true)] }),
      levelOnly: false,
      disposition: 'quarantine',
    },
  ];
  for (const c of cases) {
    it(c.name, () => {
      let rows = policyRows(c.round);
      if (c.rows) rows = c.rows(rows);
      const i = buildPolicyInput(rows);
      expect(i.risk.rev0!.levelOnly).toBe(c.levelOnly);
      expect(i.risk.rev0!.aiRaiseOnly).toBe(c.aiRaiseOnly ?? false);
      if (c.failures) expect(i.risk.rev0!.failureStatuses).toEqual(c.failures);
      const r = evaluatePolicy(i, snapshotOf([]));
      expect(r.disposition).toBe(c.disposition);
      if (c.name === 'unknown engine') expect(r.floor.tag).toBe(true);
      if (c.name === 'AI-only raise')
        expect(r.actions.some((a) => a.type === 'TAG' && a.origin === 'platform_default')).toBe(
          true,
        );
    });
  }
  it('revision 1 carries the sandbox outcome and can only raise', () => {
    const round = withFinal(
      cleanRound(),
      final('sandbox', 'malicious', ['sandbox.process_injection']),
    );
    const rows = policyRows(round, { risk: [riskRow(round, 0), riskRow(round, 1)] });
    const i = buildPolicyInput(rows);
    expect(i.risk.rev1).toMatchObject({ sandboxOutcome: 'malicious', levelOnly: false });
    expect(i.scan.engines.map((e) => e.engine)).not.toContain('sandbox');
    expect(evaluate(rows).disposition).toBe('quarantine');
  });
});

describe('buildPolicyInput: caps, truncation and permutation invariance', () => {
  it('caps recipients, attachments and URLs, lowest sequence first', () => {
    const base = policyRows(undefined, { attachmentResults: [], urlResults: [] });
    const recipients = Array.from({ length: POLICY_LIMITS.recipients + 1 }, (_, k) => ({
      rcptSeq: 5000 - k,
      address: `r${k}@corp.example`,
    }));
    const attachments = Array.from({ length: POLICY_LIMITS.attachments + 1 }, (_, k) => ({
      ...base.attachments[0]!,
      partIndex: 300 - k,
    }));
    const urls = Array.from({ length: POLICY_LIMITS.urls + 1 }, (_, k) => ({
      ...base.urls[0]!,
      urlSeq: 600 - k,
    }));
    const i = buildPolicyInput({ ...base, recipients, attachments, urls });
    expect(i.recipients).toHaveLength(POLICY_LIMITS.recipients);
    expect(i.recipients[0]!.rcptSeq).toBe(5000 - POLICY_LIMITS.recipients);
    expect(i.recipientsTruncated).toBe(true);
    expect(i.attachments).toMatchObject({ count: 201, truncated: true, totalBytes: 201 * 2048 });
    expect(i.attachments.items).toHaveLength(200);
    expect(i.attachments.items[0]!.partIndex).toBe(100);
    expect(i.urls).toMatchObject({ count: 501, truncated: true });
    expect(i.urls.items).toHaveLength(500);
  });
  it('permutations of raw rows and codes give the same input and hash', () => {
    const a = policyRows();
    const reversed: PolicyRoundRows = {
      ...a,
      recipients: [...a.recipients].reverse(),
      finals: [...a.finals]
        .reverse()
        .map((f) => ({ ...f, reasonCodes: [...(f.reasonCodes as string[])].reverse() })),
      attachmentResults: a.attachmentResults.map((r) => ({
        ...r,
        reasonCodes: [...(r.reasonCodes as string[])].reverse(),
      })),
      risk: a.risk.map((r) => ({ ...r, reasonCodes: [...(r.reasonCodes as string[])].reverse() })),
      directory: {
        departmentsByAddress: { 'bob@corp.example': [DEPT.finance, DEPT.sales] },
        usersByAddress: {},
      },
    };
    expect(canonicalJson(buildPolicyInput(reversed))).toBe(canonicalJson(buildPolicyInput(a)));
    expect(evaluate(reversed).inputSha256).toBe(evaluate(a).inputSha256);
  });
});

describe('buildPolicyInput: malformed rows throw PolicyInputError', () => {
  const base = policyRows();
  const bad: Array<[string, PolicyRoundRows]> = [
    [
      'unknown engine',
      { ...base, finals: [...base.finals, { engine: 'clamd', outcome: 'clean', reasonCodes: [] }] },
    ],
    ['duplicate final', { ...base, finals: [...base.finals, base.finals[0]!] }],
    ['malformed codes', { ...base, finals: [{ ...base.finals[0]!, reasonCodes: 'spam' }] }],
    ['unknown outcome', { ...base, finals: [{ ...base.finals[0]!, outcome: 'great' }] }],
    ['trigger mismatch', { ...base, trigger: 'scan_failed' }],
    ['scan missing', { ...base, scan: null }],
    ['parse failure with a scan', { ...base, trigger: 'parse_failed', parseFailedAt: COMPLETED }],
    ['invalid completedAt', { ...base, scan: { ...base.scan!, completedAt: new Date('x') } }],
    ['scanId not decimal', { ...base, scan: { ...base.scan!, scanId: 'abc' } }],
    ['risk revision 2', { ...base, risk: [{ ...base.risk[0]!, revision: 2 }] }],
    ['two revision-0 rows', { ...base, risk: [base.risk[0]!, base.risk[0]!] }],
    ['risk level unknown', { ...base, risk: [{ ...base.risk[0]!, level: 'extreme' }] }],
    ['risk evidence malformed', { ...base, risk: [{ ...base.risk[0]!, evidence: {} }] }],
    ['dlp action unknown', { ...base, dlp: { ...base.dlp!, action: 'shred' } }],
    ['bec rules malformed', { ...base, bec: { ...base.bec!, rules: [{ code: 'X' }] } }],
    ['auth outcome unknown', { ...base, auth: { ...base.auth!, spf: 'maybe' } }],
    [
      'directory id malformed',
      {
        ...base,
        directory: { departmentsByAddress: { 'a@b.example': ['finance'] }, usersByAddress: {} },
      },
    ],
    ['duplicate rcptSeq', { ...base, recipients: [...base.recipients, base.recipients[0]!] }],
    [
      'attachment result without attachment',
      { ...base, attachmentResults: [{ ...base.attachmentResults[0]!, partIndex: 9 }] },
    ],
    ['malformed sha256', { ...base, attachments: [{ ...base.attachments[0]!, sha256: 'xyz' }] }],
    ['malformed url host', { ...base, urls: [{ ...base.urls[0]!, host: 'bad host' }] }],
    ['url result without url', { ...base, urlResults: [{ ...base.urlResults[0]!, urlSeq: 9 }] }],
    ['rewrite status unknown', { ...base, urlRewrite: { status: 'partial', skipReason: null } }],
    ['negative size', { ...base, message: { ...base.message, sizeBytes: -1 } }],
  ];
  for (const [name, rows] of bad) {
    it(name, () => {
      expect(() => buildPolicyInput(rows)).toThrow(PolicyInputError);
    });
  }
});
