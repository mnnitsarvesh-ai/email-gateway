import { describe, expect, it } from 'vitest';
import {
  levelForScore,
  platformProfile,
  resolveProfile,
  type ResolvedProfile,
  type RiskResult,
  riskResultSchema,
  scoreRisk,
  scoringErrorResult,
  sha256Hex,
  canonicalJson,
  RISK_ACTIONS,
} from './index';
import type { RoundRows } from './input';
import {
  build,
  cleanRows,
  final,
  removeFinal,
  setFinal,
  withBec,
  withCodes,
} from './rows.test-support';

const PLATFORM = platformProfile('rsk-default/1');
const PUBLIC_ID = '0190a6f2-7b3c-7def-8abc-0123456789ab';
const tenant = (overrides: unknown, versionNo = 3): ResolvedProfile => {
  const r = resolveProfile('rsk-default/1', {
    publicId: PUBLIC_ID,
    versionNo,
    baseProfile: 'rsk-default/1',
    overrides,
  });
  expect(r.violations).toEqual([]);
  return r;
};

function score(
  rows: RoundRows,
  profile: ResolvedProfile = PLATFORM,
  revision: 0 | 1 = 0,
): RiskResult {
  const result = scoreRisk(build(rows, revision), profile);
  riskResultSchema.parse(result);
  return result;
}
const group = (r: RiskResult, g: string) => r.groups.find((x) => x.group === g);
const contribution = (r: RiskResult, s: string) => r.contributions.find((x) => x.signal === s);
const inbound = (rows: RoundRows, direction: RoundRows['message']['direction'] = 'inbound') => ({
  ...rows,
  message: { ...rows.message, direction },
});

describe('clean round', () => {
  it('scores 0, none, clean, deliver', () => {
    const r = score(cleanRows());
    expect(r).toMatchObject({ status: 'scored', score: 0, level: 'none', verdict: 'clean' });
    expect(r.recommendedAction).toBe('deliver');
    expect(r.reasonCodes).toEqual(['risk.level.none', 'risk.profile.platform']);
    expect(r.versions).toEqual({
      scorer: 'risk-score/1',
      signalMap: 'risk-signals/1',
      input: 'risk-input/1',
      profile: {
        source: 'platform',
        id: 'rsk-default/1',
        versionNo: null,
        sha256: PLATFORM.sha256,
      },
    });
    expect(r.inputSha256).toBe(sha256Hex(canonicalJson(build(cleanRows()))));
  });

  it('weak hygiene signals alone stay below low and keep clean', () => {
    const r = score(
      withCodes(cleanRows(), 'rspamd', 'clean', ['auth.spf_fail', 'clean.below_threshold']),
    );
    expect(r.score).toBe(60);
    expect(r.level).toBe('none');
    expect(r.verdict).toBe('clean');
  });

  it('skipped engines contribute nothing and do not prevent clean', () => {
    let rows = withCodes(cleanRows(), 'attachment', 'skipped', ['attachment.none']);
    rows = { ...rows, dlp: null };
    rows = withCodes(rows, 'dlp', 'skipped', ['dlp.not_inbound']);
    const r = score(rows);
    expect(r).toMatchObject({
      score: 0,
      level: 'none',
      verdict: 'clean',
      recommendedAction: 'deliver',
    });
  });
});

describe('groups (R3)', () => {
  it('auth_dmarc max: DMARC reject + BEC tenant-domain spoof = 400, not 700', () => {
    let rows = withCodes(cleanRows(), 'rspamd', 'suspicious', ['auth.dmarc_reject']);
    rows = withBec(rows, 'suspicious', ['bec.auth.tenant_domain_spoof']);
    rows = {
      ...rows,
      auth: { spf: 'fail', dkim: 'fail', dmarc: 'fail', dmarcPolicy: 'reject', arc: 'none' },
    };
    const r = score(rows);
    expect(group(r, 'auth_dmarc')).toMatchObject({ rule: 'max', raw: 400, total: 400 });
  });

  it('lookalike max: URL lookalike + BEC link lookalike = 300', () => {
    let rows = withCodes(cleanRows(), 'url', 'suspicious', ['url.lookalike_homoglyph']);
    rows = withBec(rows, 'suspicious', ['bec.link.lookalike']);
    const r = score(rows);
    expect(group(r, 'lookalike')?.total).toBe(300);
    expect(contribution(r, 'lookalike_url')?.codes).toEqual([
      'bec:bec.link.lookalike',
      'url:url.lookalike_homoglyph',
    ]);
  });

  it('attachment_malware: ClamAV + YARA + known hash = 1000 once', () => {
    const r = score(
      withCodes(cleanRows(), 'attachment', 'malicious', [
        'malware.clamav',
        'malware.known_hash',
        'yara.high',
      ]),
    );
    expect(group(r, 'attachment_malware')?.total).toBe(1000);
    expect(r.contributions.filter((c) => c.group === 'attachment_malware')).toHaveLength(1);
    expect(r.score).toBe(1000);
  });

  it('same fact from two engines counts once (auth.spf_fail from rspamd and bec)', () => {
    let rows = withCodes(cleanRows(), 'rspamd', 'clean', [
      'auth.spf_fail',
      'clean.below_threshold',
    ]);
    rows = withBec(rows, 'clean', ['bec.auth.spf_fail']);
    const r = score(rows);
    expect(contribution(r, 'auth_spf_fail')).toMatchObject({
      applied: 60,
      codes: ['bec:bec.auth.spf_fail', 'rspamd:auth.spf_fail'],
    });
    expect(group(r, 'auth_other')?.total).toBe(60);
  });

  it('capped_sum adds within the group and caps', () => {
    const r = score(
      withBec(cleanRows(), 'suspicious', [
        'bec.vendor.payment_change',
        'bec.content.gift_card',
        'bec.content.urgency',
      ]),
    );
    expect(group(r, 'bec_intent')).toMatchObject({
      rule: 'capped_sum',
      raw: 510,
      cap: 350,
      total: 350,
    });
  });

  it('max takes the strongest signal only', () => {
    const r = score(
      withCodes(cleanRows(), 'rspamd', 'spam', [
        'spam.score',
        'bayes.spam',
        'spam.suspicious_score',
      ]),
    );
    expect(group(r, 'spam')).toMatchObject({ raw: 450, total: 450 });
    expect(r.score).toBe(450);
    expect(r.level).toBe('medium');
    expect(r.verdict).toBe('spam');
    expect(r.recommendedAction).toBe('tag');
  });

  it('multipliers apply with an integer floor', () => {
    const r = score(
      withBec(cleanRows(), 'clean', ['bec.auth.dmarc_fail']),
      tenant({ groupMultipliersPermille: { auth_dmarc: 1333 } }),
    );
    // 120 × 1333 / 1000 = 159.96 → 159
    expect(group(r, 'auth_dmarc')).toMatchObject({
      raw: 120,
      multiplierPermille: 1333,
      total: 159,
    });
    const spam = score(
      withCodes(cleanRows(), 'rspamd', 'spam', ['spam.score']),
      tenant({ groupMultipliersPermille: { spam: 1500 } }),
    );
    expect(group(spam, 'spam')?.total).toBe(675);
    expect(spam.score).toBe(675);
  });

  it('the score is capped at 1000', () => {
    let rows = withCodes(cleanRows(), 'rspamd', 'spam', ['spam.gtube', 'reputation.ip_listed']);
    rows = withCodes(rows, 'url', 'malicious', ['url.feed_malicious', 'url.lookalike_homoglyph']);
    const r = score(rows);
    expect(r.score).toBe(1000);
  });
});

describe('failures (R6)', () => {
  for (const engine of ['rspamd', 'attachment', 'url', 'bec', 'dlp']) {
    for (const outcome of ['timeout', 'error'] as const) {
      it(`${engine} ${outcome} → failure weight, medium floor, quarantine`, () => {
        let rows = setFinal(cleanRows(), final(engine, outcome, []));
        rows = { ...rows, scan: { ...rows.scan, status: 'failed' } };
        if (engine === 'bec') rows = { ...rows, bec: null };
        if (engine === 'dlp') rows = { ...rows, dlp: null };
        if (engine === 'rspamd') rows = { ...rows, auth: null };
        const r = score(rows);
        expect(r.reasonCodes).toContain(`risk.engine.${engine}.${outcome}`);
        expect(r.failures).toEqual([{ engine, status: outcome, weight: 300 }]);
        expect(group(r, 'engine_failure')?.total).toBe(300);
        expect(r.level).toBe('medium');
        expect(r.score).toBe(300);
        expect(r.recommendedAction).toBe('quarantine');
        expect(r.verdict).toBe('unknown');
        expect(r.floors).toContainEqual({ source: 'engine_failure', level: 'medium' });
      });
    }
    it(`${engine} missing final → failure`, () => {
      let rows = removeFinal(cleanRows(), engine);
      rows = { ...rows, scan: { ...rows.scan, status: 'timed_out' } };
      const r = score(rows);
      expect(r.reasonCodes).toContain(`risk.engine.${engine}.missing`);
      expect(r.engines.find((e) => e.engine === engine)?.status).toBe('missing');
      expect(r.recommendedAction).toBe('quarantine');
      expect(r.verdict).toBe('unknown');
    });
    it(`${engine} unknown → unknown weight, low floor, tag action floor, never clean`, () => {
      const r = score(withCodes(cleanRows(), engine, 'unknown', []));
      expect(r.reasonCodes).toContain(`risk.engine.${engine}.unknown`);
      expect(group(r, 'engine_unknown')?.total).toBe(60);
      expect(r.level).toBe('low');
      expect(r.score).toBe(100);
      expect(r.verdict).toBe('unknown');
      // Level low maps to deliver; the unknown action floor (failures.unknownAction) raises it.
      expect(r.recommendedAction).toBe('tag');
      expect(r.floors).toContainEqual({ source: 'engine_unknown', level: 'low' });
    });
    it(`${engine} unknown → a tenant failures.unknownAction is applied`, () => {
      const r = score(
        withCodes(cleanRows(), engine, 'unknown', []),
        tenant({ failures: { unknownAction: 'require_approval' } }),
      );
      expect(r.level).toBe('low');
      expect(r.recommendedAction).toBe('require_approval');
    });
  }

  it('two failures add up, three are capped by failures.groupCap', () => {
    let rows: RoundRows = { ...cleanRows(), scan: { ...cleanRows().scan, status: 'failed' } };
    rows = setFinal(rows, final('url', 'timeout', []));
    rows = setFinal(rows, final('attachment', 'error', []));
    expect(group(score(rows), 'engine_failure')?.total).toBe(600);
    expect(score(rows).level).toBe('high');
    rows = setFinal(rows, final('rspamd', 'error', []));
    rows = { ...rows, auth: null };
    expect(group(score(rows), 'engine_failure')).toMatchObject({ raw: 900, cap: 600, total: 600 });
  });

  it('scan_failed never recommends deliver or tag, even with permissive level actions', () => {
    let rows: RoundRows = { ...cleanRows(), scan: { ...cleanRows().scan, status: 'failed' } };
    rows = setFinal(rows, final('url', 'timeout', []));
    const r = score(
      rows,
      tenant({
        thresholds: { low: 250, medium: 450, high: 700, critical: 950 },
        actions: { medium: 'tag', high: 'require_approval' },
      }),
    );
    expect(['require_approval', 'quarantine', 'block']).toContain(r.recommendedAction);
    expect(r.recommendedAction).toBe('quarantine');
    expect(r.level).toBe('medium');
    expect(r.score).toBe(450);
  });

  it('an unknown action floor never weakens a stricter level action', () => {
    const r = score(
      withCodes(cleanRows(), 'url', 'unknown', []),
      tenant({ failures: { unknownMinLevel: 'high' } }),
    );
    expect(r.level).toBe('high');
    expect(r.recommendedAction).toBe('quarantine');
  });

  it('a clean round without unknown results keeps deliver', () => {
    const r = score(cleanRows());
    expect(r.verdict).toBe('clean');
    expect(r.recommendedAction).toBe('deliver');
  });

  it('missing child rows: bec, dlp and auth (email_auth_results) are failures', () => {
    const bec = score({
      ...withBec(cleanRows(), 'suspicious', ['bec.content.urgency']),
      bec: null,
    });
    expect(bec.reasonCodes).toContain('risk.input.bec_row_missing');
    expect(bec.failures).toContainEqual({ engine: 'bec', status: 'row_missing', weight: 300 });
    expect(bec.level).toBe('medium');
    expect(bec.recommendedAction).toBe('quarantine');

    const dlp = score({ ...cleanRows(), dlp: null });
    expect(dlp.reasonCodes).toContain('risk.input.dlp_row_missing');
    expect(dlp.recommendedAction).toBe('quarantine');

    const auth = score({ ...cleanRows(), auth: null });
    expect(auth.reasonCodes).toContain('risk.input.auth_row_missing');
    expect(auth.failures).toContainEqual({ engine: 'rspamd', status: 'row_missing', weight: 300 });
    expect(contribution(auth, 'engine_failed_rspamd')?.codes).toEqual([
      'rspamd:risk.input.auth_row_missing',
    ]);
    expect(contribution(auth, 'coverage_input_missing')).toBeUndefined();
    expect(auth.level).toBe('medium');
    expect(auth.floors).toContainEqual({ source: 'engine_failure', level: 'medium' });
    expect(auth.verdict).toBe('unknown');
    expect(auth.recommendedAction).toBe('quarantine');
    expect(auth.explanation.text).toContain(
      'Expected authentication result row is missing; treated as an engine failure.',
    );
    expect(
      auth.explanation.lines.filter(
        (l) => l.code === 'input_missing' && l.params['input'] === 'authentication',
      ),
    ).toHaveLength(1);
  });

  it('sandbox failures are informational in revision 1 (no failure weight, never clean)', () => {
    for (const outcome of ['timeout', 'error'] as const) {
      const rows = setFinal(cleanRows(), final('sandbox', outcome, ['sandbox.error']));
      const r = score(rows, PLATFORM, 1);
      expect(r.failures).toEqual([]);
      expect(r.score).toBe(0);
      expect(r.reasonCodes).toContain(`risk.engine.sandbox.${outcome}`);
      expect(r.reasonCodes).toContain('risk.sandbox.included');
      expect(r.verdict).toBe('unknown');
      expect(r.recommendedAction).toBe('deliver');
    }
  });

  it('revision 0 ignores a sandbox final; revision 1 includes it', () => {
    const rows = setFinal(
      cleanRows(),
      final('sandbox', 'suspicious', ['sandbox.static.office_macro']),
    );
    expect(score(rows, PLATFORM, 0).score).toBe(0);
    const r1 = score(rows, PLATFORM, 1);
    expect(r1.score).toBe(400);
    expect(r1.verdict).toBe('suspicious');
    expect(r1.evidence.sandbox).toEqual({ outcome: 'suspicious' });
  });
});

describe('engine-verdict floors (R8)', () => {
  it('a malicious final of rspamd, attachment or url → at least high', () => {
    const r = score(withCodes(cleanRows(), 'rspamd', 'malicious', ['phishing.link_mismatch']));
    expect(r.score).toBe(550);
    expect(r.level).toBe('high');
    expect(r.floors).toContainEqual({ source: 'engine_malicious', level: 'high' });
    expect(r.reasonCodes).toContain('risk.floor.engine_malicious');
    expect(r.verdict).toBe('phishing');
    expect(r.recommendedAction).toBe('quarantine');
  });

  it('bec suspicious → at least low; raised floors from the profile', () => {
    const r = score(withBec(cleanRows(), 'suspicious', ['bec.content.urgency']));
    expect(r.level).toBe('low');
    expect(r.score).toBe(100);
    expect(r.verdict).toBe('bec');
    const raised = score(
      withBec(cleanRows(), 'suspicious', ['bec.content.urgency']),
      tenant({ floors: { becSuspicious: 'medium' } }),
    );
    expect(raised.level).toBe('medium');
    expect(raised.score).toBe(300);
  });

  it('bec malicious with hb.bec_malicious disabled → engineMalicious floor', () => {
    const r = score(
      withBec(cleanRows(), 'malicious', ['bec.impersonation.executive_name']),
      tenant({ hardBlocks: { 'hb.bec_malicious': { enabled: false } } }),
    );
    expect(r.hardBlocks).toEqual([]);
    expect(r.level).toBe('high');
    expect(r.floors).toContainEqual({ source: 'engine_malicious', level: 'high' });
  });
});

describe('hard blocks (R5)', () => {
  const cases: [string, RoundRows, string, string, 0 | 1][] = [
    [
      'hb.malware_attachment',
      withCodes(cleanRows(), 'attachment', 'malicious', ['malware.clamav']),
      'malware',
      'block',
      0,
    ],
    [
      'hb.malware_url',
      withCodes(cleanRows(), 'url', 'malicious', ['url.dnsbl_malware']),
      'malware',
      'block',
      0,
    ],
    [
      'hb.malware_sandbox',
      setFinal(cleanRows(), final('sandbox', 'malicious', ['sandbox.static.eicar_test'])),
      'malware',
      'quarantine',
      1,
    ],
    [
      'hb.dlp_block',
      {
        ...cleanRows(),
        dlp: {
          action: 'block',
          verdict: 'suspicious',
          coverage: 'complete',
          categories: [
            { category: 'payment_card', count: 1, maxSeverity: 'high', maxConfidence: 'high' },
          ],
        },
      },
      'dlp_violation',
      'block',
      0,
    ],
    [
      'hb.known_phishing',
      withCodes(cleanRows(), 'url', 'malicious', ['url.feed_malicious']),
      'phishing',
      'quarantine',
      0,
    ],
    [
      'hb.tenant_domain_spoof',
      withBec(withCodes(cleanRows(), 'rspamd', 'suspicious', ['auth.dmarc_reject']), 'suspicious', [
        'bec.auth.tenant_domain_spoof',
      ]),
      'phishing',
      'quarantine',
      0,
    ],
    [
      'hb.url_tenant_blocked',
      withCodes(cleanRows(), 'url', 'malicious', ['url.tenant_blocked']),
      'phishing',
      'quarantine',
      0,
    ],
    [
      'hb.bec_malicious',
      withBec(cleanRows(), 'malicious', ['bec.impersonation.executive_freemail']),
      'bec',
      'quarantine',
      0,
    ],
  ];
  it.each(cases)(
    '%s fires: critical, its verdict and action',
    (id, rows, verdict, action, revision) => {
      const r = score(rows, PLATFORM, revision);
      expect(r.hardBlocks).toContainEqual({ id, verdict, action });
      expect(r.level).toBe('critical');
      expect(r.score).toBeGreaterThanOrEqual(800);
      expect(r.verdict).toBe(verdict);
      expect(r.recommendedAction).toBe(action);
      expect(r.reasonCodes[0]).toBe(`risk.hard_block.${id.slice(3)}`);
    },
  );

  it.each(cases)(
    '%s survives trust and a permissive profile',
    (id, rows, _verdict, _action, revision) => {
      const permissive = tenant({
        thresholds: { low: 250, medium: 450, high: 700, critical: 950 },
        groupMultipliersPermille: Object.fromEntries(
          ['auth_dmarc', 'url_threat', 'bec_impersonation', 'dlp', 'spam', 'lookalike'].map((g) => [
            g,
            500,
          ]),
        ),
        trust: { contentFactorPermille: 250 },
      });
      let trusted: RoundRows = { ...rows };
      if (trusted.bec) {
        trusted = {
          ...trusted,
          finals: trusted.finals.map((f) =>
            f.engine === 'bec'
              ? { ...f, reasonCodes: [...(f.reasonCodes as string[]), 'bec.trusted_sender'] }
              : f,
          ),
        };
      }
      const r = score(trusted, permissive, revision);
      expect(r.hardBlocks.map((h) => h.id)).toContain(id);
      expect(r.level).toBe('critical');
      expect(r.score).toBeGreaterThanOrEqual(950);
      expect(['quarantine', 'block']).toContain(r.recommendedAction);
    },
  );

  it('a may-disable indicator can be switched off; its action can be block', () => {
    const rows = withCodes(cleanRows(), 'url', 'malicious', ['url.feed_malicious']);
    const off = score(rows, tenant({ hardBlocks: { 'hb.known_phishing': { enabled: false } } }));
    expect(off.hardBlocks).toEqual([]);
    expect(off.level).toBe('critical'); // 800 points of url_known_phishing alone
    const block = score(rows, tenant({ hardBlocks: { 'hb.known_phishing': { action: 'block' } } }));
    expect(block.recommendedAction).toBe('block');
  });

  it('hb.dmarc_reject is off by default and can be enabled', () => {
    const rows = withCodes(cleanRows(), 'rspamd', 'suspicious', ['auth.dmarc_reject']);
    const off = score(rows);
    expect(off.hardBlocks).toEqual([]);
    expect(off.score).toBe(300);
    expect(off.level).toBe('medium');
    const on = score(rows, tenant({ hardBlocks: { 'hb.dmarc_reject': { enabled: true } } }));
    expect(on.hardBlocks).toEqual([
      { id: 'hb.dmarc_reject', verdict: 'phishing', action: 'quarantine' },
    ]);
    expect(on.level).toBe('critical');
    expect(on.score).toBe(800);
    // inbound only
    const internal = score(
      inbound(rows, 'internal'),
      tenant({ hardBlocks: { 'hb.dmarc_reject': { enabled: true } } }),
    );
    expect(internal.hardBlocks).toEqual([]);
  });

  it('verdict priority: malware > phishing > bec > dlp_violation', () => {
    let rows = withCodes(cleanRows(), 'url', 'malicious', ['url.feed_malicious']);
    rows = withBec(rows, 'malicious', ['bec.impersonation.executive_freemail']);
    expect(score(rows).verdict).toBe('phishing');
    rows = withCodes(rows, 'attachment', 'malicious', ['yara.high']);
    const r = score(rows);
    expect(r.verdict).toBe('malware');
    expect(r.recommendedAction).toBe('block');
    expect(r.hardBlocks.map((h) => h.id)).toEqual([
      'hb.malware_attachment',
      'hb.known_phishing',
      'hb.bec_malicious',
    ]);
  });
});

describe('trust (R7)', () => {
  const trustedRows = (codes: string[], rules: string[] = []): RoundRows => {
    let rows = withCodes(cleanRows(), 'rspamd', 'spam', codes);
    rows = withBec(rows, 'clean', [...rules, 'bec.trusted_sender']);
    return rows;
  };

  it('applies to trust-reducible signals only, recorded', () => {
    let rows = trustedRows(['spam.score']);
    rows = withCodes(rows, 'url', 'suspicious', ['url.lookalike_homoglyph', 'url.too_long']);
    const r = score(rows);
    expect(r.trust).toEqual({
      status: 'applied',
      factorPermille: 500,
      reducedGroups: ['spam', 'url_structure'],
      pointsRemoved: 245,
    });
    expect(group(r, 'spam')).toMatchObject({ raw: 225, total: 225, trustFactorPermille: 500 });
    expect(group(r, 'lookalike')).toMatchObject({ total: 300, trustFactorPermille: null });
    expect(group(r, 'url_structure')?.total).toBe(20);
    expect(r.reasonCodes).toContain('risk.trust.applied');
    expect(r.explanation.lines.some((l) => l.code === 'trust_applied')).toBe(true);
  });

  it('denied for an unauthenticated trusted sender (T2)', () => {
    let rows = withCodes(cleanRows(), 'rspamd', 'spam', ['spam.score']);
    rows = withBec(rows, 'clean', ['bec.trusted_sender_unauthenticated']);
    const r = score(rows);
    expect(r.trust.status).toBe('denied_unauthenticated');
    expect(group(r, 'spam')?.total).toBe(450);
    expect(r.reasonCodes).toContain('risk.trust.denied_unauthenticated');
  });

  it.each(['fail', 'none'] as const)('denied when DMARC is %s', (dmarc) => {
    const rows = {
      ...trustedRows(['spam.score']),
      auth: { spf: 'pass', dkim: 'pass', dmarc, dmarcPolicy: null, arc: null },
    } as RoundRows;
    const r = score(rows);
    expect(r.trust.status).toBe('denied_unauthenticated');
    expect(group(r, 'spam')?.total).toBe(450);
  });

  it('denied when any authentication-failure signal fired', () => {
    const r = score(trustedRows(['spam.score', 'auth.dkim_fail']));
    expect(r.trust.status).toBe('denied_auth_failure');
    expect(r.reasonCodes).toContain('risk.trust.denied_auth_failure');
    expect(group(r, 'spam')?.total).toBe(450);
  });

  it('not applied to non-inbound mail', () => {
    const r = score(inbound(trustedRows(['spam.score']), 'internal'));
    expect(r.trust.status).toBe('not_trusted');
    expect(group(r, 'spam')?.total).toBe(450);
  });

  it('mode off and a custom factor', () => {
    expect(
      score(trustedRows(['spam.score']), tenant({ trust: { mode: 'off' } })).trust.status,
    ).toBe('off');
    const r = score(trustedRows(['spam.score']), tenant({ trust: { contentFactorPermille: 250 } }));
    expect(group(r, 'spam')?.total).toBe(112);
  });

  it('never reduces locked groups, failures or hard blocks', () => {
    let rows = trustedRows(['spam.score']);
    rows = withCodes(rows, 'attachment', 'malicious', ['malware.clamav']);
    rows = { ...rows, scan: { ...rows.scan, status: 'failed' } };
    rows = setFinal(rows, final('url', 'timeout', []));
    const r = score(rows);
    expect(r.trust.status).toBe('applied');
    expect(group(r, 'attachment_malware')?.total).toBe(1000);
    expect(group(r, 'engine_failure')?.total).toBe(300);
    expect(r.hardBlocks.map((h) => h.id)).toEqual(['hb.malware_attachment']);
  });
});

describe('thresholds and actions (R4)', () => {
  const t = PLATFORM.profile.thresholds;
  it.each([
    [0, 'none'],
    [99, 'none'],
    [100, 'low'],
    [299, 'low'],
    [300, 'medium'],
    [549, 'medium'],
    [550, 'high'],
    [799, 'high'],
    [800, 'critical'],
    [1000, 'critical'],
  ] as const)('score %i → %s', (s, level) => {
    expect(levelForScore(s, t)).toBe(level);
  });

  it('custom thresholds', () => {
    const custom = { low: 50, medium: 200, high: 400, critical: 650 };
    expect(levelForScore(49, custom)).toBe('none');
    expect(levelForScore(50, custom)).toBe('low');
    expect(levelForScore(400, custom)).toBe('high');
    const r = score(
      withCodes(cleanRows(), 'rspamd', 'spam', ['spam.score']),
      tenant({ thresholds: custom }),
    );
    expect(r.level).toBe('high');
    expect(r.recommendedAction).toBe('quarantine');
  });

  it('end to end at a boundary: 100 points is low', () => {
    const r = score(
      withCodes(cleanRows(), 'rspamd', 'clean', ['bayes.spam', 'clean.below_threshold']),
    );
    expect(r.score).toBe(100);
    expect(r.level).toBe('low');
    expect(r.verdict).toBe('spam');
  });

  it('level actions are non-decreasing in the default profile', () => {
    const a = PLATFORM.profile.actions;
    const order = ['none', 'low', 'medium', 'high', 'critical'] as const;
    for (let i = 1; i < order.length; i += 1) {
      expect(RISK_ACTIONS.indexOf(a[order[i]!])).toBeGreaterThanOrEqual(
        RISK_ACTIONS.indexOf(a[order[i - 1]!]),
      );
    }
  });

  it.each([
    ['allow', 'deliver'],
    ['alert', 'tag'],
    ['require_approval', 'require_approval'],
    ['quarantine', 'quarantine'],
    ['block', 'block'],
  ] as const)('DLP binding: %s → at least %s', (action, expected) => {
    const rows: RoundRows = {
      ...inbound(cleanRows(), 'outbound'),
      finals: cleanRows().finals.map((f) =>
        f.engine === 'bec'
          ? final('bec', 'skipped', ['bec.not_inbound'])
          : f.engine === 'dlp'
            ? final('dlp', action === 'allow' ? 'clean' : 'suspicious', ['dlp.payment_card.number'])
            : f,
      ),
      bec: null,
      dlp: {
        action,
        verdict: action === 'allow' ? 'clean' : 'suspicious',
        coverage: 'complete',
        categories:
          action === 'allow'
            ? []
            : [
                {
                  category: 'payment_card',
                  count: 1,
                  maxSeverity: 'medium',
                  maxConfidence: 'high',
                },
              ],
      },
    };
    const r = score(rows);
    expect(r.recommendedAction).toBe(expected);
    if (action !== 'allow') expect(r.verdict).toBe('dlp_violation');
  });

  it('a stricter level action wins over a weaker binding', () => {
    const rows = withCodes(cleanRows(), 'rspamd', 'spam', ['spam.gtube']);
    expect(score(rows).recommendedAction).toBe('quarantine');
    expect(
      score(rows, tenant({ actions: { high: 'block', critical: 'block' } })).recommendedAction,
    ).toBe('block');
  });
});

describe('AI-only raise (R9)', () => {
  const aiRows = (det: string) =>
    withBec(cleanRows(), det, [], { verdict: 'suspicious', finalCodes: ['bec.ai.flagged'] });

  it('adds at most tag, never a hold', () => {
    const r = score(aiRows('clean'));
    expect(r.evidence.aiRaiseOnly).toBe(true);
    expect(r.reasonCodes).toContain('risk.ai.raise_only');
    expect(r.recommendedAction).toBe('tag');
    expect(r.score).toBe(0);
    expect(r.level).toBe('none');
  });

  it('tenant may switch the tag off', () => {
    const r = score(aiRows('unknown'), tenant({ ai: { tagOnAiOnlyRaise: false } }));
    expect(r.evidence.aiRaiseOnly).toBe(true);
    expect(r.recommendedAction).toBe('deliver');
  });

  it('a deterministic suspicious raised by AI is not AI-only', () => {
    const r = score(
      withBec(cleanRows(), 'suspicious', ['bec.content.urgency'], {
        verdict: 'malicious',
        finalCodes: ['bec.content.urgency', 'bec.ai.corroborated'],
      }),
    );
    expect(r.evidence.aiRaiseOnly).toBe(false);
    expect(r.hardBlocks).toEqual([]);
  });

  it('suppressed rules contribute nothing', () => {
    const r = score(
      withBec(cleanRows(), 'clean', [], {
        suppressed: ['bec.content.urgency'],
        finalCodes: ['clean.below_threshold'],
      }),
    );
    expect(contribution(r, 'bec_urgency')).toBeUndefined();
  });
});

describe('scoringErrorResult (R13)', () => {
  it('is the fail-safe error row', () => {
    const input = build(cleanRows());
    const r = scoringErrorResult(input, PLATFORM, 'scorer_exception');
    riskResultSchema.parse(r);
    expect(r).toMatchObject({
      status: 'error',
      score: 550,
      level: 'high',
      verdict: 'unknown',
      recommendedAction: 'quarantine',
    });
    expect(r.reasonCodes[0]).toBe('risk.scoring_error');
    expect(r.explanation.lines.map((l) => l.code)).toContain('scoring_error');
    expect(r.explanation.text).toContain('Scoring failed; treated as high risk (fail-safe).');
    expect(r.inputSha256).toBe(sha256Hex(canonicalJson(input)));
  });

  it('without an input hashes risk-input/unavailable; uses the platform thresholds', () => {
    const r = scoringErrorResult(null, tenant({ thresholds: { high: 600 } }), 'input_invalid');
    expect(r.inputSha256).toBe(sha256Hex('risk-input/unavailable'));
    expect(r.score).toBe(550);
    expect(r.versions.profile.source).toBe('tenant');
    expect(r.engines).toEqual([]);
  });
});
