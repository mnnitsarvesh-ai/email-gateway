import type { NormalizedRspamdResult, RspamdAuthResults } from '@email-gateway/rspamd';
import {
  resolveRspamdSettings,
  RSPAMD_PLATFORM_DEFAULTS,
  type RspamdEffectiveSettings,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import { inCategory, SYMBOL_CATEGORIES } from './symbol-catalog';
import { mapRspamdVerdict, RSPAMD_MAPPING_VERSION } from './verdict-mapper';

const platform = (): RspamdEffectiveSettings => {
  const r = resolveRspamdSettings(RSPAMD_PLATFORM_DEFAULTS, null);
  if (!r.ok) throw new Error('defaults invalid');
  return r.settings;
};
const tenant = (override: Record<string, unknown>): RspamdEffectiveSettings => {
  const r = resolveRspamdSettings(RSPAMD_PLATFORM_DEFAULTS, override);
  if (!r.ok) throw new Error(JSON.stringify(r.violations));
  return r.settings;
};

const noAuth = (): RspamdAuthResults => ({
  spf: { result: null, domain: null },
  dkim: { result: null, signatures: [] },
  dmarc: { result: null, policy: null, domain: null },
  arc: { result: null },
});

function reply(
  symbols: Array<string | [string, number]>,
  extra: Partial<NormalizedRspamdResult> = {},
): NormalizedRspamdResult {
  return {
    score: 0,
    requiredScore: 15,
    action: 'no action',
    skipped: false,
    passthroughModule: null,
    symbols: symbols.map((s) =>
      typeof s === 'string'
        ? { name: s, score: 0.1, options: [] }
        : { name: s[0], score: s[1], options: [] },
    ),
    symbolsTruncated: false,
    auth: noAuth(),
    ...extra,
  };
}

const map = (r: NormalizedRspamdResult, s: RspamdEffectiveSettings = platform()) =>
  mapRspamdVerdict(r, s);

describe('Rspamd verdict mapping (S7 R0-R10)', () => {
  it('has a stable mapping version', () => {
    expect(RSPAMD_MAPPING_VERSION).toBe('rspamd-map/2');
  });

  it('R1: a skipped scan or a reply without symbols is unknown, never clean', () => {
    expect(map(reply(['R_SPF_ALLOW'], { skipped: true }))).toEqual({
      outcome: 'unknown',
      reasonCodes: ['engine.skipped'],
    });
    expect(map(reply([]))).toEqual({ outcome: 'unknown', reasonCodes: ['engine.empty_result'] });
    // R1 ends evaluation: a skipped reply with a high score is still unknown.
    expect(map(reply(['GTUBE'], { skipped: true, score: 15, action: 'reject' })).outcome).toBe(
      'unknown',
    );
  });

  it('R1: a pre-filter result that raised no verdict is unknown, never clean', () => {
    // e.g. a whitelisting multimap pre-filter: is_skipped with passthrough_module, no action.
    expect(map(reply(['EG_WHITELIST', 'R_SPF_ALLOW'], { passthroughModule: 'multimap' }))).toEqual({
      outcome: 'unknown',
      reasonCodes: ['engine.skipped'],
    });
    // A pre-filter that decided spam (GTUBE, verified against 3.12) stays a definite verdict.
    expect(
      map(reply(['GTUBE'], { passthroughModule: 'GTUBE', score: 0, action: 'reject' })),
    ).toEqual({ outcome: 'spam', reasonCodes: ['spam.gtube', 'spam.reject_action'] });
  });

  it('R10: a complete reply below every threshold is clean', () => {
    expect(map(reply(['R_SPF_ALLOW', 'R_DKIM_ALLOW'], { score: 0.1 }))).toEqual({
      outcome: 'clean',
      reasonCodes: ['clean.below_threshold'],
    });
  });

  it('R2: known-bad URL feeds and fuzzy phishing are malicious', () => {
    expect(map(reply(['EG_BAD_URL'], { score: 12 }))).toEqual({
      outcome: 'malicious',
      reasonCodes: ['phishing.known_bad_url', 'spam.score'],
    });
    for (const name of ['PH_SURBL_MULTI', 'DBL_PHISH', 'PHISHED_OPENPHISH', 'PHISHED_PHISHTANK']) {
      expect(map(reply([name])).reasonCodes).toContain('phishing.known_bad_url');
    }
    for (const name of ['MW_SURBL_MULTI', 'DBL_ABUSE_MALWARE', 'DBL_MALWARE']) {
      expect(map(reply([name]))).toEqual({
        outcome: 'malicious',
        reasonCodes: ['malware.known_bad_url'],
      });
    }
    expect(map(reply(['EG_FUZZY_PHISH']))).toEqual({
      outcome: 'malicious',
      reasonCodes: ['fuzzy.phish'],
    });
  });

  it('R3: link mismatch is the tenant phishing verdict, malicious with an auth failure', () => {
    expect(map(reply(['PHISHING'], { score: 2.9 }))).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['phishing.link_mismatch'],
    });
    expect(map(reply(['PHISHING']), tenant({ phishingVerdict: 'malicious' })).outcome).toBe(
      'malicious',
    );
    const dmarcFail = {
      ...noAuth(),
      dmarc: { result: 'fail' as const, policy: null, domain: null },
    };
    expect(map(reply(['PHISHING'], { auth: dmarcFail })).reasonCodes).toContain(
      'phishing.link_mismatch_auth_failure',
    );
    expect(map(reply(['PHISHING', 'R_SPF_FAIL'])).outcome).toBe('malicious');
    expect(map(reply(['PHISHING'], { score: 6 })).outcome).toBe('malicious');
    expect(map(reply(['EG_PHISH_AUTH_FAIL']))).toEqual({
      outcome: 'malicious',
      reasonCodes: ['phishing.link_mismatch_auth_failure'],
    });
  });

  it('R4: GTUBE, the reject action and fuzzy spam are spam', () => {
    expect(
      map(reply(['GTUBE'], { score: 15, action: 'reject', passthroughModule: 'GTUBE' })),
    ).toEqual({
      outcome: 'spam',
      reasonCodes: ['spam.gtube', 'spam.reject_action', 'spam.score'],
    });
    expect(map(reply(['X'], { action: 'reject' })).outcome).toBe('spam');
    expect(map(reply(['EG_FUZZY_SPAM'])).reasonCodes).toEqual(['fuzzy.spam']);
  });

  it('R5/R8: score thresholds come from the effective (tenant) settings', () => {
    expect(map(reply(['X'], { score: 6 }))).toEqual({
      outcome: 'spam',
      reasonCodes: ['spam.score'],
    });
    expect(map(reply(['X'], { score: 4 }))).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['spam.suspicious_score'],
    });
    expect(map(reply(['X'], { score: 3.99 })).outcome).toBe('clean');
    // A tenant may tighten or loosen the thresholds within the platform bounds.
    expect(
      map(reply(['X'], { score: 3 }), tenant({ suspiciousScore: 2, spamScore: 3 })).outcome,
    ).toBe('spam');
    expect(
      map(reply(['X'], { score: 7 }), tenant({ spamScore: 10, suspiciousScore: 8 })).outcome,
    ).toBe('clean');
  });

  it('R6: DMARC reject/quarantine without a trusted ARC chain', () => {
    expect(map(reply(['DMARC_POLICY_REJECT'], { score: 3.1 }))).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['auth.dmarc_reject'],
    });
    expect(
      map(reply(['DMARC_POLICY_REJECT']), tenant({ dmarcRejectVerdict: 'malicious' })).outcome,
    ).toBe('malicious');
    expect(map(reply(['DMARC_POLICY_QUARANTINE']))).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['auth.dmarc_quarantine'],
    });
  });

  describe('R6: ARC trust comes only from the trusted-sealer list', () => {
    const sym = (name: string, score: number, options: string[]) => ({ name, score, options });
    const arc = (symbols: ReturnType<typeof sym>[], names: string[] = ['DMARC_POLICY_REJECT']) => {
      const base = reply(names);
      return { ...base, symbols: [...base.symbols, ...symbols] };
    };
    const allow = (i = 1, d = 'forwarder.test') => sym('ARC_ALLOW', -1, [`${d}:s=arc:i=${i}`]);
    const trusted = (i = 1, score = -2, d = 'forwarder.test') =>
      sym('ARC_ALLOW_TRUSTED', score, [`${d}:s=arc:i=${i}`]);

    it('a valid chain from any sealer (ARC_ALLOW alone) keeps the DMARC verdict', () => {
      // Anyone can seal with a key of their own domain: a self-made i=1 cv=none chain.
      expect(map(arc([allow(1, 'attacker.test')]))).toEqual({
        outcome: 'suspicious',
        reasonCodes: ['auth.dmarc_reject'],
      });
      expect(map(arc([allow()], ['DMARC_POLICY_QUARANTINE']))).toEqual({
        outcome: 'suspicious',
        reasonCodes: ['auth.dmarc_quarantine'],
      });
      expect(map(arc([allow()]), tenant({ dmarcRejectVerdict: 'malicious' })).outcome).toBe(
        'malicious',
      );
    });

    it('a trusted sealer as the latest hop turns DMARC reject/quarantine into a reason only', () => {
      expect(map(arc([allow(), trusted()]))).toEqual({
        outcome: 'clean',
        reasonCodes: ['auth.dmarc_fail_arc_trusted', 'clean.below_threshold'],
      });
      expect(map(arc([allow(2, 'list.test'), trusted(2, -2, 'list.test')]))).toMatchObject({
        outcome: 'clean',
      });
      expect(map(arc([allow(), trusted()], ['DMARC_POLICY_QUARANTINE'])).reasonCodes).toEqual([
        'auth.dmarc_fail_arc_trusted',
        'clean.below_threshold',
      ]);
    });

    it('a trusted sealer followed by an untrusted hop is not trusted', () => {
      // i=1 trusted, i=2 sealed by someone else (who could have changed the message).
      expect(map(arc([allow(2, 'attacker.test'), trusted(1)])).reasonCodes).toEqual([
        'auth.dmarc_reject',
      ]);
    });

    it('a trusted sealer whose own results recorded a DMARC failure is not trusted', () => {
      // Rspamd multiplies ARC_ALLOW_TRUSTED to 0 in that case.
      expect(map(arc([allow(), trusted(1, 0)])).outcome).toBe('suspicious');
    });

    it('ARC_ALLOW_TRUSTED without ARC_ALLOW, with ARC_REJECT, or without options is not trusted', () => {
      expect(map(arc([trusted()])).outcome).toBe('suspicious');
      expect(
        map(arc([allow(), trusted(), sym('ARC_REJECT', 2, ['seal check failed'])])),
      ).toMatchObject({ outcome: 'suspicious' });
      expect(map(arc([sym('ARC_ALLOW', -1, []), trusted()])).outcome).toBe('suspicious');
      expect(map(arc([allow(), sym('ARC_ALLOW_TRUSTED', -2, ['garbage'])])).outcome).toBe(
        'suspicious',
      );
    });
  });

  it('R7: SPF, DKIM and ARC failures are reasons only unless the tenant raises them', () => {
    const r = reply(['R_SPF_FAIL', 'R_DKIM_REJECT', 'ARC_REJECT']);
    expect(map(r)).toEqual({
      outcome: 'clean',
      reasonCodes: ['auth.arc_fail', 'auth.dkim_fail', 'auth.spf_fail', 'clean.below_threshold'],
    });
    expect(map(r, tenant({ authFailureVerdict: 'suspicious' }))).toEqual({
      outcome: 'suspicious',
      reasonCodes: ['auth.arc_fail', 'auth.dkim_fail', 'auth.spf_fail'],
    });
    // The normalized SPF result counts as well as the symbol.
    const spf = { ...noAuth(), spf: { result: 'fail' as const, domain: 'x.test' } };
    expect(map(reply(['X'], { auth: spf })).reasonCodes).toContain('auth.spf_fail');
  });

  it('R9: informational categories add reasons without raising the verdict', () => {
    const r = map(
      reply([
        'EG_TEST_RBL',
        'RBL_SPAMHAUS_SBL',
        'EG_TEST_DBL',
        'URIBL_BLACK',
        ['SENDER_REP', 0.5],
        'MISSING_DATE',
        'HFILTER_HELO_BAREIP',
        'EG_DISPLAY_NAME_ADDRESS',
        'BAYES_SPAM',
        'BAYES_HAM',
        'EG_FUZZY_UNKNOWN',
        'R_SPF_DNSFAIL',
      ]),
    );
    expect(r.outcome).toBe('clean');
    expect(r.reasonCodes).toEqual([
      'auth.temperror',
      'bayes.ham',
      'bayes.spam',
      'clean.below_threshold',
      'fuzzy.unknown',
      'header.anomaly',
      'reputation.domain_listed',
      'reputation.ip_listed',
    ]);
    // A signed reputation symbol counts only on its bad side.
    expect(map(reply([['SENDER_REP', -0.5]])).reasonCodes).toEqual(['clean.below_threshold']);
  });

  it('orders reasons by the severity of their rule, then name, and keeps the most severe verdict', () => {
    const r = map(
      reply(['EG_BAD_URL', 'GTUBE', 'DMARC_POLICY_REJECT', 'EG_TEST_RBL', 'PHISHING'], {
        score: 20,
        action: 'reject',
      }),
    );
    expect(r.outcome).toBe('malicious');
    expect(r.reasonCodes).toEqual([
      'phishing.known_bad_url',
      'phishing.link_mismatch_auth_failure',
      'spam.gtube',
      'spam.reject_action',
      'spam.score',
      'auth.dmarc_reject',
      'reputation.ip_listed',
    ]);
  });

  it('matches symbols by exact name and prefix', () => {
    expect(inCategory('ipListed', 'RECEIVED_SPAMHAUS_PBL', 1)).toBe(true);
    expect(inCategory('ipListed', 'IP_REPUTATION_HAM', -1)).toBe(false);
    expect(inCategory('headerAnomaly', 'FORGED_SENDER', 0.3)).toBe(true);
    expect(inCategory('phishingUrl', 'EG_BAD_URLX', 1)).toBe(false);
    expect(Object.keys(SYMBOL_CATEGORIES).length).toBeGreaterThan(10);
  });
});
