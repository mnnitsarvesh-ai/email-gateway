import {
  ATTACHMENT_REASON_CODES,
  BEC_REASON_CODES,
  BEC_RULES,
  DLP_REASON_CODES,
  RSPAMD_REASON_CODES,
  URL_REASON_CODES,
} from '@email-gateway/security-contracts';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkReport } from '../scripts/calibrate';
import { DISCLAIMER } from '../scripts/calibration';
import {
  DATASET_CLASS_SIZES,
  DATASET_CLASSES,
  DATASET_PATH,
  datasetJsonl,
  type DatasetFixture,
  parseDatasetJsonl,
} from '../scripts/dataset';
import { checkDataset } from '../scripts/generate-dataset';
import { RISK_LEVELS, scoringInputSchema } from './index';

const ROOT = join(__dirname, '..');
const committed = readFileSync(join(ROOT, DATASET_PATH), 'utf8');
const fixtures: DatasetFixture[] = parseDatasetJsonl(committed);

const CODES: Record<string, ReadonlySet<string>> = {
  rspamd: new Set(RSPAMD_REASON_CODES),
  attachment: new Set(ATTACHMENT_REASON_CODES),
  url: new Set(URL_REASON_CODES),
  bec: new Set(BEC_REASON_CODES),
  dlp: new Set(DLP_REASON_CODES),
};

/** Rspamd codes that never raise its verdict with default settings (R7 reason-only, R9, R6 ARC). */
const RSPAMD_NON_RAISING = new Set([
  'auth.spf_fail',
  'auth.dkim_fail',
  'auth.arc_fail',
  'auth.dmarc_fail_arc_trusted',
  'reputation.ip_listed',
  'reputation.domain_listed',
  'header.anomaly',
  'bayes.spam',
  'bayes.ham',
  'fuzzy.unknown',
  'auth.temperror',
]);
const RSPAMD_SPAM = ['spam.gtube', 'spam.reject_action', 'fuzzy.spam', 'spam.score'];
const RSPAMD_MALICIOUS = [
  'phishing.known_bad_url',
  'malware.known_bad_url',
  'fuzzy.phish',
  'phishing.link_mismatch_auth_failure',
];
const RSPAMD_SUSPICIOUS = [
  'spam.suspicious_score',
  'auth.dmarc_quarantine',
  'auth.dmarc_reject',
  'phishing.link_mismatch',
];
const ATTACHMENT_MALICIOUS = ['malware.known_hash', 'malware.clamav', 'yara.high'];
const ATTACHMENT_CLEAN_INFO = new Set([
  'clean.no_findings',
  'yara.low',
  'office.macros',
  'filename.double_extension',
  'filename.executable_extension',
  'filename.bidi_control',
]);
const URL_MALICIOUS = [
  'url.feed_malicious',
  'url.dnsbl_phishing',
  'url.dnsbl_malware',
  'url.dnsbl_c2',
  'url.phishing_high_confidence',
  'url.tenant_blocked',
  'url.dynamic_phishing',
];
const URL_INFORMATIONAL = new Set([
  'url.shortened',
  'url.redirected',
  'url.meta_refresh',
  'url.idn',
  'url.brand_tld_variant',
  'url.nonstandard_port',
  'url.trailing_dot',
  'url.in_attachment',
  'url.allowlisted',
  'url.charset_guess',
  'url.fetch_skipped_limit',
]);
const URL_UNKNOWN = [
  'url.fetch_timeout',
  'url.fetch_dns_error',
  'url.fetch_tls_error',
  'url.fetch_connection_error',
  'url.fetch_http_error',
  'url.fetch_too_large',
  'url.fetch_blocked_port',
  'url.fetch_not_performed',
  'url.reputation_unavailable',
  'url.dynamic_failed',
];
const BEC_RULE_CATEGORY = new Map(Object.values(BEC_RULES).map((r) => [r.code, r.category]));

describe('synthetic dataset risk-calibration-1 (§9.2)', () => {
  it('dataset:check: regenerating gives the committed file byte for byte', () => {
    expect(datasetJsonl()).toBe(committed);
    expect(checkDataset(ROOT).ok).toBe(true);
  });

  it('has the class sizes of §9.2 and unique ids', () => {
    for (const cls of DATASET_CLASSES) {
      expect(fixtures.filter((f) => f.class === cls)).toHaveLength(DATASET_CLASS_SIZES[cls]);
    }
    expect(new Set(fixtures.map((f) => f.id)).size).toBe(fixtures.length);
    expect(fixtures).toHaveLength(1050);
  });

  it('every fixture is a schema-valid input with a valid band', () => {
    for (const f of fixtures) {
      expect(scoringInputSchema.safeParse(f.input).success, f.id).toBe(true);
      const [min, max] = f.expectedLevelBand;
      expect(RISK_LEVELS.indexOf(min)).toBeGreaterThanOrEqual(0);
      expect(RISK_LEVELS.indexOf(max)).toBeGreaterThanOrEqual(RISK_LEVELS.indexOf(min));
      expect(Object.keys(f).sort()).toEqual(['class', 'expectedLevelBand', 'id', 'input']);
    }
  });

  it('uses only codes of the engines code lists, consistent with each outcome', () => {
    for (const f of fixtures) {
      for (const e of f.input.engines) {
        const codes = e.reasonCodes.filter((c) => !c.startsWith('risk.input.'));
        for (const code of codes)
          expect(CODES[e.engine]!.has(code), `${f.id} ${e.engine}:${code}`).toBe(true);
        const ctx = `${f.id} ${e.engine} ${e.outcome}`;
        const any = (list: string[]) => codes.some((c) => list.includes(c));
        if (e.status === 'failed' || e.status === 'missing') expect(codes, ctx).toEqual([]);
        if (e.engine === 'rspamd') {
          if (e.outcome === 'clean') {
            expect(codes, ctx).toContain('clean.below_threshold');
            for (const c of codes)
              expect(c === 'clean.below_threshold' || RSPAMD_NON_RAISING.has(c), ctx).toBe(true);
          }
          if (e.outcome === 'spam') expect(any(RSPAMD_SPAM), ctx).toBe(true);
          if (e.outcome === 'malicious') expect(any(RSPAMD_MALICIOUS), ctx).toBe(true);
          if (e.outcome === 'suspicious') expect(any(RSPAMD_SUSPICIOUS), ctx).toBe(true);
          if (e.outcome === 'unknown')
            expect(codes.length === 1 && codes[0]!.startsWith('engine.'), ctx).toBe(true);
          if (e.outcome !== 'clean') expect(codes, ctx).not.toContain('clean.below_threshold');
        }
        if (e.engine === 'attachment') {
          if (e.outcome === 'malicious') expect(any(ATTACHMENT_MALICIOUS), ctx).toBe(true);
          else expect(any(ATTACHMENT_MALICIOUS), ctx).toBe(false);
          if (e.outcome === 'clean') {
            expect(codes, ctx).toContain('clean.no_findings');
            for (const c of codes) expect(ATTACHMENT_CLEAN_INFO.has(c), ctx).toBe(true);
          }
          if (e.outcome === 'skipped') expect(codes, ctx).toEqual(['attachment.none']);
          if (e.outcome === 'skipped') expect(f.input.envelope.attachmentCount).toBe(0);
        }
        if (e.engine === 'url') {
          if (e.outcome === 'malicious') expect(any(URL_MALICIOUS), ctx).toBe(true);
          else expect(any(URL_MALICIOUS), ctx).toBe(false);
          if (e.outcome === 'clean') {
            expect(codes, ctx).toContain('clean.no_findings');
            for (const c of codes)
              expect(c === 'clean.no_findings' || URL_INFORMATIONAL.has(c), ctx).toBe(true);
          }
          if (e.outcome === 'unknown') expect(any(URL_UNKNOWN), ctx).toBe(true);
          if (e.outcome === 'skipped') expect(codes, ctx).toEqual(['url.none']);
        }
        if (e.engine === 'bec' && e.status === 'definite') {
          expect(f.input.envelope.direction, ctx).toBe('inbound');
          const rules =
            f.input.bec?.activeRuleCodes ?? codes.filter((c) => BEC_RULE_CATEGORY.has(c));
          const categories = new Set(rules.map((c) => BEC_RULE_CATEGORY.get(c)));
          const det = f.input.bec?.deterministicVerdict ?? e.outcome;
          if (det === 'malicious') {
            expect(categories.has('impersonation') || categories.has('lookalike'), ctx).toBe(true);
            expect(categories.has('intent'), ctx).toBe(true);
          }
          if (det === 'suspicious')
            expect(
              rules.filter((c) => BEC_RULE_CATEGORY.get(c) !== 'engine').length,
              ctx,
            ).toBeGreaterThan(0);
          if (det === 'clean') {
            for (const c of rules)
              expect(
                ['engine', 'history', 'intent'].includes(BEC_RULE_CATEGORY.get(c) ?? ''),
                ctx,
              ).toBe(true);
            expect(
              rules.filter((c) => BEC_RULE_CATEGORY.get(c) !== 'engine').length,
              ctx,
            ).toBeLessThanOrEqual(1);
          }
          if (f.input.bec && f.input.bec.verdict !== f.input.bec.deterministicVerdict) {
            expect(
              codes.some((c) => c.startsWith('bec.ai.')),
              ctx,
            ).toBe(true);
          }
        }
        if (e.engine === 'bec' && e.status === 'skipped')
          expect(codes).toEqual(['bec.not_inbound']);
        if (e.engine === 'dlp' && e.status === 'skipped') {
          expect(codes).toEqual(['dlp.not_inbound']);
          expect(f.input.envelope.direction).toBe('inbound');
        }
        if (e.engine === 'dlp' && f.input.dlp && e.status === 'definite') {
          if (f.input.dlp.action === 'allow') expect(codes).toEqual(['dlp.no_findings']);
          else expect(codes).toContain(`dlp.action.${f.input.dlp.action}`);
          expect(codes.includes('dlp.coverage.partial')).toBe(f.input.dlp.coverage === 'partial');
        }
      }
      // round outcome consistent with the statuses
      const failed = f.input.engines.some(
        (e) => e.required && (e.status === 'failed' || e.status === 'missing'),
      );
      expect(f.input.round.outcome === 'scan_failed', f.id).toBe(failed);
    }
  });

  it('contains no addresses, domains, URLs or text', () => {
    expect(committed).not.toMatch(/@|:\/\//);
    // every string value is a code, an enum value, a version, a hash-free id or an ISO time
    const strings = committed.match(/"(?:[^"\\]|\\.)*"/g) ?? [];
    for (const s of strings) {
      expect(s).toMatch(/^"[a-z0-9_.:\-/T]*Z?"$/i);
      expect(s).not.toMatch(/\.(com|net|org|io|in|test|example)"/);
    }
  });
});

describe('calibration report (§9.2)', () => {
  it('calibrate:check: the committed report equals the regenerated one', async () => {
    const result = await checkReport(ROOT);
    expect(
      result.ok,
      `${result.path} is stale: run pnpm --filter @email-gateway/risk-scoring calibrate`,
    ).toBe(true);
  });

  it('carries the verbatim disclaimer and makes no claims', () => {
    const report = readFileSync(
      join(ROOT, '../../docs/performance/risk-scoring-calibration.md'),
      'utf8',
    );
    expect(report).toContain(DISCLAIMER);
    expect(DISCLAIMER).toContain(
      'Synthetic, self-constructed data. These numbers show that the defaults behave as designed on the cases we wrote; they are not detection accuracy, precision or recall, and no such claim is made without a validated real-world dataset.',
    );
    const withoutDisclaimer = report.split(DISCLAIMER).join('');
    expect(withoutDisclaimer).not.toMatch(/accuracy|precision|recall|\d+(\.\d+)?\s?%/i);
  });
});
