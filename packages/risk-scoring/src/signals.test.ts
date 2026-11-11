import {
  ATTACHMENT_REASON_CODES,
  BEC_REASON_CODES,
  DLP_REASON_CODES,
  REASON_CODE_MAX_LENGTH,
  REASON_CODE_PATTERN,
  RSPAMD_REASON_CODES,
  SANDBOX_REASON_CODES,
  URL_REASON_CODES,
} from '@email-gateway/security-contracts';
import { describe, expect, it } from 'vitest';
import {
  isInformationalAssertion,
  platformProfile,
  RISK_GROUP_DEFINITIONS,
  RISK_INFORMATIONAL_CODES,
  RISK_REASON_CODES,
  RISK_SIGNAL_GROUPS,
  RISK_SIGNALS,
  type RiskSignalDefinition,
  scoreRisk,
  signalForAssertion,
} from './index';
import { build, cleanRows, withBec, withCodes } from './rows.test-support';
import type { RoundRows } from './input';

const PROFILE = platformProfile('rsk-default/1');

/** Rows in which `engine:code` is asserted (bec codes as active rules). */
function rowsAsserting(assertion: string, direction: RoundRows['message']['direction']): RoundRows {
  const [engine, code] = assertion.split(':') as [string, string];
  let rows: RoundRows = { ...cleanRows(), message: { ...cleanRows().message, direction } };
  if (engine === 'bec') rows = withBec(rows, 'suspicious', [code]);
  else rows = withCodes(rows, engine, 'suspicious', [code]);
  return rows;
}

const codeSignals = RISK_SIGNALS.filter((s) => s.source === 'code');

describe('signal map risk-signals/1 (R3)', () => {
  it('every group of the catalog has signals and a consistent rule', () => {
    for (const g of RISK_SIGNAL_GROUPS) {
      expect(RISK_SIGNALS.some((s) => s.group === g)).toBe(true);
      const def = RISK_GROUP_DEFINITIONS[g];
      expect(def.rule === 'max' ? def.cap === null : def.cap !== null).toBe(true);
    }
    expect(RISK_GROUP_DEFINITIONS.engine_failure.capFromProfile).toBe(true);
  });

  it('signal ids are unique and every assertion maps to exactly one signal', () => {
    expect(new Set(RISK_SIGNALS.map((s) => s.id)).size).toBe(RISK_SIGNALS.length);
    for (const s of RISK_SIGNALS) {
      for (const code of s.codes) expect(signalForAssertion(code)?.id).toBe(s.id);
    }
  });

  it('weights are integer points on 0-1000', () => {
    for (const s of RISK_SIGNALS) {
      expect(Number.isInteger(s.weight)).toBe(true);
      expect(s.weight).toBeGreaterThanOrEqual(0);
      expect(s.weight).toBeLessThanOrEqual(1000);
    }
  });

  const rows: [string, RiskSignalDefinition][] = codeSignals.flatMap((s) =>
    s.codes
      .filter((c) => !c.includes(':risk.input.'))
      .map((c) => [c, s] as [string, RiskSignalDefinition]),
  );

  it.each(rows)('%s fires its signal in its directions only', (assertion, signal) => {
    for (const direction of ['inbound', 'outbound', 'internal'] as const) {
      const result = scoreRisk(build(rowsAsserting(assertion, direction)), PROFILE);
      const contribution = result.contributions.find((c) => c.signal === signal.id);
      if (signal.directions.includes(direction)) {
        expect(contribution, `${assertion} ${direction}`).toBeDefined();
        expect(contribution!.codes).toContain(assertion);
        expect(contribution!.group).toBe(signal.group);
        expect(contribution!.weight).toBe(signal.weight);
      } else {
        expect(contribution, `${assertion} ${direction}`).toBeUndefined();
      }
    }
  });

  it('a signal fires once however many codes assert it', () => {
    const r = scoreRisk(
      build(
        withCodes(cleanRows(), 'url', 'suspicious', [
          'url.ip_obfuscated',
          'url.obfuscated_host',
          'url.userinfo',
        ]),
      ),
      PROFILE,
    );
    const c = r.contributions.filter((x) => x.signal === 'url_obfuscation');
    expect(c).toHaveLength(1);
    expect(c[0]!.codes).toEqual([
      'url:url.ip_obfuscated',
      'url:url.obfuscated_host',
      'url:url.userinfo',
    ]);
    expect(r.groups.find((g) => g.group === 'url_structure')?.total).toBe(150);
  });
});

describe('exhaustiveness: every engine code is mapped or informational (R3)', () => {
  // Rule: a code is either asserted by a signal of the map, or informational. Informational by
  // construction: every `engine.*` attempt/size code (its effect is the engine status, R6), every
  // DLP code (DLP enters through its result row: action, severity, coverage) and every sandbox
  // code (the sandbox enters through its outcome). The remaining informational codes are listed
  // explicitly in RISK_INFORMATIONAL_CODES.
  const lists: [string, readonly string[]][] = [
    ['rspamd', RSPAMD_REASON_CODES],
    ['attachment', ATTACHMENT_REASON_CODES],
    ['url', URL_REASON_CODES],
    ['bec', BEC_REASON_CODES],
    ['dlp', DLP_REASON_CODES],
    ['sandbox', SANDBOX_REASON_CODES],
  ];
  it.each(lists)('%s', (engine, codes) => {
    const neither = codes.filter(
      (code) => !signalForAssertion(`${engine}:${code}`) && !isInformationalAssertion(engine, code),
    );
    expect(neither).toEqual([]);
  });

  it('no code is both mapped and listed informational', () => {
    for (const assertion of RISK_INFORMATIONAL_CODES) {
      expect(signalForAssertion(assertion), assertion).toBeUndefined();
    }
  });

  it('every code-asserting entry of the map is a real engine code', () => {
    const known = new Map(lists.map(([e, c]) => [e, new Set(c)]));
    for (const s of codeSignals) {
      for (const assertion of s.codes) {
        const [engine, code] = assertion.split(':') as [string, string];
        if (code.startsWith('risk.input.')) continue;
        expect(known.get(engine)?.has(code), assertion).toBe(true);
      }
    }
  });

  it('an unmapped code contributes 0 and is recorded', () => {
    const r = scoreRisk(
      build(withCodes(cleanRows(), 'url', 'suspicious', ['url.brand_new_rule'])),
      PROFILE,
    );
    expect(r.score).toBe(0);
    expect(r.evidence.unmappedCodes).toEqual(['url:url.brand_new_rule']);
    expect(r.reasonCodes).toContain('risk.signal.unmapped_code');
    expect(r.verdict).toBe('unknown');
  });
});

describe('RISK_REASON_CODES', () => {
  it('match the pattern, are at most 64 characters and unique', () => {
    expect(new Set(RISK_REASON_CODES).size).toBe(RISK_REASON_CODES.length);
    for (const code of RISK_REASON_CODES) {
      expect(code).toMatch(REASON_CODE_PATTERN);
      expect(code.length).toBeLessThanOrEqual(REASON_CODE_MAX_LENGTH);
      expect(code.startsWith('risk.')).toBe(true);
    }
  });

  it('cover every signal, hard block, engine status and profile code', () => {
    for (const s of RISK_SIGNALS) expect(RISK_REASON_CODES).toContain(`risk.signal.${s.id}`);
    for (const c of [
      'risk.hard_block.malware_attachment',
      'risk.hard_block.dmarc_reject',
      'risk.engine.sandbox.timeout',
      'risk.engine.rspamd.missing',
      'risk.input.auth_row_missing',
      'risk.trust.denied_auth_failure',
      'risk.floor.engine_unknown',
      'risk.ai.raise_only',
      'risk.profile.foreign_fallback',
      'risk.sandbox.included',
      'risk.scoring_error',
      'risk.level.critical',
    ]) {
      expect(RISK_REASON_CODES).toContain(c);
    }
  });
});
