import { describe, expect, it } from 'vitest';
import { indeterminate, negative, txtAnswer } from '../../../../test/support/dns/dns-results';
import { evaluateDmarc, isDmarcCandidate, parseDmarc, recommendDmarc } from './dmarc';

const domain = 'acme.test';
const host = `_dmarc.${domain}`;
type ReportConfig = { dmarcRua: string[]; dmarcRuf: string[] };
const gateway: ReportConfig = {
  dmarcRua: ['mailto:dmarc-reports@mail-gateway.test'],
  dmarcRuf: [],
};
const noGateway: ReportConfig = { dmarcRua: [], dmarcRuf: [] };
const evaluate = (records: string[], g = gateway) =>
  evaluateDmarc(txtAnswer(host, records), domain, g);

describe('parseDmarc', () => {
  it('parses tags in order with lower-case names', () => {
    expect(
      parseDmarc('v=DMARC1; P=reject ; pct=50; rua=mailto:a@acme.test,mailto:b@acme.test;'),
    ).toEqual({
      tags: [
        ['v', 'DMARC1'],
        ['p', 'reject'],
        ['pct', '50'],
        ['rua', 'mailto:a@acme.test,mailto:b@acme.test'],
      ],
      errors: [],
    });
  });

  it.each([
    ['p=none; v=DMARC1', 'v'],
    ['v=DMARC1', 'p'],
    ['v=DMARC1; p=block', 'p'],
    ['v=DMARC1; p=none; sp=maybe', 'sp'],
    ['v=DMARC1; p=none; pct=101', 'pct'],
    ['v=DMARC1; p=none; adkim=x', 'adkim'],
    ['v=DMARC1; p=none; rua=dmarc@acme.test', 'rua'],
    ['v=DMARC1; p=none; p=reject', 'duplicate:p'],
    ['v=DMARC1; p=none; garbage', 'syntax'],
  ])('flags %s as %s', (record, error) => {
    expect(parseDmarc(record).errors).toContain(error);
  });

  it('recognises DMARC candidates', () => {
    expect(isDmarcCandidate('v=DMARC1; p=none')).toBe(true);
    expect(isDmarcCandidate('p=none; v=DMARC1')).toBe(true);
    expect(isDmarcCandidate('v=spf1 -all')).toBe(false);
  });
});

describe('evaluateDmarc', () => {
  it('is missing without a record and recommends a monitoring policy', () => {
    const result = evaluateDmarc(negative(host), domain, gateway);
    expect(result).toEqual({
      outcome: 'missing',
      observedValue: null,
      stage: 'missing',
      partial: false,
      recommendedValue: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@mail-gateway.test; fo=1',
      nextStep: 'Publish a monitoring policy (p=none) and review the aggregate reports.',
      warnings: ['dmarc_external_rua_needs_authorization'],
    });
    expect(evaluate(['v=spf1 -all']).outcome).toBe('missing');
  });

  it('suggests a report address at the domain when the gateway has none', () => {
    const result = evaluateDmarc(negative(host, 'nodata'), domain, noGateway);
    expect(result.recommendedValue).toBe(
      'v=DMARC1; p=none; rua=mailto:dmarc-reports@acme.test; fo=1',
    );
    expect(result.warnings).toEqual([]);
  });

  it('progresses none → quarantine → pct=100 → reject → final', () => {
    const none = evaluate(['v=DMARC1; p=none; rua=mailto:d@acme.test']);
    expect(none).toMatchObject({
      outcome: 'valid',
      stage: 'none',
      partial: false,
      recommendedValue:
        'v=DMARC1; p=quarantine; rua=mailto:d@acme.test,mailto:dmarc-reports@mail-gateway.test',
      warnings: ['dmarc_policy_none', 'dmarc_external_rua_needs_authorization'],
    });

    const partial = evaluate(['v=DMARC1; p=quarantine; pct=25; rua=mailto:d@acme.test'], noGateway);
    expect(partial).toMatchObject({
      stage: 'quarantine',
      partial: true,
      recommendedValue: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:d@acme.test',
      warnings: ['dmarc_pct_partial'],
    });

    const quarantine = evaluate(['v=DMARC1; p=quarantine; rua=mailto:d@acme.test'], noGateway);
    expect(quarantine).toMatchObject({
      stage: 'quarantine',
      recommendedValue: 'v=DMARC1; p=reject; rua=mailto:d@acme.test',
    });

    const reject = evaluate(['v=DMARC1; p=reject; rua=mailto:d@acme.test; adkim=s'], noGateway);
    expect(reject).toMatchObject({
      stage: 'reject',
      recommendedValue: 'v=DMARC1; p=reject; rua=mailto:d@acme.test; adkim=s',
      nextStep: 'No change needed: the domain enforces p=reject.',
      warnings: [],
    });
  });

  it('warns when no rua is published and adds the gateway rua/ruf', () => {
    const result = evaluate(['v=DMARC1; p=reject'], {
      dmarcRua: ['mailto:agg@mail-gateway.test'],
      dmarcRuf: ['mailto:forensic@mail-gateway.test'],
    });
    expect(result.warnings).toEqual(['dmarc_no_rua', 'dmarc_external_rua_needs_authorization']);
    expect(result.recommendedValue).toBe(
      'v=DMARC1; p=reject; rua=mailto:agg@mail-gateway.test; ruf=mailto:forensic@mail-gateway.test',
    );
  });

  it('does not duplicate a gateway rua that is already present', () => {
    const result = evaluate(['v=DMARC1; p=reject; rua=MAILTO:dmarc-reports@mail-gateway.test']);
    expect(result.recommendedValue).toBe(
      'v=DMARC1; p=reject; rua=MAILTO:dmarc-reports@mail-gateway.test',
    );
  });

  it('is invalid with several records, merged from the first', () => {
    const result = evaluate(['v=DMARC1; p=reject; adkim=s', 'v=DMARC1; p=none'], noGateway);
    expect(result).toMatchObject({
      outcome: 'invalid',
      stage: 'missing',
      warnings: ['dmarc_multiple_records'],
      recommendedValue: 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@acme.test; adkim=s; fo=1',
    });
  });

  it('is invalid with syntax errors, keeping only parsable tags', () => {
    const result = evaluate(['v=DMARC1; p=block; pct=40; rua=mailto:d@acme.test'], noGateway);
    expect(result).toMatchObject({
      outcome: 'invalid',
      warnings: ['dmarc_syntax_error'],
      recommendedValue: 'v=DMARC1; p=none; pct=40; rua=mailto:d@acme.test; fo=1',
    });
    expect(evaluate(['p=none; v=DMARC1']).outcome).toBe('invalid');
  });

  it('stays indeterminate', () => {
    expect(evaluateDmarc(indeterminate(host), domain, gateway).outcome).toBe('indeterminate');
  });

  it('recommendDmarc without a record is the missing recommendation', () => {
    expect(recommendDmarc(null, domain, gateway)).toMatchObject({
      stage: 'missing',
      partial: false,
      recommendedValue: 'v=DMARC1; p=none; rua=mailto:dmarc-reports@mail-gateway.test; fo=1',
    });
  });
});
