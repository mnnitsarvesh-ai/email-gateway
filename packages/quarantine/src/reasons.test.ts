import { describe, expect, it } from 'vitest';
import { always, evaluate, PID, rev, rule } from './fixtures.test-support';
import { hardBlocksOf, primaryEngineFor, quarantineReasonFor } from './reasons';

const hb = (id: string, action: 'block' | 'quarantine' = 'quarantine') => ({ id, action });

describe('quarantineReasonFor / primaryEngineFor (Q6)', () => {
  const cases: Array<[string, Parameters<typeof evaluate>, string, string]> = [
    [
      'malware attachment hard block',
      [
        {
          risk: {
            rev0: rev('block', {
              verdict: 'malware',
              hardBlocks: [hb('hb.malware_attachment', 'block')],
            }),
          },
        },
      ],
      'malware',
      'attachment',
    ],
    [
      'malware URL hard block',
      [
        {
          risk: {
            rev0: rev('block', { verdict: 'malware', hardBlocks: [hb('hb.malware_url', 'block')] }),
          },
        },
      ],
      'malware',
      'url',
    ],
    [
      'sandbox malware (revision 1)',
      [
        {
          risk: {
            rev0: rev('deliver'),
            rev1: rev('quarantine', {
              verdict: 'malware',
              hardBlocks: [hb('hb.malware_sandbox')],
              sandboxOutcome: 'malicious',
            }),
          },
        },
      ],
      'malware',
      'sandbox',
    ],
    [
      'malicious attachment with the hard-block floor, no malware block id',
      [
        {
          attachments: [{ filename: 'a.exe', verdict: 'malicious' }],
          risk: {
            rev0: rev('quarantine', { verdict: 'phishing', hardBlocks: [hb('hb.known_phishing')] }),
          },
        },
      ],
      'malware',
      'attachment',
    ],
    [
      'phishing hard block beats BEC and DLP',
      [
        {
          risk: {
            rev0: rev('quarantine', { verdict: 'phishing', hardBlocks: [hb('hb.known_phishing')] }),
          },
          bec: { deterministicVerdict: 'suspicious', verdict: 'suspicious' },
          dlp: { action: 'quarantine' },
        },
      ],
      'phishing',
      'url',
    ],
    [
      'tenant domain spoof → phishing via rspamd/auth',
      [
        {
          risk: {
            rev0: rev('quarantine', {
              verdict: 'phishing',
              hardBlocks: [hb('hb.tenant_domain_spoof')],
            }),
          },
        },
      ],
      'phishing',
      'rspamd',
    ],
    [
      'phishing verdict without a block, malicious URL',
      [
        {
          urls: [{ host: 'evil.test', verdict: 'malicious' }],
          risk: { rev0: rev('quarantine', { verdict: 'phishing', levelOnly: true }) },
        },
      ],
      'phishing',
      'url',
    ],
    [
      'phishing verdict without facts',
      [{ risk: { rev0: rev('quarantine', { verdict: 'phishing', levelOnly: true }) } }],
      'phishing',
      'none',
    ],
    [
      'BEC deterministic suspicious (D2)',
      [{ bec: { deterministicVerdict: 'suspicious', verdict: 'suspicious' } }],
      'bec',
      'bec',
    ],
    ['DLP floor', [{ dlp: { action: 'quarantine' } }], 'dlp', 'dlp'],
    ['DLP missing row', [{ dlpFinal: 'definite' }], 'dlp', 'dlp'],
    [
      'DLP-decisive tenant rule',
      [
        { dlp: { action: 'alert', categories: ['payment_card'] } },
        [
          rule('cards', { field: 'dlp.categories', op: 'contains_any', value: ['payment_card'] }, [
            { type: 'QUARANTINE' },
          ]),
        ],
      ],
      'dlp',
      'dlp',
    ],
    [
      'scan failure',
      [
        {
          trigger: 'scan_failed',
          scan: { engines: [{ engine: 'attachment', outcome: 'timeout' }] },
        },
      ],
      'engine_unavailable',
      'attachment',
    ],
    ['parse failure', [{ trigger: 'parse_failed', risk: null }], 'engine_unavailable', 'none'],
    ['risk row missing', [{ risk: null }], 'engine_unavailable', 'none'],
    ['tenant rule', [{}, [rule('hold', always, [{ type: 'QUARANTINE' }])]], 'policy', 'policy'],
    [
      'spam verdict (platform default)',
      [{ risk: { rev0: rev('quarantine', { verdict: 'spam', levelOnly: true }) } }],
      'spam',
      'rspamd',
    ],
    [
      'bulk verdict',
      [{ risk: { rev0: rev('quarantine', { verdict: 'bulk', levelOnly: true }) } }],
      'bulk',
      'rspamd',
    ],
    [
      'anything else',
      [{ risk: { rev0: rev('quarantine', { verdict: 'suspicious', levelOnly: true }) } }],
      'suspicious',
      'none',
    ],
  ];
  it.each(cases)('%s', (_name, args, reason, engine) => {
    const evaluation = evaluate(...args);
    expect(evaluation.result.disposition).not.toBe('allow');
    expect(quarantineReasonFor(evaluation)).toBe(reason);
    expect(primaryEngineFor(evaluation)).toBe(engine);
  });

  it('an unknown-engine tag floor does not make the cause engine_unavailable', () => {
    const e = evaluate(
      { risk: { rev0: rev('tag', { failureStatuses: ['unknown'], levelOnly: false }) } },
      [rule('hold', always, [{ type: 'QUARANTINE' }])],
    );
    expect(e.result.floor.reasons).toContain('policy.floor.unknown_engine');
    expect(quarantineReasonFor(e)).toBe('policy');
  });

  it('without the input, stored hard-block ids still classify (adoption)', () => {
    const e = evaluate({
      risk: {
        rev0: rev('block', { verdict: 'malware', hardBlocks: [hb('hb.malware_url', 'block')] }),
      },
    });
    const stored = { result: e.result, hardBlocks: ['hb.malware_url'] };
    expect(quarantineReasonFor(stored)).toBe('malware');
    expect(primaryEngineFor(stored)).toBe('url');
    expect(
      hardBlocksOf({ result: e.result, input: e.input, hardBlocks: ['hb.dlp_block'] }),
    ).toEqual(['hb.dlp_block', 'hb.malware_url']);
  });

  it('a recipient decision overrides the decisive record (split recipients)', () => {
    const e = evaluate({ risk: { rev0: rev('quarantine', { verdict: 'spam', levelOnly: true }) } });
    expect(quarantineReasonFor(e)).toBe('spam');
    expect(
      quarantineReasonFor(e, { source: 'tenant_rule', decisiveRuleRef: `${PID}#1/split` }),
    ).toBe('policy');
    expect(quarantineReasonFor(e, null)).toBe('spam');
  });
});
