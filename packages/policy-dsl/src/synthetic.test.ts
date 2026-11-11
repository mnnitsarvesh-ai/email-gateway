import { describe, expect, it } from 'vitest';
import { DEPT } from './fixtures.test-support';
import { PolicyInputError, policyInputSchema } from './input';
import { buildSyntheticInput, SYNTHETIC_DEFAULT_TIME, syntheticFactsSchema } from './synthetic';

describe('synthetic facts (P23)', () => {
  it('fills documented defaults and produces a valid PolicyInput', () => {
    const i = buildSyntheticInput({});
    expect(policyInputSchema.parse(i)).toEqual(i);
    expect(i).toMatchObject({
      trigger: 'scanned',
      direction: 'inbound',
      evaluationTime: SYNTHETIC_DEFAULT_TIME,
      sender: {
        envelope: { address: 'sender@example.com' },
        headerFrom: { address: 'sender@example.com' },
        authenticated: null,
        trusted: null,
      },
      recipients: [{ rcptSeq: 0, address: 'recipient@example.net' }],
      auth: null,
      dlp: null,
      dlpFinal: 'absent',
      bec: null,
      becFinal: 'absent',
      urls: { rewriteStatus: 'none', items: [] },
    });
    expect(i.risk.rev0).toEqual({
      status: 'scored',
      score: 0,
      level: 'none',
      verdict: 'clean',
      recommendedAction: 'deliver',
      hardBlocks: [],
      reasonCodes: [],
      failureStatuses: [],
      levelOnly: true,
      aiRaiseOnly: false,
      sandboxOutcome: null,
    });
  });
  it('derives URL domains, IP host kinds, extensions and directory memberships', () => {
    const i = buildSyntheticInput({
      direction: 'outbound',
      sender: { envelope: 'CFO@Corp.Example', authenticated: true },
      urls: [{ host: 'a.b.example.co.uk' }, { host: '[2001:db8::1]' }],
      attachments: [{ filename: 'Setup.ISO', typeFamily: 'disk_image' }],
      directory: { departments: { 'cfo@corp.example': [DEPT.finance] } },
    });
    expect(i.urls.items.map((u) => [u.host, u.domain, u.hostKind])).toEqual([
      ['a.b.example.co.uk', 'example.co.uk', 'domain'],
      ['2001:db8::1', null, 'ipv6'],
    ]);
    expect(i.attachments.items[0]).toMatchObject({
      extension: 'iso',
      isArchive: false,
      filename: 'Setup.ISO',
    });
    expect(i.sender).toMatchObject({
      authenticated: { address: 'cfo@corp.example' },
      trusted: false,
      departments: [DEPT.finance],
    });
  });
  it('risk: null removes the risk rows; parse failures carry none', () => {
    expect(buildSyntheticInput({ risk: null }).risk).toEqual({ rev0: null, rev1: null });
    expect(buildSyntheticInput({ trigger: 'parse_failed' })).toMatchObject({
      risk: { rev0: null, rev1: null },
      scan: { outcome: 'not_scanned' },
      round: { scanId: null },
    });
  });
  it('refuses unknown keys and invalid values', () => {
    expect(syntheticFactsSchema.safeParse({ subject: 'x' }).success).toBe(false);
    expect(() => buildSyntheticInput({ urls: [{ host: 'bad host' }] })).toThrow(PolicyInputError);
    expect(() => buildSyntheticInput({ direction: 'sideways' } as never)).toThrow(PolicyInputError);
  });
});
