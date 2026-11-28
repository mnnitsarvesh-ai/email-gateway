import { describe, expect, it } from 'vitest';
import {
  COVERAGE_GAP_CODES,
  type DomainCoverageFacts,
  domainCoverage,
  feedIntakeOf,
  journalIntakeOf,
  mailboxAccessOf,
  PROTECTION_CAPABILITY_CODES,
  PROTECTION_MODE_CAPABILITIES,
} from './protection-coverage';

function facts(patch: Partial<DomainCoverageFacts> = {}): DomainCoverageFacts {
  return {
    domainId: '0192f3a0-2222-7000-8000-000000000002',
    name: 'contoso.example',
    status: 'active',
    effectiveMode: 'api',
    inherited: false,
    inboundEnabled: false,
    outboundEnabled: false,
    mxPointsToGateway: false,
    connection: {
      id: '0192f3a0-3333-7000-8000-000000000003',
      provider: 'microsoft_365',
      health: 'healthy',
      disabled: false,
      mailboxGrantStatus: 'active',
      journalSources: [{ status: 'active', verified: true }],
      feedsEnabled: false,
    },
    scopeKind: 'all',
    mailboxes: { total: 10, inScope: 10, covered: 10, gap: 0, feedsActive: 0 },
    remediation: { source: 'organization', mode: 'enforce', detectOnlyUntil: null },
    policyEvaluation: true,
    lastCopyAt: new Date('2026-11-27T09:00:00.000Z'),
    ...patch,
  };
}

describe('protection by mode (step API-4 A10)', () => {
  it('the capability matrix covers the twelve documented codes once, each with three cells', () => {
    expect(PROTECTION_MODE_CAPABILITIES.map((c) => c.code)).toEqual([
      ...PROTECTION_CAPABILITY_CODES,
    ]);
    const byCode = new Map(PROTECTION_MODE_CAPABILITIES.map((c) => [c.code, c]));
    expect(byCode.get('pre_delivery_blocking')).toMatchObject({ inline: 'yes', api: 'no' });
    expect(byCode.get('retroactive_clawback')).toMatchObject({ inline: 'no', api: 'yes' });
    expect(byCode.get('outbound_dlp_enforce')).toMatchObject({ api: 'no', hybrid: 'yes' });
    expect(byCode.get('outbound_dlp_detect')).toMatchObject({ api: 'yes', noteCode: null });
    for (const c of PROTECTION_MODE_CAPABILITIES) {
      if (c.inline !== 'yes' || c.api !== 'yes' || c.hybrid !== 'yes') {
        expect(c.noteCode, c.code).not.toBeNull();
      }
    }
  });

  it('a fully protected api domain has no gaps and no inline block', () => {
    const view = domainCoverage(facts());
    expect(view.gaps).toEqual([]);
    expect(view.inline.applies).toBe(false);
    expect(view.api).toMatchObject({
      connection: { mailboxAccess: 'active', health: 'healthy' },
      intake: { journal: 'verified', feeds: 'off' },
      mailboxes: { inScope: 10, covered: 10, gap: 0, total: 10 },
      remediation: { source: 'organization', mode: 'enforce', detectOnlyUntil: null },
      lastCopyAt: '2026-11-27T09:00:00.000Z',
    });
  });

  it('inline gaps: MX not at the gateway (or never observed) and not active', () => {
    const inline = domainCoverage(
      facts({ effectiveMode: 'inline', status: 'verified', mxPointsToGateway: null }),
    );
    expect(inline.api).toBeNull();
    expect(inline.gaps).toEqual(['inline_mx_not_at_gateway', 'inline_not_active']);
    expect(
      domainCoverage(facts({ effectiveMode: 'inline', mxPointsToGateway: true })).gaps,
    ).toEqual([]);
  });

  it('every api gap code, and hybrid reports both sides', () => {
    const view = domainCoverage(
      facts({
        effectiveMode: 'api',
        mxPointsToGateway: true,
        connection: null,
        mailboxes: { total: null, inScope: 3, covered: 1, gap: 2, feedsActive: 0 },
        remediation: { source: 'domain', mode: 'detect_only', detectOnlyUntil: new Date(0) },
        policyEvaluation: false,
      }),
    );
    expect(view.gaps).toEqual([
      'api_no_connection',
      'api_no_mailbox_access',
      'api_no_intake',
      'api_coverage_gaps',
      'api_mx_points_to_gateway',
      'api_detect_only',
      'api_policy_evaluation_off',
    ]);
    const hybrid = domainCoverage(
      facts({ effectiveMode: 'hybrid', mxPointsToGateway: true, status: 'active' }),
    );
    expect(hybrid.inline.applies).toBe(true);
    expect(hybrid.api).not.toBeNull();
    // MX at the gateway is expected for hybrid.
    expect(hybrid.gaps).toEqual([]);
    const all = new Set([
      ...view.gaps,
      ...domainCoverage(facts({ effectiveMode: 'inline', status: 'verified' })).gaps,
    ]);
    expect(COVERAGE_GAP_CODES.filter((c) => !all.has(c))).toEqual([]);
  });

  it('intake and access helpers', () => {
    expect(mailboxAccessOf('active')).toBe('active');
    expect(mailboxAccessOf('revoked')).toBe('revoked');
    expect(mailboxAccessOf('pending_consent')).toBe('missing');
    expect(mailboxAccessOf(null)).toBe('missing');
    expect(journalIntakeOf([{ status: 'disabled', verified: true }])).toBe('missing');
    expect(journalIntakeOf([{ status: 'pending_verification', verified: false }])).toBe('pending');
    expect(journalIntakeOf([{ status: 'paused', verified: true }])).toBe('verified');
    expect(feedIntakeOf(false, 10, 10)).toBe('off');
    expect(feedIntakeOf(true, 9, 10)).toBe('active');
    expect(feedIntakeOf(true, 8, 10)).toBe('partial');
    expect(feedIntakeOf(true, 0, 0)).toBe('partial');
  });

  it('a disabled connection is a missing connection; feeds count as intake', () => {
    const c = facts().connection!;
    const view = domainCoverage(
      facts({
        connection: { ...c, disabled: true, journalSources: [], feedsEnabled: true },
        mailboxes: { total: 10, inScope: 10, covered: 10, gap: 0, feedsActive: 10 },
      }),
    );
    expect(view.gaps).toEqual(['api_no_connection']);
    expect(view.api?.intake).toEqual({ journal: 'missing', feeds: 'active' });
  });
});
