import { describe, expect, it } from 'vitest';
import {
  ACTIVE_RESPONSE_STATUSES,
  ATO_POLICY_PRESET,
  AUTOMATION_GUARD_REASONS,
  automationDecision,
  canTransitionResponse,
  COMPLETED_RESPONSE_STATUSES,
  impactFor,
  isTerminalResponseStatus,
  recommendResponses,
  RESPONSE_ACTION_TYPES,
  RESPONSE_CATALOGUE,
  RESPONSE_TRANSITIONS,
  responseDedupeHash,
  supportsRollback,
  type AutomationGuardReason,
  type AutomationInput,
  type Contributor,
  type RecommendationAccount,
} from './responses';
import { RESPONSE_STATUSES, type ResponseStatus } from './taxonomy';

const ACCOUNT = '01890000-0000-7000-8000-000000000001';
const SHA = 'a'.repeat(64);

describe('RESPONSE_CATALOGUE (D13)', () => {
  it('lists the twelve action types with provider, impact and rollback of the table', () => {
    const table: Record<string, [string, string, string]> = {
      alert_tenant_admins: ['gateway', 'low', 'none'],
      notify_soc: ['gateway', 'low', 'none'],
      escalate_investigation: ['gateway', 'low', 'none'],
      restrict_smtp_sending: ['gateway', 'high', 'lift'],
      block_smtp_auth: ['gateway', 'high', 'lift'],
      record_manual_action: ['manual', 'low', 'none'],
      revoke_sessions: ['provider', 'medium', 'none'],
      require_mfa: ['provider', 'medium', 'provider'],
      require_password_reset: ['provider', 'high', 'none'],
      suspend_account: ['provider', 'high', 'provider'],
      remove_forwarding_rule: ['provider', 'medium', 'provider'],
      revoke_oauth_grant: ['provider', 'medium', 'none'],
    };
    expect([...RESPONSE_ACTION_TYPES].sort()).toEqual(Object.keys(table).sort());
    for (const [type, [provider, impact, rollback]] of Object.entries(table)) {
      const e = RESPONSE_CATALOGUE[type as keyof typeof RESPONSE_CATALOGUE];
      expect([e.provider, e.impact, e.rollback], type).toEqual([provider, impact, rollback]);
    }
  });

  it('block_smtp_auth is medium impact for connector + IP and high for the connector', () => {
    expect(impactFor('block_smtp_auth', { scope: 'connector_ip' })).toBe('medium');
    expect(impactFor('block_smtp_auth', { scope: 'connector' })).toBe('high');
    expect(impactFor('restrict_smtp_sending', { scope: 'mailbox' })).toBe('high');
    expect(impactFor('alert_tenant_admins', { scope: 'account' })).toBe('low');
  });

  it('rollback support follows the catalogue', () => {
    expect(supportsRollback('restrict_smtp_sending')).toBe(true);
    expect(supportsRollback('require_mfa')).toBe(true);
    expect(supportsRollback('revoke_sessions')).toBe(false);
    expect(supportsRollback('alert_tenant_admins')).toBe(false);
  });
});

describe('RESPONSE_TRANSITIONS (D13)', () => {
  const allowed: Record<ResponseStatus, ResponseStatus[]> = {
    pending_approval: ['approved', 'rejected', 'expired', 'cancelled'],
    approved: ['succeeded', 'failed', 'executing', 'unsupported'],
    executing: ['succeeded', 'failed'],
    succeeded: ['rollback_requested'],
    rollback_requested: ['rolled_back', 'rollback_failed'],
    failed: [],
    rejected: [],
    cancelled: [],
    expired: [],
    unsupported: [],
    rolled_back: [],
    rollback_failed: [],
    attested: [],
  };

  it('has exactly the edges of the design', () => {
    expect(Object.keys(RESPONSE_TRANSITIONS).sort()).toEqual([...RESPONSE_STATUSES].sort());
    for (const s of RESPONSE_STATUSES) {
      expect([...RESPONSE_TRANSITIONS[s]].sort(), s).toEqual([...allowed[s]].sort());
    }
  });

  for (const from of RESPONSE_STATUSES) {
    for (const to of RESPONSE_STATUSES) {
      const expected = allowed[from].includes(to);
      it(`${from} -> ${to} is ${expected ? 'allowed' : 'refused'} (provider action with rollback)`, () => {
        expect(canTransitionResponse(from, to, 'require_mfa')).toBe(expected);
      });
    }
  }

  it('executing exists only for provider actions; rollback only for types that support it', () => {
    expect(canTransitionResponse('approved', 'executing', 'restrict_smtp_sending')).toBe(false);
    expect(canTransitionResponse('approved', 'executing', 'revoke_sessions')).toBe(true);
    expect(canTransitionResponse('succeeded', 'rollback_requested', 'revoke_sessions')).toBe(false);
    expect(canTransitionResponse('succeeded', 'rollback_requested', 'block_smtp_auth')).toBe(true);
  });

  it('active statuses are exactly the non-terminal ones of the generated active marker', () => {
    expect([...ACTIVE_RESPONSE_STATUSES].sort()).toEqual(
      ['approved', 'executing', 'pending_approval', 'rollback_requested'].sort(),
    );
    for (const s of RESPONSE_STATUSES) {
      const terminal = isTerminalResponseStatus(s);
      expect(terminal, s).toBe(!ACTIVE_RESPONSE_STATUSES.includes(s) && s !== 'succeeded');
    }
  });

  it('completed statuses emit ato.response.completed.v1 (never pending or approved)', () => {
    expect(COMPLETED_RESPONSE_STATUSES).not.toContain('pending_approval');
    expect(COMPLETED_RESPONSE_STATUSES).not.toContain('approved');
    expect(COMPLETED_RESPONSE_STATUSES).not.toContain('executing');
    expect(COMPLETED_RESPONSE_STATUSES).toContain('attested');
    expect(COMPLETED_RESPONSE_STATUSES).toContain('rolled_back');
  });
});

describe('responseDedupeHash', () => {
  const target = { scope: 'mailbox' as const, accountPublicId: ACCOUNT, mailboxSha256: SHA };

  it('is stable, independent of key order and of null/undefined members', () => {
    const a = responseDedupeHash(5n, 'restrict_smtp_sending', target);
    const b = responseDedupeHash('5', 'restrict_smtp_sending', {
      mailboxSha256: SHA,
      accountPublicId: ACCOUNT,
      scope: 'mailbox',
      cidr: null,
      connectorId: undefined,
    });
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(b).toBe(a);
  });

  it('differs per incident, type and target', () => {
    const a = responseDedupeHash(5n, 'restrict_smtp_sending', target);
    expect(responseDedupeHash(6n, 'restrict_smtp_sending', target)).not.toBe(a);
    expect(responseDedupeHash(null, 'restrict_smtp_sending', target)).not.toBe(a);
    expect(responseDedupeHash(5n, 'block_smtp_auth', target)).not.toBe(a);
    expect(
      responseDedupeHash(5n, 'restrict_smtp_sending', { ...target, mailboxSha256: 'b'.repeat(64) }),
    ).not.toBe(a);
  });
});

const mailbox = (level: RecommendationAccount['level'] = 'high'): RecommendationAccount => ({
  kind: 'mailbox',
  publicId: ACCOUNT,
  level,
  connectorId: null,
  mailboxSha256: SHA,
});
const c = (
  code: string,
  category: Contributor['category'],
  strength: Contributor['strength'] = 'moderate',
  ip: string | null = null,
): Contributor => ({ code, category, strength, ip });
const none = { providerActions: new Set<string>() };

describe('recommendResponses (D13)', () => {
  it('mailbox with outbound abuse: restrict sending, provider actions, the policy hint, alert', () => {
    const recs = recommendResponses(
      mailbox(),
      [c('ato.content.phishing_sent', 'outbound_content', 'strong')],
      none,
      false,
    );
    expect(recs.map((r) => [r.actionType, r.availability])).toEqual([
      ['restrict_smtp_sending', 'available'],
      ['revoke_sessions', 'requires_provider'],
      ['require_password_reset', 'requires_provider'],
      ['policy_hold_outbound', 'policy'],
      ['alert_tenant_admins', 'available'],
    ]);
    expect(recs[0]!.target).toEqual({
      scope: 'mailbox',
      accountPublicId: ACCOUNT,
      mailboxSha256: SHA,
    });
    expect(recs[3]).toMatchObject({ preset: ATO_POLICY_PRESET, target: null, impact: null });
  });

  it('no policy hint when the tenant already has an active ato.* rule', () => {
    const recs = recommendResponses(
      mailbox(),
      [c('ato.outbound.volume_spike', 'outbound_behaviour')],
      none,
      true,
    );
    expect(recs.map((r) => r.actionType)).not.toContain('policy_hold_outbound');
  });

  it('provider actions are available when the adapter supports them; forwarding removal on M1/M2', () => {
    const recs = recommendResponses(
      mailbox(),
      [
        c('ato.geo.impossible_travel', 'geography'),
        c('ato.mailbox.external_forwarding', 'mailbox_configuration', 'strong'),
      ],
      { providerActions: new Set(['revoke_sessions', 'remove_forwarding_rule']) },
      false,
    );
    const byType = Object.fromEntries(recs.map((r) => [r.actionType, r]));
    expect(byType.revoke_sessions!.availability).toBe('available');
    expect(byType.require_password_reset!.availability).toBe('requires_provider');
    expect(byType.remove_forwarding_rule).toMatchObject({
      availability: 'available',
      reason: 'ato.mailbox.external_forwarding',
    });
    expect(byType.restrict_smtp_sending).toBeUndefined();
    expect(byType.policy_hold_outbound).toBeUndefined();
  });

  it('connector with an authentication anomaly: block auth for connector + IP and rotate the secret', () => {
    const recs = recommendResponses(
      {
        kind: 'smtp_connector',
        publicId: ACCOUNT,
        level: 'high',
        connectorId: '42',
        mailboxSha256: null,
      },
      [c('ato.ti.attack_source_success', 'threat_intel', 'strong', '198.51.100.7')],
      none,
      false,
    );
    expect(recs.map((r) => r.actionType)).toEqual([
      'block_smtp_auth',
      'record_manual_action',
      'alert_tenant_admins',
    ]);
    expect(recs[0]).toMatchObject({
      impact: 'medium',
      target: { scope: 'connector_ip', connectorId: '42', cidr: '198.51.100.7/32' },
    });
    expect(recs[1]).toMatchObject({ manual: 'rotate_connector_secret', availability: 'manual' });
  });

  it('connector with outbound abuse: restrict sending and block auth on the connector; IPv6 /128', () => {
    const recs = recommendResponses(
      {
        kind: 'smtp_connector',
        publicId: ACCOUNT,
        level: 'critical',
        connectorId: '42',
        mailboxSha256: null,
      },
      [
        c('ato.access.new_ip_prefix', 'access_context', 'weak', '2001:db8::5'),
        c('ato.outbound.volume_spike', 'outbound_behaviour'),
      ],
      none,
      false,
    );
    expect(recs.map((r) => [r.actionType, r.target?.scope ?? null])).toEqual([
      ['block_smtp_auth', 'connector_ip'],
      ['restrict_smtp_sending', 'connector'],
      ['block_smtp_auth', 'connector'],
      ['record_manual_action', 'account'],
      ['alert_tenant_admins', 'account'],
      ['escalate_investigation', 'account'],
      ['notify_soc', 'account'],
    ]);
    expect(recs[0]!.target!.cidr).toBe('2001:db8::5/128');
  });

  it('gateway user: manual revoke sessions, reset MFA, disable; critical adds escalation and SOC', () => {
    const recs = recommendResponses(
      {
        kind: 'gateway_user',
        publicId: ACCOUNT,
        level: 'critical',
        connectorId: null,
        mailboxSha256: null,
      },
      [c('ato.account.refresh_token_reuse', 'account_change', 'strong')],
      none,
      false,
    );
    expect(recs.map((r) => r.manual ?? r.actionType)).toEqual([
      'revoke_portal_sessions',
      'reset_portal_mfa',
      'disable_portal_user',
      'alert_tenant_admins',
      'escalate_investigation',
      'notify_soc',
    ]);
  });

  it('always recommends alerting the tenant admins', () => {
    const recs = recommendResponses(mailbox('medium'), [], none, false);
    expect(recs.map((r) => r.actionType)).toEqual(['alert_tenant_admins']);
  });
});

describe('automationDecision (D13): every guard reason', () => {
  const ok: AutomationInput = {
    impact: 'high',
    tenantMode: 'enforce',
    automation: { mode: 'automatic', minLevel: 'critical' },
    level: 'critical',
    contributors: [
      { category: 'outbound_content', strength: 'strong' },
      { category: 'geography', strength: 'moderate' },
    ],
    account: { protected: false, benignOverride: false, platformOrganization: false },
    automaticLastHour: 0,
    tenantMaxPerHour: 10,
    platformMaxPerHour: 10,
    globallyEnabled: true,
  };

  it('all conditions hold: automatic', () => {
    expect(automationDecision(ok)).toEqual({ automatic: true });
  });

  it('low-impact actions are automatic in automatic mode even in monitor mode', () => {
    expect(
      automationDecision({ ...ok, impact: 'low', tenantMode: 'monitor', globallyEnabled: false }),
    ).toEqual({ automatic: true });
  });

  it('a correlation signal counts as strong', () => {
    expect(
      automationDecision({
        ...ok,
        contributors: [
          { category: 'correlation', strength: 'moderate' },
          { category: 'outbound_behaviour', strength: 'moderate' },
        ],
      }),
    ).toEqual({ automatic: true });
  });

  const cases: Array<[AutomationGuardReason, Partial<AutomationInput>]> = [
    ['automation_off', { automation: { mode: 'off', minLevel: 'critical' } }],
    ['recommend_only', { automation: { mode: 'recommend', minLevel: 'critical' } }],
    ['globally_disabled', { globallyEnabled: false }],
    ['tenant_monitor_mode', { tenantMode: 'monitor' }],
    ['level_below_minimum', { level: 'high' }],
    [
      'no_strong_signal',
      {
        contributors: [
          { category: 'geography', strength: 'moderate' },
          { category: 'access_context', strength: 'weak' },
        ],
      },
    ],
    [
      'single_category',
      {
        contributors: [
          { category: 'outbound_content', strength: 'strong' },
          { category: 'outbound_content', strength: 'moderate' },
        ],
      },
    ],
    ['account_protected', { account: { ...ok.account, protected: true } }],
    ['benign_override', { account: { ...ok.account, benignOverride: true } }],
    ['platform_organization', { account: { ...ok.account, platformOrganization: true } }],
    ['tenant_hourly_cap', { automaticLastHour: 10 }],
    ['platform_hourly_cap', { automaticLastHour: 5, platformMaxPerHour: 5 }],
  ];

  it('covers every guard reason', () => {
    expect(cases.map(([r]) => r).sort()).toEqual([...AUTOMATION_GUARD_REASONS].sort());
  });

  for (const [reason, patch] of cases) {
    it(`guard ${reason}`, () => {
      expect(automationDecision({ ...ok, ...patch })).toEqual({ automatic: false, reason });
    });
  }

  it('minLevel high admits a high account', () => {
    expect(
      automationDecision({
        ...ok,
        level: 'high',
        automation: { mode: 'automatic', minLevel: 'high' },
      }),
    ).toEqual({ automatic: true });
  });
});
