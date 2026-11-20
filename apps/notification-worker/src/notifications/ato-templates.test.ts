import { describe, expect, it } from 'vitest';
import {
  accountLabel,
  atoNoticeMessageId,
  type AtoNoticeFacts,
  maskAddress,
  reasonTitle,
  renderAtoNotice,
} from './ato-templates';

const INCIDENT = '0193a1b2-1c2d-7e3f-8a4b-5c6d7e8f9012';
const ACTION = '0193a1b2-2d3e-7f40-8b5c-6d7e8f901234';
const common = {
  organizationName: 'Acme Corp',
  organizationSlug: 'acme-corp',
  audience: 'tenant' as const,
  portalUrl: 'https://portal.example',
  window: { from: '2026-11-18T08:00:00.000Z', to: '2026-11-18T08:15:00.000Z' },
  eventsInWindow: 3,
  suppressedBefore: 1,
};
const incidentFacts = (over: Partial<AtoNoticeFacts> = {}): AtoNoticeFacts =>
  ({
    ...common,
    kind: 'incident_alert',
    incident: {
      publicId: INCIDENT,
      severity: 'critical',
      status: 'open',
      detectedAt: '2026-11-18T08:01:00.000Z',
      titleCode: 'ato.geo.impossible_travel',
      reasonCodes: ['ato.geo.impossible_travel', 'ato.access.new_asn'],
    },
    account: { kind: 'mailbox', address: 'jane.doe@acme.example', name: null },
    ...over,
  }) as AtoNoticeFacts;

/** Nothing that looks like a full address, an IPv4/IPv6 address or a token. */
const UNSAFE = [
  /jane\.doe@/,
  /\b\d{1,3}(?:\.\d{1,3}){3}\b/,
  /[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3,}/i,
  /token|password|subject:/i,
];

describe('ATO notice templates (step 8.4 D16)', () => {
  it('masks mailboxes per ADR-0062 and never shows an address-like or URL-like name', () => {
    expect(maskAddress('jane.doe@Acme.Example')).toBe('j***@acme.example');
    expect(maskAddress('not-an-address')).toBe('***');
    expect(maskAddress('@acme.example')).toBe('***');
    expect(accountLabel({ kind: 'mailbox', address: 'ana@x.example', name: null })).toBe(
      'mailbox a***@x.example',
    );
    expect(accountLabel({ kind: 'smtp_connector', address: null, name: 'Branch relay' })).toBe(
      'SMTP connector Branch relay',
    );
    expect(accountLabel({ kind: 'smtp_connector', address: null, name: 'evil@x.example' })).toBe(
      'SMTP connector (name not shown)',
    );
    expect(accountLabel({ kind: 'gateway_user', address: null, name: 'https://x.example/t' })).toBe(
      'portal user (name not shown)',
    );
    expect(accountLabel(null)).toBe('unknown account');
  });

  it('derives reason titles from rule codes', () => {
    expect(reasonTitle('ato.geo.impossible_travel')).toBe('Geo: impossible travel');
    expect(reasonTitle('ato.correlation.login_then_outbound')).toBe(
      'Correlation: login then outbound',
    );
    expect(reasonTitle('Not A Code')).toBe('unknown reason');
  });

  it('renders the tenant incident alert with severity, masked account, reasons and the link', () => {
    const notice = renderAtoNotice(incidentFacts());
    expect(notice.subject).toBe('[Email Gateway] Account takeover incident (critical)');
    expect(notice.text).toContain('Account takeover notice for Acme Corp.');
    expect(notice.text).toContain(`Incident: ${INCIDENT}`);
    expect(notice.text).toContain('Severity: critical');
    expect(notice.text).toContain('Account: mailbox j***@acme.example');
    expect(notice.text).toContain('Top reasons: Geo: impossible travel; Access: new asn');
    expect(notice.text).toContain(`https://portal.example/incidents/${INCIDENT}`);
    for (const pattern of UNSAFE) expect(notice.text).not.toMatch(pattern);
  });

  it('the platform SOC notice carries the slug, incident id, severity and link only', () => {
    const notice = renderAtoNotice(incidentFacts({ audience: 'platform_soc' }));
    expect(notice.subject).toContain('Platform SOC');
    expect(notice.subject).toContain('acme-corp');
    expect(notice.text).toContain('Organization: acme-corp');
    expect(notice.text).toContain(`Incident: ${INCIDENT}`);
    expect(notice.text).toContain('Severity: critical');
    expect(notice.text).not.toContain('Acme Corp');
    expect(notice.text).not.toContain('***@');
    expect(notice.text).not.toContain('impossible');
  });

  it('renders approvals, failures and digests with their links and no unsafe data', () => {
    const approval = renderAtoNotice({
      ...common,
      kind: 'approval_requested',
      action: {
        publicId: ACTION,
        actionType: 'restrict_smtp_sending',
        impact: 'high',
        status: 'pending_approval',
        approvalExpiresAt: '2026-11-19T08:00:00.000Z',
      },
      account: { kind: 'mailbox', address: 'jane.doe@acme.example', name: null },
      incidentPublicId: INCIDENT,
    });
    expect(approval.subject).toBe('[Email Gateway] Account takeover response awaits approval');
    expect(approval.text).toContain('Response: restrict smtp sending');
    expect(approval.text).toContain('https://portal.example/ato/responses?status=pending_approval');
    const failed = renderAtoNotice({
      ...common,
      kind: 'response_failed',
      action: {
        publicId: ACTION,
        actionType: 'revoke_sessions',
        status: 'failed',
        provider: 'fake',
        resultCode: 'provider_error',
      },
      account: null,
      incidentPublicId: null,
    });
    expect(failed.text).toContain('Result: provider_error');
    expect(failed.text).toContain('https://portal.example/ato/responses');
    const digest = renderAtoNotice({
      ...common,
      kind: 'digest',
      period: 'weekly',
      counts: {
        openedBySeverity: { low: 0, medium: 1, high: 2, critical: 1 },
        resolvedByResolution: { remediated: 1, false_positive: 2 },
        falsePositives: 2,
        activeCritical: 1,
        pendingApprovals: 3,
        restrictedAccounts: 1,
        topRuleCodes: [{ code: 'ato.auth.bruteforce', count: 7 }],
      },
    });
    expect(digest.text).toContain('Period: weekly digest');
    expect(digest.text).toContain('critical 1, high 2, medium 1, low 0');
    expect(digest.text).toContain('remediated 1, false positive 2');
    expect(digest.text).toContain('Auth: bruteforce (7)');
    for (const text of [approval.text, failed.text, digest.text]) {
      for (const pattern of UNSAFE) expect(text).not.toMatch(pattern);
    }
  });

  it('strips control characters and header injection from tenant text', () => {
    const notice = renderAtoNotice(incidentFacts({ organizationName: 'Acme\r\nBcc: x' }));
    expect(notice.text.split('\n')[0]).toBe('Account takeover notice for AcmeBcc: x.');
  });

  it('builds a deterministic Message-ID per event and audience', () => {
    expect(atoNoticeMessageId('e1', 'platform_soc', 'Gateway <no-reply@gw.example>')).toBe(
      '<ato-notice.e1.platform-soc@gw.example>',
    );
  });
});

describe('provider_unhealthy (step 8.5 D11)', () => {
  const INTEGRATION = '0193a1b2-3e4f-7a50-9c6d-7e8f90123456';
  const facts = (over: Record<string, unknown> = {}): AtoNoticeFacts => ({
    ...common,
    kind: 'provider_unhealthy',
    integration: {
      publicId: INTEGRATION,
      provider: 'google_workspace',
      displayName: 'Fabrikam IT (example)',
      status: 'active',
      healthStatus: 'unhealthy',
      failingStreams: ['forwarding_changes'],
      missingPermissions: ['https://www.googleapis.com/auth/gmail.settings.basic'],
      ...over,
    },
  });

  it('names the provider, integration, failing streams, missing permissions and the link', () => {
    const notice = renderAtoNotice(facts());
    expect(notice.subject).toBe('[Email Gateway] Account takeover identity provider unhealthy');
    expect(notice.text).toContain('Identity provider: Google Workspace');
    expect(notice.text).toContain('Integration: Fabrikam IT (example)');
    expect(notice.text).toContain('Failing streams: forwarding changes');
    expect(notice.text).toContain('gmail.settings.basic');
    expect(notice.text).toContain(`/ato/providers/${INTEGRATION}`);
    expect(notice.text).toContain('Mail flow is not affected');
  });

  it('never shows an address-like display name, odd permission text or a tenant id', () => {
    const notice = renderAtoNotice(
      facts({
        displayName: 'admin@fabrikam-it.example',
        missingPermissions: ['<script>', 'User.Read.All'],
        failingStreams: ['Sign Ins!'],
      }),
    );
    expect(notice.text).not.toContain('admin@fabrikam-it.example');
    expect(notice.text).not.toContain('<script>');
    expect(notice.text).toContain('User.Read.All');
    expect(notice.text).toContain('Failing streams: none reported');
    expect(notice.text).not.toMatch(/Cexample|tenant id/i);
  });
});
