import { describe, expect, it } from 'vitest';
import {
  type AlertFacts,
  displayName,
  renderSecurityAlert,
  securityAlertMessageId,
} from './alert-templates';

const PORTAL = 'https://portal.example';
const MESSAGE = '0192f0c4-8a11-7c2e-9d3f-1a2b3c4d5e6f';
const DOMAIN = '0192f0c4-7d1e-7b6a-9c55-6f3e2a1d4b11';
const SUBSCRIPTION = '0192f0c4-aaaa-7bbb-8ccc-000000000001';

const common = {
  organizationName: 'Acme Corp',
  severity: 'high' as const,
  window: { from: '2026-11-13T09:00:00.000Z', to: '2026-11-13T10:00:00.000Z' },
  eventsInWindow: 4,
  suppressedBefore: 7,
  portalUrl: PORTAL,
};

const threat: AlertFacts = {
  ...common,
  kind: 'threat_detected',
  threat: {
    verdict: 'malicious',
    stage: 'scan',
    messagePublicId: MESSAGE,
    receivedAt: '2026-11-13T09:14:02.481Z',
  },
};
const dns: AlertFacts = {
  ...common,
  kind: 'domain_dns_failed',
  dns: {
    domainPublicId: DOMAIN,
    domainName: 'acme.example',
    failureKind: 'records_failed',
    reason: null,
    purposes: ['spf', 'dkim', 'spf'],
    stillFailing: ['spf'],
  },
};
const webhook: AlertFacts = {
  ...common,
  severity: 'medium',
  kind: 'webhook_disabled',
  webhook: {
    subscriptionPublicId: SUBSCRIPTION,
    name: 'SIEM\r\nBcc: evil@attacker.example ‮ feed',
    status: 'disabled',
    consecutiveFailures: 50,
    failingSince: '2026-11-12T09:00:00.000Z',
    disabledAt: '2026-11-13T09:00:00.000Z',
    disabledReason: 'sustained_failure',
  },
};

/** What an alert may never contain (§2.0 invariant 1, N4). */
function assertNoForbiddenContent(text: string): void {
  expect(text).not.toContain('@');
  expect(text).not.toContain('whsec_');
  // The only URLs are portal links.
  const urls = text.match(/[a-z][a-z0-9+.-]*:\/\/\S+/gi) ?? [];
  for (const url of urls) expect(url.startsWith(`${PORTAL}/`)).toBe(true);
  expect(urls.length).toBeLessThanOrEqual(1);
}

describe('security alert templates (step 6.2 N4)', () => {
  it('threat_detected: verdict, stage, message id, received time, counts and the message link', () => {
    const notice = renderSecurityAlert(threat);
    expect(notice.subject).toBe('[Email Gateway] Security alert (high): threat detected');
    expect(notice.text).toContain('A security alert was raised for Acme Corp.');
    expect(notice.text).toContain('Severity: high');
    expect(notice.text).toContain(
      'Window: 2026-11-13T09:00:00.000Z to 2026-11-13T10:00:00.000Z (UTC)',
    );
    expect(notice.text).toContain('Events in this window so far: 4');
    expect(notice.text).toContain('Suppressed before this alert: 7');
    expect(notice.text).toContain('Verdict: malicious');
    expect(notice.text).toContain('Detection stage: scan');
    expect(notice.text).toContain(`First message of the window: ${MESSAGE}`);
    expect(notice.text).toContain('Received: 2026-11-13T09:14:02.481Z');
    expect(notice.text).toContain(`Details: ${PORTAL}/messages/${MESSAGE}`);
    assertNoForbiddenContent(notice.subject + notice.text);
  });

  it('domain_dns_failed: the tenant domain, unique failing purposes, still failing, the domain link', () => {
    const notice = renderSecurityAlert(dns);
    expect(notice.subject).toBe('[Email Gateway] Security alert (high): domain DNS check failed');
    expect(notice.text).toContain('Domain: acme.example');
    expect(notice.text).toContain('Failure: DNS records failed');
    expect(notice.text).toContain('Failed records: spf, dkim');
    expect(notice.text).toContain('Still failing now: spf');
    expect(notice.text).not.toContain('Reason:');
    expect(notice.text).toContain(`Details: ${PORTAL}/domains/${DOMAIN}`);
    assertNoForbiddenContent(notice.subject + notice.text);
    const verification = renderSecurityAlert({
      ...dns,
      dns: {
        ...dns.dns,
        failureKind: 'verification_failed',
        reason: 'verification_expired',
        purposes: [],
        stillFailing: [],
      },
    });
    expect(verification.text).toContain('Failure: verification failed');
    expect(verification.text).toContain('Reason: verification_expired');
    expect(verification.text).toContain('Failed records: none');
  });

  it('webhook_disabled: sanitized name ≤ 80, counters, the webhook link; never the endpoint', () => {
    const notice = renderSecurityAlert(webhook);
    expect(notice.subject).toBe(
      '[Email Gateway] Security alert (medium): webhook endpoint disabled',
    );
    // A name with an address is not shown at all (tenant text could carry a mailbox or a token).
    expect(notice.text).toContain(`Subscription: (name not shown) (${SUBSCRIPTION})`);
    expect(notice.text).toContain('Status now: disabled');
    expect(notice.text).toContain('Disabled because: sustained_failure');
    expect(notice.text).toContain('Consecutive failed deliveries: 50');
    expect(notice.text).toContain('Failing since: 2026-11-12T09:00:00.000Z');
    expect(notice.text).toContain(`Details: ${PORTAL}/webhooks/${SUBSCRIPTION}`);
    expect(notice.text).not.toMatch(/^Bcc:/m);
    assertNoForbiddenContent(notice.subject + notice.text);

    const named = renderSecurityAlert({
      ...webhook,
      webhook: {
        ...webhook.webhook,
        name: `SIEM\u202e feed ${'x'.repeat(200)}`,
      },
    });
    const line = named.text.split('\n').find((l) => l.startsWith('Subscription: '))!;
    const name = line.slice('Subscription: '.length, line.lastIndexOf(' ('));
    expect(name.startsWith('SIEM feed')).toBe(true);
    expect([...name].length).toBeLessThanOrEqual(80);
    expect(name).not.toContain('\u202e');
  });

  it('hides names that look like an address or a URL; keeps ordinary names', () => {
    expect(displayName('https://hooks.example/abc?token=secret', 80)).toBe('');
    expect(displayName('ops@acme.example', 80)).toBe('');
    expect(displayName('  Ops <SIEM> feed\n', 80)).toBe('Ops SIEM feed');
    const org = renderSecurityAlert({ ...threat, organizationName: 'https://evil.example/x' });
    expect(org.text).toContain('A security alert was raised for your organization.');
    assertNoForbiddenContent(org.text);
  });

  it('never prints a code or id that is not one (defence in depth)', () => {
    const notice = renderSecurityAlert({
      ...threat,
      eventsInWindow: null,
      threat: {
        verdict: 'Mal<script>',
        stage: 'scan',
        messagePublicId: 'not-a-uuid@x://y',
        receivedAt: 'garbage',
      },
    });
    expect(notice.text).toContain('Events in this window so far: unknown');
    expect(notice.text).toContain('Verdict: unknown');
    expect(notice.text).toContain('First message of the window: unknown');
    expect(notice.text).toContain('Received: unknown');
    expect(notice.text).not.toContain('Details:');
    assertNoForbiddenContent(notice.text);
  });

  it('builds a deterministic Message-ID from the event id and the From domain', () => {
    const id = '0190f0f0-0000-7000-8000-00000000e201';
    expect(securityAlertMessageId(id, 'Email Gateway <no-reply@GW.Example>')).toBe(
      `<security-alert.${id}@gw.example>`,
    );
    expect(securityAlertMessageId(id, 'no-reply@gw.example')).toBe(
      securityAlertMessageId(id, 'Gateway <no-reply@gw.example>'),
    );
    expect(securityAlertMessageId(id, 'nobody')).toBe(`<security-alert.${id}@nobody>`);
  });
});

describe('integration_unhealthy template (step 8.2 D12)', () => {
  const CONNECTION = '0192f0c4-d466-7173-8c84-6f708192a3b4';
  const integration: AlertFacts = {
    ...common,
    kind: 'integration_unhealthy',
    integration: {
      connectionPublicId: CONNECTION,
      name: 'https://evil.example/token',
      provider: 'google_workspace',
      previousStatus: 'warning',
      status: 'critical',
      statusNow: 'critical',
      failingChecks: ['outbound.relay_activity', 'Bad Code', 'ato.unknown_check'],
      changedAt: '2026-11-13T09:30:00.000Z',
    },
  };

  it('names the provider, hides URL-looking names, titles known checks and links the health tab', () => {
    const { subject, text } = renderSecurityAlert(integration);
    expect(subject).toBe(
      '[Email Gateway] Security alert (high): mail platform connection unhealthy',
    );
    expect(text).toContain('Provider: Google Workspace');
    expect(text).toContain(`Connection: (name not shown) (${CONNECTION})`);
    expect(text).not.toContain('evil.example');
    expect(text).toContain(
      '- Outbound mail arrives through the provider relay and passes the tenant proof (outbound.relay_activity)',
    );
    expect(text).toContain('- unknown');
    expect(text).toContain('- ato.unknown_check (ato.unknown_check)');
    expect(text).toContain(`${PORTAL}/integrations/providers/${CONNECTION}?tab=health`);
    expect(text).toContain('Mail flow is not changed automatically');
  });

  it('renders an empty failing-check list and an unknown provider safely', () => {
    const { text } = renderSecurityAlert({
      ...integration,
      integration: {
        ...integration.integration,
        provider: 'other',
        name: 'Contoso',
        failingChecks: [],
      },
    });
    expect(text).toContain('Provider: unknown');
    expect(text).toContain('- none reported');
    expect(text).toContain('Connection: Contoso');
  });
});

describe('journal_intake_silent template (step 8.6 D9)', () => {
  const SOURCE = '0192f0c4-bbbb-7ccc-8ddd-000000000086';
  const intake = (
    over: Partial<Extract<AlertFacts, { kind: 'journal_intake_silent' }>['intake']> = {},
  ) =>
    ({
      ...common,
      severity: 'medium',
      kind: 'journal_intake_silent',
      intake: {
        sourcePublicId: SOURCE,
        name: 'On-prem journal',
        sourceKind: 'exchange_onprem_journal',
        healthNow: 'silent',
        lastAcceptedAt: null,
        silenceAlertMinutes: 60,
        ...over,
      },
    }) as AlertFacts;

  it('names the source and kind, says silent, links the intake page; never an address', () => {
    const notice = renderSecurityAlert(intake());
    expect(notice.subject).toBe(
      '[Email Gateway] Security alert (medium): journal intake source needs attention',
    );
    expect(notice.text).toContain(`Journal intake source: On-prem journal (${SOURCE})`);
    expect(notice.text).toContain('Source kind: On-premises Exchange journaling');
    expect(notice.text).toContain('Problem: silent.');
    expect(notice.text).toContain('Last accepted message: unknown');
    expect(notice.text).toContain(`${PORTAL}/settings/journaling/intake/${SOURCE}`);
  });

  it('hides a display name that looks like an address; unknown kinds and codes are neutral', () => {
    const notice = renderSecurityAlert(
      intake({ name: 'journal-abc@journal.gateway.test', sourceKind: 'other', healthNow: 'X!' }),
    );
    expect(notice.text).toContain('(name not shown)');
    expect(notice.text).toContain('Source kind: unknown');
    expect(notice.text).toContain('Health now: unknown');
    expect(notice.text).not.toContain('journal.gateway.test');
  });
});

describe('api_mode_unhealthy template (step API-1 D11.3)', () => {
  const CONNECTION = '0192f0c4-cccc-7ddd-8eee-0000000000a1';
  const apiMode = (
    over: Partial<Extract<AlertFacts, { kind: 'api_mode_unhealthy' }>['apiMode']> = {},
    severity: 'medium' | 'high' = 'medium',
  ) =>
    ({
      ...common,
      severity,
      kind: 'api_mode_unhealthy',
      apiMode: {
        connectionPublicId: CONNECTION,
        name: 'Contoso M365',
        provider: 'google_workspace',
        healthNow: 'degraded',
        failingChecks: ['mailbox_access.grant', 'throttling.1h'],
        ...over,
      },
    }) as AlertFacts;

  it('names the provider and connection, lists the check titles, links /api-mode; no address', () => {
    const notice = renderSecurityAlert(apiMode());
    expect(notice.subject).toBe(
      '[Email Gateway] Security alert (medium): API-mode protection needs attention',
    );
    expect(notice.text).toContain('Alert: API-mode protection connection degraded or failing');
    expect(notice.text).toContain('Provider: Google Workspace');
    expect(notice.text).toContain(`Connection: Contoso M365 (${CONNECTION})`);
    expect(notice.text).toContain('Problem: degraded.');
    expect(notice.text).toContain('- Mailbox access grant active (mailbox_access.grant)');
    expect(notice.text).toContain('- Provider throttling (last hour) (throttling.1h)');
    expect(notice.text).toContain(`Details: ${PORTAL}/api-mode?connection=${CONNECTION}`);
    expect(notice.text).not.toContain('@');
  });

  it('failing (high) text; unknown provider, codes and names are neutral', () => {
    const notice = renderSecurityAlert(
      apiMode(
        {
          name: 'admin@contoso.example',
          provider: 'other',
          healthNow: 'Bad!',
          failingChecks: ['future.check', 'NOT A CODE', 'connection.active'],
        },
        'high',
      ),
    );
    expect(notice.text).toContain('Problem: failing.');
    expect(notice.text).toContain('Provider: unknown');
    expect(notice.text).toContain('(name not shown)');
    expect(notice.text).toContain('Health now: unknown');
    expect(notice.text).toContain('- future.check (future.check)');
    expect(notice.text).toContain('- unknown');
    expect(notice.text).toContain('- Provider connection active and bound (connection.active)');
    expect(notice.text).not.toContain('contoso.example');
  });

  it('no failing check and a malformed id: no link', () => {
    const notice = renderSecurityAlert(apiMode({ failingChecks: [], connectionPublicId: 'x' }));
    expect(notice.text).toContain('- none reported');
    expect(notice.text).not.toContain('/api-mode');
  });
});

describe('api_mode_unhealthy check titles of step API-3 (C13)', () => {
  it('titles clawback.stalled and reports.backlog', () => {
    const notice = renderSecurityAlert({
      ...common,
      severity: 'medium',
      kind: 'api_mode_unhealthy',
      apiMode: {
        connectionPublicId: '0192f0c4-cccc-7ddd-8eee-0000000000a1',
        name: 'Contoso M365',
        provider: 'microsoft_365',
        healthNow: 'degraded',
        failingChecks: ['clawback.stalled', 'reports.backlog'],
      },
    });
    expect(notice.text).toContain('- Clawback without progress (clawback.stalled)');
    expect(notice.text).toContain('- User reports waiting for triage (reports.backlog)');
  });
});

describe('api_mode_purge_approval template (step API-3 C6)', () => {
  const CLAWBACK = '0192f0c4-dddd-7eee-8fff-0000000000c1';
  const purge = (
    over: Partial<Extract<AlertFacts, { kind: 'api_mode_purge_approval' }>['clawback']> = {},
  ) =>
    ({
      ...common,
      severity: 'medium',
      kind: 'api_mode_purge_approval',
      clawback: {
        clawbackPublicId: CLAWBACK,
        trigger: 'late_verdict',
        status: 'review_required',
        action: null,
        mailboxesEligible: 640,
        targetsEligible: 702,
        approvalStatus: null,
        approvalReasons: ['auto_cap'],
        approvalExpiresAt: null,
        ...over,
      },
    }) as AlertFacts;

  it('trigger, status, counts, reasons, expiry and the purge link; nothing else', () => {
    const notice = renderSecurityAlert(
      purge({
        status: 'pending_approval',
        action: 'hard_delete',
        approvalStatus: 'pending',
        approvalReasons: ['mailbox_threshold', 'hard_delete'],
        approvalExpiresAt: '2026-11-16T09:00:00.000Z',
      }),
    );
    expect(notice.subject).toBe(
      '[Email Gateway] Security alert (medium): clawback approval requested',
    );
    expect(notice.text).toContain('A security alert was raised for Acme Corp.');
    expect(notice.text).toContain(`Clawback: ${CLAWBACK}`);
    expect(notice.text).toContain('Trigger: late verdict (sandbox or URL inspection)');
    expect(notice.text).toContain('Status now: pending_approval');
    expect(notice.text).toContain('Requested action: hard_delete');
    expect(notice.text).toContain('Eligible mailboxes: 640 (702 message copies)');
    expect(notice.text).toContain(
      'Approval needed because: more mailboxes than the approval threshold; permanent deletion requested',
    );
    expect(notice.text).toContain('Approval status: pending');
    expect(notice.text).toContain('Approval expires: 2026-11-16T09:00:00.000Z');
    expect(notice.text).toContain(`Review: ${PORTAL}/api-mode?tab=purge&clawback=${CLAWBACK}`);
    assertNoForbiddenContent(notice.text);
  });

  it('review required without a request; unknown trigger, codes and ids are neutral (no link)', () => {
    const plain = renderSecurityAlert(purge());
    expect(plain.text).toContain(
      'Approval needed because: automatic clawback above the mailbox cap',
    );
    expect(plain.text).toContain('Approval status: not requested');
    expect(plain.text).toContain('Approval expires: unknown');
    expect(plain.text).not.toContain('Requested action');
    const odd = renderSecurityAlert(
      purge({
        clawbackPublicId: 'not-an-id',
        trigger: 'evil\r\nBcc: x@y.example',
        status: 'Bad Status',
        approvalReasons: ['injected <b>', 'auto_cap'],
      }),
    );
    expect(odd.text).toContain('Trigger: unknown');
    expect(odd.text).toContain('Status now: unknown');
    expect(odd.text).toContain('Clawback: unknown');
    expect(odd.text).not.toContain('/api-mode');
    expect(odd.text).not.toContain('injected');
    assertNoForbiddenContent(odd.text);
  });
});

describe('api_mode_report_received template (step API-3 C13)', () => {
  it('report counts and the reports link; no reporter, subject or sender', () => {
    const notice = renderSecurityAlert({
      ...common,
      severity: 'medium',
      kind: 'api_mode_report_received',
      reports: {
        pendingTriage: 12,
        inReview: 2,
        receivedInWindow: 5,
        oldestPendingAt: '2026-11-13T06:00:00.000Z',
      },
    });
    expect(notice.subject).toBe(
      '[Email Gateway] Security alert (medium): reported messages need triage',
    );
    expect(notice.text).toContain('Reports waiting for triage: 12');
    expect(notice.text).toContain('Reports in review: 2');
    expect(notice.text).toContain('Reports received in this window: 5');
    expect(notice.text).toContain('Oldest report waiting since: 2026-11-13T06:00:00.000Z');
    expect(notice.text).toContain(`Review: ${PORTAL}/api-mode?tab=reports`);
    assertNoForbiddenContent(notice.text);
    const none = renderSecurityAlert({
      ...common,
      severity: 'medium',
      kind: 'api_mode_report_received',
      reports: { pendingTriage: 0, inReview: 0, receivedInWindow: 0, oldestPendingAt: null },
    });
    expect(none.text).toContain('Oldest report waiting since: none waiting');
  });
});
