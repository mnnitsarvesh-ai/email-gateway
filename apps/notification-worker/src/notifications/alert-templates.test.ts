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
