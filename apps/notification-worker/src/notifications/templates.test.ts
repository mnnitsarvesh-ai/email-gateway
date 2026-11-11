import { describe, expect, it } from 'vitest';
import {
  noticeMessageId,
  type NoticeFacts,
  renderPolicyAlert,
  renderSenderNonDelivery,
  safeText,
} from './templates';

const facts = (over: Partial<NoticeFacts> = {}): NoticeFacts => ({
  organizationName: 'Acme Corp',
  messagePublicId: '0190f0f0-0000-7000-8000-0000000000aa',
  receivedAt: '2026-11-11T10:00:00.000Z',
  direction: 'outbound',
  disposition: 'reject',
  severity: 'critical',
  decisive: {
    source: 'tenant_rule',
    policyId: '0190f0f0-0000-7000-8000-00000000bbbb',
    versionNo: 3,
    ruleId: 'block-cards',
  },
  policyName: 'Card numbers',
  portalUrl: 'https://portal.example',
  internetMessageId: '<abc@mail.example>',
  recipientCount: 2,
  ...over,
});

describe('policy notice templates (P25)', () => {
  it('renders the alert with ids, enums, the policy name, rule id and a portal link only', () => {
    const notice = renderPolicyAlert(facts());
    expect(notice.subject).toBe('[Email Gateway] Policy alert (critical): message rejected');
    expect(notice.text).toContain('Message: 0190f0f0-0000-7000-8000-0000000000aa');
    expect(notice.text).toContain('Decided by: policy "Card numbers", rule block-cards');
    expect(notice.text).toContain(
      'https://portal.example/messages/0190f0f0-0000-7000-8000-0000000000aa',
    );
    expect(notice.text).not.toContain('@');
    expect(
      renderPolicyAlert(
        facts({ decisive: { source: 'floor', policyId: null, versionNo: null, ruleId: null } }),
      ).text,
    ).toContain('platform strictness floor');
  });

  it('renders the sender notice with the Internet-Message-ID and recipient count only', () => {
    const notice = renderSenderNonDelivery(facts());
    expect(notice.subject).toBe('[Email Gateway] Your message was not delivered');
    expect(notice.text).toContain('Message-ID: abc@mail.example');
    expect(notice.text).toContain('Recipients: 2');
    expect(notice.text).not.toMatch(/subject|attachment/i);
  });

  it('strips control characters, line breaks and angle brackets from database text', () => {
    const evil = facts({
      organizationName: 'Acme\r\nBcc: victim@evil.example',
      policyName: 'P\u0000<script>',
      internetMessageId: '<x@y>\r\nX-Injected: 1',
    });
    for (const notice of [renderPolicyAlert(evil), renderSenderNonDelivery(evil)]) {
      expect(notice.text).not.toMatch(/\r|\nBcc:|\nX-Injected/);
      expect(notice.text).not.toContain('<');
    }
    expect(safeText('a'.repeat(500))).toHaveLength(128);
  });

  it('builds the deterministic Message-ID from the event id and the From domain', () => {
    expect(noticeMessageId('e1', 'Gateway <No-Reply@Gateway.Example>')).toBe(
      '<policy-notice.e1@gateway.example>',
    );
    expect(noticeMessageId('e2', 'no-reply@gw.example')).toBe('<policy-notice.e2@gw.example>');
  });
});
