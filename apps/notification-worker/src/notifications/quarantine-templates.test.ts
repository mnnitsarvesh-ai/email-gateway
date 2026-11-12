import { describe, expect, it } from 'vitest';
import {
  quarantineNoticeMessageId,
  reasonText,
  renderAdminAlert,
  renderApprovalDecided,
  renderApprovalRequested,
  renderReleaseBlocked,
  renderSenderRejected,
  renderUserDigest,
} from './quarantine-templates';

const PORTAL = 'https://portal.example';
/** CR, C0/C1 controls (except tab) and the bidi embeddings/overrides U+202A–U+202E. */
// eslint-disable-next-line no-control-regex -- the assertion is that these characters never appear
const FORBIDDEN = new RegExp('[\\r\\u0000-\\u0008\\u000b-\\u001f\\u007f\\u202a-\\u202e]');
const hostile = 'Evil\r\nBcc: victim@x.example <script>alert(1)</script>‮';

/** Every rendered notice of the six kinds, with hostile database text where text exists. */
function all() {
  return [
    renderUserDigest({
      organizationName: hostile,
      portalUrl: PORTAL,
      window: { from: '2026-11-11T08:00:00.000Z', to: '2026-11-12T08:00:00.000Z' },
      includeSubject: true,
      more: 0,
      entries: [
        {
          entryId: '0190f0f0-0000-7000-8000-000000000001',
          receivedAt: '2026-11-11T09:00:00.000Z',
          sender: hostile,
          subject: hostile,
          reason: 'phishing',
          expiresAt: '2026-12-11T09:00:00.000Z',
        },
      ],
    }),
    renderApprovalRequested({
      organizationName: hostile,
      portalUrl: PORTAL,
      requests: [
        { id: 'r1', kind: 'policy_review', reason: 'dlp', approvalReasons: ['review', hostile] },
      ],
    }),
    renderApprovalDecided({
      organizationName: hostile,
      portalUrl: PORTAL,
      decision: 'expired',
      requestIds: ['r1'],
    }),
    renderReleaseBlocked({
      organizationName: hostile,
      portalUrl: PORTAL,
      releaseId: 'rel-1',
      outcomes: { rescan_required: 2 },
    }),
    renderAdminAlert({
      organizationName: hostile,
      portalUrl: PORTAL,
      hardBlocks: 1,
      pendingApprovals: 0,
      window: null,
    }),
    renderSenderRejected({
      organizationName: hostile,
      messagePublicId: 'm1',
      receivedAt: '2026-11-11T09:00:00.000Z',
      internetMessageId: hostile,
    }),
  ];
}

describe('quarantine notice templates (step 5.3 Q20 privacy)', () => {
  it('never carry control characters, header injections, markup or bidi overrides', () => {
    for (const notice of all()) {
      expect(notice.subject).not.toMatch(/[\r\n]/);
      for (const line of notice.text.split('\n')) {
        expect(line).not.toMatch(FORBIDDEN);
        expect(line).not.toMatch(/^Bcc:/i);
        expect(line).not.toMatch(/[<>]/);
      }
    }
  });

  it('link only to the portal (login required), never to a message URL', () => {
    for (const notice of all()) {
      const urls = notice.text.match(/https?:\/\/\S+/g) ?? [];
      for (const url of urls) expect(url.startsWith(`${PORTAL}/quarantine`)).toBe(true);
    }
  });

  it('a digest subject is cut to 78 characters', () => {
    const digest = renderUserDigest({
      organizationName: 'Acme',
      portalUrl: PORTAL,
      window: { from: 'a', to: 'b' },
      includeSubject: true,
      more: 0,
      entries: [
        {
          entryId: 'e',
          receivedAt: 'r',
          sender: 's@x.example',
          subject: 'x'.repeat(200),
          reason: 'spam',
          expiresAt: 'z',
        },
      ],
    });
    const line = digest.text.split('\n').find((l) => l.includes('Subject: '))!;
    expect(line.trim()).toBe(`Subject: ${'x'.repeat(78)}`);
  });

  it('names reasons in words and builds a deterministic Message-ID', () => {
    expect(reasonText('engine_unavailable')).toBe('a scanner was unavailable');
    expect(reasonText('unknown_reason')).toBe('held');
    expect(quarantineNoticeMessageId('e1', 'Gateway <no-reply@GW.example>')).toBe(
      '<quarantine-notice.e1@gw.example>',
    );
    expect(quarantineNoticeMessageId('e1', 'noreply@gw.example')).toBe(
      '<quarantine-notice.e1@gw.example>',
    );
  });
});
