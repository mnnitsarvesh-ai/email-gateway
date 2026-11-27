import { describe, expect, it } from 'vitest';
import {
  escapeHtml,
  type FeedbackVerdict,
  renderReportFeedback,
  reportFeedbackMessageId,
} from './report-feedback-templates';

/** Reporter feedback templates (step API-3 C12): fixed copy, escaping, no leakage. */
const REPORT = '0192f0c4-eeee-7fff-8aaa-0000000000d1';
const AT = new Date('2026-11-26T08:15:30.000Z');

describe('renderReportFeedback', () => {
  it('received: subject, text and HTML carry the reference and date only', () => {
    const r = renderReportFeedback({
      kind: 'received',
      organizationName: 'Acme',
      reportPublicId: REPORT,
      reportedAt: AT,
    });
    expect(r.subject).toBe('[Email Gateway] We received your report');
    expect(r.text).toContain(`Report reference: ${REPORT}`);
    expect(r.text).toContain('Reported: 2026-11-26 08:15 UTC');
    expect(r.html.startsWith('<!doctype html>')).toBe(true);
    expect(r.html).toContain(`Report reference: ${REPORT}<br>Reported: 2026-11-26 08:15 UTC`);
  });

  it.each(['malicious', 'phishing_simulation', 'spam', 'clean', 'inconclusive'] as const)(
    'resolved %s: a distinct fixed subject and headline',
    (verdict: FeedbackVerdict) => {
      const r = renderReportFeedback({
        kind: 'resolved',
        verdict,
        organizationName: 'Acme',
        reportPublicId: REPORT,
        reportedAt: AT,
      });
      expect(r.subject.startsWith('[Email Gateway] ')).toBe(true);
      expect(r.text).toContain(`Report reference: ${REPORT}`);
      expect(r.html).toContain('<strong>');
    },
  );

  it('every kind and verdict has its own subject', () => {
    const subjects = new Set<string>();
    subjects.add(
      renderReportFeedback({
        kind: 'received',
        organizationName: 'A',
        reportPublicId: REPORT,
        reportedAt: AT,
      }).subject,
    );
    for (const verdict of [
      'malicious',
      'phishing_simulation',
      'spam',
      'clean',
      'inconclusive',
    ] as const) {
      subjects.add(
        renderReportFeedback({
          kind: 'resolved',
          verdict,
          organizationName: 'A',
          reportPublicId: REPORT,
          reportedAt: AT,
        }).subject,
      );
    }
    expect(subjects.size).toBe(6);
  });

  it('escapes and sanitizes the organization name; hides address- or URL-like names', () => {
    const r = renderReportFeedback({
      kind: 'received',
      organizationName: 'Acme & "Sons" <script>alert(1)</script>\r\nBcc: x',
      reportPublicId: REPORT,
      reportedAt: AT,
    });
    expect(r.html).not.toContain('<script>');
    expect(r.html).toContain('Acme &amp; &quot;Sons&quot;');
    expect(r.text).not.toContain('\r');
    expect(r.text.split('\n').some((line) => line.startsWith('Bcc:'))).toBe(false);
    for (const name of ['admin@acme.example', 'https://evil.example/x']) {
      const hidden = renderReportFeedback({
        kind: 'received',
        organizationName: name,
        reportPublicId: REPORT,
        reportedAt: AT,
      });
      expect(hidden.text).toContain('security team of your organization.');
      expect(hidden.text).not.toContain(name);
      expect(hidden.html).not.toContain(name);
    }
  });

  it('a malformed public id or date is neutral', () => {
    const r = renderReportFeedback({
      kind: 'received',
      organizationName: 'Acme',
      reportPublicId: 'x<y>',
      reportedAt: new Date('invalid'),
    });
    expect(r.text).toContain('Report reference: unknown');
    expect(r.text).toContain('Reported: unknown');
    expect(r.html).not.toContain('x<y>');
  });

  it('never carries a URL or an address (the reported message is not repeated)', () => {
    for (const verdict of ['malicious', 'clean'] as const) {
      const r = renderReportFeedback({
        kind: 'resolved',
        verdict,
        organizationName: 'Acme',
        reportPublicId: REPORT,
        reportedAt: AT,
      });
      for (const part of [r.subject, r.text, r.html]) {
        expect(part).not.toContain('@');
        expect(part).not.toContain('://');
      }
    }
  });
});

describe('escapeHtml and reportFeedbackMessageId', () => {
  it('escapes the five HTML metacharacters', () => {
    expect(escapeHtml(`<a href="x">'&'</a>`)).toBe(
      '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;',
    );
  });

  it('builds the Message-ID from the event id and the From domain', () => {
    expect(reportFeedbackMessageId('e1', 'Gateway <no-reply@GW.example>')).toBe(
      '<report-feedback.e1@gw.example>',
    );
    expect(reportFeedbackMessageId('e1', 'bare')).toBe('<report-feedback.e1@bare>');
  });
});
