import { EventTypes, eventTypesBoundTo } from '@email-gateway/event-contracts';
import { describe, expect, it } from 'vitest';
import { sourceEvent } from '../worker.test-support';
import {
  FANOUT_SOURCE_TYPES,
  failingRecords,
  projectCandidates,
  rejectionOf,
  threatVerdictOf,
} from './projection';

const summary = (eventType: string, overrides: Record<string, unknown> = {}) =>
  projectCandidates(sourceEvent(eventType, overrides)).map((c) => ({
    type: c.type,
    subKey: c.subKey,
    severity: c.severity,
    alert: c.alert,
  }));

describe('projection rules (W3)', () => {
  it('covers exactly the eight event types bound to email.webhooks', () => {
    expect([...FANOUT_SOURCE_TYPES].sort()).toEqual(
      [...eventTypesBoundTo('email.webhooks')].sort(),
    );
  });

  it('mail.message.received.v1 → email.received (info, direction from the payload)', () => {
    const [c] = projectCandidates(
      sourceEvent(EventTypes.MessageReceived, { direction: 'outbound' }),
    );
    expect(c).toMatchObject({
      type: 'email.received',
      subKey: '',
      severity: 'info',
      direction: 'outbound',
      alert: null,
    });
  });

  it.each([
    ['clean', 'info'],
    ['unknown', 'info'],
    ['spam', 'low'],
    ['suspicious', 'medium'],
    ['malicious', 'high'],
  ])('mail.message.scanned.v1 (%s) → email.scanned (%s) with the verdict', (verdict, severity) => {
    const [c] = projectCandidates(sourceEvent(EventTypes.MessageScanned, { verdict }));
    expect(c).toMatchObject({ type: 'email.scanned', severity, verdict });
  });

  it('a phishing quarantine decision → threat (high, alert), policy.triggered, quarantined', () => {
    expect(summary(EventTypes.PolicyDecided)).toEqual([
      { type: 'email.threat.detected', subKey: 'scan', severity: 'high', alert: 'threat_detected' },
      { type: 'email.policy.triggered', subKey: '', severity: 'medium', alert: null },
      { type: 'email.quarantined', subKey: 'policy', severity: 'medium', alert: null },
    ]);
  });

  it.each([
    ['spam', 'spam', 'low'],
    ['bulk', 'spam', 'low'],
    ['suspicious', 'suspicious', 'medium'],
    ['phishing', 'malicious', 'high'],
    ['malware', 'malicious', 'high'],
    ['bec', 'malicious', 'high'],
  ])('finalVerdict %s is a %s threat (%s)', (finalVerdict, verdict, severity) => {
    const [c] = projectCandidates(sourceEvent(EventTypes.PolicyDecided, { finalVerdict }));
    expect(c).toMatchObject({ type: 'email.threat.detected', verdict, severity });
    expect(threatVerdictOf(finalVerdict)).toBe(verdict);
  });

  it.each(['clean', 'unknown', 'dlp_violation'])('finalVerdict %s is no threat', (finalVerdict) => {
    const types = projectCandidates(
      sourceEvent(EventTypes.PolicyDecided, {
        finalVerdict,
        disposition: 'allow',
        finalAction: 'deliver',
      }),
    ).map((c) => c.type);
    expect(types).toEqual(['email.policy.triggered']);
  });

  it('an allow decision is a low policy.triggered and never a policy quarantine', () => {
    const out = summary(EventTypes.PolicyDecided, {
      finalVerdict: 'clean',
      disposition: 'allow',
      finalAction: 'tag',
    });
    expect(out).toEqual([
      { type: 'email.policy.triggered', subKey: '', severity: 'low', alert: null },
    ]);
  });

  it('a split decision (partial) may have policy entries', () => {
    const types = projectCandidates(
      sourceEvent(EventTypes.PolicyDecided, {
        finalVerdict: 'clean',
        disposition: 'allow',
        finalAction: 'partial',
      }),
    ).map((c) => c.type);
    expect(types).toContain('email.quarantined');
  });

  it.each([
    ['delivered', 'delivery_complete', 'email.delivered', ''],
    ['delivered', 'delivery_partial', 'email.delivered', ''],
    ['rejected', 'policy_reject', 'email.rejected', ''],
    ['rejected', 'policy_discard', 'email.rejected', ''],
    ['rejected', 'quarantine_deleted', 'email.rejected', ''],
    ['rejected', 'review_rejected', 'email.rejected', ''],
    ['rejected', 'delivery_failed', 'email.rejected', ''],
    ['quarantined', 'manual_quarantine', 'email.quarantined', 'manual'],
  ])('state %s (%s) → %s', (state, reasonCode, type, subKey) => {
    const [c] = projectCandidates(
      sourceEvent(EventTypes.MessageStateChanged, { state, reasonCode }),
    );
    expect(c).toMatchObject({ type, subKey });
  });

  it.each([
    ['quarantined', 'policy_quarantine'],
    ['scanning', 'scan_started'],
    ['approved', 'quarantine_release'],
    ['rejected', 'deadline_exceeded'],
  ])('state %s (%s) yields nothing', (state, reasonCode) => {
    expect(
      projectCandidates(sourceEvent(EventTypes.MessageStateChanged, { state, reasonCode })),
    ).toEqual([]);
  });

  it('an approval → email.released only for quarantine releases (subKey = deliverySeq)', () => {
    expect(projectCandidates(sourceEvent(EventTypes.DeliveryApproved))).toEqual([]);
    const [c] = projectCandidates(
      sourceEvent(EventTypes.DeliveryApproved, { source: 'quarantine_release', deliverySeq: 2 }),
    );
    expect(c).toMatchObject({ type: 'email.released', subKey: '2', severity: 'info' });
    expect(c?.direction).toBeUndefined();
  });

  it('a malicious sandbox completion → threat (sandbox:<partIndex>, high, alert)', () => {
    const [c] = projectCandidates(sourceEvent(EventTypes.AttachmentSandboxCompleted));
    expect(c).toMatchObject({
      type: 'email.threat.detected',
      subKey: 'sandbox:3',
      severity: 'high',
      verdict: 'malicious',
      alert: 'threat_detected',
    });
    for (const verdict of ['clean', 'suspicious', null]) {
      expect(
        projectCandidates(sourceEvent(EventTypes.AttachmentSandboxCompleted, { verdict })),
      ).toEqual([]);
    }
  });

  it('domain status: verified → domain.verified, failed → dns.failed (verification), else nothing', () => {
    expect(summary(EventTypes.DomainStatusChanged, { status: 'verified' })).toEqual([
      { type: 'domain.verified', subKey: '', severity: 'info', alert: null },
    ]);
    expect(summary(EventTypes.DomainStatusChanged, { status: 'failed' })).toEqual([
      {
        type: 'domain.dns.failed',
        subKey: 'verification',
        severity: 'medium',
        alert: 'domain_dns_failed',
      },
    ]);
    expect(summary(EventTypes.DomainStatusChanged, { status: 'active' })).toEqual([]);
  });

  it('record changes: only valid → invalid/missing fail; critical purposes are high', () => {
    expect(summary(EventTypes.DomainDnsRecordsChanged)).toEqual([
      {
        type: 'domain.dns.failed',
        subKey: 'records',
        severity: 'high',
        alert: 'domain_dns_failed',
      },
    ]);
    const mtaSts = [
      { recordKey: 'mta', purpose: 'mta_sts', previousStatus: 'valid', status: 'missing' },
    ];
    expect(summary(EventTypes.DomainDnsRecordsChanged, { changes: mtaSts })[0]?.severity).toBe(
      'medium',
    );
    const recovering = [
      { recordKey: 'spf', purpose: 'spf', previousStatus: 'invalid', status: 'valid' },
      { recordKey: 'mx', purpose: 'mx', previousStatus: 'pending', status: 'invalid' },
    ];
    expect(summary(EventTypes.DomainDnsRecordsChanged, { changes: recovering })).toEqual([]);
    expect(
      failingRecords({
        domainId: '1',
        domainPublicId: 'x',
        name: 'a',
        domainStatus: 'active',
        checkedAt: '',
        changes: [...recovering, ...mtaSts] as never,
      }),
    ).toHaveLength(1);
  });

  it('ignores event types it does not project', () => {
    expect(projectCandidates(sourceEvent(EventTypes.MessageParsed))).toEqual([]);
  });

  it('maps rejection reasons to their stage', () => {
    expect(rejectionOf('policy_reject')).toEqual({ reason: 'policy_reject', stage: 'policy' });
    expect(rejectionOf('review_rejected')).toEqual({
      reason: 'review_rejected',
      stage: 'quarantine',
    });
    expect(rejectionOf('delivery_failed')).toEqual({
      reason: 'delivery_failed',
      stage: 'delivery',
    });
    expect(rejectionOf('something_else')).toBeNull();
  });
});
