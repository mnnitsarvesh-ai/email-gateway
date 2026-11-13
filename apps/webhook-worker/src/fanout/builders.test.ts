import { EventTypes } from '@email-gateway/event-contracts';
import { buildEnvelope, eventSeverity } from '@email-gateway/webhooks';
import { describe, expect, it, vi } from 'vitest';
import {
  DOMAIN_PUBLIC_ID,
  fakeFacts,
  messageFacts,
  ORG_PUBLIC_ID,
  sourceEvent,
} from '../worker.test-support';
import { buildPublicEvents, type PublicEvent } from './builders';
import {
  actionTypesOf,
  domainOf,
  matchedRulesOf,
  reasonCodes,
  safeInternetMessageId,
  snakeCodeOrNull,
} from './facts';
import { projectCandidates } from './projection';

async function build(
  eventType: string,
  overrides: Record<string, unknown> = {},
  facts = fakeFacts(),
): Promise<PublicEvent[]> {
  const event = sourceEvent(eventType, overrides);
  return buildPublicEvents(event, projectCandidates(event), facts);
}

/** Every built event must be a valid, guarded envelope (strict schema + payload guard). */
function envelopeOf(pe: PublicEvent) {
  return buildEnvelope({
    type: pe.type,
    occurredAt: '2026-11-01T10:15:32.000Z',
    organizationPublicId: ORG_PUBLIC_ID,
    sourceEventId: '01890a5d-ac96-774b-bcce-b302099a8f01',
    subKey: pe.subKey,
    data: pe.data as never,
  });
}

describe('public event builders (W3, §5)', () => {
  it('email.received carries the §5.1 message and no content', async () => {
    const [pe] = await build(EventTypes.MessageReceived);
    const built = envelopeOf(pe!);
    expect(built.envelope.data).toEqual({
      message: {
        id: messageFacts().publicId,
        receivedAt: '2026-11-01T10:15:30.123Z',
        direction: 'inbound',
        domainId: DOMAIN_PUBLIC_ID,
        internetMessageId: '<abc@partner.example>',
        senderDomain: 'partner.example',
        headerFromDomain: 'partner.example',
        recipientCount: 2,
        recipientDomains: ['corp.example'],
        sizeBytes: 2048,
        attachmentCount: 1,
      },
    });
    expect(built.json).not.toContain('sender@example.com');
    expect(built.json).not.toContain('org/');
    expect(pe!.matchable).toEqual({
      type: 'email.received',
      severity: 'info',
      direction: 'inbound',
      domainPublicId: DOMAIN_PUBLIC_ID,
    });
    expect(pe!.message?.messageId).toBe(9001n);
    expect(pe!.domainId).toBe(77n);
  });

  it('email.scanned keeps engines (name, outcome) and reason codes', async () => {
    const [pe] = await build(EventTypes.MessageScanned);
    const data = envelopeOf(pe!).envelope.data as { scan: Record<string, unknown> };
    expect(data.scan).toEqual({
      lifecycleRound: 0,
      kind: 'initial',
      outcome: 'scanned',
      verdict: 'spam',
      engines: [{ engine: 'rspamd', outcome: 'spam' }],
      reasonCodes: ['spam.score', 'reputation.ip_listed', 'auth.spf_fail'],
      completedAt: '2026-11-01T10:15:31.456Z',
    });
    expect(pe!.matchable.verdict).toBe('spam');
    expect(pe!.severity).toBe('low');
  });

  it('a decision builds threat (scan reason codes), policy.triggered and policy quarantine', async () => {
    const facts = fakeFacts();
    const events = await build(EventTypes.PolicyDecided, {}, facts);
    expect(events.map((e) => e.type)).toEqual([
      'email.threat.detected',
      'email.policy.triggered',
      'email.quarantined',
    ]);
    const [threat, policy, quarantined] = events.map(
      (e) => envelopeOf(e).envelope.data,
    ) as unknown as [
      { detection: Record<string, unknown> },
      { policy: Record<string, unknown> },
      { quarantine: Record<string, unknown> },
    ];
    expect(threat.detection).toEqual({
      stage: 'scan',
      verdict: 'malicious',
      riskScore: 720,
      reasonCodes: ['spam.score', 'phishing.known_bad_url'],
      lifecycleRound: 0,
      finalAction: 'quarantine',
      attachment: null,
    });
    expect(policy.policy).toMatchObject({
      disposition: 'quarantine',
      decisionSource: 'tenant_rule',
      decisive: { versionNo: 3, ruleId: 'quarantine-malware-phishing' },
      matchedRules: [{ versionNo: 3, ruleId: 'quarantine-malware-phishing' }],
      actions: ['ARCHIVE', 'ALERT'],
    });
    expect(quarantined.quarantine).toEqual({
      origin: 'policy',
      lifecycleRound: 0,
      entryCount: 2,
      kinds: { quarantine: 1, review: 1 },
      reasons: ['phishing', 'policy'],
      entryIds: ['01890a5d-ac96-774b-bcce-b302099a80a1', '01890a5d-ac96-774b-bcce-b302099a80a2'],
      earliestExpiresAt: '2026-11-20T10:00:00.000Z',
    });
    // The message is read once for the three events.
    expect(facts.calls.filter((c) => c === 'message')).toHaveLength(1);
  });

  it('a parse-failure decision has no scan reason codes to read', async () => {
    const facts = fakeFacts();
    const [threat] = await build(
      EventTypes.PolicyDecided,
      { trigger: 'parse_failed', scanId: null },
      facts,
    );
    expect(
      (threat!.data as { detection: { reasonCodes: string[] } }).detection.reasonCodes,
    ).toEqual([]);
    expect(facts.calls).not.toContain('scanReasonCodes');
  });

  it('no matched tenant rule → no policy.triggered; no entries → no quarantined', async () => {
    const events = await build(
      EventTypes.PolicyDecided,
      {},
      fakeFacts({
        executionLog: () => Promise.resolve({ matchedRules: [], actions: [] }),
        quarantineEntries: () => Promise.resolve([]),
      }),
    );
    expect(events.map((e) => e.type)).toEqual(['email.threat.detected']);
  });

  it('a platform decision names no decisive rule', async () => {
    const events = await build(EventTypes.PolicyDecided, {
      decisive: { source: 'platform_default', policyId: null, versionNo: null, ruleId: null },
    });
    const policy = events.find((e) => e.type === 'email.policy.triggered')!;
    expect(
      (envelopeOf(policy).envelope.data as { policy: { decisive: unknown } }).policy.decisive,
    ).toBeNull();
  });

  it('email.delivered: outcome from the reason code, recipient counts', async () => {
    const [pe] = await build(EventTypes.MessageStateChanged, { reasonCode: 'delivery_partial' });
    expect((envelopeOf(pe!).envelope.data as { delivery: unknown }).delivery).toEqual({
      outcome: 'partial',
      lifecycleRound: 0,
      recipients: {
        delivered: 1,
        failed: 0,
        bounced: 0,
        expired: 1,
        suppressed: 0,
        quarantined: 0,
        discarded: 0,
        other: 0,
      },
      completedAt: '2026-11-01T10:20:01.000Z',
    });
  });

  it('email.rejected: reason and stage', async () => {
    const [pe] = await build(EventTypes.MessageStateChanged, {
      state: 'rejected',
      reasonCode: 'quarantine_deleted',
    });
    expect((envelopeOf(pe!).envelope.data as { rejection: unknown }).rejection).toEqual({
      reason: 'quarantine_deleted',
      stage: 'quarantine',
      lifecycleRound: 0,
      rejectedAt: '2026-11-01T10:20:01.000Z',
    });
  });

  it('manual quarantine reads the manual entries of the round', async () => {
    let origin = '';
    const [pe] = await build(
      EventTypes.MessageStateChanged,
      { state: 'quarantined', reasonCode: 'manual_quarantine', lifecycleRound: 2 },
      fakeFacts({
        quarantineEntries: (_k, round, o) => {
          origin = `${o}:${round}`;
          return Promise.resolve([
            {
              publicId: '01890a5d-ac96-774b-bcce-b302099a80a9',
              kind: 'quarantine',
              reason: 'manual',
              expiresAt: new Date('2026-12-01T00:00:00.000Z'),
            },
          ]);
        },
      }),
    );
    expect(origin).toBe('manual:2');
    expect(envelopeOf(pe!).envelope.data).toMatchObject({
      quarantine: { origin: 'manual', lifecycleRound: 2, entryCount: 1, reasons: ['manual'] },
    });
  });

  it('email.released from the release log; none without one (optional row)', async () => {
    const overrides = { source: 'quarantine_release', deliverySeq: 1 };
    const [pe] = await build(EventTypes.DeliveryApproved, overrides);
    expect((envelopeOf(pe!).envelope.data as { release: unknown }).release).toEqual({
      releaseId: '01890a5d-ac96-774b-bcce-b302099a80a0',
      mode: 'approved',
      entryIds: ['01890a5d-ac96-774b-bcce-b302099a80a1'],
      recipientCount: 2,
      deliverySeq: 1,
      approvedAt: '2026-11-01T10:16:00.000Z',
    });
    expect(
      await build(
        EventTypes.DeliveryApproved,
        overrides,
        fakeFacts({ release: () => Promise.resolve(null) }),
      ),
    ).toEqual([]);
  });

  it('email.released for the first release of a fully quarantined message (deliverySeq 0)', async () => {
    const release = vi.fn(() =>
      Promise.resolve({
        releaseId: '01890a5d-ac96-774b-bcce-b302099a80a0',
        mode: 'operator' as const,
        entryIds: ['01890a5d-ac96-774b-bcce-b302099a80a1'],
      }),
    );
    const [pe] = await build(
      EventTypes.DeliveryApproved,
      { source: 'quarantine_release', deliverySeq: 0 },
      fakeFacts({ release }),
    );
    expect(release).toHaveBeenCalledWith(expect.anything(), 0);
    expect((envelopeOf(pe!).envelope.data as { release: unknown }).release).toMatchObject({
      mode: 'operator',
      deliverySeq: 0,
    });
  });

  it('a sandbox threat names its attachment and no final action', async () => {
    const [pe] = await build(EventTypes.AttachmentSandboxCompleted);
    expect((envelopeOf(pe!).envelope.data as { detection: unknown }).detection).toEqual({
      stage: 'sandbox',
      verdict: 'malicious',
      riskScore: null,
      reasonCodes: ['sandbox.static.script_download_cradle', 'sandbox.static.embedded_urls'],
      lifecycleRound: 0,
      finalAction: null,
      attachment: { partIndex: 3, sha256: 'c'.repeat(64), detectedType: 'seven_zip' },
    });
    expect(pe!.severity).toBe('high');
  });

  it('domain events: verified and the two dns.failed kinds, matched by domain id', async () => {
    const [verified] = await build(EventTypes.DomainStatusChanged, {
      status: 'verified',
      previousStatus: 'pending_verification',
    });
    expect(envelopeOf(verified!).envelope.data).toEqual({
      domain: { id: DOMAIN_PUBLIC_ID, name: 'acme.example', status: 'verified' },
      previousStatus: 'pending_verification',
      verifiedAt: '2026-11-02T09:00:00.000Z',
    });
    expect(verified!.matchable).toEqual({
      type: 'domain.verified',
      severity: 'info',
      domainPublicId: DOMAIN_PUBLIC_ID,
    });
    expect(verified!.domainId).toBe(77n);
    const [failed] = await build(EventTypes.DomainStatusChanged, {
      status: 'failed',
      reason: 'claimed by another organization: free text',
    });
    expect(envelopeOf(failed!).envelope.data).toMatchObject({
      failure: { kind: 'verification_failed', reason: null, records: [] },
    });
    const [expired] = await build(EventTypes.DomainStatusChanged, {
      status: 'failed',
      reason: 'verification_expired',
    });
    expect((expired!.data as { failure: { reason: string } }).failure.reason).toBe(
      'verification_expired',
    );
    const [records] = await build(EventTypes.DomainDnsRecordsChanged);
    const data = envelopeOf(records!).envelope.data as { failure: { records: unknown[] } };
    expect(data.failure.records).toEqual([
      { purpose: 'spf', recordKey: 'spf', previousStatus: 'valid', status: 'invalid' },
      { purpose: 'dmarc', recordKey: 'dmarc', previousStatus: 'valid', status: 'missing' },
    ]);
    expect(records!.severity).toBe(eventSeverity('domain.dns.failed', records!.data as never));
  });

  it('a message of no tenant domain carries domainId null (never matches domainIds)', async () => {
    const [pe] = await build(
      EventTypes.MessageReceived,
      {},
      fakeFacts({
        message: () => Promise.resolve(messageFacts({ domainId: null, domainPublicId: null })),
      }),
    );
    expect(pe!.matchable.domainPublicId).toBeNull();
    expect(pe!.domainId).toBeNull();
    expect(envelopeOf(pe!).envelope.data).toMatchObject({ message: { domainId: null } });
  });
});

describe('fact sanitizers', () => {
  it('domainOf keeps the lower-case domain of an address only', () => {
    expect(domainOf('Alice@Partner.Example')).toBe('partner.example');
    expect(domainOf('"Alice" <alice@mail.partner.example>')).toBe('mail.partner.example');
    expect(domainOf('')).toBeNull();
    expect(domainOf(null)).toBeNull();
    expect(domainOf('no-at-sign')).toBeNull();
    expect(domainOf('x@-bad-.example')).toBeNull();
  });

  it('internetMessageId: controls stripped, too long or guard-refused values dropped', () => {
    expect(safeInternetMessageId(' <a\r\n@b.example> ')).toBe('<a@b.example>');
    expect(safeInternetMessageId('<' + 'a'.repeat(300) + '@x>')).toBeNull();
    expect(safeInternetMessageId('<http://evil.example/x@y>')).toBeNull();
    expect(safeInternetMessageId('<org/42/eml/a@b>')).toBeNull();
    expect(safeInternetMessageId('')).toBeNull();
  });

  it('reason codes, matched rules, action types and snake codes are filtered', () => {
    expect(reasonCodes(['spam.score', 'spam.score', 'Bad Code', 7, 'x'])).toEqual(['spam.score']);
    expect(reasonCodes('nope')).toEqual([]);
    expect(
      matchedRulesOf([
        { policyPublicId: '01890a5d-ac96-774b-bcce-b302099a80aa', versionNo: 1, ruleId: 'r1' },
        { policyPublicId: 'pol-default/1', versionNo: 1, ruleId: 'r2' },
        { policyPublicId: '01890a5d-ac96-774b-bcce-b302099a80aa', versionNo: 0, ruleId: 'r3' },
      ]),
    ).toEqual([{ policyId: '01890a5d-ac96-774b-bcce-b302099a80aa', versionNo: 1, ruleId: 'r1' }]);
    expect(actionTypesOf([{ type: 'TAG' }, { type: 'TAG' }, { type: 'warn' }, {}])).toEqual([
      'TAG',
    ]);
    expect(snakeCodeOrNull('verification_expired')).toBe('verification_expired');
    expect(snakeCodeOrNull('Free text')).toBeNull();
  });
});
