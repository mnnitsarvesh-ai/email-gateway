/**
 * Step 8.4 D16: the projection of the four security incident / account takeover source events
 * into the public types `security.incident.created`, `security.incident.updated`,
 * `ato.account.risk_changed` and `ato.response.completed` — severity mapping from the payload,
 * the data built from the payload (plus the account kind for responses), strict schemas and the
 * payload guard (no address, IP or name ever).
 */
import { EventTypes } from '@email-gateway/event-contracts';
import { assertWebhookPayloadSafe, buildEnvelope } from '@email-gateway/webhooks';
import { describe, expect, it } from 'vitest';
import { fakeFacts, ORG_PUBLIC_ID, sourceEvent } from '../worker.test-support';
import { buildPublicEvents, type PublicEvent } from './builders';
import { projectCandidates } from './projection';

async function build(
  eventType: string,
  overrides: Record<string, unknown> = {},
  facts = fakeFacts(),
): Promise<PublicEvent[]> {
  const event = sourceEvent(eventType, overrides);
  return buildPublicEvents(event, projectCandidates(event), facts);
}

function envelopeOf(pe: PublicEvent) {
  const built = buildEnvelope({
    type: pe.type,
    occurredAt: '2026-11-18T08:01:00.000Z',
    organizationPublicId: ORG_PUBLIC_ID,
    sourceEventId: '01890a5d-ac96-774b-bcce-b302099a8f01',
    subKey: pe.subKey,
    data: pe.data as never,
  });
  assertWebhookPayloadSafe(built.envelope);
  return built;
}

const ADDRESS_OR_IP = /@|\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){3,}/i;

describe('step 8.4 projection (D16)', () => {
  it('security.incident.created.v1 → security.incident.created (severity mapped, no read)', async () => {
    const facts = fakeFacts();
    const [pe, ...rest] = await build(EventTypes.SecurityIncidentCreated, {}, facts);
    expect(rest).toEqual([]);
    expect(facts.calls).toEqual([]);
    const built = envelopeOf(pe!);
    expect(built.envelope.type).toBe('security.incident.created');
    expect(built.envelope.data).toEqual({
      incident: {
        id: expect.any(String) as string,
        category: 'account_takeover',
        status: 'open',
        severity: 'high',
        origin: 'detection',
        detectedAt: '2026-11-18T08:01:00.000Z',
        reasonCodes: ['ato.intel.spraying_success', 'ato.access.new_ip_prefix'],
      },
      subject: { type: 'ato_account', id: expect.any(String) as string },
    });
    expect(pe!.severity).toBe('high');
    expect(pe!.matchable).toEqual({ type: 'security.incident.created', severity: 'high' });
    expect(pe!.message).toBeNull();
    expect(pe!.domainId).toBeNull();
    expect(JSON.stringify(built.envelope.data)).not.toMatch(ADDRESS_OR_IP);
  });

  it.each([
    ['critical', 'high'],
    ['high', 'high'],
    ['medium', 'medium'],
    ['low', 'low'],
  ])('incident severity %s → webhook severity %s', (severity, expected) => {
    const [c] = projectCandidates(sourceEvent(EventTypes.SecurityIncidentCreated, { severity }));
    expect(c).toMatchObject({ type: 'security.incident.created', severity: expected, alert: null });
  });

  it('security.incident.updated.v1 → security.incident.updated with previous and changedFields', async () => {
    const [pe] = await build(EventTypes.SecurityIncidentUpdated);
    const built = envelopeOf(pe!);
    expect(built.envelope.data).toMatchObject({
      incident: { category: 'account_takeover', status: 'investigating', severity: 'high' },
      subject: { type: 'ato_account' },
      previous: { status: 'open', severity: 'high' },
      changedFields: ['status', 'assignee'],
    });
    expect(Object.keys((built.envelope.data as { incident: object }).incident).sort()).toEqual([
      'category',
      'id',
      'severity',
      'status',
    ]);
  });

  it('ato.account.risk.updated.v1 → ato.account.risk_changed (kind and levels, no address)', async () => {
    const [pe] = await build(EventTypes.AtoAccountRiskUpdated, {
      score: 80,
      level: 'critical',
      previousScore: 55,
      previousLevel: 'high',
    });
    const built = envelopeOf(pe!);
    expect(built.envelope.data).toEqual({
      account: { id: expect.any(String) as string, kind: 'mailbox' },
      risk: { score: 80, level: 'critical', previousLevel: 'high' },
    });
    expect(pe!.severity).toBe('high');
    // A payload without a level change (never written, defensive) projects nothing.
    expect(
      projectCandidates(
        sourceEvent(EventTypes.AtoAccountRiskUpdated, { level: 'low', previousLevel: 'low' }),
      ),
    ).toEqual([]);
  });

  it('ato.response.completed.v1 → ato.response.completed with the account kind read', async () => {
    const facts = fakeFacts({ atoAccountKind: () => Promise.resolve('smtp_connector') });
    const [pe] = await build(EventTypes.AtoResponseCompleted, {}, facts);
    expect(facts.calls).toEqual(['atoAccountKind']);
    const built = envelopeOf(pe!);
    expect(built.envelope.data).toEqual({
      response: {
        id: expect.any(String) as string,
        type: 'restrict_smtp_sending',
        status: 'succeeded',
        provider: 'gateway',
        providerStatus: 'applied',
      },
      incident: { id: expect.any(String) as string },
      account: { id: expect.any(String) as string, kind: 'smtp_connector' },
    });
    expect(pe!.severity).toBe('info');
    expect(pe!.subKey).toBe('execute');
  });

  it('a failed response is medium; a rollback has its own sub-key; no incident is null', async () => {
    const [failed] = projectCandidates(
      sourceEvent(EventTypes.AtoResponseCompleted, {
        status: 'failed',
        providerStatus: 'failed',
        resultCode: 'provider_error',
      }),
    );
    expect(failed).toMatchObject({ severity: 'medium' });
    const [pe] = await build(EventTypes.AtoResponseCompleted, {
      phase: 'rollback',
      status: 'rolled_back',
      incidentPublicId: null,
    });
    expect(pe!.subKey).toBe('rollback');
    expect(envelopeOf(pe!).envelope.data).toMatchObject({ incident: null });
  });
});
