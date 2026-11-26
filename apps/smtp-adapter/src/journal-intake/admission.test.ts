import { describe, expect, it } from 'vitest';
import { EgressIndexUnavailableError } from '../provider-relay/egress-index.service';
import {
  type AdmissionFacts,
  addressUsable,
  admitIntakeRecipient,
  intakeEntitled,
} from './admission';
import {
  snapshotFixture,
  TEST_GOOGLE_CLIENT,
  TEST_M365_CLIENT,
  TEST_ONPREM_CLIENT,
  testEgressIndex,
} from './testing/snapshots';

const NOW = new Date('2026-11-20T10:00:00.000Z');
const FP = 'ab'.repeat(32);

const facts = (overrides: Partial<AdmissionFacts> = {}): AdmissionFacts => ({
  now: NOW,
  clientAddress: TEST_M365_CLIENT,
  tls: true,
  certFingerprints: [],
  egress: testEgressIndex,
  ...overrides,
});

describe('intakeEntitled (8.6 D1, step API-1 D6)', () => {
  it.each([
    // [journalIntake, archivingFeature, archivingEnabled, apiDetect, expected]
    [true, true, true, false, true],
    [true, false, false, true, true],
    [true, true, false, true, true],
    [true, false, true, true, true],
    [true, true, false, false, false],
    [true, false, true, false, false],
    [true, false, false, false, false],
    [false, true, true, true, false],
    [false, true, true, false, false],
  ] as const)('intake=%s archiving=%s enabled=%s api=%s → %s', (j, a, e, api, expected) => {
    expect(
      intakeEntitled({
        journalIntakeFeature: j,
        archivingFeature: a,
        archivingEnabled: e,
        apiDetect: api,
      }),
    ).toBe(expected);
  });

  it('admits an API-only organization (no archiving) through the whole decision', () => {
    const snapshot = snapshotFixture('microsoft_365_journal', {
      organization: { archivingFeature: false, archivingEnabled: false, apiDetect: true },
    });
    expect(admitIntakeRecipient(snapshot, facts())).toEqual({
      ok: true,
      network: 'provider_egress',
      clientCertMatched: false,
    });
  });
});

describe('admitIntakeRecipient (D2.2 steps 1-4)', () => {
  it('admits a Microsoft 365 source from its provider egress range', () => {
    expect(admitIntakeRecipient(snapshotFixture('microsoft_365_journal'), facts())).toEqual({
      ok: true,
      network: 'provider_egress',
      clientCertMatched: false,
    });
  });

  it('admits a Google source only from Google egress', () => {
    const snapshot = snapshotFixture('google_workspace_copy');
    expect(admitIntakeRecipient(snapshot, facts({ clientAddress: TEST_GOOGLE_CLIENT })).ok).toBe(
      true,
    );
    expect(admitIntakeRecipient(snapshot, facts())).toMatchObject({
      ok: false,
      refusal: 'network',
      counter: 'refused_network',
    });
  });

  it('admits an on-premises source from its networks, never from a provider range', () => {
    const snapshot = snapshotFixture('exchange_onprem_journal', {
      source: { networks: ['203.0.113.0/24', '198.51.100.0/24'] },
    });
    expect(admitIntakeRecipient(snapshot, facts({ clientAddress: TEST_ONPREM_CLIENT }))).toEqual({
      ok: true,
      network: 'source_networks',
      clientCertMatched: false,
    });
    // 198.51.100.70 is inside the source networks but is Microsoft 365 egress.
    expect(admitIntakeRecipient(snapshot, facts())).toMatchObject({
      ok: false,
      refusal: 'network',
      code: 'refused_provider_range',
    });
    expect(admitIntakeRecipient(snapshot, facts({ clientAddress: '192.0.2.1' }))).toMatchObject({
      ok: false,
      refusal: 'network',
      code: 'refused_network',
    });
    expect(
      admitIntakeRecipient(snapshot, facts({ clientAddress: `::ffff:${TEST_ONPREM_CLIENT}` })).ok,
    ).toBe(true);
  });

  const cases: [
    string,
    Parameters<typeof snapshotFixture>[1],
    Partial<AdmissionFacts>,
    string,
    string | null,
    string | null,
  ][] = [
    [
      'disabled source',
      { source: { status: 'disabled' } },
      {},
      'unknown_address',
      'refused_address',
      'refused_disabled',
    ],
    [
      'previous address after the overlap',
      { source: { matchedPrevious: true, previousValidUntil: '2026-11-20T09:59:59.000Z' } },
      {},
      'unknown_address',
      'refused_address',
      'refused_address_expired',
    ],
    [
      'previous address without an end of overlap',
      { source: { matchedPrevious: true, previousValidUntil: null } },
      {},
      'unknown_address',
      'refused_address',
      'refused_address_expired',
    ],
    [
      'organization suspended',
      { organization: { active: false } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'no archiving feature',
      { organization: { archivingFeature: false } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'no journal_intake feature',
      { organization: { journalIntakeFeature: false } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'archiving disabled',
      { organization: { archivingEnabled: false } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'API mode active but no journal_intake feature (step API-1 D6)',
      { organization: { journalIntakeFeature: false, apiDetect: true } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'neither archiving nor API mode (step API-1 D6)',
      { organization: { archivingFeature: false, archivingEnabled: false, apiDetect: false } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_unavailable',
    ],
    [
      'paused source',
      { source: { status: 'paused' } },
      {},
      'unavailable',
      'refused_unavailable',
      'refused_paused',
    ],
    [
      'connection disabled',
      { connection: { status: 'disabled' } },
      {},
      'network',
      'refused_network',
      'refused_connection',
    ],
    [
      'connection unbound',
      { connection: { bound: false } },
      {},
      'network',
      'refused_network',
      'refused_connection',
    ],
    [
      'connection of another organization',
      { connection: { organizationId: '8' } },
      {},
      'network',
      'refused_network',
      'refused_connection',
    ],
    [
      'connection of another provider',
      { connection: { provider: 'google_workspace' } },
      {},
      'network',
      'refused_network',
      'refused_connection',
    ],
    ['no connection', { connection: null }, {}, 'network', 'refused_network', 'refused_connection'],
    [
      'client outside the egress set',
      {},
      { clientAddress: '192.0.2.1' },
      'network',
      'refused_network',
      'refused_network',
    ],
    [
      'unparsable client address',
      {},
      { clientAddress: 'unknown' },
      'network',
      'refused_network',
      'refused_network',
    ],
    [
      'client certificate required, none presented',
      { source: { clientCertFingerprints: [FP] } },
      {},
      'network',
      'refused_network',
      'refused_client_cert',
    ],
    [
      'client certificate configuration unreadable',
      { source: { clientCertInvalid: true } },
      {},
      'network',
      'refused_network',
      'refused_client_cert',
    ],
    ['TLS required, plaintext session', {}, { tls: false }, 'tls', 'refused_tls', 'refused_tls'],
  ];
  it.each(cases)('%s', (_name, overrides, factOverrides, refusal, counter, code) => {
    expect(
      admitIntakeRecipient(
        snapshotFixture('microsoft_365_journal', overrides),
        facts(factOverrides),
      ),
    ).toEqual({ ok: false, refusal, counter, code });
  });

  it('unknown address: no source, no per-source counter', () => {
    expect(admitIntakeRecipient(null, facts())).toEqual({
      ok: false,
      refusal: 'unknown_address',
      counter: null,
      code: null,
    });
  });

  it('previous address within the overlap, pending verification, plaintext allowed', () => {
    const snapshot = snapshotFixture('microsoft_365_journal', {
      source: {
        status: 'pending_verification',
        matchedPrevious: true,
        previousValidUntil: '2026-11-21T00:00:00.000Z',
        requireTls: false,
      },
    });
    expect(addressUsable(snapshot, NOW)).toBe(true);
    expect(admitIntakeRecipient(snapshot, facts({ tls: false })).ok).toBe(true);
  });

  it('matches a configured client certificate', () => {
    const snapshot = snapshotFixture('smtp_bcc', { source: { clientCertFingerprints: [FP] } });
    expect(
      admitIntakeRecipient(
        snapshot,
        facts({ clientAddress: TEST_ONPREM_CLIENT, certFingerprints: ['cd'.repeat(32), FP] }),
      ),
    ).toEqual({ ok: true, network: 'source_networks', clientCertMatched: true });
  });

  it('on-premises source without usable networks is refused', () => {
    for (const source of [{ networks: [] }, { networksInvalid: true }]) {
      expect(
        admitIntakeRecipient(
          snapshotFixture('smtp_bcc', { source }),
          facts({ clientAddress: TEST_ONPREM_CLIENT }),
        ),
      ).toMatchObject({ ok: false, refusal: 'network' });
    }
  });

  it('an unloaded egress index throws (the caller tempfails)', () => {
    const egress = () => {
      throw new EgressIndexUnavailableError();
    };
    expect(() =>
      admitIntakeRecipient(snapshotFixture('microsoft_365_journal'), facts({ egress })),
    ).toThrow(EgressIndexUnavailableError);
    expect(() =>
      admitIntakeRecipient(
        snapshotFixture('smtp_bcc'),
        facts({ egress, clientAddress: TEST_ONPREM_CLIENT }),
      ),
    ).toThrow(EgressIndexUnavailableError);
  });
});
