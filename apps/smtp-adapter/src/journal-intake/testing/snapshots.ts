import {
  egressRangesFromCidrs,
  type JournalIntakeKind,
  ProviderEgressIndex,
} from '@email-gateway/mail-routing';
import type { IntakeSourceSnapshot } from '../source-snapshot';

/** TEST-ONLY: synthetic provider egress ranges (documentation and Compose test addresses). */
export const TEST_M365_CLIENT = '198.51.100.70';
export const TEST_GOOGLE_CLIENT = '198.51.100.71';
export const TEST_ONPREM_CLIENT = '203.0.113.25';

export const testEgressIndex = (): ProviderEgressIndex =>
  ProviderEgressIndex.build([
    ...egressRangesFromCidrs('microsoft_365', [`${TEST_M365_CLIENT}/32`]),
    ...egressRangesFromCidrs('google_workspace', [`${TEST_GOOGLE_CLIENT}/32`]),
  ]);

export const TEST_TENANT_ID = '7d1c0e6a-1b2c-4d3e-8f90-a1b2c3d4e5f6';

/** TEST-ONLY: a snapshot of an entitled organization's source (overrides per section). */
export function snapshotFixture(
  kind: JournalIntakeKind,
  overrides: {
    source?: Partial<IntakeSourceSnapshot['source']>;
    organization?: Partial<IntakeSourceSnapshot['organization']>;
    connection?: Partial<NonNullable<IntakeSourceSnapshot['connection']>> | null;
    domains?: IntakeSourceSnapshot['domains'];
  } = {},
): IntakeSourceSnapshot {
  const provider =
    kind === 'microsoft_365_journal'
      ? 'microsoft_365'
      : kind === 'google_workspace_copy'
        ? 'google_workspace'
        : null;
  return {
    v: 1,
    source: {
      id: '42',
      publicId: '0190a0a0-0000-7000-8000-00000000a042',
      organizationId: '7',
      kind,
      status: 'active',
      matchedPrevious: false,
      previousValidUntil: null,
      networks: provider === null ? ['203.0.113.0/24'] : [],
      networksInvalid: false,
      requireTls: true,
      clientCertFingerprints: [],
      clientCertInvalid: false,
      maxMessageBytes: null,
      headerTokenHash: null,
      previousHeaderTokenHash: null,
      verified: true,
      ...overrides.source,
    },
    organization: {
      active: true,
      archivingFeature: true,
      journalIntakeFeature: true,
      archivingEnabled: true,
      apiDetect: false,
      messagesPerMinute: 6000,
      maxMessageBytes: 50 * 1024 * 1024,
      ...overrides.organization,
    },
    connection:
      provider === null || overrides.connection === null
        ? null
        : {
            id: '9',
            publicId: '0190a0a0-0000-7000-8000-00000000c009',
            provider,
            organizationId: '7',
            status: 'active',
            externalTenantId: TEST_TENANT_ID,
            bound: true,
            linkedDomains: ['example.com'],
            ...overrides.connection,
          },
    domains: overrides.domains ?? [
      { id: '100', name: 'example.com', status: 'active' },
      { id: '101', name: 'example.net', status: 'verified' },
    ],
  };
}
