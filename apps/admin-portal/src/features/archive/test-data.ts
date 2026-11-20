import type {
  ArchiveDetail,
  ArchiveMessage,
  ArchiveSettings,
  ArchiveStatus,
  EdiscoveryCase,
  EdiscoveryExport,
  EdiscoverySearch,
  LegalHold,
  RetentionPolicy,
  SearchHit,
} from './model';

/** Synthetic bodies of the step 8.1 component tests (every value invented, `EXAMPLE` markers). */

export const MESSAGE_ID = '01930000-0000-7000-8000-00000000c001';
export const MALICIOUS_ID = '01930000-0000-7000-8000-00000000c002';
export const POLICY_ID = '01930000-0000-7000-8000-00000000c101';
export const POLICY_2_ID = '01930000-0000-7000-8000-00000000c102';
export const HOLD_ID = '01930000-0000-7000-8000-00000000c201';
export const CASE_ID = '01930000-0000-7000-8000-00000000c301';
export const SEARCH_ID = '01930000-0000-7000-8000-00000000c401';
export const EXPORT_ID = '01930000-0000-7000-8000-00000000c501';
export const DOMAIN_ID = '01930000-0000-7000-8000-00000000c601';

export const SECRET_SUBJECT = 'EXAMPLE secret merger subject';
export const SECRET_RECIPIENT = 'priya.rao@corp.example.test';
/** A custodian (in clear for case and hold managers). */
export const CUSTODIAN = 'alex.lee@corp.example.test';

export const SETTINGS: ArchiveSettings = {
  enabled: false,
  entitled: true,
  immutability: 'none',
  objectLockAvailable: true,
  defaultRetentionPolicyId: POLICY_ID,
  settings: {
    directions: { inbound: true, outbound: true, internal: true },
    include: { rejected: false, quarantined: false, failed: false },
    scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
    policyArchive: { enabled: true },
    access: { previewEnabled: true, downloadEnabled: true },
    intake: { scanEnabled: false },
  },
  generation: 2,
  journalEnabledAt: null,
  rowVersion: 3,
  updatedAt: '2026-11-10T08:00:00.000Z',
};

export const STATUS: ArchiveStatus = {
  generatedAt: '2026-11-17T08:00:00.000Z',
  settings: { enabled: false, entitled: true, immutability: 'none', generation: 2 },
  capture: { pending: 1, capturedOpen: 2, failed: 1, lost: 0, oldestPendingAt: null },
  records: { active: 12, expiryReview: 1, disposing: 0 },
  index: { queued: 0, oldestQueuedAt: null, lagSeconds: 0 },
  disposals: { inProgress: 0, failed: 0 },
  keys: { activeVersion: 1, versions: 1 },
  objectLock: { available: true },
  search: { configured: true, available: true },
};

export const POLICY: RetentionPolicy = {
  id: POLICY_ID,
  name: 'Default seven years',
  retentionDays: 2555,
  onExpiry: 'delete',
  priority: 1000,
  criteria: {},
  isDefault: false,
  rowVersion: 1,
  createdAt: '2026-10-01T08:00:00.000Z',
  updatedAt: '2026-10-01T08:00:00.000Z',
};
export const POLICY_2: RetentionPolicy = {
  ...POLICY,
  id: POLICY_2_ID,
  name: 'Outbound review',
  retentionDays: 365,
  onExpiry: 'review',
  priority: 10,
  criteria: { directions: ['outbound'] },
  rowVersion: 2,
};

export function message(overrides: Partial<ArchiveMessage> = {}): ArchiveMessage {
  return {
    messageId: MESSAGE_ID,
    receivedAt: '2026-11-16T09:00:00.000Z',
    capturedAt: '2026-11-16T09:01:30.000Z',
    direction: 'inbound',
    category: 'delivered',
    sources: ['journal'],
    ingestSources: ['gateway'],
    status: 'active',
    envelopeFrom: 'sender@partner.example.test',
    headerFrom: 'sender@partner.example.test',
    recipients: ['p***@corp.example.test'],
    recipientsTruncated: false,
    subject: null,
    subjectMasked: true,
    sizeBytes: 4096,
    attachmentCount: 1,
    attachmentNames: ['EXAMPLE-report.pdf'],
    verdict: 'clean',
    finalAction: 'deliver',
    riskScore: 120,
    malicious: false,
    retainUntil: '2033-11-16T09:00:00.000Z',
    legalHold: false,
    lockMode: 'none',
    ...overrides,
  };
}

export function detail(overrides: Partial<ArchiveDetail> = {}): ArchiveDetail {
  const base = message();
  return {
    ...base,
    intake: null,
    mergedCopies: [],
    internetMessageId: '<EXAMPLE-1@mail.example.test>',
    parties: {
      envelopeFrom: base.envelopeFrom,
      headerFrom: base.headerFrom,
      recipients: [
        {
          seq: 0,
          address: 'p***@corp.example.test',
          direction: 'inbound',
          status: 'delivered',
          finalAction: 'deliver',
        },
      ],
      recipientCount: 1,
      recipientsTruncated: false,
    },
    capture: {
      capturedAt: '2026-11-16T09:01:30.000Z',
      sources: { journal: true, policy: false, policyRuleRef: null },
      messageState: 'delivered',
      messageStateReason: 'delivery_complete',
      settingsGeneration: 2,
      outcomeRefreshedAt: null,
    },
    retention: {
      policyId: POLICY_ID,
      policyName: 'Default seven years',
      retainUntil: '2033-11-16T09:00:00.000Z',
      effectiveRetainUntil: '2033-11-16T09:00:00.000Z',
      expiryAction: 'delete',
    },
    holds: [{ id: HOLD_ID, name: 'EXAMPLE board hold', caseId: CASE_ID }],
    immutability: { lockMode: 'none', lockUntil: null },
    integrity: {
      sha256: 'a'.repeat(64),
      sizeBytes: 4096,
      storedBytes: 4608,
      encryptionFormat: 'archive-object/1',
      keyVersion: 1,
    },
    rounds: [{ round: 0, revision: 0, frozenAt: '2026-11-16T09:01:30.000Z' }],
    ...overrides,
  };
}

export const HOLD: LegalHold = {
  id: HOLD_ID,
  caseId: CASE_ID,
  name: 'EXAMPLE board hold',
  reason: 'EXAMPLE litigation notice',
  status: 'active',
  criteria: { custodians: [CUSTODIAN], from: '2026-01-01', directions: ['inbound'] },
  criteriaVersion: 'archive-hold/1',
  createdBy: null,
  createdAt: '2026-11-10T08:00:00.000Z',
  releasedAt: null,
  releasedBy: null,
  releaseReason: null,
  rowVersion: 1,
};

export const CASE: EdiscoveryCase = {
  id: CASE_ID,
  name: 'EXAMPLE board investigation',
  description: 'EXAMPLE review',
  matterReference: 'EXAMPLE-2026-014',
  status: 'open',
  rowVersion: 3,
  createdBy: null,
  createdAt: '2026-11-01T08:00:00.000Z',
  updatedAt: '2026-11-02T08:00:00.000Z',
  closedAt: null,
  custodians: [{ id: '01930000-0000-7000-8000-00000000c701', address: CUSTODIAN, userId: null }],
  counts: { custodians: 1, activeHolds: 1, searches: 1, exports: 1 },
};

export function search(overrides: Partial<EdiscoverySearch> = {}): EdiscoverySearch {
  return {
    id: SEARCH_ID,
    caseId: CASE_ID,
    status: 'completed',
    criteria: { from: '2026-01-01', to: '2026-11-17', custodians: 'case' },
    criteriaSha256: 'b'.repeat(64),
    hitCount: 2,
    truncated: false,
    indexComplete: true,
    incompleteReason: null,
    errorCode: null,
    requestedBy: null,
    createdAt: '2026-11-15T08:00:00.000Z',
    startedAt: '2026-11-15T08:00:02.000Z',
    completedAt: '2026-11-15T08:00:09.000Z',
    ...overrides,
  };
}

export function hit(id: string, overrides: Partial<SearchHit> = {}): SearchHit {
  return {
    messageId: id,
    receivedAt: '2026-11-16T09:00:00.000Z',
    reviewTag: 'untagged',
    reviewedBy: null,
    reviewedAt: null,
    message: message({ messageId: id }),
    ...overrides,
  };
}

export function exportItem(overrides: Partial<EdiscoveryExport> = {}): EdiscoveryExport {
  return {
    id: EXPORT_ID,
    caseId: CASE_ID,
    searchId: SEARCH_ID,
    status: 'completed',
    reviewTags: ['untagged', 'relevant', 'privileged'],
    acknowledgeMalicious: false,
    itemCount: 2,
    maliciousCount: 0,
    packageBytes: 20_480,
    packageSha256: 'c'.repeat(64),
    manifestSha256: 'd'.repeat(64),
    signingKeyId: 'eg-export-EXAMPLE-1',
    expiresAt: '2026-11-24T08:00:00.000Z',
    errorCode: null,
    requestedBy: null,
    createdAt: '2026-11-16T08:00:00.000Z',
    completedAt: '2026-11-16T08:00:20.000Z',
    ...overrides,
  };
}
