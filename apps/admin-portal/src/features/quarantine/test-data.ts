import type { SuccessBody } from '@/lib/api/types';
import type {
  Approval,
  Catalog,
  EntryDetailBody,
  EntrySummary,
  PreviewBody,
  ReleaseView,
  SettingsBody,
} from './types';

/** Test builders for the quarantine pages (typed against schema.gen.ts; synthetic values). */
export const ENTRY_ID = '01933c3a-1b2c-7d4e-8f00-0000000e0001';
export const APPROVAL_ID = '01933c3a-1b2c-7d4e-8f00-0000000a0001';
export const RELEASE_ID = '01933c3a-1b2c-7d4e-8f00-0000000b0001';
export const MESSAGE_ID = '01933c3a-1b2c-7d4e-8f00-00000000a001';
export const HOSTILE = '<script>window.__pwned = 1</script><img src=x onerror=alert(1)>Invoice';

export function entrySummary(overrides: Partial<EntrySummary> = {}): EntrySummary {
  return {
    id: ENTRY_ID,
    messageId: MESSAGE_ID,
    lifecycleRound: 0,
    state: 'held',
    kind: 'quarantine',
    origin: 'policy',
    reason: 'phishing',
    direction: 'inbound',
    recipient: 'priya.rao4@alpha.example.test',
    sender: {
      envelope: 'billing@micr0soft-example.example.test',
      headerFrom: 'billing@micr0soft-example.example.test',
    },
    subject: 'Verify your account',
    receivedAt: '2026-11-12T09:14:03.120Z',
    quarantinedAt: '2026-11-12T09:14:08.000Z',
    expiresAt: '2026-12-12T09:14:08.000Z',
    riskLevel: 'high',
    riskScore: 720,
    hardBlocks: [],
    primaryEngine: 'url',
    decisive: {
      source: 'tenant_rule',
      policyId: '01933c3a-1b2c-7d4e-8f00-0000000c0001',
      versionNo: 3,
      ruleId: 'block-high-risk',
    },
    hasAttachments: true,
    attachmentCount: 1,
    sizeBytes: 48_213,
    approvalRequestId: null,
    rowVersion: 2,
    ...overrides,
  };
}

export function entryDetail(overrides: Partial<EntryDetailBody> = {}): EntryDetailBody {
  return {
    ...entrySummary(),
    explanation: {
      lines: [],
      text: 'Quarantined by rule block-high-risk of policy inbound-threats (v3).',
    },
    floorReasons: [],
    reasonCodes: ['policy.rule.matched'],
    releases: [],
    allowedActions: ['preview', 'release', 'request_release', 'reject', 'delete', 'download'],
    contentAvailable: true,
    ...overrides,
  };
}

export function preview(overrides: Partial<PreviewBody> = {}): PreviewBody {
  return {
    version: 'preview/1',
    subject: HOSTILE,
    headers: [{ name: 'X-Mailer', value: '<script>alert("header")</script>' }],
    body: {
      source: 'html',
      text: 'Dear customer,\n<script>window.__pwned = 2</script>\n<img src=x onerror=alert(1)>\nVerify [link 1]',
      truncated: false,
      unavailableReason: null,
    },
    links: [
      {
        n: 1,
        displayUrl: 'hxxps://login[.]example[.]test/verify',
        host: 'login[.]example[.]test',
        verdict: 'malicious',
      },
    ],
    linksTruncated: false,
    attachments: [
      {
        partIndex: 2,
        filename: 'invoice<script>.pdf',
        declaredType: 'application/pdf',
        detectedType: 'application/pdf',
        typeFamily: 'document',
        sizeBytes: 48_000,
        sha256: 'e'.repeat(64),
        verdict: 'clean',
        reasonCodes: [],
        downloadable: true,
      },
    ],
    dlp: { masked: 2, categories: ['payment_card'] },
    ...overrides,
  };
}

export function approval(overrides: Partial<Approval> = {}): Approval {
  return {
    id: APPROVAL_ID,
    kind: 'release_request',
    status: 'pending',
    entryId: ENTRY_ID,
    approvalReasons: ['hard_block'],
    requestedBy: { type: 'user', id: '01933c3a-1b2c-7d4e-8f00-000000000c01' },
    requestedAt: '2026-11-12T10:00:00.000Z',
    expiresAt: '2026-11-15T10:00:00.000Z',
    decidedBy: null,
    decidedAt: null,
    decisionReason: null,
    ...overrides,
  };
}

export function releaseView(overrides: Partial<ReleaseView> = {}): ReleaseView {
  return {
    id: RELEASE_ID,
    status: 'pending',
    mode: 'operator',
    requestedBy: { type: 'user', id: null },
    requestedAt: '2026-11-12T10:00:00.000Z',
    completedAt: null,
    revalidation: null,
    deliveredObject: null,
    approvalRequestId: null,
    entryIds: [ENTRY_ID],
    ...overrides,
  };
}

export const CATALOG: Catalog = {
  states: [
    'held',
    'pending_approval',
    'releasing',
    'released',
    'rejected',
    'deleted',
    'expired',
    'superseded',
  ],
  kinds: ['quarantine', 'review'],
  origins: ['policy', 'manual', 'adopted'],
  reasons: [
    'spam',
    'bulk',
    'phishing',
    'malware',
    'bec',
    'dlp',
    'policy',
    'suspicious',
    'engine_unavailable',
    'manual',
  ],
  primaryEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox', 'policy', 'none'],
  riskLevels: ['none', 'low', 'medium', 'high', 'critical'],
  releaseModes: ['operator', 'self', 'approved'],
  releaseStatuses: ['pending', 'dispatched'],
  approvalKinds: ['policy_review', 'release_approval', 'release_request'],
  approvalStatuses: ['pending', 'approved', 'denied', 'expired', 'cancelled'],
  approvalReasons: ['hard_block', 'review'],
  entryActions: ['preview', 'release', 'request_release', 'reject', 'delete', 'download'],
  bulkActions: ['release', 'reject', 'delete', 'approve', 'deny'],
  errorCodes: { quarantine_entry_not_found: 404 },
  limits: {
    searchMaxRangeDays: 31,
    searchMaxPageSize: 100,
    searchDefaultPageSize: 25,
    bulkMaxItems: 2,
    bulkMaxItemsPerMinute: 1000,
    previewMaxTextChars: 100_000,
    downloadTokenTtlSeconds: 60,
    downloadMaxBytes: 26_214_400,
    reasonMaxChars: 512,
  },
  selfService: {
    enabled: true,
    preview: true,
    selfRelease: true,
    selfReleaseReasons: ['spam', 'bulk'],
    selfReleaseMaxLevel: 'low',
    requestRelease: true,
    digestAllowOptOut: true,
  },
  downloadEnabled: true,
};

export function settings(overrides: Partial<SettingsBody> = {}): SettingsBody {
  return {
    effective: {
      review: { days: 7 },
      approvals: { requestTtlHours: 72 },
      release: { allowHardBlocks: true },
      endUser: {
        enabled: true,
        preview: true,
        selfRelease: false,
        selfReleaseReasons: ['spam', 'bulk'],
        selfReleaseMaxLevel: 'low',
        requestRelease: true,
      },
      digest: { allowOptOut: true, includeSubject: true, maxEntries: 50 },
      alerts: { approvalRequests: true, hardBlocks: true, minIntervalMinutes: 60 },
      notices: { senderOnReject: true },
      download: { enabled: false },
      hold: { days: 30 },
      digestSchedule: { enabled: true, schedule: 'daily 08:00', timeZone: 'Europe/Berlin' },
    },
    raw: { alerts: { minIntervalMinutes: 60 } },
    invalidStored: false,
    bounds: {
      maxHoldDays: 90,
      maxReviewDays: 13,
      requestTtlHours: { min: 1, max: 168 },
      digestMaxEntries: { min: 1, max: 200 },
      alertMinIntervalMinutes: { min: 15, max: 1440 },
    },
    rowVersion: 4,
    ...overrides,
  };
}

export const SUMMARY: SuccessBody<'QuarantineToolsController_summary_v1'> = {
  from: '2026-11-06T00:00:00.000Z',
  to: '2026-11-13T00:00:00.000Z',
  counts: { held: 12, pending_approval: 3, released: 5 },
  pendingApprovals: 3,
};
