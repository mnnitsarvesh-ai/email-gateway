import type { SuccessBody } from '@/lib/api/types';

/**
 * Builders of step API-3 test bodies (clawbacks, targets, reports, settings, the overview's new
 * blocks). Synthetic values only (`*.example.test`); typed against the generated client so a
 * contract change fails the build.
 */

export const T = '2026-11-27T09:00:00.000Z';
export const CONN = '0193f400-0000-7000-8000-000000000001';
export const CLAWBACK = '0193f500-0000-7000-8000-000000000001';
export const REPORT = '0193f600-0000-7000-8000-000000000001';
export const REPORT_2 = '0193f600-0000-7000-8000-000000000002';
export const MAILBOX = '0193f700-0000-7000-8000-000000000001';
export const REPORT_MAILBOX = '0193f700-0000-7000-8000-000000000009';
export const DETECTION = '0193fa00-0000-7000-8000-000000000001';
export const ACTION = '0193fb00-0000-7000-8000-000000000001';
/** `makeMe().user.id` of the rendered user (src/test/fixtures.ts). */
export const ME = '01930000-0000-7000-8000-000000000101';
export const OTHER_USER = '01930000-0000-7000-8000-000000000202';

type Overview = SuccessBody<'ApiModeController_overview_v1'>;
type Remediation = Overview['remediation'];
export type ClawbackDetail = SuccessBody<'ApiModeClawbackController_detail_v1'>;
export type ClawbackRow = SuccessBody<'ApiModeClawbackController_list_v1'>['data'][number];
export type Target = SuccessBody<'ApiModeClawbackController_targets_v1'>['data'][number];
export type ReportDetail = SuccessBody<'ApiModeReportsController_detail_v1'>;
export type ReportRow = SuccessBody<'ApiModeReportsController_list_v1'>['data'][number];
export type SettingsView = SuccessBody<'ApiModeSettingsController_get_v1'>;
export type ReportMailboxRow =
  SuccessBody<'ApiModeReportsController_listMailboxes_v1'>['data'][number];
type ConnectionRow = SuccessBody<'ApiModeController_listConnections_v1'>['data'][number];

const remediation = (): Remediation => ({
  policyMode: 'enforce',
  policySource: 'organization',
  paused: false,
  succeeded1h: 1,
  failed1h: 0,
  succeeded24h: 9,
  failed24h: 1,
  skipped24h: 2,
  simulated24h: 0,
  restores24h: 1,
  throttled24h: 0,
  backlog: { pending: 0, capped: false, oldestPendingAgeSeconds: null },
  latencyAvgSeconds24h: 5,
  latencyMaxSeconds24h: 20,
});
const lag = { p50Seconds1h: 45, p95Seconds1h: 300, p50Seconds24h: 60, p95Seconds24h: 420 };
const reportsBlock = {
  pendingTriage: 4,
  inReview: 1,
  received24h: 6,
  resolved24h: 2,
  oldestPendingAgeSeconds: 7_200,
  reportMailboxes: 1,
};

export const overview = (failingChecks: string[] = []): Overview => ({
  generatedAt: T,
  entitled: true,
  active: true,
  organizationMode: 'api',
  domainsByEffectiveMode: { inline: 0, api: 2, hybrid: 0 },
  coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
  connectionsByHealth: { unknown: 0, healthy: 0, degraded: 1, failing: 0 },
  lag,
  throttling: { events1h: 0, events24h: 0 },
  copiesToday: 12,
  remediation: remediation(),
  internal: { copies24h: 14, enabled: true },
  clawback: {
    active: 3,
    reviewRequired: 1,
    pendingApproval: 1,
    completed24h: 2,
    targetsSucceeded24h: 37,
    targetsFailed24h: 2,
    oldestActiveAgeSeconds: 600,
  },
  reports: reportsBlock,
  connections: [
    {
      id: CONN,
      displayName: 'Contoso production',
      provider: 'microsoft_365',
      health: 'degraded',
      failingChecks,
      coverage: { covered: 8, gap: 1, total: 9, percent: 88.8 },
      feedsEnabled: true,
      feedMode: 'poll',
      grantStatus: 'active',
      inventoryStatus: 'ok',
      lag,
      throttling: { events1h: 0, events24h: 0 },
      copiesToday: 12,
      throttledUntil: null,
      remediation: remediation(),
      internal: { copies24h: 14, enabled: true },
      clawback: { targetsQueued24h: 0, targetsSucceeded24h: 37, targetsFailed24h: 2 },
      reports: reportsBlock,
    },
  ],
});

export const connection = (): ConnectionRow => ({
  id: CONN,
  apiConnectionId: '0193f900-0000-7000-8000-000000000001',
  displayName: 'Contoso production',
  provider: 'microsoft_365',
  status: 'active',
  bound: true,
  feedsEnabled: true,
  feedMode: 'poll',
  feedsEnabledAt: T,
  inventoryStatus: 'ok',
  inventorySyncedAt: T,
  inventoryRequestedAt: null,
  mailboxesTotal: 9,
  health: { status: 'degraded', changedAt: T },
  throttledUntil: null,
  lastErrorCode: null,
  remediationPaused: false,
  remediationPausedAt: null,
  grant: { profile: 'm365.mailbox_remediation', status: 'active', authMethod: 'platform_app' },
  journalSources: [],
  rowVersion: 3,
});

export const clawback = (over: Partial<ClawbackDetail> = {}): ClawbackDetail => ({
  id: CLAWBACK,
  trigger: 'admin',
  status: 'ready',
  decisionMode: null,
  action: null,
  signalKind: 'admin',
  counts: {
    targetsTotal: 6,
    mailboxesTotal: 4,
    targetsEligible: 5,
    mailboxesEligible: 3,
    skipped: 1,
    simulated: 0,
    queued: 0,
    succeeded: 0,
    failed: 0,
    cancelled: 0,
  },
  approval: {
    required: false,
    status: null,
    reasons: [],
    requestedAt: null,
    expiresAt: null,
    decidedAt: null,
  },
  restore: { status: 'none', queued: 0, succeeded: 0, failed: 0, skipped: 0 },
  cancelRequested: false,
  reportId: null,
  lastErrorCode: null,
  signalAt: T,
  createdAt: T,
  submittedAt: null,
  startedAt: null,
  completedAt: null,
  updatedAt: T,
  rowVersion: 2,
  criteria: {
    window: { from: '2026-11-21T09:00:00.000Z', to: T },
    directions: ['inbound', 'internal'],
    keys: {
      messageIdHashes: ['ab12cd34ef56…'],
      attachmentSha256: [],
      urlSha256: [],
      urlDomains: [],
      senders: [],
      senderDomains: [],
      senderSubject: null,
    },
  },
  signal: { kind: 'admin', verdict: null, level: null, hardBlocks: [], seedDetectionId: null },
  requestedBy: { type: 'user', userId: ME },
  submittedBy: null,
  requestReason: 'Fake invoice reported by finance',
  approvalDecision: { decidedBy: null, reason: null },
  hints: { canSubmit: true, canApprove: false, canCancel: true, canRestore: false },
  ...over,
});

export const clawbackRow = (d: ClawbackDetail = clawback()): ClawbackRow => {
  const {
    criteria: _c,
    signal: _s,
    requestedBy: _r,
    submittedBy: _b,
    requestReason: _q,
    approvalDecision: _a,
    hints: _h,
    ...row
  } = d;
  return row;
};

export const target = (over: Partial<Target> = {}): Target => ({
  mailbox: { id: MAILBOX, address: 'ana@alpha.example.test' },
  connectionId: CONN,
  detectionId: DETECTION,
  receivedAt: T,
  headerFrom: 'billing@sender-2.example.test',
  subject: 'Invoice 1002 overdue',
  matchKeys: ['message_id'],
  copyRemediationState: 'none',
  status: 'matched',
  plannedAction: null,
  reasonCode: null,
  remediationId: null,
  restoreStatus: 'none',
  restoreReasonCode: null,
  ...over,
});

export const report = (over: Partial<ReportDetail> = {}): ReportDetail => ({
  id: REPORT,
  status: 'pending_triage',
  reporterAddress: 'ben@alpha.example.test',
  reportedAt: T,
  identification: 'attachment',
  assessment: 'malicious',
  analystVerdict: null,
  scan: { verdict: 'phishing', riskScore: 910, level: 'critical' },
  groupSize: 2,
  clawbackId: null,
  rejectReason: null,
  rowVersion: 2,
  reporter: { address: 'ben@alpha.example.test', mailboxId: MAILBOX, userId: null },
  reportMailbox: { id: REPORT_MAILBOX, address: 'report-phish@alpha.example.test' },
  original: {
    messageIdHash: 'cd'.repeat(32),
    sender: 'billing@sender-2.example.test',
    subjectKey: 'invoice 1002 overdue',
    date: T,
    attachmentCount: 1,
    urlCount: 0,
    extraOriginals: 0,
  },
  originalDetectionId: DETECTION,
  originalIngested: false,
  analyst: { verdict: null, note: null, triagedBy: null, triagedAt: null },
  group: {
    size: 2,
    members: [
      {
        id: REPORT,
        status: 'pending_triage',
        reporterAddress: 'ben@alpha.example.test',
        reportedAt: T,
      },
      {
        id: REPORT_2,
        status: 'pending_triage',
        reporterAddress: 'chen@alpha.example.test',
        reportedAt: T,
      },
    ],
  },
  history: [],
  feedback: { acknowledgement: 'queued', result: 'none' },
  updatedAt: T,
  ...over,
});

export const reportRow = (r: ReportDetail = report()): ReportRow => ({
  id: r.id,
  status: r.status,
  reporterAddress: r.reporterAddress,
  reportedAt: r.reportedAt,
  identification: r.identification,
  assessment: r.assessment,
  analystVerdict: r.analystVerdict,
  scan: r.scan,
  groupSize: r.groupSize,
  clawbackId: r.clawbackId,
  rejectReason: r.rejectReason,
  rowVersion: r.rowVersion,
});

export const settings = (over: Partial<SettingsView> = {}): SettingsView => ({
  settings: {
    internalMailEnabled: true,
    autoClawback: 'enforce',
    autoMaxMailboxes: 500,
    purgeApprovalMailboxes: 50,
    clawbackLookbackDays: 14,
    tiMinConfidence: 80,
    reportAckEnabled: true,
    reportFeedbackEnabled: true,
  },
  source: 'defaults',
  rowVersion: null,
  updatedAt: null,
  defaults: {
    internalMailEnabled: true,
    autoClawback: 'enforce',
    autoMaxMailboxes: 500,
    purgeApprovalMailboxes: 50,
    clawbackLookbackDays: 14,
    tiMinConfidence: 80,
    reportAckEnabled: true,
    reportFeedbackEnabled: true,
  },
  bounds: {
    autoMaxMailboxes: { min: 1, max: 20_000 },
    purgeApprovalMailboxes: { min: 1, max: 10_000 },
    clawbackLookbackDays: { min: 1, max: 60 },
    tiMinConfidence: { min: 50, max: 100 },
  },
  platform: {
    hardDeleteAvailable: false,
    clawbackMaxWindowDays: 31,
    purgeApprovalTtlHours: 72,
    reportMailboxesMax: 5,
  },
  ...over,
});

export const reportMailbox = (over: Partial<ReportMailboxRow> = {}): ReportMailboxRow => ({
  id: REPORT_MAILBOX,
  address: 'report-phish@alpha.example.test',
  connectionId: CONN,
  provider: 'microsoft_365',
  status: 'active',
  coverage: 'covered',
  domain: { id: '0193fe00-0000-7000-8000-000000000001', name: 'alpha.example.test' },
  reportMailbox: true,
  reportMailboxAt: T,
  lastReportAt: T,
  ...over,
});
