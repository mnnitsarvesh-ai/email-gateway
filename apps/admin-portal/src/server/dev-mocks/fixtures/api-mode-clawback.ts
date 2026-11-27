import 'server-only';
import type { OperationId, RequestBody, SuccessBody } from '@/lib/api/types';
import { paginate, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import {
  addDiscoveredMailbox,
  apiModeDomainsOf,
  apiModeStateOf,
  cancelClawbackAction,
  copySearchKeys,
  queueClawbackAction,
  registerClawbackHooks,
} from './api-mode';
import { DAY, HOUR, MINUTE, guarded, idempotent, isoAgo } from './domains';
import { releaseMailboxEntry } from './quarantine';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of API-mode clawback, search and purge, reported phishing and the organization
 * settings (step API-3 WP6, docs/plan/steps/37-api-mode-clawback-reporting.md C4–C14): the 19
 * operations over the copies of the api-mode fixture, with a simulated `clawback` role — a search
 * is materialized about 3 seconds after creation into frozen targets, a queued purge queues one
 * mailbox action per eligible target (run by the api-mode fixture's `remediate` role about 8
 * seconds later), progress is reconciled until the clawback completes, a cancel stops what is not
 * queued yet, and a restore releases the mailbox entries through the quarantine fixture's rules
 * (hard-blocked entries are left for an approver). Approvals follow C6: a second user holding
 * `remediation:purge`, never the requester or submitter, within the TTL. Reports are seeded in
 * every state with a group of two; triage applies to the group, with reporter feedback states.
 * Synthetic only (`*.example.test`), per organization, deterministic.
 */

export const API_MODE_CLAWBACK_OPERATIONS: readonly OperationId[] = [
  'ApiModeClawbackController_create_v1',
  'ApiModeClawbackController_list_v1',
  'ApiModeClawbackController_detail_v1',
  'ApiModeClawbackController_targets_v1',
  'ApiModeClawbackController_submit_v1',
  'ApiModeClawbackController_submitHardDelete_v1',
  'ApiModeClawbackController_approve_v1',
  'ApiModeClawbackController_deny_v1',
  'ApiModeClawbackController_cancel_v1',
  'ApiModeClawbackController_restore_v1',
  'ApiModeReportsController_list_v1',
  'ApiModeReportsController_detail_v1',
  'ApiModeReportsController_triage_v1',
  'ApiModeReportsController_clawback_v1',
  'ApiModeReportsController_listMailboxes_v1',
  'ApiModeReportsController_addMailbox_v1',
  'ApiModeReportsController_setMailbox_v1',
  'ApiModeSettingsController_get_v1',
  'ApiModeSettingsController_put_v1',
];

type Detail = SuccessBody<'ApiModeClawbackController_detail_v1'>;
type View = SuccessBody<'ApiModeClawbackController_list_v1'>['data'][number];
type Target = SuccessBody<'ApiModeClawbackController_targets_v1'>['data'][number];
type ReportView = SuccessBody<'ApiModeReportsController_detail_v1'>;
type ReportRow = SuccessBody<'ApiModeReportsController_list_v1'>['data'][number];
type MailboxView = SuccessBody<'ApiModeReportsController_listMailboxes_v1'>['data'][number];
type Settings = SuccessBody<'ApiModeSettingsController_get_v1'>['settings'];
type Status = Detail['status'];
type Trigger = Detail['trigger'];
type Detection = ReturnType<typeof apiModeStateOf>['detections'][number];
type MailboxAction = Target['plannedAction'];

/** Internal search keys of a clawback (the criteria view shows them shortened). */
interface SearchKeys {
  messageIds: string[];
  attachments: string[];
  urls: string[];
  senderSubject: { sender: string; subject: string } | null;
}

interface TargetRecord {
  target: Target;
  detectionId: string;
  actionId: string | null;
  restoreActionId: string | null;
}

interface ClawbackRecord {
  detail: Omit<Detail, 'hints'>;
  keys: SearchKeys;
  requesterUserId: string | null;
  submitterUserId: string | null;
  targets: TargetRecord[];
  restoreRequest: FixtureRequest | null;
  restoreReason: string | null;
}

interface ReportRecord {
  view: ReportView;
  /** The detection the original was found as (C10.3), or null. */
  originalDetectionIndex: number | null;
  reopened: boolean;
}

interface OrgState {
  clawbacks: ClawbackRecord[];
  reports: ReportRecord[];
  settings: { settings: Settings; rowVersion: number; updatedAt: string } | null;
  reportMailboxes: Map<string, { at: string; lastReportAt: string | null }>;
}

interface State {
  orgs: Map<string, OrgState>;
  idempotency: Map<string, FixtureResponse>;
}

const store = globalThis as typeof globalThis & { __egDevFixtureApiModeClawback?: State };
const state: State = (store.__egDevFixtureApiModeClawback ??= {
  orgs: new Map(),
  idempotency: new Map(),
});

export function resetApiModeClawbackFixtures(): void {
  state.orgs.clear();
  state.idempotency.clear();
}

/** Simulated `clawback` role delays (dev only). */
export const MATERIALIZE_DELAY_MS = 3_000;
export const QUEUE_DELAY_MS = 2_000;

const DEFAULTS: Settings = {
  internalMailEnabled: true,
  autoClawback: 'enforce',
  autoMaxMailboxes: 500,
  purgeApprovalMailboxes: 50,
  clawbackLookbackDays: 14,
  tiMinConfidence: 80,
  reportAckEnabled: true,
  reportFeedbackEnabled: true,
};
const BOUNDS = {
  autoMaxMailboxes: { min: 1, max: 20_000 },
  purgeApprovalMailboxes: { min: 1, max: 10_000 },
  clawbackLookbackDays: { min: 1, max: 60 },
  tiMinConfidence: { min: 50, max: 100 },
} as const;
const PLATFORM = {
  hardDeleteAvailable: false,
  clawbackMaxWindowDays: 31,
  purgeApprovalTtlHours: 72,
  reportMailboxesMax: 5,
};
const MAX_TARGETS = 20_000;
const RETENTION_DAYS = 186;
const ACTIVE: readonly Status[] = [
  'searching',
  'ready',
  'review_required',
  'pending_approval',
  'queued',
  'running',
];
const FINAL_COUNTED: readonly Status[] = ['completed', 'completed_with_errors'];
const STRENGTH = ['tag', 'move_junk', 'move_quarantine', 'soft_delete', 'hard_delete'];
const strength = (action: string | null) => (action ? STRENGTH.indexOf(action) : -1);
const ENTRY_ACTIONS = new Set(['move_quarantine', 'move_junk', 'soft_delete']);
const HEX64 = /^[0-9a-f]{64}$/;

/** Fixture hashes (SHA-256-shaped, deterministic). */
const hash = (seed: string) =>
  Array.from({ length: 8 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, '').slice(0, 8))
    .join('')
    .slice(0, 64);
const normalizeMessageId = (value: string) =>
  value
    .trim()
    .replace(/^<(.*)>$/, '$1')
    .trim();
const messageIdHash = (value: string) =>
  hash(`message-id:${normalizeMessageId(value).toLowerCase()}`);
const urlHash = (value: string) => hash(`url:${value.trim().toLowerCase().replace(/\/+$/, '')}`);
const subjectKey = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/^((re|fw|fwd|aw|wg)\s*:\s*)+/i, '')
    .replace(/\s+/g, ' ')
    .slice(0, 128);
const truncated = (h: string) => `${h.slice(0, 12)}…`;

function userIdOf(request: FixtureRequest): string | null {
  return resolveFixturePrincipal(request.token)?.userId ?? null;
}

function keyed(request: FixtureRequest, run: () => FixtureResponse): FixtureResponse {
  return idempotent(state.idempotency, request, run);
}

function reasonInvalid(reason: unknown, max = 2000): FixtureResponse | null {
  const text = typeof reason === 'string' ? reason.trim() : '';
  return text.length < 1 || text.length > max
    ? apiError(400, 'validation_failed', [`reason: 1 to ${max} characters`])
    : null;
}

// ---- seed ------------------------------------------------------------------------------------

function orgOf(organizationId: string): OrgState {
  let org = state.orgs.get(organizationId);
  if (!org) {
    org = seed(organizationId);
    state.orgs.set(organizationId, org);
  }
  tick(organizationId, org);
  return org;
}

function emptyCounts(): Detail['counts'] {
  return {
    targetsTotal: 0,
    mailboxesTotal: 0,
    targetsEligible: 0,
    mailboxesEligible: 0,
    skipped: 0,
    simulated: 0,
    queued: 0,
    succeeded: 0,
    failed: 0,
    cancelled: 0,
  };
}

function newRecord(input: {
  id: string;
  trigger: Trigger;
  status: Status;
  keys: SearchKeys;
  window: { from: string; to: string };
  directions?: Array<'inbound' | 'internal'>;
  createdAt: string;
  requester: string | null;
  reason: string | null;
  signal?: Partial<Detail['signal']>;
  reportId?: string | null;
}): ClawbackRecord {
  const automatic = input.trigger === 'late_verdict' || input.trigger === 'threat_intel';
  return {
    keys: input.keys,
    requesterUserId: input.requester,
    submitterUserId: null,
    targets: [],
    restoreRequest: null,
    restoreReason: null,
    detail: {
      id: input.id,
      trigger: input.trigger,
      status: input.status,
      decisionMode: automatic ? 'policy' : null,
      action: null,
      signalKind:
        input.signal?.kind ??
        (input.trigger === 'late_verdict'
          ? 'sandbox_revision'
          : input.trigger === 'threat_intel'
            ? 'threat_indicator'
            : input.trigger === 'report'
              ? 'report'
              : input.trigger === 'campaign'
                ? 'campaign'
                : 'admin'),
      counts: emptyCounts(),
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
      reportId: input.reportId ?? null,
      lastErrorCode: null,
      signalAt: input.createdAt,
      createdAt: input.createdAt,
      submittedAt: null,
      startedAt: null,
      completedAt: null,
      updatedAt: input.createdAt,
      rowVersion: 1,
      criteria: {
        window: input.window,
        directions: input.directions ?? ['inbound', 'internal'],
        keys: {
          messageIdHashes: input.keys.messageIds.map(truncated),
          attachmentSha256: input.keys.attachments.map(truncated),
          urlSha256: input.keys.urls.map(truncated),
          urlDomains: [],
          senders: [],
          senderDomains: [],
          senderSubject: input.keys.senderSubject
            ? {
                sender: input.keys.senderSubject.sender,
                subjectKey: subjectKey(input.keys.senderSubject.subject),
              }
            : null,
        },
      },
      signal: {
        kind: null,
        verdict: null,
        level: null,
        hardBlocks: [],
        seedDetectionId: null,
        ...input.signal,
      },
      requestedBy: input.requester
        ? { type: 'user', userId: input.requester }
        : { type: 'system', userId: null },
      submittedBy: null,
      requestReason: input.reason,
      approvalDecision: { decidedBy: null, reason: null },
    },
  };
}

/** Seeded clawbacks: a completed automatic one, one waiting for review and one for approval. */
function seed(organizationId: string): OrgState {
  const org: OrgState = {
    clawbacks: [],
    reports: [],
    settings: null,
    reportMailboxes: new Map(),
  };
  const api = apiModeStateOf(organizationId);
  if (api.detections.length === 0) return org;
  const keysOf = (index: number) => copySearchKeys(api.detections[index]?.id ?? '');
  const window = { from: isoAgo(14 * DAY), to: isoAgo(-HOUR) };
  const analyst = stableUuid('user:security_analyst@example.com');

  // 1. Late sandbox verdict of campaign group 0: completed through the policy (its targets are
  //    the copies the policy already moved to the quarantine folder).
  const late = newRecord({
    id: stableUuid(`${organizationId}:clawback:late`),
    trigger: 'late_verdict',
    status: 'searching',
    keys: {
      messageIds: [messageIdHash(keysOf(0)?.messageId ?? '')],
      attachments: [],
      urls: [],
      senderSubject: null,
    },
    window,
    createdAt: isoAgo(2 * DAY),
    requester: null,
    reason: null,
    signal: {
      kind: 'sandbox_revision',
      verdict: 'malware',
      level: 'critical',
      hardBlocks: ['hb.sandbox_malicious'],
    },
  });
  materialize(organizationId, late, 'completed');
  // 2. A threat-intelligence clawback above the automatic cap: waits for review (auto_cap).
  const ti = newRecord({
    id: stableUuid(`${organizationId}:clawback:ti`),
    trigger: 'threat_intel',
    status: 'searching',
    keys: {
      messageIds: [],
      attachments: [],
      urls: [urlHash(keysOf(3)?.urls[0] ?? 'https://x')],
      senderSubject: null,
    },
    window,
    createdAt: isoAgo(5 * HOUR),
    requester: null,
    reason: null,
    signal: {
      kind: 'threat_indicator',
      verdict: 'phishing',
      level: 'high',
      hardBlocks: ['hb.clawback.threat_intel'],
    },
  });
  materialize(organizationId, ti, 'review_required');
  ti.detail.approval.reasons = ['auto_cap'];
  // 3. An analyst's purge (Junk) above the threshold: waiting for a second approver.
  const purge = newRecord({
    id: stableUuid(`${organizationId}:clawback:purge`),
    trigger: 'admin',
    status: 'searching',
    keys: {
      messageIds: [],
      attachments: [],
      urls: [],
      senderSubject: { sender: keysOf(1)?.sender ?? '', subject: keysOf(1)?.subject ?? '' },
    },
    window: { from: isoAgo(6 * DAY), to: isoAgo(-HOUR) },
    createdAt: isoAgo(3 * HOUR),
    requester: analyst,
    reason: 'Fake invoice campaign reported by finance',
  });
  materialize(organizationId, purge, 'ready');
  purge.detail.status = 'pending_approval';
  purge.detail.decisionMode = 'explicit';
  purge.detail.action = 'move_junk';
  purge.submitterUserId = analyst;
  purge.detail.submittedBy = analyst;
  purge.detail.submittedAt = isoAgo(3 * HOUR - 5 * MINUTE);
  purge.detail.approval = {
    required: true,
    status: 'pending',
    reasons: ['mailbox_threshold'],
    requestedAt: purge.detail.submittedAt,
    expiresAt: new Date(
      Date.parse(purge.detail.submittedAt) + PLATFORM.purgeApprovalTtlHours * HOUR,
    ).toISOString(),
    decidedAt: null,
  };
  purge.detail.rowVersion = 3;
  org.clawbacks.push(purge, ti, late);

  // Report mailbox and reports (C9, C10, C11).
  const reportMailbox = api.mailboxes[8];
  if (reportMailbox) {
    org.reportMailboxes.set(reportMailbox.id, {
      at: isoAgo(10 * DAY),
      lastReportAt: isoAgo(40 * MINUTE),
    });
    const reporters = api.mailboxes.slice(0, 6);
    const specs: Array<{
      status: ReportView['status'];
      detection: number | null;
      ago: number;
      verdict?: ReportView['analystVerdict'];
      reject?: string;
      identification: ReportView['identification'];
    }> = [
      { status: 'pending_triage', detection: 4, ago: 40 * MINUTE, identification: 'attachment' },
      { status: 'pending_triage', detection: 4, ago: 55 * MINUTE, identification: 'attachment' },
      { status: 'in_review', detection: 7, ago: 3 * HOUR, identification: 'inline' },
      {
        status: 'resolved',
        detection: 2,
        ago: 9 * HOUR,
        verdict: 'spam',
        identification: 'attachment',
      },
      {
        status: 'rejected',
        detection: null,
        ago: 20 * HOUR,
        reject: 'auto_submitted',
        identification: null,
      },
      { status: 'scanning', detection: null, ago: 2 * MINUTE, identification: 'attachment' },
    ];
    specs.forEach((spec, i) => {
      const reporter = reporters[i % reporters.length]!;
      const detection = spec.detection === null ? null : (api.detections[spec.detection] ?? null);
      const keys = detection ? copySearchKeys(detection.id) : null;
      const groupKey = keys ? messageIdHash(keys.messageId) : null;
      const id = stableUuid(`${organizationId}:report:${i}`);
      const at = isoAgo(spec.ago);
      const assessment: ReportView['assessment'] =
        spec.status === 'scanning' || spec.status === 'rejected'
          ? null
          : detection?.verdict === 'phishing' || detection?.verdict === 'malware'
            ? 'malicious'
            : detection?.verdict === 'clean'
              ? 'clean'
              : 'suspicious';
      org.reports.push({
        originalDetectionIndex: spec.detection,
        reopened: false,
        view: {
          id,
          status: spec.status,
          reporterAddress: reporter.address,
          reportedAt: at,
          identification: spec.identification,
          assessment,
          analystVerdict: spec.verdict ?? null,
          scan: {
            verdict: spec.status === 'scanning' ? null : (detection?.verdict ?? 'unknown'),
            riskScore: spec.status === 'scanning' ? null : (detection?.riskScore ?? null),
            level: spec.status === 'scanning' ? null : detection ? 'high' : null,
          },
          groupSize: 1,
          clawbackId: null,
          rejectReason: spec.reject ?? null,
          rowVersion: spec.status === 'pending_triage' ? 2 : 4,
          reporter: { address: reporter.address, mailboxId: reporter.id, userId: null },
          reportMailbox: { id: reportMailbox.id, address: reportMailbox.address },
          original:
            keys && detection
              ? {
                  messageIdHash: spec.identification === 'attachment' ? groupKey : null,
                  sender: keys.sender,
                  subjectKey: subjectKey(keys.subject),
                  date: detection.receivedAt,
                  attachmentCount: keys.attachmentSha256.length,
                  urlCount: keys.urls.length,
                  extraOriginals: 0,
                }
              : null,
          originalDetectionId: detection?.id ?? null,
          originalIngested: false,
          analyst: {
            verdict: spec.verdict ?? null,
            note: null,
            triagedBy: spec.verdict ? analyst : null,
            triagedAt: spec.verdict ? isoAgo(spec.ago - 30 * MINUTE) : null,
          },
          group: { size: 1, members: [] },
          history: spec.verdict
            ? [
                {
                  at: isoAgo(spec.ago - 30 * MINUTE),
                  actor: { type: 'user', userId: analyst },
                  from: 'pending_triage',
                  to: 'resolved',
                  verdict: spec.verdict,
                  reopened: false,
                },
              ]
            : spec.status === 'in_review'
              ? [
                  {
                    at: isoAgo(spec.ago - 10 * MINUTE),
                    actor: { type: 'user', userId: analyst },
                    from: 'pending_triage',
                    to: 'in_review',
                    verdict: null,
                    reopened: false,
                  },
                ]
              : [],
          feedback: {
            acknowledgement:
              spec.status === 'rejected' || spec.status === 'scanning' ? 'none' : 'queued',
            result: spec.verdict ? 'queued' : 'none',
          },
          updatedAt: at,
        },
      });
    });
    refreshGroups(org);
  }
  return org;
}

/** C11.3: the original's Message-ID hash, else a hash of sender, subject key and date hour. */
function groupOf(r: ReportRecord): string | null {
  const o = r.view.original;
  if (!o) return null;
  if (o.messageIdHash) return o.messageIdHash;
  if (!o.sender || !o.subjectKey) return null;
  return hash(`group:${o.sender}|${o.subjectKey}|${(o.date ?? '').slice(0, 13)}`);
}

/** Group sizes and members. */
function refreshGroups(org: OrgState): void {
  for (const record of org.reports) {
    const key = groupOf(record);
    const members = key === null ? [record] : org.reports.filter((r) => groupOf(r) === key);
    record.view.groupSize = members.length;
    record.view.group = {
      size: members.length,
      members: members.slice(0, 50).map((m) => ({
        id: m.view.id,
        status: m.view.status,
        reporterAddress: m.view.reporterAddress,
        reportedAt: m.view.reportedAt,
      })),
    };
  }
}

// ---- the simulated clawback role -------------------------------------------------------------

function settingsOf(org: OrgState): Settings {
  return org.settings?.settings ?? DEFAULTS;
}

function matchKeysOf(record: ClawbackRecord, detection: Detection): Target['matchKeys'] {
  const keys = copySearchKeys(detection.id);
  if (!keys) return [];
  const out: Target['matchKeys'] = [];
  if (record.keys.messageIds.includes(messageIdHash(keys.messageId))) out.push('message_id');
  if (keys.attachmentSha256.some((h) => record.keys.attachments.includes(h)))
    out.push('attachment');
  if (keys.urls.some((u) => record.keys.urls.includes(urlHash(u)))) out.push('url');
  const ss = record.keys.senderSubject;
  if (
    ss &&
    ss.sender.toLowerCase() === keys.sender &&
    subjectKey(ss.subject) === subjectKey(keys.subject)
  )
    out.push('sender_subject');
  return out;
}

function recount(record: ClawbackRecord): void {
  const c = emptyCounts();
  const targets = record.targets.map((t) => t.target);
  c.targetsTotal = targets.length;
  c.mailboxesTotal = new Set(targets.map((t) => t.mailbox.id)).size;
  const eligible = record.targets.filter(
    (t) => t.target.status !== 'skipped' && t.target.status !== 'simulated',
  );
  c.targetsEligible = eligible.length;
  c.mailboxesEligible = new Set(eligible.map((t) => t.target.mailbox.id)).size;
  for (const t of targets) {
    if (t.status === 'skipped') c.skipped += 1;
    else if (t.status === 'simulated') c.simulated += 1;
    else if (t.status === 'queued') c.queued += 1;
    else if (t.status === 'succeeded') c.succeeded += 1;
    else if (t.status === 'failed') c.failed += 1;
    else if (t.status === 'cancelled') c.cancelled += 1;
  }
  record.detail.counts = c;
  const r = record.detail.restore;
  r.queued = targets.filter((t) => t.restoreStatus === 'queued').length;
  r.succeeded = targets.filter((t) => t.restoreStatus === 'succeeded').length;
  r.failed = targets.filter((t) => t.restoreStatus === 'failed').length;
  r.skipped = targets.filter((t) => t.restoreStatus === 'skipped').length;
}

function touch(record: ClawbackRecord, now = new Date().toISOString()): void {
  record.detail.updatedAt = now;
  record.detail.rowVersion += 1;
}

/** C4.2/C4.3, C5.2: the frozen target list. `seedStatus` lets the seed place it in a state. */
function materialize(organizationId: string, record: ClawbackRecord, seedStatus?: Status): void {
  const api = apiModeStateOf(organizationId);
  const org = state.orgs.get(organizationId);
  const reportMailboxes = org?.reportMailboxes ?? new Map();
  const from = Date.parse(record.detail.criteria.window.from);
  const to = Date.parse(record.detail.criteria.window.to);
  const directions = record.detail.criteria.directions;
  const matched = api.detections.filter((d) => {
    const at = Date.parse(d.receivedAt);
    return (
      at >= from &&
      at <= to &&
      directions.includes(d.direction) &&
      !reportMailboxes.has(d.mailboxId) &&
      matchKeysOf(record, d).length > 0
    );
  });
  const now = new Date().toISOString();
  if (matched.length > MAX_TARGETS || matched.length === 0) {
    record.detail.status = matched.length === 0 ? 'no_match' : 'too_broad';
    record.detail.completedAt = now;
    touch(record, now);
    return;
  }
  const automatic =
    record.detail.trigger === 'late_verdict' || record.detail.trigger === 'threat_intel';
  record.targets = matched.map((d) => {
    const mailbox = api.mailboxes.find((m) => m.id === d.mailboxId);
    let status: Target['status'] = 'matched';
    let reasonCode: string | null = null;
    if (mailbox?.status === 'disabled' || mailbox?.status === 'deleted') {
      status = 'skipped';
      reasonCode = 'mailbox_inactive';
    } else if (d.remediationState === 'pending') {
      status = 'skipped';
      reasonCode = 'remediation_in_progress';
    } else if (
      d.remediationState === 'remediated' &&
      strength(d.remediationAction) >= strength('move_quarantine')
    ) {
      status = seedStatus === 'completed' ? 'succeeded' : 'skipped';
      reasonCode = seedStatus === 'completed' ? null : 'already_remediated';
    }
    if (seedStatus === 'completed' && status === 'matched') {
      status = 'skipped';
      reasonCode = 'policy_none';
    }
    if (!d.clawbacks.includes(record.detail.id) && d.clawbacks.length < 5)
      d.clawbacks.push(record.detail.id);
    return {
      detectionId: d.id,
      actionId: status === 'succeeded' ? d.remediationId : null,
      restoreActionId: null,
      target: {
        mailbox: { id: d.mailboxId, address: d.mailboxAddress },
        connectionId: d.connectionId,
        detectionId: d.id,
        receivedAt: d.receivedAt,
        headerFrom: copySearchKeys(d.id)?.sender ?? null,
        subject: copySearchKeys(d.id)?.subject ?? null,
        matchKeys: matchKeysOf(record, d),
        copyRemediationState: d.remediationState,
        status,
        plannedAction:
          status === 'succeeded'
            ? d.remediationAction
            : automatic && status === 'matched'
              ? 'move_quarantine'
              : null,
        reasonCode,
        remediationId: status === 'succeeded' ? d.remediationId : null,
        restoreStatus: 'none',
        restoreReasonCode: null,
      },
    };
  });
  recount(record);
  const settings = org ? settingsOf(org) : DEFAULTS;
  let status: Status = seedStatus ?? 'ready';
  if (!seedStatus && automatic) {
    status =
      settings.autoClawback === 'review' ||
      record.detail.counts.mailboxesEligible > settings.autoMaxMailboxes
        ? 'review_required'
        : 'queued';
  }
  record.detail.status = status;
  if (status === 'completed') {
    record.detail.startedAt = record.detail.createdAt;
    record.detail.submittedAt = record.detail.createdAt;
    record.detail.completedAt = new Date(
      Date.parse(record.detail.createdAt) + 2 * MINUTE,
    ).toISOString();
  }
  touch(record, now);
}

function planned(record: ClawbackRecord, detection: Detection): NonNullable<MailboxAction> | null {
  if (record.detail.decisionMode === 'explicit' && record.detail.action)
    return record.detail.action;
  const verdict = record.detail.signal.verdict ?? 'phishing';
  const level = record.detail.signal.level ?? 'critical';
  if (
    (verdict === 'malware' || verdict === 'phishing') &&
    (level === 'critical' || record.detail.signal.hardBlocks.length > 0)
  )
    return 'move_quarantine';
  if (verdict === 'spam') return detection.verdict === 'clean' ? null : 'move_junk';
  return 'tag';
}

/** One run of the `clawback` role over the organization's clawbacks (C4, C5.4–C5.6, C6, C7). */
function tick(organizationId: string, org: OrgState, now = Date.now()): void {
  const api = apiModeStateOf(organizationId);
  const iso = new Date(now).toISOString();
  for (const record of org.clawbacks) {
    const d = record.detail;
    if (d.status === 'searching' && now - Date.parse(d.createdAt) >= MATERIALIZE_DELAY_MS) {
      materialize(organizationId, record);
      continue;
    }
    if (
      d.status === 'pending_approval' &&
      d.approval.expiresAt &&
      Date.parse(d.approval.expiresAt) < now
    ) {
      d.status = 'expired';
      d.approval.status = 'expired';
      d.completedAt = iso;
      touch(record, iso);
      continue;
    }
    if ((d.status === 'queued' || d.status === 'running') && d.cancelRequested) {
      for (const t of record.targets) {
        if (t.target.status === 'matched') t.target.status = 'cancelled';
        if (t.target.status === 'queued' && t.actionId) {
          const action = api.actions.find((a) => a.id === t.actionId);
          if (action?.status === 'pending') {
            cancelClawbackAction(organizationId, action.id);
            t.target.status = 'cancelled';
          }
        }
      }
      if (!record.targets.some((t) => t.target.status === 'queued')) {
        d.status = 'cancelled';
        d.completedAt = iso;
      }
      recount(record);
      touch(record, iso);
      continue;
    }
    if (d.status === 'queued' && now - Date.parse(d.updatedAt) >= QUEUE_DELAY_MS) {
      const trigger =
        d.trigger === 'late_verdict' || d.trigger === 'threat_intel' ? 'clawback' : 'purge';
      for (const t of record.targets) {
        if (t.target.status !== 'matched') continue;
        const detection = api.detections.find((x) => x.id === t.detectionId);
        if (!detection) continue;
        const action = planned(record, detection);
        if (action === null) {
          t.target.status = 'skipped';
          t.target.reasonCode = 'policy_none';
          continue;
        }
        if (detection.remediationState === 'pending') {
          t.target.status = 'skipped';
          t.target.reasonCode = 'remediation_in_progress';
          continue;
        }
        if (
          detection.remediationState === 'remediated' &&
          strength(detection.remediationAction) >= strength(action)
        ) {
          t.target.status = 'skipped';
          t.target.reasonCode = 'already_remediated';
          continue;
        }
        const queued = queueClawbackAction(organizationId, detection, {
          action,
          trigger,
          clawbackId: d.id,
          userId: record.submitterUserId,
          reason: d.requestReason,
        });
        t.actionId = queued.id;
        t.target.status = 'queued';
        t.target.plannedAction = action;
        t.target.remediationId = queued.id;
        t.target.copyRemediationState = detection.remediationState;
      }
      d.status = 'running';
      d.startedAt = iso;
      recount(record);
      touch(record, iso);
      continue;
    }
    if (d.status === 'running') {
      let changed = false;
      for (const t of record.targets) {
        if (t.target.status !== 'queued' || !t.actionId) continue;
        const action = api.actions.find((a) => a.id === t.actionId);
        const detection = api.detections.find((x) => x.id === t.detectionId);
        if (detection) t.target.copyRemediationState = detection.remediationState;
        if (!action || action.status === 'pending' || action.status === 'in_progress') continue;
        t.target.status =
          action.status === 'succeeded'
            ? 'succeeded'
            : action.status === 'failed'
              ? 'failed'
              : 'cancelled';
        t.target.reasonCode = action.reasonCode;
        changed = true;
      }
      if (
        !record.targets.some((t) => t.target.status === 'queued' || t.target.status === 'matched')
      ) {
        recount(record);
        d.status = d.counts.failed > 0 ? 'completed_with_errors' : 'completed';
        d.completedAt = iso;
        changed = true;
      }
      if (changed) {
        recount(record);
        touch(record, iso);
      }
      continue;
    }
    if (d.restore.status === 'requested' && record.restoreRequest) {
      for (const t of record.targets) {
        if (t.target.status !== 'succeeded') continue;
        const detection = api.detections.find((x) => x.id === t.detectionId);
        if (!detection) continue;
        const action = t.target.plannedAction;
        if (action === 'hard_delete') {
          t.target.restoreStatus = 'skipped';
          t.target.restoreReasonCode = 'not_reversible';
        } else if (action === 'tag') {
          const queued = queueClawbackAction(organizationId, detection, {
            action: 'remove_tag',
            trigger: 'admin',
            clawbackId: d.id,
            userId: userIdOf(record.restoreRequest),
            reason: record.restoreReason,
            reverses: t.actionId,
          });
          t.restoreActionId = queued.id;
          t.target.restoreStatus = 'queued';
        } else if (action && ENTRY_ACTIONS.has(action) && detection.quarantineEntryId) {
          if (detection.verdict === 'malware') {
            t.target.restoreStatus = 'skipped';
            t.target.restoreReasonCode = 'approval_required';
            continue;
          }
          const released = releaseMailboxEntry(
            detection.quarantineEntryId,
            record.restoreRequest,
            record.restoreReason ?? 'Clawback restore',
          );
          const body = released.body as
            { outcome?: string; code?: string; cause?: string } | undefined;
          if (released.status < 300 && body?.outcome === 'queued') {
            t.target.restoreStatus = 'queued';
          } else {
            t.target.restoreStatus = 'skipped';
            t.target.restoreReasonCode =
              body?.outcome === 'approval_requested'
                ? 'approval_required'
                : (body?.cause ?? 'refused');
          }
        } else {
          t.target.restoreStatus = 'skipped';
          t.target.restoreReasonCode = 'entry_missing';
        }
      }
      d.restore.status = 'running';
      record.restoreRequest = null;
      recount(record);
      touch(record, iso);
      continue;
    }
    if (d.restore.status === 'running') {
      let changed = false;
      for (const t of record.targets) {
        if (t.target.restoreStatus !== 'queued') continue;
        const detection = api.detections.find((x) => x.id === t.detectionId);
        if (detection) t.target.copyRemediationState = detection.remediationState;
        if (detection?.remediationState === 'restored') {
          t.target.restoreStatus = 'succeeded';
          changed = true;
        }
      }
      if (!record.targets.some((t) => t.target.restoreStatus === 'queued')) {
        recount(record);
        d.restore.status =
          d.restore.failed > 0 || d.restore.skipped > 0 ? 'completed_with_errors' : 'completed';
        changed = true;
      }
      if (changed) {
        recount(record);
        touch(record, iso);
      }
    }
  }
}

// ---- views -----------------------------------------------------------------------------------

function listView(record: ClawbackRecord): View {
  const {
    criteria: _c,
    signal: _s,
    requestedBy: _r,
    submittedBy: _b,
    requestReason: _q,
    approvalDecision: _a,
    ...view
  } = record.detail;
  return structuredClone(view);
}

function hintsOf(record: ClawbackRecord, request: FixtureRequest): Detail['hints'] {
  const principal = resolveFixturePrincipal(request.token);
  const permissions = principal?.permissions ?? [];
  const purge = permissions.includes('remediation:purge');
  const d = record.detail;
  const me = principal?.userId ?? null;
  const separate = me !== null && me !== record.requesterUserId && me !== record.submitterUserId;
  return {
    canSubmit: purge && (d.status === 'ready' || d.status === 'review_required'),
    canApprove:
      purge &&
      separate &&
      d.status === 'pending_approval' &&
      d.approval.status === 'pending' &&
      (d.approval.expiresAt === null || Date.parse(d.approval.expiresAt) > Date.now()),
    canCancel: purge && ACTIVE.includes(d.status) && d.status !== 'searching' && !d.cancelRequested,
    canRestore:
      purge &&
      permissions.includes('quarantine:release') &&
      ['completed', 'completed_with_errors', 'cancelled'].includes(d.status) &&
      (d.restore.status === 'none' || d.restore.status === 'completed_with_errors') &&
      d.counts.succeeded > 0,
  };
}

function detailView(record: ClawbackRecord, request: FixtureRequest): Detail {
  return { ...structuredClone(record.detail), hints: hintsOf(record, request) };
}

function reportRow(record: ReportRecord): ReportRow {
  const v = record.view;
  return structuredClone({
    id: v.id,
    status: v.status,
    reporterAddress: v.reporterAddress,
    reportedAt: v.reportedAt,
    identification: v.identification,
    assessment: v.assessment,
    analystVerdict: v.analystVerdict,
    scan: v.scan,
    groupSize: v.groupSize,
    clawbackId: v.clawbackId,
    rejectReason: v.rejectReason,
    rowVersion: v.rowVersion,
  });
}

function settingsView(org: OrgState): SuccessBody<'ApiModeSettingsController_get_v1'> {
  return {
    settings: { ...settingsOf(org) },
    source: org.settings ? 'row' : 'defaults',
    rowVersion: org.settings?.rowVersion ?? null,
    updatedAt: org.settings?.updatedAt ?? null,
    defaults: { ...DEFAULTS },
    bounds: structuredClone(BOUNDS),
    platform: { ...PLATFORM },
  };
}

function mailboxView(organizationId: string, org: OrgState, mailboxId: string): MailboxView | null {
  const api = apiModeStateOf(organizationId);
  const m = api.mailboxes.find((x) => x.id === mailboxId);
  if (!m) return null;
  const designated = org.reportMailboxes.get(m.id);
  return {
    id: m.id,
    address: m.address,
    connectionId: m.connectionId,
    provider: 'microsoft_365',
    status: m.status,
    coverage: m.coverage,
    domain: m.domain,
    reportMailbox: designated !== undefined,
    reportMailboxAt: designated?.at ?? null,
    lastReportAt: designated?.lastReportAt ?? null,
  };
}

const clawbackNotFound = () => apiError(404, 'api_mode_clawback_not_found', 'Clawback not found');
const reportNotFound = () => apiError(404, 'api_mode_report_not_found', 'Report not found');
const stateConflict = (record: ClawbackRecord) =>
  apiError(
    409,
    'api_mode_clawback_state_conflict',
    'The clawback is not in a state that allows this, or expectedRowVersion is not its current version',
    {
      status: record.detail.status,
      currentRowVersion: record.detail.rowVersion,
    },
  );

function findClawback(organizationId: string, id: string | undefined): ClawbackRecord | null {
  return orgOf(organizationId).clawbacks.find((c) => c.detail.id === id) ?? null;
}

// ---- create ----------------------------------------------------------------------------------

type CreateBody = Partial<RequestBody<'ApiModeClawbackController_create_v1'>>;

function buildRecord(
  organizationId: string,
  request: FixtureRequest,
  body: CreateBody,
): ClawbackRecord | FixtureResponse {
  const api = apiModeStateOf(organizationId);
  const codes: string[] = [];
  const c = body.criteria ?? {};
  const keys: SearchKeys = { messageIds: [], attachments: [], urls: [], senderSubject: null };
  if (c.messageId !== undefined) {
    if (!normalizeMessageId(c.messageId)) codes.push('message_id_invalid');
    else keys.messageIds.push(messageIdHash(c.messageId));
  }
  for (const h of c.attachmentSha256 ?? []) {
    if (!HEX64.test(h.toLowerCase())) codes.push('not_hex64');
    else keys.attachments.push(h.toLowerCase());
  }
  if (c.url !== undefined) {
    if (!/^https?:\/\/\S+$/i.test(c.url.trim())) codes.push('url_invalid');
    else keys.urls.push(urlHash(c.url));
  }
  if (c.sender !== undefined || c.subject !== undefined) {
    if (c.sender === undefined || c.subject === undefined) codes.push('sender_subject_together');
    else if (!/^[^@\s]+@[^@\s]+$/.test(c.sender.trim())) codes.push('sender_invalid');
    else keys.senderSubject = { sender: c.sender.trim().toLowerCase(), subject: c.subject };
  }
  const seed = body.seedDetectionId
    ? api.detections.find((d) => d.id === body.seedDetectionId)
    : null;
  if (body.seedDetectionId && !seed)
    return apiError(404, 'api_mode_detection_not_found', 'Detection not found');
  const expand = body.expand;
  const expanded = Boolean(
    expand && (expand.attachments || expand.urls || expand.senderSubjectHours),
  );
  if (expand && !seed) codes.push('expand_needs_seed');
  const seedKeys = seed ? copySearchKeys(seed.id) : null;
  if (seed && seedKeys) {
    keys.messageIds.push(messageIdHash(seedKeys.messageId));
    if (expand?.attachments) keys.attachments.push(...seedKeys.attachmentSha256);
    if (expand?.urls) keys.urls.push(...seedKeys.urls.map(urlHash));
    if (expand?.senderSubjectHours)
      keys.senderSubject = { sender: seedKeys.sender, subject: seedKeys.subject };
  }
  let from = c.from;
  let to = c.to;
  const now = Date.now();
  if (from === undefined || to === undefined) {
    if (from !== undefined || to !== undefined) codes.push('window_from_to_together');
    if (!seed) codes.push('window_required');
    else {
      const at = Date.parse(seed.receivedAt);
      const span = expand?.senderSubjectHours ? expand.senderSubjectHours * HOUR : null;
      from = new Date(at - (span ?? DAY)).toISOString();
      to = new Date(Math.min(now, at + (span ?? 7 * DAY))).toISOString();
    }
  }
  if (from && to) {
    const span = Date.parse(to) - Date.parse(from);
    if (span <= 0) codes.push('window_order');
    if (span > PLATFORM.clawbackMaxWindowDays * DAY) codes.push('window_too_long');
    if (Date.parse(from) < now - RETENTION_DAYS * DAY) codes.push('window_before_retention');
    if (keys.senderSubject && !(seed && expanded) && span > 7 * DAY)
      codes.push('sender_subject_window');
  }
  const total =
    keys.messageIds.length +
    keys.attachments.length +
    keys.urls.length +
    (keys.senderSubject ? 1 : 0);
  if (total === 0) codes.push('no_key');
  if (codes.length > 0)
    return apiError(
      422,
      'api_mode_clawback_criteria_invalid',
      'The search criteria are not valid',
      {
        codes: [...new Set(codes)].join(','),
      },
    );
  const id = stableUuid(`clawback:${organizationId}:${Date.now()}:${Math.random()}`);
  return newRecord({
    id,
    trigger: seed && expanded ? 'campaign' : 'admin',
    status: 'searching',
    keys,
    window: { from: from!, to: to! },
    directions:
      body.directions && body.directions.length > 0
        ? [...new Set(body.directions)]
        : ['inbound', 'internal'],
    createdAt: new Date(now).toISOString(),
    requester: userIdOf(request),
    reason: String(body.reason).trim(),
    signal: { seedDetectionId: seed?.id ?? null },
  });
}

// ---- overview blocks (C13) -------------------------------------------------------------------

registerClawbackHooks({
  overview: (organizationId) => {
    const org = orgOf(organizationId);
    const api = apiModeStateOf(organizationId);
    const now = Date.now();
    const within = (iso: string | null) => iso !== null && Date.parse(iso) >= now - DAY;
    const active = org.clawbacks.filter((c) => ACTIVE.includes(c.detail.status));
    const oldest = active.reduce<number | null>(
      (min, c) =>
        min === null
          ? Date.parse(c.detail.createdAt)
          : Math.min(min, Date.parse(c.detail.createdAt)),
      null,
    );
    const done24 = org.clawbacks.filter(
      (c) => FINAL_COUNTED.includes(c.detail.status) && within(c.detail.completedAt),
    );
    const pending = org.reports.filter((r) => r.view.status === 'pending_triage');
    const oldestReport = pending.reduce<number | null>(
      (min, r) =>
        min === null ? Date.parse(r.view.reportedAt) : Math.min(min, Date.parse(r.view.reportedAt)),
      null,
    );
    return {
      internal: {
        copies24h: api.detections.filter((d) => d.direction === 'internal' && within(d.receivedAt))
          .length,
        enabled: settingsOf(org).internalMailEnabled,
      },
      clawback: {
        active: active.length,
        reviewRequired: active.filter((c) => c.detail.status === 'review_required').length,
        pendingApproval: active.filter((c) => c.detail.status === 'pending_approval').length,
        completed24h: done24.length,
        targetsSucceeded24h: done24.reduce((n, c) => n + c.detail.counts.succeeded, 0),
        targetsFailed24h: done24.reduce((n, c) => n + c.detail.counts.failed, 0),
        oldestActiveAgeSeconds: oldest === null ? null : Math.floor((now - oldest) / 1000),
      },
      reports: {
        pendingTriage: pending.length,
        inReview: org.reports.filter((r) => r.view.status === 'in_review').length,
        received24h: org.reports.filter((r) => within(r.view.reportedAt)).length,
        resolved24h: org.reports.filter(
          (r) => r.view.status === 'resolved' && within(r.view.analyst.triagedAt),
        ).length,
        oldestPendingAgeSeconds:
          oldestReport === null ? null : Math.floor((now - oldestReport) / 1000),
        reportMailboxes: org.reportMailboxes.size,
      },
    };
  },
  connection: (organizationId, connectionId) => {
    const org = orgOf(organizationId);
    const api = apiModeStateOf(organizationId);
    const now = Date.now();
    const targets = org.clawbacks
      .flatMap((c) => c.targets)
      .filter(
        (t) =>
          t.target.connectionId === connectionId &&
          Date.parse(t.target.receivedAt) >= now - 30 * DAY,
      );
    const reportsHere = org.reports.filter((r) =>
      api.mailboxes.some(
        (m) => m.id === r.view.reportMailbox.id && m.connectionId === connectionId,
      ),
    );
    return {
      internal: {
        copies24h: api.detections.filter(
          (d) =>
            d.connectionId === connectionId &&
            d.direction === 'internal' &&
            Date.parse(d.receivedAt) >= now - DAY,
        ).length,
        enabled: settingsOf(org).internalMailEnabled,
      },
      clawback: {
        targetsQueued24h: targets.filter((t) => t.target.status === 'queued').length,
        targetsSucceeded24h: targets.filter((t) => t.target.status === 'succeeded').length,
        targetsFailed24h: targets.filter((t) => t.target.status === 'failed').length,
      },
      reports: {
        pendingTriage: reportsHere.filter((r) => r.view.status === 'pending_triage').length,
        inReview: reportsHere.filter((r) => r.view.status === 'in_review').length,
        received24h: reportsHere.filter((r) => Date.parse(r.view.reportedAt) >= now - DAY).length,
        resolved24h: reportsHere.filter((r) => r.view.status === 'resolved').length,
        oldestPendingAgeSeconds: null,
        reportMailboxes: [...org.reportMailboxes.keys()].filter((id) =>
          api.mailboxes.some((m) => m.id === id && m.connectionId === connectionId),
        ).length,
      },
    };
  },
});

// ---- handlers --------------------------------------------------------------------------------

const inList = (q: URLSearchParams, name: string, value: string | null) =>
  !q.get(name) || (q.get(name) ?? '').split(',').includes(value ?? '');

export const fixtures: FixtureHandlers = {
  ApiModeClawbackController_create_v1: guarded(
    'ApiModeClawbackController_create_v1',
    (request, p) =>
      keyed(request, () => {
        const body = (request.body ?? {}) as CreateBody;
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const org = orgOf(p.organizationId);
        const built = buildRecord(p.organizationId, request, body);
        if ('status' in built) return built;
        org.clawbacks.unshift(built);
        return ok(
          'ApiModeClawbackController_create_v1',
          {
            id: built.detail.id,
            status: 'searching',
            trigger: built.detail.trigger,
            rowVersion: built.detail.rowVersion,
          },
          202,
        );
      }),
  ),
  ApiModeClawbackController_list_v1: guarded('ApiModeClawbackController_list_v1', (request, p) => {
    const q = request.query;
    const from = q.get('from') ? Date.parse(q.get('from')!) : Date.now() - 7 * DAY;
    const to = q.get('to') ? Date.parse(q.get('to')!) : Date.now() + HOUR;
    if (to - from > 93 * DAY)
      return apiError(400, 'validation_failed', ['to: range longer than 93 days']);
    const rows = orgOf(p.organizationId)
      .clawbacks.filter((c) => {
        const at = Date.parse(c.detail.createdAt);
        return (
          at >= from &&
          at < to &&
          inList(q, 'status', c.detail.status) &&
          inList(q, 'trigger', c.detail.trigger) &&
          inList(q, 'approvalStatus', c.detail.approval.status)
        );
      })
      .sort((a, b) => b.detail.createdAt.localeCompare(a.detail.createdAt))
      .map(listView);
    return { status: 200, body: paginate(rows, q) };
  }),
  ApiModeClawbackController_detail_v1: guarded(
    'ApiModeClawbackController_detail_v1',
    (request, p) => {
      const record = findClawback(p.organizationId, request.params.clawbackId);
      return record
        ? ok('ApiModeClawbackController_detail_v1', detailView(record, request))
        : clawbackNotFound();
    },
  ),
  ApiModeClawbackController_targets_v1: guarded(
    'ApiModeClawbackController_targets_v1',
    (request, p) => {
      const record = findClawback(p.organizationId, request.params.clawbackId);
      if (!record) return clawbackNotFound();
      const q = request.query;
      const purge = p.permissions.includes('remediation:purge');
      const mask = (address: string) => {
        const [local = '', domain = ''] = address.split('@');
        return `${local.slice(0, 1)}***@${domain}`;
      };
      const rows = record.targets
        .map((t) => t.target)
        .filter(
          (t) =>
            inList(q, 'status', t.status) &&
            inList(q, 'restoreStatus', t.restoreStatus) &&
            inList(q, 'mailboxId', t.mailbox.id),
        )
        .map((t) => ({
          ...structuredClone(t),
          mailbox: {
            id: t.mailbox.id,
            address: purge ? t.mailbox.address : mask(t.mailbox.address),
          },
          headerFrom: purge ? t.headerFrom : null,
          subject: purge ? t.subject : null,
        }));
      return { status: 200, body: paginate(rows, q) };
    },
  ),
  ApiModeClawbackController_submit_v1: guarded(
    'ApiModeClawbackController_submit_v1',
    (request, p) =>
      keyed(request, () => {
        const record = findClawback(p.organizationId, request.params.clawbackId);
        if (!record) return clawbackNotFound();
        const body = (request.body ?? {}) as Partial<{
          mode: 'policy' | 'explicit';
          verdict: string;
          level: string;
          action: string;
          reason: string;
          expectedRowVersion: number;
        }>;
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        if (body.mode !== 'policy' && body.mode !== 'explicit')
          return apiError(400, 'validation_failed', ['mode: policy or explicit']);
        if (
          body.mode === 'explicit' &&
          !['move_quarantine', 'move_junk', 'soft_delete'].includes(String(body.action))
        )
          return apiError(400, 'validation_failed', [
            'action: move_quarantine, move_junk or soft_delete',
          ]);
        const d = record.detail;
        if (
          (d.status !== 'ready' && d.status !== 'review_required') ||
          body.expectedRowVersion !== d.rowVersion
        )
          return stateConflict(record);
        const org = orgOf(p.organizationId);
        const reasons: Detail['approval']['reasons'] = [];
        if (d.counts.mailboxesEligible > settingsOf(org).purgeApprovalMailboxes)
          reasons.push('mailbox_threshold');
        if (d.status === 'review_required' && d.approval.reasons.includes('auto_cap'))
          reasons.push('auto_cap');
        const now = new Date().toISOString();
        d.decisionMode = body.mode;
        d.action = body.mode === 'explicit' ? (body.action as Detail['action']) : null;
        if (
          body.mode === 'policy' &&
          d.trigger !== 'late_verdict' &&
          d.trigger !== 'threat_intel'
        ) {
          d.signal.verdict =
            (body.verdict as Detail['signal']['verdict']) ?? d.signal.verdict ?? 'phishing';
          d.signal.level = (body.level as Detail['signal']['level']) ?? 'critical';
        }
        record.submitterUserId = userIdOf(request);
        d.submittedBy = record.submitterUserId;
        d.submittedAt = now;
        if (!d.requestReason) d.requestReason = String(body.reason).trim();
        const expiresAt = new Date(
          Date.now() + PLATFORM.purgeApprovalTtlHours * HOUR,
        ).toISOString();
        if (reasons.length > 0) {
          d.status = 'pending_approval';
          d.approval = {
            required: true,
            status: 'pending',
            reasons,
            requestedAt: now,
            expiresAt,
            decidedAt: null,
          };
        } else {
          d.status = 'queued';
        }
        touch(record, now);
        return ok(
          'ApiModeClawbackController_submit_v1',
          {
            id: d.id,
            status: d.status === 'queued' ? 'queued' : 'pending_approval',
            requiresApproval: reasons.length > 0,
            approvalReasons: reasons,
            approvalExpiresAt: reasons.length > 0 ? expiresAt : null,
            rowVersion: d.rowVersion,
          },
          202,
        );
      }),
  ),
  ApiModeClawbackController_submitHardDelete_v1: guarded(
    'ApiModeClawbackController_submitHardDelete_v1',
    (request, p) =>
      keyed(request, () => {
        const record = findClawback(p.organizationId, request.params.clawbackId);
        if (!record) return clawbackNotFound();
        const body = (request.body ?? {}) as { reason?: string; expectedRowVersion?: number };
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        if (!PLATFORM.hardDeleteAvailable)
          return apiError(
            422,
            'api_mode_hard_delete_disabled',
            'Hard delete is turned off on this platform',
          );
        return stateConflict(record);
      }),
  ),
  ApiModeClawbackController_approve_v1: guarded(
    'ApiModeClawbackController_approve_v1',
    (request, p) => keyed(request, () => decide(request, p.organizationId, 'approve')),
  ),
  ApiModeClawbackController_deny_v1: guarded('ApiModeClawbackController_deny_v1', (request, p) =>
    keyed(request, () => decide(request, p.organizationId, 'deny')),
  ),
  ApiModeClawbackController_cancel_v1: guarded(
    'ApiModeClawbackController_cancel_v1',
    (request, p) =>
      keyed(request, () => {
        const record = findClawback(p.organizationId, request.params.clawbackId);
        if (!record) return clawbackNotFound();
        const invalid = reasonInvalid((request.body as { reason?: string } | null)?.reason);
        if (invalid) return invalid;
        const d = record.detail;
        const now = new Date().toISOString();
        if (d.status === 'cancelled' || d.cancelRequested)
          return ok('ApiModeClawbackController_cancel_v1', listView(record), 202);
        if (
          d.status === 'ready' ||
          d.status === 'review_required' ||
          d.status === 'pending_approval'
        ) {
          if (d.approval.status === 'pending') {
            d.approval.status = 'cancelled';
            d.approval.decidedAt = now;
          }
          for (const t of record.targets)
            if (t.target.status === 'matched') t.target.status = 'cancelled';
          d.status = 'cancelled';
          d.cancelRequested = true;
          d.completedAt = now;
          recount(record);
        } else if (d.status === 'queued' || d.status === 'running') {
          d.cancelRequested = true;
        } else {
          return apiError(
            409,
            'api_mode_clawback_not_cancellable',
            'The clawback can no longer be cancelled',
            {
              status: d.status,
            },
          );
        }
        touch(record, now);
        return ok('ApiModeClawbackController_cancel_v1', listView(record), 202);
      }),
  ),
  ApiModeClawbackController_restore_v1: guarded(
    'ApiModeClawbackController_restore_v1',
    (request, p) =>
      keyed(request, () => {
        const record = findClawback(p.organizationId, request.params.clawbackId);
        if (!record) return clawbackNotFound();
        const reason = (request.body as { reason?: string } | null)?.reason;
        const invalid = reasonInvalid(reason);
        if (invalid) return invalid;
        const d = record.detail;
        if (
          !['completed', 'completed_with_errors', 'cancelled'].includes(d.status) ||
          !(d.restore.status === 'none' || d.restore.status === 'completed_with_errors') ||
          d.counts.succeeded === 0
        )
          return apiError(
            409,
            'api_mode_clawback_not_restorable',
            'Only a completed or cancelled clawback without a restore can be restored',
            {
              status: d.status,
              restoreStatus: d.restore.status,
            },
          );
        d.restore.status = 'requested';
        record.restoreRequest = request;
        record.restoreReason = String(reason).trim();
        for (const t of record.targets)
          if (t.target.restoreStatus === 'failed' || t.target.restoreStatus === 'skipped') {
            t.target.restoreStatus = 'none';
            t.target.restoreReasonCode = null;
          }
        touch(record);
        return ok('ApiModeClawbackController_restore_v1', listView(record), 202);
      }),
  ),

  // ---- reports (C14 #11–#17) -----------------------------------------------------------------
  ApiModeReportsController_list_v1: guarded('ApiModeReportsController_list_v1', (request, p) => {
    const q = request.query;
    const from = q.get('from') ? Date.parse(q.get('from')!) : Date.now() - 7 * DAY;
    const to = q.get('to') ? Date.parse(q.get('to')!) : Date.now() + HOUR;
    const reporter = q.get('reporter')?.toLowerCase();
    const rows = orgOf(p.organizationId)
      .reports.filter((r) => {
        const at = Date.parse(r.view.reportedAt);
        return (
          at >= from &&
          at < to &&
          inList(q, 'status', r.view.status) &&
          inList(q, 'assessment', r.view.assessment) &&
          inList(q, 'analystVerdict', r.view.analystVerdict) &&
          (!reporter || r.view.reporterAddress === reporter)
        );
      })
      .sort((a, b) => b.view.reportedAt.localeCompare(a.view.reportedAt))
      .map(reportRow);
    return { status: 200, body: paginate(rows, q) };
  }),
  ApiModeReportsController_detail_v1: guarded(
    'ApiModeReportsController_detail_v1',
    (request, p) => {
      const record = orgOf(p.organizationId).reports.find(
        (r) => r.view.id === request.params.reportId,
      );
      return record
        ? ok('ApiModeReportsController_detail_v1', structuredClone(record.view))
        : reportNotFound();
    },
  ),
  ApiModeReportsController_triage_v1: guarded('ApiModeReportsController_triage_v1', (request, p) =>
    keyed(request, () => {
      const org = orgOf(p.organizationId);
      const record = org.reports.find((r) => r.view.id === request.params.reportId);
      if (!record) return reportNotFound();
      const body = (request.body ?? {}) as Partial<
        RequestBody<'ApiModeReportsController_triage_v1'>
      >;
      const v = record.view;
      if (!['in_review', 'resolved', 'rejected'].includes(String(body.status)))
        return apiError(400, 'validation_failed', ['status: in_review, resolved or rejected']);
      if (body.status === 'resolved' && !body.verdict)
        return apiError(400, 'validation_failed', ['verdict: required to resolve']);
      if (typeof body.note === 'string' && body.note.length > 1000)
        return apiError(400, 'validation_failed', ['note: at most 1000 characters']);
      const conflict = () =>
        apiError(
          409,
          'api_mode_report_state_conflict',
          'The report is not in a state that allows this triage',
          {
            status: v.status,
            currentRowVersion: v.rowVersion,
          },
        );
      if (body.expectedRowVersion !== v.rowVersion) return conflict();
      let reopened = false;
      if (body.status === 'in_review') {
        if (v.status === 'resolved') {
          if (record.reopened)
            return apiError(
              409,
              'api_mode_report_not_reopenable',
              'A resolved report can be reopened only once',
            );
          reopened = true;
        } else if (v.status !== 'pending_triage') return conflict();
      } else if (body.status === 'resolved') {
        if (v.status !== 'pending_triage' && v.status !== 'in_review') return conflict();
      } else if (!['received', 'parsing', 'pending_triage', 'in_review'].includes(v.status))
        return conflict();
      const settings = settingsOf(org);
      const notify =
        body.status === 'resolved' && (body.notifyReporter ?? settings.reportFeedbackEnabled);
      const applyToGroup = body.status === 'resolved' && (body.applyToGroup ?? true);
      const key = groupOf(record);
      const group =
        applyToGroup && key !== null
          ? org.reports.filter(
              (r) =>
                groupOf(r) === key &&
                (r === record ||
                  r.view.status === 'pending_triage' ||
                  r.view.status === 'in_review'),
            )
          : [record];
      const now = new Date().toISOString();
      const userId = userIdOf(request);
      let feedbackQueued = 0;
      for (const r of group) {
        const from = r.view.status;
        r.view.status = body.status as ReportView['status'];
        r.view.rowVersion += 1;
        r.view.updatedAt = now;
        if (reopened && r === record) r.reopened = true;
        if (body.status === 'resolved') {
          r.view.analystVerdict = body.verdict!;
          r.view.analyst = {
            verdict: body.verdict!,
            note: body.note?.trim() || null,
            triagedBy: userId,
            triagedAt: now,
          };
          if (notify) {
            r.view.feedback.result = 'queued';
            feedbackQueued += 1;
          }
        } else if (body.status === 'rejected') {
          r.view.rejectReason = 'analyst_rejected';
          r.view.analyst = {
            ...r.view.analyst,
            note: body.note?.trim() || null,
            triagedBy: userId,
            triagedAt: now,
          };
        } else if (reopened) {
          r.view.analystVerdict = null;
          r.view.analyst = { ...r.view.analyst, verdict: null };
        }
        r.view.history.push({
          at: now,
          actor: { type: 'user', userId },
          from,
          to: r.view.status,
          verdict: body.status === 'resolved' ? body.verdict! : null,
          reopened: reopened && r === record,
        });
      }
      refreshGroups(org);
      return ok('ApiModeReportsController_triage_v1', {
        report: reportRow(record),
        groupResolved: body.status === 'resolved' ? group.length : 0,
        feedbackQueued,
      });
    }),
  ),
  ApiModeReportsController_clawback_v1: guarded(
    'ApiModeReportsController_clawback_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgOf(p.organizationId);
        const record = org.reports.find((r) => r.view.id === request.params.reportId);
        if (!record) return reportNotFound();
        const body = (request.body ?? {}) as Partial<
          RequestBody<'ApiModeReportsController_clawback_v1'>
        >;
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const original = record.view.original;
        const detection =
          record.originalDetectionIndex === null
            ? null
            : (apiModeStateOf(p.organizationId).detections[record.originalDetectionIndex] ?? null);
        const keys = detection ? copySearchKeys(detection.id) : null;
        if (
          !original ||
          !keys ||
          (!original.messageIdHash && !(original.sender && original.subjectKey))
        )
          return apiError(
            409,
            'api_mode_report_original_unknown',
            'The reported message was not identified',
          );
        const expand = body.expand;
        const expanded = Boolean(
          expand && (expand.attachments || expand.urls || expand.senderSubjectHours),
        );
        const searchKeys: SearchKeys = {
          messageIds: original.messageIdHash ? [messageIdHash(keys.messageId)] : [],
          attachments: expand?.attachments ? [...keys.attachmentSha256] : [],
          urls: expand?.urls ? keys.urls.map(urlHash) : [],
          senderSubject:
            !original.messageIdHash || expand?.senderSubjectHours
              ? { sender: keys.sender, subject: keys.subject }
              : null,
        };
        const at = Date.parse(original.date ?? record.view.reportedAt);
        const hours = expand?.senderSubjectHours ?? 72;
        const now = Date.now();
        const clawback = newRecord({
          id: stableUuid(`clawback:report:${record.view.id}:${now}`),
          trigger: expanded ? 'campaign' : 'report',
          status: 'searching',
          keys: searchKeys,
          window: {
            from: new Date(at - hours * HOUR).toISOString(),
            to: new Date(Math.min(now, at + hours * HOUR)).toISOString(),
          },
          createdAt: new Date(now).toISOString(),
          requester: userIdOf(request),
          reason: String(body.reason).trim(),
          reportId: record.view.id,
          signal: {
            kind: expanded ? 'campaign' : 'report',
            verdict: record.view.analystVerdict === 'malicious' ? 'phishing' : null,
            level: record.view.analystVerdict === 'malicious' ? 'critical' : null,
          },
        });
        org.clawbacks.unshift(clawback);
        record.view.clawbackId = clawback.detail.id;
        record.view.rowVersion += 1;
        return ok(
          'ApiModeReportsController_clawback_v1',
          {
            reportId: record.view.id,
            clawbackId: clawback.detail.id,
            status: 'searching',
            trigger: expanded ? 'campaign' : 'report',
          },
          202,
        );
      }),
  ),
  ApiModeReportsController_listMailboxes_v1: guarded(
    'ApiModeReportsController_listMailboxes_v1',
    (_request, p) => {
      const org = orgOf(p.organizationId);
      return ok('ApiModeReportsController_listMailboxes_v1', {
        data: [...org.reportMailboxes.keys()]
          .map((id) => mailboxView(p.organizationId, org, id))
          .filter((m): m is MailboxView => m !== null),
        max: PLATFORM.reportMailboxesMax,
      });
    },
  ),
  ApiModeReportsController_addMailbox_v1: guarded(
    'ApiModeReportsController_addMailbox_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgOf(p.organizationId);
        const body = (request.body ?? {}) as { address?: string; reason?: string };
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        const address = (body.address ?? '').trim().toLowerCase();
        if (!/^[^@\s]+@[^@\s]+$/.test(address))
          return apiError(400, 'validation_failed', ['address: an e-mail address']);
        const api = apiModeStateOf(p.organizationId);
        let mailbox = api.mailboxes.find(
          (m) => m.address === address || m.aliases.includes(address),
        );
        let created = false;
        if (!mailbox) {
          const domain = apiModeDomainsOf(p.organizationId).find((d) =>
            address.endsWith(`@${d.name}`),
          );
          if (!domain)
            return apiError(
              422,
              'api_mode_report_address_out_of_scope',
              'The address is not a mailbox of an API-mode domain',
            );
          mailbox = addDiscoveredMailbox(p.organizationId, address, domain);
          created = true;
        }
        const changed = !org.reportMailboxes.has(mailbox.id);
        if (changed && org.reportMailboxes.size >= PLATFORM.reportMailboxesMax)
          return apiError(
            409,
            'api_mode_report_mailbox_limit',
            'The organization already has the most report mailboxes allowed',
            {
              max: PLATFORM.reportMailboxesMax,
            },
          );
        if (changed)
          org.reportMailboxes.set(mailbox.id, { at: new Date().toISOString(), lastReportAt: null });
        return ok('ApiModeReportsController_addMailbox_v1', {
          mailbox: mailboxView(p.organizationId, org, mailbox.id)!,
          created,
          changed,
        });
      }),
  ),
  ApiModeReportsController_setMailbox_v1: guarded(
    'ApiModeReportsController_setMailbox_v1',
    (request, p) =>
      keyed(request, () => {
        const org = orgOf(p.organizationId);
        const body = (request.body ?? {}) as { enabled?: boolean; reason?: string };
        const invalid = reasonInvalid(body.reason);
        if (invalid) return invalid;
        if (typeof body.enabled !== 'boolean')
          return apiError(400, 'validation_failed', ['enabled: a boolean']);
        const mailbox = apiModeStateOf(p.organizationId).mailboxes.find(
          (m) => m.id === request.params.mailboxId,
        );
        if (!mailbox) return apiError(404, 'api_mode_mailbox_not_found', 'Mailbox not found');
        if (body.enabled && mailbox.status === 'deleted')
          return apiError(409, 'api_mode_report_mailbox_not_eligible', 'The mailbox is deleted', {
            cause: 'mailbox_deleted',
          });
        const has = org.reportMailboxes.has(mailbox.id);
        if (body.enabled && !has && org.reportMailboxes.size >= PLATFORM.reportMailboxesMax)
          return apiError(
            409,
            'api_mode_report_mailbox_limit',
            'The organization already has the most report mailboxes allowed',
            {
              max: PLATFORM.reportMailboxesMax,
            },
          );
        const changed = body.enabled !== has;
        if (body.enabled && !has)
          org.reportMailboxes.set(mailbox.id, { at: new Date().toISOString(), lastReportAt: null });
        if (!body.enabled) org.reportMailboxes.delete(mailbox.id);
        return ok('ApiModeReportsController_setMailbox_v1', {
          mailbox: mailboxView(p.organizationId, org, mailbox.id)!,
          created: false,
          changed,
        });
      }),
  ),

  // ---- settings (C14 #18, #19) ---------------------------------------------------------------
  ApiModeSettingsController_get_v1: guarded('ApiModeSettingsController_get_v1', (_request, p) =>
    ok('ApiModeSettingsController_get_v1', settingsView(orgOf(p.organizationId))),
  ),
  ApiModeSettingsController_put_v1: guarded('ApiModeSettingsController_put_v1', (request, p) =>
    keyed(request, () => {
      const org = orgOf(p.organizationId);
      const body = (request.body ?? {}) as Partial<RequestBody<'ApiModeSettingsController_put_v1'>>;
      const invalid = reasonInvalid(body.reason);
      if (invalid) return invalid;
      const issues: string[] = [];
      for (const [key, b] of Object.entries(BOUNDS)) {
        const value = body[key as keyof typeof BOUNDS];
        if (!Number.isInteger(value) || (value as number) < b.min || (value as number) > b.max)
          issues.push(`${key}: ${b.min} to ${b.max}`);
      }
      for (const key of [
        'internalMailEnabled',
        'reportAckEnabled',
        'reportFeedbackEnabled',
      ] as const)
        if (typeof body[key] !== 'boolean') issues.push(`${key}: a boolean`);
      if (!['enforce', 'review', 'off'].includes(String(body.autoClawback)))
        issues.push('autoClawback: enforce, review or off');
      if (issues.length > 0) return apiError(400, 'validation_failed', issues);
      const current = org.settings?.rowVersion ?? null;
      if (body.expectedRowVersion !== current)
        return apiError(
          409,
          'api_mode_settings_conflict',
          'expectedRowVersion is not the current version',
          {
            currentRowVersion: current,
          },
        );
      const before = settingsOf(org);
      const next: Settings = {
        internalMailEnabled: body.internalMailEnabled!,
        autoClawback: body.autoClawback!,
        autoMaxMailboxes: body.autoMaxMailboxes!,
        purgeApprovalMailboxes: body.purgeApprovalMailboxes!,
        clawbackLookbackDays: body.clawbackLookbackDays!,
        tiMinConfidence: body.tiMinConfidence!,
        reportAckEnabled: body.reportAckEnabled!,
        reportFeedbackEnabled: body.reportFeedbackEnabled!,
      };
      const changed = (Object.keys(next) as Array<keyof Settings>).filter(
        (k) => next[k] !== before[k],
      );
      const created = org.settings === null;
      org.settings = {
        settings: next,
        rowVersion: (current ?? 0) + 1,
        updatedAt: new Date().toISOString(),
      };
      return ok('ApiModeSettingsController_put_v1', { ...settingsView(org), changed, created });
    }),
  ),
};

function decide(
  request: FixtureRequest,
  organizationId: string,
  decision: 'approve' | 'deny',
): FixtureResponse {
  const record = findClawback(organizationId, request.params.clawbackId);
  if (!record) return clawbackNotFound();
  const body = (request.body ?? {}) as { reason?: string; expectedRowVersion?: number };
  const invalid = reasonInvalid(body.reason);
  if (invalid) return invalid;
  const d = record.detail;
  const expired = d.approval.expiresAt !== null && Date.parse(d.approval.expiresAt) <= Date.now();
  if (d.status !== 'pending_approval' || d.approval.status !== 'pending' || expired)
    return apiError(
      409,
      'api_mode_purge_approval_not_pending',
      'The clawback has no pending approval request',
      {
        reason: expired ? 'expired' : 'not_pending',
      },
    );
  const me = userIdOf(request);
  if (me === null || me === record.requesterUserId || me === record.submitterUserId)
    return apiError(
      403,
      'api_mode_purge_approval_forbidden',
      'A purge is approved or denied by another user',
      {
        reason: 'requester',
      },
    );
  if (body.expectedRowVersion !== d.rowVersion) return stateConflict(record);
  const now = new Date().toISOString();
  d.approval.status = decision === 'approve' ? 'approved' : 'denied';
  d.approval.decidedAt = now;
  d.approvalDecision = { decidedBy: me, reason: String(body.reason).trim() };
  if (decision === 'approve') d.status = 'queued';
  else {
    d.status = 'denied';
    d.completedAt = now;
  }
  touch(record, now);
  return ok(
    decision === 'approve'
      ? 'ApiModeClawbackController_approve_v1'
      : 'ApiModeClawbackController_deny_v1',
    listView(record),
  );
}
