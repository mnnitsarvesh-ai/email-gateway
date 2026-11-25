import 'server-only';
import type { ListItem, RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, fixtureAnchor, paginate, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandler,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { maskAddress } from './message-dataset';
import { fixtureGuard } from './messages';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the compliance pages of step 8.1 (WP5): all 41 archive and eDiscovery
 * operations (§4.4) over an in-memory archive per organization, on globalThis (shared by the
 * separately bundled BFF route handlers of `next dev`). The rules of the api that the pages
 * depend on are kept: masking for every caller and reveal only with `message:reveal`,
 * reveal-gated and hold-gated filters (`403 archive_filter_forbidden`), required ranges, MFA
 * routes (`403 mfa_required`), content refused under a platform override, CAS conflicts with
 * `currentRowVersion`, required Idempotency-Key with replays, immutability downgrade refusal,
 * the malicious download block, single-use download tokens, the export acknowledgement, search
 * and export jobs that complete a few seconds later (with completeness flags), review bounds.
 * Content is synthetic text with `EXAMPLE` placeholders; nothing is real and nothing is
 * decrypted.
 */

export const ARCHIVE_OPERATIONS = [
  'ArchiveAdminController_get_v1',
  'ArchiveAdminController_update_v1',
  'ArchiveRetentionController_list_v1',
  'ArchiveRetentionController_create_v1',
  'ArchiveRetentionController_get_v1',
  'ArchiveRetentionController_update_v1',
  'ArchiveRetentionController_delete_v1',
  'ArchiveAdminController_listKeys_v1',
  'ArchiveAdminController_rotate_v1',
  'ArchiveAdminController_status_v1',
  'ArchiveAdminController_captureIssues_v1',
  'ArchiveAdminController_captureIssue_v1',
  'ArchiveAdminController_retry_v1',
  'ArchiveAdminController_disposals_v1',
  'ArchiveAdminController_signingKeys_v1',
  'ArchiveMessagesController_list_v1',
  'ArchiveMessagesController_detail_v1',
  'ArchiveMessagesController_journal_v1',
  'ArchiveMessagesController_security_v1',
  'ArchiveMessagesController_reveal_v1',
  'ArchiveMessagesController_preview_v1',
  'ArchiveMessagesController_grant_v1',
  'ArchiveDownloadsController_download_v1',
  'ArchiveMessagesController_dispose_v1',
  'LegalHoldsController_list_v1',
  'LegalHoldsController_get_v1',
  'LegalHoldsController_release_v1',
  'EdiscoveryCasesController_createHold_v1',
  'EdiscoveryCasesController_list_v1',
  'EdiscoveryCasesController_create_v1',
  'EdiscoveryCasesController_get_v1',
  'EdiscoveryCasesController_update_v1',
  'EdiscoveryCasesController_close_v1',
  'EdiscoverySearchesController_create_v1',
  'EdiscoverySearchesController_list_v1',
  'EdiscoverySearchesController_get_v1',
  'EdiscoverySearchesController_hits_v1',
  'EdiscoverySearchesController_review_v1',
  'EdiscoveryExportsController_create_v1',
  'EdiscoveryExportsController_list_v1',
  'EdiscoveryExportsController_get_v1',
  'EdiscoveryExportsController_grant_v1',
] as const;

type Settings = SuccessBody<'ArchiveAdminController_get_v1'>;
type Policy = SuccessBody<'ArchiveRetentionController_get_v1'>;
type Key = ListItem<'ArchiveAdminController_listKeys_v1'>;
type Issue = ListItem<'ArchiveAdminController_captureIssues_v1'>;
type Disposal = ListItem<'ArchiveAdminController_disposals_v1'>;
type Detail = SuccessBody<'ArchiveMessagesController_detail_v1'>;
type Summary = ListItem<'ArchiveMessagesController_list_v1'>;
type Hold = SuccessBody<'LegalHoldsController_get_v1'>;
type Case = SuccessBody<'EdiscoveryCasesController_get_v1'>;
type Search = SuccessBody<'EdiscoverySearchesController_get_v1'>;
type Hit = ListItem<'EdiscoverySearchesController_hits_v1'>;
type Export = SuccessBody<'EdiscoveryExportsController_get_v1'>;
type ReviewTag = Hit['reviewTag'];

interface Record_ {
  detail: Detail;
  subject: string;
  recipients: string[];
}
interface SearchRecord {
  search: Search;
  hits: Hit[];
  readyAt: number;
}
interface ExportRecord {
  export: Export;
  readyAt: number;
}
interface OrgArchive {
  settings: Settings;
  policies: Map<string, Policy & { deleted?: boolean }>;
  keys: Key[];
  issues: Issue[];
  disposals: Disposal[];
  records: Map<string, Record_>;
  holds: Map<string, Hold>;
  cases: Map<string, Case>;
  searches: Map<string, SearchRecord>;
  exports: Map<string, ExportRecord>;
  grants: Map<string, { userId: string; used: boolean; expiresAt: number; filename: string }>;
  idempotency: Map<string, { fingerprint: string; response: FixtureResponse }>;
  reveals: number[];
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
/** Search and export jobs complete this long after they were queued. */
export const FIXTURE_JOB_DELAY_MS = 4_000;
/** Reveals per minute and principal (`ARCHIVE_REVEAL_PER_MINUTE` scaled down). */
export const FIXTURE_REVEAL_PER_MINUTE = 30;
const SIGNING_KEY_ID = 'eg-export-EXAMPLE-1';

const sha = (seed: string) =>
  Array.from({ length: 2 }, (_, i) => stableUuid(`${seed}:${i}`).replace(/-/g, ''))
    .join('')
    .slice(0, 64);
const iso = (ms: number) => new Date(ms).toISOString();

function summaryOf(detail: Detail): Summary {
  return {
    messageId: detail.messageId,
    receivedAt: detail.receivedAt,
    capturedAt: detail.capturedAt,
    direction: detail.direction,
    category: detail.category,
    sources: detail.sources,
    ingestSources: detail.ingestSources,
    status: detail.status,
    envelopeFrom: detail.envelopeFrom,
    headerFrom: detail.headerFrom,
    recipients: detail.recipients,
    recipientsTruncated: detail.recipientsTruncated,
    subject: null,
    subjectMasked: detail.subjectMasked,
    sizeBytes: detail.sizeBytes,
    attachmentCount: detail.attachmentCount,
    attachmentNames: detail.attachmentNames,
    verdict: detail.verdict,
    finalAction: detail.finalAction,
    riskScore: detail.riskScore,
    malicious: detail.malicious,
    retainUntil: detail.retainUntil,
    legalHold: detail.legalHold,
    lockMode: detail.lockMode,
  };
}

const SUBJECTS = [
  'EXAMPLE Quarterly budget review',
  'EXAMPLE Contract renewal draft',
  'EXAMPLE Board meeting minutes',
  'EXAMPLE Invoice 4471',
  'EXAMPLE Shipping confirmation',
  'EXAMPLE Password reset request',
];
const PEOPLE = ['alex.lee', 'sam.patel', 'jordan.kim', 'priya.rao', 'chen.silva', 'maria.novak'];

function buildOrg(organizationId: string): OrgArchive {
  const random = new SeededRandom(`archive:${organizationId}`);
  const anchor = fixtureAnchor();
  const policyDefault: Policy = {
    id: stableUuid(`${organizationId}:retention:default`),
    name: 'Default seven years',
    retentionDays: 2555,
    onExpiry: 'delete',
    priority: 1000,
    criteria: {},
    isDefault: false,
    rowVersion: 1,
    createdAt: iso(anchor - 90 * DAY),
    updatedAt: iso(anchor - 90 * DAY),
  };
  const policyReview: Policy = {
    id: stableUuid(`${organizationId}:retention:review`),
    name: 'Outbound mail, review at expiry',
    retentionDays: 365,
    onExpiry: 'review',
    priority: 10,
    criteria: { directions: ['outbound'] },
    isDefault: false,
    rowVersion: 2,
    createdAt: iso(anchor - 60 * DAY),
    updatedAt: iso(anchor - 30 * DAY),
  };
  const policies = new Map<string, Policy>([
    [policyDefault.id, policyDefault],
    [policyReview.id, policyReview],
  ]);
  const settings: Settings = {
    enabled: true,
    entitled: true,
    immutability: 'governance',
    objectLockAvailable: true,
    defaultRetentionPolicyId: policyDefault.id,
    settings: {
      directions: { inbound: true, outbound: true, internal: true },
      include: { rejected: false, quarantined: true, failed: false },
      scope: { mode: 'all', domainIds: [], departmentIds: [], userIds: [], addresses: [] },
      policyArchive: { enabled: true },
      access: { previewEnabled: true, downloadEnabled: true },
      intake: { scanEnabled: false },
    },
    generation: 4,
    journalEnabledAt: iso(anchor - 90 * DAY),
    rowVersion: 4,
    updatedAt: iso(anchor - 30 * DAY),
  };
  const keys: Key[] = [
    {
      id: stableUuid(`${organizationId}:key:2`),
      version: 2,
      status: 'active',
      rootKeyId: 'root-EXAMPLE-1',
      algorithm: 'AES-256-GCM',
      rotationReason: 'EXAMPLE annual rotation',
      createdBy: stableUuid(`${organizationId}:user:admin`),
      createdAt: iso(anchor - 20 * DAY),
      activatedAt: iso(anchor - 20 * DAY),
      retiredAt: null,
      destroyedAt: null,
    },
    {
      id: stableUuid(`${organizationId}:key:1`),
      version: 1,
      status: 'retired',
      rootKeyId: 'root-EXAMPLE-1',
      algorithm: 'AES-256-GCM',
      rotationReason: null,
      createdBy: null,
      createdAt: iso(anchor - 90 * DAY),
      activatedAt: iso(anchor - 90 * DAY),
      retiredAt: iso(anchor - 20 * DAY),
      destroyedAt: null,
    },
  ];
  const records = new Map<string, Record_>();
  const holdId = stableUuid(`${organizationId}:hold:board`);
  const caseId = stableUuid(`${organizationId}:case:board`);
  const domain = 'corp.example.test';
  for (let i = 0; i < 60; i += 1) {
    const messageId = stableUuid(`${organizationId}:archive:${i}`);
    const receivedMs = anchor - Math.floor(random.next() * 60 * DAY) - i * 60_000;
    const direction = random.pick(['inbound', 'outbound', 'internal'] as const);
    const malicious = i % 17 === 5;
    const review = i % 13 === 3;
    const person = random.pick(PEOPLE);
    const external = `${random.pick(PEOPLE)}@partner.example.test`;
    const internal = `${person}@${domain}`;
    const from = direction === 'inbound' ? external : internal;
    const recipients =
      direction === 'outbound'
        ? [external]
        : [internal, ...(i % 4 === 0 ? [`team@${domain}`] : [])];
    const subject = random.pick(SUBJECTS);
    const held = i % 9 === 0;
    const verdict = malicious
      ? 'phishing'
      : random.pick(['clean', 'clean', 'spam', 'bulk'] as const);
    const policy = direction === 'outbound' ? policyReview : policyDefault;
    const retainUntil = review
      ? iso(anchor - 2 * DAY)
      : iso(receivedMs + policy.retentionDays * DAY);
    const attachments = i % 3 === 0 ? ['EXAMPLE-report.pdf'] : [];
    // Step 8.6: every 7th record arrived only through journal intake, every 7th + 2 was captured
    // by the gateway and a journal intake copy was merged into it (every 14th + 4 with a
    // differing body stored as a content variant).
    const intakeOnly = i % 7 === 2;
    const merged = i % 7 === 4;
    const ingestSources: Detail['ingestSources'] = intakeOnly
      ? ['journal_intake']
      : merged
        ? ['gateway', 'journal_intake']
        : ['gateway'];
    const intake: Detail['intake'] =
      intakeOnly || merged
        ? {
            kind: 'microsoft_365_journal',
            sourceId: stableUuid(`${organizationId}:intake:m365`),
            sourceDisplayName: 'EXAMPLE Microsoft 365 journal',
          }
        : null;
    const mergedCopies: Detail['mergedCopies'] = merged
      ? [
          {
            id: stableUuid(`${messageId}:merged:1`),
            source: 'journal_intake',
            receivedAt: iso(receivedMs + 45_000),
            mergedAt: iso(receivedMs + 150_000),
            sizeBytes: 4096 + i * 37 + 211,
            sha256: sha(`${messageId}:merged:1`),
            contentVariant: i % 14 === 4,
            recipientsAdded: 1,
          },
        ]
      : [];
    const detail: Detail = {
      messageId,
      receivedAt: iso(receivedMs),
      capturedAt: iso(receivedMs + 90_000),
      direction,
      category: i % 11 === 7 && !intakeOnly ? 'quarantined' : 'delivered',
      sources: i % 5 === 0 && !intakeOnly ? ['journal', 'policy'] : ['journal'],
      ingestSources,
      intake,
      mergedCopies,
      status: review ? 'expiry_review' : 'active',
      envelopeFrom: from,
      headerFrom: from,
      recipients: recipients.map(maskAddress),
      recipientsTruncated: false,
      subject: null,
      subjectMasked: true,
      sizeBytes: 4096 + i * 37,
      attachmentCount: attachments.length,
      attachmentNames: attachments,
      verdict,
      finalAction: malicious ? 'quarantine' : 'deliver',
      riskScore: malicious ? 910 : random.int(20, 420),
      malicious,
      retainUntil,
      legalHold: held,
      lockMode: 'governance',
      internetMessageId: `<${messageId}@EXAMPLE.mail.example.test>`,
      parties: {
        envelopeFrom: from,
        headerFrom: from,
        recipients: [
          ...recipients.map((address, seq) => ({
            seq,
            address: maskAddress(address),
            direction,
            status: intakeOnly ? 'journaled' : 'delivered',
            finalAction: intakeOnly ? null : 'deliver',
            ...(intake ? { field: 'to' as const, ingestSources } : {}),
          })),
          ...(intake
            ? [
                {
                  seq: recipients.length,
                  address: maskAddress(`legal.review@${domain}`),
                  direction: 'internal' as const,
                  status: 'journaled',
                  finalAction: null,
                  field: 'bcc' as const,
                  ingestSources: ['journal_intake' as const],
                },
              ]
            : []),
        ],
        recipientCount: recipients.length + (intake ? 1 : 0),
        recipientsTruncated: false,
      },
      capture: {
        capturedAt: iso(receivedMs + 90_000),
        sources: {
          journal: true,
          policy: i % 5 === 0,
          policyRuleRef: i % 5 === 0 ? 'EXAMPLE-policy#1/archive' : null,
        },
        messageState: intakeOnly ? 'journaled' : 'delivered',
        messageStateReason: intakeOnly ? 'intake_unscanned' : 'delivery_complete',
        settingsGeneration: 3,
        outcomeRefreshedAt: null,
      },
      retention: {
        policyId: policy.id,
        policyName: policy.name,
        retainUntil,
        effectiveRetainUntil: retainUntil,
        expiryAction: policy.onExpiry,
      },
      holds: held ? [{ id: holdId, name: 'EXAMPLE board investigation', caseId }] : [],
      immutability: { lockMode: 'governance', lockUntil: retainUntil },
      integrity: {
        sha256: sha(`${messageId}:eml`),
        sizeBytes: 4096 + i * 37,
        storedBytes: 4096 + i * 37 + 512,
        encryptionFormat: 'archive-object/1',
        keyVersion: receivedMs > anchor - 20 * DAY ? 2 : 1,
      },
      rounds: [{ round: 0, revision: 0, frozenAt: iso(receivedMs + 90_000) }],
    };
    records.set(messageId, { detail, subject, recipients });
  }
  const recordIds = [...records.keys()];
  const hold: Hold = {
    id: holdId,
    caseId,
    name: 'EXAMPLE board investigation',
    reason: 'EXAMPLE litigation notice',
    status: 'active',
    criteria: {
      custodians: [`priya.rao@${domain}`, `alex.lee@${domain}`],
      from: iso(anchor - 120 * DAY).slice(0, 10),
      directions: ['inbound', 'outbound', 'internal'],
    },
    criteriaVersion: 'archive-hold/1',
    createdBy: stableUuid(`${organizationId}:user:admin`),
    createdAt: iso(anchor - 10 * DAY),
    releasedAt: null,
    releasedBy: null,
    releaseReason: null,
    rowVersion: 1,
  };
  const legacy: Hold = {
    id: stableUuid(`${organizationId}:hold:legacy`),
    caseId: null,
    name: 'EXAMPLE legacy hold (step 5.3)',
    reason: 'EXAMPLE legacy reason',
    status: 'released',
    criteria: {},
    criteriaVersion: null,
    createdBy: null,
    createdAt: iso(anchor - 200 * DAY),
    releasedAt: iso(anchor - 100 * DAY),
    releasedBy: null,
    releaseReason: 'EXAMPLE matter closed',
    rowVersion: 2,
  };
  const theCase: Case = {
    id: caseId,
    name: 'EXAMPLE board investigation',
    description: 'EXAMPLE internal review of board communications.',
    matterReference: 'EXAMPLE-2026-014',
    status: 'open',
    rowVersion: 3,
    createdBy: stableUuid(`${organizationId}:user:admin`),
    createdAt: iso(anchor - 12 * DAY),
    updatedAt: iso(anchor - 10 * DAY),
    closedAt: null,
    custodians: [`priya.rao@${domain}`, `alex.lee@${domain}`].map((address) => ({
      id: stableUuid(`${caseId}:${address}`),
      address,
      userId: null,
    })),
    counts: { custodians: 2, activeHolds: 1, searches: 1, exports: 1 },
  };
  const searchId = stableUuid(`${organizationId}:search:1`);
  const hits: Hit[] = recordIds.slice(0, 18).map((id, i) => {
    const record = records.get(id)!;
    return {
      messageId: id,
      receivedAt: record.detail.receivedAt,
      reviewTag: i < 4 ? 'relevant' : i === 4 ? 'privileged' : 'untagged',
      reviewedBy: i < 5 ? stableUuid(`${organizationId}:user:admin`) : null,
      reviewedAt: i < 5 ? iso(anchor - 2 * DAY) : null,
      message: summaryOf(record.detail),
    };
  });
  const search: Search = {
    id: searchId,
    caseId,
    status: 'completed',
    criteria: {
      from: iso(anchor - 365 * DAY).slice(0, 10),
      to: iso(anchor).slice(0, 10),
      custodians: 'case',
    },
    criteriaSha256: sha(`${searchId}:criteria`),
    hitCount: hits.length,
    truncated: false,
    indexComplete: false,
    incompleteReason: 'unverified_days',
    errorCode: null,
    requestedBy: stableUuid(`${organizationId}:user:admin`),
    createdAt: iso(anchor - 3 * DAY),
    startedAt: iso(anchor - 3 * DAY + 2_000),
    completedAt: iso(anchor - 3 * DAY + 9_000),
  };
  const exportId = stableUuid(`${organizationId}:export:1`);
  const theExport: Export = {
    id: exportId,
    caseId,
    searchId,
    status: 'completed',
    reviewTags: ['untagged', 'relevant', 'privileged'],
    acknowledgeMalicious: false,
    itemCount: 5,
    maliciousCount: 0,
    packageBytes: 48_213,
    packageSha256: sha(`${exportId}:package`),
    manifestSha256: sha(`${exportId}:manifest`),
    signingKeyId: SIGNING_KEY_ID,
    expiresAt: iso(anchor + 5 * DAY),
    errorCode: null,
    requestedBy: stableUuid(`${organizationId}:user:admin`),
    createdAt: iso(anchor - 2 * DAY),
    completedAt: iso(anchor - 2 * DAY + 20_000),
  };
  const issues: Issue[] = [0, 1, 2].map((i) => ({
    messageId: stableUuid(`${organizationId}:issue:${i}`),
    receivedAt: iso(anchor - (i + 1) * 5 * HOUR),
    status: i === 2 ? 'lost' : 'failed',
    code: i === 2 ? 'original_missing' : i === 1 ? 'tenant_key_unavailable' : 'S3ServiceException',
    attempts: i === 2 ? 1 : 4 + i,
    sources: { journal: true, policy: i === 1 },
    nextCheckAt: iso(anchor + (i + 1) * HOUR),
    createdAt: iso(anchor - (i + 1) * 5 * HOUR),
  }));
  const disposals: Disposal[] = [0, 1, 2, 3].map((i) => ({
    messageId: stableUuid(`${organizationId}:disposed:${i}`),
    receivedAt: iso(anchor - (400 + i) * DAY),
    reason: i === 3 ? 'review_disposed' : 'retention_expired',
    state: i === 0 ? 'objects_deleted' : 'completed',
    sha256: sha(`${organizationId}:disposed:${i}`),
    sizeBytes: 5120 + i,
    attempts: 1,
    requestedAt: iso(anchor - (10 - i) * DAY),
    completedAt: i === 0 ? null : iso(anchor - (10 - i) * DAY + 60_000),
  }));
  return {
    settings,
    policies,
    keys,
    issues,
    disposals,
    records,
    holds: new Map([
      [hold.id, hold],
      [legacy.id, legacy],
    ]),
    cases: new Map([[theCase.id, theCase]]),
    searches: new Map([[searchId, { search, hits, readyAt: 0 }]]),
    exports: new Map([[exportId, { export: theExport, readyAt: 0 }]]),
    grants: new Map(),
    idempotency: new Map(),
    reveals: [],
  };
}

const globalState = globalThis as typeof globalThis & {
  __egDevFixtureArchive?: Map<string, OrgArchive>;
};

type Principal = NonNullable<ReturnType<typeof resolveFixturePrincipal>>;

function principalOf(request: FixtureRequest): Principal {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) throw new Error('fixture principal missing after the guard');
  return principal;
}

function orgOf(request: FixtureRequest): OrgArchive {
  globalState.__egDevFixtureArchive ??= new Map();
  const id = principalOf(request).organizationId;
  let org = globalState.__egDevFixtureArchive.get(id);
  if (!org) {
    org = buildOrg(id);
    globalState.__egDevFixtureArchive.set(id, org);
  }
  advanceJobs(org);
  return org;
}

/**
 * The archive settings row of the caller's organization (step 8.6: Journaling and the Archive
 * edit the same row; the journaling fixtures read and write it through this accessor).
 */
export function archiveSettingsRow(request: FixtureRequest): {
  get: () => Settings;
  set: (next: Settings) => void;
  defaultPolicyLive: () => boolean;
} {
  const org = orgOf(request);
  return {
    get: () => org.settings,
    set: (next) => {
      org.settings = next;
    },
    defaultPolicyLive: () =>
      Boolean(
        org.settings.defaultRetentionPolicyId &&
        livePolicies(org).some((p) => p.id === org.settings.defaultRetentionPolicyId),
      ),
  };
}

/** Resets the in-memory archive (tests). */
export function resetArchiveFixtures(): void {
  globalState.__egDevFixtureArchive = new Map();
}

function has(request: FixtureRequest, permission: string): boolean {
  return principalOf(request).permissions.includes(permission);
}

function bodyOf(request: FixtureRequest): Record<string, unknown> {
  return request.body && typeof request.body === 'object'
    ? (request.body as Record<string, unknown>)
    : {};
}

/** Guarded handler: permission check, then the handler with the organization's archive. */
function route(
  handler: (request: FixtureRequest, org: OrgArchive) => FixtureResponse,
): FixtureHandler {
  return (request) => fixtureGuard(request) ?? handler(request, orgOf(request));
}

/** `@UserOnly() @RequireMfa()`: the session must be signed in with MFA. */
function mfa(request: FixtureRequest): FixtureResponse | null {
  return principalOf(request).mfaAuthenticated
    ? null
    : apiError(403, 'mfa_required', 'This action requires a session signed in with MFA');
}

/** Content routes refuse platform override sessions (A20). */
function noOverride(request: FixtureRequest): FixtureResponse | null {
  return principalOf(request).override
    ? apiError(
        403,
        'archive_override_forbidden',
        'Archived content is not available under a platform override',
      )
    : null;
}

function idempotent(
  request: FixtureRequest,
  org: OrgArchive,
  handler: () => FixtureResponse,
): FixtureResponse {
  const key = request.headers.get('idempotency-key');
  if (!key)
    return apiError(400, 'idempotency_key_required', 'The Idempotency-Key header is required');
  const scoped = `${principalOf(request).userId}:${key}`;
  const fingerprint = JSON.stringify([request.operationId, request.params, request.body]);
  const stored = org.idempotency.get(scoped);
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
    org.idempotency.set(scoped, { fingerprint, response });
  return response;
}

function reasonOf(body: Record<string, unknown>, max: number): string | FixtureResponse {
  const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
  if (!reason || reason.length > max) {
    return apiError(400, 'validation_failed', [`reason: must be 1-${max} characters`]);
  }
  return reason;
}

function advanceJobs(org: OrgArchive): void {
  const now = Date.now();
  for (const record of org.searches.values()) {
    if (
      record.search.status !== 'completed' &&
      record.search.status !== 'failed' &&
      record.readyAt <= now
    ) {
      record.search = {
        ...record.search,
        status: 'completed',
        startedAt: record.search.startedAt ?? iso(now - 1000),
        completedAt: iso(now),
        hitCount: record.hits.length,
        indexComplete: true,
        incompleteReason: null,
      };
    } else if (
      record.search.status === 'queued' &&
      record.readyAt - now < FIXTURE_JOB_DELAY_MS / 2
    ) {
      record.search = { ...record.search, status: 'running', startedAt: iso(now) };
    }
  }
  for (const record of org.exports.values()) {
    if (
      (record.export.status === 'queued' || record.export.status === 'building') &&
      record.readyAt <= now
    ) {
      record.export = {
        ...record.export,
        status: 'completed',
        packageBytes: 12_000 + record.export.itemCount * 4_100,
        packageSha256: sha(`${record.export.id}:package`),
        manifestSha256: sha(`${record.export.id}:manifest`),
        signingKeyId: SIGNING_KEY_ID,
        expiresAt: iso(now + 7 * DAY),
        completedAt: iso(now),
      };
    }
  }
}

function caseCounts(org: OrgArchive, c: Case): Case['counts'] {
  return {
    custodians: c.custodians.length,
    activeHolds: [...org.holds.values()].filter((h) => h.caseId === c.id && h.status === 'active')
      .length,
    searches: [...org.searches.values()].filter((s) => s.search.caseId === c.id).length,
    exports: [...org.exports.values()].filter((e) => e.export.caseId === c.id).length,
  };
}

function withCase(
  request: FixtureRequest,
  org: OrgArchive,
  handler: (c: Case) => FixtureResponse,
): FixtureResponse {
  const c = org.cases.get(request.params.caseId ?? '');
  if (!c) return apiError(404, 'ediscovery_case_not_found', 'eDiscovery case not found');
  return handler(c);
}

function openCase(c: Case): FixtureResponse | null {
  return c.status === 'closed'
    ? apiError(409, 'ediscovery_case_closed', 'The eDiscovery case is closed')
    : null;
}

function withRecord(
  request: FixtureRequest,
  org: OrgArchive,
  handler: (record: Record_) => FixtureResponse,
): FixtureResponse {
  const record = org.records.get(request.params.messageId ?? '');
  if (!record) return apiError(404, 'archive_message_not_found', 'Archived message not found');
  return handler(record);
}

function contentGone(record: Record_): FixtureResponse | null {
  return record.detail.status === 'disposing'
    ? apiError(410, 'archive_content_unavailable', 'The archived content is no longer available')
    : null;
}

function reauth(body: Record<string, unknown>): FixtureResponse | null {
  if (
    typeof body.password !== 'string' ||
    body.password.length === 0 ||
    body.password === 'wrong'
  ) {
    return apiError(401, 'quarantine_reauth_failed', 'Password or verification code is incorrect');
  }
  return null;
}

function grantToken(): string {
  return `v1.${Buffer.from(crypto.randomUUID()).toString('base64url')}.${Buffer.from(crypto.randomUUID()).toString('base64url')}`;
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function custodiansOf(value: unknown): string[] | FixtureResponse {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((v) => typeof v !== 'string' || !EMAIL.test(v))) {
    return apiError(400, 'validation_failed', ['custodians: must be email addresses']);
  }
  return [...new Set((value as string[]).map((v) => v.toLowerCase()))];
}

function policyFromBody(
  body: Record<string, unknown>,
  org: OrgArchive,
  exceptId?: string,
): Omit<Policy, 'id' | 'rowVersion' | 'createdAt' | 'updatedAt' | 'isDefault'> | FixtureResponse {
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > 128)
    return apiError(400, 'validation_failed', ['name: must be 1-128 characters']);
  const days = body.retentionDays;
  if (typeof days !== 'number' || !Number.isInteger(days) || days < 1) {
    return apiError(400, 'validation_failed', ['retentionDays: must be a positive integer']);
  }
  if (days > 2555) {
    return apiError(
      422,
      'archive_retention_exceeds_limit',
      'retentionDays exceeds the retention allowed for the organization',
      { limit: 2555 },
    );
  }
  if ([...org.policies.values()].some((p) => !p.deleted && p.id !== exceptId && p.name === name)) {
    return apiError(
      409,
      'archive_retention_policy_name_taken',
      'A retention policy with this name already exists',
    );
  }
  return {
    name,
    retentionDays: days,
    onExpiry: body.onExpiry === 'review' ? 'review' : 'delete',
    priority: typeof body.priority === 'number' ? body.priority : 100,
    criteria: (body.criteria as Policy['criteria'] | undefined) ?? {},
  };
}

function livePolicies(org: OrgArchive): Policy[] {
  return [...org.policies.values()]
    .filter((p) => !p.deleted)
    .map(({ deleted: _deleted, ...p }) => ({
      ...p,
      isDefault: p.id === org.settings.defaultRetentionPolicyId,
    }))
    .sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
}

function parseRange(query: URLSearchParams): { from: number; to: number } | FixtureResponse {
  const from = Date.parse(query.get('from') ?? '');
  const to = Date.parse(query.get('to') ?? '');
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from || to - from > 366 * DAY) {
    return apiError(
      400,
      'archive_search_range_invalid',
      'from and to must be a valid range of at most the allowed days',
      { maxDays: 366 },
    );
  }
  return { from, to };
}

function listOf(query: URLSearchParams, key: string): string[] {
  return (query.get(key) ?? '').split(',').filter(Boolean);
}

/** `GET /archive/messages` semantics over the in-memory records (masked results). */
function searchRecords(request: FixtureRequest, org: OrgArchive): FixtureResponse {
  const q = request.query;
  for (const filter of ['recipient', 'subject', 'custodian']) {
    if (q.get(filter) && !has(request, 'message:reveal')) {
      return apiError(
        403,
        'archive_filter_forbidden',
        'This filter needs a permission the caller does not hold',
        { filter },
      );
    }
  }
  if (
    q.get('holdId') &&
    !has(request, 'archive:legal_hold') &&
    !has(request, 'ediscovery:manage')
  ) {
    return apiError(
      403,
      'archive_filter_forbidden',
      'This filter needs a permission the caller does not hold',
      { filter: 'holdId' },
    );
  }
  if ((q.get('sender') ?? '').startsWith('unavailable@')) {
    return apiError(503, 'archive_search_unavailable', 'Archive search is temporarily unavailable');
  }
  const range = parseRange(q);
  if ('status' in range) return range;
  const holdId = q.get('holdId');
  if (holdId && !org.holds.get(holdId))
    return apiError(404, 'legal_hold_not_found', 'Legal hold not found');
  const lists: Record<string, string[]> = {
    direction: listOf(q, 'direction'),
    category: listOf(q, 'category'),
    source: listOf(q, 'source'),
    status: listOf(q, 'status'),
    verdict: listOf(q, 'verdict'),
    finalAction: listOf(q, 'finalAction'),
  };
  const gte = q.get('riskScore.gte');
  const lte = q.get('riskScore.lte');
  const rows = [...org.records.values()]
    .filter(({ detail: d, subject, recipients }) => {
      const t = Date.parse(d.receivedAt);
      if (t < range.from || t >= range.to) return false;
      if (lists.direction!.length && !lists.direction!.includes(d.direction)) return false;
      if (lists.category!.length && !lists.category!.includes(d.category)) return false;
      if (lists.source!.length && !d.sources.some((s) => lists.source!.includes(s))) return false;
      const ingest = q.get('ingestSource');
      if (ingest && !d.ingestSources.some((s) => s === ingest)) return false;
      if (lists.status!.length && !lists.status!.includes(d.status)) return false;
      if (lists.verdict!.length && !lists.verdict!.includes(d.verdict ?? '')) return false;
      if (lists.finalAction!.length && !lists.finalAction!.includes(d.finalAction ?? ''))
        return false;
      const sender = q.get('sender')?.toLowerCase();
      if (sender && d.envelopeFrom.toLowerCase() !== sender) return false;
      const senderDomain = q.get('senderDomain')?.toLowerCase();
      if (senderDomain && !d.envelopeFrom.toLowerCase().endsWith(`@${senderDomain}`)) return false;
      const recipient = q.get('recipient')?.toLowerCase();
      if (recipient && !recipients.includes(recipient)) return false;
      const recipientDomain = q.get('recipientDomain')?.toLowerCase();
      if (recipientDomain && !recipients.some((r) => r.endsWith(`@${recipientDomain}`)))
        return false;
      const custodian = q.get('custodian')?.toLowerCase();
      if (custodian && d.envelopeFrom !== custodian && !recipients.includes(custodian))
        return false;
      const phrase = q.get('subject')?.toLowerCase();
      if (phrase && !subject.toLowerCase().includes(phrase)) return false;
      const mid = q.get('internetMessageId');
      if (mid && d.internetMessageId?.replace(/[<>]/g, '') !== mid.replace(/[<>]/g, ''))
        return false;
      if (q.get('hasAttachments') && d.attachmentCount > 0 !== (q.get('hasAttachments') === 'true'))
        return false;
      const name = q.get('attachmentName')?.toLowerCase();
      if (name && !d.attachmentNames.some((n) => n.toLowerCase().includes(name))) return false;
      if (q.get('malicious') && d.malicious !== (q.get('malicious') === 'true')) return false;
      if (q.get('legalHold') && d.legalHold !== (q.get('legalHold') === 'true')) return false;
      if (holdId && !(d.holds ?? []).some((h) => h.id === holdId)) return false;
      if (gte && (d.riskScore ?? -1) < Number(gte)) return false;
      if (lte && (d.riskScore ?? 1001) > Number(lte)) return false;
      return true;
    })
    .map((r) => summaryOf(r.detail))
    .sort((a, b) =>
      q.get('sort') === 'receivedAt'
        ? a.receivedAt.localeCompare(b.receivedAt)
        : b.receivedAt.localeCompare(a.receivedAt),
    );
  const lag = org.records.size % 2 === 0 ? '4' : '0';
  return {
    status: 200,
    body: paginate(rows, q),
    headers: { 'x-eg-index-lag-seconds': lag, 'cache-control': 'no-store' },
  };
}

function detailFor(request: FixtureRequest, record: Record_): Detail {
  const canHolds = has(request, 'archive:legal_hold') || has(request, 'ediscovery:manage');
  return { ...record.detail, holds: canHolds ? record.detail.holds : null };
}

function journalOf(record: Record_): SuccessBody<'ArchiveMessagesController_journal_v1'> {
  const d = record.detail;
  return {
    messageId: d.messageId,
    captureId: stableUuid(`${d.messageId}:capture`),
    capturedAt: d.capture.capturedAt,
    category: d.category,
    message: {
      internetMessageId: d.internetMessageId,
      envelopeFrom: d.envelopeFrom,
      headerFrom: d.headerFrom,
      subject: null,
      subjectMasked: true,
      sizeBytes: d.sizeBytes,
      emlSha256: d.integrity.sha256,
      clientIp: '192.0.2.10',
      clientHelo: 'mx.partner.example.test',
    },
    envelope: {
      recipients: d.parties.recipients.map((r) => ({
        seq: r.seq,
        address: r.address,
        direction: r.direction,
        status: r.status,
        ...(r.field ? { field: r.field } : {}),
      })),
    },
    intake: d.intake?.sourceId
      ? {
          sourceId: d.intake.sourceId,
          kind: d.intake.kind ?? 'microsoft_365_journal',
          format: 'journal_report',
          envelope: {
            sender: d.envelopeFrom,
            onBehalfOf: null,
            messageId: d.internetMessageId,
            recipients: d.parties.recipients
              .filter((r) => r.field)
              .map((r) => ({
                address: r.address,
                field: r.field ?? 'to',
                ...(r.field === 'bcc'
                  ? { expandedFrom: maskAddress(`legal@corp.example.test`) }
                  : {}),
              })),
            truncated: false,
          },
          envelopeMismatch: false,
          proof: {
            network: 'provider_egress',
            tls: true,
            clientCert: 'n/a',
            tenantHeader: 'match',
            headerToken: 'n/a',
            dkim: 'pass',
          },
        }
      : null,
    headers: [
      { name: 'From', value: d.headerFrom, masked: false },
      { name: 'To', value: null, masked: true },
      { name: 'Subject', value: null, masked: true },
      { name: 'Date', value: new Date(d.receivedAt).toUTCString(), masked: false },
      { name: 'Message-ID', value: d.internetMessageId, masked: false },
      {
        name: 'Authentication-Results',
        value: 'mx.example.test; spf=pass; dkim=pass; dmarc=pass',
        masked: false,
      },
    ],
    parse: { status: 'parsed', codes: [] },
    body: { textAvailable: true, htmlAvailable: true, truncated: false, unavailableReason: null },
    attachments: d.attachmentNames.map((fileName, i) => ({
      partIndex: i + 2,
      fileName,
      contentType: 'application/pdf',
      detectedType: 'pdf',
      sizeBytes: 2048,
      sha256: sha(`${d.messageId}:att:${i}`),
    })),
    deliveries: d.parties.recipients.map((r) => ({
      seq: r.seq,
      status: 'delivered',
      finalAt: d.capturedAt,
    })),
  };
}

function securityOf(record: Record_): SuccessBody<'ArchiveMessagesController_security_v1'> {
  const d = record.detail;
  const frozen = d.rounds[0]?.frozenAt ?? d.capturedAt ?? d.receivedAt;
  const scan = {
    scanId: stableUuid(`${d.messageId}:scan`),
    round: 0,
    scanKind: 'initial',
    status: 'completed',
    verdict: d.malicious ? 'malicious' : 'clean',
    requiredEngines: ['rspamd', 'url', 'attachment'],
    reasonCodes: d.malicious ? ['url.feed_malicious'] : [],
    startedAt: d.receivedAt,
    completedAt: frozen,
    deadlineAt: iso(Date.parse(d.receivedAt) + 30 * 60_000),
    auth: {
      spf: 'pass',
      spfDomain: 'partner.example.test',
      dkim: 'pass',
      dkimSignatures: [{ result: 'pass', domain: 'partner.example.test', selector: 'EXAMPLE' }],
      dmarc: 'pass',
      dmarcPolicy: 'reject',
      dmarcDomain: 'partner.example.test',
      arc: 'none',
    },
    engines: [],
    risk: [],
    policy: null,
  };
  return {
    messageId: d.messageId,
    rounds: d.rounds.map((r) => ({ ...r, frozenAt: frozen, scan })),
    dlpEvidence: 'not_retained',
  };
}

function previewOf(record: Record_): SuccessBody<'ArchiveMessagesController_preview_v1'> {
  return {
    version: 'preview/1',
    subject: record.subject,
    headers: [
      { name: 'From', value: record.detail.envelopeFrom },
      { name: 'Date', value: new Date(record.detail.receivedAt).toUTCString() },
    ],
    body: {
      source: 'html',
      text: `EXAMPLE synthetic archived body of “${record.subject}”.\n\nRead it at [link 1].\n<script>alert(1)</script> stays text.`,
      truncated: false,
      unavailableReason: null,
    },
    links: [
      {
        n: 1,
        displayUrl: 'hxxps://docs[.]partner.example.test/EXAMPLE',
        host: 'docs.partner.example.test',
        verdict: record.detail.malicious ? 'malicious' : 'clean',
      },
    ],
    linksTruncated: false,
    attachments: record.detail.attachmentNames.map((filename, i) => ({
      partIndex: i + 2,
      filename,
      declaredType: 'application/pdf',
      detectedType: 'application/pdf',
      typeFamily: 'document',
      sizeBytes: 2048,
      sha256: sha(`${record.detail.messageId}:att:${i}`),
      verdict: 'clean',
      reasonCodes: [],
      downloadable: false,
    })),
    dlp: { masked: 0, categories: [] },
  };
}

function reveal(request: FixtureRequest, org: OrgArchive, record: Record_): FixtureResponse {
  const now = Date.now();
  org.reveals = org.reveals.filter((t) => t > now - 60_000);
  if (org.reveals.length >= FIXTURE_REVEAL_PER_MINUTE) {
    return {
      ...apiError(429, 'rate_limited', 'Too many requests'),
      headers: { 'retry-after': '30' },
    };
  }
  org.reveals.push(now);
  const fields = Array.isArray(bodyOf(request).fields) ? (bodyOf(request).fields as string[]) : [];
  if (fields.length === 0)
    return apiError(400, 'validation_failed', ['fields: at least one field']);
  const body: SuccessBody<'ArchiveMessagesController_reveal_v1'> = {
    messageId: record.detail.messageId,
    revealedAt: iso(now),
    ...(fields.includes('subject') ? { subject: record.subject } : {}),
    ...(fields.includes('recipients')
      ? { recipients: record.recipients.map((address, seq) => ({ seq, address })) }
      : {}),
    ...(fields.includes('headers')
      ? {
          headers: [
            { name: 'To', value: record.recipients.join(', ') },
            { name: 'Subject', value: record.subject },
          ],
        }
      : {}),
  };
  return { status: 200, body, headers: { 'cache-control': 'no-store' } };
}

function settingsUpdate(request: FixtureRequest, org: OrgArchive): FixtureResponse {
  const body = bodyOf(request) as Partial<RequestBody<'ArchiveAdminController_update_v1'>>;
  if (typeof body.expectedRowVersion !== 'number') {
    return apiError(400, 'validation_failed', ['expectedRowVersion: Required']);
  }
  const s = org.settings;
  if (body.expectedRowVersion !== s.rowVersion) {
    return apiError(
      409,
      'archive_settings_conflict',
      'expectedRowVersion is not the current version of the archive settings',
      { currentRowVersion: s.rowVersion },
    );
  }
  // Step 8.6: per changed path (journaling paths → journal:manage, archive paths → archive:manage).
  const changed = (a: unknown, b: unknown) =>
    b !== undefined && JSON.stringify(a) !== JSON.stringify(b);
  const paths: { path: string; permission: string }[] = [];
  const journal = (path: string, a: unknown, b: unknown) => {
    if (changed(a, b) && !has(request, 'journal:manage'))
      paths.push({ path, permission: 'journal:manage' });
  };
  const archive = (path: string, a: unknown, b: unknown) => {
    if (changed(a, b) && !has(request, 'archive:manage'))
      paths.push({ path, permission: 'archive:manage' });
  };
  journal('enabled', s.enabled, body.enabled);
  for (const key of ['directions', 'include', 'scope', 'policyArchive', 'intake'] as const)
    journal(`settings.${key}`, s.settings[key], body.settings?.[key]);
  archive('immutability', s.immutability, body.immutability);
  archive('defaultRetentionPolicyId', s.defaultRetentionPolicyId, body.defaultRetentionPolicyId);
  archive('settings.access', s.settings.access, body.settings?.access);
  if (paths.length > 0) {
    return apiError(403, 'archive_settings_forbidden_path', 'You may not change these paths', {
      paths,
    });
  }
  const immutability = body.immutability ?? s.immutability;
  if (s.immutability === 'compliance' && immutability !== 'compliance') {
    return apiError(
      409,
      'archive_immutability_downgrade_forbidden',
      'Compliance immutability cannot be weakened',
    );
  }
  if (immutability !== 'none' && !s.objectLockAvailable) {
    return apiError(
      409,
      'archive_object_lock_unavailable',
      'Object Lock is not available on the archive storage',
    );
  }
  const enabled = body.enabled ?? s.enabled;
  if (enabled && !s.entitled)
    return apiError(403, 'archiving_not_enabled', 'Archiving is not enabled for this organization');
  const defaultId =
    body.defaultRetentionPolicyId === undefined
      ? s.defaultRetentionPolicyId
      : body.defaultRetentionPolicyId;
  if (enabled && (!defaultId || !livePolicies(org).some((p) => p.id === defaultId))) {
    return apiError(
      422,
      'archive_default_retention_required',
      'Enabled archiving needs a live default retention policy',
    );
  }
  const scope = body.settings?.scope;
  const badId = (scope?.domainIds ?? []).findIndex((id) => id.startsWith('00000000'));
  if (badId >= 0) {
    return apiError(
      422,
      'archive_scope_reference_invalid',
      'A referenced domain, department or user does not exist in the organization',
      { path: `settings.scope.domainIds[${badId}]` },
    );
  }
  const next = body.settings ?? {};
  org.settings = {
    ...s,
    enabled,
    immutability,
    defaultRetentionPolicyId: defaultId ?? null,
    settings: {
      directions: { ...s.settings.directions, ...next.directions },
      include: { ...s.settings.include, ...next.include },
      scope: { ...s.settings.scope, ...next.scope },
      policyArchive: { ...s.settings.policyArchive, ...next.policyArchive },
      access: { ...s.settings.access, ...next.access },
      intake: { ...s.settings.intake, ...next.intake },
    },
    generation: s.generation + 1,
    journalEnabledAt: enabled && !s.enabled ? iso(Date.now()) : s.journalEnabledAt,
    rowVersion: s.rowVersion + 1,
    updatedAt: iso(Date.now()),
  };
  return ok('ArchiveAdminController_update_v1', org.settings);
}

export const fixtures: FixtureHandlers = {
  ArchiveAdminController_get_v1: route((_r, org) =>
    ok('ArchiveAdminController_get_v1', org.settings),
  ),
  ArchiveAdminController_update_v1: route(
    (request, org) => mfa(request) ?? idempotent(request, org, () => settingsUpdate(request, org)),
  ),
  ArchiveAdminController_status_v1: route((_r, org) => {
    const records = [...org.records.values()].map((r) => r.detail);
    return ok('ArchiveAdminController_status_v1', {
      generatedAt: iso(Date.now()),
      settings: {
        enabled: org.settings.enabled,
        entitled: org.settings.entitled,
        immutability: org.settings.immutability,
        generation: org.settings.generation,
      },
      capture: {
        pending: 2,
        capturedOpen: 5,
        failed: org.issues.filter((i) => i.status === 'failed').length,
        lost: org.issues.filter((i) => i.status === 'lost').length,
        oldestPendingAt: iso(Date.now() - 4 * 60_000),
      },
      records: {
        active: records.filter((r) => r.status === 'active').length,
        expiryReview: records.filter((r) => r.status === 'expiry_review').length,
        disposing: records.filter((r) => r.status === 'disposing').length,
      },
      index: { queued: 3, oldestQueuedAt: iso(Date.now() - 4_000), lagSeconds: 4 },
      disposals: {
        inProgress: org.disposals.filter((d) => d.state !== 'completed' && d.state !== 'failed')
          .length,
        failed: org.disposals.filter((d) => d.state === 'failed').length,
      },
      keys: { activeVersion: org.keys[0]?.version ?? null, versions: org.keys.length },
      objectLock: { available: org.settings.objectLockAvailable },
      search: { configured: true, available: true },
    });
  }),
  ArchiveAdminController_listKeys_v1: route((request, org) => ({
    status: 200,
    body: paginate(org.keys, request.query),
  })),
  ArchiveAdminController_rotate_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(request, org, () => {
        const reason = reasonOf(bodyOf(request), 1024);
        if (typeof reason !== 'string') return reason;
        const previous = org.keys[0];
        const version = (previous?.version ?? 0) + 1;
        const now = iso(Date.now());
        const key: Key = {
          id: stableUuid(`key:${version}:${now}`),
          version,
          status: 'active',
          rootKeyId: 'root-EXAMPLE-1',
          algorithm: 'AES-256-GCM',
          rotationReason: reason,
          createdBy: principalOf(request).userId,
          createdAt: now,
          activatedAt: now,
          retiredAt: null,
          destroyedAt: null,
        };
        org.keys = [
          key,
          ...org.keys.map((k) =>
            k.status === 'active' ? { ...k, status: 'retired' as const, retiredAt: now } : k,
          ),
        ];
        return ok(
          'ArchiveAdminController_rotate_v1',
          { key, previousVersion: previous?.version ?? null },
          201,
        );
      }),
  ),
  ArchiveAdminController_captureIssues_v1: route((request, org) => {
    const statuses = listOf(request.query, 'status');
    const rows = org.issues.filter((i) => statuses.length === 0 || statuses.includes(i.status));
    return { status: 200, body: paginate(rows, request.query) };
  }),
  ArchiveAdminController_captureIssue_v1: route((request, org) => {
    const issue = org.issues.find((i) => i.messageId === request.params.messageId);
    return issue
      ? ok('ArchiveAdminController_captureIssue_v1', issue)
      : apiError(404, 'archive_capture_issue_not_found', 'Capture issue not found');
  }),
  ArchiveAdminController_retry_v1: route((request, org) =>
    idempotent(request, org, () => {
      const issue = org.issues.find((i) => i.messageId === request.params.messageId);
      if (!issue)
        return apiError(404, 'archive_capture_issue_not_found', 'Capture issue not found');
      if (issue.status !== 'failed') {
        return apiError(
          409,
          'archive_capture_retry_not_allowed',
          'Only a failed capture can be retried',
          { status: issue.status },
        );
      }
      const nextCheckAt = iso(Date.now());
      org.issues = org.issues.filter((i) => i !== issue);
      return ok('ArchiveAdminController_retry_v1', {
        messageId: issue.messageId,
        status: 'pending',
        nextCheckAt,
      });
    }),
  ),
  ArchiveAdminController_disposals_v1: route((request, org) => {
    const reasons = listOf(request.query, 'reason');
    const states = listOf(request.query, 'state');
    const rows = org.disposals
      .filter(
        (d) =>
          (reasons.length === 0 || reasons.includes(d.reason)) &&
          (states.length === 0 || states.includes(d.state)),
      )
      .sort((a, b) => b.requestedAt.localeCompare(a.requestedAt));
    return { status: 200, body: paginate(rows, request.query) };
  }),
  ArchiveAdminController_signingKeys_v1: route(() =>
    ok('ArchiveAdminController_signingKeys_v1', {
      data: [
        {
          id: SIGNING_KEY_ID,
          algorithm: 'Ed25519',
          format: 'spki-der-base64url',
          publicKey: 'MCowBQYDK2VwAyEA-EXAMPLE-public-key-placeholder',
          current: true,
        },
      ],
    }),
  ),
  ArchiveRetentionController_list_v1: route((request, org) => ({
    status: 200,
    body: paginate(livePolicies(org), request.query),
  })),
  ArchiveRetentionController_get_v1: route((request, org) => {
    const policy = livePolicies(org).find((p) => p.id === request.params.policyId);
    return policy
      ? ok('ArchiveRetentionController_get_v1', policy)
      : apiError(404, 'archive_retention_policy_not_found', 'Retention policy not found');
  }),
  ArchiveRetentionController_create_v1: route((request, org) =>
    idempotent(request, org, () => {
      const parsed = policyFromBody(bodyOf(request), org);
      if ('status' in parsed) return parsed;
      if (livePolicies(org).length >= 50) {
        return apiError(
          422,
          'archive_retention_policy_limit',
          'The organization has reached the maximum number of retention policies',
          { limit: 50 },
        );
      }
      const now = iso(Date.now());
      const policy: Policy = {
        ...parsed,
        id: crypto.randomUUID(),
        isDefault: false,
        rowVersion: 1,
        createdAt: now,
        updatedAt: now,
      };
      org.policies.set(policy.id, policy);
      return ok('ArchiveRetentionController_create_v1', policy, 201);
    }),
  ),
  ArchiveRetentionController_update_v1: route((request, org) =>
    idempotent(request, org, () => {
      const current = org.policies.get(request.params.policyId ?? '');
      if (!current || current.deleted)
        return apiError(404, 'archive_retention_policy_not_found', 'Retention policy not found');
      const body = bodyOf(request);
      if (body.expectedRowVersion !== current.rowVersion) {
        return apiError(
          409,
          'archive_retention_policy_conflict',
          'expectedRowVersion is not the current version of the retention policy',
          { currentRowVersion: current.rowVersion },
        );
      }
      const parsed = policyFromBody(body, org, current.id);
      if ('status' in parsed) return parsed;
      const next: Policy = {
        ...current,
        ...parsed,
        rowVersion: current.rowVersion + 1,
        updatedAt: iso(Date.now()),
      };
      org.policies.set(next.id, next);
      return ok('ArchiveRetentionController_update_v1', {
        ...next,
        isDefault: next.id === org.settings.defaultRetentionPolicyId,
      });
    }),
  ),
  ArchiveRetentionController_delete_v1: route((request, org) =>
    idempotent(request, org, () => {
      const current = org.policies.get(request.params.policyId ?? '');
      if (!current || current.deleted)
        return apiError(404, 'archive_retention_policy_not_found', 'Retention policy not found');
      if (current.id === org.settings.defaultRetentionPolicyId) {
        return apiError(
          409,
          'archive_retention_policy_is_default',
          'The default retention policy of the archive settings cannot be deleted',
        );
      }
      org.policies.set(current.id, { ...current, deleted: true });
      return noContent();
    }),
  ),
  ArchiveMessagesController_list_v1: route(searchRecords),
  ArchiveMessagesController_detail_v1: route((request, org) =>
    withRecord(request, org, (record) =>
      ok('ArchiveMessagesController_detail_v1', detailFor(request, record)),
    ),
  ),
  ArchiveMessagesController_journal_v1: route((request, org) =>
    withRecord(
      request,
      org,
      (record) =>
        contentGone(record) ?? ok('ArchiveMessagesController_journal_v1', journalOf(record)),
    ),
  ),
  ArchiveMessagesController_security_v1: route((request, org) =>
    withRecord(
      request,
      org,
      (record) =>
        contentGone(record) ?? ok('ArchiveMessagesController_security_v1', securityOf(record)),
    ),
  ),
  ArchiveMessagesController_reveal_v1: route((request, org) =>
    withRecord(request, org, (record) => contentGone(record) ?? reveal(request, org, record)),
  ),
  ArchiveMessagesController_preview_v1: route((request, org) =>
    withRecord(
      request,
      org,
      (record) =>
        mfa(request) ??
        noOverride(request) ??
        contentGone(record) ??
        (org.settings.settings.access.previewEnabled
          ? ok('ArchiveMessagesController_preview_v1', previewOf(record))
          : apiError(
              403,
              'archive_preview_disabled',
              'Archive previews are disabled for the organization',
            )),
    ),
  ),
  ArchiveMessagesController_grant_v1: route((request, org) =>
    withRecord(request, org, (record) => {
      const refused =
        mfa(request) ?? noOverride(request) ?? contentGone(record) ?? reauth(bodyOf(request));
      if (refused) return refused;
      if (!org.settings.settings.access.downloadEnabled) {
        return apiError(
          403,
          'archive_download_disabled',
          'Archive downloads are disabled for the organization',
        );
      }
      if (record.detail.malicious) {
        return apiError(
          409,
          'archive_download_blocked',
          'The archived message cannot be downloaded interactively',
          { reason: 'malicious' },
        );
      }
      const variantId = bodyOf(request).variant;
      const variant =
        typeof variantId === 'string'
          ? record.detail.mergedCopies.find((c) => c.id === variantId && c.contentVariant)
          : undefined;
      if (typeof variantId === 'string' && !variant) {
        return apiError(404, 'archive_variant_not_found', 'Content variant not found');
      }
      const token = grantToken();
      const filename = variant
        ? `archive-${record.detail.messageId}.variant-1.eml`
        : `archive-${record.detail.messageId}.eml`;
      org.grants.set(token, {
        userId: principalOf(request).userId,
        used: false,
        expiresAt: Date.now() + 60_000,
        filename,
      });
      return {
        ...ok(
          'ArchiveMessagesController_grant_v1',
          {
            token,
            expiresAt: iso(Date.now() + 60_000),
            filename,
            sizeBytes: variant?.sizeBytes ?? record.detail.sizeBytes,
            sha256: variant?.sha256 ?? record.detail.integrity.sha256,
          },
          201,
        ),
        headers: { 'cache-control': 'no-store' },
      };
    }),
  ),
  ArchiveDownloadsController_download_v1: route((request, org) => {
    const refused = noOverride(request);
    if (refused) return refused;
    const grant = org.grants.get(request.params.token ?? '');
    if (!grant || grant.userId !== principalOf(request).userId || grant.expiresAt < Date.now()) {
      return apiError(404, 'archive_download_token_invalid', 'Download token not found or expired');
    }
    if (grant.used)
      return apiError(410, 'archive_download_token_used', 'The download token was already used');
    grant.used = true;
    return {
      status: 200,
      body: 'From: dev-fixture@example.test\r\nSubject: EXAMPLE synthetic archived message\r\n\r\nSynthetic content of the dev fixture mode.\r\n',
      headers: {
        'content-type': 'application/octet-stream',
        'content-disposition': `attachment; filename="${grant.filename}"`,
        'x-content-type-options': 'nosniff',
        'cache-control': 'no-store',
      },
    };
  }),
  ArchiveMessagesController_dispose_v1: route((request, org) =>
    withRecord(
      request,
      org,
      (record) =>
        mfa(request) ??
        idempotent(request, org, () => {
          const reason = reasonOf(bodyOf(request), 4096);
          if (typeof reason !== 'string') return reason;
          if (record.detail.status !== 'expiry_review') {
            return apiError(
              409,
              'archive_dispose_not_allowed',
              'The archived message cannot be disposed now',
              { reason: 'not_in_review' },
            );
          }
          if ((record.detail.holds ?? []).length > 0) {
            return apiError(
              409,
              'archive_dispose_not_allowed',
              'The archived message cannot be disposed now',
              { reason: 'legal_hold' },
            );
          }
          const now = iso(Date.now());
          record.detail = { ...record.detail, status: 'disposing' };
          org.disposals.unshift({
            messageId: record.detail.messageId,
            receivedAt: record.detail.receivedAt,
            reason: 'review_disposed',
            state: 'shredded',
            sha256: record.detail.integrity.sha256,
            sizeBytes: record.detail.sizeBytes,
            attempts: 0,
            requestedAt: now,
            completedAt: null,
          });
          return ok(
            'ArchiveMessagesController_dispose_v1',
            { messageId: record.detail.messageId, status: 'disposing', disposalRequestedAt: now },
            202,
          );
        }),
    ),
  ),
  LegalHoldsController_list_v1: route((request, org) => {
    const status = request.query.get('status');
    const caseId = request.query.get('caseId');
    const rows = [...org.holds.values()]
      .filter((h) => (!status || h.status === status) && (!caseId || h.caseId === caseId))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return { status: 200, body: paginate(rows, request.query) };
  }),
  LegalHoldsController_get_v1: route((request, org) => {
    const hold = org.holds.get(request.params.holdId ?? '');
    return hold
      ? ok('LegalHoldsController_get_v1', hold)
      : apiError(404, 'legal_hold_not_found', 'Legal hold not found');
  }),
  LegalHoldsController_release_v1: route(
    (request, org) =>
      mfa(request) ??
      idempotent(request, org, () => {
        const hold = org.holds.get(request.params.holdId ?? '');
        if (!hold) return apiError(404, 'legal_hold_not_found', 'Legal hold not found');
        if (hold.status === 'released')
          return apiError(409, 'legal_hold_already_released', 'The legal hold is already released');
        const reason = reasonOf(bodyOf(request), 4096);
        if (typeof reason !== 'string') return reason;
        const released: Hold = {
          ...hold,
          status: 'released',
          releasedAt: iso(Date.now()),
          releasedBy: principalOf(request).userId,
          releaseReason: reason,
          rowVersion: hold.rowVersion + 1,
        };
        org.holds.set(hold.id, released);
        for (const record of org.records.values()) {
          if (record.detail.holds?.some((h) => h.id === hold.id)) {
            record.detail = {
              ...record.detail,
              holds: record.detail.holds.filter((h) => h.id !== hold.id),
            };
          }
        }
        return ok('LegalHoldsController_release_v1', released);
      }),
  ),
  EdiscoveryCasesController_list_v1: route((request, org) => {
    const status = request.query.get('status');
    const rows = [...org.cases.values()]
      .filter((c) => !status || c.status === status)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map(({ custodians: _c, counts: _n, ...summary }) => summary);
    return { status: 200, body: paginate(rows, request.query) };
  }),
  EdiscoveryCasesController_get_v1: route((request, org) =>
    withCase(request, org, (c) =>
      ok('EdiscoveryCasesController_get_v1', { ...c, counts: caseCounts(org, c) }),
    ),
  ),
  EdiscoveryCasesController_create_v1: route((request, org) =>
    idempotent(request, org, () => {
      const body = bodyOf(request);
      const name = typeof body.name === 'string' ? body.name.trim() : '';
      if (!name) return apiError(400, 'validation_failed', ['name: Required']);
      if ([...org.cases.values()].some((c) => c.name === name)) {
        return apiError(
          409,
          'ediscovery_case_name_taken',
          'An eDiscovery case with this name already exists',
        );
      }
      const custodians = custodiansOf(body.custodians);
      if (!Array.isArray(custodians)) return custodians;
      const now = iso(Date.now());
      const id = crypto.randomUUID();
      const c: Case = {
        id,
        name,
        description: typeof body.description === 'string' ? body.description : null,
        matterReference: typeof body.matterReference === 'string' ? body.matterReference : null,
        status: 'open',
        rowVersion: 1,
        createdBy: principalOf(request).userId,
        createdAt: now,
        updatedAt: now,
        closedAt: null,
        custodians: custodians.map((address) => ({
          id: stableUuid(`${id}:${address}`),
          address,
          userId: null,
        })),
        counts: { custodians: custodians.length, activeHolds: 0, searches: 0, exports: 0 },
      };
      org.cases.set(id, c);
      return ok('EdiscoveryCasesController_create_v1', c, 201);
    }),
  ),
  EdiscoveryCasesController_update_v1: route((request, org) =>
    withCase(
      request,
      org,
      (c) =>
        openCase(c) ??
        idempotent(request, org, () => {
          const body = bodyOf(request);
          if (body.expectedRowVersion !== c.rowVersion) {
            return apiError(
              409,
              'ediscovery_case_conflict',
              'expectedRowVersion is not the current version of the case',
              { currentRowVersion: c.rowVersion },
            );
          }
          const custodians =
            body.custodians === undefined ? undefined : custodiansOf(body.custodians);
          if (custodians && !Array.isArray(custodians)) return custodians;
          const next: Case = {
            ...c,
            ...(typeof body.name === 'string' ? { name: body.name.trim() } : {}),
            ...(body.description !== undefined
              ? { description: (body.description as string | null) ?? null }
              : {}),
            ...(body.matterReference !== undefined
              ? { matterReference: (body.matterReference as string | null) ?? null }
              : {}),
            ...(custodians
              ? {
                  custodians: custodians.map((address) => ({
                    id: stableUuid(`${c.id}:${address}`),
                    address,
                    userId: null,
                  })),
                }
              : {}),
            rowVersion: c.rowVersion + 1,
            updatedAt: iso(Date.now()),
          };
          next.counts = caseCounts(org, next);
          org.cases.set(c.id, next);
          return ok('EdiscoveryCasesController_update_v1', next);
        }),
    ),
  ),
  EdiscoveryCasesController_close_v1: route((request, org) =>
    withCase(
      request,
      org,
      (c) =>
        mfa(request) ??
        openCase(c) ??
        idempotent(request, org, () => {
          const activeHolds = caseCounts(org, c).activeHolds;
          if (activeHolds > 0) {
            return apiError(
              409,
              'ediscovery_case_has_active_holds',
              'Release the active legal holds of the case before closing it',
              { activeHolds },
            );
          }
          const now = iso(Date.now());
          const next: Case = {
            ...c,
            status: 'closed',
            closedAt: now,
            updatedAt: now,
            rowVersion: c.rowVersion + 1,
          };
          org.cases.set(c.id, next);
          return ok('EdiscoveryCasesController_close_v1', next);
        }),
    ),
  ),
  EdiscoveryCasesController_createHold_v1: route((request, org) =>
    withCase(
      request,
      org,
      (c) =>
        mfa(request) ??
        openCase(c) ??
        idempotent(request, org, () => {
          const body = bodyOf(request);
          const name = typeof body.name === 'string' ? body.name.trim() : '';
          if (!name) return apiError(400, 'validation_failed', ['name: Required']);
          const reason = reasonOf(body, 4096);
          if (typeof reason !== 'string') return reason;
          const criteria = (body.criteria as Record<string, unknown> | undefined) ?? {};
          const custodians = body.useCaseCustodians
            ? c.custodians.map((x) => x.address)
            : custodiansOf(criteria.custodians);
          if (!Array.isArray(custodians)) return custodians;
          if (body.useCaseCustodians && custodians.length === 0) {
            return apiError(
              422,
              'legal_hold_criteria_invalid',
              'The legal hold criteria are invalid',
              { reason: 'no_case_custodians' },
            );
          }
          const hold: Hold = {
            id: crypto.randomUUID(),
            caseId: c.id,
            name,
            reason,
            status: 'active',
            criteria: { ...criteria, custodians },
            criteriaVersion: 'archive-hold/1',
            createdBy: principalOf(request).userId,
            createdAt: iso(Date.now()),
            releasedAt: null,
            releasedBy: null,
            releaseReason: null,
            rowVersion: 1,
          };
          org.holds.set(hold.id, hold);
          return ok('EdiscoveryCasesController_createHold_v1', hold, 201);
        }),
    ),
  ),
  EdiscoverySearchesController_create_v1: route((request, org) =>
    withCase(
      request,
      org,
      (c) =>
        openCase(c) ??
        idempotent(request, org, () => {
          const criteria = (bodyOf(request).criteria as Record<string, unknown> | undefined) ?? {};
          if (typeof criteria.from !== 'string' || typeof criteria.to !== 'string') {
            return apiError(400, 'validation_failed', ['criteria.from: Required']);
          }
          const revealGated =
            ['recipients', 'subject'].some((k) => criteria[k] !== undefined) ||
            Array.isArray(criteria.custodians);
          if (revealGated && !has(request, 'message:reveal')) {
            return apiError(
              403,
              'archive_filter_forbidden',
              'This filter needs a permission the caller does not hold',
              { filter: 'recipients' },
            );
          }
          const active = [...org.searches.values()].filter(
            (s) =>
              s.search.caseId === c.id &&
              (s.search.status === 'queued' || s.search.status === 'running'),
          );
          if (active.length >= 3)
            return apiError(
              429,
              'ediscovery_search_limit',
              'Too many searches of the case are queued or running',
            );
          const id = crypto.randomUUID();
          const custodians =
            criteria.custodians === 'case' ? c.custodians.map((x) => x.address) : null;
          const hits: Hit[] = [...org.records.values()]
            .filter(
              (r) =>
                !custodians ||
                custodians.includes(r.detail.envelopeFrom) ||
                r.recipients.some((x) => custodians.includes(x)),
            )
            .slice(0, 40)
            .map((r) => ({
              messageId: r.detail.messageId,
              receivedAt: r.detail.receivedAt,
              reviewTag: 'untagged',
              reviewedBy: null,
              reviewedAt: null,
              message: summaryOf(r.detail),
            }));
          const search: Search = {
            id,
            caseId: c.id,
            status: 'queued',
            criteria,
            criteriaSha256: sha(`${id}:criteria`),
            hitCount: 0,
            truncated: false,
            indexComplete: null,
            incompleteReason: null,
            errorCode: null,
            requestedBy: principalOf(request).userId,
            createdAt: iso(Date.now()),
            startedAt: null,
            completedAt: null,
          };
          org.searches.set(id, { search, hits, readyAt: Date.now() + FIXTURE_JOB_DELAY_MS });
          return ok('EdiscoverySearchesController_create_v1', search, 202);
        }),
    ),
  ),
  EdiscoverySearchesController_list_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const status = request.query.get('status');
      const rows = [...org.searches.values()]
        .map((s) => s.search)
        .filter((s) => s.caseId === c.id && (!status || s.status === status))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return { status: 200, body: paginate(rows, request.query) };
    }),
  ),
  EdiscoverySearchesController_get_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const record = org.searches.get(request.params.searchId ?? '');
      if (!record || record.search.caseId !== c.id)
        return apiError(404, 'ediscovery_search_not_found', 'eDiscovery search not found');
      return ok('EdiscoverySearchesController_get_v1', record.search);
    }),
  ),
  EdiscoverySearchesController_hits_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const record = org.searches.get(request.params.searchId ?? '');
      if (!record || record.search.caseId !== c.id)
        return apiError(404, 'ediscovery_search_not_found', 'eDiscovery search not found');
      if (record.search.status !== 'completed')
        return apiError(409, 'ediscovery_search_not_completed', 'The search has not completed');
      const tag = request.query.get('reviewTag');
      const rows = record.hits.filter((h) => !tag || h.reviewTag === tag);
      return { status: 200, body: paginate(rows, request.query) };
    }),
  ),
  EdiscoverySearchesController_review_v1: route((request, org) =>
    withCase(request, org, (c) =>
      idempotent(request, org, () => {
        const record = org.searches.get(request.params.searchId ?? '');
        if (!record || record.search.caseId !== c.id)
          return apiError(404, 'ediscovery_search_not_found', 'eDiscovery search not found');
        const body = bodyOf(request);
        const ids = Array.isArray(body.messageIds) ? (body.messageIds as string[]) : [];
        if (ids.length > 500)
          return apiError(400, 'ediscovery_review_limit', 'Too many hits in one review request', {
            limit: 500,
          });
        const tag = body.tag as ReviewTag;
        let updated = 0;
        record.hits = record.hits.map((hit) => {
          if (!ids.includes(hit.messageId)) return hit;
          updated += 1;
          return {
            ...hit,
            reviewTag: tag,
            reviewedBy: principalOf(request).userId,
            reviewedAt: iso(Date.now()),
          };
        });
        return ok('EdiscoverySearchesController_review_v1', {
          searchId: record.search.id,
          tag,
          updated,
          notFound: ids.length - updated,
        });
      }),
    ),
  ),
  EdiscoveryExportsController_create_v1: route((request, org) =>
    withCase(
      request,
      org,
      (c) =>
        openCase(c) ??
        idempotent(request, org, () => {
          const body = bodyOf(request);
          const record = org.searches.get(typeof body.searchId === 'string' ? body.searchId : '');
          if (!record || record.search.caseId !== c.id)
            return apiError(404, 'ediscovery_search_not_found', 'eDiscovery search not found');
          if (record.search.status !== 'completed')
            return apiError(409, 'ediscovery_search_not_completed', 'The search has not completed');
          const tags = (
            Array.isArray(body.reviewTags)
              ? body.reviewTags
              : ['untagged', 'relevant', 'privileged']
          ) as ReviewTag[];
          const items = record.hits.filter((h) => tags.includes(h.reviewTag));
          const malicious = items.filter((h) => h.message?.malicious).length;
          if (malicious > 0 && body.acknowledgeMalicious !== true) {
            return apiError(
              409,
              'ediscovery_export_malicious_ack_required',
              'The selection contains malicious messages',
              { maliciousCount: malicious },
            );
          }
          const id = crypto.randomUUID();
          const item: Export = {
            id,
            caseId: c.id,
            searchId: record.search.id,
            status: 'queued',
            reviewTags: tags,
            acknowledgeMalicious: body.acknowledgeMalicious === true,
            itemCount: items.length,
            maliciousCount: malicious,
            packageBytes: null,
            packageSha256: null,
            manifestSha256: null,
            signingKeyId: null,
            expiresAt: null,
            errorCode: null,
            requestedBy: principalOf(request).userId,
            createdAt: iso(Date.now()),
            completedAt: null,
          };
          org.exports.set(id, { export: item, readyAt: Date.now() + FIXTURE_JOB_DELAY_MS });
          return ok('EdiscoveryExportsController_create_v1', item, 202);
        }),
    ),
  ),
  EdiscoveryExportsController_list_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const status = request.query.get('status');
      const rows = [...org.exports.values()]
        .map((e) => e.export)
        .filter((e) => e.caseId === c.id && (!status || e.status === status))
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
      return { status: 200, body: paginate(rows, request.query) };
    }),
  ),
  EdiscoveryExportsController_get_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const record = org.exports.get(request.params.exportId ?? '');
      if (!record || record.export.caseId !== c.id)
        return apiError(404, 'ediscovery_export_not_found', 'eDiscovery export not found');
      return ok('EdiscoveryExportsController_get_v1', record.export);
    }),
  ),
  EdiscoveryExportsController_grant_v1: route((request, org) =>
    withCase(request, org, (c) => {
      const refused = mfa(request) ?? noOverride(request) ?? reauth(bodyOf(request));
      if (refused) return refused;
      const record = org.exports.get(request.params.exportId ?? '');
      if (!record || record.export.caseId !== c.id)
        return apiError(404, 'ediscovery_export_not_found', 'eDiscovery export not found');
      if (record.export.status === 'expired')
        return apiError(410, 'ediscovery_export_expired', 'The export package has expired');
      if (record.export.status !== 'completed') {
        return apiError(409, 'ediscovery_export_not_ready', 'The eDiscovery export is not ready', {
          status: record.export.status,
        });
      }
      const token = grantToken();
      const filename = `ediscovery-export-${record.export.id}.zip`;
      org.grants.set(token, {
        userId: principalOf(request).userId,
        used: false,
        expiresAt: Date.now() + 60_000,
        filename,
      });
      return {
        ...ok(
          'EdiscoveryExportsController_grant_v1',
          {
            token,
            expiresAt: iso(Date.now() + 60_000),
            filename,
            sizeBytes: record.export.packageBytes ?? 0,
            sha256: record.export.packageSha256 ?? sha(record.export.id),
          },
          201,
        ),
        headers: { 'cache-control': 'no-store' },
      };
    }),
  ),
};
