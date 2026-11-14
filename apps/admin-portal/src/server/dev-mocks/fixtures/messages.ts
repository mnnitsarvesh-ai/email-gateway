import 'server-only';
import type { ListItem, SuccessBody } from '@/lib/api/types';
import { canPerform } from '@/lib/auth/permissions';
import { SeededRandom, hashString, stableUuid } from '../generator';
import {
  apiError,
  noContent,
  ok,
  type FixtureHandlers,
  type FixtureRequest,
  type FixtureResponse,
} from '../types';
import { findDomain } from './domains';
import {
  FIXTURE_DELIVERY_STATUSES,
  FIXTURE_QUARANTINE_STATES,
  evaluationFor,
  fixtureDataset,
  fixtureDatasetAnchor,
  fixtureMessageById,
  messageDetailView,
  messageListItem,
  quarantineStatesOf,
  roundFor,
  type FixtureMessage,
} from './message-dataset';
import {
  SAFE_HEADER_NAMES,
  STORED_HEADER_NAMES,
  currentState,
  deliveriesOf,
  deliveryEventsOf,
  dlpEvidenceOf,
  enrichRound,
  enrichedRounds,
  headerAvailability,
  historicMessageAuditRows,
  historyOf,
  isRevealableHeader,
  isSafeHeader,
  lifecycleOf,
  matchedUserOf,
  recipientItems,
  rescanAllowed,
  storedHeaders,
  type FixtureRescan,
} from './message-details-data';
import { resolveFixturePrincipal } from './session';

export { DEV_MOCK_MARKER } from '../types';
export {
  HOSTILE_SUBJECTS,
  fixtureDataset,
  fixtureMessageById,
  maskAddress,
  maskAddressesInText,
  messageDetailView,
  messageListItem,
  type FixtureMessage,
} from './message-dataset';

/**
 * Dev fixtures of the mail pages (7.1 WP5, extended by step 7.2 WP3, §2 E14): `GET /messages`
 * with every filter and the api's semantics (search drivers with exact pages, budgeted short
 * pages for residual filters, the capped subject prefix with `422 message_search_too_broad`,
 * filter-level `403 message_filter_forbidden`, masked subjects), `POST /messages/reveal` with an
 * in-memory audit list (`message.revealed`, exposed by `audit.ts`), the saved views of each
 * fixture user, and the 7.1 detail, scan, attachment, URL and evaluation reads. The dataset lives
 * in `message-dataset.ts`. Everything is synthetic.
 */

/** Every dataset message (newest first): the quarantine and policy fixtures derive from it. */
export const FIXTURE_MESSAGES: readonly FixtureMessage[] = fixtureDataset();

/** @deprecated use `fixtureMessageById` (kept for the 7.1 fixture files). */
export function fixtureMessage(id: string): FixtureMessage | undefined {
  return fixtureMessageById(id);
}

/** 403 unless the caller's role grants the operation (mirrors `x-eg-permissions`). */
export function fixtureGuard(request: FixtureRequest): FixtureResponse | null {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) return apiError(401, 'unauthorized', 'Authentication required');
  if (!canPerform(request.operationId, principal.permissions)) {
    return apiError(403, 'forbidden', 'You do not have permission to perform this action');
  }
  return null;
}

/** Wraps a handler with the permission guard. */
export function guarded(
  handler: (request: FixtureRequest) => FixtureResponse | Promise<FixtureResponse>,
): (request: FixtureRequest) => FixtureResponse | Promise<FixtureResponse> {
  return (request) => fixtureGuard(request) ?? handler(request);
}

type Principal = NonNullable<ReturnType<typeof resolveFixturePrincipal>>;

function principalOf(request: FixtureRequest): Principal {
  const principal = resolveFixturePrincipal(request.token);
  if (!principal) throw new Error('fixture principal missing after the guard');
  return principal;
}

// ---------------------------------------------------------------------------------------------
// GET /messages: validation (shared with saved view definitions), drivers, budget, cap.
// ---------------------------------------------------------------------------------------------

/** Rows examined per request when residual filters apply (the api's scan budget, scaled down). */
export const FIXTURE_SCAN_BUDGET = 40;
/** `API_MESSAGES_SEARCH_MAX_MATCHES` of fixture mode (§2 E14). */
export const FIXTURE_SEARCH_MAX_MATCHES = 200;
/** A `subjectPrefix` that simulates `503 message_search_timeout` in fixture mode. */
export const FIXTURE_TIMEOUT_PREFIX = 'zzz-timeout';

const DIRECTIONS = ['inbound', 'outbound', 'internal'];
const STATUSES = [
  'received',
  'persisted',
  'scanning',
  'scanned',
  'scan_failed',
  'policy_evaluated',
  'approved',
  'quarantined',
  'held_for_review',
  'rejected',
  'delivery_pending',
  'delivery_retry',
  'delivered',
  'archived',
  'expired',
];
const VERDICTS = [
  'clean',
  'spam',
  'bulk',
  'phishing',
  'malware',
  'bec',
  'dlp_violation',
  'suspicious',
  'unknown',
];
const ACTIONS = [
  'deliver',
  'tag',
  'quarantine',
  'discard',
  'reject',
  'require_approval',
  'partial',
];
const RESERVED = ['limit', 'cursor', 'sort', 'from', 'to'];
const FILTER_KEYS = [
  'direction',
  'status',
  'verdict',
  'action',
  'domainId',
  'sender',
  'headerFrom',
  'recipient',
  'internetMessageId',
  'subject',
  'subjectPrefix',
  'senderDomain',
  'recipientDomain',
  'deliveryStatus',
  'quarantineStatus',
  'hasAttachments',
  'riskScore',
  'riskScore.gte',
  'riskScore.lte',
  'riskScore.gt',
  'riskScore.lt',
] as const;
type FilterKey = (typeof FILTER_KEYS)[number];

/** Filter-level permissions of `GET /messages` (§2 E2). */
const FILTER_PERMISSION: Partial<Record<FilterKey, string>> = {
  recipient: 'message:reveal',
  subject: 'message:reveal',
  subjectPrefix: 'message:reveal',
  deliveryStatus: 'delivery:read',
  quarantineStatus: 'quarantine:read',
};

const WS =
  '[\\u0009-\\u000D\\u0020\\u0085\\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000]';
const REPLY_MARKERS = new RegExp(
  `^(?:${WS}*(?:re|fw|fwd|aw|wg|sv|vs|antw|tr|rif|enc|odp)${WS}*(?:\\[[0-9]+\\]${WS}*)?:)+`,
  'iu',
);
const WHITE_SPACE_RUNS = new RegExp(`${WS}+`, 'gu');
const DOMAIN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** The api's subject key (`search-keys.ts`), then folded like `utf8mb4_unicode_ci` (roughly). */
function subjectKey(value: string, truncate = true): string {
  const key = value
    .replace(REPLY_MARKERS, '')
    .replace(WHITE_SPACE_RUNS, ' ')
    .replace(/^ | $/gu, '');
  return truncate ? Array.from(key).slice(0, 128).join('') : key;
}
function fold(value: string): string {
  return value.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
}
function messageIdKey(value: string): string {
  return value
    .replace(/^ +| +$/gu, '')
    .replace(/^<+/u, '')
    .replace(/>+$/u, '')
    .slice(0, 255)
    .toLowerCase();
}
const domainOf = (address: string) =>
  address.includes('@') ? address.slice(address.lastIndexOf('@') + 1).toLowerCase() : null;

interface ParsedFilters {
  lists: Partial<Record<'direction' | 'status' | 'verdict' | 'action', string[]>>;
  text: Partial<
    Record<
      | 'domainId'
      | 'sender'
      | 'headerFrom'
      | 'recipient'
      | 'internetMessageId'
      | 'subject'
      | 'subjectPrefix'
      | 'senderDomain'
      | 'recipientDomain'
      | 'deliveryStatus'
      | 'quarantineStatus',
      string
    >
  >;
  hasAttachments?: boolean;
  risk: { op: 'eq' | 'gte' | 'lte' | 'gt' | 'lt'; value: number }[];
  present: FilterKey[];
}

/**
 * Validates the filters of `GET /messages` like the api's `MessageListQuerySchema` (unknown
 * parameters, enums, comma-list maxima, address and domain shapes, the subject refinements).
 * `prefix` is prepended to the issue paths (`definition.filters.` for saved views).
 */
export function parseMessageFilters(
  entries: readonly [string, string][],
  prefix = '',
): { ok: true; filters: ParsedFilters } | { ok: false; issues: string[] } {
  const issues: string[] = [];
  const filters: ParsedFilters = { lists: {}, text: {}, risk: [], present: [] };
  const seen = new Set<string>();
  for (const [key, raw] of entries) {
    const path = `${prefix}${key}`;
    if (!(FILTER_KEYS as readonly string[]).includes(key)) {
      issues.push(`${path}: unknown parameter`);
      continue;
    }
    if (seen.has(key)) {
      issues.push(`${path}: given more than once`);
      continue;
    }
    seen.add(key);
    const name = key as FilterKey;
    filters.present.push(name);
    const value = raw.trim();
    switch (name) {
      case 'direction':
      case 'status':
      case 'verdict':
      case 'action': {
        const allowed =
          name === 'direction'
            ? DIRECTIONS
            : name === 'status'
              ? STATUSES
              : name === 'verdict'
                ? VERDICTS
                : ACTIONS;
        const values = value.split(',').filter(Boolean);
        if (values.length === 0) issues.push(`${path}: must not be empty`);
        else if (values.length > 5) issues.push(`${path}: at most 5 values`);
        else if (values.some((v) => !allowed.includes(v)))
          issues.push(`${path}: must be one of ${allowed.join(', ')}`);
        else filters.lists[name] = values;
        break;
      }
      case 'domainId':
        if (!UUID.test(value)) issues.push(`${path}: must be a UUID`);
        else filters.text.domainId = value.toLowerCase();
        break;
      case 'sender':
      case 'recipient':
        if (value.length < 3 || value.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(value))
          issues.push(`${path}: must be an address`);
        else filters.text[name] = value.toLowerCase();
        break;
      case 'headerFrom':
        if (value.length < 1 || value.length > 320) issues.push(`${path}: 1-320 characters`);
        else filters.text.headerFrom = value.toLowerCase();
        break;
      case 'internetMessageId':
        if (value.length > 998) issues.push(`${path}: at most 998 characters`);
        else if (messageIdKey(value) === '') issues.push(`${path}: must not be brackets only`);
        else filters.text.internetMessageId = messageIdKey(value);
        break;
      case 'subject':
        if (value.length === 0 || value.length > 998) issues.push(`${path}: 1-998 characters`);
        else if (subjectKey(value) === '')
          issues.push(`${path}: must not be empty after removing reply markers`);
        else filters.text.subject = fold(subjectKey(value));
        break;
      case 'subjectPrefix': {
        const key = subjectKey(value, false);
        const length = Array.from(key).length;
        if (value.length > 998 || length < 3 || length > 128)
          issues.push(`${path}: 3-128 characters after normalization`);
        else filters.text.subjectPrefix = fold(key);
        break;
      }
      case 'senderDomain':
      case 'recipientDomain': {
        const lower = value.toLowerCase();
        const domain = lower.startsWith('@') ? lower.slice(1) : lower;
        if (domain.length > 253 || !DOMAIN.test(domain))
          issues.push(`${path}: must be a domain name (IDNs in A-label form)`);
        else filters.text[name] = domain;
        break;
      }
      case 'deliveryStatus':
        if (!(FIXTURE_DELIVERY_STATUSES as readonly string[]).includes(value))
          issues.push(`${path}: must be one of ${FIXTURE_DELIVERY_STATUSES.join(', ')}`);
        else filters.text.deliveryStatus = value;
        break;
      case 'quarantineStatus':
        if (!(FIXTURE_QUARANTINE_STATES as readonly string[]).includes(value))
          issues.push(`${path}: must be one of ${FIXTURE_QUARANTINE_STATES.join(', ')}`);
        else filters.text.quarantineStatus = value;
        break;
      case 'hasAttachments':
        if (value !== 'true' && value !== 'false') issues.push(`${path}: must be true or false`);
        else filters.hasAttachments = value === 'true';
        break;
      default: {
        const n = Number(value);
        if (!/^\d{1,4}$/.test(value) || n > 1000) issues.push(`${path}: must be 0-1000`);
        else {
          const op = name === 'riskScore' ? 'eq' : (name.split('.')[1] as 'gte');
          filters.risk.push({ op, value: n });
        }
      }
    }
  }
  return issues.length > 0 ? { ok: false, issues } : { ok: true, filters };
}

/** The first filter that needs a permission the caller lacks (§2 E2), or null. */
export function forbiddenFilter(
  present: readonly string[],
  permissions: readonly string[],
): { filter: string; permission: string } | null {
  for (const filter of present) {
    const permission = FILTER_PERMISSION[filter as FilterKey];
    if (permission && !permissions.includes(permission)) return { filter, permission };
  }
  return null;
}

function filterForbiddenResponse(denied: { filter: string; permission: string }): FixtureResponse {
  return apiError(
    403,
    'message_filter_forbidden',
    `The ${denied.filter} filter needs the ${denied.permission} permission`,
    denied,
  );
}

const DRIVER_ORDER = [
  'internetMessageId',
  'sender',
  'headerFrom',
  'recipient',
  'subject',
  'senderDomain',
  'recipientDomain',
  'subjectPrefix',
  'quarantineStatus',
  'deliveryStatus',
] as const;
type Driver = (typeof DRIVER_ORDER)[number] | 'verdict' | 'none' | 'scan';

/** The search driver of §2 E1 (first present filter by priority), `scan` for residuals only. */
export function driverOf(filters: ParsedFilters): Driver {
  for (const name of DRIVER_ORDER) if (filters.text[name] !== undefined) return name;
  if (filters.lists.verdict?.length === 1) return 'verdict';
  return filters.present.length === 0 ? 'none' : 'scan';
}

function matchesFilter(
  m: FixtureMessage,
  name: FilterKey,
  f: ParsedFilters,
  organizationId: string,
): boolean {
  const d = m.detail;
  switch (name) {
    case 'direction':
    case 'status':
    case 'action':
    case 'verdict': {
      const values = f.lists[name] ?? [];
      const actual =
        name === 'direction'
          ? d.direction
          : name === 'status'
            ? d.status
            : name === 'action'
              ? d.finalAction
              : d.finalVerdict;
      return actual !== null && values.includes(actual);
    }
    case 'domainId':
      return messageDetailView(m, organizationId).domainId === f.text.domainId;
    case 'sender':
      return d.envelopeFrom.toLowerCase() === f.text.sender;
    case 'headerFrom':
      return (d.headerFrom ?? '').toLowerCase() === f.text.headerFrom;
    case 'recipient':
      return m.recipients.some((r) => r.toLowerCase() === f.text.recipient);
    case 'internetMessageId':
      return (
        d.internetMessageId !== null &&
        messageIdKey(d.internetMessageId) === f.text.internetMessageId
      );
    case 'subject':
      return d.subject !== null && fold(subjectKey(d.subject)) === f.text.subject;
    case 'subjectPrefix':
      return (
        d.subject !== null && fold(subjectKey(d.subject)).startsWith(f.text.subjectPrefix ?? '')
      );
    case 'senderDomain':
      return domainOf(d.envelopeFrom) === f.text.senderDomain;
    case 'recipientDomain':
      return m.recipients.some((r) => domainOf(r) === f.text.recipientDomain);
    case 'deliveryStatus':
      return m.recipientRows.some((r) => r.delivery === f.text.deliveryStatus);
    case 'quarantineStatus':
      return quarantineStatesOf(m).includes(f.text.quarantineStatus ?? '');
    case 'hasAttachments':
      return d.attachmentCount > 0 === f.hasAttachments;
    default:
      return f.risk.every(({ op, value }) => {
        const score = d.riskScore;
        if (score === null) return false;
        return op === 'eq'
          ? score === value
          : op === 'gte'
            ? score >= value
            : op === 'lte'
              ? score <= value
              : op === 'gt'
                ? score > value
                : score < value;
      });
  }
}

function encodeCursor(offset: number, hash: string, driver: Driver): string {
  return Buffer.from(JSON.stringify({ v: 1, o: offset, f: hash, d: driver })).toString('base64url');
}

function decodeCursor(cursor: string, hash: string, driver: Driver): number | null {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
      o?: unknown;
      f?: unknown;
      d?: unknown;
    };
    if (typeof parsed.o !== 'number' || parsed.f !== hash || parsed.d !== driver) return null;
    return parsed.o;
  } catch {
    return null;
  }
}

function listMessages(request: FixtureRequest): FixtureResponse {
  const principal = principalOf(request);
  const q = request.query;
  const filterEntries: [string, string][] = [];
  const issues: string[] = [];
  for (const [key, value] of q.entries()) {
    if (RESERVED.includes(key)) continue;
    filterEntries.push([key, value]);
  }
  const parsed = parseMessageFilters(filterEntries);
  if (!parsed.ok) issues.push(...parsed.issues);
  const sort = q.get('sort') ?? '-receivedAt';
  if (sort !== '-receivedAt' && sort !== 'receivedAt')
    issues.push('sort: -receivedAt or receivedAt');
  const limitRaw = q.get('limit') ?? '25';
  const limit = Number(limitRaw);
  if (!/^\d{1,3}$/.test(limitRaw) || limit < 1 || limit > 100) issues.push('limit: 1-100');
  const now = Date.now();
  const to = q.get('to') ? Date.parse(q.get('to') ?? '') : now;
  const from = q.get('from') ? Date.parse(q.get('from') ?? '') : to - 86_400_000;
  if (!Number.isFinite(from) || !Number.isFinite(to)) issues.push('from: must be ISO 8601');
  else if (to <= from) issues.push('to: must be after from');
  else if (to - from > 31 * 86_400_000) issues.push('to: the range is at most 31 days');
  if (issues.length > 0 || !parsed.ok) return apiError(400, 'validation_failed', issues);
  const filters = parsed.filters;

  const denied = forbiddenFilter(filters.present, principal.permissions);
  if (denied) return filterForbiddenResponse(denied);
  if (filters.text.domainId && !findDomain(principal.organizationId, filters.text.domainId)) {
    return apiError(404, 'domain_not_found', 'Domain not found');
  }

  const driver = driverOf(filters);
  const hash = String(
    hashString(
      JSON.stringify([...q.entries()].filter(([k]) => k !== 'cursor' && k !== 'limit').sort()),
    ),
  );
  let offset = 0;
  const cursor = q.get('cursor');
  if (cursor) {
    const decoded = decodeCursor(cursor, hash, driver);
    if (decoded === null) {
      return apiError(
        400,
        'cursor_invalid',
        'The cursor is invalid for these filters; restart the list',
      );
    }
    offset = decoded;
  }

  const inRange = FIXTURE_MESSAGES.filter((m) => {
    const t = Date.parse(m.detail.receivedAt);
    return t >= from && t < to;
  });
  const ordered = sort === 'receivedAt' ? [...inRange].reverse() : inRange;
  const org = principal.organizationId;
  const driverFilter: FilterKey | null = driver === 'none' || driver === 'scan' ? null : driver;
  const candidates = driverFilter
    ? ordered.filter((m) => matchesFilter(m, driverFilter, filters, org))
    : ordered;
  const residuals = filters.present.filter((name) => name !== driverFilter);

  if (driver === 'subjectPrefix') {
    if (filters.text.subjectPrefix === FIXTURE_TIMEOUT_PREFIX) {
      return apiError(
        503,
        'message_search_timeout',
        'The subject search took too long; type more of the subject or narrow the range',
      );
    }
    if (candidates.length - offset > FIXTURE_SEARCH_MAX_MATCHES) {
      return apiError(
        422,
        'message_search_too_broad',
        `More than ${FIXTURE_SEARCH_MAX_MATCHES} messages in this range start with that subject; type more of it, use the exact subject or narrow the range`,
        { maxMatches: FIXTURE_SEARCH_MAX_MATCHES },
      );
    }
  }

  const passes = (m: FixtureMessage) =>
    residuals.every((name) => matchesFilter(m, name, filters, org));
  let page: FixtureMessage[];
  let nextOffset: number | null;
  if (residuals.length === 0) {
    // Exact page in the driver's index order.
    page = candidates.slice(offset, offset + limit);
    nextOffset = offset + limit < candidates.length ? offset + limit : null;
  } else {
    // Budgeted page: at most FIXTURE_SCAN_BUDGET driver entries examined per request.
    page = [];
    let position = offset;
    let examined = 0;
    while (position < candidates.length && examined < FIXTURE_SCAN_BUDGET && page.length < limit) {
      const m = candidates[position];
      position += 1;
      examined += 1;
      if (m && passes(m)) page.push(m);
    }
    nextOffset = position < candidates.length ? position : null;
  }
  return ok('MessagesController_list_v1', {
    data: page.map((m) => messageListItem(m, org)),
    nextCursor: nextOffset === null ? null : encodeCursor(nextOffset, hash, driver),
  });
}

// ---------------------------------------------------------------------------------------------
// POST /messages/reveal and the in-memory audit list.
// ---------------------------------------------------------------------------------------------

type AuditRow = ListItem<'AuditLogsController_search_v1'>;
interface RevealState {
  audit: (AuditRow & { organizationId: string })[];
  calls: Map<string, number[]>;
  nextId: number;
}
const revealGlobal = globalThis as typeof globalThis & { __egDevFixtureReveal?: RevealState };
function revealState(): RevealState {
  revealGlobal.__egDevFixtureReveal ??= { audit: [], calls: new Map(), nextId: 9_500_000 };
  return revealGlobal.__egDevFixtureReveal;
}

/** `API_MESSAGES_REVEAL_PER_MINUTE` of fixture mode (the api default). */
export const FIXTURE_REVEALS_PER_MINUTE = 30;

/**
 * The audit rows of the message fixtures for an organization, newest first (shown by the audit
 * fixtures): `message.revealed`, `message.rescan_requested` and `dlp_evidence.read` written in
 * fixture mode, plus the dataset's historic rescans.
 */
export function revealAuditRows(organizationId: string): AuditRow[] {
  const recorded = revealState()
    .audit.filter((row) => row.organizationId === organizationId)
    .map(({ organizationId: _org, ...row }) => {
      void _org;
      return row;
    })
    .reverse();
  return [...recorded, ...historicMessageAuditRows(FIXTURE_MESSAGES)];
}

/** Records one audit row of the message fixtures (before the response, like the api). */
export function recordAudit(
  principal: Principal,
  entry: {
    action: string;
    resourceType: string;
    resourceId: string;
    metadata: Record<string, unknown>;
  },
): void {
  const state = revealState();
  state.audit.push({
    organizationId: principal.organizationId,
    id: String((state.nextId += 1)),
    createdAt: new Date().toISOString(),
    actor: { type: 'user', id: principal.userId },
    action: entry.action,
    resourceType: entry.resourceType,
    resourceId: entry.resourceId,
    correlationId: crypto.randomUUID(),
    sourceIp: '198.51.100.10',
    metadata: { ...entry.metadata },
  });
}

/** Per-principal reveal limit (one bucket for both reveal operations), or a 429. */
export function revealRateLimit(principal: Principal, now = Date.now()): FixtureResponse | null {
  const state = revealState();
  const recent = (state.calls.get(principal.userId) ?? []).filter((t) => now - t < 60_000);
  if (recent.length >= FIXTURE_REVEALS_PER_MINUTE) {
    const retryAfter = Math.max(1, Math.ceil((60_000 - (now - (recent[0] ?? now))) / 1000));
    const response = apiError(429, 'rate_limited', 'Too many reveals; try again later', {
      scope: 'route',
    });
    return { ...response, headers: { 'retry-after': String(retryAfter) } };
  }
  recent.push(now);
  state.calls.set(principal.userId, recent);
  return null;
}

/** Records one `message.revealed` row per message (before the response, like the api). */
export function recordReveal(
  principal: Principal,
  messageIds: readonly string[],
  metadata: Record<string, unknown>,
  at: string,
): void {
  const state = revealState();
  for (const messageId of messageIds) {
    state.audit.push({
      organizationId: principal.organizationId,
      id: String((state.nextId += 1)),
      createdAt: at,
      actor: { type: 'user', id: principal.userId },
      action: 'message.revealed',
      resourceType: 'message',
      resourceId: messageId,
      correlationId: crypto.randomUUID(),
      sourceIp: '198.51.100.10',
      metadata: { ...metadata },
    });
  }
}

function revealMany(request: FixtureRequest): FixtureResponse {
  const principal = principalOf(request);
  const body = request.body;
  const issues: string[] = [];
  let ids: string[] = [];
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    issues.push('(body): must be an object');
  } else {
    const record = body as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (key !== 'messageIds') issues.push(`${key}: unknown property`);
    }
    const value = record.messageIds;
    if (!Array.isArray(value)) issues.push('messageIds: required array');
    else if (value.length < 1 || value.length > 100) issues.push('messageIds: 1-100 ids');
    else if (value.some((id) => typeof id !== 'string' || !UUID.test(id)))
      issues.push('messageIds: every id must be a UUID');
    else {
      ids = value.map((id: string) => id.toLowerCase());
      if (new Set(ids).size !== ids.length) issues.push('messageIds: ids must be distinct');
    }
  }
  if (issues.length > 0) return apiError(400, 'validation_failed', issues);
  const limited = revealRateLimit(principal);
  if (limited) return limited;
  const found = ids.flatMap((id) => {
    const message = fixtureMessageById(id);
    return message ? [{ id: message.detail.id, subject: message.detail.subject }] : [];
  });
  const revealedAt = new Date().toISOString();
  recordReveal(
    principal,
    found.map((item) => item.id),
    { fields: ['subject'], bulk: true },
    revealedAt,
  );
  return {
    status: 200,
    body: {
      revealedAt,
      data: found,
    } satisfies SuccessBody<'MessageRevealController_revealMany_v1'>,
    headers: { 'cache-control': 'no-store' },
  };
}

// ---------------------------------------------------------------------------------------------
// Saved views (per fixture user and organization, on globalThis).
// ---------------------------------------------------------------------------------------------

type SavedView = SuccessBody<'SavedViewsController_get_v1'>;
interface ViewRecord {
  view: SavedView;
  userId: string;
  organizationId: string;
}
interface ViewsState {
  views: Map<string, ViewRecord>;
  seeded: Set<string>;
}
const viewsGlobal = globalThis as typeof globalThis & { __egDevFixtureSavedViews?: ViewsState };
function viewsState(): ViewsState {
  viewsGlobal.__egDevFixtureSavedViews ??= { views: new Map(), seeded: new Set() };
  return viewsGlobal.__egDevFixtureSavedViews;
}

/** `SAVED_VIEWS_MAX_PER_USER` of fixture mode (the api default). */
export const FIXTURE_SAVED_VIEWS_MAX = 50;
const VIEW_KIND = 'message_explorer';
const COLUMN_ID = /^[a-zA-Z][a-zA-Z0-9]{0,31}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function seedViews(principal: Principal): void {
  const state = viewsState();
  const key = `${principal.organizationId}:${principal.userId}`;
  if (state.seeded.has(key)) return;
  state.seeded.add(key);
  const anchor = fixtureDatasetAnchor();
  const seeds: { name: string; definition: SavedView['definition'] }[] = [
    {
      name: 'Inbound phishing and malware, last 7 days',
      definition: {
        version: 1,
        filters: { direction: 'inbound', verdict: 'phishing,malware' },
        sort: '-receivedAt',
        range: { kind: 'relative', preset: '7d' },
        columns: null,
      },
    },
    {
      // An outdated view: a parameter the explorer does not offer and an unknown column.
      name: 'Legacy triage view',
      definition: {
        version: 1,
        filters: { 'riskScore.gt': '700', hasAttachments: 'true' },
        sort: '-receivedAt',
        range: { kind: 'relative', preset: '30d' },
        columns: ['receivedAt', 'from', 'subject', 'risk', 'legacyScore'],
      },
    },
  ];
  seeds.forEach((seed, i) => {
    const created = new Date(anchor - (i + 2) * 86_400_000).toISOString();
    const id = stableUuid(`saved-view:${key}:${i}`);
    state.views.set(id, {
      userId: principal.userId,
      organizationId: principal.organizationId,
      view: {
        id,
        kind: VIEW_KIND,
        name: seed.name,
        definition: seed.definition,
        rowVersion: 1,
        createdAt: created,
        updatedAt: created,
      },
    });
  });
}

function ownViews(principal: Principal): ViewRecord[] {
  seedViews(principal);
  return [...viewsState().views.values()]
    .filter((r) => r.userId === principal.userId && r.organizationId === principal.organizationId)
    .sort(
      (a, b) =>
        b.view.createdAt.localeCompare(a.view.createdAt) || b.view.id.localeCompare(a.view.id),
    );
}

/** Member users only: an override session is refused (`saved_views_member_only`, §2 E4). */
function viewsPrincipal(request: FixtureRequest): Principal | FixtureResponse {
  const principal = principalOf(request);
  if (principal.override) {
    return apiError(
      403,
      'saved_views_member_only',
      'Saved views are available to members of the organization only',
    );
  }
  return principal;
}

const isResponse = (value: Principal | FixtureResponse): value is FixtureResponse =>
  'status' in value;

function viewName(value: unknown, issues: string[]): string | null {
  if (typeof value !== 'string') {
    issues.push('name: required string');
    return null;
  }
  const name = value.trim();
  // eslint-disable-next-line no-control-regex -- the api refuses control characters
  if (name.length < 1 || name.length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) {
    issues.push('name: 1-80 characters without control characters');
    return null;
  }
  return name;
}

/** Validates a definition like the api (strict shape, real filter validation, ≤ 8 KiB). */
function validateDefinition(
  value: unknown,
  issues: string[],
): { definition: SavedView['definition']; present: string[] } | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    issues.push('definition: required object');
    return null;
  }
  const d = value as Record<string, unknown>;
  for (const key of Object.keys(d)) {
    if (!['version', 'filters', 'sort', 'range', 'columns'].includes(key))
      issues.push(`definition.${key}: unknown property`);
  }
  if (d.version !== 1) issues.push('definition.version: must be 1');
  if (d.sort !== '-receivedAt' && d.sort !== 'receivedAt')
    issues.push('definition.sort: -receivedAt or receivedAt');
  const filters = d.filters;
  let present: string[] = [];
  if (!filters || typeof filters !== 'object' || Array.isArray(filters)) {
    issues.push('definition.filters: required object');
  } else {
    const entries = Object.entries(filters as Record<string, unknown>);
    if (entries.length > 24) issues.push('definition.filters: at most 24 filters');
    const strings: [string, string][] = [];
    for (const [key, raw] of entries) {
      if (RESERVED.includes(key)) issues.push(`definition.filters.${key}: not allowed`);
      else if (typeof raw !== 'string' || raw.length < 1 || raw.length > 998)
        issues.push(`definition.filters.${key}: 1-998 characters`);
      else strings.push([key, raw]);
    }
    const parsed = parseMessageFilters(strings, 'definition.filters.');
    if (!parsed.ok) issues.push(...parsed.issues);
    else present = parsed.filters.present;
  }
  const range = d.range as Record<string, unknown> | undefined;
  if (!range || typeof range !== 'object') issues.push('definition.range: required object');
  else if (range.kind === 'relative') {
    if (Object.keys(range).some((k) => k !== 'kind' && k !== 'preset'))
      issues.push('definition.range: unknown property');
    if (!['1h', '24h', '7d', '30d'].includes(String(range.preset)))
      issues.push('definition.range.preset: 1h, 24h, 7d or 30d');
  } else if (range.kind === 'absolute') {
    const from =
      typeof range.from === 'string' && ISO_INSTANT.test(range.from) ? Date.parse(range.from) : NaN;
    const to =
      typeof range.to === 'string' && ISO_INSTANT.test(range.to) ? Date.parse(range.to) : NaN;
    if (!Number.isFinite(from) || !Number.isFinite(to))
      issues.push('definition.range: ISO 8601 from and to');
    else if (to <= from) issues.push('definition.range.to: must be after from');
    else if (to - from > 31 * 86_400_000) issues.push('definition.range: at most 31 days');
  } else {
    issues.push('definition.range.kind: relative or absolute');
  }
  const columns = d.columns;
  if (columns !== null) {
    if (!Array.isArray(columns)) issues.push('definition.columns: array or null');
    else if (columns.length > 24) issues.push('definition.columns: at most 24');
    else if (columns.some((c) => typeof c !== 'string' || !COLUMN_ID.test(c)))
      issues.push('definition.columns: ids of letters and digits');
    else if (new Set(columns).size !== columns.length)
      issues.push('definition.columns: unique ids');
  }
  if (JSON.stringify(value).length > 8192) issues.push('definition: at most 8192 bytes');
  return issues.length > 0 ? null : { definition: value as SavedView['definition'], present };
}

function nameTaken(name: string, views: readonly ViewRecord[], except?: string): boolean {
  return views.some(
    (r) => r.view.id !== except && r.view.name.toLowerCase() === name.toLowerCase(),
  );
}

const viewNotFound = () => apiError(404, 'saved_view_not_found', 'Saved view not found');

function listViews(request: FixtureRequest): FixtureResponse {
  const principal = viewsPrincipal(request);
  if (isResponse(principal)) return principal;
  const q = request.query;
  const issues: string[] = [];
  if (q.get('kind') !== VIEW_KIND) issues.push('kind: must be message_explorer');
  const sort = q.get('sort');
  if (sort !== null && sort !== '-createdAt') issues.push('sort: -createdAt');
  const limitRaw = q.get('limit') ?? '25';
  const limit = Number(limitRaw);
  if (!/^\d{1,3}$/.test(limitRaw) || limit < 1 || limit > 100) issues.push('limit: 1-100');
  if (issues.length > 0) return apiError(400, 'validation_failed', issues);
  const views = ownViews(principal).map((r) => r.view);
  let offset = 0;
  const cursor = q.get('cursor');
  if (cursor) {
    const decoded = decodeCursor(cursor, 'saved-views', 'none');
    if (decoded === null) return apiError(400, 'cursor_invalid', 'The cursor is invalid');
    offset = decoded;
  }
  const page = views.slice(offset, offset + limit);
  return ok('SavedViewsController_list_v1', {
    data: page,
    nextCursor:
      offset + limit < views.length ? encodeCursor(offset + limit, 'saved-views', 'none') : null,
  });
}

function createView(request: FixtureRequest): FixtureResponse {
  const principal = viewsPrincipal(request);
  if (isResponse(principal)) return principal;
  const body = (request.body ?? {}) as Record<string, unknown>;
  const issues: string[] = [];
  for (const key of Object.keys(body)) {
    if (!['kind', 'name', 'definition'].includes(key)) issues.push(`${key}: unknown property`);
  }
  if (body.kind !== VIEW_KIND) issues.push('kind: must be message_explorer');
  const views = ownViews(principal);
  const name = viewName(body.name, issues);
  const valid = validateDefinition(body.definition, issues);
  if (issues.length > 0 || !name || !valid) return apiError(400, 'validation_failed', issues);
  const denied = forbiddenFilter(valid.present, principal.permissions);
  if (denied) return filterForbiddenResponse(denied);
  if (views.length >= FIXTURE_SAVED_VIEWS_MAX) {
    return apiError(
      409,
      'saved_view_limit_reached',
      'You have reached the maximum number of saved views',
      {
        limit: FIXTURE_SAVED_VIEWS_MAX,
      },
    );
  }
  if (nameTaken(name, views)) {
    return apiError(409, 'saved_view_name_taken', 'You already have a view with this name');
  }
  const now = new Date().toISOString();
  const view: SavedView = {
    id: crypto.randomUUID(),
    kind: VIEW_KIND,
    name,
    definition: valid.definition,
    rowVersion: 1,
    createdAt: now,
    updatedAt: now,
  };
  viewsState().views.set(view.id, {
    view,
    userId: principal.userId,
    organizationId: principal.organizationId,
  });
  return ok('SavedViewsController_create_v1', view, 201);
}

function withView(
  handler: (record: ViewRecord, request: FixtureRequest, principal: Principal) => FixtureResponse,
) {
  return (request: FixtureRequest): FixtureResponse => {
    const principal = viewsPrincipal(request);
    if (isResponse(principal)) return principal;
    const id = (request.params.viewId ?? '').toLowerCase();
    const record = ownViews(principal).find((r) => r.view.id === id);
    return record ? handler(record, request, principal) : viewNotFound();
  };
}

const getView = withView((record) => ok('SavedViewsController_get_v1', record.view));

const updateView = withView((record, request, principal) => {
  const body = (request.body ?? {}) as Record<string, unknown>;
  const issues: string[] = [];
  for (const key of Object.keys(body)) {
    if (!['name', 'definition', 'expectedRowVersion'].includes(key))
      issues.push(`${key}: unknown property`);
  }
  const views = ownViews(principal);
  const name = viewName(body.name, issues);
  const valid = validateDefinition(body.definition, issues);
  const expected = body.expectedRowVersion;
  if (typeof expected !== 'number' || !Number.isInteger(expected) || expected < 1)
    issues.push('expectedRowVersion: positive integer');
  if (issues.length > 0 || !name || !valid) return apiError(400, 'validation_failed', issues);
  const denied = forbiddenFilter(valid.present, principal.permissions);
  if (denied) return filterForbiddenResponse(denied);
  if (expected !== record.view.rowVersion) {
    return apiError(409, 'saved_view_conflict', 'The view was changed by another request', {
      currentRowVersion: record.view.rowVersion,
    });
  }
  if (nameTaken(name, views, record.view.id)) {
    return apiError(409, 'saved_view_name_taken', 'You already have a view with this name');
  }
  record.view = {
    ...record.view,
    name,
    definition: valid.definition,
    rowVersion: record.view.rowVersion + 1,
    updatedAt: new Date().toISOString(),
  };
  return ok('SavedViewsController_update_v1', record.view);
});

const removeView = withView((record) => {
  viewsState().views.delete(record.view.id);
  return noContent();
});

// ---------------------------------------------------------------------------------------------
// Email Details (step 7.2 WP4, §2 E14): detail, lifecycle, history, rescan, recipients, single
// reveal, headers, scans, evidence, deliveries and their events.
// ---------------------------------------------------------------------------------------------

/** After this long a fixture rescan has completed (the new round is scored and evaluated). */
export const FIXTURE_RESCAN_MS = 20_000;

interface DetailsState {
  rescans: Map<string, FixtureRescan[]>;
  idempotency: Map<string, { fingerprint: string; response: FixtureResponse }>;
}
const detailsGlobal = globalThis as typeof globalThis & { __egDevFixtureDetails?: DetailsState };
function detailsState(): DetailsState {
  detailsGlobal.__egDevFixtureDetails ??= { rescans: new Map(), idempotency: new Map() };
  return detailsGlobal.__egDevFixtureDetails;
}
const rescansOf = (message: FixtureMessage) => detailsState().rescans.get(message.detail.id) ?? [];

function withMessage(
  handler: (
    message: FixtureMessage,
    request: FixtureRequest,
    principal: Principal,
  ) => FixtureResponse,
) {
  return guarded((request) => {
    const message = fixtureMessageById(request.params.messageId ?? '');
    if (!message) return apiError(404, 'message_not_found', 'Message not found');
    return handler(message, request, principalOf(request));
  });
}

function offsetPage<T>(items: readonly T[], query: URLSearchParams, max = 100, fallback = 25) {
  const limit = Math.min(max, Math.max(1, Number(query.get('limit') ?? fallback) || fallback));
  const cursor = query.get('cursor');
  const offset = cursor ? Number(Buffer.from(cursor, 'base64url').toString('utf8')) || 0 : 0;
  const page = items.slice(offset, offset + limit);
  const next =
    offset + limit < items.length
      ? Buffer.from(String(offset + limit)).toString('base64url')
      : null;
  return { page, next };
}

/** A v1-style cursor bound to its resource, message and organization (`400 cursor_invalid`). */
function boundCursor(offset: number, resource: string, messageId: string, organizationId: string) {
  return Buffer.from(
    JSON.stringify({ v: 1, r: resource, m: messageId, g: organizationId, o: offset }),
  ).toString('base64url');
}
function readBoundCursor(
  cursor: string,
  resource: string,
  messageId: string,
  organizationId: string,
): number | null {
  try {
    const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
    return parsed.v === 1 &&
      parsed.r === resource &&
      parsed.m === messageId &&
      parsed.g === organizationId &&
      typeof parsed.o === 'number'
      ? parsed.o
      : null;
  } catch {
    return null;
  }
}

/** The message as `GET /messages/{id}` returns it, with fixture rescans applied. */
function detailOf(message: FixtureMessage, organizationId: string) {
  const view = messageDetailView(message, organizationId);
  const state = currentState(message, rescansOf(message));
  return {
    ...view,
    status: state.status,
    statusChangedAt: state.statusChangedAt,
    version: state.version,
    lifecycleRound: state.lifecycleRound,
  };
}

/** Rounds newest first: fixture rescans (running, then scored) before the dataset's rounds. */
function roundsOf(message: FixtureMessage, now = Date.now()) {
  const added = rescansOf(message)
    .map((rescan) => {
      if (now < rescan.completedAt) {
        const started = new Date(rescan.startedAt).toISOString();
        return {
          scanId: String(800_000 + rescan.lifecycleRound),
          round: rescan.lifecycleRound,
          scanKind: 'rescan' as const,
          status: 'running' as const,
          verdict: null,
          reasonCodes: [],
          requiredEngines: ['rspamd', 'attachment', 'url', 'bec', 'dlp'],
          startedAt: started,
          completedAt: null,
          deadlineAt: new Date(rescan.startedAt + 120_000).toISOString(),
          auth: null,
          engines: [],
          risk: [],
          policy: null,
        } satisfies ListItem<'MessageScansController_scansOf_v1'>;
      }
      const detail = { ...message.detail, lifecycleRound: rescan.lifecycleRound };
      const round = roundFor(
        detail,
        rescan.lifecycleRound,
        new SeededRandom(`${message.detail.id}:rescan:${rescan.lifecycleRound}`),
      );
      return enrichRound(message, {
        ...round,
        startedAt: new Date(rescan.startedAt).toISOString(),
      });
    })
    .reverse();
  return [...added, ...enrichedRounds(message)];
}

/** `dlp` masked findings only for callers also holding `dlp:read` (step 4.5). */
function withoutDlp(round: ListItem<'MessageScansController_scansOf_v1'>) {
  return {
    ...round,
    engines: round.engines.map((engine) =>
      engine.engine === 'dlp' ? { ...engine, dlp: null } : engine,
    ),
  };
}

function scansOf(message: FixtureMessage, request: FixtureRequest, principal: Principal) {
  const { page, next } = offsetPage(roundsOf(message), request.query, 20, 10);
  const dlp = principal.permissions.includes('dlp:read');
  return ok('MessageScansController_scansOf_v1', {
    messageId: message.detail.id,
    data: dlp ? page : page.map(withoutDlp),
    nextCursor: next,
  });
}

function evaluationsOf(message: FixtureMessage) {
  const now = Date.now();
  const added = rescansOf(message)
    .filter((rescan) => now >= rescan.completedAt)
    .map((rescan) =>
      evaluationFor(
        { ...message.detail, lifecycleRound: rescan.lifecycleRound },
        String(900_000 + rescan.lifecycleRound),
        rescan.lifecycleRound,
      ),
    )
    .reverse();
  return [...added, ...message.evaluations];
}

function rescan(message: FixtureMessage, request: FixtureRequest, principal: Principal) {
  const key = request.headers.get('idempotency-key');
  if (!key) {
    return apiError(400, 'idempotency_key_required', 'The Idempotency-Key header is required');
  }
  const state = detailsState();
  const scoped = `${principal.organizationId}:${principal.userId}:${key}`;
  const fingerprint = JSON.stringify([request.operationId, request.params, request.body]);
  const stored = state.idempotency.get(scoped);
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
  const body = (request.body ?? {}) as Record<string, unknown>;
  const issues: string[] = [];
  for (const k of Object.keys(body)) {
    if (k !== 'expectedVersion' && k !== 'reason') issues.push(`${k}: unknown property`);
  }
  const expected = body.expectedVersion;
  if (typeof expected !== 'number' || !Number.isInteger(expected) || expected < 0)
    issues.push('expectedVersion: integer ≥ 0');
  const reason = body.reason;
  if (typeof reason !== 'string' || reason.length < 10 || reason.length > 500)
    issues.push('reason: 10-500 characters');
  if (issues.length > 0) return apiError(400, 'validation_failed', issues);
  const now = Date.now();
  const rescans = rescansOf(message);
  const current = currentState(message, rescans, now);
  const conflict = { currentState: current.status, currentVersion: current.version };
  if (!rescanAllowed(current.status)) {
    return apiError(
      409,
      'message_state_conflict',
      `A ${current.status} message cannot be rescanned`,
      conflict,
    );
  }
  if (expected !== current.version) {
    return apiError(409, 'message_version_conflict', 'The message changed; reload it', conflict);
  }
  if (
    (current.status === 'quarantined' || current.status === 'held_for_review') &&
    !principal.permissions.includes('quarantine:release')
  ) {
    return apiError(
      403,
      'quarantine_rescan_forbidden',
      'Rescanning a quarantined or held message also needs quarantine:release',
    );
  }
  const last = rescans.at(-1);
  const running = last && now < last.completedAt;
  const next: FixtureRescan = {
    version: current.version + 1,
    lifecycleRound: current.lifecycleRound + 1,
    startedAt: now,
    completedAt: now + FIXTURE_RESCAN_MS,
    previousStatus: running ? last.previousStatus : current.status,
    actorId: principal.userId,
  };
  state.rescans.set(message.detail.id, [
    ...rescans.map((r) =>
      r === last && running ? { ...r, completedAt: Number.POSITIVE_INFINITY } : r,
    ),
    next,
  ]);
  recordAudit(principal, {
    action: 'message.rescan_requested',
    resourceType: 'message',
    resourceId: message.detail.id,
    metadata: {
      fromState: current.status,
      lifecycleRound: next.lifecycleRound,
      quarantineEntriesSuperseded: 0,
    },
  });
  const response = ok(
    'MessageLifecycleController_rescan_v1',
    {
      messageId: message.detail.id,
      state: 'scanning',
      version: next.version,
      lifecycleRound: next.lifecycleRound,
      rescanEventId: crypto.randomUUID(),
      note: 'Every registered scan engine scans the new round; earlier rounds stay unchanged.',
    },
    202,
  );
  state.idempotency.set(scoped, { fingerprint, response });
  return response;
}

const REVEAL_FIELDS = ['subject', 'headers', 'recipients'];

function revealOne(message: FixtureMessage, request: FixtureRequest, principal: Principal) {
  const body = request.body;
  const issues: string[] = [];
  let fields: string[] = [];
  let cursor: string | undefined;
  let limit = 100;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    issues.push('(body): must be an object');
  } else {
    const record = body as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (!['fields', 'recipientsCursor', 'recipientsLimit'].includes(key))
        issues.push(`${key}: unknown property`);
    }
    const value = record.fields;
    if (!Array.isArray(value) || value.length < 1 || value.length > 3)
      issues.push('fields: 1-3 of subject, headers, recipients');
    else if (value.some((f) => typeof f !== 'string' || !REVEAL_FIELDS.includes(f)))
      issues.push('fields: subject, headers or recipients');
    else if (new Set(value).size !== value.length) issues.push('fields: must be distinct');
    else fields = value as string[];
    if (record.recipientsCursor !== undefined) {
      if (typeof record.recipientsCursor !== 'string' || record.recipientsCursor.length < 1)
        issues.push('recipientsCursor: string');
      else cursor = record.recipientsCursor;
    }
    if (record.recipientsLimit !== undefined) {
      const l = record.recipientsLimit;
      if (typeof l !== 'number' || !Number.isInteger(l) || l < 1 || l > 100)
        issues.push('recipientsLimit: 1-100');
      else limit = l;
    }
    if (
      (record.recipientsCursor !== undefined || record.recipientsLimit !== undefined) &&
      !fields.includes('recipients')
    )
      issues.push('recipientsCursor: only with the recipients field');
  }
  if (issues.length > 0) return apiError(400, 'validation_failed', issues);
  let offset = 0;
  if (cursor) {
    const decoded = readBoundCursor(
      cursor,
      'message_recipients_reveal',
      message.detail.id,
      principal.organizationId,
    );
    if (decoded === null) return apiError(400, 'cursor_invalid', 'The cursor is invalid');
    offset = decoded;
  }
  const limited = revealRateLimit(principal);
  if (limited) return limited;
  const revealedAt = new Date().toISOString();
  const out: SuccessBody<'MessageRevealController_reveal_v1'> = {
    messageId: message.detail.id,
    revealedAt,
  };
  const metadata: Record<string, unknown> = { fields };
  if (fields.includes('subject')) out.subject = message.detail.subject;
  if (fields.includes('headers')) {
    out.headers = storedHeaders(message).filter((h) => isRevealableHeader(h.name));
    metadata.headerCount = out.headers.length;
  }
  if (fields.includes('recipients')) {
    const page = message.recipientRows.slice(offset, offset + limit);
    out.recipients = {
      data: page.map((row) => ({
        rcptSeq: row.rcptSeq,
        address: row.address,
        userId: matchedUserOf(row.address),
      })),
      nextCursor:
        offset + limit < message.recipientRows.length
          ? boundCursor(
              offset + limit,
              'message_recipients_reveal',
              message.detail.id,
              principal.organizationId,
            )
          : null,
    };
    metadata.recipients = {
      count: page.length,
      firstRcptSeq: page[0]?.rcptSeq ?? null,
      lastRcptSeq: page.at(-1)?.rcptSeq ?? null,
    };
  }
  recordReveal(principal, [message.detail.id], metadata, revealedAt);
  return { status: 200, body: out, headers: { 'cache-control': 'no-store' } };
}

function headersOf(message: FixtureMessage) {
  return ok('MessageHeadersController_headers_v1', {
    messageId: message.detail.id,
    availability: headerAvailability(message),
    storedHeaderNames: STORED_HEADER_NAMES,
    safeHeaderNames: SAFE_HEADER_NAMES,
    headers: storedHeaders(message).map((h) =>
      isSafeHeader(h.name)
        ? { seq: h.seq, name: h.name, value: h.value, masked: false }
        : { seq: h.seq, name: h.name, value: null, masked: true },
    ),
  });
}

function evidence(message: FixtureMessage, request: FixtureRequest, principal: Principal) {
  if (!principal.mfaAuthenticated) {
    return apiError(403, 'mfa_required', 'This route needs a session signed in with MFA');
  }
  const scanId = request.params.scanId ?? '';
  const round = roundsOf(message).find((r) => r.scanId === scanId);
  if (!round) return apiError(404, 'scan_not_found', 'Scan not found');
  const dlp = round.engines.find((e) => e.engine === 'dlp')?.dlp;
  if (!dlp || dlp.evidence.status !== 'stored') {
    return apiError(404, 'dlp_evidence_not_found', 'No DLP evidence is stored for this round');
  }
  const body = dlpEvidenceOf(message, scanId);
  // Audited before the value leaves (the api commits `dlp_evidence.read` before decrypting).
  recordAudit(principal, {
    action: 'dlp_evidence.read',
    resourceType: 'dlp_evidence',
    resourceId: message.detail.id,
    metadata: { scanId, matchCount: body.matches.length },
  });
  return {
    status: 200,
    body: {
      messageId: message.detail.id,
      scanId,
      matchCount: body.matches.length + body.dropped,
      expiresAt: dlp.evidence.expiresAt ?? new Date().toISOString(),
      evidence: body,
    } satisfies SuccessBody<'DlpMessageEvidenceController_read_v1'>,
    headers: { 'cache-control': 'no-store' },
  };
}

function recipientsOf(message: FixtureMessage, request: FixtureRequest, principal: Principal) {
  const q = request.query;
  const sort = q.get('sort');
  if (sort !== null && sort !== 'rcptSeq')
    return apiError(400, 'validation_failed', ['sort: rcptSeq']);
  const limit = Math.min(100, Math.max(1, Number(q.get('limit') ?? '25') || 25));
  let offset = 0;
  const cursor = q.get('cursor');
  if (cursor) {
    const decoded = readBoundCursor(
      cursor,
      'message_recipients',
      message.detail.id,
      principal.organizationId,
    );
    if (decoded === null) return apiError(400, 'cursor_invalid', 'The cursor is invalid');
    offset = decoded;
  }
  const items = recipientItems(message);
  return ok('MessagesController_recipients_v1', {
    data: items.slice(offset, offset + limit),
    nextCursor:
      offset + limit < items.length
        ? boundCursor(
            offset + limit,
            'message_recipients',
            message.detail.id,
            principal.organizationId,
          )
        : null,
  });
}

function deliveryEvents(message: FixtureMessage, request: FixtureRequest) {
  const rcpt = request.query.get('rcptSeq');
  const events = deliveryEventsOf(message).filter(
    (e) => rcpt === null || String(e.rcptSeq) === rcpt,
  );
  const { page, next } = offsetPage(events, request.query, 100, 25);
  return ok('DeliveriesController_events_v1', { data: page, nextCursor: next });
}

export const fixtures: FixtureHandlers = {
  MessagesController_list_v1: guarded(listMessages),
  MessageRevealController_revealMany_v1: guarded(revealMany),
  SavedViewsController_list_v1: guarded(listViews),
  SavedViewsController_create_v1: guarded(createView),
  SavedViewsController_get_v1: guarded(getView),
  SavedViewsController_update_v1: guarded(updateView),
  SavedViewsController_remove_v1: guarded(removeView),
  MessagesController_detail_v1: withMessage((m, _request, principal) =>
    ok('MessagesController_detail_v1', detailOf(m, principal.organizationId)),
  ),
  MessageLifecycleController_lifecycle_v1: withMessage((m) =>
    ok('MessageLifecycleController_lifecycle_v1', lifecycleOf(m, rescansOf(m))),
  ),
  MessageLifecycleController_history_v1: withMessage((m, request) => {
    const { page, next } = offsetPage(historyOf(m, rescansOf(m)), request.query, 100, 25);
    return ok('MessageLifecycleController_history_v1', { data: page, nextCursor: next });
  }),
  MessageLifecycleController_rescan_v1: withMessage(rescan),
  MessagesController_recipients_v1: withMessage(recipientsOf),
  MessageRevealController_reveal_v1: withMessage(revealOne),
  MessageHeadersController_headers_v1: withMessage(headersOf),
  MessageScansController_scansOf_v1: withMessage(scansOf),
  DlpMessageEvidenceController_read_v1: withMessage(evidence),
  DeliveriesController_forMessage_v1: withMessage((m) =>
    ok('DeliveriesController_forMessage_v1', {
      message: {
        id: m.detail.id,
        direction: m.detail.direction,
        status: currentState(m, rescansOf(m)).status,
        statusReason: m.detail.statusReason,
        receivedAt: m.detail.receivedAt,
      },
      deliveries: deliveriesOf(m),
    }),
  ),
  DeliveriesController_events_v1: withMessage(deliveryEvents),
  AttachmentsController_ofMessage_v1: withMessage((m, request) => {
    const { page, next } = offsetPage(m.attachments, request.query);
    return ok('AttachmentsController_ofMessage_v1', { data: page, nextCursor: next });
  }),
  UrlProtectionController_ofMessage_v1: withMessage((m, request) => {
    const { page, next } = offsetPage(m.urls, request.query);
    return ok('UrlProtectionController_ofMessage_v1', { data: page, nextCursor: next });
  }),
  PolicyMessagesController_evaluations_v1: withMessage((m) =>
    ok('PolicyMessagesController_evaluations_v1', {
      messageId: m.detail.id,
      data: evaluationsOf(m),
    }),
  ),
};
