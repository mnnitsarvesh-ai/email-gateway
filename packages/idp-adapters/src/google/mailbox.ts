/**
 * Google primary stream `forwarding_changes`: the Gmail settings snapshot sweep (design note D3,
 * D8.3). One unit of work per `ingest` call:
 *
 * 0. clear the priority flags of the identities refreshed by the page that wrote this cursor (it
 *    came back, so the runner committed it; deviation WP1-4);
 * 1. priority refresh of identities flagged by the api (processed first);
 * 2. the sweep in progress, or a new sweep when `snapshot.sweepIntervalHours` (Google default
 *    24 h) has passed: Directory `users.list` (`customer=my_customer`, `maxResults=100`, active
 *    users only), then per user (impersonated, R1) `settings/autoForwarding`, `settings/filters`
 *    and `settings/delegates`; ≤ `ATO_IDP_SNAPSHOT_MAX_USERS_PER_POLL` users and
 *    ≤ `ATO_IDP_PAGE_MAX_EVENTS` events per page, the position (users page token, offset) in the
 *    cursor.
 *
 * Events of the companions `mailbox_audit` (filters without forwarding) and `delegation_changes`
 * (delegates) are produced here. Telemetry issues **reads only** (PQ14). Cursor-confirmed state:
 * items written by a page carry its `seq`; a page the runner did not commit is re-emitted with the
 * same event ids on the next poll from the previous cursor.
 */
import { encodeCursor, resolveCursor, type CursorV1, type SweepState } from '../core/cursor';
import { THROTTLE_CODES, toProviderCallError } from '../core/errors';
import { identityHash } from '../core/hash';
import { PageCollector } from '../core/page';
import { inScope, scopeDomains } from '../core/scope';
import { effectiveSweepIntervalHours } from '../core/settings';
import { diffSnapshot, type SnapshotItem } from '../core/snapshot';
import type { ProviderIdentityRef, ProviderIngestPage } from '../port/ato-port';
import {
  DIRECTORY_USERS_PAGE,
  GOOGLE_ADAPTER_VERSION,
  GOOGLE_PROVIDER,
  PRIORITY_REFRESH_BATCH,
} from './constants';
import type { GoogleCalls, GoogleContext } from './context';
import { autoForwardingItem, delegateItem, filterItem } from './mappers/settings';
import { directoryUserSchema, type DirectoryUser } from './schemas';

const STREAM = 'forwarding_changes' as const;
const HOUR_MS = 3_600_000;
const OFFSET = /^u:(\d{1,4})$/;
/** Per-user answers that skip the mailbox instead of failing the page (user gone, no Gmail). */
const SKIPPED_USER_CODES = new Set(['not_found', 'bad_request']);

/** A position in the sweep: the users page (token, absent for the first) and the offset in it. */
interface SweepPosition {
  at: string;
  token?: string;
  offset: number;
}

interface Work {
  ctx: GoogleContext;
  calls: GoogleCalls;
  page: PageCollector;
  cursorSeq: bigint;
  pageSeq: bigint;
  now: Date;
  directoryDomains: string[];
  /** Provider-verified linked domains: users outside them are never impersonated (inv. 4). */
  scope: ReadonlySet<string>;
  /** Position after the last fully processed user (throttling resumes there). */
  progress: SweepPosition | null;
}

function inProgress(cursor: CursorV1): SweepPosition | null {
  const offset = typeof cursor.page === 'string' ? OFFSET.exec(cursor.page) : null;
  if (!cursor.sw?.at || (!cursor.sw.next && !offset)) return null;
  return {
    at: cursor.sw.at,
    ...(cursor.sw.next ? { token: cursor.sw.next } : {}),
    offset: offset ? Number(offset[1]) : 0,
  };
}

function sweepDue(ctx: GoogleContext, sweep: SweepState | undefined, now: Date): boolean {
  if (!sweep?.at) return true;
  const hours = effectiveSweepIntervalHours(GOOGLE_PROVIDER, ctx.deps.integration.settings);
  return now.getTime() - Date.parse(sweep.at) >= hours * HOUR_MS;
}

/** Writes a position (or a finished sweep, `null`) into the next cursor. */
function placeSweep(next: CursorV1, at: string, position: SweepPosition | null): void {
  delete next.page;
  if (position === null) {
    next.sw = { at };
    return;
  }
  next.sw = { at: position.at, ...(position.token ? { next: position.token } : {}) };
  if (position.offset > 0) next.page = `u:${position.offset}`;
}

export async function ingestSettingsSnapshot(
  ctx: GoogleContext,
  raw: string | null,
  signal: AbortSignal,
): Promise<ProviderIngestPage> {
  const deps = ctx.deps;
  const now = deps.clock();
  const { cursor, reset } = resolveCursor(raw, GOOGLE_ADAPTER_VERSION, now);
  if (reset) deps.metrics?.cursorReset?.({ provider: GOOGLE_PROVIDER, stream: STREAM });
  // A cursor carrying `pq` is never handed back as is: its flags are cleared by this call.
  let unchanged = raw !== null && !reset ? raw : encodeCursor(cursor);
  if (cursor.pq) {
    const cleared: CursorV1 = { ...cursor, seq: cursor.seq + 1 };
    delete cleared.pq;
    unchanged = encodeCursor(cleared);
  }
  const page = new PageCollector(GOOGLE_PROVIDER, deps.integration.settings, deps.metrics);
  const next: CursorV1 = { ...cursor, seq: cursor.seq + 1 };
  delete next.pq;
  let work: Work | null = null;
  try {
    const calls = await ctx.open(signal);
    work = {
      ctx,
      calls,
      page,
      cursorSeq: BigInt(cursor.seq),
      pageSeq: BigInt(cursor.seq + 1),
      now,
      directoryDomains: ctx.directoryDomains(calls.session),
      scope: scopeDomains(deps.integration.directoryDomains, calls.session),
      progress: null,
    };

    // 0. The page that refreshed these identities was committed: clear their flags now.
    if (cursor.pq && cursor.pq.length > 0) {
      await deps.mailboxState.clearPriority(deps.integration.id, [...cursor.pq]);
    }

    // 1. Priority refresh (api route): processed first.
    const priority = await deps.mailboxState.priorityIdentities(
      deps.integration.id,
      PRIORITY_REFRESH_BATCH,
    );
    if (priority.length > 0) {
      for (const identity of priority) await refreshPriority(work, identity);
      next.pq = priority.map((identity) => identityHash(GOOGLE_PROVIDER, identity.externalId));
      return { events: page.events, cursor: encodeCursor(next), hasMore: true };
    }

    // 2. Sweep in progress or due.
    let start = inProgress(cursor);
    if (start === null) {
      if (!sweepDue(ctx, cursor.sw, now)) return { events: [], cursor: unchanged, hasMore: false };
      start = { at: now.toISOString(), offset: 0 };
    }
    const stopped = await sweep(work, start);
    placeSweep(next, start.at, stopped);
    return { events: page.events, cursor: encodeCursor(next), hasMore: stopped !== null };
  } catch (error) {
    const failure = toProviderCallError(error);
    if (THROTTLE_CODES.has(failure.code)) {
      // Items written so far carry this page's seq and their events are returned with it; the
      // sweep resumes after the last fully processed user (or where it started).
      if (work?.progress) placeSweep(next, work.progress.at, work.progress);
      return {
        events: page.events,
        cursor: encodeCursor(next),
        hasMore: true,
        retryAfterMs: Math.max(1, failure.retryAfterMs ?? 1_000),
      };
    }
    throw failure;
  } finally {
    page.flush();
  }
}

/**
 * Sweeps from `start` until the users are exhausted (`null`) or the per-poll user or event budget
 * is reached (the position to resume from).
 */
async function sweep(work: Work, start: SweepPosition): Promise<SweepPosition | null> {
  const deps = work.ctx.deps;
  const maxUsers = deps.config.snapshotMaxUsersPerPoll;
  const maxEvents = deps.config.pageMaxEvents;
  const directory = work.calls.directory();
  let position = start;
  let processed = 0;
  for (;;) {
    const listing = await directory.listUsers(DIRECTORY_USERS_PAGE, position.token);
    const users = listing.users ?? [];
    for (let i = position.offset; i < users.length; i += 1) {
      if (processed >= maxUsers || work.page.size >= maxEvents) return { ...position, offset: i };
      const parsed = directoryUserSchema.safeParse(users[i]);
      if (parsed.success && parsed.data.suspended !== true && parsed.data.archived !== true) {
        if (await snapshotUser(work, parsed.data)) processed += 1;
      }
      work.progress = { ...position, offset: i + 1 };
    }
    if (!listing.nextPageToken) return null;
    position = { at: position.at, token: listing.nextPageToken, offset: 0 };
    work.progress = position;
    if (processed >= maxUsers || work.page.size >= maxEvents) return position;
  }
}

/** Priority refresh of one identity: a fresh directory read, then its mailbox snapshot. */
async function refreshPriority(work: Work, identity: ProviderIdentityRef): Promise<void> {
  const user = await work.calls.directory().getUser(identity.externalId);
  if (!user || user.suspended === true || user.archived === true) return;
  await snapshotUser(work, user);
}

/**
 * Reads one mailbox's settings (impersonating its owner) and diffs them (D8.3). A user outside the
 * provider-verified linked domains is skipped before any impersonation or state write
 * (`foreign_domain`, inv. 4); returns whether the mailbox was read.
 */
async function snapshotUser(work: Work, user: DirectoryUser): Promise<boolean> {
  const deps = work.ctx.deps;
  const identity = work.ctx.identityFromUser(user);
  const mailbox = identity.primaryEmail;
  if (!mailbox) {
    work.page.drop(STREAM, 'invalid');
    return false;
  }
  if (!inScope(identity, work.scope)) {
    work.page.drop(STREAM, 'foreign_domain');
    return false;
  }
  const gmail = work.calls.gmail();
  let forwarding;
  let filters: unknown[];
  let delegates;
  try {
    forwarding = await gmail.getAutoForwarding(mailbox);
    filters = await gmail.listFilters(mailbox);
    delegates = await gmail.listDelegates(mailbox);
  } catch (error) {
    const failure = toProviderCallError(error);
    if (SKIPPED_USER_CODES.has(failure.code)) return true; // deleted meanwhile, or Gmail not enabled
    throw failure;
  }
  const context = { directoryDomains: work.directoryDomains };
  const current: SnapshotItem[] = [];
  const forwardingItem = autoForwardingItem(user.id, forwarding, context);
  if (forwardingItem) current.push(forwardingItem);
  for (const raw of filters) {
    const item = filterItem(user.id, raw, context);
    if (item) current.push(item);
    else work.page.drop('mailbox_audit', 'invalid');
  }
  for (const delegate of delegates) {
    const item = delegateItem(user.id, delegate);
    if (item) current.push(item);
  }
  const known = await deps.mailboxState.load(
    deps.integration.id,
    identityHash(GOOGLE_PROVIDER, user.id),
  );
  const diff = diffSnapshot({
    provider: GOOGLE_PROVIDER,
    identity,
    current,
    known,
    coveredKinds: ['forwarding', 'inbox_rule', 'delegate'],
    cursorSeq: work.cursorSeq,
    pageSeq: work.pageSeq,
    now: work.now,
  });
  if (diff.writes.length > 0) {
    await deps.mailboxState.write(deps.integration.id, identity, diff.writes, work.pageSeq);
    for (const write of diff.writes) {
      if (write.change) {
        deps.metrics?.snapshotItems?.(
          { provider: GOOGLE_PROVIDER, kind: write.kind, change: write.change },
          1,
        );
      }
    }
  }
  for (const event of diff.events) work.page.add(event);
  return true;
}
