/**
 * Microsoft primary stream `mailbox_audit` (design note D7.4, D8.3, §3.2). One unit of work per
 * `ingest` call:
 *
 * 1. priority refresh of identities flagged by the api (Graph inbox rules, snapshot diff);
 * 2. the Office 365 Management `Audit.Exchange` window in progress (listing page, blob, offset in
 *    the cursor; blobs are immutable and re-fetched for the next slice);
 * 3. the weekly inbox-rule sweep over Graph users (alternating with audit windows);
 * 4. a new audit window.
 *
 * Events of the companions `forwarding_changes` and `delegation_changes` are produced here.
 */
import {
  encodeCursor,
  resolveCursor,
  type CursorV1,
  type O365Page,
  type SweepState,
} from '../core/cursor';
import { THROTTLE_CODES, toProviderCallError } from '../core/errors';
import { identityHash, mailboxItemHash, domainOf } from '../core/hash';
import { eventIdPart } from '../core/normalize';
import { PageCollector } from '../core/page';
import { inScope, scopeDomains } from '../core/scope';
import { effectiveSweepIntervalHours } from '../core/settings';
import { diffSnapshot, streamOfMailboxChange, type SnapshotItem } from '../core/snapshot';
import { classifyRule, forwardingTraits } from '../core/traits';
import { hasMoreWindows, nextWindow } from '../core/windows';
import type { ProviderEvent, ProviderIdentityRef, ProviderIngestPage } from '../port/ato-port';
import type { MailboxItemKind, MailboxItemRow, MailboxItemWrite } from '../port/state-ports';
import { PROVIDER_RETENTION_DAYS } from '../requirements';
import {
  GRAPH_USERS_PAGE,
  MAX_BLOBS_PER_PAGE,
  MICROSOFT_ADAPTER_VERSION,
  MICROSOFT_PROVIDER,
  PRIORITY_REFRESH_BATCH,
} from './constants';
import type { MicrosoftCalls, MicrosoftContext } from './context';
import { GRAPH_USER_SELECT } from './graph-client';
import { mapExchangeRecord, type ExchangeObservation } from './mappers/exchange';
import { graphRuleDefinition, parseGraphRule } from './mappers/rules';
import { graphUserSchema } from './schemas';

const STREAM = 'mailbox_audit' as const;
const HOUR_MS = 3_600_000;

interface Work {
  ctx: MicrosoftContext;
  calls: MicrosoftCalls;
  page: PageCollector;
  /** Seq of the cursor ingest was called with (S) and of this page (S + 1). */
  cursorSeq: bigint;
  pageSeq: bigint;
  now: Date;
  directoryDomains: string[];
  /** Provider-verified linked domains: users outside them are never read or stored (inv. 4). */
  scope: ReadonlySet<string>;
  rulesReadable: boolean;
}

/** Whether a sweep is in progress or due. */
function sweepDue(ctx: MicrosoftContext, sweep: SweepState | undefined, now: Date): boolean {
  if (sweep?.next) return true;
  if (!sweep?.at) return true;
  const hours = effectiveSweepIntervalHours(MICROSOFT_PROVIDER, ctx.deps.integration.settings);
  return now.getTime() - Date.parse(sweep.at) >= hours * HOUR_MS;
}

export async function ingestMailboxAudit(
  ctx: MicrosoftContext,
  raw: string | null,
  signal: AbortSignal,
): Promise<ProviderIngestPage> {
  const deps = ctx.deps;
  const now = deps.clock();
  const { cursor, reset } = resolveCursor(raw, MICROSOFT_ADAPTER_VERSION, now);
  if (reset) deps.metrics?.cursorReset?.({ provider: MICROSOFT_PROVIDER, stream: STREAM });
  // The cursor returned when nothing new was processed. A cursor carrying `pq` is never handed
  // back as is: its flags are cleared by this call, so the next cursor must not clear them again.
  let unchanged = raw !== null && !reset ? raw : encodeCursor(cursor);
  if (cursor.pq) {
    const cleared: CursorV1 = { ...cursor, seq: cursor.seq + 1 };
    delete cleared.pq;
    unchanged = encodeCursor(cleared);
  }
  const page = new PageCollector(MICROSOFT_PROVIDER, deps.integration.settings, deps.metrics);
  let progress: CursorV1 | null = null;
  try {
    const calls = await ctx.open(signal);
    const work: Work = {
      ctx,
      calls,
      page,
      cursorSeq: BigInt(cursor.seq),
      pageSeq: BigInt(cursor.seq + 1),
      now,
      directoryDomains: ctx.directoryDomains(calls.session),
      scope: scopeDomains(deps.integration.directoryDomains, calls.session),
      rulesReadable: calls.session.hasObservedPermission(
        'm365.ato_telemetry',
        'MailboxSettings.Read',
      ),
    };
    const next: CursorV1 = { ...cursor, seq: cursor.seq + 1 };
    delete next.pq;

    // 0. The page that refreshed these identities was committed (this cursor came back): their
    //    priority flags can be cleared now. A crash before the commit keeps the flags, so the
    //    refresh runs again and re-emits the same events (cursor-confirmed state, D8.3).
    if (cursor.pq && cursor.pq.length > 0) {
      await deps.mailboxState.clearPriority(deps.integration.id, [...cursor.pq]);
    }

    // 1. Priority refresh (api route): processed first.
    if (work.rulesReadable) {
      const priority = await deps.mailboxState.priorityIdentities(
        deps.integration.id,
        PRIORITY_REFRESH_BATCH,
      );
      if (priority.length > 0) {
        for (const identity of priority) await refreshPriority(work, identity);
        next.pq = priority.map((identity) => identityHash(MICROSOFT_PROVIDER, identity.externalId));
        return { events: page.events, cursor: encodeCursor(next), hasMore: true };
      }
    }

    // 2. Audit window in progress.
    if (cursor.ws && cursor.we) {
      const result = await auditPage(work, next, (p) => (progress = p));
      return { events: page.events, cursor: encodeCursor(result.cursor), hasMore: result.hasMore };
    }

    // 3. Sweep (alternating with audit windows so neither starves).
    const due = sweepDue(ctx, cursor.sw, now);
    if (due && !(cursor.sw?.alt === true)) {
      const sweep = await sweepPage(work, cursor.sw);
      next.sw = { ...sweep, alt: true };
      return { events: page.events, cursor: encodeCursor(next), hasMore: true };
    }

    // 4. New audit window.
    const window = nextWindow({
      family: 'o365_management',
      watermark: cursor.wm ? new Date(cursor.wm) : null,
      now,
      retentionDays: PROVIDER_RETENTION_DAYS.microsoft_entra.mailbox_audit,
    });
    if (window === null) {
      if (due) {
        const sweep = await sweepPage(work, cursor.sw);
        next.sw = { ...sweep, alt: true };
        return { events: page.events, cursor: encodeCursor(next), hasMore: true };
      }
      return { events: [], cursor: unchanged, hasMore: false };
    }
    next.ws = window.start.toISOString();
    next.we = window.end.toISOString();
    delete next.page;
    if (next.sw) next.sw = { ...next.sw, alt: false };
    const result = await auditPage(work, next, (p) => (progress = p));
    return { events: page.events, cursor: encodeCursor(result.cursor), hasMore: result.hasMore };
  } catch (error) {
    const failure = toProviderCallError(error);
    if (THROTTLE_CODES.has(failure.code)) {
      // Events of fully processed records are returned with the cursor at that position.
      const resume = progress as CursorV1 | null;
      return resume
        ? {
            events: page.events,
            cursor: encodeCursor(resume),
            hasMore: true,
            retryAfterMs: failure.retryAfterMs ?? 1_000,
          }
        : {
            events: [],
            cursor: unchanged,
            hasMore: true,
            retryAfterMs: failure.retryAfterMs ?? 1_000,
          };
    }
    throw failure;
  } finally {
    page.flush();
  }
}

/**
 * One page of the audit window in `next.ws`/`next.we`. `onProgress` receives the cursor after
 * every fully processed record, so a throttle mid-page resumes exactly there.
 */
async function auditPage(
  work: Work,
  next: CursorV1,
  onProgress: (cursor: CursorV1) => void,
): Promise<{ cursor: CursorV1; hasMore: boolean }> {
  const deps = work.ctx.deps;
  const o365 = work.calls.o365();
  const window = { start: new Date(next.ws as string), end: new Date(next.we as string) };
  const position: O365Page = typeof next.page === 'object' ? { ...next.page } : {};
  const listPath = position.next ?? o365.listPath(window);
  const listing = await o365.list(listPath);
  let index = 0;
  let offset = 0;
  if (position.blob) {
    const found = listing.items.findIndex((item) => item.contentId === position.blob?.id);
    if (found >= 0) {
      index = found;
      offset = position.blob.offset;
    }
  }
  const pageMax = deps.config.pageMaxEvents;
  const snapshotOf = (blobIndex: number, recordOffset: number): CursorV1 => {
    const cursor: CursorV1 = { ...next };
    const blob = listing.items[blobIndex];
    const pagePart: O365Page = {};
    if (position.next) pagePart.next = position.next;
    if (blob) pagePart.blob = { id: blob.contentId, offset: recordOffset };
    cursor.page = pagePart;
    return cursor;
  };
  const ownerRulesFetched = new Set<string>();
  let blobs = 0;
  while (index < listing.items.length && work.page.size < pageMax && blobs < MAX_BLOBS_PER_PAGE) {
    const item = listing.items[index];
    if (!item) break;
    const records = await o365.blob(item.contentUri);
    blobs += 1;
    let i = offset;
    for (; i < records.length && work.page.size < pageMax; i += 1) {
      await processRecord(work, records[i], ownerRulesFetched);
      onProgress(snapshotOf(index, i + 1));
    }
    if (i < records.length) {
      return { cursor: snapshotOf(index, i), hasMore: true };
    }
    index += 1;
    offset = 0;
    onProgress(snapshotOf(index, 0));
  }
  if (index < listing.items.length) {
    return { cursor: snapshotOf(index, offset), hasMore: true };
  }
  if (listing.nextPath) {
    const cursor: CursorV1 = { ...next, page: { next: listing.nextPath } };
    return { cursor, hasMore: true };
  }
  // Window complete.
  const done: CursorV1 = { v: 1, a: next.a, seq: next.seq, wm: window.end.toISOString() };
  if (next.sw) done.sw = next.sw;
  const more =
    hasMoreWindows({ family: 'o365_management', watermark: window.end, now: work.now }) ||
    sweepDue(work.ctx, next.sw, work.now);
  return { cursor: done, hasMore: more };
}

async function processRecord(
  work: Work,
  raw: unknown,
  ownerRulesFetched: Set<string>,
): Promise<void> {
  const observation = mapExchangeRecord(raw);
  if (observation.type === 'dropped') {
    work.page.drop(STREAM, 'dropped_operation');
    return;
  }
  if (observation.type === 'invalid') {
    work.page.drop(STREAM, 'invalid');
    return;
  }
  const owner = await work.ctx.owner(work.calls, observation.ownerKey);
  if (!owner) {
    work.page.drop(STREAM, 'invalid');
    return;
  }
  // Mailboxes outside the provider-verified linked domains (or guests) are neither read nor
  // stored (inv. 4).
  if (!inScope(owner, work.scope)) {
    work.page.drop(STREAM, 'foreign_domain');
    return;
  }
  await handleObservation(work, observation, owner, ownerRulesFetched);
}

function auditEvent(
  observation: Exclude<ExchangeObservation, { type: 'dropped' } | { type: 'invalid' }>,
  owner: ProviderIdentityRef,
  stream: ProviderEvent['stream'],
  mailbox: NonNullable<ProviderEvent['mailbox']>,
): ProviderEvent {
  return {
    provider: MICROSOFT_PROVIDER,
    eventId: `o365:${eventIdPart(observation.recordId)}`.slice(0, 128),
    stream,
    occurredAt: observation.occurredAt,
    identity: owner,
    ...(observation.ip ? { ip: observation.ip } : {}),
    mailbox,
  };
}

async function handleObservation(
  work: Work,
  observation: Exclude<ExchangeObservation, { type: 'dropped' } | { type: 'invalid' }>,
  owner: ProviderIdentityRef,
  ownerRulesFetched: Set<string>,
): Promise<void> {
  const context = { directoryDomains: work.directoryDomains };
  switch (observation.type) {
    case 'access':
      work.page.add(
        auditEvent(observation, owner, 'mailbox_audit', {
          change: 'access',
          clientType: observation.clientType,
        }),
      );
      return;
    case 'inbox_rule': {
      if (work.rulesReadable) {
        if (ownerRulesFetched.has(owner.externalId)) return;
        try {
          await refreshRules(work, owner);
          ownerRulesFetched.add(owner.externalId);
          return;
        } catch (error) {
          const failure = toProviderCallError(error);
          // Rules unreadable now (permission removed, mailbox gone): fall back to the audit record.
          if (
            !['missing_permission', 'forbidden', 'not_found', 'missing_license'].includes(
              failure.code,
            )
          )
            throw failure;
        }
      }
      const { traits, targetDomain } = classifyRule(observation.definition, context);
      const canonical = `audit_rule|${observation.ruleName ?? observation.recordId}`;
      const itemHash = mailboxItemHash(
        MICROSOFT_PROVIDER,
        owner.externalId,
        'inbox_rule',
        canonical,
      );
      await writeAuditItem(work, owner, {
        kind: 'inbox_rule',
        itemHash,
        targetDomain,
        traits,
        state: 'present',
        change: observation.change,
      });
      work.page.add(
        auditEvent(observation, owner, streamOfMailboxChange('inbox_rule', traits), {
          change: observation.change === 'added' ? 'inbox_rule_added' : 'inbox_rule_changed',
          ...(targetDomain ? { targetDomain } : {}),
          ruleHash: itemHash,
          ruleTraits: traits,
        }),
      );
      return;
    }
    case 'forwarding': {
      const itemHash = mailboxItemHash(
        MICROSOFT_PROVIDER,
        owner.externalId,
        'forwarding',
        'mailbox_forwarding',
      );
      if (observation.target === null) {
        await writeAuditItem(work, owner, {
          kind: 'forwarding',
          itemHash,
          targetDomain: null,
          traits: [],
          state: 'removed',
          change: 'removed',
        });
        work.page.add(
          auditEvent(observation, owner, 'forwarding_changes', { change: 'forwarding_removed' }),
        );
        return;
      }
      const { traits, targetDomain } = forwardingTraits(observation.target, context);
      await writeAuditItem(work, owner, {
        kind: 'forwarding',
        itemHash,
        targetDomain,
        traits,
        state: 'present',
        change: 'added',
      });
      work.page.add(
        auditEvent(observation, owner, 'forwarding_changes', {
          change: 'forwarding_added',
          ...(targetDomain ? { targetDomain } : {}),
        }),
      );
      return;
    }
    case 'permission': {
      const grantee = observation.grantee.toLowerCase();
      const itemHash = mailboxItemHash(
        MICROSOFT_PROVIDER,
        owner.externalId,
        observation.kind,
        `${observation.kind}|${grantee}`,
      );
      const targetDomain = domainOf(grantee);
      await writeAuditItem(work, owner, {
        kind: observation.kind,
        itemHash,
        targetDomain,
        traits: [],
        state: 'present',
        change: 'added',
      });
      work.page.add(
        auditEvent(observation, owner, 'delegation_changes', {
          change: observation.kind === 'delegate' ? 'delegate_added' : 'permission_added',
          ...(targetDomain ? { targetDomain } : {}),
        }),
      );
      return;
    }
  }
}

/** Upserts one audit-derived mailbox item (events of audit records carry their own ids). */
async function writeAuditItem(
  work: Work,
  owner: ProviderIdentityRef,
  item: {
    kind: MailboxItemKind;
    itemHash: string;
    targetDomain: string | null;
    traits: readonly string[];
    state: 'present' | 'removed';
    change: 'added' | 'changed' | 'removed';
  },
): Promise<void> {
  const deps = work.ctx.deps;
  const known = await deps.mailboxState.load(
    deps.integration.id,
    identityHash(MICROSOFT_PROVIDER, owner.externalId),
  );
  const row: MailboxItemRow | undefined = known.find(
    (r) => r.kind === item.kind && r.itemHash === item.itemHash,
  );
  if (item.state === 'removed' && (!row || row.state === 'removed')) return;
  const nowIso = work.now.toISOString();
  const change =
    row && row.state === 'present' && item.state === 'present' ? 'changed' : item.change;
  const write: MailboxItemWrite = {
    kind: item.kind,
    itemHash: item.itemHash,
    providerItemRef: row?.providerItemRef ?? null,
    targetDomain: item.targetDomain,
    traits: item.traits,
    enabled: item.state === 'present' ? true : (row?.enabled ?? null),
    state: item.state,
    source: 'audit',
    firstSeenAt: row && row.state === 'present' ? row.firstSeenAt : nowIso,
    lastSeenAt: nowIso,
    removedAt: item.state === 'removed' ? nowIso : null,
    change,
  };
  await deps.mailboxState.write(deps.integration.id, owner, [write], work.pageSeq);
  deps.metrics?.snapshotItems?.({ provider: MICROSOFT_PROVIDER, kind: item.kind, change }, 1);
}

/**
 * Reads a user's inbox rules through Graph and diffs them against the stored items (D8.3). A user
 * outside the provider-verified linked domains is skipped before the read (`foreign_domain`).
 */
async function refreshRules(work: Work, identity: ProviderIdentityRef): Promise<void> {
  const deps = work.ctx.deps;
  if (!inScope(identity, work.scope)) {
    work.page.drop(STREAM, 'foreign_domain');
    return;
  }
  const rawRules = await work.calls.graph.listRules(identity.externalId);
  const current: SnapshotItem[] = [];
  for (const raw of rawRules) {
    const rule = parseGraphRule(raw);
    if (!rule) {
      work.page.drop(STREAM, 'invalid');
      continue;
    }
    const { traits, targetDomain } = classifyRule(graphRuleDefinition(rule), {
      directoryDomains: work.directoryDomains,
    });
    current.push({
      kind: 'inbox_rule',
      itemHash: mailboxItemHash(MICROSOFT_PROVIDER, identity.externalId, 'inbox_rule', rule.id),
      providerItemRef: rule.id.slice(0, 255),
      targetDomain,
      traits,
      enabled: rule.isEnabled !== false,
      source: 'snapshot',
    });
  }
  const hash = identityHash(MICROSOFT_PROVIDER, identity.externalId);
  const known = await deps.mailboxState.load(deps.integration.id, hash);
  const diff = diffSnapshot({
    provider: MICROSOFT_PROVIDER,
    identity,
    current,
    known,
    coveredKinds: ['inbox_rule'],
    cursorSeq: work.cursorSeq,
    pageSeq: work.pageSeq,
    now: work.now,
  });
  if (diff.writes.length > 0) {
    await deps.mailboxState.write(deps.integration.id, identity, diff.writes, work.pageSeq);
    for (const write of diff.writes) {
      if (write.change)
        deps.metrics?.snapshotItems?.(
          { provider: MICROSOFT_PROVIDER, kind: write.kind, change: write.change },
          1,
        );
    }
  }
  for (const event of diff.events) work.page.add(event);
}

/**
 * Priority refresh of one identity: the owner is resolved through Graph (cached) so the scope check
 * sees its current UPN and address, then its rules are read. An unknown user is skipped.
 */
async function refreshPriority(work: Work, identity: ProviderIdentityRef): Promise<void> {
  const owner = await work.ctx.owner(work.calls, identity.externalId);
  if (!owner) return;
  await refreshRules(work, owner);
}

/** One sweep page: a Graph users page, inbox rules of each enabled user (D8.3). */
async function sweepPage(work: Work, sweep: SweepState | undefined): Promise<SweepState> {
  const state: SweepState = sweep?.next ? { ...sweep } : { at: work.now.toISOString() };
  if (!work.rulesReadable) return { at: state.at ?? work.now.toISOString() };
  const params = new URLSearchParams({
    $select: GRAPH_USER_SELECT,
    $top: String(Math.min(GRAPH_USERS_PAGE, work.ctx.deps.config.snapshotMaxUsersPerPoll)),
  });
  if (state.next) params.set('$skiptoken', state.next);
  const result = await work.calls.graph.page(`/v1.0/users?${params.toString()}`, '/v1.0/users');
  for (const raw of result.value) {
    const user = graphUserSchema.safeParse(raw);
    if (!user.success || user.data.accountEnabled === false) continue;
    try {
      await refreshRules(work, work.ctx.identityFromUser(user.data));
    } catch (error) {
      const failure = toProviderCallError(error);
      // A mailbox-less user (404) or one without access is skipped; anything else stops the page.
      if (failure.code !== 'not_found' && failure.code !== 'forbidden') throw failure;
    }
  }
  const nextLink = result['@odata.nextLink'];
  if (nextLink) return { at: state.at, next: work.calls.graph.skipToken(nextLink) };
  return { at: state.at ?? work.now.toISOString() };
}
