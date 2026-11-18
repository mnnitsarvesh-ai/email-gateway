import { journalEligibility, type MessageDirection } from '@email-gateway/archive';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import type { ArchiveMetrics } from '../metrics/archive-metrics';
import { big, orgAllowed, readCursor, writeCursor } from '../shared/db';
import { type IntentUpsert, upsertIntents } from './intents';
import type { OrgContextCache } from './org-context';

export const JOURNAL_SWEEP_LOCK = 'eg:archive-journal-sweep';
export const JOURNAL_SWEEP_CURSOR = 'archive:journal-sweep';
export const POLICY_RECONCILE_LOCK = 'eg:archive-policy-reconcile';
export const POLICY_RECONCILE_CURSOR = 'archive:policy-reconcile';

const DAY_MS = 86_400_000;
/** First-run position `oldest`: before every row. */
const EPOCH = new Date(0);

export interface SweepReport {
  scanned: number;
  intents: number;
  /** True when the batch was full and the next pass should run at once. */
  more: boolean;
  /** The pass stopped at a row newer than the safety lag. */
  stoppedAtLag: boolean;
}

interface SweepOptions {
  metrics: ArchiveMetrics;
  logger: Logger;
  batchSize: number;
  safetyLagSeconds: number;
  start: 'now' | 'oldest';
  cursorName?: string;
  organizationIds?: readonly bigint[];
  now?: () => Date;
}

/** Initial cursor of a sweep (A2 start positions; `now` = no historical backfill, §8). */
async function initialCursor(
  prisma: PrismaClient,
  table: 'email_messages' | 'policy_execution_logs',
  start: 'now' | 'oldest',
  now: Date,
): Promise<{ positionId: bigint; lastEventAt: Date }> {
  if (start === 'oldest') return { positionId: 0n, lastEventAt: EPOCH };
  const since = new Date(now.getTime() - DAY_MS);
  const rows =
    table === 'email_messages'
      ? await prisma.$queryRaw<Array<{ id: bigint | number | null }>>`
          SELECT MAX(id) AS id FROM email_messages WHERE received_at >= ${since}`
      : await prisma.$queryRaw<Array<{ id: bigint | number | null }>>`
          SELECT MAX(id) AS id FROM policy_execution_logs WHERE received_at >= ${since}`;
  const id = rows[0]?.id;
  return { positionId: id === null || id === undefined ? 0n : big(id), lastEventAt: now };
}

/**
 * Source 1, the journal completeness sweep (A2, leader `GET_LOCK('eg:archive-journal-sweep')`):
 * a forward cursor over `email_messages.id` (`stream_cursors` row `archive:journal-sweep`):
 * `id > cursor AND received_at >= cursorReceivedAt - 1 day ORDER BY id LIMIT batch`. The pass
 * **stops at the first row newer than the safety lag** (`created_at > now - lag`), so a message
 * whose registry id was allocated earlier but committed later is never passed over. Every message
 * row is visited exactly once; organizations that are entitled, enabled and journaling since
 * `journal_enabled_at` get an intent for each eligible message (A4).
 */
export class JournalSweep {
  private readonly cursorName: string;
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly orgs: OrgContextCache,
    private readonly options: SweepOptions,
  ) {
    this.cursorName = options.cursorName ?? JOURNAL_SWEEP_CURSOR;
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<SweepReport> {
    const now = this.now();
    const cutoff = new Date(now.getTime() - this.options.safetyLagSeconds * 1000);
    let cursor = await readCursor(this.prisma, this.cursorName);
    if (cursor === null || cursor.positionId === null) {
      const init = await initialCursor(this.prisma, 'email_messages', this.options.start, now);
      await writeCursor(this.prisma, this.cursorName, init.positionId, init.lastEventAt);
      cursor = init;
    }
    const position = cursor.positionId ?? 0n;
    const since = new Date((cursor.lastEventAt ?? EPOCH).getTime() - DAY_MS);
    const rows = await this.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        received_at: Date;
        organization_id: bigint | number;
        direction: MessageDirection;
        envelope_from: string;
        header_from: string | null;
        created_at: Date;
      }>
    >`
      SELECT id, received_at, organization_id, direction, envelope_from, header_from, created_at
      FROM email_messages
      WHERE id > ${position} AND received_at >= ${since}
      ORDER BY id LIMIT ${this.options.batchSize}`;
    const visible: typeof rows = [];
    let stoppedAtLag = false;
    for (const row of rows) {
      if (row.created_at.getTime() > cutoff.getTime()) {
        stoppedAtLag = true;
        break;
      }
      visible.push(row);
    }
    const intents: IntentUpsert[] = [];
    const candidates = [];
    for (const row of visible) {
      const org = big(row.organization_id);
      if (!orgAllowed(org, this.options.organizationIds)) continue;
      const ctx = await this.orgs.get(org);
      if (!ctx.entitled || !ctx.enabled || ctx.journalEnabledAt === null) continue;
      if (row.received_at.getTime() < ctx.journalEnabledAt.getTime()) continue;
      candidates.push({ row, ctx });
    }
    const recipients = await this.recipients(candidates.map((c) => c.row));
    for (const { row, ctx } of candidates) {
      const id = big(row.id);
      const eligible = journalEligibility({
        settings: ctx.settings,
        journalEnabledAt: ctx.journalEnabledAt,
        message: {
          receivedAt: row.received_at,
          direction: row.direction,
          envelopeFrom: row.envelope_from,
          headerFrom: row.header_from,
          recipients: recipients.get(id.toString()) ?? [],
        },
        matcher: ctx.matcher,
      });
      if (!eligible.eligible) continue;
      intents.push({
        organizationId: ctx.organizationId,
        messageId: id,
        receivedAt: row.received_at,
        direction: row.direction,
        journal: true,
        policy: false,
        policyRuleRef: null,
        settingsGeneration: ctx.generation,
        nextCheckAt: now,
      });
    }
    const last = visible[visible.length - 1];
    await this.prisma.$transaction(async (tx) => {
      await upsertIntents(tx, intents);
      if (last !== undefined) {
        await writeCursor(tx, this.cursorName, big(last.id), last.received_at);
      }
    });
    if (last !== undefined) {
      this.options.metrics.sweepLag.set(
        { sweep: 'journal' },
        Math.max(0, (now.getTime() - last.created_at.getTime()) / 1000),
      );
    } else {
      // Nothing new to pass: the sweep is as current as its safety lag allows.
      this.options.metrics.sweepLag.set({ sweep: 'journal' }, this.options.safetyLagSeconds);
    }
    return {
      scanned: visible.length,
      intents: intents.length,
      more: !stoppedAtLag && rows.length === this.options.batchSize,
      stoppedAtLag,
    };
  }

  /** Recipient addresses and directions of the candidate messages (one query per batch). */
  private async recipients(
    rows: ReadonlyArray<{ id: bigint | number; received_at: Date; direction: MessageDirection }>,
  ): Promise<Map<string, Array<{ address: string; direction: MessageDirection }>>> {
    const out = new Map<string, Array<{ address: string; direction: MessageDirection }>>();
    if (rows.length === 0) return out;
    const ids = rows.map((r) => big(r.id));
    const times = rows.map((r) => r.received_at.getTime());
    const found = await this.prisma.emailRecipient.findMany({
      where: {
        messageId: { in: ids },
        receivedAt: { gte: new Date(Math.min(...times)), lte: new Date(Math.max(...times)) },
      },
      select: { messageId: true, receivedAt: true, address: true, direction: true },
    });
    const byId = new Map(rows.map((r) => [big(r.id).toString(), r]));
    for (const r of found) {
      const msg = byId.get(r.messageId.toString());
      if (msg === undefined || msg.received_at.getTime() !== r.receivedAt.getTime()) continue;
      const list = out.get(r.messageId.toString()) ?? [];
      list.push({ address: r.address, direction: r.direction ?? msg.direction });
      out.set(r.messageId.toString(), list);
    }
    return out;
  }
}

/** The ARCHIVE action of a stored evaluation (`policy_execution_logs.actions`), when requested. */
export function archiveRequest(actions: unknown): { requested: boolean; ruleRef: string | null } {
  if (!Array.isArray(actions)) return { requested: false, ruleRef: null };
  for (const a of actions as Array<{ type?: unknown; status?: unknown; ruleRefs?: unknown }>) {
    if (a?.type === 'ARCHIVE' && a.status === 'requested') {
      const refs = Array.isArray(a.ruleRefs) ? a.ruleRefs : [];
      const first = refs.find((r): r is string => typeof r === 'string' && r.length > 0);
      return { requested: true, ruleRef: first ?? null };
    }
  }
  return { requested: false, ruleRef: null };
}

/**
 * Source 3, the policy reconciler (A2, leader `GET_LOCK('eg:archive-policy-reconcile')`): a
 * forward cursor over `policy_execution_logs.id` (`stream_cursors` row
 * `archive:policy-reconcile`), the same window and lag rule as the journal sweep
 * (`ARCHIVE_POLICY_RECONCILE_SAFETY_LAG_SECONDS` ≥ the policy transaction budget). Rows whose
 * `actions` hold `{ type: 'ARCHIVE', status: 'requested' }` get the policy upsert. Start `oldest`
 * recovers every request the lossy queue dropped (within the table's 6-month retention).
 */
export class PolicyReconciler {
  private readonly cursorName: string;
  private readonly now: () => Date;

  constructor(
    private readonly prisma: PrismaClient,
    private readonly orgs: OrgContextCache,
    private readonly options: SweepOptions,
  ) {
    this.cursorName = options.cursorName ?? POLICY_RECONCILE_CURSOR;
    this.now = options.now ?? (() => new Date());
  }

  async runOnce(): Promise<SweepReport> {
    const now = this.now();
    const cutoff = new Date(now.getTime() - this.options.safetyLagSeconds * 1000);
    let cursor = await readCursor(this.prisma, this.cursorName);
    if (cursor === null || cursor.positionId === null) {
      const init = await initialCursor(
        this.prisma,
        'policy_execution_logs',
        this.options.start,
        now,
      );
      await writeCursor(this.prisma, this.cursorName, init.positionId, init.lastEventAt);
      cursor = init;
    }
    const position = cursor.positionId ?? 0n;
    const since = new Date((cursor.lastEventAt ?? EPOCH).getTime() - DAY_MS);
    const rows = await this.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        received_at: Date;
        organization_id: bigint | number;
        message_id: bigint | number;
        direction: MessageDirection;
        actions: unknown;
        created_at: Date;
      }>
    >`
      SELECT id, received_at, organization_id, message_id, direction, actions, created_at
      FROM policy_execution_logs
      WHERE id > ${position} AND received_at >= ${since}
      ORDER BY id LIMIT ${this.options.batchSize}`;
    const visible: typeof rows = [];
    let stoppedAtLag = false;
    for (const row of rows) {
      if (row.created_at.getTime() > cutoff.getTime()) {
        stoppedAtLag = true;
        break;
      }
      visible.push(row);
    }
    const intents: IntentUpsert[] = [];
    for (const row of visible) {
      const org = big(row.organization_id);
      if (!orgAllowed(org, this.options.organizationIds)) continue;
      const actions = typeof row.actions === 'string' ? safeJson(row.actions) : row.actions;
      const request = archiveRequest(actions);
      if (!request.requested) continue;
      const ctx = await this.orgs.get(org);
      intents.push({
        organizationId: org,
        messageId: big(row.message_id),
        receivedAt: row.received_at,
        direction: row.direction,
        journal: false,
        policy: true,
        policyRuleRef: request.ruleRef,
        settingsGeneration: ctx.generation,
        nextCheckAt: now,
      });
    }
    const last = visible[visible.length - 1];
    await this.prisma.$transaction(async (tx) => {
      await upsertIntents(tx, intents);
      if (last !== undefined) {
        await writeCursor(tx, this.cursorName, big(last.id), last.received_at);
      }
    });
    if (last !== undefined) {
      this.options.metrics.sweepLag.set(
        { sweep: 'policy' },
        Math.max(0, (now.getTime() - last.created_at.getTime()) / 1000),
      );
    } else {
      // Nothing new to pass: the sweep is as current as its safety lag allows.
      this.options.metrics.sweepLag.set({ sweep: 'policy' }, this.options.safetyLagSeconds);
    }
    return {
      scanned: visible.length,
      intents: intents.length,
      more: !stoppedAtLag && rows.length === this.options.batchSize,
      stoppedAtLag,
    };
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
