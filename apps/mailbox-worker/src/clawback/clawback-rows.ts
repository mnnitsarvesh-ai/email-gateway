import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import {
  canonicalCriteriaSha256,
  clawbackCriteriaSchema,
  clawbackSignalSchema,
  normalizeClawbackCriteria,
  type ClawbackCriteria,
  type ClawbackSignal,
  type ClawbackSignalFacts,
} from '@email-gateway/mailbox-api';

const DAY_MS = 86_400_000;
/** `from` never before now − 186 days (the copies retention, C4.1); one minute of slack. */
const RETENTION_MS = 186 * DAY_MS - 60_000;

/** An automatic clawback as the copies role (late verdict) or the TI sweep creates it. */
export interface AutomaticClawback {
  organizationId: bigint;
  trigger: 'late_verdict' | 'threat_intel';
  signalKey: string;
  signal: ClawbackSignal;
  criteria: ClawbackCriteria;
  facts: ClawbackSignalFacts;
  signalAt: Date;
  now: Date;
}

/**
 * C2.1 / C2.2: the search window of an automatic clawback — `[anchor − lookback, now]`, never
 * before the copies retention.
 */
export function automaticWindow(
  anchor: Date,
  lookbackDays: number,
  now: Date,
): { from: string; to: string } {
  const from = Math.max(anchor.getTime() - lookbackDays * DAY_MS, now.getTime() - RETENTION_MS);
  return {
    from: new Date(Math.min(from, now.getTime())).toISOString(),
    to: now.toISOString(),
  };
}

/** The criteria document of an automatic signal, validated, or null when it has no key. */
export function automaticCriteria(input: {
  window: { from: string; to: string };
  keys: ClawbackCriteria['keys'];
}): ClawbackCriteria | null {
  const keys = Object.fromEntries(
    Object.entries(input.keys).filter(
      ([, value]) => value !== undefined && (!Array.isArray(value) || value.length > 0),
    ),
  ) as ClawbackCriteria['keys'];
  const parsed = clawbackCriteriaSchema.safeParse({
    v: 1,
    window: input.window,
    keys,
    directions: ['inbound', 'internal'],
    includeReportMailboxes: false,
  });
  return parsed.success ? normalizeClawbackCriteria(parsed.data) : null;
}

/**
 * Writes an automatic clawback (`INSERT IGNORE` on UNIQUE (organization_id, signal_key), C2.5):
 * `decision_mode = policy`, the signal facts (C3.1), status `searching` due now, requested by the
 * system. Strict documents only (`api-clawback-signal/1`, `api-clawback-criteria/1`); content-free
 * (hashes, keys, addresses, windows). True when a row was created.
 */
export async function insertAutomaticClawback(
  tx: Prisma.TransactionClient,
  input: AutomaticClawback,
): Promise<boolean> {
  const signal = clawbackSignalSchema.parse(input.signal);
  const criteria = normalizeClawbackCriteria(clawbackCriteriaSchema.parse(input.criteria));
  const inserted = await tx.$executeRaw`
    INSERT IGNORE INTO api_clawbacks
      (public_id, organization_id, \`trigger\`, signal_key, \`signal\`, criteria, criteria_sha256,
       decision_mode, signal_verdict, signal_level, signal_hard_blocks, status, restore_status,
       requires_approval, requested_by_type, signal_at, next_step_at, row_version, created_at,
       updated_at)
    VALUES (${uuidv7(input.now.getTime())}, ${input.organizationId}, ${input.trigger},
            ${input.signalKey}, ${JSON.stringify(signal)}, ${JSON.stringify(criteria)},
            ${canonicalCriteriaSha256(criteria)}, 'policy', ${input.facts.verdict},
            ${input.facts.level}, ${JSON.stringify(input.facts.hardBlocks)}, 'searching', 'none', 0,
            'system', ${input.signalAt}, ${input.now}, 1, ${input.now}, ${input.now})`;
  return inserted === 1;
}
