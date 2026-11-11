import { Prisma } from '@email-gateway/database';
import type { RoundRows } from '@email-gateway/risk-scoring';
import type { RiskRead } from './risk-metrics';

/**
 * The writer reads of the risk scorer (step 5.1 R12, R13, §6), always inside the caller's
 * transaction (the round's completion or the sandbox final), with the step 4.2 §6 mitigation of
 * the Prisma wrong-read defect: every deciding read selects and verifies its identifying columns,
 * and a row of another scan, message, organization or time throws `InconsistentRiskReadError`
 * (retryable: the whole transaction is retried, nothing is scored from a wrong row).
 *
 * The result rows (`scan_engine_results` finals when the caller has none, `email_auth_results`,
 * `bec_scan_results`, `dlp_scan_results`) are read with `FOR SHARE`: the sandbox path holds only
 * the `email_scans` row lock and its REPEATABLE READ snapshot may predate the completion that
 * committed them, so a consistent read could miss them (the step 4.6 X15 rule "rows that decide
 * are read with a locking read"). Lock order stays scan → result rows, as in the round's own
 * transactions (message → scan → results). The message row is read without a lock (its
 * direction and counts are written before the round opens and never change afterwards); taking
 * it after the scan row would invert the message → scan order.
 */

/** A writer read returned rows that do not belong to the request; retryable (§6). */
export class InconsistentRiskReadError extends Error {
  override readonly name = 'InconsistentRiskReadError';

  constructor(
    readonly read: RiskRead,
    readonly check: string,
  ) {
    super(`inconsistent risk ${read} read: ${check}`);
  }
}

/** The round as the scorer needs it (a `ScanRound` satisfies it). */
export interface RiskRound {
  scanId: bigint;
  receivedAt: Date;
  messageId: bigint;
  organizationId: bigint;
  round: number;
  scanKind: 'initial' | 'rescan';
  requiredEngines: string[];
  /** `email_scans.risk_profile_version_id`: the snapshot taken at open (null = platform). */
  riskProfileVersionId: bigint | null;
}

export type RiskScanStatus = 'completed' | 'failed' | 'timed_out';
export type RiskFinal = RoundRows['finals'][number];

/** The `email_scans` row of a round, locked (the sandbox path, R13 (a)). */
export interface LockedRiskRound extends RiskRound {
  status: string;
}

/** `scan_engine_results` columns of a final as `buildScoringInput` needs them (R12). */
export const RISK_FINAL_SELECT = {
  engine: true,
  outcome: true,
  errorCode: true,
  reasonCodes: true,
  score: true,
  engineVersion: true,
  settingsVersion: true,
  attempt: true,
  completedAt: true,
} as const;

type RawRow = Record<string, unknown>;

const sameTime = (a: unknown, b: Date): boolean => a instanceof Date && a.getTime() === b.getTime();
const big = (value: unknown): bigint | null =>
  typeof value === 'bigint' || typeof value === 'number' || typeof value === 'string'
    ? BigInt(value)
    : null;
const str = (value: unknown): string | null =>
  typeof value === 'string'
    ? value
    : typeof value === 'number' || typeof value === 'bigint'
      ? value.toString()
      : null;

/** A JSON column as read: raw queries may return the text, typed reads the value. */
export function jsonColumn(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    // Left as text: buildScoringInput refuses it (RiskInputError → the error row).
    return value;
  }
}

/** A DECIMAL as canonical text (`1.500` and `1.5` give `1.5`), so both read paths hash alike. */
export function decimalText(value: unknown): string | null {
  let text: string;
  if (typeof value === 'string') text = value;
  else if (typeof value === 'number' || typeof value === 'bigint') text = value.toString();
  else if (value instanceof Prisma.Decimal) text = value.toString();
  else if (typeof value === 'object' && value !== null && 'toFixed' in value) {
    // A Decimal of another decimal.js instance (raw query results).
    text = (value as { toString(): string }).toString();
  } else return null;
  try {
    return new Prisma.Decimal(text).toString();
  } catch {
    return text;
  }
}

/** A final row of the typed `RISK_FINAL_SELECT` read (the completion path). */
export function toRiskFinal(row: {
  engine: string;
  outcome: string;
  errorCode: string | null;
  reasonCodes: unknown;
  score: unknown;
  engineVersion: string | null;
  settingsVersion: string | null;
  attempt: number;
  completedAt: Date;
}): RiskFinal {
  return {
    engine: row.engine,
    outcome: row.outcome as RiskFinal['outcome'],
    errorCode: row.errorCode,
    reasonCodes: jsonColumn(row.reasonCodes),
    score: decimalText(row.score),
    engineVersion: row.engineVersion,
    settingsVersion: row.settingsVersion,
    attempt: row.attempt,
    completedAt: row.completedAt,
  };
}

export class RiskRoundReader {
  constructor(private readonly onInconsistent: (read: RiskRead) => void = () => undefined) {}

  private wrong(read: RiskRead, check: string): never {
    this.onInconsistent(read);
    throw new InconsistentRiskReadError(read, check);
  }

  private echo(read: RiskRead, row: RawRow, round: RiskRound): void {
    if (
      big(row.scan_id) !== round.scanId ||
      big(row.message_id) !== round.messageId ||
      big(row.organization_id) !== round.organizationId ||
      !sameTime(row.received_at, round.receivedAt)
    ) {
      this.wrong(read, 'scan echo');
    }
  }

  /**
   * The `email_scans` row `FOR UPDATE` (re-entrant when the caller holds it), echo-checked; null
   * when it is gone. The sandbox path decides on its `status` and scores with its snapshot.
   */
  async lockRound(
    tx: Prisma.TransactionClient,
    ref: { scanId: bigint; receivedAt: Date; organizationId: bigint; messageId: bigint },
  ): Promise<LockedRiskRound | null> {
    const rows = await tx.$queryRaw<RawRow[]>`
      SELECT id, received_at, message_id, organization_id, status, lifecycle_round, scan_kind,
             required_engines, risk_profile_version_id
      FROM email_scans WHERE id = ${ref.scanId} AND received_at = ${ref.receivedAt}
      FOR UPDATE`;
    const row = rows[0];
    if (!row) return null;
    if (
      rows.length !== 1 ||
      big(row.id) !== ref.scanId ||
      !sameTime(row.received_at, ref.receivedAt) ||
      big(row.organization_id) !== ref.organizationId ||
      big(row.message_id) !== ref.messageId
    ) {
      this.wrong('scan', 'identity echo');
    }
    const required = jsonColumn(row.required_engines);
    return {
      scanId: ref.scanId,
      receivedAt: ref.receivedAt,
      messageId: ref.messageId,
      organizationId: ref.organizationId,
      round: Number(row.lifecycle_round),
      scanKind: row.scan_kind === 'rescan' ? 'rescan' : 'initial',
      requiredEngines: Array.isArray(required)
        ? required.filter((v): v is string => typeof v === 'string')
        : [],
      riskProfileVersionId: big(row.risk_profile_version_id),
      status: String(row.status),
    };
  }

  /** Every final row of the round (`FOR SHARE`, the sandbox path), echo-checked. */
  async lockedFinals(tx: Prisma.TransactionClient, round: RiskRound): Promise<RiskFinal[]> {
    const rows = await tx.$queryRaw<RawRow[]>`
      SELECT scan_id, received_at, message_id, organization_id, engine, outcome, error_code,
             reason_codes, score, engine_version, settings_version, attempt, completed_at, is_final
      FROM scan_engine_results
      WHERE scan_id = ${round.scanId} AND received_at = ${round.receivedAt} AND is_final = 1
      FOR SHARE`;
    return rows.map((row) => {
      this.echo('finals', row, round);
      if (!(Number(row.is_final) === 1 || row.is_final === true)) this.wrong('finals', 'final');
      const completedAt = row.completed_at;
      if (!(completedAt instanceof Date)) this.wrong('finals', 'completed_at');
      return {
        engine: String(row.engine),
        outcome: String(row.outcome) as RiskFinal['outcome'],
        errorCode: str(row.error_code),
        reasonCodes: jsonColumn(row.reason_codes),
        score: decimalText(row.score),
        engineVersion: str(row.engine_version),
        settingsVersion: str(row.settings_version),
        attempt: Number(row.attempt),
        completedAt,
      };
    });
  }

  /**
   * The rows of R12 for one round (null: the message row is gone, nothing to score). `finals` are
   * every final row of the round (sandbox included), as the caller read them.
   */
  async read(
    tx: Prisma.TransactionClient,
    round: RiskRound,
    scanStatus: RiskScanStatus,
    finals: readonly RiskFinal[],
  ): Promise<RoundRows | null> {
    const message = await tx.emailMessage.findFirst({
      where: {
        id: round.messageId,
        receivedAt: round.receivedAt,
        organizationId: round.organizationId,
      },
      select: {
        id: true,
        receivedAt: true,
        organizationId: true,
        direction: true,
        attachmentCount: true,
        recipientCount: true,
      },
    });
    if (!message) return null;
    if (
      message.id !== round.messageId ||
      message.organizationId !== round.organizationId ||
      !sameTime(message.receivedAt, round.receivedAt)
    ) {
      this.wrong('message', 'identity echo');
    }
    const has = (engine: string) => finals.some((f) => f.engine === engine);
    return {
      scan: {
        requiredEngines: round.requiredEngines,
        scanKind: round.scanKind,
        lifecycleRound: round.round,
        status: scanStatus,
      },
      message: {
        direction: message.direction,
        attachmentCount: message.attachmentCount,
        recipientCount: message.recipientCount,
      },
      finals,
      auth: has('rspamd') ? await this.auth(tx, round) : null,
      bec: has('bec') ? await this.bec(tx, round) : null,
      dlp: has('dlp') ? await this.dlp(tx, round) : null,
    };
  }

  private async auth(tx: Prisma.TransactionClient, round: RiskRound): Promise<RoundRows['auth']> {
    const rows = await tx.$queryRaw<RawRow[]>`
      SELECT scan_id, received_at, message_id, organization_id, engine, spf, dkim, dmarc,
             dmarc_policy, arc
      FROM email_auth_results
      WHERE scan_id = ${round.scanId} AND received_at = ${round.receivedAt} AND engine = 'rspamd'
      FOR SHARE`;
    const row = rows[0];
    if (!row) return null;
    if (rows.length !== 1 || row.engine !== 'rspamd') this.wrong('auth', 'unique row');
    this.echo('auth', row, round);
    type Auth = NonNullable<RoundRows['auth']>;
    return {
      spf: str(row.spf) as Auth['spf'],
      dkim: str(row.dkim) as Auth['dkim'],
      dmarc: str(row.dmarc) as Auth['dmarc'],
      dmarcPolicy: str(row.dmarc_policy) as Auth['dmarcPolicy'],
      arc: str(row.arc) as Auth['arc'],
    };
  }

  private async bec(tx: Prisma.TransactionClient, round: RiskRound): Promise<RoundRows['bec']> {
    const rows = await tx.$queryRaw<RawRow[]>`
      SELECT scan_id, received_at, message_id, organization_id, lifecycle_round,
             deterministic_verdict, verdict, rules
      FROM bec_scan_results
      WHERE scan_id = ${round.scanId} AND received_at = ${round.receivedAt}
      FOR SHARE`;
    const row = rows[0];
    if (!row) return null;
    if (rows.length !== 1) this.wrong('bec', 'unique row');
    this.echo('bec', row, round);
    if (Number(row.lifecycle_round) !== round.round) this.wrong('bec', 'round echo');
    return {
      deterministicVerdict: String(row.deterministic_verdict),
      verdict: String(row.verdict),
      rules: jsonColumn(row.rules),
    };
  }

  private async dlp(tx: Prisma.TransactionClient, round: RiskRound): Promise<RoundRows['dlp']> {
    const rows = await tx.$queryRaw<RawRow[]>`
      SELECT scan_id, received_at, message_id, organization_id, lifecycle_round, action, verdict,
             coverage, categories
      FROM dlp_scan_results
      WHERE scan_id = ${round.scanId} AND received_at = ${round.receivedAt}
      FOR SHARE`;
    const row = rows[0];
    if (!row) return null;
    if (rows.length !== 1) this.wrong('dlp', 'unique row');
    this.echo('dlp', row, round);
    if (Number(row.lifecycle_round) !== round.round) this.wrong('dlp', 'round echo');
    return {
      action: String(row.action),
      verdict: String(row.verdict),
      coverage: String(row.coverage),
      categories: jsonColumn(row.categories),
    };
  }
}
