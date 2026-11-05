import { BadRequestException } from '@nestjs/common';
import { ENGINE_CATALOG } from '@email-gateway/security-contracts';
import { z } from 'zod';
import type {
  ScanAttempt,
  ScanAuthView,
  ScanEngineResultView,
  ScanRoundView,
  ScanSymbol,
} from '../dto/message-scans.schemas';
import type {
  AuthResultRow,
  EngineResultRow,
  ScanRoundRow,
} from '../repositories/message-scans-read.repository';

/**
 * Pure mapping of the scan rows to the read API (step 4.1 S16) and its round cursor. Stored
 * JSON is parsed defensively: a malformed value is shown as empty, never passed through raw.
 */

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());
const decimal = (value: { toNumber(): number } | null): number | null =>
  value === null ? null : value.toNumber();

const stringList = z.array(z.string());
/** A JSON array of strings, or `[]` for anything else. */
export function stringArray(value: unknown): string[] {
  const parsed = stringList.safeParse(value);
  return parsed.success ? parsed.data : [];
}

const MAX_SYMBOLS = 200;
const symbolSchema = z.object({
  name: z.string().min(1).max(128),
  score: z.number().finite(),
  options: z.array(z.string().max(200)).max(5).default([]),
});

/** `evidence.signals` (S9) as symbols; invalid entries are skipped, at most 200. */
export function symbolsOf(evidence: unknown): ScanSymbol[] {
  if (evidence === null || typeof evidence !== 'object' || Array.isArray(evidence)) return [];
  const signals = (evidence as { signals?: unknown }).signals;
  if (!Array.isArray(signals)) return [];
  const out: ScanSymbol[] = [];
  for (const signal of signals) {
    const parsed = symbolSchema.safeParse(signal);
    if (parsed.success) out.push(parsed.data);
    if (out.length >= MAX_SYMBOLS) break;
  }
  return out;
}

const signatureSchema = z.object({
  domain: z.string(),
  result: z.enum(['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror']),
  selector: z.string().nullable().default(null),
});

export function authOf(row: AuthResultRow): ScanAuthView {
  const signatures = Array.isArray(row.dkimSignatures)
    ? row.dkimSignatures.flatMap((entry) => {
        const parsed = signatureSchema.safeParse(entry);
        return parsed.success ? [parsed.data] : [];
      })
    : [];
  return {
    spf: row.spf,
    spfDomain: row.spfDomain,
    dkim: row.dkim,
    dkimSignatures: signatures,
    dmarc: row.dmarc,
    dmarcPolicy: row.dmarcPolicy,
    dmarcDomain: row.dmarcDomain,
    arc: row.arc,
  };
}

function attemptOf(row: EngineResultRow): ScanAttempt {
  return {
    attempt: row.attempt,
    outcome: row.outcome,
    errorCode: row.errorCode,
    durationMs: row.durationMs,
    at: row.completedAt.toISOString(),
  };
}

/** One engine of a round: the final row as the result (if any), every row as an attempt. */
export function engineOf(engine: string, rows: readonly EngineResultRow[]): ScanEngineResultView {
  const sorted = [...rows].sort((a, b) => a.attempt - b.attempt);
  const final = sorted.find((row) => row.isFinal) ?? null;
  return {
    engine,
    final: final !== null,
    engineVersion: final?.engineVersion ?? sorted.at(-1)?.engineVersion ?? null,
    outcome: final?.outcome ?? null,
    score: final ? decimal(final.score) : null,
    requiredScore: final ? decimal(final.requiredScore) : null,
    action: final?.action ?? null,
    reasonCodes: final ? stringArray(final.reasonCodes) : [],
    symbols: final ? symbolsOf(final.evidence) : [],
    attempts: sorted.map(attemptOf),
    durationMs: final?.durationMs ?? null,
    settingsVersion: final?.settingsVersion ?? null,
    completedAt: final ? final.completedAt.toISOString() : null,
  };
}

const catalogRank = (engine: string): number => {
  const index = ENGINE_CATALOG.findIndex((entry) => entry.name === engine);
  return index === -1 ? ENGINE_CATALOG.length : index;
};
const byCatalog = (a: string, b: string): number =>
  catalogRank(a) - catalogRank(b) || (a < b ? -1 : a > b ? 1 : 0);

/** A round with its engines (catalog order) and the first engine's authentication results. */
export function roundOf(
  scan: ScanRoundRow,
  engineRows: readonly EngineResultRow[],
  authRows: readonly AuthResultRow[],
): ScanRoundView {
  const byEngine = new Map<string, EngineResultRow[]>();
  for (const row of engineRows) {
    if (row.scanId !== scan.id) continue;
    const list = byEngine.get(row.engine) ?? [];
    list.push(row);
    byEngine.set(row.engine, list);
  }
  const auth = authRows
    .filter((row) => row.scanId === scan.id)
    .sort((a, b) => byCatalog(a.engine, b.engine))[0];
  return {
    round: scan.lifecycleRound,
    scanKind: scan.scanKind,
    status: scan.status,
    verdict: scan.scanVerdict,
    reasonCodes: stringArray(scan.reasonCodes),
    requiredEngines: stringArray(scan.requiredEngines),
    startedAt: iso(scan.startedAt),
    completedAt: iso(scan.completedAt),
    deadlineAt: iso(scan.deadlineAt),
    auth: auth ? authOf(auth) : null,
    engines: [...byEngine.keys()]
      .sort(byCatalog)
      .map((engine) => engineOf(engine, byEngine.get(engine)!)),
  };
}

const CURSOR_PREFIX = 'r';

/** Scan cursor: the round of the last entry of the previous page (rounds are unique). */
export function encodeScanCursor(round: number): string {
  return Buffer.from(`${CURSOR_PREFIX}${round}`, 'utf8').toString('base64url');
}

export function decodeScanCursor(cursor: string): number {
  const decoded = Buffer.from(cursor, 'base64url').toString('utf8');
  const match = /^r(0|[1-9][0-9]{0,4})$/.exec(decoded);
  const round = match ? Number(match[1]) : NaN;
  if (!Number.isSafeInteger(round) || round > 65_535 || encodeScanCursor(round) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return round;
}
