import { withTransactionDefaults } from '@email-gateway/common';
import type { PrismaClient } from '@email-gateway/database';
import type { Logger } from '@email-gateway/logger';
import {
  clawbackSignalKey,
  ORG_SETTINGS_DEFAULTS,
  signalFacts,
  signatureEligible,
  tiEligible,
  type ClawbackCriteria,
  type ClawbackSignalFacts,
  type ClawbackTiTable,
  type ThreatCategory,
  type ThreatIndicatorType,
  type ThreatSeverity,
} from '@email-gateway/mailbox-api';
import { loadOrgApiModeState } from '../domain/api-mode-state';
import { OrgSettingsMemo } from '../domain/org-settings';
import type { MailboxMetrics } from '../metrics/mailbox-metrics';
import { big, TX_MAX_WAIT_MS, TX_TIMEOUT_MS } from '../shared/db';
import { automaticCriteria, automaticWindow, insertAutomaticClawback } from './clawback-rows';
import { searchCopies } from './search';

/** Leader lock of the TI sweep (C2.2; the health role's GET_LOCK pattern). */
export const TI_SWEEP_LOCK = 'eg:mailbox:clawback-ti';
const DAY_MS = 86_400_000;
const HEX64 = /^[0-9a-f]{64}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

/** `api_mode_cursors.position` (`{ createdAt, id }` keyset). */
export interface SweepCursor {
  createdAt: Date;
  id: bigint;
}

export interface TiSweepDeps {
  prisma: PrismaClient;
  metrics: MailboxMetrics | null;
  logger: Logger;
  now: () => Date;
  config: { batch: number; maxTargets: number };
  /** Cursor name prefix (integration suites run beside a live worker); '' in production. */
  cursorPrefix?: string;
  /** TEST SEAM: only these organizations get clawbacks. */
  organizationIds?: readonly bigint[];
}

export interface TiSweepReport {
  indicators: number;
  signatures: number;
  created: number;
}

/** One swept row as a signal (indicator or signature). */
interface SweptSignal {
  table: ClawbackTiTable;
  rowId: bigint;
  /** null = platform row (every API-active organization). */
  organizationId: bigint | null;
  createdAt: Date;
  keys: ClawbackCriteria['keys'] | null;
  eligible: (minConfidence: number, now: Date) => boolean;
  facts: ClawbackSignalFacts;
  kind: 'threat_indicator' | 'malware_signature';
}

/** The criteria keys of an indicator (C2.2, C4.1): URL hash, domain, file hash, sender. */
export function indicatorKeys(
  type: ThreatIndicatorType,
  value: string,
  valueSha256: string,
): ClawbackCriteria['keys'] | null {
  const v = value.trim().toLowerCase();
  switch (type) {
    case 'url':
      return HEX64.test(valueSha256) ? { urlSha256: [valueSha256] } : null;
    case 'domain':
      return DOMAIN.test(v) ? { urlDomains: [v], senderDomains: [v] } : null;
    case 'file_sha256':
      return HEX64.test(v) ? { attachmentSha256: [v] } : null;
    case 'email': {
      const at = v.lastIndexOf('@');
      return at > 0 && DOMAIN.test(v.slice(at + 1)) && !/\s/.test(v) ? { senders: [v] } : null;
    }
    default:
      return null;
  }
}

/**
 * The threat-intelligence sweep of the `clawback` role leader (step API-3 C2.2): every
 * `API_MODE_CLAWBACK_TI_INTERVAL_SECONDS`, `threat_indicators` and `malware_signatures` created
 * after the stored cursor (`api_mode_cursors`, `(created_at, id)` keyset over the new indexes,
 * batch `API_MODE_CLAWBACK_TI_BATCH`; the first run starts at the default lookback). Eligible
 * rows (`tiEligible` with the organization's `ti_min_confidence`, `signatureEligible`) — platform
 * rows fanned out to every API-active organization, organization rows to their own — get an
 * inline search (index lookups, existence only) per organization; a clawback
 * (`trigger = threat_intel`, signal key C2.5, `INSERT IGNORE`) is created only when at least one
 * copy matches and the organization's automatic clawback is not `off`. The cursor advances after
 * each batch. The tenant of a platform indicator comes from the worker's fan-out, never a client.
 */
export class TiSweep {
  private readonly txPrisma: PrismaClient;

  constructor(private readonly deps: TiSweepDeps) {
    this.txPrisma = withTransactionDefaults(deps.prisma, {
      timeoutMs: TX_TIMEOUT_MS,
      maxWaitMs: TX_MAX_WAIT_MS,
    });
  }

  cursorName(table: ClawbackTiTable): string {
    return `${this.deps.cursorPrefix ?? ''}ti:${table}`.slice(0, 64);
  }

  async runOnce(): Promise<TiSweepReport> {
    const report: TiSweepReport = { indicators: 0, signatures: 0, created: 0 };
    const settings = new OrgSettingsMemo();
    const orgs = await this.activeOrganizations();
    for (const table of ['threat_indicators', 'malware_signatures'] as const) {
      for (let pass = 0; pass < 50; pass++) {
        const cursor = await this.cursor(table);
        const rows =
          table === 'threat_indicators'
            ? await this.indicators(cursor)
            : await this.signatures(cursor);
        if (rows.length === 0) break;
        for (const row of rows) {
          if (table === 'threat_indicators') report.indicators += 1;
          else report.signatures += 1;
          const targets =
            row.organizationId === null ? orgs : orgs.filter((o) => o === row.organizationId);
          // A failure leaves the cursor before this batch: the batch is replayed next run and
          // the signal key makes the replay create nothing twice.
          for (const organizationId of targets) {
            if (await this.signalFor(row, organizationId, settings)) report.created += 1;
          }
        }
        const last = rows[rows.length - 1]!;
        await this.storeCursor(table, { createdAt: last.createdAt, id: last.rowId });
        if (rows.length < this.deps.config.batch) break;
      }
    }
    if (report.created > 0) {
      this.deps.logger.info({ ...report }, 'threat-intelligence sweep created clawbacks');
    }
    return report;
  }

  /** Organizations with an API connection whose API mode is active (D1), test seam applied. */
  private async activeOrganizations(): Promise<bigint[]> {
    const rows = await this.deps.prisma.apiModeConnection.findMany({
      where: this.deps.organizationIds
        ? { organizationId: { in: [...this.deps.organizationIds] } }
        : {},
      select: { organizationId: true },
      distinct: ['organizationId'],
      orderBy: { organizationId: 'asc' },
    });
    const out: bigint[] = [];
    for (const { organizationId } of rows) {
      const state = await loadOrgApiModeState(this.deps.prisma, organizationId);
      if (state?.active) out.push(organizationId);
    }
    return out;
  }

  private async cursor(table: ClawbackTiTable): Promise<SweepCursor> {
    const row = await this.deps.prisma.apiModeCursor.findUnique({
      where: { name: this.cursorName(table) },
      select: { position: true },
    });
    const position = row?.position as { createdAt?: unknown; id?: unknown } | null | undefined;
    if (
      position &&
      typeof position.createdAt === 'string' &&
      typeof position.id === 'string' &&
      /^[0-9]{1,20}$/.test(position.id) &&
      !Number.isNaN(Date.parse(position.createdAt))
    ) {
      return { createdAt: new Date(position.createdAt), id: BigInt(position.id) };
    }
    // First run: never older than the (default) lookback.
    const start = this.deps.now().getTime() - ORG_SETTINGS_DEFAULTS.clawbackLookbackDays * DAY_MS;
    return { createdAt: new Date(start), id: 0n };
  }

  private async storeCursor(table: ClawbackTiTable, cursor: SweepCursor): Promise<void> {
    const position = JSON.stringify({
      createdAt: cursor.createdAt.toISOString(),
      id: cursor.id.toString(),
    });
    const now = this.deps.now();
    await this.deps.prisma.$executeRaw`
      INSERT INTO api_mode_cursors (name, position, updated_at)
      VALUES (${this.cursorName(table)}, ${position}, ${now})
      ON DUPLICATE KEY UPDATE position = VALUES(position), updated_at = VALUES(updated_at)`;
  }

  private async indicators(cursor: SweepCursor): Promise<SweptSignal[]> {
    const rows = await this.deps.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        organization_id: bigint | number | null;
        indicator_type: ThreatIndicatorType;
        value: string;
        value_sha256: string;
        severity: ThreatSeverity;
        confidence: number;
        category: ThreatCategory | null;
        expires_at: Date | null;
        created_at: Date;
      }>
    >`
      SELECT id, organization_id, indicator_type, value, value_sha256, severity, confidence,
             category, expires_at, created_at
      FROM threat_indicators
      WHERE created_at > ${cursor.createdAt}
         OR (created_at = ${cursor.createdAt} AND id > ${cursor.id})
      ORDER BY created_at, id
      LIMIT ${this.deps.config.batch}`;
    return rows.map((r) => {
      const type = r.indicator_type;
      const confidence = Number(r.confidence);
      const facts =
        type === 'ip'
          ? null
          : signalFacts({
              kind: 'threat_indicator',
              indicatorType: type,
              severity: r.severity,
              confidence,
              category: r.category,
            });
      return {
        table: 'threat_indicators' as const,
        rowId: big(r.id),
        organizationId: r.organization_id === null ? null : big(r.organization_id),
        createdAt: r.created_at,
        keys: indicatorKeys(type, r.value, r.value_sha256),
        eligible: (minConfidence: number, now: Date) =>
          facts !== null &&
          tiEligible(
            { indicatorType: type, severity: r.severity, confidence, expiresAt: r.expires_at },
            minConfidence,
            now,
          ),
        facts: facts ?? { verdict: 'suspicious', level: 'low', hardBlocks: [] },
        kind: 'threat_indicator' as const,
      };
    });
  }

  private async signatures(cursor: SweepCursor): Promise<SweptSignal[]> {
    const rows = await this.deps.prisma.$queryRaw<
      Array<{
        id: bigint | number;
        sha256: string;
        severity: ThreatSeverity;
        expires_at: Date | null;
        created_at: Date;
      }>
    >`
      SELECT id, sha256, severity, expires_at, created_at FROM malware_signatures
      WHERE created_at > ${cursor.createdAt}
         OR (created_at = ${cursor.createdAt} AND id > ${cursor.id})
      ORDER BY created_at, id
      LIMIT ${this.deps.config.batch}`;
    return rows.map((r) => ({
      table: 'malware_signatures' as const,
      rowId: big(r.id),
      organizationId: null,
      createdAt: r.created_at,
      keys: indicatorKeys('file_sha256', r.sha256, ''),
      eligible: (_minConfidence: number, now: Date) =>
        signatureEligible({ severity: r.severity, expiresAt: r.expires_at }, now),
      facts: signalFacts({ kind: 'malware_signature', severity: r.severity }),
      kind: 'malware_signature' as const,
    }));
  }

  /** One (signal, organization): eligibility, inline existence search, clawback. */
  private async signalFor(
    row: SweptSignal,
    organizationId: bigint,
    memo: OrgSettingsMemo,
  ): Promise<boolean> {
    if (row.keys === null) return false;
    const settings = await memo.get(this.deps.prisma, organizationId);
    if (settings.autoClawback === 'off') return false;
    const now = this.deps.now();
    if (!row.eligible(settings.tiMinConfidence, now)) return false;
    const criteria = automaticCriteria({
      window: automaticWindow(now, settings.clawbackLookbackDays, now),
      keys: row.keys,
    });
    if (criteria === null) return false;
    const found = await searchCopies(this.deps.prisma, organizationId, criteria, {
      maxTargets: this.deps.config.maxTargets,
      firstOnly: true,
    });
    if (found.kind !== 'ok' || found.copies.length === 0) return false;
    const signalAt = row.createdAt;
    const created = await this.txPrisma.$transaction((tx) =>
      insertAutomaticClawback(tx, {
        organizationId,
        trigger: 'threat_intel',
        signalKey: clawbackSignalKey(organizationId, {
          source: 'ti',
          table: row.table,
          rowId: row.rowId,
        }),
        signal: {
          v: 1,
          kind: row.kind,
          refs:
            row.table === 'threat_indicators'
              ? { indicatorId: row.rowId.toString() }
              : { signatureId: row.rowId.toString() },
          facts: row.facts,
          signalAt: signalAt.toISOString(),
        },
        criteria,
        facts: row.facts,
        signalAt,
        now,
      }),
    );
    if (created) this.deps.metrics?.clawback('threat_intel', 'created');
    return created;
  }
}
