import { BadRequestException, Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { categoriesOf, collectRefs, findingsOf, policyOf } from '../domain/dlp-result';
import type { DlpIncidentListQuery, DlpIncidentPage, DlpIncidentView } from '../dto/dlp.schemas';
import {
  DlpResultsRepository,
  type DlpResultRow,
  type IncidentPage,
} from '../repositories/dlp-results.repository';

/** Reads that refill a page whose rows were journal intake results (step 8.6 D5). */
const INCIDENT_FILL_ROUNDS = 5;

const CURSOR = /^i(0|[1-9][0-9]{0,15}):([1-9][0-9]{0,19})$/;

/** Incident cursor: the received time (ms) and id of the last entry of the previous page. */
export function encodeIncidentCursor(row: { receivedAt: Date; id: bigint }): string {
  return Buffer.from(`i${row.receivedAt.getTime()}:${row.id.toString()}`, 'utf8').toString(
    'base64url',
  );
}

export function decodeIncidentCursor(cursor: string): { receivedAt: Date; id: bigint } {
  const match = CURSOR.exec(Buffer.from(cursor, 'base64url').toString('utf8'));
  const parsed = match ? { receivedAt: new Date(Number(match[1])), id: BigInt(match[2]!) } : null;
  if (parsed === null || encodeIncidentCursor(parsed) !== cursor) {
    throw new BadRequestException(['cursor: Invalid cursor']);
  }
  return parsed;
}

const toSecond = (value: Date): string =>
  new Date(Math.floor(value.getTime() / 1000) * 1000).toISOString();

/**
 * `GET /dlp/incidents` (step 4.5 D14, D21): the organization's DLP results whose action is not
 * `allow`, newest first (received time, then id), cursor-paginated, filtered by action,
 * direction and a received-time window, from the read replica. The masked view of D20 without
 * samples: categories, finding codes and counts, the policy match with this organization's
 * public ids; no evidence, no values, no durations.
 */
@Injectable()
export class DlpIncidentsService {
  constructor(private readonly repository: DlpResultsRepository) {}

  async list(scope: TenantScope, query: DlpIncidentListQuery): Promise<DlpIncidentPage> {
    const from = query.from === undefined ? undefined : new Date(query.from);
    const to = query.to === undefined ? undefined : new Date(query.to);
    if (from !== undefined && to !== undefined && from.getTime() >= to.getTime()) {
      throw new BadRequestException(['to: must be after from']);
    }
    const filter: Omit<IncidentPage, 'take' | 'before'> = {
      ...(query.action !== undefined && { action: query.action }),
      ...(query.direction !== undefined && { direction: query.direction }),
      ...(from !== undefined && { from }),
      ...(to !== undefined && { to }),
    };
    // Step 8.6 D5: results of journal intake messages are not gateway incidents. They are
    // dropped after the read (the result rows carry no ingest source), so a page is refilled
    // from the following rows, at most INCIDENT_FILL_ROUNDS reads; a page that is still short
    // ends with the cursor of the last row read.
    const kept: Array<{ row: DlpResultRow; messageId: string }> = [];
    let before = query.cursor === undefined ? undefined : decodeIncidentCursor(query.cursor);
    let exhausted = false;
    let lastRead: DlpResultRow | undefined;
    for (let round = 0; round < INCIDENT_FILL_ROUNDS && kept.length <= query.limit; round += 1) {
      const rows = await this.repository.listIncidents(scope, {
        take: query.limit + 1,
        ...(before !== undefined && { before }),
        ...filter,
      });
      const messages = await this.repository.messagePublicIds(scope, rows);
      for (const row of rows) {
        const messageId = messages.get(row.messageId.toString());
        if (messageId !== undefined) kept.push({ row, messageId });
      }
      lastRead = rows.at(-1) ?? lastRead;
      if (rows.length <= query.limit) {
        exhausted = true;
        break;
      }
      before = { receivedAt: lastRead!.receivedAt, id: lastRead!.id };
    }
    const page = kept.slice(0, query.limit);
    const ids = await this.repository.publicIds(scope, collectRefs(page.map((p) => p.row)));
    const data = page.map((p) => this.viewOf(p.row, p.messageId, ids));
    let nextCursor: string | null = null;
    if (kept.length > query.limit) nextCursor = encodeIncidentCursor(page.at(-1)!.row);
    else if (!exhausted && lastRead !== undefined) nextCursor = encodeIncidentCursor(lastRead);
    return { data, nextCursor };
  }

  private viewOf(
    row: DlpResultRow,
    messageId: string,
    ids: Parameters<typeof policyOf>[1],
  ): DlpIncidentView {
    return {
      messageId,
      scanId: row.scanId.toString(),
      lifecycleRound: row.lifecycleRound,
      receivedAt: row.receivedAt.toISOString(),
      direction: row.direction,
      verdict: row.verdict,
      action: row.action,
      actionSource: row.actionSource,
      coverage: row.coverage,
      findingCount: row.findingCount,
      categories: categoriesOf(row.categories),
      findings: findingsOf(row.findings, ids).map((f) => ({
        detector: f.detector,
        code: f.code,
        category: f.category,
        severity: f.severity,
        count: f.count,
        capped: f.capped,
        ...(f.customPatternId !== undefined && { customPatternId: f.customPatternId }),
        ...(f.dictionaryId !== undefined && { dictionaryId: f.dictionaryId }),
      })),
      policy: policyOf(row, ids),
      detectedAt: toSecond(row.createdAt),
    };
  }
}
