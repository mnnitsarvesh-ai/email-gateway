import { BadRequestException, Injectable } from '@nestjs/common';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { categoriesOf, collectRefs, findingsOf, policyOf } from '../domain/dlp-result';
import type { DlpIncidentListQuery, DlpIncidentPage, DlpIncidentView } from '../dto/dlp.schemas';
import { DlpResultsRepository, type DlpResultRow } from '../repositories/dlp-results.repository';

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
    const rows = await this.repository.listIncidents(scope, {
      take: query.limit + 1,
      ...(query.cursor !== undefined && { before: decodeIncidentCursor(query.cursor) }),
      ...(query.action !== undefined && { action: query.action }),
      ...(query.direction !== undefined && { direction: query.direction }),
      ...(from !== undefined && { from }),
      ...(to !== undefined && { to }),
    });
    const page = rows.slice(0, query.limit);
    const [messages, ids] = await Promise.all([
      this.repository.messagePublicIds(
        scope,
        page.map((row) => row.messageId),
      ),
      this.repository.publicIds(scope, collectRefs(page)),
    ]);
    const data = page.flatMap((row): DlpIncidentView[] => {
      const messageId = messages.get(row.messageId.toString());
      if (messageId === undefined) return [];
      return [this.viewOf(row, messageId, ids)];
    });
    const last = page.at(-1);
    return {
      data,
      nextCursor: rows.length > query.limit && last ? encodeIncidentCursor(last) : null,
    };
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
