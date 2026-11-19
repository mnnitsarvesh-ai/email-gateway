import { Injectable } from '@nestjs/common';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decodeListCursor,
  encodeListCursor,
  listBinding,
  timeIdKeyOf,
  timeIdKeys,
} from '../../messages/domain/v1-list';
import { ATO_CURSOR_RESOURCES, ATO_RANGES } from '../ato.constants';
import { atoIncidentNotFound } from '../ato.errors';
import { authEventView, signalView } from '../domain/ato-views';
import type { AuthEventPage, IncidentEvidenceQuery, SignalPage } from '../dto/ato.schemas';
import { AtoReadRepository } from '../repositories/ato-read.repository';
import { AtoAccessService, parsePublicId } from './ato-access.service';

const DAY = 86_400_000;

/** Evidence range of an incident: from its first evidence (or detection) a day earlier, to now. */
export function evidenceRange(
  incident: { detectedAt: Date; firstEvidenceAt: Date | null },
  now: Date,
): { from: Date; to: Date } {
  const start = incident.firstEvidenceAt ?? incident.detectedAt;
  const earliest = now.getTime() - ATO_RANGES.incidentEvidence.maxDays * DAY;
  return {
    from: new Date(Math.max(earliest, start.getTime() - DAY)),
    to: new Date(now.getTime() + 60_000),
  };
}

/**
 * The ATO evidence of an incident (step 8.4 §5.1 #14, #15; D24): the signals linked to it
 * (`ato_risk_signals.incident_id`, bounded by the incident's evidence range on the monthly
 * partitions) and the linked authentication events (`security_incident_links`). The id must be
 * an `account_takeover` incident of the organization, else `404 incident_not_found`.
 */
@Injectable()
export class AtoEvidenceService {
  constructor(
    private readonly reads: AtoReadRepository,
    private readonly access: AtoAccessService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  private async incident(scope: TenantScope, rawId: unknown) {
    const id = parsePublicId(rawId, 'incidentId');
    if (!(await this.access.enabled(scope))) throw atoIncidentNotFound();
    const incident = await this.reads.atoIncident(scope, id);
    if (incident === null) throw atoIncidentNotFound();
    return incident;
  }

  async signals(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: IncidentEvidenceQuery,
  ): Promise<SignalPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.incidentSignals,
      principal,
      filters: { incident: { values: [parsePublicId(rawId, 'incidentId')] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const incident = await this.incident(scope, rawId);
    const range = evidenceRange(incident, this.now());
    const rows = await this.reads.signals(scope, {
      where: { incidentId: incident.id },
      range,
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.detectedAt, id: r.id }),
    });
    return {
      data: rows.slice(0, decision.rows).map(signalView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }

  async authEvents(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    query: IncidentEvidenceQuery,
  ): Promise<AuthEventPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.incidentAuthEvents,
      principal,
      filters: { incident: { values: [parsePublicId(rawId, 'incidentId')] } },
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 2);
    const incident = await this.incident(scope, rawId);
    const rows = await this.reads.incidentAuthEvents(scope, {
      incidentId: incident.id,
      after: timeIdKeyOf(decoded),
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({
      fetched: rows,
      limit: query.limit,
      keyOf: (r) => ({ at: r.occurredAt, id: r.id }),
    });
    return {
      data: rows.slice(0, decision.rows).map(authEventView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, timeIdKeys(decision.next)),
    };
  }
}
