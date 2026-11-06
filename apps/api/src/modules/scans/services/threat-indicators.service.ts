import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import { normalizeIndicator } from '@email-gateway/url-security';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { TransactionRunner } from '../../../database/transaction-runner';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import type {
  ThreatIndicatorCreate,
  ThreatIndicatorListQuery,
  ThreatIndicatorPage,
  ThreatIndicatorType,
  ThreatIndicatorView,
} from '../dto/threat-indicators.schemas';
import {
  type ThreatIndicatorRow,
  ThreatIndicatorsRepository,
} from '../repositories/threat-indicators.repository';
import { indicatorExists, threatIndicatorNotFound } from '../scans.errors';
import { assertPlatformUser } from './threat-hashes.service';

/** `audit_logs.action` of the catalog changes (D14 `<resource>.<verb>`). */
export const THREAT_INDICATOR_AUDIT = {
  added: 'threat_indicator.added',
  removed: 'threat_indicator.removed',
} as const;
export const THREAT_INDICATOR_RESOURCE = 'threat_indicator';

/**
 * Budget of the indicator writes (step 4.3 §6, the 4.2 §6 mitigation): an interactive
 * transaction is never abandoned by a short timeout (an abandoned statement can leave an unread
 * reply on a pooled connection); 120 s budget, 10 s to obtain a connection.
 */
export const INDICATOR_TX = { timeoutMs: 120_000, maxWaitMs: 10_000 } as const;

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

const NORMALIZE_MESSAGES: Record<string, string> = {
  invalid: 'Not a valid value for the indicator type',
  public_suffix: 'A public suffix (e.g. co.uk, github.io) is not allowed',
  too_long: 'The normalized URL is longer than 2048 characters',
  ip_literal: 'An IP address is not a domain; use type ip',
  single_label: 'A single label is not a registrable domain',
};

/**
 * The value normalized by `@email-gateway/url-security` (U16): URL identity form, domain ASCII
 * registrable-or-host (never a public suffix), IP canonical; and its SHA-256. A value that does
 * not normalize is a `400` (`value: …`).
 */
export function normalizeIndicatorValue(
  type: ThreatIndicatorType,
  raw: string,
): { value: string; valueSha256: string } {
  const result = normalizeIndicator(type, raw);
  if (!result.ok) {
    throw new BadRequestException([`value: ${NORMALIZE_MESSAGES[result.code] ?? 'Invalid value'}`]);
  }
  return { value: result.value, valueSha256: result.valueSha256 };
}

export function threatIndicatorView(row: ThreatIndicatorRow): ThreatIndicatorView {
  return {
    id: row.id.toString(),
    type: row.indicatorType as ThreatIndicatorType,
    value: row.value,
    valueSha256: row.valueSha256,
    severity: row.severity,
    category: row.category,
    source: row.source,
    reason: row.reason,
    expiresAt: iso(row.expiresAt),
    addedByUserId: row.addedBy?.publicId ?? null,
    firstSeenAt: row.firstSeenAt.toISOString(),
    lastSeenAt: row.lastSeenAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** What the audit row keeps of an indicator (the normalized value and metadata). */
const auditImage = (row: ThreatIndicatorRow) => ({
  id: row.id.toString(),
  type: row.indicatorType,
  value: row.value,
  valueSha256: row.valueSha256,
  severity: row.severity,
  category: row.category,
  source: row.source,
  reason: row.reason,
  expiresAt: iso(row.expiresAt),
  addedByUserId: row.addedBy?.publicId ?? null,
  createdAt: row.createdAt.toISOString(),
});

/**
 * The platform threat-indicator catalog (step 4.3 U16): platform rows of `threat_indicators`
 * (`organization_id` NULL, `source = analyst` for this API), consulted uncached by the URL
 * engine (`local_feed`) and the click-service, so a change applies to the next scan and the next
 * click of every organization. Platform users only (`platform:threat_intel_manage`, MFA; enforced
 * by the guard and re-checked here). Adds and removals run on the writer with their
 * `audit_logs` row (`threat_indicator.added` / `threat_indicator.removed` with the
 * before-image) in the same transaction (120 s budget, §6); lists read the replica.
 */
@Injectable()
export class ThreatIndicatorsService {
  private readonly logger = new Logger(ThreatIndicatorsService.name);

  constructor(
    private readonly repository: ThreatIndicatorsRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
  ) {}

  /** `GET /platform/threat-indicators` (replica). */
  async list(
    principal: UserPrincipal,
    query: ThreatIndicatorListQuery,
  ): Promise<ThreatIndicatorPage> {
    assertPlatformUser(principal);
    if (query.value !== undefined && query.type === undefined) {
      throw new BadRequestException(['value: requires type']);
    }
    const window = pageWindow(query);
    const valueSha256 =
      query.value !== undefined && query.type !== undefined
        ? normalizeIndicatorValue(query.type, query.value).valueSha256
        : undefined;
    const rows = await this.repository.list({
      ...window,
      ...(query.type !== undefined && { type: query.type }),
      ...(query.source !== undefined && { source: query.source }),
      ...(valueSha256 !== undefined && { valueSha256 }),
    });
    return toPage(rows, query.limit, threatIndicatorView);
  }

  /** `POST /platform/threat-indicators`: `201`, or `409 indicator_exists`. */
  async add(
    principal: UserPrincipal,
    body: ThreatIndicatorCreate,
    client: ClientContext,
  ): Promise<ThreatIndicatorView> {
    assertPlatformUser(principal);
    const normalized = normalizeIndicatorValue(body.type, body.value);
    const now = new Date();
    const expiresAt = body.expiresAt === undefined ? null : new Date(body.expiresAt);
    if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) {
      throw new BadRequestException(['expiresAt: must be in the future']);
    }
    try {
      const view = await this.transactions.run(async (tx) => {
        const existing = await this.repository.findAnalystForUpdate(
          tx,
          body.type,
          normalized.valueSha256,
        );
        if (existing) throw indicatorExists(existing.id.toString());
        const row = await this.repository.create(tx, {
          type: body.type,
          value: normalized.value,
          valueSha256: normalized.valueSha256,
          severity: body.severity,
          category: body.category,
          reason: body.reason,
          expiresAt,
          addedByUserId: principal.userId,
          now,
        });
        await this.audit.record(
          {
            organizationId: null,
            actor: this.audit.actorFrom(principal),
            action: THREAT_INDICATOR_AUDIT.added,
            resourceType: THREAT_INDICATOR_RESOURCE,
            resourceId: row.id.toString(),
            sourceIp: client.ip,
            metadata: auditImage(row),
          },
          tx,
        );
        return threatIndicatorView(row);
      }, INDICATOR_TX);
      // Values are never logged (a URL may carry tokens); the hash prefix identifies it.
      this.logger.log({
        message: 'threat indicator added',
        id: view.id,
        type: view.type,
        valueSha256Prefix: view.valueSha256.slice(0, 12),
        severity: view.severity,
        actor: principal.userPublicId,
      });
      return view;
    } catch (error) {
      // Two adds of the same value raced on the unique key: the loser is a conflict.
      if (isUniqueViolation(error)) throw indicatorExists(null);
      throw error;
    }
  }

  /** `DELETE /platform/threat-indicators/{id}?reason=`: `204`, or `404`. */
  async remove(
    principal: UserPrincipal,
    id: bigint,
    reason: string,
    client: ClientContext,
  ): Promise<void> {
    assertPlatformUser(principal);
    const removed = await this.transactions.run(async (tx) => {
      const row = await this.repository.findPlatformForUpdate(tx, id);
      if (!row) throw threatIndicatorNotFound();
      await this.repository.remove(tx, row.id);
      await this.audit.record(
        {
          organizationId: null,
          actor: this.audit.actorFrom(principal),
          action: THREAT_INDICATOR_AUDIT.removed,
          resourceType: THREAT_INDICATOR_RESOURCE,
          resourceId: row.id.toString(),
          sourceIp: client.ip,
          metadata: { reason, before: auditImage(row) },
        },
        tx,
      );
      return row;
    }, INDICATOR_TX);
    this.logger.log({
      message: 'threat indicator removed',
      id: removed.id.toString(),
      type: removed.indicatorType,
      actor: principal.userPublicId,
    });
  }
}
