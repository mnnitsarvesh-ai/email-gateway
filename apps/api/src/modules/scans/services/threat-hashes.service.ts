import { BadRequestException, ForbiddenException, Injectable, Logger } from '@nestjs/common';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { TransactionRunner } from '../../../database/transaction-runner';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import { isUniqueViolation } from '../../domains/repositories/domains.repository';
import type {
  ThreatHashCreate,
  ThreatHashListQuery,
  ThreatHashPage,
  ThreatHashView,
} from '../dto/threat-hashes.schemas';
import {
  type ThreatHashRow,
  ThreatHashesRepository,
} from '../repositories/threat-hashes.repository';
import { hashExists, threatHashNotFound } from '../scans.errors';

/** `audit_logs.action` of the catalog changes (D14 `<resource>.<verb>`). */
export const THREAT_HASH_AUDIT = {
  added: 'threat_hash.added',
  removed: 'threat_hash.removed',
} as const;
export const THREAT_HASH_RESOURCE = 'malware_signature';

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

export function threatHashView(row: ThreatHashRow): ThreatHashView {
  return {
    sha256: row.sha256,
    md5: row.md5,
    severity: row.severity,
    family: row.family,
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

/** What the audit row keeps of a catalog entry (hashes and metadata, never content). */
const auditImage = (row: ThreatHashRow) => ({
  sha256: row.sha256,
  md5: row.md5,
  severity: row.severity,
  family: row.family,
  source: row.source,
  reason: row.reason,
  expiresAt: iso(row.expiresAt),
  addedByUserId: row.addedBy?.publicId ?? null,
  firstSeenAt: row.firstSeenAt.toISOString(),
});

/**
 * The platform known-threat hash catalog (step 4.2 A16, A17): `malware_signatures`, consulted by
 * the attachment engine on every scan (never cached, so a change applies to the next scan).
 * Platform users only (`platform:threat_intel_manage`, MFA; enforced by the guard and re-checked
 * here: no API keys, no override sessions). Adds and removals run on the writer with their
 * `audit_logs` row (`threat_hash.added` / `threat_hash.removed` with the before-image) in the
 * same transaction; lists read the replica.
 */
@Injectable()
export class ThreatHashesService {
  private readonly logger = new Logger(ThreatHashesService.name);

  constructor(
    private readonly repository: ThreatHashesRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
  ) {}

  /** `GET /platform/threat-hashes` (replica). */
  async list(principal: UserPrincipal, query: ThreatHashListQuery): Promise<ThreatHashPage> {
    assertPlatformUser(principal);
    const window = pageWindow(query);
    const rows = await this.repository.list({
      ...window,
      ...(query.source !== undefined && { source: query.source }),
      ...(query.sha256 !== undefined && { sha256: query.sha256 }),
    });
    return toPage(rows, query.limit, threatHashView);
  }

  /** `POST /platform/threat-hashes`: `201`, or `409 hash_exists`. */
  async add(
    principal: UserPrincipal,
    body: ThreatHashCreate,
    client: ClientContext,
  ): Promise<ThreatHashView> {
    assertPlatformUser(principal);
    const now = new Date();
    const expiresAt = body.expiresAt === undefined ? null : new Date(body.expiresAt);
    if (expiresAt !== null && expiresAt.getTime() <= now.getTime()) {
      throw new BadRequestException(['expiresAt: must be in the future']);
    }
    try {
      const view = await this.transactions.run(async (tx) => {
        if (await this.repository.findForUpdate(tx, body.sha256)) throw hashExists();
        const row = await this.repository.create(tx, {
          sha256: body.sha256,
          md5: body.md5 ?? null,
          severity: body.severity,
          family: body.family ?? null,
          reason: body.reason,
          expiresAt,
          addedByUserId: principal.userId,
          now,
        });
        await this.audit.record(
          {
            organizationId: null,
            actor: this.audit.actorFrom(principal),
            action: THREAT_HASH_AUDIT.added,
            resourceType: THREAT_HASH_RESOURCE,
            resourceId: row.sha256,
            sourceIp: client.ip,
            metadata: auditImage(row),
          },
          tx,
        );
        return threatHashView(row);
      });
      this.logger.log({
        message: 'known-threat hash added',
        sha256: view.sha256,
        severity: view.severity,
        actor: principal.userPublicId,
      });
      return view;
    } catch (error) {
      // Two adds of the same hash raced on the unique key: the loser is a conflict.
      if (isUniqueViolation(error)) throw hashExists();
      throw error;
    }
  }

  /** `DELETE /platform/threat-hashes/{sha256}?reason=`: `204`, or `404 threat_hash_not_found`. */
  async remove(
    principal: UserPrincipal,
    sha256: string,
    reason: string,
    client: ClientContext,
  ): Promise<void> {
    assertPlatformUser(principal);
    await this.transactions.run(async (tx) => {
      const row = await this.repository.findForUpdate(tx, sha256);
      if (!row) throw threatHashNotFound();
      await this.repository.remove(tx, row.id);
      await this.audit.record(
        {
          organizationId: null,
          actor: this.audit.actorFrom(principal),
          action: THREAT_HASH_AUDIT.removed,
          resourceType: THREAT_HASH_RESOURCE,
          resourceId: row.sha256,
          sourceIp: client.ip,
          metadata: { reason, before: auditImage(row) },
        },
        tx,
      );
    });
    this.logger.log({
      message: 'known-threat hash removed',
      sha256,
      actor: principal.userPublicId,
    });
  }
}

/**
 * The guard already requires the platform permission (stripped from API keys and override
 * sessions); a platform function is only ever run by a platform member (D9).
 */
export function assertPlatformUser(principal: UserPrincipal): void {
  if (principal.organizationKind !== 'platform' || principal.override !== undefined) {
    throw new ForbiddenException();
  }
}
