import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import type { DomainStatus, Prisma } from '@email-gateway/database';
import { getCorrelationId } from '@email-gateway/logger';
import { type AuditActor, AuditService } from '../../../audit/audit.service';
import { DOMAIN_RESOURCE_TYPE, type DomainAuditAction } from '../domains.constants';
import { DomainOutboxRepository } from '../repositories/domain-outbox.repository';

type Client = Prisma.TransactionClient;

export interface DomainRef {
  id: bigint;
  publicId: string;
  name: string;
}

export interface DomainTransitionRecord {
  organizationId: bigint;
  domain: DomainRef;
  from: DomainStatus | null;
  to: DomainStatus;
  reason: string | null;
  action: DomainAuditAction;
  actor: AuditActor;
  sourceIp?: string | null;
  /** Extra audit metadata (never keys, tokens or evidence, D15). */
  metadata?: Record<string, unknown>;
  at: Date;
}

export interface DomainAuditRecord {
  organizationId: bigint;
  domain: Pick<DomainRef, 'publicId' | 'name'>;
  action: DomainAuditAction;
  actor: AuditActor;
  sourceIp?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Audit rows and `domain.status.changed.v1` outbox events of the domains module (D15), always
 * in the caller's transaction so they commit with the change they describe. Events are written
 * only for status transitions, never per check, so repeating a check is idempotent.
 */
@Injectable()
export class DomainEventsService {
  constructor(
    private readonly audit: AuditService,
    private readonly outbox: DomainOutboxRepository,
  ) {}

  /** One audit row (`from`, `to`, `reason` + metadata) and one event for a status transition. */
  async transition(tx: Client, record: DomainTransitionRecord): Promise<void> {
    await this.record(tx, {
      organizationId: record.organizationId,
      domain: record.domain,
      action: record.action,
      actor: record.actor,
      sourceIp: record.sourceIp ?? null,
      metadata: {
        ...record.metadata,
        from: record.from,
        to: record.to,
        reason: record.reason,
      },
    });
    await this.outbox.insertStatusChanged(tx, {
      organizationId: record.organizationId,
      correlationId: getCorrelationId() ?? `domain:${randomUUID()}`,
      payload: {
        domainId: record.domain.id.toString(10),
        domainPublicId: record.domain.publicId,
        name: record.domain.name,
        previousStatus: record.from,
        status: record.to,
        reason: record.reason,
        changedAt: record.at.toISOString(),
      },
    });
  }

  /** An audit row without a status change (creation, DKIM activity, ownership warnings). */
  async record(tx: Client, record: DomainAuditRecord): Promise<void> {
    await this.audit.record(
      {
        organizationId: record.organizationId,
        actor: record.actor,
        action: record.action,
        resourceType: DOMAIN_RESOURCE_TYPE,
        resourceId: record.domain.publicId,
        sourceIp: record.sourceIp ?? null,
        metadata: { name: record.domain.name, ...record.metadata },
      },
      tx,
    );
  }
}
