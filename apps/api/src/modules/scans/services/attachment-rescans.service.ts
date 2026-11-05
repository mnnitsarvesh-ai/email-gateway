import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import { pageWindow, toPage } from '../../../http/pagination';
import type { ClientContext } from '../../auth/services/session.service';
import {
  RESCAN_STATES,
  type RescanJobCancel,
  type RescanJobCreate,
  type RescanJobCreated,
  type RescanJobEstimate,
  type RescanJobListQuery,
  type RescanJobPage,
  type RescanJobView,
} from '../dto/attachment-rescans.schemas';
import {
  AttachmentRescansRepository,
  type RescanJobRow,
} from '../repositories/attachment-rescans.repository';
import { organizationNotFound, rescanJobNotCancellable, rescanJobNotFound } from '../scans.errors';
import { assertPlatformUser } from './threat-hashes.service';

/** `audit_logs.action` of the job routes (D14 `<resource>.<verb>`). */
export const RESCAN_AUDIT = {
  requested: 'attachment_rescan.requested',
  cancelled: 'attachment_rescan.cancelled',
} as const;
export const RESCAN_RESOURCE = 'attachment_rescan_job';

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

const statesOf = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((s): s is string => typeof s === 'string') : [];

export function rescanJobView(row: RescanJobRow): RescanJobView {
  return {
    jobId: row.publicId,
    trigger: row.trigger,
    status: row.status,
    organizationId: row.organization?.publicId ?? null,
    windowStart: row.windowStart.toISOString(),
    windowEnd: row.windowEnd.toISOString(),
    states: statesOf(row.states),
    component: row.component,
    fromVersion: row.fromVersion,
    toVersion: row.toVersion,
    maxMessages: row.maxMessages,
    selectedCount: row.selectedCount,
    requestedCount: row.requestedCount,
    skippedCount: row.skippedCount,
    requestedByUserId: row.requestedBy?.publicId ?? null,
    reason: row.reason,
    lastError: row.lastError,
    startedAt: iso(row.startedAt),
    completedAt: iso(row.completedAt),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

export type RescanRequestResult =
  { kind: 'estimate'; body: RescanJobEstimate } | { kind: 'created'; body: RescanJobCreated };

/**
 * Bulk attachment rescans requested by a platform administrator (step 4.2 A13). The api only
 * writes and cancels `attachment_rescan_jobs` rows; the email-worker's rescan runner selects the
 * candidates on the writer and moves each through the existing rescan path (E19, new round, every
 * engine). Platform users only (`platform:scan_rescan`, MFA; re-checked here). A dry run counts
 * the candidates with the runner's predicate on the replica and writes nothing; a job and its
 * `attachment_rescan.requested` audit row are written in one writer transaction; a cancel moves
 * `pending|running → cancelled` with its audit row. Parameters only, never content.
 */
@Injectable()
export class AttachmentRescansService {
  private readonly logger = new Logger(AttachmentRescansService.name);
  private readonly maxMessagesCap: number;

  constructor(
    @Inject(API_CONFIG) config: Pick<ApiConfig, 'ATTACHMENT_RESCAN_MAX_MESSAGES'>,
    private readonly repository: AttachmentRescansRepository,
    private readonly transactions: TransactionRunner,
    private readonly audit: AuditService,
  ) {
    this.maxMessagesCap = config.ATTACHMENT_RESCAN_MAX_MESSAGES;
  }

  /** `POST /platform/attachment-rescans`: an estimate (dry run, 200) or a pending job (202). */
  async request(
    principal: UserPrincipal,
    body: RescanJobCreate,
    client: ClientContext,
  ): Promise<RescanRequestResult> {
    assertPlatformUser(principal);
    if (body.maxMessages !== undefined && body.maxMessages > this.maxMessagesCap) {
      throw new BadRequestException([
        `maxMessages: must be at most ATTACHMENT_RESCAN_MAX_MESSAGES (${this.maxMessagesCap})`,
      ]);
    }
    const organization =
      body.organizationId === undefined
        ? null
        : await this.repository.findOrganization(body.organizationId);
    if (body.organizationId !== undefined && organization === null) throw organizationNotFound();
    const windowEnd = new Date();
    const windowStart = new Date(windowEnd.getTime() - body.windowHours * 3_600_000);
    const states = body.states ?? [...RESCAN_STATES];
    const maxMessages = body.maxMessages ?? this.maxMessagesCap;
    const filter = {
      windowStart,
      windowEnd,
      states,
      organizationId: organization?.id ?? null,
    };
    const estimatedMessages = Math.min(await this.repository.countCandidates(filter), maxMessages);
    if (body.dryRun) {
      return {
        kind: 'estimate',
        body: {
          dryRun: true,
          estimatedMessages,
          windowStart: windowStart.toISOString(),
          windowEnd: windowEnd.toISOString(),
          states,
          maxMessages,
        },
      };
    }
    const job = await this.transactions.run(async (tx) => {
      const row = await this.repository.create(tx, {
        ...filter,
        maxMessages,
        reason: body.reason,
        requestedByUserId: principal.userId,
      });
      await this.audit.record(
        {
          organizationId: organization?.id ?? null,
          actor: this.audit.actorFrom(principal),
          action: RESCAN_AUDIT.requested,
          resourceType: RESCAN_RESOURCE,
          resourceId: row.publicId,
          sourceIp: client.ip,
          metadata: {
            jobId: row.publicId,
            windowHours: body.windowHours,
            windowStart: windowStart.toISOString(),
            windowEnd: windowEnd.toISOString(),
            states,
            organizationId: organization?.publicId ?? null,
            maxMessages,
            estimatedMessages,
            reason: body.reason,
          },
        },
        tx,
      );
      return row;
    });
    this.logger.log({
      message: 'attachment rescan job requested',
      jobId: job.publicId,
      windowHours: body.windowHours,
      maxMessages,
      estimatedMessages,
      organizationId: organization?.publicId ?? null,
      actor: principal.userPublicId,
    });
    return {
      kind: 'created',
      body: { jobId: job.publicId, status: 'pending', estimatedMessages },
    };
  }

  /** `GET /platform/attachment-rescans` (replica, newest first). */
  async list(principal: UserPrincipal, query: RescanJobListQuery): Promise<RescanJobPage> {
    assertPlatformUser(principal);
    const rows = await this.repository.list({
      ...pageWindow(query),
      ...(query.status !== undefined && { status: query.status }),
    });
    return toPage(rows, query.limit, rescanJobView);
  }

  /** `GET /platform/attachment-rescans/{jobId}` (replica). */
  async get(principal: UserPrincipal, jobId: string): Promise<RescanJobView> {
    assertPlatformUser(principal);
    const row = await this.repository.find(jobId);
    if (!row) throw rescanJobNotFound();
    return rescanJobView(row);
  }

  /** `POST /platform/attachment-rescans/{jobId}/cancel`: `pending|running → cancelled`. */
  async cancel(
    principal: UserPrincipal,
    jobId: string,
    body: RescanJobCancel,
    client: ClientContext,
  ): Promise<RescanJobView> {
    assertPlatformUser(principal);
    const view = await this.transactions.run(async (tx) => {
      const row = await this.repository.findOnWriter(tx, jobId);
      if (!row) throw rescanJobNotFound();
      if (!(await this.repository.cancel(tx, row.id, new Date()))) {
        const now = await this.repository.findOnWriter(tx, jobId);
        throw rescanJobNotCancellable(now?.status ?? row.status);
      }
      await this.audit.record(
        {
          organizationId: row.organizationId,
          actor: this.audit.actorFrom(principal),
          action: RESCAN_AUDIT.cancelled,
          resourceType: RESCAN_RESOURCE,
          resourceId: row.publicId,
          sourceIp: client.ip,
          metadata: {
            jobId: row.publicId,
            fromStatus: row.status,
            organizationId: row.organization?.publicId ?? null,
            reason: body.reason ?? null,
          },
        },
        tx,
      );
      const after = await this.repository.findOnWriter(tx, jobId);
      return rescanJobView(after ?? row);
    });
    this.logger.log({
      message: 'attachment rescan job cancelled',
      jobId,
      actor: principal.userPublicId,
    });
    return view;
  }
}
