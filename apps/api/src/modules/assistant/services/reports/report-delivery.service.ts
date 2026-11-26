import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  type AssistantCard,
  CARD_VERSION,
  classifyRecipient,
  type NativeImpactSnapshot,
  normalizeRecipient,
  type OperationTool,
  type RecipientKind,
  recipientDomainOf,
  recipientSha256,
  reportPortalHref,
  reportStateDigest,
  type ToolResultOk,
} from '@email-gateway/assistant';
import { uuidv7 } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../../api-config.token';
import { AuditService } from '../../../../audit/audit.service';
import type { UserPrincipal } from '../../../../auth-contracts/principal';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  utcDayStart,
} from '../../assistant.constants';
import {
  ASSISTANT_ERROR_CODES,
  REPORT_ERROR_CODES,
  REPORT_GUARD_MESSAGES,
  REPORT_GUARDS,
} from '../../assistant.errors';
import { nativeRequestOf, type StoredRequest } from '../../domain/confirmation-binding';
import type { Owner } from '../../repositories/conversations.repository';
import { RecipientDirectoryRepository } from '../../repositories/recipient-directory.repository';
import { ReportDeliveriesRepository } from '../../repositories/report-deliveries.repository';
import { type ReportRow, ReportsRepository } from '../../repositories/reports.repository';
import { AssistantMetrics } from '../assistant-metrics';
import type { NativeDenial, NativeFailure } from './report-generator.service';

type Tx = Prisma.TransactionClient;

/** The owner facts of a native call (from the authenticated principal, never from input). */
export interface DeliveryActor {
  principal: UserPrincipal;
  owner: Owner;
  conversationId: bigint;
}

/** A prepared `report_send_email` proposal (design 31 D5 steps 1–5). */
export interface PreparedDelivery {
  kind: 'ready';
  finalArgs: { reportId: string; to: string };
  request: StoredRequest;
  stateDigest: string;
  native: NativeImpactSnapshot;
}

export type DeliveryProposal =
  | NativeDenial
  | { kind: 'failed_own'; failure: { httpStatus: number; code: string; message: string } }
  | PreparedDelivery;

/** The confirm-time state (D5 step 12). */
export type DeliveryState =
  | { kind: 'state'; stateDigest: string }
  /** The recipient is not allowed any more (`403 assistant_action_not_allowed`). */
  | { kind: 'refused' };

/** The outcome of a confirmed send inside the execution's transaction (D5 step 13). */
export type DeliveryExecution =
  | {
      kind: 'queued';
      httpStatus: 202;
      deliveryId: string;
      reportId: string;
      to: string;
      card: (executionId: string) => AssistantCard;
      envelope: (seq: number) => ToolResultOk;
    }
  | NativeFailure;

export interface DeliveryExecuteOptions {
  executionId: string;
  correlationId: string;
  /** The confirmation row (unique `confirmation_id` of the delivery). */
  confirmationRowId: bigint;
  confirmationPublicId: string;
}

interface Recipient {
  address: string;
  kind: RecipientKind | null;
  domain: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const reportIdArg = (args: Readonly<Record<string, unknown>>): string | null =>
  typeof args.reportId === 'string' && UUID.test(args.reportId)
    ? args.reportId.toLowerCase()
    : null;

/** The period label stored with the row (`sections.label`), else the stored window. */
function periodLabelOf(row: ReportRow): string {
  const sections = row.sections as { label?: unknown } | null;
  return typeof sections?.label === 'string'
    ? sections.label
    : `${row.periodFrom.toISOString()} to ${row.periodTo.toISOString()}`;
}

/**
 * `report_send_email` (step AI-R D5, invariant I17; ADR-0093 amendment AI-R): the proposal's
 * report resolution, the recipient rule (own address, active verified users of the scope's
 * organization, addresses of its `verified`/`active` domains; anything else refused before any
 * confirmation exists), the per-user and per-tenant daily limits and the bound state digest; the
 * confirm-time re-check of that state; and the confirmed send in the execution's transaction:
 * the tenant's `ai_chat_settings` row lock, the exact recount, the delivery row, its outbox
 * event (ids only) and the `assistant.report_email_requested` audit. Refused addresses are never
 * stored, logged or audited (their domain and SHA-256 only).
 */
@Injectable()
export class ReportDeliveryService {
  private readonly logger = new Logger(ReportDeliveryService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly reports: ReportsRepository,
    private readonly deliveries: ReportDeliveriesRepository,
    private readonly directory: RecipientDirectoryRepository,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
  ) {}

  now(): Date {
    return new Date();
  }

  /** D5 steps 1–5 (nothing stored; the proposer stores the confirmation). */
  async prepareProposal(
    actor: DeliveryActor,
    tool: OperationTool,
    args: Readonly<Record<string, unknown>>,
  ): Promise<DeliveryProposal> {
    const { principal, owner } = actor;
    // 1. The report: this owner's, in this conversation; latest available by default.
    const requested = args.reportId === undefined ? null : reportIdArg(args);
    if (args.reportId !== undefined && requested === null) {
      return this.ownFailure(
        404,
        REPORT_ERROR_CODES.notFound,
        'There is no such report in this conversation.',
      );
    }
    const report = await this.reports.findForConversation(
      owner,
      principal.override?.id ?? null,
      actor.conversationId,
      requested,
    );
    const refused = this.reportRefusal(report);
    if (refused) return refused;
    const row = report!;

    // 2. The recipient rule (own address by default).
    const recipient = await this.classify(actor, args.to);
    if (recipient === null) {
      return {
        kind: 'denied',
        decision: 'denied_schema',
        message:
          'The arguments do not match the tool’s input schema. to must be one plain email address.',
      };
    }
    if (recipient.kind === null) {
      this.metrics.reportEmails.inc({ outcome: 'refused_recipient' });
      this.logger.log({ message: 'Assistant report recipient refused', reportId: row.publicId });
      return {
        kind: 'denied',
        decision: 'denied_guard',
        guard: REPORT_GUARDS.recipientNotAllowed,
        message: REPORT_GUARD_MESSAGES.report_recipient_not_allowed,
        auditExtra: {
          recipientDomain: recipient.domain,
          recipientSha256: recipientSha256(recipient.address),
        },
        redact: ['to'],
      };
    }

    // 3. The daily limits (pending confirmations reserve nothing; re-checked at confirm).
    const since = utcDayStart(this.now());
    const organizationId = owner.scope.organizationId;
    const userCount = await this.deliveries.countUserSince(organizationId, owner.userId, since);
    const tenantCount = await this.deliveries.countTenantSince(organizationId, since);
    const limit = this.limitReached(userCount, tenantCount);
    if (limit) {
      this.metrics.reportEmails.inc({ outcome: 'limit' });
      return {
        kind: 'denied',
        decision: 'denied_budget',
        code: REPORT_ERROR_CODES.emailLimit,
        message: limit.message,
        auditExtra: { scope: limit.scope },
      };
    }

    // 4. The stored request and the bound state.
    const finalArgs = { reportId: row.publicId, to: recipient.address };
    const userLimit = this.config.ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY;
    const tenantLimit = this.config.ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY;
    return {
      kind: 'ready',
      finalArgs,
      request: nativeRequestOf(tool, finalArgs),
      stateDigest: reportStateDigest({
        reportId: row.publicId,
        sha256: row.sha256!,
        status: 'available',
        recipientKind: recipient.kind,
      }),
      native: {
        report: { title: row.title, period: periodLabelOf(row), sizeBytes: row.sizeBytes ?? 0 },
        recipient: { address: recipient.address, kind: recipient.kind, domain: recipient.domain },
        limits: {
          userRemaining: Math.max(0, userLimit - userCount),
          userLimit,
          tenantRemaining: Math.max(0, tenantLimit - tenantCount),
          tenantLimit,
        },
      },
    };
  }

  /**
   * D5 step 12: the state with current data. A recipient no longer allowed is `refused`; any other
   * difference (report purged, replaced or gone, recipient of another class) changes the digest.
   */
  async readState(
    actor: DeliveryActor,
    args: Readonly<Record<string, unknown>>,
  ): Promise<DeliveryState> {
    const requested = reportIdArg(args);
    const report =
      requested === null
        ? null
        : await this.reports.findForConversation(
            actor.owner,
            actor.principal.override?.id ?? null,
            actor.conversationId,
            requested,
          );
    const recipient = await this.classify(actor, args.to);
    if (recipient === null || recipient.kind === null) return { kind: 'refused' };
    return {
      kind: 'state',
      stateDigest: reportStateDigest({
        reportId: report?.publicId ?? requested ?? 'missing',
        sha256: report?.sha256 ?? 'missing',
        status: report === null ? 'missing' : report.status,
        recipientKind: recipient.kind,
      }),
    };
  }

  /**
   * D5 step 13, inside the execution's persist transaction: the tenant's settings row lock
   * (serializes the organization's sends), the report and recipient once more, the exact UTC-day
   * recount (limit → `429`, nothing written), then the delivery, its outbox event and the audit.
   */
  async execute(
    actor: DeliveryActor & { clientIp: string | null },
    args: Readonly<Record<string, unknown>>,
    options: DeliveryExecuteOptions,
    tx: Tx,
  ): Promise<DeliveryExecution> {
    const { principal, owner } = actor;
    const organizationId = owner.scope.organizationId;
    if (!(await this.deliveries.lockTenant(organizationId, tx))) {
      return this.failed(
        403,
        ASSISTANT_ERROR_CODES.tenantDisabled,
        'The AI assistant is turned off in the organization settings.',
      );
    }
    const requested = reportIdArg(args);
    const report =
      requested === null
        ? null
        : await this.reports.findForConversation(
            owner,
            principal.override?.id ?? null,
            actor.conversationId,
            requested,
            tx,
          );
    if (report === null || report.status !== 'available' || report.sha256 === null) {
      this.metrics.reportEmails.inc({ outcome: 'failed' });
      return report?.status === 'purged'
        ? this.failed(
            410,
            REPORT_ERROR_CODES.purged,
            'This report was deleted with the conversation content.',
          )
        : this.failed(
            404,
            REPORT_ERROR_CODES.notFound,
            'There is no such report in this conversation.',
          );
    }
    const recipient = await this.classify(actor, args.to, tx);
    if (recipient === null || recipient.kind === null) {
      this.metrics.reportEmails.inc({ outcome: 'refused_recipient' });
      return this.failed(
        403,
        ASSISTANT_ERROR_CODES.actionNotAllowed,
        REPORT_GUARD_MESSAGES.report_recipient_not_allowed,
      );
    }
    const now = this.now();
    const since = utcDayStart(now);
    const userCount = await this.deliveries.countUserSince(organizationId, owner.userId, since, tx);
    const tenantCount = await this.deliveries.countTenantSince(organizationId, since, tx);
    const limit = this.limitReached(userCount, tenantCount);
    if (limit) {
      this.metrics.reportEmails.inc({ outcome: 'limit' });
      return {
        ...this.failed(429, REPORT_ERROR_CODES.emailLimit, limit.message),
        details: { scope: limit.scope, limit: limit.limit },
      };
    }

    const deliveryId = uuidv7(now.getTime());
    const sha = recipientSha256(recipient.address);
    const delivery = await this.deliveries.insert(
      {
        publicId: deliveryId,
        organizationId,
        userId: owner.userId,
        conversationId: actor.conversationId,
        reportId: report.id,
        confirmationId: options.confirmationRowId,
        recipientAddress: recipient.address,
        recipientSha256: sha,
        recipientKind: recipient.kind,
        sizeBytes: report.sizeBytes ?? 0,
        correlationId: options.correlationId.slice(0, 128),
        requestedAt: now,
      },
      tx,
    );
    // The outbox event (ids only; eventId = aggregateId = the delivery public id).
    await this.deliveries.insertEmailRequested(tx, {
      organizationId,
      correlationId: options.correlationId,
      payload: {
        deliveryId: delivery.publicId,
        reportId: report.publicId,
        requestedAt: now.toISOString(),
      },
    });
    await this.audit.record(
      {
        organizationId,
        actor: this.audit.actorFrom(principal),
        action: ASSISTANT_AUDIT.reportEmailRequested,
        resourceType: AUDIT_RESOURCE.delivery,
        resourceId: delivery.publicId,
        sourceIp: actor.clientIp,
        metadata: {
          deliveryId: delivery.publicId,
          reportId: report.publicId,
          confirmationId: options.confirmationPublicId,
          executionId: options.executionId,
          recipientKind: recipient.kind,
          recipientDomain: recipient.domain,
          recipientSha256: sha,
          correlationId: options.correlationId,
        },
      },
      tx,
    );
    this.metrics.reportEmails.inc({ outcome: 'queued' });
    this.logger.log({
      message: 'Assistant report email queued',
      deliveryId: delivery.publicId,
      reportId: report.publicId,
      confirmationId: options.confirmationPublicId,
    });
    const to = recipient.address;
    const reportId = report.publicId;
    const href = reportPortalHref(reportId);
    return {
      kind: 'queued',
      httpStatus: 202,
      deliveryId: delivery.publicId,
      reportId,
      to,
      card: (executionId) => ({
        version: CARD_VERSION,
        executionId,
        tool: 'report_send_email',
        title: 'Email security report',
        status: 'ok',
        kind: 'message',
        message: `Report email queued to ${to}`,
        portalLinks: href ? [{ label: 'report', href }] : [],
        refs: [],
      }),
      envelope: (seq) => ({
        kind: 'tool_result/1',
        tool: 'report_send_email',
        status: 'ok',
        httpStatus: 202,
        ref: `r${seq}`,
        returned: 1,
        hasMore: false,
        truncated: false,
        note: 'The report email was queued; the notification mailer sends it shortly.',
        data: { deliveryId: delivery.publicId, reportId, to, status: 'queued' },
      }),
    };
  }

  /** The proposal refusal of a missing, purged, unfinished or oversize report (D5 step 1). */
  private reportRefusal(report: ReportRow | null): DeliveryProposal | null {
    if (report === null) {
      return this.ownFailure(
        404,
        REPORT_ERROR_CODES.notFound,
        'There is no such report in this conversation; generate one first.',
      );
    }
    if (report.status === 'purged') {
      return this.ownFailure(
        410,
        REPORT_ERROR_CODES.purged,
        'This report was deleted with the conversation content.',
      );
    }
    // Step AI-6 D5: a background report that is still being generated.
    if (report.status === 'queued' || report.status === 'pending') {
      return this.ownFailure(
        409,
        REPORT_ERROR_CODES.notReady,
        'This report is still being generated; email it when it is ready.',
      );
    }
    if (report.status !== 'available' || report.sha256 === null || report.sizeBytes === null) {
      return this.ownFailure(
        404,
        REPORT_ERROR_CODES.notFound,
        'This report is not available; generate a new one.',
      );
    }
    if (report.sizeBytes > this.config.ASSISTANT_REPORT_MAX_HTML_BYTES) {
      return this.ownFailure(
        413,
        REPORT_ERROR_CODES.tooLarge,
        'This report is too large to email.',
      );
    }
    return null;
  }

  /**
   * The normalized recipient and its class (null class: refused); null when `to` is not one
   * plain address. Lookups on the writer, scoped to the scope's organization.
   */
  private async classify(actor: DeliveryActor, to: unknown, tx?: Tx): Promise<Recipient | null> {
    const selfEmail = await this.directory.selfEmail(actor.principal.userId, tx);
    const raw = to === undefined || to === null ? selfEmail : to;
    if (raw === null) {
      // No verified own address: nothing to send to (refused like any other recipient).
      return { address: '', kind: null, domain: '' };
    }
    const address = normalizeRecipient(raw);
    if (address === null) return null;
    const domain = recipientDomainOf(address);
    const member = await this.directory.isActiveMember(actor.owner.scope, address, tx);
    const verifiedDomains = await this.directory.verifiedDomains(actor.owner.scope, [domain], tx);
    const kind = classifyRecipient(address, {
      selfEmail,
      isActiveMember: (candidate) => member && candidate.toLowerCase() === address.toLowerCase(),
      verifiedDomains,
    });
    return { address, kind, domain };
  }

  private limitReached(
    userCount: number,
    tenantCount: number,
  ): { scope: 'user' | 'tenant'; limit: number; message: string } | null {
    const userLimit = this.config.ASSISTANT_REPORT_EMAILS_PER_USER_PER_DAY;
    const tenantLimit = this.config.ASSISTANT_REPORT_EMAILS_PER_TENANT_PER_DAY;
    if (userCount >= userLimit) {
      return {
        scope: 'user',
        limit: userLimit,
        message: `You sent the maximum of ${userLimit} report emails for today (UTC).`,
      };
    }
    if (tenantCount >= tenantLimit) {
      return {
        scope: 'tenant',
        limit: tenantLimit,
        message: `Your organization sent the maximum of ${tenantLimit} report emails for today (UTC).`,
      };
    }
    return null;
  }

  private ownFailure(httpStatus: number, code: string, message: string): DeliveryProposal {
    this.metrics.reportEmails.inc({ outcome: 'failed' });
    return { kind: 'failed_own', failure: { httpStatus, code, message } };
  }

  private failed(httpStatus: number, code: string, message: string): NativeFailure {
    return {
      kind: 'failed',
      status: 'failed',
      httpStatus,
      recordedStatus: httpStatus,
      code,
      message,
    };
  }
}
