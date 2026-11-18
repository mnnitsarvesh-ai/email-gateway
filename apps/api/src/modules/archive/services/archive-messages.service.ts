import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  decideExpiry,
  effectiveRetainUntil,
  legalHoldMatches,
  type ScanSnapshot,
} from '@email-gateway/archive';
import {
  BODY_UNAVAILABLE_REASONS,
  type BodyUnavailableReason,
  type QuarantinePreview,
  renderPreview,
} from '@email-gateway/mail-safety';
import { API_CONFIG } from '../../../api-config.token';
import { type AuditEntry, AuditService } from '../../../audit/audit.service';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { TransactionRunner } from '../../../database/transaction-runner';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { NO_ID_MAPS } from '../../bec/domain/bec-result';
import { NO_DLP_IDS } from '../../dlp/domain/dlp-result';
import { roundOf } from '../../messages/domain/message-scans';
import {
  classifyHeader,
  isRevealableHeader,
  maskAddress,
} from '../../messages/domain/sensitive-masking';
import { revealNotRecorded } from '../../messages/messages.errors';
import type {
  AttachmentPartRow,
  AttachmentResultRow,
  AuthResultRow,
  BecResultRow,
  DlpResultRow,
  MessageUrlRow,
  RiskScoreRow,
  SandboxAnalysisRow,
  SandboxArtifactRow,
  SandboxSubmissionRow,
  ScanRoundRow,
  UrlInspectionRow,
  UrlResultRow,
  UrlRewriteRow,
} from '../../messages/repositories/message-scans-read.repository';
import type { EvaluationRow } from '@email-gateway/database';
import {
  ARCHIVE_AUDIT,
  ARCHIVE_OPERATIONS,
  ARCHIVE_PERMISSIONS as P,
  ARCHIVE_RESOURCE,
  ARCHIVE_TX_TIMEOUT_MS,
  type ArchiveConfig,
} from '../archive.constants';
import {
  archiveContentUnavailable,
  archiveDisposeNotAllowed,
  archiveMessageNotFound,
  archivePreviewDisabled,
} from '../archive.errors';
import {
  DETAIL_RECIPIENTS,
  engineRowsOfSnapshot,
  holdFactsOf,
  messageViewOfRecord,
  partiesOf,
  roundsOf,
} from '../domain/archive-views';
import type {
  ArchiveJournalView,
  ArchiveMessageDetailView,
  ArchiveRevealBody,
  ArchiveRevealView,
  ArchiveSecurityView,
  DisposeAccepted,
  DisposeBody,
} from '../dto/archive.schemas';
import { ArchiveConfigRepository } from '../repositories/archive-config.repository';
import {
  ArchiveRecordsRepository,
  type MessageKeyRow,
  type RecordRow,
} from '../repositories/archive-records.repository';
import { parsePublicId, refuseOverride, userIdOf } from './archive-common';
import { ArchiveContentService } from './archive-content.service';
import { effectiveSettings } from './archive-settings.service';

/** Most envelope recipients a reveal returns. */
export const REVEAL_MAX_RECIPIENTS = 1_000;

type Config = Pick<ArchiveConfig, 'ARCHIVE_TEST_DAY_SECONDS'> &
  Pick<ApiConfig, 'QUARANTINE_PREVIEW_MAX_TEXT_CHARS'>;

const isUnavailableReason = (value: string | null): value is BodyUnavailableReason =>
  value !== null && (BODY_UNAVAILABLE_REASONS as readonly string[]).includes(value);

/** The rows of a decoded snapshot as the scans mapper reads them. */
function snapshotRound(snapshot: ScanSnapshot, dlpVisible: boolean) {
  const r = snapshot.rows as unknown as {
    scan: ScanRoundRow | null;
    engines: unknown;
    auth: AuthResultRow[];
    attachments: AttachmentResultRow[];
    attachmentParts: AttachmentPartRow[];
    sandboxSubmissions: SandboxSubmissionRow[];
    sandboxAnalyses: SandboxAnalysisRow[];
    sandboxArtifacts: SandboxArtifactRow[];
    urls: MessageUrlRow[];
    urlResults: UrlResultRow[];
    urlRewrites: UrlRewriteRow[];
    urlInspections: UrlInspectionRow[];
    bec: BecResultRow[];
    dlp: DlpResultRow[];
    risk: RiskScoreRow[];
    policy: EvaluationRow | null;
  };
  if (r.scan === null) return null;
  return roundOf(
    r.scan,
    // Frozen scores are decimal strings (WP3 D2): restored to `Prisma.Decimal` for the mapper.
    engineRowsOfSnapshot(r.engines),
    r.auth,
    {
      results: r.attachments,
      parts: r.attachmentParts,
      submissions: r.sandboxSubmissions,
      analyses: r.sandboxAnalyses,
      artifacts: r.sandboxArtifacts,
    },
    {
      urls: r.urls,
      results: r.urlResults,
      rewrites: r.urlRewrites,
      inspections: r.urlInspections,
      // Live-only (A5): click summaries are not frozen.
      clicks: [],
    },
    // BEC feedback references are live-only; internal ids are not mapped (dropped).
    { results: r.bec, feedback: [], ids: NO_ID_MAPS },
    // DLP: masked view for `dlp:read` holders as live; evidence is not retained in the archive.
    { visible: dlpVisible, results: r.dlp, evidence: [], ids: NO_DLP_IDS },
    r.risk,
    r.policy === null ? [] : [r.policy],
  );
}

/**
 * Archived message reads and the disposal of reviewed records (step 8.1 §4.4 #16–#20, #23; A13,
 * A14, A19, ADR-0062). Metadata (detail) comes from the replica and is audited before it is
 * returned. Every content read (journal, security, reveal of header values, preview) first
 * re-reads the record on the **writer** (status and wrapped DEK: replica lag never serves
 * disposed content, A14) and commits its audit row before decrypting (preview) or before
 * responding. Masking applies to every caller. The preview is customer-only (`403
 * archive_override_forbidden` under a platform override) and needs the tenant switch
 * `access.previewEnabled`.
 */
@Injectable()
export class ArchiveMessagesService {
  private readonly logger = new Logger(ArchiveMessagesService.name);

  constructor(
    @Inject(API_CONFIG) private readonly config: Config,
    private readonly records: ArchiveRecordsRepository,
    private readonly configs: ArchiveConfigRepository,
    private readonly content: ArchiveContentService,
    private readonly audit: AuditService,
    private readonly runner: TransactionRunner,
    private readonly idempotency: IdempotencyService,
  ) {}

  now(): Date {
    return new Date();
  }

  /** The record of a public id on the replica (metadata routes), 404 when unknown or foreign. */
  private async replicaRecord(scope: TenantScope, rawId: unknown): Promise<RecordRow> {
    const id = parsePublicId(rawId, 'messageId');
    const key = await this.records.messageKey(scope, id);
    const record = key === null ? null : await this.records.record(scope, key);
    if (record === null) throw archiveMessageNotFound();
    return record;
  }

  /** The record re-read on the writer for a content route; disposing → `410`. */
  async writerRecord(scope: TenantScope, rawId: unknown): Promise<RecordRow> {
    const id = parsePublicId(rawId, 'messageId');
    const key = await this.records.messageKey(scope, id, 'writer');
    const record = key === null ? null : await this.records.record(scope, key, 'writer');
    if (record === null) throw archiveMessageNotFound();
    if (record.status === 'disposing' || record.wrappedDek === null || record.deletedAt !== null) {
      throw archiveContentUnavailable();
    }
    return record;
  }

  private entry(
    principal: Principal,
    scope: TenantScope,
    action: string,
    messageId: string,
    sourceIp: string | null,
    metadata: Record<string, unknown>,
  ): AuditEntry {
    return {
      organizationId: scope.organizationId,
      actor: this.audit.actorFrom(principal),
      action,
      resourceType: ARCHIVE_RESOURCE.message,
      resourceId: messageId,
      sourceIp,
      metadata: { messageId, ...metadata },
    };
  }

  /** Commits the audit row in its own writer transaction (before content leaves the api). */
  private async commitAudit(entry: AuditEntry): Promise<void> {
    try {
      await this.runner.run((tx) => this.audit.record(entry, tx));
    } catch (error) {
      this.logger.error({ message: 'archive audit write failed: no content returned', err: error });
      throw revealNotRecorded();
    }
  }

  /** `GET /archive/messages/{messageId}` (#16). */
  async detail(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<ArchiveMessageDetailView> {
    const record = await this.replicaRecord(scope, rawId);
    const holdsVisible =
      principal.permissions.has(P.legalHold) || principal.permissions.has(P.ediscovery);
    const [policy, holds] = await Promise.all([
      record.retentionPolicyId === null
        ? Promise.resolve(null)
        : this.records.policyFacts(scope, record.retentionPolicyId),
      holdsVisible ? this.records.activeHolds(scope) : Promise.resolve(null),
    ]);
    const effective = effectiveRetainUntil({
      storedRetainUntil: record.retainUntil,
      receivedAt: record.receivedAt,
      policy:
        policy === null
          ? null
          : { retentionDays: policy.retentionDays, onExpiry: policy.onExpiry, live: policy.live },
      ...(this.config.ARCHIVE_TEST_DAY_SECONDS !== undefined && {
        daySeconds: this.config.ARCHIVE_TEST_DAY_SECONDS,
      }),
    });
    const facts = holdFactsOf(record);
    const matching =
      holds === null
        ? null
        : holds
            .filter((h) =>
              legalHoldMatches(h.criteria, facts, { criteriaVersion: h.criteriaVersion }),
            )
            .map((h) => ({ id: h.publicId, name: h.name, caseId: h.casePublicId }));
    const parties = partiesOf(record);
    await this.commitAudit(
      this.entry(principal, scope, ARCHIVE_AUDIT.messageViewed, record.messagePublicId, sourceIp, {
        status: record.status,
        holdsShown: matching !== null,
      }),
    );
    return {
      ...messageViewOfRecord(record),
      internetMessageId: record.internetMessageId,
      parties: {
        envelopeFrom: record.envelopeFrom,
        headerFrom: record.headerFrom,
        recipients: parties.recipients.slice(0, DETAIL_RECIPIENTS).map((r) => ({
          seq: r.seq,
          address: maskAddress(r.address),
          direction: r.direction,
          status: r.status,
          finalAction: r.finalAction,
        })),
        recipientCount: record.recipientCount,
        recipientsTruncated: parties.recipients.length > DETAIL_RECIPIENTS,
      },
      capture: {
        capturedAt: record.archivedAt.toISOString(),
        sources: {
          journal: record.capturedByJournal,
          policy: record.capturedByPolicy,
          policyRuleRef: record.policyRuleRef,
        },
        messageState: record.messageState,
        messageStateReason: record.messageStateReason,
        settingsGeneration: Number(record.settingsGeneration),
        outcomeRefreshedAt: record.outcomeRefreshedAt?.toISOString() ?? null,
      },
      retention: {
        policyId: policy?.publicId ?? null,
        policyName: policy?.name ?? null,
        retainUntil: record.retainUntil.toISOString(),
        effectiveRetainUntil: effective.toISOString(),
        expiryAction: record.expiryAction,
      },
      holds: matching,
      immutability: {
        lockMode: record.lockMode,
        lockUntil: record.lockUntil?.toISOString() ?? null,
      },
      integrity: {
        sha256: record.sha256,
        sizeBytes: record.sizeBytes,
        storedBytes: Number(record.storedBytes),
        encryptionFormat: record.encryptionFormat,
        keyVersion: record.keyVersion,
      },
      rounds: roundsOf(record),
    };
  }

  /** `GET /archive/messages/{messageId}/journal` (#17). */
  async journal(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<ArchiveJournalView> {
    const record = await this.writerRecord(scope, rawId);
    await this.commitAudit(
      this.entry(
        principal,
        scope,
        ARCHIVE_AUDIT.journalViewed,
        record.messagePublicId,
        sourceIp,
        {},
      ),
    );
    const j = await this.content.journal(scope, record);
    this.content.count('journal', 'ok');
    return {
      messageId: record.messagePublicId,
      captureId: j.captureId,
      capturedAt: j.capturedAt,
      category: j.category,
      message: {
        internetMessageId: j.message.internetMessageId,
        envelopeFrom: j.message.envelopeFrom,
        headerFrom: j.message.headerFrom,
        subject: null,
        subjectMasked: true,
        sizeBytes: j.message.sizeBytes,
        emlSha256: j.message.emlSha256,
        clientIp: j.message.clientIp,
        clientHelo: j.message.clientHelo,
      },
      envelope: {
        recipients: j.envelope.recipients.map((r) => ({
          seq: r.seq,
          address: maskAddress(r.address),
          direction: r.direction,
          status: r.status,
        })),
      },
      headers: j.headers.map((h) =>
        classifyHeader(h.name) === 'safe'
          ? { name: h.name, value: h.value, masked: false }
          : { name: h.name, value: null, masked: true },
      ),
      parse: { status: j.parse.status, codes: [...j.parse.codes] },
      body: {
        textAvailable: j.body.text !== null,
        htmlAvailable: j.body.html !== null,
        truncated: j.body.truncated,
        unavailableReason: j.body.unavailableReason,
      },
      attachments: j.attachments.map((a) => ({
        partIndex: a.partIndex,
        fileName: a.fileName,
        contentType: a.contentType,
        detectedType: a.detectedType,
        sizeBytes: a.sizeBytes,
        sha256: a.sha256,
      })),
      deliveries: j.deliveries.map((d) => ({ seq: d.seq, status: d.status, finalAt: d.finalAt })),
    };
  }

  /** `GET /archive/messages/{messageId}/security` (#18): frozen rounds, mapped like live. */
  async security(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<ArchiveSecurityView> {
    const record = await this.writerRecord(scope, rawId);
    const linked = roundsOf(record);
    await this.commitAudit(
      this.entry(principal, scope, ARCHIVE_AUDIT.securityViewed, record.messagePublicId, sourceIp, {
        rounds: linked.length,
      }),
    );
    const snapshots = await this.content.scanSnapshots(scope, record);
    const dlpVisible = principal.permissions.has(P.dlpRead);
    this.content.count('security', 'ok');
    return {
      messageId: record.messagePublicId,
      rounds: snapshots.flatMap((s) => {
        const view = snapshotRound(s.snapshot, dlpVisible);
        if (view === null) return [];
        return [
          {
            round: s.round,
            revision: s.revision,
            frozenAt: s.snapshot.frozenAt.toISOString(),
            scan: view,
          },
        ];
      }),
      dlpEvidence: 'not_retained',
    };
  }

  /** `POST /archive/messages/{messageId}/reveal` (#19): audited before the response. */
  async reveal(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    body: ArchiveRevealBody,
    sourceIp: string | null,
  ): Promise<ArchiveRevealView> {
    const record = await this.writerRecord(scope, rawId);
    const fields = new Set(body.fields);
    const parties = partiesOf(record);
    const recipients = fields.has('recipients')
      ? parties.recipients
          .slice(0, REVEAL_MAX_RECIPIENTS)
          .map((r) => ({ seq: r.seq, address: r.address }))
      : undefined;
    let headers: Array<{ name: string; value: string }> | undefined;
    if (fields.has('headers')) {
      const journal = await this.content.journal(scope, record);
      headers = journal.headers
        .filter((h) => isRevealableHeader(h.name))
        .map((h) => ({ name: h.name, value: h.value }));
    }
    const revealedAt = this.now();
    await this.commitAudit(
      this.entry(principal, scope, ARCHIVE_AUDIT.revealed, record.messagePublicId, sourceIp, {
        fields: [...body.fields].sort(),
        ...(recipients !== undefined && { recipientCount: recipients.length }),
        ...(headers !== undefined && { headerCount: headers.length }),
      }),
    );
    this.content.count('reveal', 'ok');
    return {
      messageId: record.messagePublicId,
      revealedAt: revealedAt.toISOString(),
      ...(fields.has('subject') && { subject: record.subject }),
      ...(recipients !== undefined && { recipients }),
      ...(headers !== undefined && { headers }),
    };
  }

  /** `GET /archive/messages/{messageId}/preview` (#20): audit committed before decryption. */
  async preview(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    sourceIp: string | null,
  ): Promise<QuarantinePreview> {
    refuseOverride(principal);
    const settings = await this.configs.settingsOnWriter(scope);
    if (!effectiveSettings(settings?.settings ?? null).access.previewEnabled) {
      this.content.count('preview', 'disabled');
      throw archivePreviewDisabled();
    }
    const record = await this.writerRecord(scope, rawId);
    await this.commitAudit(
      this.entry(principal, scope, ARCHIVE_AUDIT.previewed, record.messagePublicId, sourceIp, {
        malicious: record.malicious,
      }),
    );
    const [journal, latest] = await Promise.all([
      this.content.journal(scope, record),
      this.content.scanSnapshots(scope, record, { latestOnly: true }),
    ]);
    const rows = latest[0]?.snapshot.rows as
      { attachments?: AttachmentResultRow[]; urlResults?: UrlResultRow[] } | undefined;
    const attachmentResults = rows?.attachments ?? [];
    const urlVerdicts = (rows?.urlResults ?? []).map((u) => ({
      urlSha256: u.urlSha256,
      verdict: u.verdict,
    }));
    const unavailable = isUnavailableReason(journal.body.unavailableReason)
      ? journal.body.unavailableReason
      : journal.body.text === null && journal.body.html === null
        ? 'no_text_part'
        : null;
    const preview = renderPreview({
      subject: journal.message.subject,
      headers: journal.headers,
      textPart: journal.body.text,
      htmlPart: journal.body.text === null ? journal.body.html : null,
      partsTruncated: journal.body.truncated,
      unavailableReason: unavailable,
      attachments: journal.attachments.map((a) => {
        const result = attachmentResults.find((r) => r.partIndex === a.partIndex);
        return {
          partIndex: a.partIndex,
          filename: a.fileName,
          declaredType: a.contentType,
          detectedType: result?.detectedType ?? a.detectedType,
          typeFamily: result?.typeFamily ?? null,
          sizeBytes: a.sizeBytes,
          sha256: a.sha256,
          verdict: result?.verdict ?? null,
          reasonCodes: Array.isArray(result?.reasonCodes)
            ? (result.reasonCodes as unknown[]).filter((c): c is string => typeof c === 'string')
            : [],
          // Per-attachment downloads are not offered (A19): the original EML contains them.
          downloadable: false,
        };
      }),
      urlVerdicts,
      now: this.now(),
      limits: { maxTextChars: this.config.QUARANTINE_PREVIEW_MAX_TEXT_CHARS },
    });
    this.content.count('preview', 'ok');
    return preview;
  }

  /**
   * `POST /archive/messages/{messageId}/dispose` (#23; A13, A14): only `expiry_review` records;
   * on the writer with the record locked, re-runs the retention and hold rules (1–2 of A13) and,
   * when the record may go, writes the disposal decision exactly like the lifecycle role
   * (crypto-shred + `archive_disposals` + index delete); the worker completes it. `202`.
   */
  async dispose(
    principal: Principal,
    scope: TenantScope,
    rawId: unknown,
    idempotencyKey: unknown,
    body: DisposeBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<DisposeAccepted>> {
    const id = parsePublicId(rawId, 'messageId');
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ARCHIVE_OPERATIONS.dispose;
    return this.idempotency.execute<DisposeAccepted>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: id,
        fingerprint: requestFingerprint({ operation, resourceId: id, body }),
      },
      async (tx) => {
        const message: MessageKeyRow | null = await this.records.messageKey(scope, id, tx);
        if (message === null) throw archiveMessageNotFound();
        // Organization (shared with hold creation), then the record: the holds read below are
        // authoritative against a hold committed concurrently.
        await this.records.lockOrganizationForHolds(tx, scope);
        const record = await this.records.lockRecord(tx, scope, message);
        if (record === null) throw archiveMessageNotFound();
        if (record.status !== 'expiry_review') throw archiveDisposeNotAllowed(record.status);
        const now = this.now();
        const [policy, holds] = await Promise.all([
          record.retentionPolicyId === null
            ? Promise.resolve(null)
            : this.records.policyFacts(scope, record.retentionPolicyId, tx),
          this.records.activeHolds(scope, tx),
        ]);
        const decision = decideExpiry({
          now,
          mode: 'manual_dispose',
          record: {
            receivedAt: record.receivedAt,
            retainUntil: record.retainUntil,
            expiryAction: record.expiryAction,
            lockMode: record.lockMode,
            lockUntil: record.lockUntil,
            status: 'expiry_review',
          },
          policy:
            policy === null
              ? null
              : {
                  retentionDays: policy.retentionDays,
                  onExpiry: policy.onExpiry,
                  live: policy.live,
                },
          holds: holds.map((h) => ({
            id: h.publicId,
            criteria: h.criteria,
            criteriaVersion: h.criteriaVersion,
          })),
          holdFacts: holdFactsOf(record),
          holdExtensionDays: 0,
          reviewExtensionDays: 0,
          ...(this.config.ARCHIVE_TEST_DAY_SECONDS !== undefined && {
            daySeconds: this.config.ARCHIVE_TEST_DAY_SECONDS,
          }),
        });
        if (decision.outcome !== 'disposed') {
          throw archiveDisposeNotAllowed(decision.outcome === 'held' ? 'legal_hold' : 'retention');
        }
        await this.records.writeDisposalDecision(tx, scope, {
          record,
          reason: 'review_disposed',
          requestedByUserId: userIdOf(principal),
          now,
        });
        await this.audit.record(
          this.entry(
            principal,
            scope,
            ARCHIVE_AUDIT.disposalRequested,
            record.messagePublicId,
            sourceIp,
            {
              reason: 'review_disposed',
              justification: body.reason,
              sha256: record.sha256,
            },
          ),
          tx,
        );
        return {
          statusCode: 202,
          body: {
            messageId: record.messagePublicId,
            status: 'disposing',
            disposalRequestedAt: now.toISOString(),
          },
        };
      },
      { timeoutMs: ARCHIVE_TX_TIMEOUT_MS },
    );
  }
}
