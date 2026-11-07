import { createHash } from 'node:crypto';
import { HttpException, Inject, Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import { DlpEvidenceCryptoError, openEvidence } from '@email-gateway/dlp';
import {
  DLP_EVIDENCE_ALGORITHM,
  dlpEvidenceDocumentSchema,
} from '@email-gateway/security-contracts';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedHttpException } from '../../../http/coded-exception';
import type { ClientContext } from '../../auth/services/session.service';
import { messageNotFound } from '../../messages/messages.errors';
import {
  DLP_EVIDENCE_NOT_FOUND,
  dlpEvidenceNotFound,
  dlpScanNotFound,
  EVIDENCE_EXPIRED,
  EVIDENCE_PURGED,
  evidenceExpired,
  evidencePurged,
  evidenceUnavailable,
  evidenceUnreadable,
} from '../dlp.errors';
import type { DlpEvidencePurged, DlpEvidenceResponse } from '../dto/dlp.schemas';
import {
  DlpResultsRepository,
  type EvidenceMessage,
  type EvidenceRow,
} from '../repositories/dlp-results.repository';
import { DlpEvidenceStore, EvidenceObjectError } from './dlp-evidence-store';
import { DlpAuditor } from './dlp-views';
import {
  DLP_AUDIT,
  DLP_RESOURCE,
  DlpMetrics,
  DlpWriter,
  type EvidenceReadResult,
} from './dlp-writer';

type Keys = { DLP_EVIDENCE_KEY: string; DLP_EVIDENCE_KEY_PREVIOUS?: string };

/** Rows one tenant purge transaction shreds (D16: batches of 500). */
export const EVIDENCE_PURGE_BATCH = 500;

/** Why an evidence read failed after its audit row (`dlp_evidence.read_failed`, reason only). */
export type EvidenceReadFailure =
  | 'object_missing'
  | 'object_key'
  | 'object_size'
  | 'integrity'
  | 'algorithm'
  | 'decrypt'
  | 'document_invalid'
  | 'storage_error';

class EvidenceReadError extends Error {
  constructor(readonly reason: EvidenceReadFailure) {
    super(`evidence read failed (${reason})`);
    this.name = 'EvidenceReadError';
  }
}

const RESULT_OF_CODE: Record<string, EvidenceReadResult> = {
  [DLP_EVIDENCE_NOT_FOUND]: 'not_found',
  [EVIDENCE_PURGED]: 'purged',
  [EVIDENCE_EXPIRED]: 'expired',
};

/**
 * The single audited door to decrypted DLP evidence (step 4.5 §2.0 invariant 3, D16) and the
 * tenant purge (crypto-shredding).
 *
 * Read (`dlp:evidence_read`, MFA-authenticated users only): (1) a writer transaction reads the
 * message, the scan and the round's evidence row tenant-scoped and echo-checked (another
 * organization's ids → 404; purged → `410 evidence_purged`; past `expires_at` →
 * `410 evidence_expired`) and **commits the `dlp_evidence.read` audit row before any byte is
 * fetched or decrypted**; (2) the object is read from S3 only under `org/<org>/dlp-evidence/`,
 * its SHA-256 and size compared with the row, the data key unwrapped with `DLP_EVIDENCE_KEY`
 * (`_PREVIOUS` during a rotation), the payload decrypted with the row-bound AAD and the JSON
 * validated with `dlpEvidenceDocumentSchema`. Any failure after the audit row writes
 * `dlp_evidence.read_failed` (a reason, never content) in its own transaction. The response is
 * never logged; the controller sends it with `Cache-Control: no-store`.
 *
 * Purge (`dlp:manage`, MFA): crypto-shred first (`wrapped_key` NULL, `purged_at`,
 * `purge_reason = tenant_request`, audited `dlp_evidence.purged` in the same transaction), then
 * delete the object and clear `object_key` only after the delete succeeded (a failed delete is
 * retried by the next purge; the object is undecryptable already).
 */
@Injectable()
export class DlpEvidenceService {
  private readonly logger = new Logger(DlpEvidenceService.name);

  constructor(
    @Inject(API_CONFIG) private readonly keys: Keys,
    private readonly repository: DlpResultsRepository,
    private readonly store: DlpEvidenceStore,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
    private readonly metrics: DlpMetrics,
  ) {}

  async read(
    principal: UserPrincipal,
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    client: ClientContext,
  ): Promise<DlpEvidenceResponse> {
    const now = new Date();
    let target: { message: EvidenceMessage; evidence: EvidenceRow };
    try {
      // (1) Access decision and the audit row, committed before anything is fetched.
      target = await this.writer.run(async (tx) => {
        const { message, evidence } = await this.locate(tx, scope, messageId, scanId, false);
        if (
          evidence.purgedAt !== null ||
          evidence.wrappedKey === null ||
          evidence.objectKey === null
        ) {
          throw evidencePurged();
        }
        if (evidence.expiresAt.getTime() <= now.getTime()) throw evidenceExpired();
        await this.auditor.record(tx, {
          principal,
          scope,
          client,
          action: DLP_AUDIT.evidenceRead,
          resourceType: DLP_RESOURCE.evidence,
          resourceId: message.publicId,
          metadata: {
            messageId: message.publicId,
            scanId: scanId.toString(),
            matchCount: evidence.matchCount,
          },
        });
        return { message, evidence };
      });
    } catch (error) {
      const code = error instanceof CodedHttpException ? error.code : null;
      if (code !== null && code in RESULT_OF_CODE) {
        this.metrics.evidenceReads.inc({ result: RESULT_OF_CODE[code]! });
      } else if (error instanceof HttpException && error.getStatus() === 404) {
        this.metrics.evidenceReads.inc({ result: 'not_found' });
      }
      throw error;
    }
    // (2) Fetch, verify, decrypt, validate.
    try {
      const evidence = await this.open(scope, target.message, target.evidence, scanId);
      this.metrics.evidenceReads.inc({ result: 'ok' });
      this.logger.log({
        message: 'dlp evidence read',
        organizationId: scope.organizationId.toString(),
        messageId: target.message.publicId,
        scanId: scanId.toString(),
        matchCount: target.evidence.matchCount,
      });
      return {
        messageId: target.message.publicId,
        scanId: scanId.toString(),
        matchCount: target.evidence.matchCount,
        expiresAt: target.evidence.expiresAt.toISOString(),
        evidence,
      };
    } catch (error) {
      const reason = this.failureOf(error);
      this.metrics.evidenceReads.inc({
        result: reason === 'storage_error' ? 'unavailable' : 'failed',
      });
      await this.recordFailure(principal, scope, client, target.message, scanId, reason);
      throw reason === 'storage_error' ? evidenceUnavailable() : evidenceUnreadable();
    }
  }

  /** `DELETE /messages/{messageId}/scans/{scanId}/dlp-evidence`: crypto-shred, then delete. */
  async purgeOne(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    client: ClientContext,
  ): Promise<void> {
    const now = new Date();
    const evidence = await this.writer.run(async (tx) => {
      const { message, evidence: row } = await this.locate(tx, scope, messageId, scanId, true);
      if (row.purgedAt === null) {
        await this.repository.shred(tx, scope, [row], 'tenant_request', now);
        await this.auditor.record(tx, {
          principal,
          scope,
          client,
          action: DLP_AUDIT.evidencePurged,
          resourceType: DLP_RESOURCE.evidence,
          resourceId: message.publicId,
          metadata: {
            messageId: message.publicId,
            scanId: scanId.toString(),
            purged: 1,
            reason: 'tenant_request',
          },
        });
      }
      return row;
    });
    const deleted = await this.deleteObject(scope, evidence);
    this.logger.log({
      message: 'dlp evidence purged',
      organizationId: scope.organizationId.toString(),
      scanId: scanId.toString(),
      objectDeleted: deleted,
    });
  }

  /**
   * `DELETE /dlp/evidence`: every evidence of the organization, in batches of 500 (shred in a
   * transaction, then delete the objects), answered after completion with the counts. The audit
   * row (`dlp_evidence.purged`, the total) is written in the last batch's transaction.
   */
  async purgeAll(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
  ): Promise<DlpEvidencePurged> {
    const totals = { purged: 0, objectsDeleted: 0, objectsPending: 0 };
    let afterId = 0n;
    let batches = 0;
    for (;;) {
      const now = new Date();
      const { rows, shredded } = await this.writer.run(async (tx) => {
        const batch = await this.repository.purgeBatch(tx, scope, afterId, EVIDENCE_PURGE_BATCH);
        const count = await this.repository.shred(
          tx,
          scope,
          batch.filter((row) => row.purgedAt === null),
          'tenant_request',
          now,
        );
        if (batch.length < EVIDENCE_PURGE_BATCH) {
          await this.auditor.record(tx, {
            principal,
            scope,
            client,
            action: DLP_AUDIT.evidencePurged,
            resourceType: DLP_RESOURCE.evidence,
            resourceId: null,
            metadata: {
              purged: totals.purged + count,
              batches: batches + 1,
              reason: 'tenant_request',
              scope: 'organization',
            },
          });
        }
        return { rows: batch, shredded: count };
      });
      totals.purged += shredded;
      batches += 1;
      for (const row of rows) {
        if (await this.deleteObject(scope, row)) totals.objectsDeleted += 1;
        else if (row.objectKey !== null) totals.objectsPending += 1;
      }
      if (rows.length < EVIDENCE_PURGE_BATCH) break;
      afterId = rows[rows.length - 1]!.id;
    }
    this.logger.log({
      message: 'dlp evidence of the organization purged',
      organizationId: scope.organizationId.toString(),
      ...totals,
      batches,
    });
    return totals;
  }

  /** Message → scan → the round's evidence row, tenant-scoped (404s never confirm existence). */
  private async locate(
    tx: Prisma.TransactionClient,
    scope: TenantScope,
    messageId: string,
    scanId: bigint,
    lock: boolean,
  ): Promise<{ message: EvidenceMessage; evidence: EvidenceRow }> {
    const message = await this.repository.findMessage(tx, scope, messageId);
    if (!message) throw messageNotFound();
    if (!(await this.repository.scanExists(tx, scope, message, scanId))) throw dlpScanNotFound();
    const evidence = await this.repository.evidenceOf(tx, scope, message, scanId, lock);
    if (!evidence) throw dlpEvidenceNotFound();
    return { message, evidence };
  }

  private async open(
    scope: TenantScope,
    message: EvidenceMessage,
    row: EvidenceRow,
    scanId: bigint,
  ): Promise<DlpEvidenceResponse['evidence']> {
    if (row.algorithm !== DLP_EVIDENCE_ALGORITHM) throw new EvidenceReadError('algorithm');
    const object = await this.store.read(scope.organizationId, row.objectKey!);
    if (object.length !== row.objectSizeBytes) throw new EvidenceReadError('object_size');
    const sha256 = createHash('sha256').update(object).digest('hex');
    if (sha256 !== row.objectSha256.toLowerCase()) throw new EvidenceReadError('integrity');
    const opened = openEvidence(
      {
        current: this.keys.DLP_EVIDENCE_KEY,
        previous: this.keys.DLP_EVIDENCE_KEY_PREVIOUS ?? null,
      },
      object,
      row.wrappedKey!,
      {
        organizationId: scope.organizationId.toString(),
        messageId: message.id.toString(),
        scanId: scanId.toString(),
      },
    );
    try {
      let json: unknown;
      try {
        json = JSON.parse(opened.plaintext.toString('utf8'));
      } catch {
        throw new EvidenceReadError('document_invalid');
      }
      const parsed = dlpEvidenceDocumentSchema.safeParse(json);
      if (!parsed.success) throw new EvidenceReadError('document_invalid');
      return parsed.data;
    } finally {
      opened.plaintext.fill(0);
    }
  }

  private failureOf(error: unknown): EvidenceReadFailure {
    if (error instanceof EvidenceReadError) return error.reason;
    if (error instanceof DlpEvidenceCryptoError) return 'decrypt';
    if (error instanceof EvidenceObjectError) {
      if (error.why === 'not_found') return 'object_missing';
      if (error.why === 'foreign_key') return 'object_key';
      if (error.why === 'too_large') return 'object_size';
      return 'storage_error';
    }
    return 'storage_error';
  }

  /** `dlp_evidence.read_failed` in its own transaction (the read row is already committed). */
  private async recordFailure(
    principal: Principal,
    scope: TenantScope,
    client: ClientContext,
    message: EvidenceMessage,
    scanId: bigint,
    reason: EvidenceReadFailure,
  ): Promise<void> {
    try {
      await this.writer.run((tx) =>
        this.auditor.record(tx, {
          principal,
          scope,
          client,
          action: DLP_AUDIT.evidenceReadFailed,
          resourceType: DLP_RESOURCE.evidence,
          resourceId: message.publicId,
          metadata: { messageId: message.publicId, scanId: scanId.toString(), reason },
        }),
      );
    } catch (error) {
      this.logger.warn({
        message: 'dlp evidence read_failed audit row not written',
        organizationId: scope.organizationId.toString(),
        scanId: scanId.toString(),
        reason,
        errorName: error instanceof Error ? error.name : typeof error,
      });
    }
    this.logger.warn({
      message: 'dlp evidence read failed',
      organizationId: scope.organizationId.toString(),
      scanId: scanId.toString(),
      reason,
    });
  }

  /** Deletes the row's object (if any) and clears `object_key`; false when it failed. */
  private async deleteObject(scope: TenantScope, row: EvidenceRow): Promise<boolean> {
    if (row.objectKey === null) return false;
    try {
      await this.store.delete(scope.organizationId, row.objectKey);
      await this.repository.clearObjectKey(scope, row);
      return true;
    } catch (error) {
      this.logger.warn({
        message: 'dlp evidence object not deleted (undecryptable; retried by the next purge)',
        organizationId: scope.organizationId.toString(),
        scanId: row.scanId.toString(),
        errorName: error instanceof Error ? error.name : typeof error,
      });
      return false;
    }
  }
}
