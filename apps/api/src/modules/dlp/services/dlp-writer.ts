import { Injectable, Logger } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { Principal } from '../../../auth-contracts/principal';
import { TransactionRunner } from '../../../database/transaction-runner';
import { InconsistentDlpReadError, inconsistentRead } from '../dlp.errors';

/**
 * Budget of every DLP write and of the evidence-read audit (step 4.5 §6, the 4.2 §6
 * mitigation): an interactive transaction is never abandoned by a short timeout; 120 s budget,
 * 10 s to obtain a connection.
 */
export const DLP_TX = { timeoutMs: 120_000, maxWaitMs: 10_000 } as const;

/**
 * `audit_logs.action` of the DLP changes and evidence access (D21 `<resource>.<verb>`). Audit
 * metadata never holds a test sample, a dictionary term (counts only) or an evidence value, and
 * no key matching `/code/i` (AuditService.scrubMetadata drops those).
 */
export const DLP_AUDIT = {
  policyCreated: 'dlp_policy.created',
  policyUpdated: 'dlp_policy.updated',
  policyDeleted: 'dlp_policy.deleted',
  ruleCreated: 'dlp_rule.created',
  ruleUpdated: 'dlp_rule.updated',
  ruleDeleted: 'dlp_rule.deleted',
  exceptionCreated: 'dlp_exception.created',
  exceptionUpdated: 'dlp_exception.updated',
  exceptionDeleted: 'dlp_exception.deleted',
  patternCreated: 'dlp_pattern.created',
  patternUpdated: 'dlp_pattern.updated',
  patternDeleted: 'dlp_pattern.deleted',
  dictionaryCreated: 'dlp_dictionary.created',
  dictionaryUpdated: 'dlp_dictionary.updated',
  dictionaryDeleted: 'dlp_dictionary.deleted',
  aadhaarEnabled: 'dlp_compliance.aadhaar_enabled',
  aadhaarDisabled: 'dlp_compliance.aadhaar_disabled',
  evidenceRead: 'dlp_evidence.read',
  evidenceReadFailed: 'dlp_evidence.read_failed',
  evidencePurged: 'dlp_evidence.purged',
} as const;

export const DLP_RESOURCE = {
  policy: 'dlp_policy',
  rule: 'dlp_policy_rule',
  exception: 'dlp_exception',
  pattern: 'dlp_custom_pattern',
  dictionary: 'dlp_keyword_dictionary',
  compliance: 'dlp_compliance_settings',
  evidence: 'dlp_evidence',
} as const;

export const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

export const iso = (value: Date | null): string | null =>
  value === null ? null : value.toISOString();

/**
 * Runs a DLP writer transaction (120 s budget, 10 s `maxWait`); an echo-check mismatch
 * (`InconsistentDlpReadError`) retries the whole transaction once, a second mismatch is
 * `503 inconsistent_read` (step 4.5 §6).
 */
@Injectable()
export class DlpWriter {
  private readonly logger = new Logger(DlpWriter.name);

  constructor(private readonly transactions: TransactionRunner) {}

  async run<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.transactions.run(fn, DLP_TX);
      } catch (error) {
        if (!(error instanceof InconsistentDlpReadError)) throw error;
        this.logger.warn({ message: 'inconsistent writer read', read: error.read, attempt });
        if (attempt >= 2) throw inconsistentRead();
      }
    }
  }
}

/** Results of `dlp_evidence_reads_total` (D16, D22). */
export type EvidenceReadResult =
  'ok' | 'not_found' | 'purged' | 'expired' | 'unavailable' | 'failed';

/**
 * The api's DLP series (D22): `dlp_evidence_reads_total{result}` and
 * `dlp_pattern_tests_total{result}`. No label carries a value, a tenant, a pattern or an id.
 */
@Injectable()
export class DlpMetrics {
  readonly evidenceReads: Counter<'result'>;
  readonly patternTests: Counter<'result'>;

  constructor(metrics: MetricsService) {
    this.evidenceReads = metrics.counter(
      'dlp_evidence_reads_total',
      'DLP evidence reads through the audited api endpoint, by result (ok, not_found, purged, expired, unavailable: object storage failed, failed: missing, altered or undecryptable evidence)',
      ['result'],
    );
    this.patternTests = metrics.counter(
      'dlp_pattern_tests_total',
      'DLP custom pattern tests (POST /dlp/patterns/test), by result (valid, invalid); the pattern and the sample are never logged',
      ['result'],
    );
  }
}
