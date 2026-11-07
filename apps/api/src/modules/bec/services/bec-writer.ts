import { Injectable, Logger } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';
import type { Principal } from '../../../auth-contracts/principal';
import { TransactionRunner } from '../../../database/transaction-runner';
import { InconsistentBecReadError, inconsistentRead } from '../bec.errors';

/**
 * Budget of every BEC write (step 4.4 §6, the 4.2 §6 mitigation): an interactive transaction is
 * never abandoned by a short timeout; 120 s budget, 10 s to obtain a connection.
 */
export const BEC_TX = { timeoutMs: 120_000, maxWaitMs: 10_000 } as const;

/** `audit_logs.action` of the BEC tenant data changes (D14 `<resource>.<verb>`). */
export const BEC_AUDIT = {
  executiveCreated: 'bec_executive.created',
  executiveUpdated: 'bec_executive.updated',
  executiveDeleted: 'bec_executive.deleted',
  vendorCreated: 'bec_vendor.created',
  vendorUpdated: 'bec_vendor.updated',
  vendorDeleted: 'bec_vendor.deleted',
  trustedCreated: 'bec_trusted_sender.created',
  trustedUpdated: 'bec_trusted_sender.updated',
  trustedDeleted: 'bec_trusted_sender.deleted',
  feedbackRecorded: 'bec_feedback.recorded',
  feedbackExported: 'bec_feedback.exported',
  suppressionDeleted: 'bec_suppression.deleted',
  historyPurged: 'bec_history.purged',
} as const;

export const BEC_RESOURCE = {
  executive: 'bec_executive_profile',
  vendor: 'bec_vendor_profile',
  trusted: 'bec_trusted_sender',
  feedback: 'bec_feedback',
  suppression: 'bec_suppression_rule',
  history: 'bec_contact_history',
} as const;

export const userIdOf = (principal: Principal): bigint | null =>
  principal.kind === 'user' ? principal.userId : null;

export const iso = (value: Date | null): string | null =>
  value === null ? null : value.toISOString();

/** A JSON array of strings, or `[]` for anything else (stored rows are parsed defensively). */
export const stringList = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];

/**
 * Runs a BEC writer transaction (120 s budget, 10 s `maxWait`); an echo-check mismatch
 * (`InconsistentBecReadError`) retries the whole transaction once, a second mismatch is
 * `503 inconsistent_read` (step 4.4 §6).
 */
@Injectable()
export class BecWriter {
  private readonly logger = new Logger(BecWriter.name);

  constructor(private readonly transactions: TransactionRunner) {}

  async run<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await this.transactions.run(fn, BEC_TX);
      } catch (error) {
        if (!(error instanceof InconsistentBecReadError)) throw error;
        this.logger.warn({ message: 'inconsistent writer read', read: error.read, attempt });
        if (attempt >= 2) throw inconsistentRead();
      }
    }
  }
}

/** The api's BEC series (B19): `bec_feedback_total{kind}`. */
@Injectable()
export class BecMetrics {
  readonly feedback: Counter<'kind'>;

  constructor(metrics: MetricsService) {
    this.feedback = metrics.counter(
      'bec_feedback_total',
      'BEC feedback recorded through the api, by kind (false_positive, false_negative)',
      ['kind'],
    );
  }
}
