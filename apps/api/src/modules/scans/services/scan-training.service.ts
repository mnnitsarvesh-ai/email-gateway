import type { Readable } from 'node:stream';
import { ForbiddenException, Injectable, Logger } from '@nestjs/common';
import {
  isRspamdError,
  type RspamdClient,
  RspamdHttpError,
  type RspamdError,
} from '@email-gateway/rspamd';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { CodedHttpException } from '../../../http/coded-exception';
import { TransactionRunner } from '../../../database/transaction-runner';
import type { ClientContext } from '../../auth/services/session.service';
import type {
  FuzzyFlagName,
  ScanTrainingBody,
  ScanTrainingOperation,
  ScanTrainingResponse,
  ScanTrainingResult,
} from '../dto/scan-training.schemas';
import { messageNotFound } from '../../messages/messages.errors';
import {
  contentUnavailable,
  organizationNotFound,
  rspamdUnavailable,
  scanTrainingNotApplicable,
} from '../scans.errors';
import {
  type TrainingMessage,
  type TrainingOrganization,
  ScanTrainingRepository,
} from '../repositories/scan-training.repository';
import { EmlStore, EmlUnavailableError } from './eml-store';
import { RspamdController } from './rspamd-controller';

/** Rspamd fuzzy flags of the local storage (S12 `fuzzy_check.conf`, S13). */
export const FUZZY_FLAG_NUMBERS: Readonly<Record<FuzzyFlagName, number>> = {
  spam: 11,
  phishing: 12,
};

/** Outcomes recorded in the audit row: a training result or why it did not happen. */
type TrainingOutcome =
  ScanTrainingResult | 'content_unavailable' | 'rspamd_unavailable' | 'not_applicable';

const auditAction = (operation: ScanTrainingOperation) => `scan_training.${operation}`;

/** The controller call of an operation. */
async function train(
  client: RspamdClient,
  body: ScanTrainingBody,
  fuzzyWeight: number,
  eml: { body: Readable; sizeBytes: number },
): Promise<ScanTrainingResult> {
  switch (body.operation) {
    case 'learn_spam':
      return client.learn('spam', eml.body, eml.sizeBytes);
    case 'learn_ham':
      return client.learn('ham', eml.body, eml.sizeBytes);
    case 'fuzzy_add':
    case 'fuzzy_delete': {
      const flag = FUZZY_FLAG_NUMBERS[body.fuzzyFlag!];
      const result = await client.fuzzy(
        body.operation === 'fuzzy_add' ? 'add' : 'delete',
        flag,
        fuzzyWeight,
        eml.body,
        eml.sizeBytes,
      );
      return result.result;
    }
  }
}

/** Maps a controller failure: 404 of a fuzzy call = nothing to hash, everything else = 503. */
export function trainingFailure(
  operation: ScanTrainingOperation,
  error: RspamdError,
): { outcome: TrainingOutcome; exception: CodedHttpException } {
  if (
    error instanceof RspamdHttpError &&
    error.status === 404 &&
    (operation === 'fuzzy_add' || operation === 'fuzzy_delete')
  ) {
    return { outcome: 'not_applicable', exception: scanTrainingNotApplicable() };
  }
  return { outcome: 'rspamd_unavailable', exception: rspamdUnavailable() };
}

/**
 * Platform training of the shared spam classifiers (step 4.1 S13): Bayes learning and fuzzy
 * hashes in the Rspamd storage shared by every tenant, so only platform users with
 * `platform:scan_training` and an MFA session may train (a tenant admin could otherwise poison
 * another tenant's filtering). The message is looked up on the writer within the organization
 * of the path; its EML is streamed from S3 (key prefix checked) to the controller and never
 * stored or logged. Every call that found its message writes one `audit_logs` row
 * (`scan_training.<operation>`, with the outcome, never content); a successful one also writes
 * the `email_events` row `scan.training`. Learning does not rescan the message.
 */
@Injectable()
export class ScanTrainingService {
  private readonly logger = new Logger(ScanTrainingService.name);

  constructor(
    private readonly repository: ScanTrainingRepository,
    private readonly transactions: TransactionRunner,
    private readonly eml: EmlStore,
    private readonly rspamd: RspamdController,
    private readonly audit: AuditService,
  ) {}

  async train(
    principal: UserPrincipal,
    organizationPublicId: string,
    messagePublicId: string,
    body: ScanTrainingBody,
    client: ClientContext,
  ): Promise<ScanTrainingResponse> {
    // The guard already requires the platform permission (stripped from API keys and override
    // sessions); a platform function is only ever run by a platform member (D9).
    if (principal.organizationKind !== 'platform' || principal.override !== undefined) {
      throw new ForbiddenException();
    }
    const organization = await this.repository.findOrganization(organizationPublicId);
    if (!organization) throw organizationNotFound();
    const message = await this.repository.findMessage(organization, messagePublicId);
    if (!message) throw messageNotFound();

    const rspamd = this.rspamd.client;
    if (rspamd === null) {
      this.logger.warn({
        message: 'scan training refused: RSPAMD_CONTROLLER_URL or the enable password is unset',
      });
      await this.record(principal, organization, message, body, 'rspamd_unavailable', null, client);
      throw rspamdUnavailable();
    }

    let result: ScanTrainingResult;
    let stream: Readable | undefined;
    try {
      const eml = await this.eml.open(organization.id, message.emlObjectKey);
      stream = eml.body;
      result = await train(rspamd, body, this.rspamd.fuzzyWeight, eml);
    } catch (error) {
      const failure = this.failureOf(body.operation, message, error);
      await this.record(principal, organization, message, body, failure.outcome, null, client);
      throw failure.exception;
    } finally {
      if (stream && !stream.destroyed) stream.destroy();
    }
    const engineVersion = await this.engineVersion(rspamd);
    await this.record(principal, organization, message, body, result, engineVersion, client);
    this.logger.log({
      message: 'scan training applied',
      operation: body.operation,
      result,
      organizationId: organization.id.toString(),
      messageId: message.id.toString(),
      engineVersion,
    });
    return { operation: body.operation, result, engineVersion };
  }

  private failureOf(
    operation: ScanTrainingOperation,
    message: TrainingMessage,
    error: unknown,
  ): { outcome: TrainingOutcome; exception: CodedHttpException } {
    const ids = { operation, messageId: message.id.toString() };
    if (error instanceof EmlUnavailableError) {
      const log = error.why === 'foreign_key' ? 'error' : 'warn';
      this.logger[log]({ message: 'scan training: EML unavailable', ...ids, why: error.why });
      return { outcome: 'content_unavailable', exception: contentUnavailable() };
    }
    if (isRspamdError(error)) {
      const failure = trainingFailure(operation, error);
      this.logger.warn({
        message: 'scan training: Rspamd controller call failed',
        ...ids,
        kind: error.kind,
        status: error instanceof RspamdHttpError ? error.status : null,
        outcome: failure.outcome,
      });
      return failure;
    }
    // S3 or network failure while opening or streaming the EML: the controller call never
    // completed, so nothing was trained; retry later.
    this.logger.warn({
      message: 'scan training: EML stream failed',
      ...ids,
      errName: error instanceof Error ? error.name : 'unknown',
    });
    return { outcome: 'rspamd_unavailable', exception: rspamdUnavailable() };
  }

  /** The Rspamd version (`/stat`), or the last one seen; `unknown` if neither is available. */
  private async engineVersion(client: RspamdClient): Promise<string> {
    try {
      return await client.version();
    } catch {
      return client.lastServerVersion ?? 'unknown';
    }
  }

  /** The audit row of every call and, after a training result, the timeline row (one tx). */
  private async record(
    principal: UserPrincipal,
    organization: TrainingOrganization,
    message: TrainingMessage,
    body: ScanTrainingBody,
    outcome: TrainingOutcome,
    engineVersion: string | null,
    client: ClientContext,
  ): Promise<void> {
    const trained =
      outcome === 'learned' ||
      outcome === 'already_learned' ||
      outcome === 'added' ||
      outcome === 'deleted';
    await this.transactions.run(async (tx) => {
      await this.audit.record(
        {
          organizationId: organization.id,
          actor: this.audit.actorFrom(principal),
          action: auditAction(body.operation),
          resourceType: 'message',
          resourceId: message.publicId,
          sourceIp: client.ip,
          metadata: {
            operation: body.operation,
            ...(body.fuzzyFlag !== undefined && {
              fuzzyFlag: body.fuzzyFlag,
              fuzzyFlagNumber: FUZZY_FLAG_NUMBERS[body.fuzzyFlag],
            }),
            outcome,
            engineVersion,
            reason: body.reason,
          },
        },
        tx,
      );
      if (trained) {
        await this.repository.insertTrainingEvent(tx, message, {
          occurredAt: new Date(),
          actorId: principal.userPublicId,
          details: { operation: body.operation, result: outcome },
        });
      }
    });
  }
}
