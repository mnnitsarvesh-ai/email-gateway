import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  buildPolicyInput,
  compileSnapshot,
  evaluatePolicyPerRecipient,
  type PolicyEvaluationResult,
  type PolicyInput,
  PolicyInputError,
  referencedDirectoryIds,
  restrictToRecipient,
} from '@email-gateway/policy-dsl';
import {
  type ApprovalReason,
  decideRelease,
  type MessageState,
  type QuarantineReleaseMode,
  type QuarantineSettings,
  type ReleaseDecision,
} from '@email-gateway/quarantine';
import type { Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  directoryMaps,
  policyRoundRowsOf,
  roundAddresses,
  snapshotSource,
} from '../../policies/domain/policy-round';
import { PolicyFactsRepository } from '../../policies/repositories/policy-facts.repository';
import type { EntryRow } from '../domain/entry';
import type { QuarantineConfig } from '../quarantine.constants';
import { QuarantineFactsRepository } from '../repositories/quarantine-facts.repository';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';

export interface PrecheckInput {
  scope: TenantScope;
  entry: EntryRow;
  /** The message's registry public id (PolicyFactsRepository addresses messages by it). */
  messagePublicId: string;
  mode: QuarantineReleaseMode;
  approvedReasons?: readonly ApprovalReason[];
  /** Fresh from the writer's lifecycle lock. */
  messageState: MessageState;
  settings: QuarantineSettings;
  now: Date;
}

export interface Precheck {
  decision: ReleaseDecision;
  /** `quarantine_release_logs.precheck` / approval documents (content-free). */
  document: Prisma.InputJsonValue;
}

/**
 * The advisory release pre-check of the api (step 5.3 Q13.1; the executor decides, 13.2): the
 * latest completed scan round of the message read from the **replica** with the policy test's
 * reader (`PolicyFactsRepository`, the same rows the policy-engine assembles), the organization's
 * **current** active snapshot, `evaluatePolicyPerRecipient` restricted to the entry's recipient,
 * the Q13.4 staleness facts and `decideRelease`. A round whose stored facts the input builder
 * refuses, or no completed round at all, is decided as `no_scan_round` (approval required).
 */
@Injectable()
export class QuarantinePrecheckService {
  private readonly logger = new Logger(QuarantinePrecheckService.name);

  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      QuarantineConfig,
      | 'POLICY_PLATFORM_DEFAULT'
      | 'QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS'
      | 'QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS'
    >,
    private readonly policyFacts: PolicyFactsRepository,
    private readonly facts: QuarantineFactsRepository,
    private readonly reads: QuarantineReadRepository,
  ) {}

  async run(input: PrecheckInput): Promise<Precheck> {
    const { scope, entry } = input;
    const ref = {
      id: entry.messageId,
      receivedAt: entry.messageReceivedAt,
      organizationId: scope.organizationId,
    };
    const db = this.reads.client;
    const scan = await this.facts.latestScan(db, scope, ref);
    let result: PolicyEvaluationResult | null = null;
    let policyInput: PolicyInput | null = null;
    if (scan !== null && scan.completedAt !== null) {
      const evaluated = await this.evaluate(scope, input.messagePublicId, scan, entry);
      result = evaluated?.result ?? null;
      policyInput = evaluated?.input ?? null;
    }
    const staleness = await this.facts.stalenessFacts(db, scope, ref, scan?.id ?? null);
    const decision = decideRelease({
      entry: {
        kind: entry.kind,
        reason: entry.reason,
        state: entry.state,
        riskLevel: entry.riskLevel,
      },
      mode: input.mode,
      approvedReasons: input.approvedReasons,
      messageState: input.messageState,
      scan:
        result === null || scan === null || scan.completedAt === null
          ? null
          : { scanId: scan.id.toString(), completedAt: scan.completedAt },
      result,
      input: policyInput,
      staleness: {
        hasAttachments: entry.hasAttachments || (policyInput?.attachments.count ?? 0) > 0,
        hasUrls: staleness.hasUrls,
        hasScannedAttachments: staleness.hasScannedAttachments,
        newestClamavDbFirstSeenAt: staleness.newestClamavDbFirstSeenAt,
      },
      now: input.now,
      settings: input.settings,
      bounds: {
        maxVerdictAgeHours: this.config.QUARANTINE_RELEASE_MAX_VERDICT_AGE_HOURS,
        signatureMaxLagHours: this.config.QUARANTINE_RELEASE_SIGNATURE_MAX_LAG_HOURS,
      },
    });
    return { decision, document: precheckDocument(decision, input.now) };
  }

  private async evaluate(
    scope: TenantScope,
    messagePublicId: string,
    scan: NonNullable<Awaited<ReturnType<QuarantineFactsRepository['latestScan']>>>,
    entry: EntryRow,
  ): Promise<{ result: PolicyEvaluationResult; input: PolicyInput } | null> {
    const message = await this.policyFacts.message(scope, messagePublicId);
    if (message === null) return null;
    const snapshotRows = await this.policyFacts.snapshot(scope);
    const compiled = compileSnapshot(
      snapshotSource(snapshotRows, this.config.POLICY_PLATFORM_DEFAULT, { kind: 'active' }),
    );
    const rows = await this.policyFacts.roundRows(scope, message, scan.id);
    const refs = referencedDirectoryIds(compiled);
    const directory =
      refs.departmentIds.length === 0 && refs.userIds.length === 0
        ? { departmentsByAddress: {}, usersByAddress: {} }
        : directoryMaps(
            await this.policyFacts.directory(scope, roundAddresses(message, rows), refs),
          );
    let input: PolicyInput;
    try {
      input = buildPolicyInput(policyRoundRowsOf(message, scan, rows, directory));
    } catch (error) {
      if (!(error instanceof PolicyInputError)) throw error;
      this.logger.warn({
        message: 'stored round facts refused by the input builder',
        code: error.message,
      });
      return null;
    }
    const own = recipientOf(input, entry);
    const restricted = restrictToRecipient(input, entry.rcptSeq, own);
    const evaluation = evaluatePolicyPerRecipient(restricted, compiled);
    return { result: evaluation.message, input: restricted };
  }
}

/** The entry's recipient as an input recipient (beyond the input's recipient window too). */
function recipientOf(input: PolicyInput, entry: EntryRow): PolicyInput['recipients'][number] {
  const found = input.recipients.find((r) => r.rcptSeq === entry.rcptSeq);
  if (found !== undefined) return found;
  const address = entry.recipientAddress.toLowerCase();
  const at = address.lastIndexOf('@');
  return {
    rcptSeq: entry.rcptSeq,
    address,
    domain: at > 0 ? address.slice(at + 1) : null,
    localPart: at > 0 ? address.slice(0, at) : address,
    departments: [],
    users: [],
  };
}

/** The stored pre-check: outcome, reasons, staleness, the 13.3 summary, time. */
export function precheckDocument(decision: ReleaseDecision, now: Date): Prisma.InputJsonValue {
  return {
    source: 'api_precheck',
    at: now.toISOString(),
    outcome: decision.outcome,
    approvalReasons: decision.approvalReasons,
    refusal: decision.refusal ?? null,
    staleness: {
      stale: decision.staleness.stale,
      causes: decision.staleness.causes,
      verdictAgeHours: decision.staleness.verdictAgeHours,
      signatureLagHours: decision.staleness.signatureLagHours,
    },
    summary: decision.summary === null ? null : { ...decision.summary },
  };
}
