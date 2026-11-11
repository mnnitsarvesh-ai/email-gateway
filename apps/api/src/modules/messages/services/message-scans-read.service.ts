import { Injectable } from '@nestjs/common';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { referencedIds } from '../../bec/domain/bec-result';
import { collectRefs } from '../../dlp/domain/dlp-result';
import {
  BEC_ENGINE,
  decodeScanCursor,
  DLP_ENGINE,
  type DlpInputs,
  encodeScanCursor,
  NO_BEC,
  NO_DLP,
  roundOf,
  URL_ENGINE,
} from '../domain/message-scans';
import type { MessageScansPage, MessageScansQuery } from '../dto/message-scans.schemas';
import { messageNotFound } from '../messages.errors';
import {
  type LifecycleMessageRow,
  MessageLifecycleReadRepository,
} from '../repositories/message-lifecycle-read.repository';
import { MessageScansReadRepository } from '../repositories/message-scans-read.repository';

/** Holders of this permission see the masked `dlp` section (D20; `message:read` alone does not). */
export const DLP_READ_PERMISSION = 'dlp:read';

/**
 * `GET /messages/{messageId}/scans` (step 4.1 S16; step 4.2 A16: per-attachment results on the
 * `attachment` engine entry; step 4.3 U16: per-URL results and the rewrite on the `url` entry;
 * step 4.4 B15: the explainable BEC verdict on the `bec` entry; step 4.5 D20: the masked DLP
 * result on the `dlp` entry, only for callers holding `dlp:read`; step 4.6 X18: the sandbox
 * submissions with their outcome on each attachment and with the analysis report on the
 * `sandbox` entry; step 5.1 R15: the stored risk scores of each round in `risk`; step 5.2 P16: its stored policy
 * evaluation in `policy`): the scan rounds of a message of the caller's organization, newest
 * round first, from the read replica (a few seconds behind the writer: a round that just
 * completed may still show as running). Every query filters by the scope's organization;
 * another organization's message is `404 message_not_found`.
 */
@Injectable()
export class MessageScansReadService {
  constructor(
    private readonly messages: MessageLifecycleReadRepository,
    private readonly rounds: MessageScansReadRepository,
  ) {}

  async list(
    principal: Principal,
    scope: TenantScope,
    messageId: string,
    query: MessageScansQuery,
  ): Promise<MessageScansPage> {
    const beforeRound = query.cursor === undefined ? undefined : decodeScanCursor(query.cursor);
    const message = await this.messages.findMessage(scope, messageId);
    if (!message) throw messageNotFound();
    const rows = await this.rounds.rounds(scope, message, {
      take: query.limit + 1,
      ...(beforeRound !== undefined && { beforeRound }),
    });
    const page = rows.slice(0, query.limit);
    const scanIds = page.map((row) => row.id);
    const [engineRows, authRows, results, submissions, riskRows, policyRows] = await Promise.all([
      this.rounds.engineResults(scope, message, scanIds),
      this.rounds.authResults(scope, message, scanIds),
      this.rounds.attachmentResults(scope, message, scanIds),
      this.rounds.sandboxSubmissions(scope, message, scanIds),
      // Step 5.1 R15: the stored risk scores (message:read; profile public ids only).
      this.rounds.riskScores(scope, message, scanIds),
      // Step 5.2 P16: the stored policy evaluation of each round (message:read; ids only).
      this.rounds.policyEvaluations(scope, message, scanIds),
    ]);
    // Step 4.3 U16: URL rows only when a page round has a url engine row.
    const hasUrl = engineRows.some((row) => row.engine === URL_ENGINE);
    const [urls, urlResults, rewrites, inspections, clicks] = hasUrl
      ? await Promise.all([
          this.rounds.messageUrls(scope, message),
          this.rounds.urlResults(scope, message, scanIds),
          this.rounds.urlRewrites(scope, message, scanIds),
          this.rounds.urlInspections(scope, message, scanIds),
          this.rounds.urlClicks(scope, message),
        ])
      : [[], [], [], [], []];
    // Step 4.4 B15: BEC rows only when a page round has a bec engine row.
    const hasBec = engineRows.some((row) => row.engine === BEC_ENGINE);
    const becInputs = hasBec ? await this.becInputs(scope, message, scanIds) : NO_BEC;
    // Step 4.5 D20: DLP rows only for a caller holding dlp:read and a page round with a dlp row.
    const dlpVisible = principal.permissions.has(DLP_READ_PERMISSION);
    const hasDlp = dlpVisible && engineRows.some((row) => row.engine === DLP_ENGINE);
    const dlpInputs = hasDlp ? await this.dlpInputs(scope, message, scanIds) : NO_DLP;
    // Step 4.6 X18: the analyses that completed this organization's terminal submissions (ids
    // from the tenant-scoped submission rows only) and their artifact metadata.
    const analysisIds = submissions.flatMap((s) =>
      s.analysisId !== null && s.externalRef !== null && s.status !== 'skipped'
        ? [s.analysisId]
        : [],
    );
    const [parts, analyses, artifacts] = await Promise.all([
      this.rounds.attachmentParts(
        scope,
        message,
        results.map((row) => row.partIndex),
      ),
      analysisIds.length === 0 ? [] : this.rounds.sandboxAnalyses(analysisIds),
      analysisIds.length === 0 ? [] : this.rounds.sandboxArtifacts(analysisIds),
    ]);
    const attachments = { results, parts, submissions, analyses, artifacts };
    const urlInputs = { urls, results: urlResults, rewrites, inspections, clicks };
    const last = page.at(-1);
    return {
      messageId: message.publicId,
      data: page.map((scan) =>
        roundOf(
          scan,
          engineRows,
          authRows,
          attachments,
          urlInputs,
          becInputs,
          dlpInputs,
          riskRows,
          policyRows,
        ),
      ),
      nextCursor: rows.length > query.limit && last ? encodeScanCursor(last.lifecycleRound) : null,
    };
  }

  /**
   * The DLP results and evidence states of the page's rounds; internal ids of the stored
   * policy match and finding references are mapped to the organization's public ids, else
   * dropped (D20).
   */
  private async dlpInputs(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ): Promise<DlpInputs> {
    const [results, evidence] = await Promise.all([
      this.rounds.dlpResults(scope, message, scanIds),
      this.rounds.dlpEvidence(scope, message, scanIds),
    ]);
    const ids =
      results.length === 0
        ? NO_DLP.ids
        : await this.rounds.dlpPublicIds(scope, collectRefs(results));
    return { visible: true, results, evidence, ids };
  }

  /**
   * The BEC results and feedback references of the page's rounds; internal ids referenced by
   * stored evidence (if any) are mapped to the organization's public ids, else dropped.
   */
  private async becInputs(
    scope: TenantScope,
    message: LifecycleMessageRow,
    scanIds: readonly bigint[],
  ) {
    const [results, feedback] = await Promise.all([
      this.rounds.becResults(scope, message, scanIds),
      this.rounds.becFeedback(scope, message, scanIds),
    ]);
    const refs = referencedIds([]);
    for (const row of results) referencedIds(row.rules, refs);
    const big = (set: Set<string>) => [...set].map((id) => BigInt(id));
    const any =
      refs.executive.size + refs.vendor.size + refs.trusted.size + refs.suppression.size > 0;
    const ids = any
      ? await this.rounds.becPublicIds(scope, {
          executive: big(refs.executive),
          vendor: big(refs.vendor),
          trusted: big(refs.trusted),
          suppression: big(refs.suppression),
        })
      : NO_BEC.ids;
    return { results, feedback, ids };
  }
}
