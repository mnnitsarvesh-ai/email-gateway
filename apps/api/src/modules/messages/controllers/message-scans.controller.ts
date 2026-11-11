import { Controller, Get, Param, Query, UseFilters } from '@nestjs/common';
import { ApiBearerAuth, ApiOkResponse, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiMessageNotFound, MESSAGE_READ } from '../api-docs';
import {
  type MessageScansPage,
  MessageScansPageSchema,
  type MessageScansQuery,
  MessageScansQuerySchema,
} from '../dto/message-scans.schemas';
import { MessageScansReadService } from '../services/message-scans-read.service';

/**
 * Security scan results of a message of the caller's organization (step 4.1 S16; step 4.2 A16
 * per-attachment results), from the read replica. Translation only; the logic is in
 * MessageScansReadService.
 */
@ApiTags('messages')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'messages', version: '1' })
export class MessageScansController {
  constructor(private readonly scans: MessageScansReadService) {}

  @Get(':messageId/scans')
  @RequirePermissions(MESSAGE_READ)
  @ApiOperation({
    summary: 'Get the security scan results of a message',
    description:
      'One entry per scan round (`round` = lifecycle round: 0 is the initial scan, each ' +
      'rescan adds one), newest first, cursor-paginated (at most 20 rounds per page): status, ' +
      'aggregate verdict (`clean`, `spam`, `suspicious`, `malicious`, `unknown`, `timeout`, ' +
      '`error`; null while running), reason codes, required engines, the deadline, the ' +
      'SPF/DKIM/DMARC/ARC results and per engine its final result (outcome, score, threshold, ' +
      'action, reason codes, symbols with bounded options, engine and settings versions) and ' +
      'every attempt (failed attempts are retried and listed with their error code). The ' +
      '`attachment` engine entry lists its per-attachment results (step 4.2): part index, ' +
      'sanitized filename, declared and detected type, size, SHA-256, verdict, reason codes, ' +
      'the ClamAV signature and versions, YARA rule matches, archive inspection counts and ' +
      'findings (by entry index path, never names), a known-hash hit and the sandbox ' +
      'submission. The content cache is shared across organizations, so its hit/miss ' +
      'outcome is never shown, and the `attachment` engine reports no durations and ' +
      'second-granular times. The `bec` engine entry (step 4.4) carries its explainable ' +
      'verdict: versions, deterministic and final verdict and score, thresholds, input states, ' +
      'the fired rules with structured evidence (span offsets, never text), applied and shadow ' +
      'AI assessments (no response hashes or durations) and feedback references; `scanId` of ' +
      'a round is the id the BEC feedback route takes. The `dlp` engine entry (step 4.5) carries ' +
      'its masked result (versions, verdict, action, coverage detail, category aggregates, ' +
      'findings with masked samples only, the policy match and applied exceptions as public ' +
      'ids, the evidence state) **only for callers also holding `dlp:read`**; otherwise `dlp` ' +
      'is null and only the standard engine fields are shown. Matched values are never shown ' +
      'here: decrypted evidence is only in the audited ' +
      '`GET /messages/{messageId}/scans/{scanId}/dlp-evidence`. Each round lists its stored ' +
      'risk scores in `risk` (step 5.1; revision 0 = the round, 1 = with the late sandbox ' +
      'result): score 0–1000, level, verdict, recommended action, hard blocks, contributions ' +
      'by signal and group, engine evidence, trust decision, explanation and every version ' +
      '(profile public ids only); `[]` while running. Step 5.1 recommends and does not ' +
      'enforce (policy, step 5.2, decides); the default weights and thresholds are not ' +
      'validated detection accuracy. Each round carries its stored policy evaluation in ' +
      '`policy` (step 5.2; null while not evaluated): disposition, decisive rule, actions ' +
      'with their status (`enforced`, `requested`, `recorded`, `not_applicable`), floor, ' +
      'recommendation, explanation and hashes (ids and codes only; the full list per message ' +
      'is `GET /messages/{messageId}/policy-evaluations`). From the read replica: a round ' +
      'that just completed may still show as running. Symbol options can contain addresses or URLs of the ' +
      'message; filenames are attacker-controlled text.',
  })
  @ApiMessageId()
  @ApiQueryFrom(MessageScansQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(MessageScansPageSchema) })
  @ApiErrors(400, 401, 403)
  @ApiMessageNotFound()
  scansOf(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Query(new ZodValidationPipe(MessageScansQuerySchema)) query: MessageScansQuery,
  ): Promise<MessageScansPage> {
    return this.scans.list(principal, scope, messageId, query);
  }
}
