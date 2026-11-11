import { Body, Controller, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { CurrentScope, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import {
  ApiDryRunErrors,
  ApiRiskScanId,
  MESSAGE_READ,
  POLICY_MANAGE,
  RISK_DOC_NOTE,
  RiskController,
  riskScanIdPipe,
} from '../api-docs';
import {
  type RiskDryRun,
  RiskDryRunDocSchema,
  type RiskDryRunResponse,
  RiskDryRunResponseSchema,
  RiskDryRunSchema,
} from '../dto/risk-scoring.schemas';
import { RiskDryRunService } from '../services/risk-dry-run.service';

/**
 * The risk scoring dry-run of a stored round (step 5.1 R15), under the message's scans.
 * Translation only; the logic is in RiskDryRunService.
 */
@RiskController()
@Controller({ path: 'messages', version: '1' })
export class RiskDryRunController {
  constructor(private readonly dryRuns: RiskDryRunService) {}

  @Post(':messageId/scans/:scanId/risk/dry-run')
  @RequirePermissions(POLICY_MANAGE, MESSAGE_READ)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Dry-run the risk scoring of a stored scan round against a profile',
    description:
      'Reads the round of a message of the organization from the read replica (its final ' +
      'engine results, authentication, BEC and DLP results: the same rows the email-worker ' +
      'scores), scores it against `profile` (`active`: the version the round snapshotted when ' +
      'it opened, or the platform default; `platform`; `{ versionId }`: a draft or published ' +
      'version; `{ overrides }`: an unsaved document validated like a draft) for `revision` 0 ' +
      '(the round) or 1 (with its late sandbox result), and returns the full result next to ' +
      'the stored score of that revision. `reproducible` is true when the stored input hash ' +
      'equals the recomputed one (with `profile: active` the result then equals the stored ' +
      'score). **Writes nothing**: no score row, no audit row, no event, no cache entry. ' +
      'A round still pending or running (or not yet replicated) is ' +
      '`409 scan_round_not_complete`. Requires `policy:manage` and `message:read`. ' +
      RISK_DOC_NOTE,
  })
  @ApiMessageId()
  @ApiRiskScanId()
  @ApiBody({ schema: zodToOpenApi(RiskDryRunDocSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RiskDryRunResponseSchema) })
  @ApiErrors(401, 403)
  @ApiDryRunErrors()
  dryRun(
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Param('scanId', riskScanIdPipe) scanId: string,
    @Body(new ZodValidationPipe(RiskDryRunSchema)) body: RiskDryRun,
  ): Promise<RiskDryRunResponse> {
    return this.dryRuns.dryRun(scope, messageId, BigInt(scanId), body);
  }
}
