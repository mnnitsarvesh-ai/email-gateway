import { Body, Controller, HttpCode, HttpStatus, Param, Post, UseFilters } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { Idempotent } from '../../../http/idempotency/idempotency.interceptor';
import { RequireMfa, RequirePermissions, UserOnly } from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { UuidParamSchema } from '../../organizations/dto/organizations.schemas';
import {
  ApiContentUnavailable,
  ApiRspamdUnavailable,
  ApiTrainingNotApplicable,
  ApiTrainingNotFound,
  PLATFORM_SCAN_TRAINING,
} from '../api-docs';
import {
  type ScanTrainingBody,
  ScanTrainingBodySchema,
  type ScanTrainingResponse,
  ScanTrainingResponseSchema,
} from '../dto/scan-training.schemas';
import { ScanTrainingService } from '../services/scan-training.service';

const organizationIdPipe = new ZodValidationPipe(UuidParamSchema);

/**
 * Training of the shared spam classifiers from a stored message (step 4.1 S13). Platform users
 * only (no API keys, no override tokens), with an MFA session and `platform:scan_training`;
 * 60 calls per caller per minute. The logic is in ScanTrainingService.
 */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'platform/organizations', version: '1' })
export class ScanTrainingController {
  constructor(private readonly training: ScanTrainingService) {}

  @Post(':organizationId/messages/:messageId/scan-training')
  @Idempotent({ operation: 'platform.scan_training', legacy: true })
  @RequirePermissions(PLATFORM_SCAN_TRAINING)
  @RequireMfa()
  @RateLimit({ bucket: 'scan-training', limit: 60, windowSeconds: 60, by: 'principal' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Train the shared spam classifiers from a message',
    description:
      'Streams the stored message of the organization to the Rspamd controller: ' +
      '`learn_spam` / `learn_ham` train the Bayes classifier (`already_learned` when Rspamd ' +
      'has learned it before or already classifies it that way), `fuzzy_add` / ' +
      '`fuzzy_delete` add or remove its fuzzy hashes with `fuzzyFlag` `spam` (flag 11, ' +
      '`EG_FUZZY_SPAM`) or `phishing` (flag 12, `EG_FUZZY_PHISH`). Bayes and fuzzy storage are ' +
      'shared by every organization, hence the platform permission. Learning does not rescan ' +
      'the message (use the rescan route). Audited as `scan_training.<operation>` with the ' +
      'outcome (never content); a successful call also adds the timeline event ' +
      '`scan.training`. 60 calls per caller per minute.',
  })
  @ApiParam({ name: 'organizationId', format: 'uuid', description: 'Organization public id' })
  @ApiMessageId()
  @ApiBody({ schema: zodToOpenApi(ScanTrainingBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(ScanTrainingResponseSchema) })
  @ApiErrors(400, 401, 403, 429)
  @ApiTrainingNotFound()
  @ApiContentUnavailable()
  @ApiTrainingNotApplicable()
  @ApiRspamdUnavailable()
  train(
    @CurrentUser() principal: UserPrincipal,
    @Param('organizationId', organizationIdPipe) organizationId: string,
    @Param('messageId', messageIdPipe) messageId: string,
    @Body(new ZodValidationPipe(ScanTrainingBodySchema)) body: ScanTrainingBody,
    @Client() client: ClientContext,
  ): Promise<ScanTrainingResponse> {
    return this.training.train(principal, organizationId, messageId, body, client);
  }
}
