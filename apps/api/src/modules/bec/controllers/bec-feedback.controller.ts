import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiProduces,
  ApiResponse,
} from '@nestjs/swagger';
import { Idempotent } from '../../../http/idempotency/idempotency.interceptor';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiBecId,
  ApiFeedbackConflict,
  ApiFeedbackInvalid,
  ApiFeedbackTargetNotFound,
  ApiInconsistentRead,
  ApiScanId,
  ApiSuppressionNotFound,
  BEC_APPLY_NOTE,
  BEC_FEEDBACK,
  BEC_FEEDBACK_EXPORT,
  BEC_MANAGE,
  BEC_READ,
  becIdPipe,
  scanIdPipe,
} from '../api-docs';
import {
  type BecFeedbackCreate,
  BecFeedbackCreateSchema,
  type BecFeedbackCreated,
  BecFeedbackCreatedSchema,
  type BecFeedbackExportQuery,
  BecFeedbackExportQuerySchema,
  BecFeedbackExportRecordSchema,
  type BecFeedbackListQuery,
  BecFeedbackListQuerySchema,
  type BecFeedbackPage,
  BecFeedbackPageSchema,
  type BecHistoryPurged,
  BecHistoryPurgedSchema,
  type BecSuppressionListQuery,
  BecSuppressionListQuerySchema,
  type BecSuppressionPage,
  BecSuppressionPageSchema,
} from '../dto/bec.schemas';
import { BecFeedbackService } from '../services/bec-feedback.service';
import { BecController } from './bec-common';

/** Response header carrying the cursor of the next export page. */
export const NEXT_CURSOR_HEADER = 'X-Next-Cursor';

/**
 * Feedback on a scan's BEC result (step 4.4 B11, B18), under the message's scans. User sessions
 * only (one feedback per scan, user and kind). Translation only.
 */
@BecController()
@Controller({ path: 'messages', version: '1' })
export class BecMessageFeedbackController {
  constructor(private readonly feedback: BecFeedbackService) {}

  @Post(':messageId/scans/:scanId/bec-feedback')
  @RequirePermissions(BEC_FEEDBACK)
  @UserOnly()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Record false-positive or false-negative feedback on a BEC verdict',
    description:
      'Against the `bec` result of one scan round of a message of the caller’s organization. ' +
      '`reasonCodes` lists disputed codes (for a false positive, codes of the result); `note` ' +
      '(≤ 500 characters, never exported) must not contain message content. A false positive ' +
      'may `suppress` suppressible codes of the result for the scanned message’s From ' +
      '`address` or registrable `domain` (never a free-mail domain) for 1–90 days; an ' +
      'existing rule for the same code and sender is renewed. At most ' +
      'BEC_SUPPRESSIONS_MAX_PER_TENANT active rules. False negatives are recorded only. One ' +
      'feedback per scan, user and kind (`409 feedback_exists`). User sessions only. Audited ' +
      `as \`bec_feedback.recorded\`. ${BEC_APPLY_NOTE}`,
  })
  @ApiMessageId()
  @ApiScanId()
  @ApiBody({ schema: zodToOpenApi(BecFeedbackCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(BecFeedbackCreatedSchema) })
  @ApiErrors(400, 401, 403)
  @ApiFeedbackTargetNotFound()
  @ApiFeedbackConflict()
  @ApiFeedbackInvalid()
  @ApiInconsistentRead()
  record(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Param('scanId', scanIdPipe) scanId: string,
    @Body(new ZodValidationPipe(BecFeedbackCreateSchema)) body: BecFeedbackCreate,
    @Client() client: ClientContext,
  ): Promise<BecFeedbackCreated> {
    return this.feedback.record(principal, scope, messageId, BigInt(scanId), body, client);
  }
}

/**
 * The organization's BEC feedback, the retraining export, the suppression rules and the
 * communication-history purge (step 4.4 B11, B12, B18). Translation only; the logic is in
 * BecFeedbackService.
 */
@BecController()
@Controller({ path: 'bec', version: '1' })
export class BecFeedbackController {
  constructor(private readonly feedback: BecFeedbackService) {}

  @Get('feedback')
  @CursorList('v0')
  @RequirePermissions(BEC_READ)
  @ApiOperation({
    summary: 'List the BEC feedback',
    description:
      'Newest first, cursor-paginated, optionally one `kind` and a `from`/`to` window on the ' +
      'creation time. From the read replica.',
  })
  @ApiQueryFrom(BecFeedbackListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(BecFeedbackPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecFeedbackListQuerySchema)) query: BecFeedbackListQuery,
  ): Promise<BecFeedbackPage> {
    return this.feedback.list(scope, query);
  }

  @Get('feedback/export')
  @RequirePermissions(BEC_FEEDBACK_EXPORT)
  @RequireMfa()
  @RateLimit({ bucket: 'bec-feedback-export', limit: 10, windowSeconds: 60, by: 'principal' })
  @ApiOperation({
    summary: 'Export BEC feedback features for model retraining (NDJSON)',
    description:
      'One JSON object per line, oldest first, at most `limit` (≤ 10 000) per response; ' +
      `\`${NEXT_CURSOR_HEADER}\` names the cursor of the next response (absent on the last). ` +
      'Fields: feedbackId, kind, createdAt, rulesVersion, engineVersion, localModel, llm, ' +
      'firedCodes, deterministicScore, score, verdict, deterministicVerdict, features (the AI ' +
      'feature vector), aiLabels. Never bodies, excerpts, span text, addresses, display ' +
      'names, domains, notes or message ids. MFA-authenticated users only, 10 calls per ' +
      'caller per minute. Audited as `bec_feedback.exported`. From the read replica.',
  })
  @ApiQueryFrom(BecFeedbackExportQuerySchema)
  @ApiProduces('application/x-ndjson')
  @ApiResponse({
    status: 200,
    description: 'NDJSON: one record per line',
    content: {
      'application/x-ndjson': { schema: zodToOpenApi(BecFeedbackExportRecordSchema) },
    },
  })
  @ApiErrors(400, 401, 403, 429)
  async export(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecFeedbackExportQuerySchema)) query: BecFeedbackExportQuery,
    @Client() client: ClientContext,
    @Res() res: Response,
  ): Promise<void> {
    const stream = await this.feedback.export(principal, scope, query, client);
    res.status(HttpStatus.OK);
    res.setHeader('Content-Type', 'application/x-ndjson; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store');
    if (stream.nextCursor !== null) res.setHeader(NEXT_CURSOR_HEADER, stream.nextCursor);
    try {
      for await (const line of stream.lines) res.write(line);
      res.end();
    } catch (error) {
      // Headers are sent: the only signal left is an aborted response.
      res.destroy(error instanceof Error ? error : undefined);
    }
  }

  @Get('suppressions')
  @CursorList('v0')
  @RequirePermissions(BEC_READ)
  @ApiOperation({
    summary: 'List the BEC suppression rules',
    description:
      'Rules created from false-positive feedback, newest first, cursor-paginated, optionally ' +
      'only active or expired ones. From the read replica.',
  })
  @ApiQueryFrom(BecSuppressionListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(BecSuppressionPageSchema) })
  @ApiErrors(400, 401, 403)
  listSuppressions(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(BecSuppressionListQuerySchema)) query: BecSuppressionListQuery,
  ): Promise<BecSuppressionPage> {
    return this.feedback.listSuppressions(scope, query);
  }

  @Delete('suppressions/:id')
  @RequirePermissions(BEC_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a BEC suppression rule',
    description: `Audited as \`bec_suppression.deleted\` with the rule as it was. ${BEC_APPLY_NOTE}`,
  })
  @ApiBecId('Suppression rule public id')
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiSuppressionNotFound()
  @ApiInconsistentRead()
  async deleteSuppression(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', becIdPipe) id: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.feedback.deleteSuppression(principal, scope, id, client);
  }

  @Delete('history')
  @Idempotent({ operation: 'bec.history_purge', legacy: true })
  @RequirePermissions(BEC_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Purge the organization’s BEC communication history',
    description:
      'Deletes every `bec_contact_history` row of the organization (keyed hashes and counts, ' +
      'ADR-0035) in batches of 5 000 and answers with the number deleted. Turning ' +
      '`history.enabled` off does not delete rows; this does. Messages scanned while history ' +
      'is enabled start new rows. MFA-authenticated users only. Audited as ' +
      '`bec_history.purged` with the count.',
  })
  @ApiAcceptedResponse({ schema: zodToOpenApi(BecHistoryPurgedSchema) })
  @ApiErrors(401, 403)
  purgeHistory(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Client() client: ClientContext,
  ): Promise<BecHistoryPurged> {
    return this.feedback.purgeHistory(principal, scope, client);
  }
}
