import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
  UseFilters,
} from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { Idempotent } from '../../../http/idempotency/idempotency.interceptor';
import type { Response } from 'express';
import {
  CursorList,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
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
import { ApiQueryFrom } from '../../organizations/api-docs';
import { UuidParamSchema } from '../../organizations/dto/organizations.schemas';
import {
  ApiRescanJobNotCancellable,
  ApiRescanJobNotFound,
  ApiRescanOrganizationNotFound,
  PLATFORM_SCAN_RESCAN,
} from '../api-docs';
import {
  type RescanJobCancel,
  RescanJobCancelSchema,
  type RescanJobCreate,
  RescanJobCreatedSchema,
  RescanJobCreateSchema,
  type RescanJobCreated,
  type RescanJobEstimate,
  RescanJobEstimateSchema,
  type RescanJobListQuery,
  RescanJobListQuerySchema,
  type RescanJobPage,
  RescanJobPageSchema,
  type RescanJobView,
  RescanJobViewSchema,
} from '../dto/attachment-rescans.schemas';
import { AttachmentRescansService } from '../services/attachment-rescans.service';

const jobIdPipe = new ZodValidationPipe(UuidParamSchema);

/**
 * Bulk attachment rescans (step 4.2 A13): a platform administrator asks for every recent
 * message with attachments to be scanned again (after a signature update or a newly added
 * hash). The api writes the job; the email-worker's rescan runner executes it at a bounded rate
 * through the existing rescan path. Platform users only (no API keys, no override tokens), MFA,
 * `platform:scan_rescan`, 10 calls per caller per minute. Translation only; the logic is in
 * AttachmentRescansService.
 */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@UseFilters(CodedExceptionFilter)
@RateLimit({ bucket: 'attachment-rescans', limit: 10, windowSeconds: 60, by: 'principal' })
@Controller({ path: 'platform/attachment-rescans', version: '1' })
export class AttachmentRescansController {
  constructor(private readonly rescans: AttachmentRescansService) {}

  @Post()
  @Idempotent({ operation: 'platform.attachment_rescan', legacy: true })
  @RequirePermissions(PLATFORM_SCAN_RESCAN)
  @RequireMfa()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Request a bulk attachment rescan',
    description:
      'Creates a `pending` admin job for messages received in the last `windowHours` (1-168) ' +
      'in the given `states` (default `scanned`, `scan_failed`, `quarantined`, ' +
      '`held_for_review`; never scanning, delivery or final states), optionally one ' +
      'organization, with at least one attachment and without a `malicious` attachment ' +
      'result in their current round (a `scan_failed` message always qualifies), at most ' +
      '`maxMessages` (default and maximum `ATTACHMENT_RESCAN_MAX_MESSAGES`). The ' +
      'email-worker executes it at a bounded rate: each message gets a new scan round on ' +
      'every engine. `estimatedMessages` counts the candidates now on the read replica (the ' +
      'worker selects on the writer as it goes). `dryRun: true` answers `200` with the count ' +
      'and writes nothing. Audited as `attachment_rescan.requested` (parameters only). 10 ' +
      'calls per caller per minute (shared by the rescan job routes).',
  })
  @ApiBody({ schema: zodToOpenApi(RescanJobCreateSchema, { io: 'input' }) })
  @ApiAcceptedResponse({ schema: zodToOpenApi(RescanJobCreatedSchema) })
  @ApiOkResponse({
    description: 'Dry run: the estimate only, nothing written',
    schema: zodToOpenApi(RescanJobEstimateSchema),
  })
  @ApiErrors(400, 401, 403, 429)
  @ApiRescanOrganizationNotFound()
  async request(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(RescanJobCreateSchema)) body: RescanJobCreate,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RescanJobCreated | RescanJobEstimate> {
    const result = await this.rescans.request(principal, body, client);
    if (result.kind === 'estimate') res.status(HttpStatus.OK);
    return result.body;
  }

  @Get()
  @CursorList('v0')
  @RequirePermissions(PLATFORM_SCAN_RESCAN)
  @RequireMfa()
  @ApiOperation({
    summary: 'List the attachment rescan jobs',
    description:
      'Admin and signature-update jobs, newest first, cursor-paginated, optionally one ' +
      '`status`, with their progress counters. From the read replica.',
  })
  @ApiQueryFrom(RescanJobListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(RescanJobPageSchema) })
  @ApiErrors(400, 401, 403, 429)
  list(
    @CurrentUser() principal: UserPrincipal,
    @Query(new ZodValidationPipe(RescanJobListQuerySchema)) query: RescanJobListQuery,
  ): Promise<RescanJobPage> {
    return this.rescans.list(principal, query);
  }

  @Get(':jobId')
  @RequirePermissions(PLATFORM_SCAN_RESCAN)
  @RequireMfa()
  @ApiOperation({ summary: 'Get an attachment rescan job (read replica)' })
  @ApiParam({ name: 'jobId', format: 'uuid' })
  @ApiOkResponse({ schema: zodToOpenApi(RescanJobViewSchema) })
  @ApiErrors(400, 401, 403, 429)
  @ApiRescanJobNotFound()
  get(
    @CurrentUser() principal: UserPrincipal,
    @Param('jobId', jobIdPipe) jobId: string,
  ): Promise<RescanJobView> {
    return this.rescans.get(principal, jobId);
  }

  @Post(':jobId/cancel')
  @RequirePermissions(PLATFORM_SCAN_RESCAN)
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Cancel an attachment rescan job',
    description:
      'Moves a `pending` or `running` job to `cancelled`; the runner stops at its next batch ' +
      '(messages already requested keep their new round). Audited as ' +
      '`attachment_rescan.cancelled`. `409 rescan_job_not_cancellable` for any other status.',
  })
  @ApiParam({ name: 'jobId', format: 'uuid' })
  @ApiBody({ schema: zodToOpenApi(RescanJobCancelSchema, { io: 'input' }), required: false })
  @ApiOkResponse({ schema: zodToOpenApi(RescanJobViewSchema) })
  @ApiErrors(400, 401, 403, 429)
  @ApiRescanJobNotFound()
  @ApiRescanJobNotCancellable()
  cancel(
    @CurrentUser() principal: UserPrincipal,
    @Param('jobId', jobIdPipe) jobId: string,
    @Body(new ZodValidationPipe(RescanJobCancelSchema)) body: RescanJobCancel,
    @Client() client: ClientContext,
  ): Promise<RescanJobView> {
    return this.rescans.cancel(principal, jobId, body, client);
  }
}
