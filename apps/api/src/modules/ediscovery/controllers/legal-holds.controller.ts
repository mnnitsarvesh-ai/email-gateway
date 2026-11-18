import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOperation,
  ApiParam,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireAnyPermission,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ApiKeyedErrors,
  ArchiveIdempotency,
} from '../../archive/api-docs';
import { ARCHIVE_PERMISSIONS as P } from '../../archive/archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../../archive/archive.errors';
import { PAGE_PARAMETERS } from '../../archive/dto/archive.schemas';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  EDISCOVERY_EXAMPLES as X,
  LegalHoldListQuerySchema,
  type LegalHoldListQuery,
  type LegalHoldPage,
  LegalHoldPageSchema,
  LegalHoldSchema,
  type LegalHoldView,
  type ReleaseHoldBody,
  ReleaseHoldBodySchema,
} from '../dto/ediscovery.schemas';
import { EDISCOVERY_OPERATIONS } from '../ediscovery.constants';
import { LegalHoldsService } from '../services/legal-holds.service';

export const ApiHoldId = (): MethodDecorator =>
  ApiParam({ name: 'holdId', description: 'Legal hold public id (UUID)', format: 'uuid' });

const ApiHoldNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown legal hold, or one of another organization', [C.legalHoldNotFound]);

const CONFIDENTIAL =
  ' Who is under hold is confidential: `archive:legal_hold` or `ediscovery:manage` is required ' +
  '(`archive:read` alone is not enough).';

/**
 * Organization-wide legal holds (step 8.1 §4.4 #24–#26; A12). Holds are created inside an
 * eDiscovery case (POST /ediscovery/cases/{caseId}/holds). Translation only.
 */
@ApiTags('ediscovery')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'legal-holds', version: '1' })
export class LegalHoldsController {
  constructor(private readonly holds: LegalHoldsService) {}

  @Get()
  @RequireAnyPermission(P.legalHold, P.ediscovery)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List legal holds',
    description:
      'Every legal hold of your organization, newest first (`status`, `caseId` filters), with ' +
      'its criteria and case. Holds created before step 8.1 have no case and the 5.3 criteria ' +
      'subset; criteria that cannot be read hold every record (fail-safe). v1 list ' +
      '(`legal_holds`).' +
      CONFIDENTIAL,
  })
  @ApiListQuery(LegalHoldListQuerySchema, {
    ...PAGE_PARAMETERS,
    status: '`active`, `released`; comma list',
    caseId: 'Holds of one case (public id)',
    sort: '`-id` (newest first)',
  })
  @ApiArchiveResponse(200, LegalHoldPageSchema, X.holdPage, 'One page of holds')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(LegalHoldListQuerySchema)) query: LegalHoldListQuery,
  ): Promise<LegalHoldPage> {
    return this.holds.list(principal, scope, query);
  }

  @Get(':holdId')
  @RequireAnyPermission(P.legalHold, P.ediscovery)
  @ApiOperation({
    summary: 'Get a legal hold',
    description:
      'One legal hold of your organization. "Which records does it cover" is answered by ' +
      'GET /archive/messages?holdId=… (informational; holds are enforced at disposal time).' +
      CONFIDENTIAL,
  })
  @ApiHoldId()
  @ApiArchiveResponse(200, LegalHoldSchema, X.hold, 'The hold')
  @ApiArchiveForbidden()
  @ApiHoldNotFound()
  @ApiArchiveUnavailable()
  get(@CurrentScope() scope: TenantScope, @Param('holdId') holdId: string): Promise<LegalHoldView> {
    return this.holds.get(scope, holdId);
  }

  @Post(':holdId/release')
  @RequirePermissions(P.legalHold)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.holdRelease)
  @ApiOperation({
    summary: 'Release a legal hold',
    description:
      'Sets the hold `released` with your reason; records it held become eligible for ' +
      'disposal at their next expiry evaluation (never immediately). A released hold cannot be ' +
      'reactivated (`409 legal_hold_already_released`): create a new hold. Audited ' +
      '`legal_hold.released`. Requires the Idempotency-Key header; rate class `sensitive`. ' +
      'MFA-authenticated users only.',
  })
  @ApiHoldId()
  @ApiBody({
    schema: zodToOpenApi(ReleaseHoldBodySchema, { io: 'input' }),
    examples: { settled: { value: X.release } },
  })
  @ApiArchiveResponse(200, LegalHoldSchema, X.released, 'The released hold', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden()
  @ApiHoldNotFound()
  @ApiArchiveConflicts([C.legalHoldAlreadyReleased], '`legal_hold_already_released`', true)
  @ApiArchiveUnavailable()
  async release(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('holdId') holdId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(ReleaseHoldBodySchema)) body: ReleaseHoldBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LegalHoldView> {
    const result = await this.holds.release(
      principal,
      scope,
      holdId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
