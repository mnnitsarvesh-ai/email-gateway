import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
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
  ApiArchiveUnprocessable,
  ApiKeyedErrors,
  ArchiveIdempotency,
} from '../../archive/api-docs';
import { ARCHIVE_PERMISSIONS as P } from '../../archive/archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../../archive/archive.errors';
import { PAGE_PARAMETERS } from '../../archive/dto/archive.schemas';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  CaseDetailSchema,
  type CaseDetailView,
  CaseListQuerySchema,
  type CaseListQuery,
  type CasePage,
  CasePageSchema,
  type CreateCaseBody,
  CreateCaseBodySchema,
  type CreateHoldBody,
  CreateHoldBodySchema,
  EDISCOVERY_EXAMPLES as X,
  LegalHoldSchema,
  type LegalHoldView,
  type UpdateCaseBody,
  UpdateCaseBodySchema,
} from '../dto/ediscovery.schemas';
import { EDISCOVERY_OPERATIONS } from '../ediscovery.constants';
import { EdiscoveryCasesService } from '../services/ediscovery-cases.service';
import { LegalHoldsService } from '../services/legal-holds.service';

export const ApiCaseId = (): MethodDecorator =>
  ApiParam({ name: 'caseId', description: 'eDiscovery case public id (UUID)', format: 'uuid' });

export const ApiCaseNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown case, or a case of another organization', [C.caseNotFound]);

const ENTITLED = ' Needs the plan feature `archiving` (`403 archiving_not_enabled`).';

/**
 * eDiscovery cases, custodians and case-scoped legal holds (step 8.1 §4.4 #27–#32; A12, A18).
 * Translation only.
 */
@ApiTags('ediscovery')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'ediscovery/cases', version: '1' })
export class EdiscoveryCasesController {
  constructor(
    private readonly cases: EdiscoveryCasesService,
    private readonly holds: LegalHoldsService,
  ) {}

  @Get()
  @RequirePermissions(P.ediscovery)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List eDiscovery cases',
    description:
      'The cases of your organization, newest first. Every holder of `ediscovery:manage` sees ' +
      'every case (per-case access lists are not offered). v1 list (`ediscovery_cases`).',
  })
  @ApiListQuery(CaseListQuerySchema, {
    ...PAGE_PARAMETERS,
    status: '`open`, `closed`; comma list',
    sort: '`-id` (newest first)',
  })
  @ApiArchiveResponse(200, CasePageSchema, X.casePage, 'One page of cases')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(CaseListQuerySchema)) query: CaseListQuery,
  ): Promise<CasePage> {
    return this.cases.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(P.ediscovery)
  @HttpCode(HttpStatus.CREATED)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.caseCreate)
  @ApiOperation({
    summary: 'Create an eDiscovery case',
    description:
      'A case with a unique name (`409 ediscovery_case_name_taken`), an optional description ' +
      'and matter reference and its custodians (addresses, lower-cased; ≤ ' +
      'ARCHIVE_CASE_MAX_CUSTODIANS: `422 ediscovery_custodian_limit`; linked to the ' +
      'organization user with that address). Custodian addresses drive case searches and holds, ' +
      'so a non-empty list needs `message:reveal` (`403 archive_filter_forbidden`, `filter: ' +
      'custodians`). At most ARCHIVE_CASES_MAX_OPEN_PER_ORG open cases ' +
      '(`422 ediscovery_case_limit`).' +
      ENTITLED +
      ' Audited `ediscovery.case_created`. Requires the Idempotency-Key header; rate class ' +
      '`sensitive`.',
  })
  @ApiBody({
    schema: zodToOpenApi(CreateCaseBodySchema, { io: 'input' }),
    examples: { matter: { value: X.caseCreate } },
  })
  @ApiArchiveResponse(201, CaseDetailSchema, X.caseDetail, 'The created case', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden(
    [C.notEnabled, C.filterForbidden],
    '`archiving_not_enabled`, `archive_filter_forbidden` (`filter: custodians`)',
  )
  @ApiArchiveConflicts([C.caseNameTaken], '`ediscovery_case_name_taken`', true)
  @ApiArchiveUnprocessable(
    [C.caseLimit, C.custodianLimit],
    '`ediscovery_case_limit` / `ediscovery_custodian_limit` (`limit`)',
    true,
    { limit: { type: 'integer' } },
  )
  @ApiArchiveUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(CreateCaseBodySchema)) body: CreateCaseBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CaseDetailView> {
    const result = await this.cases.create(principal, scope, idempotencyKey, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':caseId')
  @RequirePermissions(P.ediscovery)
  @ApiOperation({
    summary: 'Get an eDiscovery case',
    description:
      'One case with its custodians (at most ARCHIVE_CASE_MAX_CUSTODIANS) and counts of ' +
      'active holds, searches and exports. From the read replica.',
  })
  @ApiCaseId()
  @ApiArchiveResponse(200, CaseDetailSchema, X.caseDetail, 'The case')
  @ApiArchiveForbidden()
  @ApiCaseNotFound()
  @ApiArchiveUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
  ): Promise<CaseDetailView> {
    return this.cases.get(scope, caseId);
  }

  @Patch(':caseId')
  @RequirePermissions(P.ediscovery)
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.caseUpdate)
  @ApiOperation({
    summary: 'Update an eDiscovery case',
    description:
      'Changes any of `name`, `description`, `matterReference` and `custodians` (the complete ' +
      'list replaces the current one; a non-empty list needs `message:reveal`: `403 ' +
      'archive_filter_forbidden`, `filter: custodians`) with `expectedRowVersion` (`409 ' +
      'ediscovery_case_conflict` ' +
      'with `currentRowVersion`). Closed cases are read-only (`409 ediscovery_case_closed`). ' +
      'Holds already created keep the custodians they snapshotted.' +
      ENTITLED +
      ' Audited `ediscovery.case_updated` (changed paths, custodian count). Requires the ' +
      'Idempotency-Key header; rate class `sensitive`.',
  })
  @ApiCaseId()
  @ApiBody({
    schema: zodToOpenApi(UpdateCaseBodySchema, { io: 'input' }),
    examples: { custodians: { value: X.caseUpdate } },
  })
  @ApiArchiveResponse(200, CaseDetailSchema, { ...X.caseDetail, rowVersion: 2 }, 'The case', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden(
    [C.notEnabled, C.filterForbidden],
    '`archiving_not_enabled`, `archive_filter_forbidden` (`filter: custodians`)',
  )
  @ApiCaseNotFound()
  @ApiArchiveConflicts(
    [C.caseConflict, C.caseClosed, C.caseNameTaken],
    '`ediscovery_case_conflict` (`currentRowVersion`), `ediscovery_case_closed`, ' +
      '`ediscovery_case_name_taken`',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiArchiveUnprocessable([C.custodianLimit], '`ediscovery_custodian_limit` (`limit`)', true, {
    limit: { type: 'integer' },
  })
  @ApiArchiveUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(UpdateCaseBodySchema)) body: UpdateCaseBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CaseDetailView> {
    const result = await this.cases.update(
      principal,
      scope,
      caseId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post(':caseId/close')
  @RequirePermissions(P.ediscovery)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.caseClose)
  @ApiOperation({
    summary: 'Close an eDiscovery case',
    description:
      'Closes an open case (read-only afterwards). Refused while the case has active legal ' +
      'holds (`409 ediscovery_case_has_active_holds`, `activeHolds`): release them first.' +
      ENTITLED +
      ' Audited `ediscovery.case_closed`. Requires the Idempotency-Key header; rate class ' +
      '`sensitive`. MFA-authenticated users only.',
  })
  @ApiCaseId()
  @ApiArchiveResponse(
    200,
    CaseDetailSchema,
    { ...X.caseDetail, status: 'closed', closedAt: '2026-12-01T09:00:00.000Z', rowVersion: 2 },
    'The closed case',
    true,
  )
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiCaseNotFound()
  @ApiArchiveConflicts(
    [C.caseClosed, C.caseHasActiveHolds, C.caseConflict],
    '`ediscovery_case_closed`, `ediscovery_case_has_active_holds` (`activeHolds`)',
    true,
    { activeHolds: { type: 'integer' } },
  )
  @ApiArchiveUnavailable()
  async close(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CaseDetailView> {
    const result = await this.cases.close(principal, scope, caseId, idempotencyKey, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post(':caseId/holds')
  @RequirePermissions(P.legalHold, P.ediscovery)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @ArchiveIdempotency(EDISCOVERY_OPERATIONS.holdCreate)
  @ApiOperation({
    summary: 'Place a legal hold in a case',
    description:
      'Creates an immutable legal hold of an open case (`409 ediscovery_case_closed`) with ' +
      '`archive-hold/1` criteria: custodian addresses (or the case’s custodians snapshotted ' +
      'with `useCaseCustodians`; `422 legal_hold_criteria_invalid` `reason: ' +
      'custodians_conflict | no_case_custodians`; explicit addresses need `message:reveal`: ' +
      '`403 archive_filter_forbidden`, `filter: criteria.custodians`), a `from`/`to` range ' +
      '(whole UTC days for ' +
      'dates) and directions. Empty criteria hold every record. A matching hold blocks every ' +
      'disposal (retention expiry, review disposal, quarantine deletion, organization ' +
      'deletion) until it is released. At most ARCHIVE_HOLDS_MAX_ACTIVE_PER_ORG active holds ' +
      '(`422 legal_hold_limit_reached`). Audited `legal_hold.created` (criteria names and ' +
      'custodian count, never addresses). Requires the Idempotency-Key header; rate class ' +
      '`sensitive`. MFA-authenticated users only.',
  })
  @ApiCaseId()
  @ApiBody({
    schema: zodToOpenApi(CreateHoldBodySchema, { io: 'input' }),
    examples: { caseCustodians: { value: X.holdCreate } },
  })
  @ApiArchiveResponse(201, LegalHoldSchema, X.hold, 'The created hold', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.filterForbidden], '`archive_filter_forbidden` (`filter`)')
  @ApiCaseNotFound()
  @ApiArchiveConflicts([C.caseClosed], '`ediscovery_case_closed`', true)
  @ApiArchiveUnprocessable(
    [C.legalHoldLimitReached, C.legalHoldCriteriaInvalid],
    '`legal_hold_limit_reached` (`limit`), `legal_hold_criteria_invalid` (`reason`)',
    true,
    { limit: { type: 'integer' }, reason: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async createHold(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('caseId') caseId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(CreateHoldBodySchema)) body: CreateHoldBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LegalHoldView> {
    const result = await this.holds.create(
      principal,
      scope,
      caseId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
