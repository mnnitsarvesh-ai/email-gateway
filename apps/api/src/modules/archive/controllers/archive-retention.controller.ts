import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  Res,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
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
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ApiArchiveUnprocessable,
  ApiKeyedErrors,
  ApiPolicyIdParam,
  ArchiveIdempotency,
} from '../api-docs';
import { ARCHIVE_OPERATIONS, ARCHIVE_PERMISSIONS as P } from '../archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../archive.errors';
import {
  ARCHIVE_EXAMPLES as X,
  type CreateRetentionPolicyBody,
  CreateRetentionPolicyBodySchema,
  PAGE_PARAMETERS,
  RetentionPolicyListQuerySchema,
  type RetentionPolicyListQuery,
  type RetentionPolicyPage,
  RetentionPolicyPageSchema,
  RetentionPolicySchema,
  type RetentionPolicyView,
  type UpdateRetentionPolicyBody,
  UpdateRetentionPolicyBodySchema,
} from '../dto/archive.schemas';
import { ArchiveRetentionService } from '../services/archive-retention.service';

const ApiPolicyNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown or deleted retention policy, or one of another organization', [
    C.retentionPolicyNotFound,
  ]);

const RETENTION_RULES =
  '`retentionDays` is capped by the plan limit `archive_retention_days` and ' +
  'ARCHIVE_MAX_RETENTION_DAYS (`422 archive_retention_exceeds_limit`, `limit`); criteria ' +
  'follow `archive-retention/1` (domain and department ids must be your organization’s: `422 ' +
  'archive_scope_reference_invalid`). Needs the plan feature `archiving`. Changes apply to new ' +
  'captures; a longer retention also protects existing records when they reach their stored ' +
  'date (lazy, extend-only), a shorter one never shortens them.';

/**
 * Retention policies (step 8.1 §4.4 #3–#7, A11). Translation only.
 */
@ApiTags('archive')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'archive/retention-policies', version: '1' })
export class ArchiveRetentionController {
  constructor(private readonly retention: ArchiveRetentionService) {}

  @Get()
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List retention policies',
    description:
      'The live retention policies of your organization in selection order (`priority`, then ' +
      'creation): the first whose criteria match a record wins at capture, else the default ' +
      'policy of the archive settings (`isDefault`). v1 list (`archive_retention_policies`).',
  })
  @ApiListQuery(RetentionPolicyListQuerySchema, { ...PAGE_PARAMETERS, sort: '`priority`' })
  @ApiArchiveResponse(200, RetentionPolicyPageSchema, X.policyPage, 'One page of policies')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(RetentionPolicyListQuerySchema)) query: RetentionPolicyListQuery,
  ): Promise<RetentionPolicyPage> {
    return this.retention.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(P.manage)
  @HttpCode(HttpStatus.CREATED)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.retentionCreate)
  @ApiOperation({
    summary: 'Create a retention policy',
    description:
      'Creates a policy: name (unique: `409 archive_retention_policy_name_taken`), ' +
      '`retentionDays`, `onExpiry` (`delete` | `review`), `priority`, `criteria`. At most ' +
      'ARCHIVE_RETENTION_POLICIES_MAX_PER_ORG live policies (`422 archive_retention_policy_limit`). ' +
      RETENTION_RULES +
      ' Audited `archive.retention_policy_created`. Requires the Idempotency-Key header; rate ' +
      'class `sensitive`.',
  })
  @ApiBody({
    schema: zodToOpenApi(CreateRetentionPolicyBodySchema, { io: 'input' }),
    examples: { sevenYears: { value: X.policyCreate } },
  })
  @ApiArchiveResponse(201, RetentionPolicySchema, X.policy, 'The created policy', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiArchiveConflicts([C.retentionPolicyNameTaken], '`archive_retention_policy_name_taken`', true)
  @ApiArchiveUnprocessable(
    [C.retentionExceedsLimit, C.retentionPolicyLimit, C.scopeReferenceInvalid],
    '`archive_retention_exceeds_limit` / `archive_retention_policy_limit` (`limit`), ' +
      '`archive_scope_reference_invalid` (`path`)',
    true,
    { limit: { type: 'integer' }, path: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(CreateRetentionPolicyBodySchema)) body: CreateRetentionPolicyBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RetentionPolicyView> {
    const result = await this.retention.create(principal, scope, idempotencyKey, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':policyId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get a retention policy',
    description: 'One live retention policy of your organization. From the read replica.',
  })
  @ApiPolicyIdParam()
  @ApiArchiveResponse(200, RetentionPolicySchema, X.policy, 'The policy')
  @ApiArchiveForbidden()
  @ApiPolicyNotFound()
  @ApiArchiveUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('policyId') policyId: string,
  ): Promise<RetentionPolicyView> {
    return this.retention.get(scope, policyId);
  }

  @Put(':policyId')
  @RequirePermissions(P.manage)
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.retentionUpdate)
  @ApiOperation({
    summary: 'Replace a retention policy',
    description:
      'Replaces name, `retentionDays`, `onExpiry`, `priority` and `criteria` with ' +
      '`expectedRowVersion` (`409 archive_retention_policy_conflict` with ' +
      '`currentRowVersion`). ' +
      RETENTION_RULES +
      ' Audited `archive.retention_policy_updated` (changed paths). Requires the ' +
      'Idempotency-Key header; rate class `sensitive`.',
  })
  @ApiPolicyIdParam()
  @ApiBody({
    schema: zodToOpenApi(UpdateRetentionPolicyBodySchema, { io: 'input' }),
    examples: { longer: { value: X.policyUpdate } },
  })
  @ApiArchiveResponse(
    200,
    RetentionPolicySchema,
    { ...X.policy, retentionDays: 2920, rowVersion: 2 },
    'The policy',
    true,
  )
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiPolicyNotFound()
  @ApiArchiveConflicts(
    [C.retentionPolicyConflict, C.retentionPolicyNameTaken],
    '`archive_retention_policy_conflict` (`currentRowVersion`), `archive_retention_policy_name_taken`',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiArchiveUnprocessable(
    [C.retentionExceedsLimit, C.scopeReferenceInvalid],
    '`archive_retention_exceeds_limit` (`limit`), `archive_scope_reference_invalid` (`path`)',
    true,
    { limit: { type: 'integer' }, path: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId') policyId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(UpdateRetentionPolicyBodySchema)) body: UpdateRetentionPolicyBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RetentionPolicyView> {
    const result = await this.retention.update(
      principal,
      scope,
      policyId,
      idempotencyKey,
      body,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete(':policyId')
  @RequirePermissions(P.manage)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.retentionDelete)
  @ApiOperation({
    summary: 'Delete a retention policy',
    description:
      'Soft delete: the policy stops matching new captures; records captured under it keep ' +
      'their stored retention. The default policy of the archive settings cannot be deleted ' +
      '(`409 archive_retention_policy_is_default`). Needs the plan feature `archiving`. ' +
      'Audited `archive.retention_policy_deleted`. Requires the Idempotency-Key header; rate ' +
      'class `sensitive`.',
  })
  @ApiPolicyIdParam()
  @ApiNoContentResponse({
    description: 'Deleted (or the stored response of an earlier identical request replayed)',
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  })
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiPolicyNotFound()
  @ApiArchiveConflicts(
    [C.retentionPolicyIsDefault, C.retentionPolicyConflict],
    '`archive_retention_policy_is_default`',
    true,
  )
  @ApiArchiveUnavailable()
  async delete(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('policyId') policyId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const result = await this.retention.delete(
      principal,
      scope,
      policyId,
      idempotencyKey,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  }
}
