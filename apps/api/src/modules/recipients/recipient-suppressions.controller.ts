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
  Query,
  Res,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiNoContentResponse,
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
  RequirePermissions,
} from '../../auth-contracts/decorators';
import type { Principal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_KEY_INVALID,
  IDEMPOTENCY_KEY_REQUIRED,
  IDEMPOTENCY_KEY_REUSED,
  IDEMPOTENCY_REPLAYED_HEADER,
  IDEMPOTENCY_REQUEST_IN_PROGRESS,
} from '../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { DELIVERY_READ } from '../deliveries/api-docs';
import {
  ApiCreatedExample,
  ApiInconsistentRead,
  ApiListErrors,
  ApiListQuery,
  ApiOkExample,
  SCAN_BUDGET_RULE,
  TransactionalIdempotency,
} from '../messages/api-docs';
import {
  CreateSuppressionBodySchema,
  SUPPRESSION_EXAMPLES,
  SUPPRESSION_LIST_PARAMETERS,
  type SuppressionListQuery,
  SuppressionListQuerySchema,
  type SuppressionPage,
  SuppressionPageSchema,
  SuppressionSchema,
  type SuppressionView,
} from './recipient-suppressions.schemas';
import { OPERATIONS, RecipientSuppressionsService } from './recipient-suppressions.service';
import {
  SUPPRESSION_EXISTS,
  SUPPRESSION_LIMIT_REACHED,
  SUPPRESSION_NOT_FOUND,
} from './recipients.errors';

/** Permission of the suppression mutations (seed catalog, step 6.1 §3.6). */
export const SUPPRESSION_MANAGE = 'delivery:suppression_manage';

const ApiSuppressionId = (): MethodDecorator =>
  ApiParam({
    name: 'suppressionId',
    description: 'Decimal id of the suppression',
    example: '4711',
  });

const ApiIdempotencyErrors = (): MethodDecorator =>
  ApiCodedError(
    400,
    'The body or id is invalid (`validation_failed`), or the Idempotency-Key header is missing ' +
      '(`idempotency_key_required`) or invalid (`idempotency_key_invalid`)',
    ['validation_failed', IDEMPOTENCY_KEY_REQUIRED, IDEMPOTENCY_KEY_INVALID],
  );

const ApiKeyReused = (): MethodDecorator =>
  ApiCodedError(
    422,
    'The Idempotency-Key was already used for a different request (body, path, operation or caller)',
    [IDEMPOTENCY_KEY_REUSED],
  );

const ApiSuppressionNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown id, or a suppression of another organization', [
    SUPPRESSION_NOT_FOUND,
  ]);

/**
 * The recipient suppression list of the caller's organization (step 6.1 WP2, §3.3): the
 * `delivery_suppressions` rows the smtp-adapter enforces on outbound mail. Translation only
 * (RecipientSuppressionsService). Mutations require an Idempotency-Key and run in the
 * `sensitive` rate class.
 */
@ApiTags('recipients')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'recipients/suppressions', version: '1' })
export class RecipientSuppressionsController {
  constructor(private readonly suppressions: RecipientSuppressionsService) {}

  @Get()
  @RequirePermissions(DELIVERY_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List recipient suppressions',
    description:
      'The addresses outbound mail of your organization is not delivered to (step 2.2 D11: ' +
      'suppressed while `expiresAt` is null or in the future), newest first (keyset `id` over ' +
      '`(organization_id, id)`): hard bounces and complaints recorded by the gateway, and ' +
      'manual and unsubscribe entries created here (`source: api`). `address` uses the unique ' +
      'key; `reason` and `active` filters are scan-bounded. ' +
      SCAN_BUDGET_RULE +
      ' From the read replica.',
  })
  @ApiListQuery(SuppressionListQuerySchema, SUPPRESSION_LIST_PARAMETERS)
  @ApiOkExample(SuppressionPageSchema, SUPPRESSION_EXAMPLES.page)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiInconsistentRead()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(SuppressionListQuerySchema)) query: SuppressionListQuery,
  ): Promise<SuppressionPage> {
    return this.suppressions.list(principal, scope, query);
  }

  @Get(':suppressionId')
  @RequirePermissions(DELIVERY_READ)
  @ApiOperation({
    summary: 'Get a recipient suppression',
    description:
      'One suppression of your organization by its decimal id, with `active` computed now. ' +
      'From the read replica: right after a create it may still be `404` for a moment.',
  })
  @ApiSuppressionId()
  @ApiOkExample(SuppressionSchema, SUPPRESSION_EXAMPLES.item)
  @ApiErrors(400, 401, 403)
  @ApiSuppressionNotFound()
  @ApiInconsistentRead()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('suppressionId') suppressionId: string,
  ): Promise<SuppressionView> {
    return this.suppressions.get(scope, suppressionId);
  }

  @Post()
  @RequirePermissions(SUPPRESSION_MANAGE)
  @TransactionalIdempotency(OPERATIONS.create)
  @ApiOperation({
    summary: 'Suppress a recipient address',
    description:
      'Adds an address (trimmed, lower-cased) to the suppression list with reason `manual` ' +
      '(default) or `unsubscribe` and an optional expiry (future, at most 3650 days ahead; ' +
      'none = permanent). Outbound mail to it is not delivered from the next attempt on (the ' +
      'delivery shows `suppressed`). `409 suppression_exists` (with the existing `id`) when the ' +
      'address is already listed, active or expired (delete it first to replace it); `409 ' +
      'suppression_limit_reached` at RECIPIENT_SUPPRESSIONS_MAX_MANUAL manual and unsubscribe ' +
      'entries. Requires the Idempotency-Key header: effect, audit row ' +
      '(`recipient_suppression.created`, the address only as SHA-256) and the stored response ' +
      'commit together. Rate class `sensitive`.',
  })
  @ApiBody({
    schema: zodToOpenApi(CreateSuppressionBodySchema, { io: 'input' }),
    examples: { unsubscribe: { value: SUPPRESSION_EXAMPLES.create } },
  })
  @ApiCreatedExample(
    SuppressionSchema,
    SUPPRESSION_EXAMPLES.item,
    'Suppression created (or the stored response replayed)',
  )
  @ApiIdempotencyErrors()
  @ApiErrors(401, 403)
  @ApiCodedError(
    409,
    '`suppression_exists` (`id` of the existing row), `suppression_limit_reached` (`limit`), or ' +
      '`idempotency_request_in_progress`. Not stored under the Idempotency-Key.',
    [SUPPRESSION_EXISTS, SUPPRESSION_LIMIT_REACHED, IDEMPOTENCY_REQUEST_IN_PROGRESS],
    { id: { type: 'string' }, limit: { type: 'integer' } },
  )
  @ApiKeyReused()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SuppressionView> {
    const result = await this.suppressions.create(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete(':suppressionId')
  @RequirePermissions(SUPPRESSION_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @TransactionalIdempotency(OPERATIONS.delete)
  @ApiOperation({
    summary: 'Remove a recipient suppression (unsuppress)',
    description:
      'Removes a manual, unsubscribe, hard-bounce or complaint entry of your organization, so ' +
      'outbound mail to the address is delivered again from the next attempt on. Requires the ' +
      'Idempotency-Key header: repeating the request with the same key answers `204` again ' +
      '(`Idempotency-Replayed: true`); a new key for a removed entry is `404`. Audited ' +
      '(`recipient_suppression.deleted` with the former reason and source, the address only ' +
      'as SHA-256). Rate class `sensitive`.',
  })
  @ApiSuppressionId()
  @ApiNoContentResponse({
    description: 'Removed (or the stored response of an earlier identical request replayed)',
    headers: {
      [IDEMPOTENCY_REPLAYED_HEADER]: {
        description: '`true` when this is the stored response of an earlier identical request',
        schema: { type: 'string', enum: ['true'] },
      },
    },
  })
  @ApiIdempotencyErrors()
  @ApiErrors(401, 403)
  @ApiSuppressionNotFound()
  @ApiCodedError(409, 'A request with this Idempotency-Key is still in progress', [
    IDEMPOTENCY_REQUEST_IN_PROGRESS,
  ])
  @ApiKeyReused()
  async delete(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('suppressionId') suppressionId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    const result = await this.suppressions.delete(
      principal,
      scope,
      { suppressionId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
  }
}
