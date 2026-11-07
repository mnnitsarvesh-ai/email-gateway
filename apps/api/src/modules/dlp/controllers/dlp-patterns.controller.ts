import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import {
  ApiDlpId,
  ApiInconsistentRead,
  ApiPatternConflict,
  ApiPatternInvalid,
  ApiPatternNotFound,
  DLP_APPLY_NOTE,
  DLP_MANAGE,
  DLP_READ,
  DlpController,
  dlpIdPipe,
} from '../api-docs';
import {
  type DlpDeleteQuery,
  DlpDeleteQuerySchema,
  type DlpListQuery,
  DlpListQuerySchema,
  type DlpPatternCreate,
  DlpPatternCreateSchema,
  type DlpPatternPage,
  DlpPatternPageSchema,
  type DlpPatternTest,
  type DlpPatternTestResult,
  DlpPatternTestResultSchema,
  DlpPatternTestSchema,
  type DlpPatternUpdate,
  DlpPatternUpdateSchema,
  type DlpPatternView,
  DlpPatternViewSchema,
} from '../dto/dlp.schemas';
import { DlpPatternsService } from '../services/dlp-patterns.service';

const SAFETY =
  'Validated by the D9 safety rules: RE2 syntax through re2js (linear time; backreferences, ' +
  'lookaround and possessive constructs refused), at most DLP_CUSTOM_PATTERN_MAX_LENGTH ' +
  'characters, counted repetition ≤ 100 with a nested product ≤ 1 000, no empty match, at most ' +
  '50 matches and DLP_CUSTOM_PATTERN_PROBE_MAX_MS on the packaged probe corpus; a refusal is a ' +
  '`400` whose code names the rule (never the pattern).';

/** Tenant custom patterns and the pattern test (step 4.5 D9, D21). Translation only. */
@DlpController()
@Controller({ path: 'dlp/patterns', version: '1' })
export class DlpPatternsController {
  constructor(private readonly patterns: DlpPatternsService) {}

  @Get()
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'List the custom patterns',
    description:
      'Newest first, cursor-paginated, optionally only enabled or disabled. From the read replica.',
  })
  @ApiQueryFrom(DlpListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpPatternPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpListQuerySchema)) query: DlpListQuery,
  ): Promise<DlpPatternPage> {
    return this.patterns.list(scope, query);
  }

  @Post('test')
  @RequirePermissions(DLP_MANAGE)
  @RateLimit({ bucket: 'dlp-pattern-test', limit: 30, windowSeconds: 60, by: 'principal' })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Test a custom pattern on a sample',
    description:
      'Validates the pattern as create does and returns at most 50 matches of the sample (≤ ' +
      '4 096 characters) with offsets, the masked match (per `maskStyle`), the validator ' +
      'result and whether a context keyword is nearby. Persists nothing; the sample and the ' +
      'pattern are never logged, audited or echoed (also not in errors). 30 calls per caller ' +
      'per minute. Use synthetic samples.',
  })
  @ApiBody({ schema: zodToOpenApi(DlpPatternTestSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpPatternTestResultSchema) })
  @ApiErrors(400, 401, 403, 429)
  test(
    @Body(new ZodValidationPipe(DlpPatternTestSchema)) body: DlpPatternTest,
  ): DlpPatternTestResult {
    return this.patterns.test(body);
  }

  @Get(':id')
  @RequirePermissions(DLP_READ)
  @ApiOperation({ summary: 'Get a custom pattern', description: 'From the read replica.' })
  @ApiDlpId('id', 'Custom pattern public id')
  @ApiOkResponse({ schema: zodToOpenApi(DlpPatternViewSchema) })
  @ApiErrors(400, 401, 403)
  @ApiPatternNotFound()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
  ): Promise<DlpPatternView> {
    return this.patterns.get(scope, id);
  }

  @Post()
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Create a custom pattern',
    description:
      `${SAFETY} Unique name per organization (\`409 dlp_pattern_exists\`), at most ` +
      'DLP_CUSTOM_PATTERNS_MAX_PER_TENANT (`409 dlp_limit_reached`). Matches are masked per ' +
      '`maskStyle` everywhere outside the encrypted evidence. Audited as ' +
      `\`dlp_pattern.created\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiBody({ schema: zodToOpenApi(DlpPatternCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(DlpPatternViewSchema) })
  @ApiErrors(401, 403)
  @ApiPatternInvalid()
  @ApiPatternConflict()
  @ApiInconsistentRead()
  create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(DlpPatternCreateSchema)) body: DlpPatternCreate,
    @Client() client: ClientContext,
  ): Promise<DlpPatternView> {
    return this.patterns.create(principal, scope, body, client);
  }

  @Patch(':id')
  @RequirePermissions(DLP_MANAGE)
  @ApiOperation({
    summary: 'Update a custom pattern',
    description:
      `\`version\` must be the current version (\`409 version_conflict\`). ${SAFETY} ` +
      'Audited as `dlp_pattern.updated` with the pattern before and after. ' +
      DLP_APPLY_NOTE,
  })
  @ApiDlpId('id', 'Custom pattern public id')
  @ApiBody({ schema: zodToOpenApi(DlpPatternUpdateSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(DlpPatternViewSchema) })
  @ApiErrors(401, 403)
  @ApiPatternInvalid()
  @ApiPatternNotFound()
  @ApiPatternConflict()
  @ApiInconsistentRead()
  update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Body(new ZodValidationPipe(DlpPatternUpdateSchema)) body: DlpPatternUpdate,
    @Client() client: ClientContext,
  ): Promise<DlpPatternView> {
    return this.patterns.update(principal, scope, id, body, client);
  }

  @Delete(':id')
  @RequirePermissions(DLP_MANAGE)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a custom pattern',
    description:
      'Optionally only at `?version=`. Refused while a rule selects it (`409 ' +
      `dlp_pattern_in_use\`). Audited as \`dlp_pattern.deleted\`. ${DLP_APPLY_NOTE}`,
  })
  @ApiDlpId('id', 'Custom pattern public id')
  @ApiQueryFrom(DlpDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401, 403)
  @ApiPatternNotFound()
  @ApiPatternConflict()
  @ApiInconsistentRead()
  async remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', dlpIdPipe) id: string,
    @Query(new ZodValidationPipe(DlpDeleteQuerySchema)) query: DlpDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.patterns.remove(principal, scope, id, query.version, client);
  }
}
