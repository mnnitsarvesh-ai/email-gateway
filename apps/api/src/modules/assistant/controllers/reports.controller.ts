import { Controller, Get, Header, Param } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import {
  ApiAssistantForbidden,
  ApiAssistantResponse,
  ApiAssistantUnavailable,
  USER_ONLY_RULE,
} from '../api-docs';
import { ASSISTANT_PERMISSIONS as P } from '../assistant.constants';
import { ASSISTANT_ERROR_CODES as C } from '../assistant.errors';
import {
  ASSISTANT_EXAMPLES as X,
  PublicIdSchema,
  ReportResultSchema,
  type ReportResultView,
} from '../dto/assistant.schemas';
import { ReportsService } from '../services/reports/reports.service';
import { userOf } from './assistant.controller';

const publicId = new ZodValidationPipe(PublicIdSchema);

/**
 * The reports of the assistant (step AI-R §4.1, D6; ADR-0095). Translation only: ownership and
 * the object read live in `ReportsService`. Tagged `assistant`, so the registry classifies the
 * route `not_applicable` (the model never calls it).
 */
@ApiTags('assistant')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@Controller({ path: 'assistant/reports', version: '1' })
export class AssistantReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get(':reportId')
  @RequirePermissions(P.use)
  @Header('Cache-Control', 'no-store')
  @ApiParam({ name: 'reportId', description: 'Report public id (UUID)', format: 'uuid' })
  @ApiOperation({
    summary: 'Get an assistant report',
    description:
      'One of your own security reports generated in chat (`report_generate`): its metadata ' +
      '(`assistant-report-view/1`: status, period, sections, omitted sections with their ' +
      'reasons, summary figures, size, SHA-256, template version) with its emails (newest ' +
      'first, at most 20; the address is null after the content purge) and, while the report ' +
      'is `available`, the stored HTML. The HTML is a self-contained, inert document (no ' +
      'script, no link, no external resource) and is served only inside this JSON: show it in ' +
      'a sandboxed iframe (`srcdoc`, `sandbox=""`). `html` is null for `pending`, `failed` and ' +
      '`purged` reports (purged with the conversation content: still `200`, so the card can ' +
      'show the state). A report belongs to the user, organization (and platform override) ' +
      'that generated it; any other report answers `404 assistant_report_not_found`. ' +
      '`Cache-Control: no-store`.' +
      USER_ONLY_RULE,
  })
  @ApiAssistantResponse(200, ReportResultSchema, X.report, 'The report and its HTML')
  @ApiCodedError(404, 'Unknown report, or one of another user, organization or platform override', [
    C.reportNotFound,
  ])
  @ApiAssistantForbidden()
  @ApiAssistantUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('reportId', publicId) reportId: string,
  ): Promise<ReportResultView> {
    return this.reports.get(userOf(principal), scope, reportId);
  }
}
