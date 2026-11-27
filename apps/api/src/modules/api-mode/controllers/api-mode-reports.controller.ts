import {
  Body,
  Controller,
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
  ApiBadId,
  ApiKeyedErrors,
  ApiMailboxIdParam,
  ApiMailboxNotFound,
  ApiModeConflicts,
  ApiModeForbidden,
  ApiModeIdempotency,
  ApiModeResponse,
  ApiModeUnavailable,
  ApiModeUnprocessable,
  KEYED_RULE,
} from '../api-docs';
import { API_MODE_OPERATIONS, API_MODE_PERMISSIONS as P } from '../api-mode.constants';
import { API_MODE_ERROR_CODES as C } from '../api-mode.errors';
import {
  AddReportMailboxBodySchema,
  CLAWBACK_EXAMPLES as X,
  REPORT_LIST_PARAMETERS,
  ReportClawbackBodySchema,
  ReportClawbackResponseSchema,
  type ReportClawbackResponseView,
  ReportDetailSchema,
  type ReportDetailView,
  type ReportListQuery,
  ReportListQuerySchema,
  ReportMailboxChangeSchema,
  type ReportMailboxChangeView,
  ReportMailboxListSchema,
  type ReportMailboxListView,
  type ReportPage,
  ReportPageSchema,
  SetReportMailboxBodySchema,
  TriageBodySchema,
  TriageResponseSchema,
  type TriageResponseView,
} from '../dto/api-mode-clawback.schemas';
import { ReportsService } from '../services/reports.service';

const ApiReportIdParam = (): MethodDecorator =>
  ApiParam({ name: 'reportId', description: 'User report public id (UUID)', format: 'uuid' });

const ApiReportNotFound = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown report, or one of another organization', [C.reportNotFound]);

/**
 * User-reported phishing in API mode (step API-3 C9-C12, C14 #11-#17,
 * docs/plan/steps/37-api-mode-clawback-reporting.md; ADR-0104): the reports users forwarded to a
 * report mailbox (parsed and scanned by the mailbox-worker), their triage (with group resolution
 * and the reporter's result e-mail), the clawback from a report and the report mailboxes. Reads
 * need `remediation:read`; triage and report mailboxes `remediation:write`; a clawback
 * `remediation:purge`. Translation only.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get('reports')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List API-mode user reports',
    description:
      'Messages users forwarded to a report mailbox, newest first: status, reporter (untrusted), ' +
      'identification of the original, the automatic assessment (a hint; reports never act by ' +
      'themselves), the analyst verdict, the scan facts, the group size (reports of the same ' +
      'original) and the clawback. Filters `status`, `assessment`, `analystVerdict`, `reporter`, ' +
      '`from`/`to` (at most 93 days; default the last 30). v1 list (`api_user_reports`). From ' +
      'the read replica. Needs `remediation:read`.',
  })
  @ApiListQuery(ReportListQuerySchema, REPORT_LIST_PARAMETERS)
  @ApiModeResponse(200, ReportPageSchema, X.reportPage, 'One page of reports')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ReportListQuerySchema)) query: ReportListQuery,
  ): Promise<ReportPage> {
    return this.reports.list(principal, scope, query);
  }

  @Get('reports/:reportId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an API-mode user report',
    description:
      'One report: the reporter and report mailbox, how the original was identified, its keys ' +
      '(Message-ID hash truncated; sender and subject key as untrusted mail data; attachment and ' +
      'URL counts), the original’s detection when it was found in the tenant, the scan facts and ' +
      'assessment, the analyst verdict and note (untrusted), the group members (≤ 50), the ' +
      'triage history (audit rows, ≤ 50) and the reporter feedback states. Never the message ' +
      'content. Needs `remediation:read`.',
  })
  @ApiReportIdParam()
  @ApiModeResponse(200, ReportDetailSchema, X.reportDetail, 'The report')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiReportNotFound()
  @ApiModeUnavailable()
  detail(
    @CurrentScope() scope: TenantScope,
    @Param('reportId') reportId: string,
  ): Promise<ReportDetailView> {
    return this.reports.detail(scope, reportId);
  }

  @Post('reports/:reportId/triage')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.reportTriage)
  @ApiOperation({
    summary: 'Triage an API-mode user report',
    description:
      '`{ status: in_review | resolved | rejected, verdict? (required for resolved: malicious, ' +
      'phishing_simulation, spam, clean, inconclusive), note?, notifyReporter?, applyToGroup?, ' +
      'expectedRowVersion }` on a `pending_triage` or `in_review` report; a `resolved` report ' +
      'can be reopened to `in_review` once (then `409 api_mode_report_not_reopenable`). ' +
      '`resolved` with `applyToGroup` (default true) also resolves the open reports of the same ' +
      'original; with `notifyReporter` (default: the organization’s report feedback setting) ' +
      'each reporter gets a result e-mail without the reported message’s subject or content ' +
      '(`mail.report.feedback_requested.v1`). A wrong state or version → `409 ' +
      'api_mode_report_state_conflict` (`status`, `currentRowVersion`). Audited ' +
      '`api_mode.report_triaged` per report (never the note text). Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiReportIdParam()
  @ApiBody({
    schema: zodToOpenApi(TriageBodySchema, { io: 'input' }),
    examples: { resolve: { value: X.triage } },
  })
  @ApiModeResponse(200, TriageResponseSchema, X.triaged, 'Triaged', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiReportNotFound()
  @ApiModeConflicts(
    [C.reportStateConflict, C.reportNotReopenable],
    '`api_mode_report_state_conflict` (`status`, `currentRowVersion`), ' +
      '`api_mode_report_not_reopenable`',
    true,
    { status: { type: 'string' }, currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnavailable()
  async triage(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('reportId') reportId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TriageResponseView> {
    const result = await this.reports.triage(
      principal,
      scope,
      { id: reportId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('reports/:reportId/clawback')
  @RequirePermissions(P.purge)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.reportClawback)
  @ApiOperation({
    summary: 'Create a clawback from an API-mode user report',
    description:
      '`{ expand?: { attachments?, urls?, senderSubjectHours? }, reason }`: searches the copies ' +
      'of the reported original (its Message-ID, else its sender + subject key; `expand` adds ' +
      'its attachment and URL hashes and the sender + subject within ± the hours: a campaign) ' +
      'within ± 72 hours (or the given hours) of its date. The clawback is then previewed and ' +
      'submitted like an admin search (approval rules apply). An unidentified original → `409 ' +
      'api_mode_report_original_unknown`; a rejected report → `409 ' +
      'api_mode_report_state_conflict`. Audited `api_mode.report_clawback_requested` and ' +
      '`api_mode.clawback_created`. Needs `remediation:purge`.' +
      KEYED_RULE,
  })
  @ApiReportIdParam()
  @ApiBody({
    schema: zodToOpenApi(ReportClawbackBodySchema, { io: 'input' }),
    examples: { campaign: { value: X.reportClawback } },
  })
  @ApiModeResponse(202, ReportClawbackResponseSchema, X.reportClawbackCreated, 'Searching', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiReportNotFound()
  @ApiModeConflicts(
    [C.reportOriginalUnknown, C.reportStateConflict],
    '`api_mode_report_original_unknown`, `api_mode_report_state_conflict`',
    true,
    { status: { type: 'string' } },
  )
  @ApiModeUnprocessable(
    [C.clawbackCriteriaInvalid],
    '`api_mode_clawback_criteria_invalid` (`codes`: e.g. the original is older than the copy ' +
      'retention)',
    true,
    { codes: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async clawback(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('reportId') reportId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReportClawbackResponseView> {
    const result = await this.reports.clawback(
      principal,
      scope,
      { id: reportId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('report-mailboxes')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'List the API-mode report mailboxes',
    description:
      'The mailboxes users forward suspicious mail to (no add-in): address, connection, ' +
      'provider, status, coverage, when it was designated and the last report received, plus ' +
      'the most allowed. Their copies are never remediated and never clawed back. Needs ' +
      '`remediation:read`.',
  })
  @ApiModeResponse(200, ReportMailboxListSchema, X.reportMailboxes, 'The report mailboxes')
  @ApiModeForbidden()
  @ApiModeUnavailable()
  listMailboxes(@CurrentScope() scope: TenantScope): Promise<ReportMailboxListView> {
    return this.reports.mailboxes(scope);
  }

  @Post('report-mailboxes')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.reportMailboxAdd)
  @ApiOperation({
    summary: 'Add an API-mode report mailbox by address',
    description:
      '`{ address, reason }`: a known API-mode mailbox (primary address or alias) is designated; ' +
      'an address not seen yet is added as a `discovered` mailbox of the API-mode connection of ' +
      'its domain (an `api` or `hybrid` domain linked to a provider connection; else `422 ' +
      'api_mode_report_address_out_of_scope`). At most `API_MODE_REPORT_MAILBOXES_MAX` (default ' +
      '5; `409 api_mode_report_mailbox_limit`). Audited `api_mode.report_mailbox_updated`. Needs ' +
      '`remediation:write`.' +
      KEYED_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(AddReportMailboxBodySchema, { io: 'input' }),
    examples: { add: { value: X.addReportMailbox } },
  })
  @ApiModeResponse(200, ReportMailboxChangeSchema, X.reportMailboxChange, 'Designated', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiModeConflicts(
    [C.reportMailboxLimit, C.reportMailboxNotEligible],
    '`api_mode_report_mailbox_limit` (`max`), `api_mode_report_mailbox_not_eligible` (`cause`)',
    true,
    { max: { type: 'integer' }, cause: { type: 'string' } },
  )
  @ApiModeUnprocessable([C.reportAddressOutOfScope], '`api_mode_report_address_out_of_scope`', true)
  @ApiModeUnavailable()
  async addMailbox(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReportMailboxChangeView> {
    const result = await this.reports.addMailbox(
      principal,
      scope,
      { idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Put('mailboxes/:mailboxId/report-mailbox')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.reportMailboxSet)
  @ApiOperation({
    summary: 'Designate or clear an API-mode report mailbox',
    description:
      '`{ enabled, reason }`. Designating needs a mailbox of your organization that is ' +
      '`active`, `discovered` or `disabled` (shared mailboxes are often disabled accounts) of an ' +
      '`api` or `hybrid` domain (`409 api_mode_report_mailbox_not_eligible`, `cause`) and fewer ' +
      'than the most report mailboxes (`409 api_mode_report_mailbox_limit`). Clearing is always ' +
      'allowed; an unchanged flag changes nothing. Audited `api_mode.report_mailbox_updated`. ' +
      'Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiMailboxIdParam()
  @ApiBody({
    schema: zodToOpenApi(SetReportMailboxBodySchema, { io: 'input' }),
    examples: { designate: { value: X.setReportMailbox } },
  })
  @ApiModeResponse(200, ReportMailboxChangeSchema, X.reportMailboxChange, 'Stored', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiMailboxNotFound()
  @ApiModeConflicts(
    [C.reportMailboxLimit, C.reportMailboxNotEligible],
    '`api_mode_report_mailbox_limit` (`max`), `api_mode_report_mailbox_not_eligible` (`cause`)',
    true,
    { max: { type: 'integer' }, cause: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async setMailbox(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('mailboxId') mailboxId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReportMailboxChangeView> {
    const result = await this.reports.setMailbox(
      principal,
      scope,
      { id: mailboxId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }
}
