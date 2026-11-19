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
  RequireAnyPermission,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateClass } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery, TransactionalIdempotency } from '../../messages/api-docs';
import {
  ApiAtoKeyedErrors as ApiKeyedErrors,
  ApiAtoResponse as ApiOkResponse,
  ApiAtoUnavailable as ApiUnavailable,
} from '../../ato/api-docs';
import { ATO_ERROR_CODES } from '../../ato/ato.errors';
import { INCIDENT_EXAMPLES as X } from '../dto/incidents.examples';
import {
  type AddNoteBody,
  AddNoteBodySchema,
  type CreateIncidentBody,
  CreateIncidentBodySchema,
  IncidentDetailSchema,
  type IncidentDetailView,
  type IncidentListQuery,
  IncidentListQuerySchema,
  type IncidentMessagePage,
  IncidentMessagePageSchema,
  type IncidentPage,
  IncidentPageSchema,
  IncidentReportSchema,
  type IncidentReportView,
  type MessagesQuery,
  MessagesQuerySchema,
  PAGE_PARAMETERS,
  TimelineEntrySchema,
  type TimelineEntryView,
  type TimelinePage,
  TimelinePageSchema,
  type TimelineQuery,
  TimelineQuerySchema,
  type UpdateIncidentBody,
  UpdateIncidentBodySchema,
} from '../dto/incidents.schemas';
import { incidentPermissionLists } from '../incident-categories';
import { INCIDENT_ERROR_CODES as C } from '../incidents.errors';
import { INCIDENT_OPERATIONS as O, IncidentsService } from '../services/incidents.service';

/**
 * The read and manage permissions of every registered incident category (D17, D24): the routes
 * admit a principal holding any of them; the service then restricts every query to the
 * categories the principal may read (8.4: exactly `ato:read` / `ato:manage`).
 */
export const INCIDENT_PERMISSIONS = incidentPermissionLists();
const READ = INCIDENT_PERMISSIONS.read;
const MANAGE = INCIDENT_PERMISSIONS.manage;

const CATEGORY_RULE =
  ' Incidents of a category are visible only with that category’s read permission (account ' +
  'takeover: `ato:read`) and while the category is enabled for your organization (ATO: plan ' +
  'feature `ato_detection`); any other incident answers `404 incident_not_found`, exactly like ' +
  'an unknown id or another organization’s.';
const MANAGE_RULE =
  ' Needs the incident category’s manage permission (account takeover: `ato:manage`; else ' +
  '`404 incident_not_found`) and the category enabled (ATO: else `403 ato_not_enabled`). ' +
  'Requires the Idempotency-Key header (transactional); rate class `sensitive`.';

const ApiIncidentId = (): MethodDecorator =>
  ApiParam({
    name: 'incidentId',
    description: 'Security incident public id (UUID)',
    format: 'uuid',
  });
const ApiNotFound = (extra: readonly string[] = []): MethodDecorator =>
  ApiCodedError(
    404,
    'Unknown incident, one of another organization, or of a category you may not read',
    [C.notFound, ...extra],
  );
const ApiForbidden = (mutation = false): MethodDecorator =>
  ApiCodedError(
    403,
    'None of the incident categories’ permissions (`forbidden`)' +
      (mutation ? ', or the incident’s category is not enabled (ATO: `ato_not_enabled`)' : ''),
    ['forbidden', ...(mutation ? [ATO_ERROR_CODES.notEnabled] : [])],
  );

/**
 * The generic security incident routes (step 8.4 §5.2, D24; ADR-0075). Translation only.
 */
@ApiTags('incidents')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'incidents', version: '1' })
export class IncidentsController {
  constructor(private readonly incidents: IncidentsService) {}

  private static replay<T>(res: Response, result: { replayed: boolean; body: T }): T {
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequireAnyPermission(...READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List security incidents',
    description:
      'Incidents of every category you may read (or `category`, a comma list), newest first ' +
      '(`-detectedAt`) or by severity (`-severity`). Filters `status` and `severity` (lists), ' +
      '`assignee` (`me`, `unassigned` or a user id), `subjectType`, `subjectId`, `origin`, ' +
      '`detectedFrom`/`detectedTo`. Items carry the category and the subject with a display ' +
      'string (ATO: the account address, user display name or connector name).' +
      CATEGORY_RULE,
  })
  @ApiListQuery(IncidentListQuerySchema, {
    ...PAGE_PARAMETERS,
    sort: '`-detectedAt` (default) or `-severity`',
    category: 'Categories (comma list), e.g. `account_takeover`',
    status: 'Statuses (comma list)',
    severity: 'Severities (comma list)',
    assignee: '`me`, `unassigned` or a user public id',
    subjectType: 'Subject type, e.g. `ato_account`',
    subjectId: 'Subject public id',
    origin: '`detection` or `manual`',
    detectedFrom: 'Detected at or after (ISO 8601)',
    detectedTo: 'Detected before (ISO 8601)',
  })
  @ApiOkResponse(200, IncidentPageSchema, X.page, 'One page of incidents')
  @ApiListErrors()
  @ApiForbidden()
  @ApiUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(IncidentListQuerySchema)) query: IncidentListQuery,
  ): Promise<IncidentPage> {
    return this.incidents.list(principal, scope, query);
  }

  @Post()
  @RequireAnyPermission(...MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @TransactionalIdempotency(O.create)
  @ApiOperation({
    summary: 'Open a manual security incident',
    description:
      'Opens an incident of `category` for `subject` (ATO: `{ type: "ato_account", id: ' +
      '<account public id> }`), e.g. after a user report, with an optional `severity` (default ' +
      '`medium`) and a reason (10-4000 characters, the opening timeline note). One active ' +
      'incident per subject and category (`409 incident_active` with `incidentId`); an unknown ' +
      'subject is `404 incident_subject_not_found`; an unknown category or subject type is ' +
      '`422 incident_category_unsupported`. Audited `security_incident.created`. Users and API ' +
      'keys.' +
      MANAGE_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateIncidentBodySchema, { io: 'input' }),
    examples: { manual: { value: X.create } },
  })
  @ApiOkResponse(201, IncidentDetailSchema, X.detail, 'The new incident', true)
  @ApiKeyedErrors([C.active], [C.categoryUnsupported])
  @ApiCodedError(404, 'The subject was not found in your organization', [C.subjectNotFound])
  @ApiForbidden(true)
  @ApiUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(CreateIncidentBodySchema)) body: CreateIncidentBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<IncidentDetailView> {
    return IncidentsController.replay(
      res,
      await this.incidents.create(principal, scope, key, body, client.ip),
    );
  }

  @Get(':incidentId')
  @RequireAnyPermission(...READ)
  @ApiOperation({
    summary: 'Get a security incident',
    description:
      'The incident: category, subject, origin, status, severity, reason codes, times, ' +
      'assignment, resolution, evidence counts, `rowVersion` (for PATCH), whether you may ' +
      'manage it and the transitions you may request now, and the category detail (ATO: the ' +
      'account, scores at open, peak and current, the detection reason rendered and ' +
      'structured, related IPs, geography, devices, counts, recommendations with ' +
      'availability, a responses summary).' +
      CATEGORY_RULE,
  })
  @ApiIncidentId()
  @ApiOkResponse(200, IncidentDetailSchema, X.detail, 'The incident')
  @ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiNotFound()
  @ApiForbidden()
  @ApiUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
  ): Promise<IncidentDetailView> {
    return this.incidents.get(principal, scope, incidentId);
  }

  @Patch(':incidentId')
  @RequireAnyPermission(...MANAGE)
  @HttpCode(HttpStatus.OK)
  @TransactionalIdempotency(O.update)
  @ApiOperation({
    summary: 'Update a security incident',
    description:
      'Compare-and-set on `expectedRowVersion` (`409 incident_conflict` with ' +
      '`currentRowVersion`), then in one transaction: `severity`, `assigneeId` (an active user ' +
      'of your organization, `null` to unassign; `422 incident_assignee_invalid`), `status` ' +
      '(allowed transitions only: `open → investigating | confirmed | false_positive | ' +
      'resolved`, `investigating → confirmed | false_positive | resolved`, `confirmed → ' +
      'mitigated | resolved`, `mitigated → resolved | confirmed`; `false_positive` and ' +
      '`resolved` are terminal and need `resolution { code, note }`, `confirmed` needs a ' +
      '`note`; else `422 incident_transition_invalid` with `reason`), `note`. ' +
      '`categoryFeedback` is validated by the category (ATO with `false_positive`: ' +
      '`{ trustedContexts[], dismissSignals }` dismisses the incident’s signals, adds the ' +
      'trusted contexts and rescores the account; `422 incident_feedback_invalid`). A closed ' +
      'incident never re-opens (`409 incident_closed` for assignment and severity). Audited.' +
      MANAGE_RULE,
  })
  @ApiIncidentId()
  @ApiBody({
    schema: zodToOpenApi(UpdateIncidentBodySchema, { io: 'input' }),
    examples: { falsePositive: { value: X.update } },
  })
  @ApiOkResponse(200, IncidentDetailSchema, X.detail, 'The updated incident', true)
  @ApiKeyedErrors(
    [C.conflict, C.closed],
    [C.transitionInvalid, C.assigneeInvalid, C.feedbackInvalid],
  )
  @ApiNotFound()
  @ApiForbidden(true)
  @ApiUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(UpdateIncidentBodySchema)) body: UpdateIncidentBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<IncidentDetailView> {
    return IncidentsController.replay(
      res,
      await this.incidents.update(principal, scope, incidentId, key, body, client.ip),
    );
  }

  @Post(':incidentId/notes')
  @RequireAnyPermission(...MANAGE)
  @HttpCode(HttpStatus.CREATED)
  @TransactionalIdempotency(O.addNote)
  @ApiOperation({
    summary: 'Add an investigation note to a security incident',
    description:
      'A free note (1-4000 characters; never message content) on the timeline. Audited ' +
      '`security_incident.note_added` (the length only).' +
      MANAGE_RULE,
  })
  @ApiIncidentId()
  @ApiBody({
    schema: zodToOpenApi(AddNoteBodySchema, { io: 'input' }),
    examples: { note: { value: X.addNote } },
  })
  @ApiOkResponse(201, TimelineEntrySchema, X.note, 'The timeline entry', true)
  @ApiKeyedErrors()
  @ApiNotFound()
  @ApiForbidden(true)
  @ApiUnavailable()
  async addNote(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) key: unknown,
    @Body(new ZodValidationPipe(AddNoteBodySchema)) body: AddNoteBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<TimelineEntryView> {
    return IncidentsController.replay(
      res,
      await this.incidents.addNote(principal, scope, incidentId, key, body, client.ip),
    );
  }

  @Get(':incidentId/timeline')
  @RequireAnyPermission(...READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the timeline of a security incident',
    description:
      'Timeline entries oldest first: creation, evidence, severity, status, assignment, notes, ' +
      'escalation, report exports and category events (ATO: responses, overrides, feedback), ' +
      'each with its actor (public id).' +
      CATEGORY_RULE,
  })
  @ApiIncidentId()
  @ApiListQuery(TimelineQuerySchema, { ...PAGE_PARAMETERS, sort: '`at` (oldest first)' })
  @ApiOkResponse(200, TimelinePageSchema, X.timeline, 'One page of timeline entries')
  @ApiListErrors()
  @ApiNotFound()
  @ApiForbidden()
  @ApiUnavailable()
  timeline(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Query(new ZodValidationPipe(TimelineQuerySchema)) query: TimelineQuery,
  ): Promise<TimelinePage> {
    return this.incidents.timeline(principal, scope, incidentId, query);
  }

  @Get(':incidentId/messages')
  @RequireAnyPermission(...READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the messages linked to a security incident',
    description:
      'Linked messages newest first (at most 500 are linked): public id, received time, ' +
      'direction, final verdict and action, risk score and level, recipient count, number of ' +
      'external recipient domains and finding codes. **No subject, no recipient address.**' +
      CATEGORY_RULE,
  })
  @ApiIncidentId()
  @ApiListQuery(MessagesQuerySchema, { ...PAGE_PARAMETERS, sort: '`-receivedAt`' })
  @ApiOkResponse(200, IncidentMessagePageSchema, X.messages, 'One page of linked messages')
  @ApiListErrors()
  @ApiNotFound()
  @ApiForbidden()
  @ApiUnavailable()
  messages(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Query(new ZodValidationPipe(MessagesQuerySchema)) query: MessagesQuery,
  ): Promise<IncidentMessagePage> {
    return this.incidents.messages(principal, scope, incidentId, query);
  }

  @Get(':incidentId/report')
  @RequireAnyPermission(...READ)
  @RateClass('expensive')
  @ApiOperation({
    summary: 'Export the report of a security incident',
    description:
      '`security-incident-report/1` (JSON; the portal renders a print view): summary, timeline, ' +
      'notes, resolution, evidence counts, related messages (sender masked per ADR-0062; never ' +
      'a subject or a recipient) and the category sections (ATO: detection reason and ' +
      'explanation, signals, related IPs, geography and devices, responses). The timeline, ' +
      'messages, signals and responses are bounded by API_ATO_REPORT_MAX_ITEMS (default 500; ' +
      '`truncated`). Audited `security_incident.report_exported` (and a `report_exported` ' +
      'timeline entry). Rate class `expensive`.' +
      CATEGORY_RULE,
  })
  @ApiIncidentId()
  @ApiOkResponse(200, IncidentReportSchema, X.report, 'The report')
  @ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiNotFound()
  @ApiForbidden()
  @ApiUnavailable()
  report(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('incidentId') incidentId: string,
    @Client() client: ClientContext,
  ): Promise<IncidentReportView> {
    return this.incidents.report(principal, scope, incidentId, client.ip);
  }
}
