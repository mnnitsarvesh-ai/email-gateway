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
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { z } from 'zod';
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
  ApiConnectionIdParam,
  ApiConnectionNotFound,
  ApiDetectionIdParam,
  ApiDetectionNotFound,
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
  API_MODE_EXAMPLES as X,
  ApiModeConnectionDetailSchema,
  type ApiModeConnectionDetailView,
  ApiModeConnectionListSchema,
  type ApiModeConnectionListView,
  ApiModeConnectionSchema,
  type ApiModeConnectionView,
  ApiModeGuideSchema,
  ApiModeOverviewSchema,
  type ApiModeOverviewView,
  DETECTION_LIST_PARAMETERS,
  DetectionDetailSchema,
  type DetectionDetailView,
  type DetectionListQuery,
  DetectionListQuerySchema,
  type DetectionPage,
  DetectionPageSchema,
  InventorySyncSchema,
  type InventorySyncView,
  MAILBOX_LIST_PARAMETERS,
  MailboxDetailSchema,
  type MailboxDetailView,
  type MailboxListQuery,
  MailboxListQuerySchema,
  type MailboxPage,
  MailboxPageSchema,
  MailboxResyncSchema,
  type MailboxResyncView,
  UpdateSettingsBodySchema,
} from '../dto/api-mode.schemas';
import { ApiModeGuideService } from '../services/api-mode-guide.service';
import { ApiModeService } from '../services/api-mode.service';

const GuideQuerySchema = z.strictObject({ format: z.enum(['json', 'markdown']).optional() });
type GuideQuery = z.output<typeof GuideQuerySchema>;

/** `400` of the guide route (bad id or `format`). */
const ApiBadIdOrQuery = (): MethodDecorator =>
  ApiCodedError(400, 'The id is not a UUID or the query is invalid (`validation_failed`)', [
    'validation_failed',
  ]);

const NEVER_SECRETS =
  ' Never returns a feed cursor (delta link / history id), a Graph subscription id or client ' +
  'state.';

/**
 * API-mode protection (step API-1 D10, D11, D12 #4-#14; ADR-0098..0100): coverage and health,
 * connections with their API-mode settings, wizard and guide, mailboxes and detections. Reads
 * need `remediation:read`, writes `remediation:write`. Translation only: the services own the
 * rules and the audit rows.
 */
@ApiTags('api-mode')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'api-mode', version: '1' })
export class ApiModeController {
  constructor(
    private readonly apiMode: ApiModeService,
    private readonly guides: ApiModeGuideService,
  ) {}

  @Get('overview')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the API-mode coverage and health overview',
    description:
      'Whether the plan entitles API mode and whether it is active, the organization’s mode and ' +
      'the domains per effective mode, mailbox coverage (covered, gap, total of the last ' +
      'inventory or null, percent), connections by health, intake lag p50/p95 of the last hour ' +
      'and day (seconds, from the hourly counters’ buckets), throttling events, copies today, ' +
      'and per connection: health with its failing checks, coverage, feeds, the mailbox-access ' +
      'grant status, inventory status, lag, throttling, copies today and `throttledUntil`. Needs ' +
      '`remediation:read`.',
  })
  @ApiModeResponse(200, ApiModeOverviewSchema, X.overview, 'The overview')
  @ApiModeForbidden()
  @ApiModeUnavailable()
  overview(@CurrentScope() scope: TenantScope): Promise<ApiModeOverviewView> {
    return this.apiMode.overview(scope);
  }

  @Get('connections')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'List the provider connections with their API-mode settings',
    description:
      'Every 8.2 provider connection of your organization with its API-mode row (absent: the ' +
      'defaults, `apiConnectionId: null`), the status of its mailbox-access grant ' +
      '(`*.mailbox_remediation`) and the provider journal intake sources bound to it. Needs ' +
      '`remediation:read`.' +
      NEVER_SECRETS,
  })
  @ApiModeResponse(200, ApiModeConnectionListSchema, X.connections, 'The connections')
  @ApiModeForbidden()
  @ApiModeUnavailable()
  listConnections(@CurrentScope() scope: TenantScope): Promise<ApiModeConnectionListView> {
    return this.apiMode.connections(scope);
  }

  @Get('connections/:connectionId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get a provider connection’s API-mode state',
    description:
      'One connection (`connectionId` = the 8.2 provider connection public id) with its ' +
      'coverage, the server-computed setup wizard (`domains`, `connection`, `journal`, ' +
      '`mailbox_access`, `feeds`, `monitor`: each `not_started`, `in_progress`, `done`, ' +
      '`blocked` or `skipped` with blockers, and the next action), the `api-mode-health/1` ' +
      'checks of the last evaluation and the counters of the last 7 UTC days. Needs ' +
      '`remediation:read`.' +
      NEVER_SECRETS,
  })
  @ApiConnectionIdParam()
  @ApiModeResponse(200, ApiModeConnectionDetailSchema, X.connectionDetail, 'The connection')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiConnectionNotFound()
  @ApiModeUnavailable()
  getConnection(
    @CurrentScope() scope: TenantScope,
    @Param('connectionId') connectionId: string,
  ): Promise<ApiModeConnectionDetailView> {
    return this.apiMode.connection(scope, connectionId);
  }

  @Get('connections/:connectionId/setup-guide')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the API-mode setup guide of a provider connection',
    description:
      'The customer-specific guide (`api-mode-guide/1`) generated from the connection’s own ' +
      'values: journal rule (the intake address masked), mailbox-access consent (Microsoft ' +
      'Graph `Mail.ReadWrite` + `User.Read.All`, or Google domain-wide delegation of ' +
      '`gmail.modify` + `admin.directory.user.readonly`), the optional Exchange Online scoping, ' +
      'change feeds, verification, revocation and troubleshooting, with attestation codes. The ' +
      'gateway never applies a step. `?format=markdown` or `Accept: text/markdown` returns ' +
      '`text/markdown` as a download. Needs `remediation:read`.',
  })
  @ApiConnectionIdParam()
  @ApiQuery({
    name: 'format',
    required: false,
    description: '`json` (default) or `markdown`',
    schema: { type: 'string', enum: ['json', 'markdown'] },
  })
  @ApiOkResponse({
    description: 'The guide (JSON) or its Markdown rendering',
    content: {
      'application/json': {
        schema: zodToOpenApi(ApiModeGuideSchema),
        example: {
          schema: 'api-mode-guide/1',
          provider: 'microsoft_365',
          connection: { id: X.connection.id, displayName: X.connection.displayName },
          notice: 'The gateway never changes your Microsoft 365 configuration.',
          sections: [
            {
              id: 'overview',
              number: 1,
              title: 'Overview',
              paragraphs: ['API mode scans a copy of each message; mail flow never changes.'],
              steps: [],
            },
          ],
          attestations: [],
          permissions: ['Mail.ReadWrite', 'User.Read.All'],
          generatedAt: '2026-11-26T09:00:00.000Z',
        },
      },
      'text/markdown': {
        schema: { type: 'string' },
        example: '# API-mode setup guide: Contoso Microsoft 365\n',
      },
    },
  })
  @ApiBadIdOrQuery()
  @ApiModeForbidden()
  @ApiConnectionNotFound()
  @ApiModeUnavailable()
  async setupGuide(
    @CurrentScope() scope: TenantScope,
    @Param('connectionId') connectionId: string,
    @Query(new ZodValidationPipe(GuideQuerySchema)) query: GuideQuery,
    @Headers('accept') accept: string | undefined,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    const markdown =
      query.format === 'markdown' ||
      (query.format === undefined && (accept ?? '').toLowerCase().includes('text/markdown'));
    if (!markdown) return this.guides.guide(scope, connectionId);
    const { fileName, markdown: text } = await this.guides.markdown(scope, connectionId);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return text;
  }

  @Put('connections/:connectionId/settings')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.OK)
  @ApiModeIdempotency(API_MODE_OPERATIONS.settingsUpdate)
  @ApiOperation({
    summary: 'Change the change-feed settings of a provider connection',
    description:
      '`{ feedsEnabled, feedMode?, expectedRowVersion }` (CAS: `409 api_mode_connection_conflict` ' +
      'with `currentRowVersion`; a connection without an API-mode row has version 1 and the row ' +
      'is created). Feeds are off by default; enabling them needs the active mailbox-access grant ' +
      '(`409 api_mode_mailbox_access_required`) and marks every in-scope mailbox with a provider ' +
      'id for its first (no-backfill) sync. `feedMode: notify` (Graph change notifications as ' +
      'wake-up hints for the delta query) needs Microsoft 365 and a public notification URL on ' +
      'the platform (`422 api_mode_notifications_unavailable`, `reason` `provider`/`platform`); ' +
      'Google Workspace always polls. Disabling stops the feeds at the worker’s next claim. ' +
      'Audited `api_mode.settings_updated`. Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiConnectionIdParam()
  @ApiBody({
    schema: zodToOpenApi(UpdateSettingsBodySchema, { io: 'input' }),
    examples: { enableFeeds: { value: X.settingsUpdate } },
  })
  @ApiModeResponse(200, ApiModeConnectionSchema, X.connection, 'The updated connection', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiConnectionNotFound()
  @ApiModeConflicts(
    [C.connectionConflict, C.mailboxAccessRequired],
    '`api_mode_connection_conflict` (`currentRowVersion`), `api_mode_mailbox_access_required`',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiModeUnprocessable(
    [C.notificationsUnavailable],
    '`api_mode_notifications_unavailable` (`reason`)',
    true,
    { reason: { type: 'string' } },
  )
  @ApiModeUnavailable()
  async updateSettings(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('connectionId') connectionId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ApiModeConnectionView> {
    const result = await this.apiMode.updateSettings(
      principal,
      scope,
      { id: connectionId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Post('connections/:connectionId/inventory-sync')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.inventorySync)
  @ApiOperation({
    summary: 'Request a mailbox inventory of a provider connection',
    description:
      'The mailbox-worker lists the tenant’s users at its next inventory tick (it runs every ' +
      'API_MODE_INVENTORY_INTERVAL_HOURS anyway): `inventoryRequestedAt` and `nextInventoryAt` ' +
      '= now. Needs the active mailbox-access grant (`409 api_mode_mailbox_access_required`). ' +
      'Audited `api_mode.inventory_sync_requested`. Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiConnectionIdParam()
  @ApiModeResponse(202, InventorySyncSchema, X.inventorySync, 'Requested', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiConnectionNotFound()
  @ApiModeConflicts([C.mailboxAccessRequired], '`api_mode_mailbox_access_required`', true)
  @ApiModeUnavailable()
  async inventorySync(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('connectionId') connectionId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<InventorySyncView> {
    const result = await this.apiMode.inventorySync(
      principal,
      scope,
      { id: connectionId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('mailboxes')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List API-mode mailboxes',
    description:
      'Mailboxes known to API mode (from the inventory or seen in journal copies), newest ' +
      'first: address, domain, status, coverage, feed status, journal last seen, last sync and ' +
      'last error code. Filters `connectionId`, `coverage`, `feedStatus`, `status`, `domainId`, ' +
      '`q` (address prefix, primary or alias). v1 list (`api_mailboxes`). From the read replica. ' +
      'Needs `remediation:read`.' +
      NEVER_SECRETS,
  })
  @ApiListQuery(MailboxListQuerySchema, MAILBOX_LIST_PARAMETERS)
  @ApiModeResponse(200, MailboxPageSchema, X.mailboxPage, 'One page of mailboxes')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  listMailboxes(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(MailboxListQuerySchema)) query: MailboxListQuery,
  ): Promise<MailboxPage> {
    return this.apiMode.mailboxes(principal, scope, query);
  }

  @Get('mailboxes/:mailboxId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an API-mode mailbox',
    description:
      'The mailbox with its aliases, feed state (whether a change-notification subscription ' +
      'exists and when it expires, never its id) and its last 20 copies (detection summaries, ' +
      'subjects withheld and senders masked). Needs `remediation:read`.' +
      NEVER_SECRETS,
  })
  @ApiMailboxIdParam()
  @ApiModeResponse(200, MailboxDetailSchema, X.mailboxDetail, 'The mailbox')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiMailboxNotFound()
  @ApiModeUnavailable()
  getMailbox(
    @CurrentScope() scope: TenantScope,
    @Param('mailboxId') mailboxId: string,
  ): Promise<MailboxDetailView> {
    return this.apiMode.mailbox(scope, mailboxId);
  }

  @Post('mailboxes/:mailboxId/resync')
  @RequirePermissions(P.write)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiModeIdempotency(API_MODE_OPERATIONS.mailboxResync)
  @ApiOperation({
    summary: 'Resynchronize a mailbox’s change feed',
    description:
      'Clears the mailbox’s feed cursor (the worker re-initializes it WITHOUT backfill: only mail ' +
      'arriving afterwards is fetched) and requests a sync now. Needs the active mailbox-access ' +
      'grant of its connection (`409 api_mode_mailbox_access_required`). Audited ' +
      '`api_mode.mailbox_resync_requested`. Needs `remediation:write`.' +
      KEYED_RULE,
  })
  @ApiMailboxIdParam()
  @ApiModeResponse(202, MailboxResyncSchema, X.mailboxResync, 'Requested', true)
  @ApiKeyedErrors()
  @ApiModeForbidden()
  @ApiMailboxNotFound()
  @ApiModeConflicts([C.mailboxAccessRequired], '`api_mode_mailbox_access_required`', true)
  @ApiModeUnavailable()
  async resyncMailbox(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('mailboxId') mailboxId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<MailboxResyncView> {
    const result = await this.apiMode.resync(
      principal,
      scope,
      { id: mailboxId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('detections')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List API-mode detections',
    description:
      'Per-mailbox copies scanned in detect mode (never delivered), newest first: mailbox, ' +
      'source of the scanned copy (`journal`, `graph`, `gmail`), whether the journal and the ' +
      'feed saw it, status, verdict, risk score, verdict authority (`inline` for hybrid copies ' +
      'already filtered inline), receipt, provider delivery and verdict times and the lag. The ' +
      'subject is withheld (`subjectMasked`) and the sender’s local part masked (ADR-0062; ' +
      '`message:reveal` holders use the reveal flow of the message routes). Filters `verdict`, ' +
      '`status`, `source`, `mailboxId`, `connectionId`, `minRiskScore`, `from`/`to` (at most 31 ' +
      'days; default the last 7). v1 list (`api_message_copies`). From the read replica. Needs ' +
      '`remediation:read`.',
  })
  @ApiListQuery(DetectionListQuerySchema, DETECTION_LIST_PARAMETERS)
  @ApiModeResponse(200, DetectionPageSchema, X.detectionPage, 'One page of detections')
  @ApiListErrors()
  @ApiModeForbidden()
  @ApiModeUnavailable()
  listDetections(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DetectionListQuerySchema)) query: DetectionListQuery,
  ): Promise<DetectionPage> {
    return this.apiMode.detections(principal, scope, query);
  }

  @Get('detections/:detectionId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get an API-mode detection',
    description:
      'One copy with its direction, the basis of its provider delivery time and up to 10 risk ' +
      'reason codes of its scan (codes only; subject withheld, sender masked). Needs ' +
      '`remediation:read`.',
  })
  @ApiDetectionIdParam()
  @ApiModeResponse(200, DetectionDetailSchema, X.detectionDetail, 'The detection')
  @ApiBadId()
  @ApiModeForbidden()
  @ApiDetectionNotFound()
  @ApiModeUnavailable()
  getDetection(
    @CurrentScope() scope: TenantScope,
    @Param('detectionId') detectionId: string,
  ): Promise<DetectionDetailView> {
    return this.apiMode.detection(scope, detectionId);
  }
}
