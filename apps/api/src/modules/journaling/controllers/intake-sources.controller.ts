import {
  Body,
  Controller,
  Delete,
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
import { RateClass, ReturnsSecret } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiIntakeUnavailable,
  ApiJournalConflicts,
  ApiJournalForbidden,
  ApiJournalResponse,
  ApiJournalUnavailable,
  ApiJournalUnprocessable,
  ApiKeyedErrors,
  ApiSourceIdParam,
  ApiSourceNotFound,
  JournalIdempotency,
  MFA_RULE,
  REDACTED_REPLAY_RULE,
} from '../api-docs';
import {
  AttestationBodySchema,
  AttestationsSchema,
  type AttestationsView,
  CreatedIntakeSourceSchema,
  type CreatedIntakeSourceView,
  CreateIntakeSourceBodySchema,
  INTAKE_LIST_PARAMETERS,
  IntakeSourceDetailSchema,
  type IntakeSourceDetailView,
  type IntakeSourceGetQuery,
  IntakeSourceGetQuerySchema,
  type IntakeSourceListQuery,
  IntakeSourceListQuerySchema,
  type IntakeSourcePage,
  IntakeSourcePageSchema,
  IntakeSourceSchema,
  type IntakeSourceView,
  IntakeWizardSchema,
  type IntakeWizardView,
  JOURNALING_EXAMPLES as X,
  JournalIntakeGuideSchema,
  UpdateIntakeSourceBodySchema,
} from '../dto/journaling.schemas';
import { JOURNAL_OPERATIONS, JOURNAL_PERMISSIONS as P } from '../journaling.constants';
import { JOURNAL_ERROR_CODES as C } from '../journaling.errors';
import { IntakeGuideService } from '../services/intake-guide.service';
import { IntakeSourcesService } from '../services/intake-sources.service';

/** `422` details: `reason` (connection) or `issues: [{ code, index }]` (networks). */
const ISSUES = { type: 'array', items: { type: 'object' } };
const DETAILS_422 = { reason: { type: 'string' }, issues: ISSUES };

const GuideQuerySchema = z.strictObject({ format: z.enum(['json', 'markdown']).optional() });
type GuideQuery = z.output<typeof GuideQuerySchema>;

const SOURCE_RULES =
  ' Creating or resuming a source needs the plan feature `journal_intake` and either archiving ' +
  '(the feature `archiving`, enabled with a live default retention policy) or, since step ' +
  'API-1, active API mode (`api_mode_protection` and a domain in `api` or `hybrid` mode; ' +
  'ADR-0098) — otherwise `403 journal_intake_not_enabled` without `archiving`, `409 ' +
  'archiving_not_enabled` with it — and a TXT-verified domain (provider kinds: linked to the ' +
  'connection; `409 journal_intake_domain_required`, `reason`).';

/**
 * Journal intake sources (step 8.6 D1, D10, D11; ADR-0087). Translation only: the services own
 * the rules, the address derivation and the audit rows.
 */
@ApiTags('journaling')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'journaling/intake-sources', version: '1' })
export class IntakeSourcesController {
  constructor(
    private readonly sources: IntakeSourcesService,
    private readonly guides: IntakeGuideService,
  ) {}

  @Get()
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List journal intake sources',
    description:
      'Your organization’s journal intake sources, newest first: kind, status, health, last ' +
      'accepted and refused messages, the masked intake address. Filters `status`, `kind`, ' +
      '`health`. v1 list (`journal_intake_sources`). From the read replica.',
  })
  @ApiListQuery(IntakeSourceListQuerySchema, INTAKE_LIST_PARAMETERS)
  @ApiJournalResponse(200, IntakeSourcePageSchema, X.sourcePage, 'One page of sources')
  @ApiListErrors()
  @ApiJournalForbidden()
  @ApiJournalUnavailable()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(IntakeSourceListQuerySchema)) query: IntakeSourceListQuery,
  ): Promise<IntakeSourcePage> {
    return this.sources.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @JournalIdempotency(JOURNAL_OPERATIONS.sourceCreate)
  @ReturnsSecret({ redactedReplay: true })
  @ApiOperation({
    summary: 'Create a journal intake source',
    description:
      'A sender configuration for journal-only intake: `microsoft_365_journal` (Purview journal ' +
      'rule) and `google_workspace_copy` (routing rule “Also deliver to”) need ' +
      '`providerConnectionId`, an 8.2 connection of the same provider, not disabled, bound to ' +
      'its tenant (`422 journal_intake_connection_invalid`, `reason`); ' +
      '`exchange_onprem_journal` and `smtp_bcc` need `networks` (1-32 public CIDRs, never a ' +
      'provider egress range, no prefix shorter than /16 (IPv4) or /32 (IPv6); `422 ' +
      'journal_intake_networks_invalid` with `issues: [{ code, index }]`). The source starts ' +
      '`pending_verification` (mail is accepted; the first accepted message makes it `active`). ' +
      'At most JOURNAL_INTAKE_MAX_SOURCES_PER_ORG sources that are not disabled (`409 ' +
      'journal_intake_source_limit`); unique names (`409 journal_intake_source_name_taken`). ' +
      'Without an intake domain on the platform: `503 journal_intake_unavailable`.' +
      SOURCE_RULES +
      ' Audited `journal_intake.source_created` (ids and codes only).' +
      REDACTED_REPLAY_RULE +
      ' Requires the Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateIntakeSourceBodySchema, { io: 'input' }),
    examples: {
      microsoft365: { value: X.sourceCreate },
      onPremises: { value: X.sourceCreateOnPrem },
    },
  })
  @ApiJournalResponse(
    201,
    CreatedIntakeSourceSchema,
    X.created,
    'Created; `address` (and `headerToken`) are shown only here (`null` on a replay)',
    true,
  )
  @ApiKeyedErrors()
  @ApiJournalForbidden([C.notEnabled], '`journal_intake_not_enabled`')
  @ApiJournalConflicts(
    [C.archivingNotEnabled, C.sourceLimit, C.sourceNameTaken, C.domainRequired],
    '`archiving_not_enabled`, `journal_intake_source_limit` (`limit`), ' +
      '`journal_intake_source_name_taken`, `journal_intake_domain_required` (`reason`)',
    true,
    { limit: { type: 'integer' }, reason: { type: 'string' } },
  )
  @ApiJournalUnprocessable(
    [C.connectionInvalid, C.networksInvalid],
    '`journal_intake_connection_invalid` (`reason`), `journal_intake_networks_invalid` (`issues`)',
    true,
    DETAILS_422,
  )
  @ApiIntakeUnavailable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CreatedIntakeSourceView> {
    const result = await this.sources.create(principal, scope, { idempotencyKey, body }, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':sourceId')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get a journal intake source',
    description:
      'The source with its health and the counters of the last 7 UTC days (accepted, ' +
      'duplicates, bytes, refusals by reason, proof drops, unwrap failures). The intake address ' +
      '(and the Google header token) are masked (`journal-••••<last 4>@…`); `?reveal=true` shows ' +
      'them in clear for `journal:manage` holders (`403 forbidden` otherwise) and is audited ' +
      '`journal_intake.address_revealed` before the response.',
  })
  @ApiSourceIdParam()
  @ApiQuery({
    name: 'reveal',
    required: false,
    description: '`true`: the address and token in clear (`journal:manage`; audited)',
    schema: { type: 'string', enum: ['true', 'false'] },
  })
  @ApiJournalResponse(200, IntakeSourceDetailSchema, X.sourceDetail, 'The source')
  @ApiCodedError(400, 'The id is not a UUID or the query is invalid (`validation_failed`)', [
    'validation_failed',
  ])
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiIntakeUnavailable()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Query(new ZodValidationPipe(IntakeSourceGetQuerySchema)) query: IntakeSourceGetQuery,
    @Client() client: ClientContext,
  ): Promise<IntakeSourceDetailView> {
    return this.sources.get(principal, scope, sourceId, query.reveal, client.ip);
  }

  @Patch(':sourceId')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @JournalIdempotency(JOURNAL_OPERATIONS.sourceUpdate)
  @ApiOperation({
    summary: 'Update a journal intake source',
    description:
      '`displayName`, `networks` (on-premises kinds; the rules of creation), `requireTls`, ' +
      '`clientCertFingerprints`, `maxMessageBytes`, `silenceAlertMinutes` and `status`: ' +
      '`paused` stops intake (senders get `450 4.7.1` and retry), `active` resumes it ' +
      '(`pending_verification` until the first accepted message). CAS `expectedRowVersion` ' +
      '(`409 journal_intake_source_conflict`, `currentRowVersion`); a disabled source cannot ' +
      'change (`409 journal_intake_source_disabled`).' +
      SOURCE_RULES +
      ' Audited `journal_intake.source_updated`, `…source_paused` or `…source_resumed`. ' +
      'Requires the Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiSourceIdParam()
  @ApiBody({
    schema: zodToOpenApi(UpdateIntakeSourceBodySchema, { io: 'input' }),
    examples: { pause: { value: X.sourceUpdate } },
  })
  @ApiJournalResponse(200, IntakeSourceSchema, X.source, 'The updated source', true)
  @ApiKeyedErrors()
  @ApiJournalForbidden([C.notEnabled], '`journal_intake_not_enabled` when resuming')
  @ApiSourceNotFound()
  @ApiJournalConflicts(
    [
      C.sourceConflict,
      C.sourceDisabled,
      C.sourceNameTaken,
      C.archivingNotEnabled,
      C.domainRequired,
    ],
    '`journal_intake_source_conflict` (`currentRowVersion`), `journal_intake_source_disabled`, ' +
      '`journal_intake_source_name_taken`, `archiving_not_enabled`, ' +
      '`journal_intake_domain_required`',
    true,
    { currentRowVersion: { type: 'integer' }, reason: { type: 'string' } },
  )
  @ApiJournalUnprocessable(
    [C.connectionInvalid, C.networksInvalid],
    '`journal_intake_connection_invalid` (`reason`), `journal_intake_networks_invalid` (`issues`)',
    true,
    DETAILS_422,
  )
  @ApiJournalUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<IntakeSourceView> {
    const result = await this.sources.update(
      principal,
      scope,
      { id: sourceId, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Delete(':sourceId')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Disable a journal intake source',
    description:
      'Sets the source `disabled` (terminal: its address is refused with `550 5.1.1` within ' +
      'the gateway’s source cache TTL; the row and its counters are kept for the trail). A ' +
      'repeat answers the disabled source without a change. Audited ' +
      '`journal_intake.source_disabled`. Rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiSourceIdParam()
  @ApiJournalResponse(200, IntakeSourceSchema, { ...X.source, status: 'disabled' }, 'Disabled')
  @ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiJournalConflicts([C.sourceConflict], '`journal_intake_source_conflict`', false)
  @ApiJournalUnavailable()
  disable(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Client() client: ClientContext,
  ): Promise<IntakeSourceView> {
    return this.sources.disable(principal, scope, sourceId, client.ip);
  }

  @Post(':sourceId/rotate-address')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @JournalIdempotency(JOURNAL_OPERATIONS.rotateAddress)
  @ReturnsSecret({ redactedReplay: true })
  @ApiOperation({
    summary: 'Rotate the intake address of a source',
    description:
      'A new intake address (and Google header token): `addressVersion + 1`. The previous ' +
      'address and token stay accepted until `previousAddressValidUntil` (now + ' +
      'JOURNAL_INTAKE_ROTATION_OVERLAP_DAYS); update the journal rule or routing setting within ' +
      'that time. A disabled source cannot rotate (`409 journal_intake_source_disabled`). ' +
      'Audited `journal_intake.address_rotated` (versions, never addresses).' +
      REDACTED_REPLAY_RULE +
      ' Requires the Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiSourceIdParam()
  @ApiJournalResponse(
    200,
    CreatedIntakeSourceSchema,
    { ...X.created, source: { ...X.source, addressVersion: 2 } },
    'Rotated; the new `address` (and `headerToken`) are shown only here',
    true,
  )
  @ApiKeyedErrors()
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiJournalConflicts(
    [C.sourceDisabled, C.sourceConflict],
    '`journal_intake_source_disabled`, `journal_intake_source_conflict`',
    true,
  )
  @ApiIntakeUnavailable()
  async rotate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CreatedIntakeSourceView> {
    const result = await this.sources.rotate(
      principal,
      scope,
      { id: sourceId, idempotencyKey },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get(':sourceId/wizard')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the setup wizard of a source',
    description:
      'Computed from the rows (never stored): `archiving` (entitled, enabled, default ' +
      'retention; `skipped` with `reason: api_mode` when active API mode entitles the source ' +
      'without archiving, step API-1), `domains` (a TXT-verified domain; provider kinds: linked to the ' +
      'connection), `connection` (provider kinds: bound and not disabled; `skipped` otherwise), ' +
      '`configure` (the customer-side attestations of the kind’s guide), `verify` (first ' +
      'accepted message), `monitor` (health). Each step `not_started`, `in_progress`, `done`, ' +
      '`blocked` or `skipped` with blockers, and the next action.',
  })
  @ApiSourceIdParam()
  @ApiJournalResponse(200, IntakeWizardSchema, X.wizard, 'The wizard')
  @ApiCodedError(400, 'The id is not a UUID (`validation_failed`)', ['validation_failed'])
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiJournalUnavailable()
  wizard(
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
  ): Promise<IntakeWizardView> {
    return this.sources.wizard(scope, sourceId);
  }

  @Get(':sourceId/setup-guide')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'Get the setup guide of a source',
    description:
      'The customer-specific guide (`journal-intake-guide/1`) generated from the source’s own ' +
      'values: Microsoft 365 (Purview journal rule, undeliverable-reports mailbox, PowerShell), ' +
      'Google Workspace (routing setting with “Also deliver to”, X-Gm-Original-To and the ' +
      'X-EG-Journal-Token header), on-premises Exchange (journal recipient, journal rule, Send ' +
      'connector with TLS) or generic SMTP (`always_bcc`), with attestation codes. The gateway ' +
      'never applies a step. The address and token are in clear only for `journal:manage` ' +
      'holders (audited `journal_intake.address_revealed`, `via: guide`), masked otherwise. ' +
      '`?format=markdown` or `Accept: text/markdown` returns `text/markdown` as a download.',
  })
  @ApiSourceIdParam()
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
        schema: zodToOpenApi(JournalIntakeGuideSchema),
        example: {
          schema: 'journal-intake-guide/1',
          kind: 'microsoft_365_journal',
          source: {
            id: X.source.id,
            displayName: X.source.displayName,
            kind: 'microsoft_365_journal',
          },
          address: 'journal-••••wxyz@journal.example.com',
          revealed: false,
          notice: 'The gateway never changes your Microsoft 365 configuration.',
          sections: [
            {
              id: 'overview',
              number: 1,
              title: 'Overview',
              paragraphs: ['Journal reports are archived; they are never delivered.'],
              steps: [],
            },
          ],
          attestations: [],
          generatedAt: '2026-11-20T09:00:00.000Z',
        },
      },
      'text/markdown': {
        schema: { type: 'string' },
        example: '# Journal intake setup guide: Contoso Microsoft 365\n',
      },
    },
  })
  @ApiCodedError(400, 'The id is not a UUID or the query is invalid (`validation_failed`)', [
    'validation_failed',
  ])
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiIntakeUnavailable()
  async guide(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Query(new ZodValidationPipe(GuideQuerySchema)) query: GuideQuery,
    @Headers('accept') accept: string | undefined,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    const markdown =
      query.format === 'markdown' ||
      (query.format === undefined && (accept ?? '').toLowerCase().includes('text/markdown'));
    if (!markdown) return this.guides.guide(principal, scope, sourceId, client.ip);
    const { fileName, markdown: text } = await this.guides.markdown(
      principal,
      scope,
      sourceId,
      client.ip,
    );
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return text;
  }

  @Post(':sourceId/attestations')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @RateClass('sensitive')
  @ApiOperation({
    summary: 'Record an attestation of a customer-side step',
    description:
      '`{ code, attested }` with a `journal.*` code of the source kind’s guide (`422 ' +
      'journal_intake_attestation_unknown`); `false` withdraws it. At most 32 are kept. ' +
      'Attestations are statements by your administrator, not proofs (the gateway cannot ' +
      'observe customer-side configuration). Audited `journal_intake.attested`. Rate class ' +
      '`sensitive`.' +
      MFA_RULE,
  })
  @ApiSourceIdParam()
  @ApiBody({
    schema: zodToOpenApi(AttestationBodySchema, { io: 'input' }),
    examples: { ruleCreated: { value: X.attestation } },
  })
  @ApiJournalResponse(200, AttestationsSchema, X.attestations, 'Recorded')
  @ApiCodedError(400, 'The id or body is invalid (`validation_failed`)', ['validation_failed'])
  @ApiJournalForbidden()
  @ApiSourceNotFound()
  @ApiJournalConflicts(
    [C.sourceDisabled, C.sourceConflict],
    '`journal_intake_source_disabled`, `journal_intake_source_conflict`',
    false,
  )
  @ApiJournalUnprocessable([C.attestationUnknown], '`journal_intake_attestation_unknown`', false)
  @ApiJournalUnavailable()
  attest(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('sourceId') sourceId: string,
    @Body() body: unknown,
    @Client() client: ClientContext,
  ): Promise<AttestationsView> {
    return this.sources.attest(principal, scope, sourceId, body, client.ip);
  }
}
