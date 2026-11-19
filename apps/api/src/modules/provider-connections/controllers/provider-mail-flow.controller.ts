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
  UseFilters,
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
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../../http/coded-exception';
import {
  IDEMPOTENCY_KEY_HEADER,
  IDEMPOTENCY_REPLAYED_HEADER,
} from '../../../http/idempotency/idempotency-key';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { ReturnsSecret } from '../../../rate-limit/rate-class.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiListErrors, ApiListQuery, ApiOkExample } from '../../messages/api-docs';
import {
  ApiChangeForbidden,
  ApiConnectionBasics,
  ApiConnectionId,
  ApiConnectionNotFound,
  ApiKeyedBadRequest,
  ApiKeyedConflict,
  ApiKeyedResponse,
  ApiKeyedUnprocessable,
  ApiRunId,
  ApiUnavailable,
  KEYED_RULE,
  ProviderIdempotency,
  REDACTED_REPLAY_RULE,
} from '../api-docs';
import {
  type AppliedView,
  AppliedSchema,
  ApplyBodySchema,
  CreatedValidationSchema,
  type CreatedValidationView,
  CreateValidationBodySchema,
  type GuideQuery,
  GuideQuerySchema,
  type MailFlowStateView,
  MailFlowStateSchema,
  type PreviewBody,
  PreviewBodySchema,
  PreviewSchema,
  type PreviewView,
  PROVIDER_EXAMPLES,
  SetupGuideSchema,
  VALIDATION_LIST_PARAMETERS,
  type ValidationListQuery,
  ValidationListQuerySchema,
  type ValidationPage,
  ValidationPageSchema,
  ValidationRunDetailSchema,
  type ValidationRunDetailView,
} from '../dto/provider-connections.schemas';
import {
  INTEGRATION_MANAGE,
  INTEGRATION_READ,
  PROVIDER_OPERATIONS,
} from '../provider-connections.constants';
import { PROVIDER_ERROR_CODES as C } from '../provider-connections.errors';
import { ProviderRateLimit } from '../provider-connections-rate-limit';
import { ProviderGuideService } from '../services/provider-guide.service';
import { ProviderMailFlowService } from '../services/provider-mail-flow.service';
import { ProviderValidationService } from '../services/provider-validation.service';

const CHANGE_RULES =
  'Change kinds: `inbound { domainIds, microsoftHosts? }` (deliver inbound mail of linked ' +
  'domains to the provider preset; needs `domain:routing_manage`), `outbound { mode: ' +
  '"probe_only" }` (create or re-enable the provider relay connector; probes only, other mail ' +
  '`451`), `activate { outboundMode, internalRouting }` (needs a passed validation and, for ' +
  '`active`, a passed outbound probe within 7 days: `409 validation_required`), `proof { ' +
  'relayProof }` (provider-relay-proof/1 within the provider bounds: Microsoft 365 `tenantHeader: ' +
  '"off"` needs `dkimAligned: "required"`, `dkimMaxAgeSeconds` and `dkimReplayMax`; Google ' +
  'always keeps all three; `422 proof_policy_invalid`), `suspend`, `disable_outbound` and `disable` (disconnect, applied by ' +
  '`DELETE /provider-connections/{id}`); all but `inbound` need `connector:manage`. Every change ' +
  'needs a bound connection (`409 connection_not_bound`) except `proof`, `suspend`, ' +
  '`disable_outbound` and `disable`. Customer-side configuration is never changed by the ' +
  'gateway (it holds no write permission).';

/**
 * Gateway-side mail flow of a connection (step 8.2 §5.2 #15–17; D13, ADR-0080): preview → impact
 * token → apply, and the desired vs observed state. Translation only (ProviderMailFlowService).
 */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/mail-flow', version: '1' })
export class ProviderMailFlowController {
  constructor(private readonly mailFlow: ProviderMailFlowService) {}

  @Post('preview')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Preview a mail-flow change',
    description:
      '`{ change }` → the concrete change set (per domain: current vs proposed destination ' +
      'servers; connector action; connection fields from → to; grants revoked) with warning ' +
      'codes and an `impactToken` (HMAC bound to your organization, the connection’s row ' +
      'version, the change set, your user and a PROVIDER_IMPACT_TOKEN_TTL_SECONDS expiry). ' +
      'Nothing changes; audited `integration.mail_flow_previewed` (kind and counts only). ' +
      CHANGE_RULES,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(PreviewBodySchema, { io: 'input' }),
    examples: { inbound: { value: PROVIDER_EXAMPLES.preview } },
  })
  @ApiOkExample(PreviewSchema, PROVIDER_EXAMPLES.previewed)
  @ApiErrors(400, 401)
  @ApiChangeForbidden()
  @ApiConnectionBasics()
  @ApiCodedError(
    409,
    '`connection_not_bound`, `connection_disabled`, `validation_required` (`reason`), ' +
      '`change_not_applicable` (`reason`)',
    [C.connectionNotBound, C.connectionDisabled, C.validationRequired, C.changeNotApplicable],
    { reason: { type: 'string' }, status: { type: 'string' } },
  )
  @ApiCodedError(
    422,
    '`domain_not_linked` (`domainId`), `proof_policy_invalid` (`issues`), or a refused ' +
      'destination host (`reason`, `field`)',
    [C.domainNotLinked, C.proofPolicyInvalid],
    { domainId: { type: 'string' }, issues: { type: 'integer' } },
  )
  preview(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Body(new ZodValidationPipe(PreviewBodySchema)) body: PreviewBody,
    @Client() client: ClientContext,
  ): Promise<PreviewView> {
    return this.mailFlow.preview(principal, scope, id, body, client.ip);
  }

  @Post('apply')
  @RequirePermissions(INTEGRATION_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ProviderIdempotency(PROVIDER_OPERATIONS.mailFlowApply, null)
  @RateLimit({ bucket: 'provider-mail-flow-apply', limit: 30, windowSeconds: 60, by: 'principal' })
  @ApiOperation({
    summary: 'Apply a previewed mail-flow change',
    description:
      '`{ change, impactToken, confirm: true }`. In ONE writer transaction with the connection ' +
      'locked: the change set is recomputed and the impact token verified (constant time; ' +
      '`409 impact_changed` when it expired, belongs to another user or the change set ' +
      'changed: preview again), then destinations (with their own audit rows and ' +
      '`domain.routing.changed.v1`), the relay connector and the connection columns are ' +
      'written. Audited `integration.mail_flow_applied` with the change set. At most 30 per ' +
      'caller per minute. ' +
      CHANGE_RULES +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(ApplyBodySchema, { io: 'input' }),
    examples: { inbound: { value: PROVIDER_EXAMPLES.apply } },
  })
  @ApiKeyedResponse(200, AppliedSchema, PROVIDER_EXAMPLES.applied, 'Applied')
  @ApiKeyedBadRequest()
  @ApiErrors(401)
  @ApiChangeForbidden()
  @ApiConnectionBasics()
  @ApiKeyedConflict(
    [
      C.impactChanged,
      C.connectionNotBound,
      C.validationRequired,
      C.changeNotApplicable,
      C.connectionDisabled,
      C.connectionVersionConflict,
    ],
    '`impact_changed`, `connection_not_bound`, `validation_required` (`reason`), ' +
      '`change_not_applicable` (`reason`), `connection_disabled`, or the SMTP connector limit',
  )
  @ApiKeyedUnprocessable(
    [C.domainNotLinked, C.proofPolicyInvalid],
    '`domain_not_linked`, `proof_policy_invalid`, or a refused destination host',
  )
  async apply(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AppliedView> {
    const result = await this.mailFlow.apply(
      principal,
      scope,
      { id, idempotencyKey, body },
      client,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get the mail flow of a connection',
    description:
      'Desired vs observed: per linked domain its destination servers and stored MX/SPF ' +
      'statuses, the outbound mode, internal routing, the relay proof policy, the relay ' +
      'connector, the relay activity of the last 24 hours (accepted, proof failures, ' +
      'temporary failures, probes) and, for Microsoft 365, the route token version (its value ' +
      'only with `integration:manage`, otherwise masked).',
  })
  @ApiConnectionId()
  @ApiOkExample(MailFlowStateSchema, PROVIDER_EXAMPLES.mailFlow)
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
  ): Promise<MailFlowStateView> {
    return this.mailFlow.state(principal, scope, id);
  }
}

/** Validation runs (step 8.2 §5.2 #19–21; D10, ADR-0079). Translation only. */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/validations', version: '1' })
export class ProviderValidationsController {
  constructor(private readonly validations: ProviderValidationService) {}

  @Post()
  @RequirePermissions(INTEGRATION_MANAGE)
  @ProviderIdempotency(PROVIDER_OPERATIONS.validationCreate)
  @ReturnsSecret({ redactedReplay: true })
  @ProviderRateLimit('validation')
  @ApiOperation({
    summary: 'Start a validation run',
    description:
      '`{ kind }` (`full`, `credentials`, `inbound`, `outbound`) → a `queued` run the ' +
      'integration-worker executes (token, permissions, tenant, domains, DNS, SMTP reachability ' +
      'without DATA, recent deliveries, loops, attestations). An `outbound`/`full` run of a ' +
      'connection whose outbound mode is not `off` gets a single-use `probeAddress` (expires ' +
      'after PROVIDER_PROBE_TTL_SECONDS): send one message to it through the provider (Exchange ' +
      'admin center “Validate connector”, or any message from a linked domain for Google); only ' +
      'its SHA-256 is stored. At most 10 per connection per hour (`429 rate_limited`). Audited ' +
      '`integration.validation_requested`.' +
      REDACTED_REPLAY_RULE('probeAddress') +
      KEYED_RULE,
  })
  @ApiConnectionId()
  @ApiBody({
    schema: zodToOpenApi(CreateValidationBodySchema, { io: 'input' }),
    examples: { full: { value: PROVIDER_EXAMPLES.createValidation } },
  })
  @ApiKeyedResponse(
    201,
    CreatedValidationSchema,
    PROVIDER_EXAMPLES.createdValidation,
    'Queued; `probeAddress` is shown only here (`null` on a replay)',
  )
  @ApiKeyedBadRequest()
  @ApiErrors(401, 403)
  @ApiConnectionBasics()
  @ApiKeyedConflict([C.connectionDisabled], '`connection_disabled`')
  @ApiKeyedUnprocessable()
  async create(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body() body: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CreatedValidationView> {
    const result = await this.validations.create(
      principal,
      scope,
      { id, idempotencyKey, body },
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the validation runs of a connection',
    description:
      'Newest first with kind, status and the result summary (v1 list; the cursor is bound to ' +
      'the connection). From the read replica.',
  })
  @ApiConnectionId()
  @ApiListQuery(ValidationListQuerySchema, VALIDATION_LIST_PARAMETERS)
  @ApiOkExample(ValidationPageSchema, PROVIDER_EXAMPLES.validationPage)
  @ApiListErrors()
  @ApiErrors(401, 403)
  @ApiConnectionBasics()
  list(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Query(new ZodValidationPipe(ValidationListQuerySchema)) query: ValidationListQuery,
  ): Promise<ValidationPage> {
    return this.validations.list(principal, scope, id, query);
  }

  @Get(':runId')
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get a validation run',
    description:
      'The run with its check results (`provider-validation/1`: code, subject, status, ' +
      'severity, bounded non-secret evidence, remediation anchor of the setup guide) and the ' +
      'probe observations (TLS, tenant header and DKIM results; never the probe token or any ' +
      'message content).',
  })
  @ApiConnectionId()
  @ApiRunId()
  @ApiOkExample(ValidationRunDetailSchema, PROVIDER_EXAMPLES.validation)
  @ApiErrors(400, 401, 403)
  @ApiConnectionNotFound([C.validationRunNotFound])
  @ApiUnavailable()
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Param('runId') runId: string,
  ): Promise<ValidationRunDetailView> {
    return this.validations.get(scope, id, runId);
  }
}

/** Customer-specific setup guides (step 8.2 §5.2 #24; D14). Translation only. */
@ApiTags('provider-connections')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'provider-connections/:id/setup-guide', version: '1' })
export class ProviderGuideController {
  constructor(private readonly guides: ProviderGuideService) {}

  @Get()
  @RequirePermissions(INTEGRATION_READ)
  @ApiOperation({
    summary: 'Get the setup guide of a connection',
    description:
      'The customer-specific setup guide (`setup-guide/1`) generated from the connection’s own ' +
      'values: what the gateway will never do, the read-only access grant, domains, inbound ' +
      '(MX, destination, Exchange inbound partner connector and Enhanced Filtering, or the Gmail ' +
      'inbound gateway), outbound (DKIM, SPF, the outbound connector or Gmail host and routing ' +
      'rule, SMTP relay service), internal routing (Microsoft 365 transport rules with the ' +
      'route token), validation, failover and disconnection, with attestation codes. ' +
      '`?format=markdown` returns `text/markdown` as a download ' +
      '(`setup-<provider>-<name>.md`). The route token is masked (`••••` + last 4) without ' +
      '`integration:manage`. No secret-shaped value is ever included.',
  })
  @ApiConnectionId()
  @ApiQuery({
    name: 'format',
    required: false,
    description: '`json` (default) or `markdown`',
    schema: zodToOpenApi(GuideQuerySchema.shape.format, { io: 'input' }),
  })
  @ApiOkResponse({
    description: 'The guide (JSON) or its Markdown rendering',
    content: {
      'application/json': {
        schema: zodToOpenApi(SetupGuideSchema),
        example: {
          schema: 'setup-guide/1',
          provider: 'microsoft_365',
          connection: {
            id: '0192f0c4-d466-7173-8c84-6f708192a3b4',
            displayName: 'Contoso tenant',
            tenantId: '11111111-2222-3333-4444-555555555555',
            tenantName: 'Contoso Ltd',
          },
          generatedAt: '2026-11-18T09:00:00.000Z',
          notice: 'Attestations are statements by your administrator, not proofs.',
          sections: [
            {
              id: 'overview',
              number: 1,
              title: 'Overview',
              paragraphs: ['The gateway never changes your Microsoft 365 configuration.'],
              steps: [],
            },
          ],
        },
      },
      'text/markdown': {
        schema: { type: 'string' },
        example: '# Microsoft 365 setup: Contoso tenant\n',
      },
    },
  })
  @ApiErrors(400, 401, 403)
  @ApiConnectionBasics()
  async get(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id') id: string,
    @Query(new ZodValidationPipe(GuideQuerySchema)) query: GuideQuery,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    if (query.format !== 'markdown') return this.guides.guide(principal, scope, id);
    const { fileName, markdown } = await this.guides.markdown(principal, scope, id);
    res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
    return markdown;
  }
}
