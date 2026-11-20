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
import { ApiBearerAuth, ApiBody, ApiOperation, ApiSecurity, ApiTags } from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequireAnyPermission,
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
import { ApiListErrors, ApiListQuery } from '../../messages/api-docs';
import {
  ApiArchiveConflicts,
  ApiArchiveForbidden,
  ApiArchiveResponse,
  ApiArchiveUnavailable,
  ApiArchiveUnprocessable,
  ApiKeyedErrors,
  ApiMessageIdParam,
  ArchiveIdempotency,
} from '../api-docs';
import { ARCHIVE_OPERATIONS, ARCHIVE_PERMISSIONS as P } from '../archive.constants';
import { ARCHIVE_ERROR_CODES as C } from '../archive.errors';
import {
  ARCHIVE_EXAMPLES as X,
  ArchiveKeyListQuerySchema,
  type ArchiveKeyListQuery,
  type ArchiveKeyPage,
  ArchiveKeyPageSchema,
  type ArchiveSettingsView,
  ArchiveSettingsViewSchema,
  ArchiveStatusSchema,
  type ArchiveStatusView,
  CaptureIssueListQuerySchema,
  type CaptureIssueListQuery,
  type CaptureIssuePage,
  CaptureIssuePageSchema,
  CaptureRetrySchema,
  type CaptureRetryView,
  DisposalListQuerySchema,
  type DisposalListQuery,
  type DisposalPage,
  DisposalPageSchema,
  PAGE_PARAMETERS,
  RotatedKeySchema,
  type RotatedKeyView,
  type RotateKeyBody,
  RotateKeyBodySchema,
  SigningKeysSchema,
  type SigningKeysView,
  type UpdateArchiveSettingsBody,
  UpdateArchiveSettingsBodySchema,
} from '../dto/archive.schemas';
import { ArchiveKeysService } from '../services/archive-keys.service';
import { ArchiveOperationsService } from '../services/archive-operations.service';
import { ArchiveSettingsService } from '../services/archive-settings.service';

const MFA_RULE =
  ' MFA-authenticated users only (`403 mfa_required`; API keys `403 user_required`).';

/**
 * Archive administration (step 8.1 §4.4 #1, #2, #8–#14): settings, key versions and rotation,
 * status, capture issues and their retry, the disposal log and the export signing keys.
 * Translation only (services own the rules).
 */
@ApiTags('archive')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'archive', version: '1' })
export class ArchiveAdminController {
  constructor(
    private readonly settings: ArchiveSettingsService,
    private readonly keys: ArchiveKeysService,
    private readonly operations: ArchiveOperationsService,
  ) {}

  @Get('settings')
  @RequireAnyPermission(P.read, P.journalRead)
  @ApiTags('journaling')
  @ApiOperation({
    summary: 'Get the archive settings',
    description:
      'The effective archive settings of your organization (`archive-settings/1` with the ' +
      'defaults applied: every direction journaled, rejected/quarantined/failed mail not ' +
      'included, scope `all`, policy ARCHIVE honoured, preview on, original download off, ' +
      'journal intake scanning off), ' +
      'whether archiving is enabled and entitled (plan feature `archiving`), the immutability ' +
      'mode, whether S3 Object Lock is available, the default retention policy and the ' +
      '`rowVersion` to send with PUT (0 when no settings exist yet). From the read replica. ' +
      'Step 8.6: `archive:read` or `journal:read`.',
  })
  @ApiArchiveResponse(200, ArchiveSettingsViewSchema, X.settings, 'The archive settings')
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  get(@CurrentScope() scope: TenantScope): Promise<ArchiveSettingsView> {
    return this.settings.get(scope);
  }

  @Put('settings')
  @RequireAnyPermission(P.journalManage, P.manage)
  @ApiTags('journaling')
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.settingsUpdate)
  @ApiOperation({
    summary: 'Update the archive settings',
    description:
      'Changes any of `enabled`, `immutability` (`none` | `governance` | `compliance`), ' +
      '`defaultRetentionPolicyId` and the whole `settings` document, with ' +
      '`expectedRowVersion` (`409 archive_settings_conflict` with `currentRowVersion`). ' +
      'Enabling needs the plan feature `archiving` (`403 archiving_not_enabled`) and a live ' +
      'default retention policy (`422 archive_default_retention_required`); journaling starts ' +
      'with mail received after the enablement (no backfill). Scope domain, department and ' +
      'user ids must be your organization’s (`422 archive_scope_reference_invalid`, `path`). ' +
      '`compliance` can never be weakened (`409 archive_immutability_downgrade_forbidden`); a ' +
      'new governance/compliance mode needs S3 Object Lock (`409 ' +
      'archive_object_lock_unavailable`); a stronger mode is applied to existing records by ' +
      'the archive-worker. Each change increments `generation`; the archive-worker applies it ' +
      'within its settings cache TTL. Audited `archive.settings_updated` (changed paths, never ' +
      'values). Step 8.6: requires `journal:manage` or `archive:manage` and authorizes each ' +
      'changed path: `enabled`, `settings.directions|include|scope|policyArchive|intake` need ' +
      '`journal:manage`; `immutability`, `defaultRetentionPolicyId`, `settings.access` need ' +
      '`archive:manage` (`403 archive_settings_forbidden_path` with `paths`; an omitted section ' +
      'of the replacing `settings` document that changes the effective value counts as a ' +
      'change). Requires the Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(UpdateArchiveSettingsBodySchema, { io: 'input' }),
    examples: { enable: { value: X.settingsUpdate } },
  })
  @ApiArchiveResponse(200, ArchiveSettingsViewSchema, X.settings, 'The updated settings', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden(
    [C.notEnabled, C.settingsForbiddenPath],
    '`archiving_not_enabled` when enabling without the plan feature, ' +
      '`archive_settings_forbidden_path` (`paths`: `{ path, permission }` of each changed path ' +
      'the caller may not change)',
  )
  @ApiCodedError(404, 'The default retention policy is unknown', [C.retentionPolicyNotFound])
  @ApiArchiveConflicts(
    [C.settingsConflict, C.immutabilityDowngradeForbidden, C.objectLockUnavailable],
    '`archive_settings_conflict` (`currentRowVersion`), `archive_immutability_downgrade_forbidden`, ' +
      '`archive_object_lock_unavailable`',
    true,
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiArchiveUnprocessable(
    [C.defaultRetentionRequired, C.scopeReferenceInvalid],
    '`archive_default_retention_required`, `archive_scope_reference_invalid` (`path`)',
    true,
    { path: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async update(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(UpdateArchiveSettingsBodySchema)) body: UpdateArchiveSettingsBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ArchiveSettingsView> {
    const result = await this.settings.update(principal, scope, idempotencyKey, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('keys')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the archive encryption key versions',
    description:
      'The per-tenant key versions (newest first): status (`active`: new captures; `retired`: ' +
      'decrypt-only; `destroyed`: after an organization purge), the root key id that wraps ' +
      'each, times and the rotating user. Never key material. v1 list (`archive_keys`).',
  })
  @ApiListQuery(ArchiveKeyListQuerySchema, {
    ...PAGE_PARAMETERS,
    sort: '`-version` (newest first)',
  })
  @ApiArchiveResponse(200, ArchiveKeyPageSchema, X.keyPage, 'One page of key versions')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  listKeys(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(ArchiveKeyListQuerySchema)) query: ArchiveKeyListQuery,
  ): Promise<ArchiveKeyPage> {
    return this.keys.list(principal, scope, query);
  }

  @Post('keys/rotate')
  @RequirePermissions(P.manage)
  @UserOnly()
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.keyRotate)
  @ApiOperation({
    summary: 'Rotate the archive encryption key',
    description:
      'Creates a new tenant key version (wrapped under the current root key) that becomes ' +
      '`active` for new captures within the archive-worker’s key cache TTL; the previous ' +
      'version becomes `retired` (decrypt-only). Existing records keep their version (no ' +
      're-wrap). Audited `archive.key_rotated` (`fromVersion`, `toVersion`, `reason`). Requires ' +
      'the Idempotency-Key header; rate class `sensitive`.' +
      MFA_RULE,
  })
  @ApiBody({
    schema: zodToOpenApi(RotateKeyBodySchema, { io: 'input' }),
    examples: { annual: { value: X.rotate } },
  })
  @ApiArchiveResponse(201, RotatedKeySchema, X.rotated, 'The new active version', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden()
  @ApiArchiveConflicts([], 'A request with this Idempotency-Key is still in progress', true)
  @ApiArchiveUnavailable()
  async rotate(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Body(new ZodValidationPipe(RotateKeyBodySchema)) body: RotateKeyBody,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RotatedKeyView> {
    const result = await this.keys.rotate(principal, scope, idempotencyKey, body, client.ip);
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('status')
  @RequireAnyPermission(P.read, P.journalRead)
  @ApiOperation({
    summary: 'Get the archive status',
    description:
      'Counts of your organization: capture intents (pending, open, failed, lost, oldest ' +
      'pending), records by status, the search index queue and its lag, disposals in progress ' +
      'and failed, key versions, S3 Object Lock availability and whether archive search is ' +
      'configured and reachable. From the read replica. Step 8.6: `archive:read` or ' +
      '`journal:read`.',
  })
  @ApiArchiveResponse(200, ArchiveStatusSchema, X.status, 'The archive status')
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  status(@CurrentScope() scope: TenantScope): Promise<ArchiveStatusView> {
    return this.settings.status(scope);
  }

  @Get('export-signing-keys')
  @RequirePermissions(P.read)
  @ApiOperation({
    summary: 'List the export signing public keys',
    description:
      'The Ed25519 public keys (SPKI DER, base64url) that verify `manifest.sig` of eDiscovery ' +
      'export packages: the current key and earlier ones still valid for packages signed ' +
      'before a rotation, with their ids (`signingKeyId` of a manifest). See ' +
      'docs/runbooks/ediscovery.md for the verification steps.',
  })
  @ApiArchiveResponse(200, SigningKeysSchema, X.signingKeys, 'The signing public keys')
  @ApiArchiveForbidden()
  signingKeys(): SigningKeysView {
    return this.settings.exportSigningKeys();
  }

  @Get('capture-issues')
  @RequireAnyPermission(P.journalManage, P.manage)
  @ApiTags('journaling')
  @CursorList('v1')
  @ApiOperation({
    summary: 'List capture issues',
    description:
      'Messages whose journal capture `failed` (retryable), was `lost` (the original left the ' +
      'mail store before capture), was `skipped` because it aged out (code `max_age`: the ' +
      'message never reached a capturable state in time and was not archived) or is still ' +
      '`pending` after 6 hours (a message waiting in quarantine is expected to wait and is not ' +
      'listed), newest first: message id, received time, status, a code (never text), ' +
      'attempts, sources. v1 list (`archive_capture_issues`). Step 8.6: `journal:manage` or ' +
      '`archive:manage`.',
  })
  @ApiListQuery(CaptureIssueListQuerySchema, {
    ...PAGE_PARAMETERS,
    status:
      '`failed`, `lost`, `pending` (aged), `skipped` (aged out, `max_age`); comma list ' +
      '(default: all four)',
    sort: '`-receivedAt`',
  })
  @ApiArchiveResponse(200, CaptureIssuePageSchema, X.captureIssues, 'One page of capture issues')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  captureIssues(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(CaptureIssueListQuerySchema)) query: CaptureIssueListQuery,
  ): Promise<CaptureIssuePage> {
    return this.operations.captureIssues(principal, scope, query);
  }

  @Post('capture-issues/:messageId/retry')
  @RequireAnyPermission(P.journalManage, P.manage)
  @ApiTags('journaling')
  @HttpCode(HttpStatus.OK)
  @ArchiveIdempotency(ARCHIVE_OPERATIONS.captureRetry)
  @ApiOperation({
    summary: 'Retry a failed capture',
    description:
      'Moves a `failed` capture intent back to `pending`, due now (the archive-worker retries ' +
      'it). A `lost` capture cannot be retried (`409 archive_capture_retry_not_allowed`). Needs ' +
      'the plan feature `archiving`. Audited `archive.capture_retried`. Step 8.6: ' +
      '`journal:manage` or `archive:manage`. Requires the Idempotency-Key header; rate class ' +
      '`sensitive`.',
  })
  @ApiMessageIdParam()
  @ApiArchiveResponse(200, CaptureRetrySchema, X.captureRetry, 'Queued for capture', true)
  @ApiKeyedErrors()
  @ApiArchiveForbidden([C.notEnabled], '`archiving_not_enabled`')
  @ApiCodedError(404, 'No capture issue for this message in your organization', [
    C.captureIssueNotFound,
  ])
  @ApiArchiveConflicts(
    [C.captureRetryNotAllowed],
    '`archive_capture_retry_not_allowed` (`status`)',
    true,
    { status: { type: 'string' } },
  )
  @ApiArchiveUnavailable()
  async retry(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId') messageId: string,
    @Headers(IDEMPOTENCY_KEY_HEADER) idempotencyKey: unknown,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<CaptureRetryView> {
    const result = await this.operations.retry(
      principal,
      scope,
      messageId,
      idempotencyKey,
      client.ip,
    );
    if (result.replayed) res.setHeader(IDEMPOTENCY_REPLAYED_HEADER, 'true');
    return result.body;
  }

  @Get('disposals')
  @RequirePermissions(P.read)
  @CursorList('v1')
  @ApiOperation({
    summary: 'List the disposal log',
    description:
      'The append-only disposal log of your organization (`archive_disposals`, kept for the ' +
      'compliance tier): message id, received time, reason (`retention_expired`, ' +
      '`review_disposed`, `organization_deleted`), pipeline state, original SHA-256 and size, ' +
      'times. Newest first within `from`/`to` (default the last 30 days, at most 366). v1 list ' +
      '(`archive_disposals`).',
  })
  @ApiListQuery(DisposalListQuerySchema, {
    ...PAGE_PARAMETERS,
    from: 'Start of the request-time range (default `to` − 30 days)',
    to: 'End of the range (exclusive; default now); at most 366 days',
    reason: '`retention_expired`, `review_disposed`, `organization_deleted`; comma list',
    state: '`shredded`, `objects_deleted`, `index_deleted`, `completed`, `failed`; comma list',
    sort: '`-requestedAt`',
  })
  @ApiArchiveResponse(200, DisposalPageSchema, X.disposals, 'One page of disposals')
  @ApiListErrors()
  @ApiArchiveForbidden()
  @ApiArchiveUnavailable()
  disposals(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DisposalListQuerySchema)) query: DisposalListQuery,
  ): Promise<DisposalPage> {
    return this.operations.disposals(principal, scope, query);
  }
}
