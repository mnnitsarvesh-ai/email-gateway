import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentScope,
  CursorList,
  RequirePermissions,
  UserOnly,
} from '../../auth-contracts/decorators';
import type { UserPrincipal } from '../../auth-contracts/principal';
import type { TenantScope } from '../../auth-contracts/tenant-scope';
import { ApiCodedError, CodedExceptionFilter } from '../../http/coded-exception';
import { INCONSISTENT_READ } from '../../http/listing/echo-check';
import { ACCESS_TOKEN_SCHEME } from '../../http/openapi';
import { zodToOpenApi } from '../../validation/zod-openapi';
import { ZodValidationPipe } from '../../validation/zod-validation.pipe';
import { ApiErrors } from '../auth/api-docs';
import { Client } from '../auth/client-context.decorator';
import { CurrentUser } from '../auth/current-user.decorator';
import type { ClientContext } from '../auth/services/session.service';
import { ApiListErrors, ApiListQuery, ApiOkExample, MESSAGE_READ } from '../messages/api-docs';
import { MESSAGE_FILTER_FORBIDDEN } from '../messages/messages.errors';
import { SAVED_VIEW_ERROR_CODES as C } from './saved-views.errors';
import {
  type CreateSavedViewBody,
  CreateSavedViewBodySchema,
  SAVED_VIEW_EXAMPLES,
  SAVED_VIEW_LIST_PARAMETERS,
  type SavedView,
  SavedViewIdSchema,
  type SavedViewListQuery,
  SavedViewListQuerySchema,
  type SavedViewPage,
  SavedViewPageSchema,
  SavedViewSchema,
  type UpdateSavedViewBody,
  UpdateSavedViewBodySchema,
} from './saved-views.schemas';
import { SavedViewsService } from './saved-views.service';

const viewIdPipe = new ZodValidationPipe(SavedViewIdSchema.transform((v) => v.toLowerCase()));

const ApiViewId = (): MethodDecorator =>
  ApiParam({ name: 'viewId', format: 'uuid', description: 'Saved view public id' });

const WRITER_NOTE =
  'Read from the writer, not the replica: a saved view is the caller’s own setting and is read ' +
  'right after it is written.';

const MEMBERS_ONLY =
  'For users who are members of the organization: API keys get `403 user_required`, a platform ' +
  'override session `403 saved_views_member_only`.';

const Api403 = (filters: boolean): MethodDecorator =>
  ApiCodedError(
    403,
    'Missing `message:read` (`forbidden`), an API key (`user_required`), a platform override ' +
      'session (`saved_views_member_only`)' +
      (filters
        ? ', or a filter of the definition needs a permission you do not hold ' +
          '(`message_filter_forbidden`: `recipient`/`subject`/`subjectPrefix` need ' +
          '`message:reveal`, `deliveryStatus` `delivery:read`, `quarantineStatus` ' +
          '`quarantine:read`; `filter` and `permission` name it)'
        : ''),
    ['forbidden', 'user_required', C.memberOnly, ...(filters ? [MESSAGE_FILTER_FORBIDDEN] : [])],
    filters ? { filter: { type: 'string' }, permission: { type: 'string' } } : {},
  );

const Api404 = (): MethodDecorator =>
  ApiCodedError(404, 'Unknown id, or a view of another user or organization', [C.notFound]);

const ApiUnavailable = (): MethodDecorator =>
  ApiCodedError(
    503,
    'The database returned a row that does not echo the query (`inconsistent_read`, retry) or ' +
      'a dependency is unavailable',
    [INCONSISTENT_READ, 'service_unavailable'],
  );

const Api400 = (): MethodDecorator =>
  ApiCodedError(
    400,
    '`validation_failed`: the body is not strict JSON of the documented shape, or the definition ' +
      'breaks a rule (`message` lists `"<path>: <issue>"` with paths under `definition`, e.g. ' +
      '`definition.filters.subjectPrefix: must be 3 to 128 characters …`, `definition.filters: ' +
      'Unrecognized key: "foo"`, `definition: must be at most 8192 bytes as JSON`)',
    ['validation_failed'],
  );

/**
 * Saved Email Explorer views of the caller (step 7.2 §2 E4, §3.3, ADR-0061): list, create, get,
 * replace and delete. Translation only (SavedViewsService). `message:read`, users who are members
 * of the organization only.
 */
@ApiTags('saved-views')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UseFilters(CodedExceptionFilter)
@Controller({ path: 'saved-views', version: '1' })
export class SavedViewsController {
  constructor(private readonly views: SavedViewsService) {}

  @Get()
  @RequirePermissions(MESSAGE_READ)
  @UserOnly()
  @CursorList('v1')
  @ApiOperation({
    summary: 'List my saved views',
    description:
      'Your saved views of `kind` (`message_explorer`), newest first (keyset `id`), v1 cursor ' +
      `(signed, bound to you and your organization). ${MEMBERS_ONLY} ${WRITER_NOTE}`,
  })
  @ApiListQuery(SavedViewListQuerySchema, SAVED_VIEW_LIST_PARAMETERS, ['kind'])
  @ApiOkExample(SavedViewPageSchema, SAVED_VIEW_EXAMPLES.page)
  @ApiListErrors()
  @ApiErrors(401)
  @Api403(false)
  @ApiUnavailable()
  list(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(SavedViewListQuerySchema)) query: SavedViewListQuery,
  ): Promise<SavedViewPage> {
    return this.views.list(principal, scope, query);
  }

  @Post()
  @RequirePermissions(MESSAGE_READ)
  @UserOnly()
  @ApiOperation({
    summary: 'Save a view',
    description:
      'Saves an explorer view: `kind` (`message_explorer`), `name` (1-80 characters, unique ' +
      'among your views of the kind, case-insensitive: `409 saved_view_name_taken`) and the ' +
      'strict `definition` `{ version: 1, filters, sort, range, columns }`. `filters` are ' +
      '`GET /messages` query parameters (at most 24, values as strings) and are validated with ' +
      'the same rules as the list, including its filter-level permissions; the JSON is at most ' +
      '8 192 bytes. At most SAVED_VIEWS_MAX_PER_USER (default 50) views per user and kind ' +
      `(\`409 saved_view_limit_reached\`). Audited \`saved_view.created\` (id and kind only: ` +
      `names and filters may hold addresses). ${MEMBERS_ONLY}`,
  })
  @ApiBody({
    schema: zodToOpenApi(CreateSavedViewBodySchema, { io: 'input' }),
    examples: { phishing: { value: SAVED_VIEW_EXAMPLES.create } },
  })
  @ApiCreatedResponse({
    description: 'The saved view',
    schema: { ...zodToOpenApi(SavedViewSchema), example: SAVED_VIEW_EXAMPLES.view },
  })
  @Api400()
  @ApiErrors(401)
  @Api403(true)
  @ApiCodedError(
    409,
    '`saved_view_name_taken` or `saved_view_limit_reached` (`limit`: the per-user maximum)',
    [C.nameTaken, C.limitReached],
    { limit: { type: 'integer' } },
  )
  @ApiUnavailable()
  create(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Body(new ZodValidationPipe(CreateSavedViewBodySchema)) body: CreateSavedViewBody,
    @Client() client: ClientContext,
  ): Promise<SavedView> {
    return this.views.create(principal, scope, body, client);
  }

  @Get(':viewId')
  @RequirePermissions(MESSAGE_READ)
  @UserOnly()
  @ApiOperation({
    summary: 'Get a saved view',
    description: `One of your saved views. ${MEMBERS_ONLY} ${WRITER_NOTE}`,
  })
  @ApiViewId()
  @ApiOkExample(SavedViewSchema, SAVED_VIEW_EXAMPLES.view)
  @ApiErrors(400, 401)
  @Api403(false)
  @Api404()
  @ApiUnavailable()
  get(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('viewId', viewIdPipe) viewId: string,
  ): Promise<SavedView> {
    return this.views.get(principal, scope, viewId);
  }

  @Put(':viewId')
  @RequirePermissions(MESSAGE_READ)
  @UserOnly()
  @ApiOperation({
    summary: 'Replace a saved view',
    description:
      'Replaces the name and the definition (same rules as create) with `expectedRowVersion` ' +
      '(`409 saved_view_conflict` with `currentRowVersion` when the view changed). The kind ' +
      `never changes. Audited \`saved_view.updated\` (id and kind only). ${MEMBERS_ONLY} ` +
      WRITER_NOTE,
  })
  @ApiViewId()
  @ApiBody({
    schema: zodToOpenApi(UpdateSavedViewBodySchema, { io: 'input' }),
    examples: { rename: { value: SAVED_VIEW_EXAMPLES.update } },
  })
  @ApiOkExample(SavedViewSchema, { ...SAVED_VIEW_EXAMPLES.view, rowVersion: 2 })
  @Api400()
  @ApiErrors(401)
  @Api403(true)
  @Api404()
  @ApiCodedError(
    409,
    '`saved_view_conflict` (`currentRowVersion`) or `saved_view_name_taken`',
    [C.conflict, C.nameTaken],
    { currentRowVersion: { type: 'integer' } },
  )
  @ApiUnavailable()
  update(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('viewId', viewIdPipe) viewId: string,
    @Body(new ZodValidationPipe(UpdateSavedViewBodySchema)) body: UpdateSavedViewBody,
    @Client() client: ClientContext,
  ): Promise<SavedView> {
    return this.views.update(principal, scope, viewId, body, client);
  }

  @Delete(':viewId')
  @RequirePermissions(MESSAGE_READ)
  @UserOnly()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Delete a saved view',
    description: `Deletes one of your saved views. Audited \`saved_view.deleted\`. ${MEMBERS_ONLY}`,
  })
  @ApiViewId()
  @ApiNoContentResponse({ description: 'Deleted' })
  @ApiErrors(400, 401)
  @Api403(false)
  @Api404()
  @ApiUnavailable()
  async remove(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('viewId', viewIdPipe) viewId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.views.remove(principal, scope, viewId, client);
  }
}
