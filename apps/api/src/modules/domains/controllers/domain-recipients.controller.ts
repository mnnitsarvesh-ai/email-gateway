import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  CursorList,
  RequirePermissions,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import type { Page } from '../../../http/pagination';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiDomainId, DOMAIN_MANAGE, DOMAIN_READ, domainIdPipe } from '../api-docs';
import {
  type AddRecipientsResult,
  AddRecipientsResultSchema,
  type ListRecipientsQuery,
  ListRecipientsQuerySchema,
  RecipientPageSchema,
  type RecipientsBody,
  RecipientsBodySchema,
  type RecipientValidationView,
  RecipientValidationSchema,
  type RecipientView,
  type RemoveRecipientsResult,
  RemoveRecipientsResultSchema,
  type SetRecipientValidationInput,
  SetRecipientValidationSchema,
} from '../dto/recipients.schemas';
import { RecipientValidationService } from '../services/recipient-validation.service';

/** Inbound recipient validation and the recipient allow-list of a domain (step 2.2 §4.1, D3). */
@ApiTags('domains')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'domains', version: '1' })
export class DomainRecipientsController {
  constructor(private readonly recipients: RecipientValidationService) {}

  @Get(':id/recipient-validation')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'Get the recipient validation mode',
    description:
      '`accept_all` accepts every local part; `allow_list` checks the domain recipient list: ' +
      'with `enforcement: reject` unknown recipients are refused at RCPT (`550 5.1.1`), with ' +
      '`monitor` they are accepted and only counted. `implemented: false` for `smtp_callout` ' +
      'and `ldap` (not implemented; the mail path accepts everyone).',
  })
  @ApiDomainId()
  @ApiOkResponse({ schema: zodToOpenApi(RecipientValidationSchema) })
  @ApiErrors(400, 401, 403, 404)
  get(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
  ): Promise<RecipientValidationView> {
    return this.recipients.get(scope, id);
  }

  @Put(':id/recipient-validation')
  @RequirePermissions(DOMAIN_MANAGE)
  @ApiOperation({
    summary: 'Set the recipient validation mode',
    description:
      '`{ mode: accept_all }` or `{ mode: allow_list, enforcement: reject | monitor }`. ' +
      '`smtp_callout` and `ldap` are `422 Not implemented`. Enforcing an empty allow-list is ' +
      '`409 Add recipients before enforcing the allow-list`. Changes reach the mail path ' +
      'within about 60 seconds (adapter cache).',
  })
  @ApiDomainId()
  @ApiBody({ schema: zodToOpenApi(SetRecipientValidationSchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RecipientValidationSchema) })
  @ApiErrors(400, 401, 403, 404, 409, 422)
  set(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(SetRecipientValidationSchema)) body: SetRecipientValidationInput,
    @Client() client: ClientContext,
  ): Promise<RecipientValidationView> {
    return this.recipients.set(principal, scope, id, body, client);
  }

  @Get(':id/recipients')
  @CursorList('v0')
  @RequirePermissions(DOMAIN_READ)
  @ApiOperation({
    summary: 'List the recipient allow-list',
    description: 'Local parts, newest first, cursor-paginated, from the read replica.',
  })
  @ApiDomainId()
  @ApiQueryFrom(ListRecipientsQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(RecipientPageSchema) })
  @ApiErrors(400, 401, 403, 404)
  list(
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Query(new ZodValidationPipe(ListRecipientsQuerySchema)) query: ListRecipientsQuery,
  ): Promise<Page<RecipientView>> {
    return this.recipients.list(scope, id, query);
  }

  @Post(':id/recipients')
  @RequirePermissions(DOMAIN_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Add recipients to the allow-list',
    description:
      '1–1000 local parts per request; idempotent (`existing` counts the ones already listed). ' +
      'At most `DOMAIN_RECIPIENTS_MAX_PER_DOMAIN` (default 100 000) per domain: a request ' +
      'that would exceed it adds nothing (`409`).',
  })
  @ApiDomainId()
  @ApiBody({ schema: zodToOpenApi(RecipientsBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(AddRecipientsResultSchema) })
  @ApiErrors(400, 401, 403, 404, 409)
  add(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(RecipientsBodySchema)) body: RecipientsBody,
    @Client() client: ClientContext,
  ): Promise<AddRecipientsResult> {
    return this.recipients.add(principal, scope, id, body, client);
  }

  @Post(':id/recipients/remove')
  @RequirePermissions(DOMAIN_MANAGE)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Remove recipients from the allow-list',
    description: '1–1000 local parts per request; unknown ones are ignored (idempotent).',
  })
  @ApiDomainId()
  @ApiBody({ schema: zodToOpenApi(RecipientsBodySchema, { io: 'input' }) })
  @ApiOkResponse({ schema: zodToOpenApi(RemoveRecipientsResultSchema) })
  @ApiErrors(400, 401, 403, 404)
  remove(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('id', domainIdPipe) id: string,
    @Body(new ZodValidationPipe(RecipientsBodySchema)) body: RecipientsBody,
    @Client() client: ClientContext,
  ): Promise<RemoveRecipientsResult> {
    return this.recipients.remove(principal, scope, id, body, client);
  }
}
