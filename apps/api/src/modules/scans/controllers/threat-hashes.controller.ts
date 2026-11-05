import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  UseFilters,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiTags,
} from '@nestjs/swagger';
import { RequireMfa, RequirePermissions, UserOnly } from '../../../auth-contracts/decorators';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import { CodedExceptionFilter } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME } from '../../../http/openapi';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { ApiHashExists, ApiThreatHashNotFound, PLATFORM_THREAT_INTEL_MANAGE } from '../api-docs';
import {
  type ThreatHashCreate,
  ThreatHashCreateSchema,
  type ThreatHashDeleteQuery,
  ThreatHashDeleteQuerySchema,
  type ThreatHashListQuery,
  ThreatHashListQuerySchema,
  type ThreatHashPage,
  ThreatHashPageSchema,
  ThreatHashParamSchema,
  type ThreatHashView,
  ThreatHashViewSchema,
} from '../dto/threat-hashes.schemas';
import { ThreatHashesService } from '../services/threat-hashes.service';

const sha256Pipe = new ZodValidationPipe(ThreatHashParamSchema);

/**
 * The platform known-threat file hash catalog (step 4.2 A16, A17): SHA-256 hashes the attachment
 * engine treats as malware (`high`/`critical`) or suspicious (`low`/`medium`), platform-wide.
 * Platform users only (no API keys, no override tokens), MFA, `platform:threat_intel_manage`,
 * 60 calls per caller per minute. Translation only; the logic is in ThreatHashesService.
 */
@ApiTags('platform')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@UserOnly()
@UseFilters(CodedExceptionFilter)
@RateLimit({ bucket: 'threat-hashes', limit: 60, windowSeconds: 60, by: 'principal' })
@Controller({ path: 'platform/threat-hashes', version: '1' })
export class ThreatHashesController {
  constructor(private readonly hashes: ThreatHashesService) {}

  @Get()
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @ApiOperation({
    summary: 'List the known-threat file hashes',
    description:
      'The platform catalog the attachment engine consults on every scan (never cached), ' +
      'newest first, cursor-paginated, optionally one `source` (`analyst`, `sandbox`, ' +
      '`feed:<name>`) or one `sha256`. From the read replica: a hash added a moment ago may ' +
      'not be listed yet. 60 calls per caller per minute (shared by the catalog routes).',
  })
  @ApiQueryFrom(ThreatHashListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(ThreatHashPageSchema) })
  @ApiErrors(400, 401, 403, 429)
  list(
    @CurrentUser() principal: UserPrincipal,
    @Query(new ZodValidationPipe(ThreatHashListQuerySchema)) query: ThreatHashListQuery,
  ): Promise<ThreatHashPage> {
    return this.hashes.list(principal, query);
  }

  @Post()
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Add a known-threat file hash',
    description:
      'Adds a SHA-256 (lower-case hex) with its severity, optional MD5 and family, the ' +
      'reason and an optional future `expiresAt`. `source` is `analyst`, the caller is ' +
      'recorded, first/last seen are now. Applies to the next scan of every organization: ' +
      '`high`/`critical` make an attachment `malicious` (`malware.known_hash`), ' +
      '`low`/`medium` `suspicious` (`hash.known_suspicious`). Audited as `threat_hash.added` ' +
      '(hash and metadata, never content). `409 hash_exists` when the hash is listed already.',
  })
  @ApiBody({ schema: zodToOpenApi(ThreatHashCreateSchema, { io: 'input' }) })
  @ApiCreatedResponse({ schema: zodToOpenApi(ThreatHashViewSchema) })
  @ApiErrors(400, 401, 403, 429)
  @ApiHashExists()
  add(
    @CurrentUser() principal: UserPrincipal,
    @Body(new ZodValidationPipe(ThreatHashCreateSchema)) body: ThreatHashCreate,
    @Client() client: ClientContext,
  ): Promise<ThreatHashView> {
    return this.hashes.add(principal, body, client);
  }

  @Delete(':sha256')
  @RequirePermissions(PLATFORM_THREAT_INTEL_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Remove a known-threat file hash',
    description:
      'Deletes the hash from the catalog (the next scan no longer matches it). `reason` is ' +
      'required. Audited as `threat_hash.removed` with the entry as it was (before-image).',
  })
  @ApiParam({ name: 'sha256', description: 'Lower-case hex SHA-256' })
  @ApiQueryFrom(ThreatHashDeleteQuerySchema)
  @ApiNoContentResponse({ description: 'Removed' })
  @ApiErrors(400, 401, 403, 429)
  @ApiThreatHashNotFound()
  async remove(
    @CurrentUser() principal: UserPrincipal,
    @Param('sha256', sha256Pipe) sha256: string,
    @Query(new ZodValidationPipe(ThreatHashDeleteQuerySchema)) query: ThreatHashDeleteQuery,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.hashes.remove(principal, sha256, query.reason, client);
  }
}
