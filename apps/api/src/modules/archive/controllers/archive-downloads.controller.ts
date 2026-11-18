import { Controller, Get, Header, Param, Res, StreamableFile } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiProduces,
  ApiSecurity,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireAnyPermission,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { ApiCodedError } from '../../../http/coded-exception';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME } from '../../../http/openapi';
import { Client } from '../../auth/client-context.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import {
  ApiArchiveForbidden,
  ApiArchiveUnavailable,
  ApiContentGone,
  ApiIntegrityFailed,
} from '../api-docs';
import { ArchiveRateLimit } from '../archive-rate-limit';
import { ARCHIVE_PERMISSIONS as P, NO_STORE } from '../archive.constants';
import { ARCHIVE_ERROR_CODES as C, archiveDownloadTokenInvalid } from '../archive.errors';
import { ArchiveDownloadsService } from '../services/archive-downloads.service';

/** The shape of an archive download token (`v1.<payload>.<mac>`, base64url parts). */
const TOKEN = /^v1\.[A-Za-z0-9_-]{1,900}\.[A-Za-z0-9_-]{1,100}$/;

/**
 * Archive and eDiscovery downloads through single-use grants (step 8.1 §4.4 #22; A18, A19).
 * Streams the decrypted bytes; never an S3 URL. Translation only.
 */
@ApiTags('archive')
@ApiBearerAuth(ACCESS_TOKEN_SCHEME)
@ApiSecurity(API_KEY_SCHEME)
@Controller({ path: 'archive/downloads', version: '1' })
export class ArchiveDownloadsController {
  constructor(private readonly downloads: ArchiveDownloadsService) {}

  @Get(':token')
  @RequireAnyPermission(P.retrieve, P.export)
  @UserOnly()
  @ArchiveRateLimit('download')
  @Header('Cache-Control', NO_STORE)
  @ApiOperation({
    summary: 'Download through a single-use archive grant',
    description:
      'The token of POST /archive/messages/{messageId}/download-grants (an original message: ' +
      'needs `archive:retrieve`) or of POST /ediscovery/cases/{caseId}/exports/{exportId}/' +
      'download-grants (an export package: needs `archive:export` and `ediscovery:manage`), by ' +
      'the same user in the same organization, once, before it expires (`404 ' +
      'archive_download_token_invalid`, `410 archive_download_token_used`). The target is ' +
      're-checked on the writer (a disposed record `410 archive_content_unavailable`, an ' +
      'expired export `410 ediscovery_export_expired`); the audit row (`archive.downloaded` / ' +
      '`ediscovery.downloaded`) is committed before the bytes are streamed with `Content-Type: ' +
      'application/octet-stream`, `Content-Disposition: attachment`, `X-Content-Type-Options: ' +
      'nosniff`, `Cache-Control: no-store` and `Content-Security-Policy: sandbox; default-src ' +
      "'none'`. The plaintext SHA-256 is verified while streaming: a mismatch aborts the " +
      'transfer (the client sees an incomplete body; alerted). Customer-only: refused under a ' +
      'platform override. ARCHIVE_DOWNLOAD_GRANTS_PER_HOUR per user.',
  })
  @ApiParam({ name: 'token', description: '`v1.<payload>.<mac>`' })
  @ApiProduces('application/octet-stream')
  @ApiOkResponse({
    description: 'The decrypted bytes (EML or ZIP)',
    schema: { type: 'string', format: 'binary' },
  })
  @ApiArchiveForbidden([C.overrideForbidden], '`archive_override_forbidden`')
  @ApiCodedError(404, 'Unknown, expired or foreign token', [C.downloadTokenInvalid])
  @ApiCodedError(409, 'The target is blocked or the export is not ready', [
    C.downloadBlocked,
    C.exportNotReady,
  ])
  @ApiContentGone()
  @ApiCodedError(410, 'Token used, record disposed or export expired', [
    C.downloadTokenUsed,
    C.contentUnavailable,
    C.exportExpired,
  ])
  @ApiIntegrityFailed()
  @ApiArchiveUnavailable()
  async download(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('token') token: string,
    @Client() client: ClientContext,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    if (typeof token !== 'string' || !TOKEN.test(token)) throw archiveDownloadTokenInvalid();
    const file = await this.downloads.download(principal, scope, token, client);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "sandbox; default-src 'none'");
    return new StreamableFile(file.body, {
      type: 'application/octet-stream',
      disposition: `attachment; filename="${file.filename}"`,
      length: file.sizeBytes,
    });
  }
}
