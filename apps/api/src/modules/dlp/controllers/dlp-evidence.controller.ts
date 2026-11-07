import { Controller, Delete, Get, Header, HttpCode, HttpStatus, Param } from '@nestjs/common';
import {
  ApiAcceptedResponse,
  ApiNoContentResponse,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';
import {
  CurrentPrincipal,
  CurrentScope,
  RequireMfa,
  RequirePermissions,
  UserOnly,
} from '../../../auth-contracts/decorators';
import type { Principal, UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { RateLimit } from '../../../rate-limit/rate-limit.decorator';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ApiErrors } from '../../auth/api-docs';
import { Client } from '../../auth/client-context.decorator';
import { CurrentUser } from '../../auth/current-user.decorator';
import type { ClientContext } from '../../auth/services/session.service';
import { ApiMessageId, messageIdPipe } from '../../deliveries/api-docs';
import {
  ApiDlpScanId,
  ApiEvidenceGone,
  ApiEvidenceNotFound,
  ApiEvidenceUnreadable,
  ApiInconsistentRead,
  DLP_EVIDENCE_READ,
  DLP_MANAGE,
  DlpController,
  dlpScanIdPipe,
} from '../api-docs';
import {
  type DlpEvidencePurged,
  DlpEvidencePurgedSchema,
  type DlpEvidenceResponse,
  DlpEvidenceResponseSchema,
} from '../dto/dlp.schemas';
import { DlpEvidenceService } from '../services/dlp-evidence.service';

/**
 * The audited evidence door and the evidence purge of one round (step 4.5 D16), under the
 * message's scans. Translation only; the logic is in DlpEvidenceService.
 */
@DlpController()
@Controller({ path: 'messages', version: '1' })
export class DlpMessageEvidenceController {
  constructor(private readonly evidence: DlpEvidenceService) {}

  @Get(':messageId/scans/:scanId/dlp-evidence')
  @RequirePermissions(DLP_EVIDENCE_READ)
  @RequireMfa()
  @UserOnly()
  @RateLimit({ bucket: 'dlp-evidence-read', limit: 30, windowSeconds: 60, by: 'principal' })
  @Header('Cache-Control', 'no-store')
  @ApiOperation({
    summary: 'Read the decrypted DLP evidence of a scan round',
    description:
      'The only way to see matched values. An audit row `dlp_evidence.read` (actor, message, ' +
      'scan, match count; no content) is committed **before** the evidence is fetched and ' +
      'decrypted; a failure afterwards adds `dlp_evidence.read_failed` with the reason. The ' +
      'object (under `org/<org>/dlp-evidence/`) is checked against the recorded SHA-256 and ' +
      'size, its data key unwrapped with DLP_EVIDENCE_KEY and the document validated. Aadhaar ' +
      'numbers, private keys and secrets are masked even here; card numbers keep the first 6 ' +
      'and last 4 digits; card verification codes are never stored. Purged evidence answers ' +
      '`410 evidence_purged`, evidence past its retention `410 evidence_expired`. ' +
      'MFA-authenticated users only, 30 reads per user per minute; `Cache-Control: no-store`. ' +
      'Never cache, log or forward the response.',
  })
  @ApiMessageId()
  @ApiDlpScanId()
  @ApiOkResponse({
    schema: zodToOpenApi(DlpEvidenceResponseSchema),
    headers: { 'Cache-Control': { schema: { type: 'string', enum: ['no-store'] } } },
  })
  @ApiErrors(400, 401, 403, 429)
  @ApiEvidenceNotFound()
  @ApiEvidenceGone()
  @ApiEvidenceUnreadable()
  read(
    @CurrentUser() principal: UserPrincipal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Param('scanId', dlpScanIdPipe) scanId: string,
    @Client() client: ClientContext,
  ): Promise<DlpEvidenceResponse> {
    return this.evidence.read(principal, scope, messageId, BigInt(scanId), client);
  }

  @Delete(':messageId/scans/:scanId/dlp-evidence')
  @RequirePermissions(DLP_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({
    summary: 'Purge the DLP evidence of a scan round',
    description:
      'Crypto-shreds the evidence (its wrapped data key is erased in the database, so the ' +
      'object, and any old version of it, is undecryptable), then deletes the object. ' +
      'Idempotent (already purged: 204; a pending object delete is retried). The scan result ' +
      'keeps its masked findings. MFA-authenticated sessions only. Audited as ' +
      '`dlp_evidence.purged`.',
  })
  @ApiMessageId()
  @ApiDlpScanId()
  @ApiNoContentResponse({ description: 'Purged' })
  @ApiErrors(400, 401, 403)
  @ApiEvidenceNotFound()
  @ApiInconsistentRead()
  async purge(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Param('messageId', messageIdPipe) messageId: string,
    @Param('scanId', dlpScanIdPipe) scanId: string,
    @Client() client: ClientContext,
  ): Promise<void> {
    await this.evidence.purgeOne(principal, scope, messageId, BigInt(scanId), client);
  }
}

/** The organization-wide evidence purge (step 4.5 D16). Translation only. */
@DlpController()
@Controller({ path: 'dlp', version: '1' })
export class DlpEvidenceController {
  constructor(private readonly evidence: DlpEvidenceService) {}

  @Delete('evidence')
  @RequirePermissions(DLP_MANAGE)
  @RequireMfa()
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Purge all DLP evidence of the organization',
    description:
      'Crypto-shreds every evidence row of the organization in batches of 500, then deletes ' +
      'the objects, and answers after completion with the counts (objects whose delete failed ' +
      'are undecryptable already and retried by the next purge). Scan results keep their ' +
      'masked findings. MFA-authenticated sessions only. Audited as `dlp_evidence.purged` with ' +
      'the count.',
  })
  @ApiAcceptedResponse({ schema: zodToOpenApi(DlpEvidencePurgedSchema) })
  @ApiErrors(401, 403)
  @ApiInconsistentRead()
  purgeAll(
    @CurrentPrincipal() principal: Principal,
    @CurrentScope() scope: TenantScope,
    @Client() client: ClientContext,
  ): Promise<DlpEvidencePurged> {
    return this.evidence.purgeAll(principal, scope, client);
  }
}
