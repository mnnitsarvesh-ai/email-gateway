import { Controller, Get, Query } from '@nestjs/common';
import { ApiOkResponse, ApiOperation } from '@nestjs/swagger';
import { CurrentScope, CursorList, RequirePermissions } from '../../../auth-contracts/decorators';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { zodToOpenApi } from '../../../validation/zod-openapi';
import { ZodValidationPipe } from '../../../validation/zod-validation.pipe';
import { ApiErrors } from '../../auth/api-docs';
import { ApiQueryFrom } from '../../organizations/api-docs';
import { DLP_READ, DlpController } from '../api-docs';
import {
  type DlpIncidentListQuery,
  DlpIncidentListQuerySchema,
  type DlpIncidentPage,
  DlpIncidentPageSchema,
} from '../dto/dlp.schemas';
import { DlpIncidentsService } from '../services/dlp-incidents.service';

/** DLP incidents (step 4.5 D14, D21). Translation only; the logic is in DlpIncidentsService. */
@DlpController()
@Controller({ path: 'dlp/incidents', version: '1' })
export class DlpIncidentsController {
  constructor(private readonly incidents: DlpIncidentsService) {}

  @Get()
  @CursorList('v0')
  @RequirePermissions(DLP_READ)
  @ApiOperation({
    summary: 'List the DLP incidents',
    description:
      'Scan results whose DLP action is not `allow` (the same rounds that emitted ' +
      '`mail.message.dlp_incident.v1`), newest first by received time, cursor-paginated, ' +
      'optionally one `action`, one `direction` and a received-time window `[from, to)`. ' +
      'Categories, detector codes and counts, the policy match (public ids) and the coverage; ' +
      'never values, masked samples, evidence or durations. From the read replica (a result ' +
      'recorded seconds ago may be missing).',
  })
  @ApiQueryFrom(DlpIncidentListQuerySchema)
  @ApiOkResponse({ schema: zodToOpenApi(DlpIncidentPageSchema) })
  @ApiErrors(400, 401, 403)
  list(
    @CurrentScope() scope: TenantScope,
    @Query(new ZodValidationPipe(DlpIncidentListQuerySchema)) query: DlpIncidentListQuery,
  ): Promise<DlpIncidentPage> {
    return this.incidents.list(scope, query);
  }
}
