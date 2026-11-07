import { Injectable, Logger } from '@nestjs/common';
import type { Prisma } from '@email-gateway/database';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import { dlpVersionConflict } from '../dlp.errors';
import { checkAadhaarReview } from '../domain/dlp-inputs';
import type { DlpAadhaarPut, DlpComplianceView } from '../dto/dlp.schemas';
import { type AadhaarData, DlpConfigRepository } from '../repositories/dlp-config.repository';
import { complianceImage, complianceView, DlpAuditor } from './dlp-views';
import { DLP_AUDIT, DLP_RESOURCE, DlpWriter } from './dlp-writer';

const DISABLED: AadhaarData = {
  aadhaarEnabled: false,
  aadhaarBasis: null,
  aadhaarReference: null,
  aadhaarAttested: false,
  aadhaarRecordedByUserId: null,
  aadhaarRecordedAt: null,
  aadhaarReviewDueAt: null,
};

/**
 * The organization's Aadhaar detection compliance basis (step 4.5 D17, D21). NI2 runs only when
 * the row is enabled, attested, has a basis and a reference and its review date is in the
 * future (the worker's rule, shown as `active`). Recording (`PUT`) and disabling (`DELETE`) are
 * MFA-authenticated user actions with `dlp:compliance_manage`, compare and set the row
 * `version` (0 = never recorded) and write `dlp_compliance.aadhaar_enabled` /
 * `aadhaar_disabled` with the before-image in the same transaction. The platform records the
 * attestation; whether the basis is lawful is the organization's decision.
 */
@Injectable()
export class DlpComplianceService {
  private readonly logger = new Logger(DlpComplianceService.name);

  constructor(
    private readonly repository: DlpConfigRepository,
    private readonly writer: DlpWriter,
    private readonly auditor: DlpAuditor,
  ) {}

  async get(scope: TenantScope): Promise<DlpComplianceView> {
    return complianceView(await this.repository.findCompliance(scope), new Date());
  }

  async enableAadhaar(
    principal: UserPrincipal,
    scope: TenantScope,
    body: DlpAadhaarPut,
    client: ClientContext,
  ): Promise<DlpComplianceView> {
    const now = new Date();
    const reviewDueAt = checkAadhaarReview(body.reviewDueAt, now);
    const data: AadhaarData = {
      aadhaarEnabled: true,
      aadhaarBasis: body.basis,
      aadhaarReference: body.reference,
      aadhaarAttested: body.attested,
      aadhaarRecordedByUserId: principal.userId,
      aadhaarRecordedAt: now,
      aadhaarReviewDueAt: reviewDueAt,
    };
    const view = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findComplianceForUpdate(tx, scope);
      const currentVersion = current?.version ?? 0;
      if (currentVersion !== body.expectedVersion) throw dlpVersionConflict(currentVersion);
      if (current === null) {
        await this.repository.createCompliance(tx, scope, data);
      } else if (!(await this.repository.updateCompliance(tx, scope, currentVersion, data))) {
        throw dlpVersionConflict(currentVersion);
      }
      const row = await this.repository.complianceOf(tx, scope);
      await this.record(tx, principal, scope, client, DLP_AUDIT.aadhaarEnabled, {
        before: complianceImage(current),
        after: complianceImage(row),
      });
      return complianceView(row, now);
    });
    this.logChange('enabled', scope, view.version);
    return view;
  }

  async disableAadhaar(
    principal: UserPrincipal,
    scope: TenantScope,
    expectedVersion: number | undefined,
    client: ClientContext,
  ): Promise<DlpComplianceView> {
    const now = new Date();
    const result = await this.writer.run(async (tx) => {
      await this.repository.lockOrganization(tx, scope);
      const current = await this.repository.findComplianceForUpdate(tx, scope);
      const currentVersion = current?.version ?? 0;
      if (expectedVersion !== undefined && currentVersion !== expectedVersion) {
        throw dlpVersionConflict(currentVersion);
      }
      // Nothing recorded or already disabled: idempotent, nothing to audit.
      if (current === null || (!current.aadhaarEnabled && !current.aadhaarAttested)) {
        return { view: complianceView(current, now), changed: false };
      }
      if (!(await this.repository.updateCompliance(tx, scope, currentVersion, DISABLED))) {
        throw dlpVersionConflict(currentVersion);
      }
      const row = await this.repository.complianceOf(tx, scope);
      await this.record(tx, principal, scope, client, DLP_AUDIT.aadhaarDisabled, {
        before: complianceImage(current),
        after: complianceImage(row),
      });
      return { view: complianceView(row, now), changed: true };
    });
    if (result.changed) this.logChange('disabled', scope, result.view.version);
    return result.view;
  }

  private record(
    tx: Prisma.TransactionClient,
    principal: UserPrincipal,
    scope: TenantScope,
    client: ClientContext,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    return this.auditor.record(tx, {
      principal,
      scope,
      client,
      action,
      resourceType: DLP_RESOURCE.compliance,
      resourceId: 'aadhaar',
      metadata,
    });
  }

  private logChange(change: string, scope: TenantScope, version: number): void {
    this.logger.log({
      message: `dlp aadhaar detection ${change}`,
      organizationId: scope.organizationId.toString(),
      version,
    });
  }
}
