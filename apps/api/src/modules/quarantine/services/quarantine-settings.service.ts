import { createHash } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { canonicalJson } from '@email-gateway/policy-dsl';
import type { Prisma } from '@email-gateway/database';
import {
  checkSelfService,
  QUARANTINE_SETTINGS_BOUNDS,
  quarantineSettingsSchema,
  type QuarantineSettingsDocument,
  validateQuarantineSettings,
} from '@email-gateway/quarantine';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ClientContext } from '../../auth/services/session.service';
import type {
  PreferencesBody,
  PreferencesResponse,
  SettingsResponse,
  SettingsUpdateBody,
} from '../dto/quarantine.schemas';
import { QUARANTINE_AUDIT, QUARANTINE_RESOURCE } from '../quarantine.constants';
import { quarantineError, settingsConflict, settingsInvalid } from '../quarantine.errors';
import { QuarantineReadRepository } from '../repositories/quarantine-read.repository';
import { QuarantineWriteRepository } from '../repositories/quarantine-write.repository';
import { QuarantineContext, permissionsOf } from './quarantine-context';
import { QuarantineMetrics } from './quarantine-metrics';
import { QuarantineWriter } from './quarantine-writer';

/** Dotted paths of the leaves that differ between two settings documents (audit metadata). */
export function changedPaths(before: unknown, after: unknown, prefix = ''): string[] {
  const isObj = (v: unknown): v is Record<string, unknown> =>
    v !== null && typeof v === 'object' && !Array.isArray(v);
  if (isObj(before) && after === undefined) return changedPaths(before, {}, prefix);
  if (isObj(after) && before === undefined) return changedPaths({}, after, prefix);
  if (!isObj(before) || !isObj(after)) {
    return canonicalJson(before ?? null) === canonicalJson(after ?? null) ? [] : [prefix || '$'];
  }
  const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return keys.flatMap((k) =>
    changedPaths(before[k], after[k], prefix === '' ? k : `${prefix}.${k}`),
  );
}

/**
 * Tenant quarantine settings and end-user preferences (step 5.3 Q24, Q15): `GET` returns the
 * effective settings, the stored document and the bounds (replica); `PUT` validates the whole
 * document (`400 quarantine_settings_invalid` with violations by path), compares `rowVersion`
 * (`409 quarantine_settings_conflict`) and is audited `quarantine.settings_updated` with the
 * changed paths only. Preferences (`digestOptOut`) only when `digest.allowOptOut`.
 */
@Injectable()
export class QuarantineSettingsService {
  constructor(
    private readonly reads: QuarantineReadRepository,
    private readonly writes: QuarantineWriteRepository,
    private readonly context: QuarantineContext,
    private readonly writer: QuarantineWriter,
    private readonly metrics: QuarantineMetrics,
  ) {}

  async get(scope: TenantScope): Promise<SettingsResponse> {
    const [row, org] = await Promise.all([
      this.reads.settings(scope),
      this.reads.orgSettings(scope),
    ]);
    return this.view(row, org);
  }

  private view(
    row: { settings: unknown; rowVersion: number } | null,
    org: Parameters<QuarantineContext['resolve']>[1],
  ): SettingsResponse {
    const effective = this.context.resolve(row?.settings ?? null, org);
    const raw = quarantineSettingsSchema.safeParse(row?.settings ?? {});
    return {
      effective,
      raw: row === null ? null : raw.success ? raw.data : null,
      invalidStored: row !== null && !raw.success,
      bounds: {
        maxHoldDays: this.context.bounds.maxHoldDays,
        maxReviewDays: this.context.bounds.maxReviewDays,
        requestTtlHours: QUARANTINE_SETTINGS_BOUNDS.requestTtlHours,
        digestMaxEntries: QUARANTINE_SETTINGS_BOUNDS.digestMaxEntries,
        alertMinIntervalMinutes: QUARANTINE_SETTINGS_BOUNDS.alertMinIntervalMinutes,
      },
      rowVersion: row?.rowVersion ?? 0,
    };
  }

  async put(
    principal: Principal,
    scope: TenantScope,
    body: SettingsUpdateBody,
    client: ClientContext,
  ): Promise<SettingsResponse> {
    const check = validateQuarantineSettings(body.settings, this.context.bounds);
    if (!check.ok) {
      this.metrics.request('settings', 'invalid');
      throw settingsInvalid(check.violations);
    }
    const doc: QuarantineSettingsDocument = check.settings;
    const sha256 = createHash('sha256').update(canonicalJson(doc)).digest('hex');
    const userId = principal.kind === 'user' ? principal.userId : null;
    const written = await this.writer.run(async (tx) => {
      const current = await this.writes.lockSettings(tx, scope);
      const currentVersion = current?.rowVersion ?? 0;
      if (currentVersion !== body.expectedRowVersion) throw settingsConflict(currentVersion);
      const data = { settings: doc as Prisma.InputJsonValue, sha256, userId };
      if (current === null) {
        await this.writes.insertSettings(tx, scope, data);
      } else if (!(await this.writes.updateSettings(tx, scope, currentVersion, data))) {
        throw settingsConflict(currentVersion);
      }
      await this.writer.record(tx, {
        principal,
        scope,
        client,
        action: QUARANTINE_AUDIT.settingsUpdated,
        resourceType: QUARANTINE_RESOURCE.settings,
        resourceId: null,
        metadata: {
          changedPaths: changedPaths(current?.settings ?? {}, doc).slice(0, 64),
          settingsSha256: sha256,
          rowVersion: currentVersion + 1,
        },
      });
      // The response reads the writer (the replica may lag behind this write).
      return { rowVersion: currentVersion + 1, org: await this.writes.orgSettings(tx, scope) };
    });
    this.metrics.request('settings', 'updated');
    return this.view({ settings: doc, rowVersion: written.rowVersion }, written.org);
  }

  async preferences(principal: Principal, scope: TenantScope): Promise<PreferencesResponse> {
    const caller = await this.context.selfCaller(principal, scope);
    const settings = await this.context.settings(scope);
    if (!settings.endUser.enabled) throw quarantineError('quarantine_entry_not_found', 'Not found');
    return {
      digestOptOut: await this.reads.preferences(scope, caller.userId),
      allowOptOut: settings.digest.allowOptOut,
    };
  }

  async putPreferences(
    principal: Principal,
    scope: TenantScope,
    body: PreferencesBody,
    client: ClientContext,
  ): Promise<PreferencesResponse> {
    const caller = await this.context.selfCaller(principal, scope);
    const settings = await this.context.settings(scope);
    const check = checkSelfService({
      action: 'preferences',
      settings,
      caller: {
        type: 'user',
        verifiedEmail: caller.address,
        permissions: permissionsOf(principal),
      },
      changesDigestOptOut: body.digestOptOut,
    });
    if (!check.allowed) {
      if (check.code === 'quarantine_settings_invalid') {
        throw settingsInvalid([
          {
            path: 'digestOptOut',
            code: 'value_invalid',
            message: 'The organization does not allow opting out of the digest',
          },
        ]);
      }
      throw quarantineError('quarantine_entry_not_found', 'Not found');
    }
    await this.writer.run(async (tx) => {
      await this.writes.upsertPreferences(tx, scope, caller.userId, body.digestOptOut);
      await this.writer.record(tx, {
        principal,
        scope,
        client,
        action: QUARANTINE_AUDIT.preferencesUpdated,
        resourceType: QUARANTINE_RESOURCE.preferences,
        resourceId: principal.kind === 'user' ? principal.userPublicId : null,
        metadata: { digestOptOut: body.digestOptOut },
      });
    });
    this.metrics.request('preferences', 'updated');
    return { digestOptOut: body.digestOptOut, allowOptOut: settings.digest.allowOptOut };
  }
}
