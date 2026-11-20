import { Inject, Injectable } from '@nestjs/common';
import {
  ATO_RULES,
  ATO_RULES_VERSION,
  ATO_SETTINGS_BOUNDS,
  ATO_SETTINGS_SCHEMA_VERSION,
  ATO_TRANSACTION_ISOLATION,
  ruleAvailability,
} from '@email-gateway/ato-detection';
import { API_CONFIG } from '../../../api-config.token';
import type { Principal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import {
  parseIdempotencyKey,
  principalKey,
  requestFingerprint,
} from '../../../http/idempotency/idempotency-key';
import {
  type IdempotentResult,
  IdempotencyService,
} from '../../../http/idempotency/idempotency.service';
import { CursorCodec } from '../../../http/cursor/cursor-codec';
import { decideKeysetPage } from '../../../http/listing/scan-budget';
import {
  decimalKey,
  decodeListCursor,
  encodeListCursor,
  listBinding,
} from '../../messages/domain/v1-list';
import { IncidentStores } from '../../incidents/incident-stores';
import {
  ATO_CURSOR_RESOURCES,
  ATO_OPERATIONS,
  ATO_TX_TIMEOUT_MS,
  type AtoConfig,
} from '../ato.constants';
import { atoSettingsConflict, mapAtoStoreError } from '../ato.errors';
import { restrictionView } from '../domain/ato-views';
import type {
  RestrictionListQuery,
  RestrictionPage,
  RulesView,
  SettingsView,
  UpdateSettingsBody,
} from '../dto/ato.schemas';
import { AtoProvidersRepository } from '../repositories/ato-providers.repository';
import { AtoReadRepository, type Db } from '../repositories/ato-read.repository';
import { AtoAccessService } from './ato-access.service';

/** The two identity providers of step 8.5 (§5.1 #24; their adapters in @email-gateway/idp-adapters). */
const IDENTITY_PROVIDERS = ['microsoft_entra', 'google_workspace'] as const;

/**
 * ATO settings, the rule catalogue and SMTP restrictions (step 8.4 §5.1 #23–#26, §4.3): the
 * stored and effective `ato-settings/1`, version and `rowVersion`, bounds, capabilities, sources,
 * identity providers with their integrations (step 8.5), whether a tenant policy uses `ato.*` fields; the PUT through
 * `AtoStore.saveSettings` (strict validation with paths, CAS, a new version and an audit row with
 * the changed paths); the rules with their effective state and availability; the restrictions.
 */
@Injectable()
export class AtoSettingsService {
  constructor(
    @Inject(API_CONFIG)
    private readonly config: Pick<
      AtoConfig,
      | 'ATO_APPROVAL_TTL_HOURS'
      | 'ATO_AUTOMATED_RESPONSES_ENABLED'
      | 'ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR'
      | 'ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG'
    >,
    private readonly reads: AtoReadRepository,
    private readonly providers: AtoProvidersRepository,
    private readonly access: AtoAccessService,
    private readonly stores: IncidentStores,
    private readonly idempotency: IdempotencyService,
    private readonly codec: CursorCodec,
  ) {}

  now(): Date {
    return new Date();
  }

  async get(scope: TenantScope, db?: Db): Promise<SettingsView> {
    const now = this.now();
    const [featureEnabled, loaded, capabilities, sources, atoFieldsInUse, integrations] =
      await Promise.all([
        this.access.enabled(scope, db),
        this.access.settings(scope, db),
        this.access.capabilities(),
        this.reads.sourcesLastEvent(scope, now),
        this.reads.atoFieldsInUse(scope),
        this.providers.nonDisabled(scope, db),
      ]);
    return {
      featureEnabled,
      version: loaded.version,
      rowVersion: loaded.rowVersion,
      schemaVersion: ATO_SETTINGS_SCHEMA_VERSION,
      stored: loaded.stored,
      effective: loaded.settings as unknown as Record<string, unknown>,
      storedInvalid: loaded.invalid,
      learning: {
        active: loaded.learning,
        startedAt: loaded.learningStartedAt?.toISOString() ?? null,
        endsAt: loaded.learningEndsAt?.toISOString() ?? null,
      },
      bounds: ATO_SETTINGS_BOUNDS as unknown as Record<string, unknown>,
      capabilities: capabilities.view,
      sources: (
        [
          'portal_login',
          'account_change',
          'smtp_auth',
          'smtp_submission',
          'outbound_message',
        ] as const
      ).map((source) => ({ source, lastEventAt: sources[source]?.toISOString() ?? null })),
      // Step 8.5: the organization's non-disabled integrations per provider (§6).
      identityProviders: IDENTITY_PROVIDERS.map((provider) => ({
        provider,
        integrations: integrations
          .filter((r) => r.provider === provider)
          .map((r) => ({ id: r.publicId, provider, health: r.healthStatus })),
      })),
      policy: { atoFieldsInUse },
      automation: {
        platformEnabled: this.config.ATO_AUTOMATED_RESPONSES_ENABLED,
        platformMaxPerHour: this.config.ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR,
        approvalTtlHours: this.config.ATO_APPROVAL_TTL_HOURS,
        maxActiveRestrictions: this.config.ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG,
      },
      updatedAt: loaded.updatedAt?.toISOString() ?? null,
    };
  }

  /**
   * `PUT /ato/settings` (#25): `expectedRowVersion` 0 creates the first row (the defaults, as the
   * worker would) and applies the document over it; otherwise CAS on the current row version.
   */
  update(
    principal: Principal,
    scope: TenantScope,
    idempotencyKey: unknown,
    body: UpdateSettingsBody,
    sourceIp: string | null,
  ): Promise<IdempotentResult<SettingsView>> {
    const key = parseIdempotencyKey(idempotencyKey);
    const operation = ATO_OPERATIONS.settingsUpdate;
    return this.idempotency.execute<SettingsView>(
      {
        organizationId: scope.organizationId,
        principal: principalKey(principal),
        operation,
        key,
        resourceId: '-',
        fingerprint: requestFingerprint({ operation, resourceId: '-', body }),
      },
      async (tx) => {
        await this.access.requireEnabled(scope, tx);
        try {
          const store = this.stores.ato;
          const current = await store.loadSettings(tx, scope.organizationId);
          let expected = body.expectedRowVersion;
          if (current === null) {
            if (expected !== 0) throw atoSettingsConflict(0);
            expected = (await store.ensureSettings(tx, scope.organizationId)).rowVersion;
          } else if (current.rowVersion !== expected) {
            throw atoSettingsConflict(current.rowVersion);
          }
          await store.saveSettings(tx, {
            organizationId: scope.organizationId,
            settings: body.settings,
            expectedRowVersion: expected,
            actor: this.access.actorOf(principal),
            sourceIp,
          });
        } catch (error) {
          mapAtoStoreError(error);
        }
        return { statusCode: 200, body: await this.get(scope, tx) };
      },
      { timeoutMs: ATO_TX_TIMEOUT_MS, isolationLevel: ATO_TRANSACTION_ISOLATION },
    );
  }

  /** `GET /ato/rules` (#26): the catalogue with the effective state and availability. */
  async rules(scope: TenantScope): Promise<RulesView> {
    const [loaded, capabilities] = await Promise.all([
      this.access.settings(scope),
      this.access.capabilities(),
    ]);
    return {
      rulesVersion: ATO_RULES_VERSION,
      capabilities: capabilities.view,
      data: ATO_RULES.map((rule) => {
        const effective = loaded.settings.rules[rule.code];
        const availability = ruleAvailability(rule, capabilities.set);
        return {
          id: rule.id,
          code: rule.code,
          title: rule.title,
          category: rule.category,
          strength: rule.strength,
          kinds: [...rule.kinds],
          sources: [...rule.sources],
          correlation: rule.correlation,
          baselineRelative: rule.baselineRelative,
          defaultWeight: rule.defaultWeight,
          effective: {
            enabled: effective?.enabled ?? true,
            weight: effective?.weight ?? rule.defaultWeight,
            params: { ...(effective?.params ?? {}) },
          },
          params: Object.entries(rule.params).map(([name, p]) => ({
            name,
            default: p.default,
            min: p.min,
            max: p.max,
          })),
          capabilities: [...rule.capabilities],
          availability: availability.available
            ? { available: true, reason: null, missing: [] }
            : {
                available: false,
                reason: capabilities.known ? 'capability_unavailable' : 'capabilities_unknown',
                missing: availability.missing,
              },
          explanation: rule.explanation,
        };
      }),
    };
  }

  /** `GET /ato/restrictions` (#23): status `active` by default, newest first. */
  async restrictions(
    principal: Principal,
    scope: TenantScope,
    query: RestrictionListQuery,
  ): Promise<RestrictionPage> {
    const binding = listBinding({
      resource: ATO_CURSOR_RESOURCES.restrictions,
      principal,
      filters: query.filters,
      sort: query.sort,
    });
    const decoded = decodeListCursor(this.codec, binding, query.cursor, 1);
    if (!(await this.access.enabled(scope))) return { data: [], nextCursor: null };
    const f = query.filters;
    const rows = await this.reads.restrictions(scope, {
      filters: {
        statuses: f.status?.values ?? ['active'],
        kinds: f.kind?.values,
        scopes: f.scope?.values,
      },
      beforeId: decoded ? decimalKey(decoded.keys[0]) : undefined,
      take: query.limit + 1,
    });
    const decision = decideKeysetPage({ fetched: rows, limit: query.limit, keyOf: (r) => r.id });
    return {
      data: rows.slice(0, decision.rows).map(restrictionView),
      nextCursor:
        decision.next === null
          ? null
          : encodeListCursor(this.codec, binding, [decision.next.toString()]),
    };
  }
}
