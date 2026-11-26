import { createHash } from 'node:crypto';
import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { LlmError, type LlmProvider } from '@email-gateway/assistant';
import type { AiChatTenantKeyStatus } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import { AuditService } from '../../../audit/audit.service';
import type { UserPrincipal } from '../../../auth-contracts/principal';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import { SecretBox } from '../../../crypto/secret-box';
import { TransactionRunner } from '../../../database/transaction-runner';
import {
  ASSISTANT_AUDIT,
  AUDIT_RESOURCE,
  type AssistantConfig,
  TENANT_KEY_CLIENT_CACHE_MAX,
  TENANT_KEY_CLIENT_CACHE_TTL_MS,
  tenantKeyAad,
} from '../assistant.constants';
import {
  assistantSettingsConflict,
  assistantTenantKeyNotFound,
  assistantTenantKeyRejected,
  assistantTenantKeysDisabled,
  assistantTenantKeyUnverified,
} from '../assistant.errors';
import { scopeOrganizationPublicId } from '../domain/tool-catalog';
import type { SetProviderKeyBody, TenantKeyView } from '../dto/assistant.schemas';
import { AssistantSettingsRepository } from '../repositories/assistant-settings.repository';
import {
  type ProviderKeyRow,
  ProviderKeysRepository,
} from '../repositories/provider-keys.repository';
import { AssistantMetrics } from './assistant-metrics';
import { LLM_PROVIDER_FACTORY, type LlmProviderFactory, tenantSpec } from './llm-provider-factory';

/** First 16 hex characters of SHA-256 of the API key: the only visible trace of it (D7). */
export function keyFingerprint(apiKey: string): string {
  return createHash('sha256').update(apiKey, 'utf8').digest('hex').slice(0, 16);
}

/**
 * AES-256-GCM of tenant provider keys (step AI-6 D7, I27): the `SecretBox` construction under
 * ASSISTANT_TENANT_KEY_ENCRYPTION_KEY (+ `_PREVIOUS`, decrypt only), AAD
 * `assistant-provider-key:v1:<organizationId>:<keyVersion>` (a ciphertext copied to another row or
 * version does not decrypt), `kid` = `k` + 7 hex of the key's SHA-256 (ADR-0077).
 */
export class TenantKeyCipher {
  private constructor(private readonly box: SecretBox) {}

  /** Null when no encryption key is configured (tenant keys then cannot be stored or used). */
  static fromConfig(
    config: Pick<
      AssistantConfig,
      'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY' | 'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS'
    >,
  ): TenantKeyCipher | null {
    if (!config.ASSISTANT_TENANT_KEY_ENCRYPTION_KEY) return null;
    return new TenantKeyCipher(
      SecretBox.withKeys({
        current: config.ASSISTANT_TENANT_KEY_ENCRYPTION_KEY,
        previous: config.ASSISTANT_TENANT_KEY_ENCRYPTION_KEY_PREVIOUS,
        name: 'ASSISTANT_TENANT_KEY_ENCRYPTION_KEY',
      }),
    );
  }

  get kid(): string {
    return this.box.kid;
  }

  encrypt(organizationId: bigint, keyVersion: number, apiKey: string): string {
    return this.box.encrypt(apiKey, tenantKeyAad(organizationId, keyVersion));
  }

  /** Throws `SecretBoxError` (no detail) for a ciphertext of another row or version. */
  decrypt(organizationId: bigint, keyVersion: number, ciphertext: string): string {
    return this.box.decrypt(ciphertext, tenantKeyAad(organizationId, keyVersion)).plaintext;
  }
}

/** The outcome of a probe (codes only; the provider's text is never kept). */
export type ProbeOutcome =
  | { outcome: 'valid' }
  | { outcome: 'rejected'; code: string }
  | { outcome: 'unverified'; code: string };

/** A built tenant client of one key version (the plaintext lives only inside `provider`). */
export interface TenantClient {
  provider: LlmProvider;
  providerId: 'anthropic' | 'openai';
  model: string;
  keyVersion: number;
}

/** The status a probe outcome stores. */
const STATUS_OF: Readonly<Record<ProbeOutcome['outcome'], AiChatTenantKeyStatus>> = {
  valid: 'valid',
  rejected: 'invalid',
  unverified: 'unverified',
};

/**
 * The optional tenant-supplied provider key (step AI-6 D7, PO Q8, ADR-0097, I27):
 * `PUT|DELETE /assistant/settings/provider-key` and `POST …/validate`, the routing's decrypted
 * client per organization and key version, and the invalidation after a provider refused the key
 * during a turn. The key is probed before it is stored (`models.retrieve` / `GET /models/{id}`
 * through the same provider classes; `401/403` → `422 assistant_tenant_key_rejected`, anything
 * else → `502 assistant_tenant_key_unverified`, nothing stored), encrypted with a dedicated key and
 * row-bound AAD, never returned, logged, audited, put in an event or sent to the model: views,
 * audit rows (`assistant.provider_key_*` with `{ provider, model, fingerprint, outcome }`) and
 * logs carry the fingerprint at most. The CAS is the settings document's `rowVersion` (the key is
 * part of `assistant-settings/1`; every write bumps it).
 */
@Injectable()
export class TenantKeyService {
  private readonly logger = new Logger(TenantKeyService.name);
  private readonly cipher: TenantKeyCipher | null;
  /** `<organizationId>:<keyVersion>` → client and its expiry (insertion order = age). */
  private readonly clients = new Map<string, { client: TenantClient; expiresAt: number }>();

  constructor(
    @Inject(API_CONFIG) private readonly config: AssistantConfig,
    private readonly keys: ProviderKeysRepository,
    private readonly settings: AssistantSettingsRepository,
    private readonly runner: TransactionRunner,
    private readonly audit: AuditService,
    private readonly metrics: AssistantMetrics,
    @Inject(LLM_PROVIDER_FACTORY) private readonly factory: LlmProviderFactory,
  ) {
    this.cipher = TenantKeyCipher.fromConfig(config);
  }

  now(): Date {
    return new Date();
  }

  /** Whether the platform offers tenant keys (gate on and an encryption key configured). */
  get enabled(): boolean {
    return this.config.ASSISTANT_TENANT_KEYS_ENABLED && this.cipher !== null;
  }

  offered(): { enabled: boolean; providers: string[]; models: string[] } {
    return {
      enabled: this.enabled,
      providers: [...this.config.ASSISTANT_TENANT_KEY_PROVIDERS],
      models: [...this.config.ASSISTANT_TENANT_KEY_MODELS],
    };
  }

  /** The stored key as `TenantKeyView` (never the key or its ciphertext), or null. */
  async view(organizationId: bigint): Promise<TenantKeyView | null> {
    const row = await this.keys.find(organizationId);
    return row ? this.viewOf(row) : null;
  }

  async viewOf(row: ProviderKeyRow): Promise<TenantKeyView> {
    return {
      provider: row.provider,
      model: row.model,
      fingerprint: row.keyFingerprint,
      status: row.status,
      setAt: row.setAt.toISOString(),
      setBy: await this.keys.setBy(row.setByUserId),
      lastValidatedAt: row.lastValidatedAt?.toISOString() ?? null,
      lastErrorCode: row.lastErrorCode,
    };
  }

  /** `PUT /assistant/settings/provider-key`: probe, then store (CAS on the settings version). */
  async set(
    principal: UserPrincipal,
    scope: TenantScope,
    body: SetProviderKeyBody,
    sourceIp: string | null,
  ): Promise<TenantKeyView> {
    const cipher = this.requireEnabled();
    const issues: string[] = [];
    if (!this.config.ASSISTANT_TENANT_KEY_PROVIDERS.includes(body.provider)) {
      issues.push('provider: not offered on this platform');
    }
    if (!this.config.ASSISTANT_TENANT_KEY_MODELS.includes(body.model)) {
      issues.push('model: not offered on this platform');
    }
    if (issues.length > 0) throw new BadRequestException(issues);
    await this.assertSettingsVersion(scope, body.expectedRowVersion);

    const fingerprint = keyFingerprint(body.apiKey);
    const organizationPublicId = scopeOrganizationPublicId(principal);
    const probe = await this.probe(
      { provider: body.provider, model: body.model, apiKey: body.apiKey },
      organizationPublicId,
    );
    this.metrics.tenantKeyValidations.inc({ outcome: probe.outcome });
    if (probe.outcome === 'rejected') throw assistantTenantKeyRejected();
    if (probe.outcome === 'unverified') throw assistantTenantKeyUnverified();

    const now = this.now();
    const organizationId = scope.organizationId;
    await this.runner.run(async (tx) => {
      const current = await this.keys.find(organizationId, tx);
      const keyVersion = (current?.keyVersion ?? 0) + 1;
      const stored = await this.keys.put(
        organizationId,
        current?.keyVersion ?? null,
        {
          provider: body.provider,
          model: body.model,
          keyCiphertext: cipher.encrypt(organizationId, keyVersion, body.apiKey),
          keyKid: cipher.kid,
          keyFingerprint: fingerprint,
          keyVersion,
          status: 'valid',
          lastValidatedAt: now,
          setByUserId: principal.userId,
          setAt: now,
        },
        tx,
      );
      if (
        !stored ||
        !(await this.settings.bump(scope, body.expectedRowVersion, {}, tx, this.defaults))
      ) {
        const latest = await this.settings.get(scope, tx);
        throw assistantSettingsConflict(latest?.rowVersion ?? 0);
      }
      await this.recordAudit(
        principal,
        scope,
        ASSISTANT_AUDIT.providerKeySet,
        sourceIp,
        {
          provider: body.provider,
          model: body.model,
          fingerprint,
          outcome: 'valid',
        },
        tx,
      );
    });
    this.logger.log({
      message: 'Assistant tenant provider key stored',
      provider: body.provider,
      fingerprint,
    });
    const row = await this.keys.find(organizationId);
    if (!row) throw assistantTenantKeyNotFound();
    return this.viewOf(row);
  }

  /** `DELETE /assistant/settings/provider-key`: the row goes, `useTenantKey` becomes false. */
  async remove(
    principal: UserPrincipal,
    scope: TenantScope,
    expectedRowVersion: number,
    sourceIp: string | null,
  ): Promise<void> {
    const organizationId = scope.organizationId;
    await this.runner.run(async (tx) => {
      const current = await this.keys.find(organizationId, tx);
      if (!current) throw assistantTenantKeyNotFound();
      const settings = await this.settings.get(scope, tx);
      if ((settings?.rowVersion ?? 0) !== expectedRowVersion) {
        throw assistantSettingsConflict(settings?.rowVersion ?? 0);
      }
      await this.keys.remove(organizationId, tx);
      if (
        !(await this.settings.bump(
          scope,
          expectedRowVersion,
          { useTenantKey: false },
          tx,
          this.defaults,
        ))
      ) {
        const latest = await this.settings.get(scope, tx);
        throw assistantSettingsConflict(latest?.rowVersion ?? 0);
      }
      await this.recordAudit(
        principal,
        scope,
        ASSISTANT_AUDIT.providerKeyRemoved,
        sourceIp,
        {
          provider: current.provider,
          model: current.model,
          fingerprint: current.keyFingerprint,
          outcome: 'removed',
        },
        tx,
      );
    });
    this.dropClients(organizationId);
  }

  /** `POST /assistant/settings/provider-key/validate`: re-probes the stored key (status only). */
  async validate(
    principal: UserPrincipal,
    scope: TenantScope,
    sourceIp: string | null,
  ): Promise<TenantKeyView> {
    const cipher = this.requireEnabled();
    const organizationId = scope.organizationId;
    const row = await this.keys.findSecret(organizationId);
    if (!row) throw assistantTenantKeyNotFound();
    let probe: ProbeOutcome;
    try {
      const apiKey = cipher.decrypt(organizationId, row.keyVersion, row.keyCiphertext);
      probe = await this.probe(
        { provider: row.provider, model: row.model, apiKey },
        scopeOrganizationPublicId(principal),
      );
    } catch {
      // An undecryptable ciphertext (rotated away key): the stored key cannot be used.
      probe = { outcome: 'unverified', code: 'tenant_key_undecryptable' };
    }
    this.metrics.tenantKeyValidations.inc({ outcome: probe.outcome });
    const now = this.now();
    await this.runner.run(async (tx) => {
      await this.keys.setStatus(
        organizationId,
        row.keyVersion,
        STATUS_OF[probe.outcome],
        probe.outcome === 'valid' ? null : probe.code,
        now,
        tx,
      );
      await this.recordAudit(
        principal,
        scope,
        ASSISTANT_AUDIT.providerKeyValidated,
        sourceIp,
        {
          provider: row.provider,
          model: row.model,
          fingerprint: row.keyFingerprint,
          outcome: probe.outcome,
        },
        tx,
      );
    });
    if (probe.outcome !== 'valid') this.dropClients(organizationId);
    const latest = await this.keys.find(organizationId);
    if (!latest) throw assistantTenantKeyNotFound();
    return this.viewOf(latest);
  }

  /**
   * The routing's client of the organization's valid key (cached per organization and key
   * version, at most 100 for 10 minutes); null when there is none, it is not `valid`, or it
   * cannot be decrypted.
   */
  async client(organizationId: bigint, organizationPublicId: string): Promise<TenantClient | null> {
    if (!this.enabled || !this.cipher) return null;
    const row = await this.keys.findSecret(organizationId);
    if (!row || row.status !== 'valid') return null;
    const cacheKey = `${organizationId}:${row.keyVersion}`;
    const now = Date.now();
    const cached = this.clients.get(cacheKey);
    if (cached && cached.expiresAt > now && cached.client.model === row.model) {
      return cached.client;
    }
    let apiKey: string;
    try {
      apiKey = this.cipher.decrypt(organizationId, row.keyVersion, row.keyCiphertext);
    } catch {
      this.logger.warn({
        message: 'Assistant tenant provider key cannot be decrypted',
        fingerprint: row.keyFingerprint,
      });
      return null;
    }
    const client: TenantClient = {
      provider: this.factory(
        tenantSpec(
          this.config,
          { provider: row.provider, model: row.model, apiKey },
          organizationPublicId,
        ),
      ),
      providerId: row.provider,
      model: row.model,
      keyVersion: row.keyVersion,
    };
    this.dropClients(organizationId);
    this.clients.set(cacheKey, { client, expiresAt: now + TENANT_KEY_CLIENT_CACHE_TTL_MS });
    while (this.clients.size > TENANT_KEY_CLIENT_CACHE_MAX) {
      const oldest = this.clients.keys().next().value;
      if (oldest === undefined) break;
      this.clients.delete(oldest);
    }
    return client;
  }

  /**
   * A turn's call was answered 401/403 (D6): the key version becomes `invalid`
   * (`last_error_code`), audited `assistant.provider_key_invalidated` (actor: the user of the
   * turn). A key replaced meanwhile is left alone.
   */
  async invalidate(
    principal: UserPrincipal,
    scope: TenantScope,
    keyVersion: number,
  ): Promise<void> {
    const organizationId = scope.organizationId;
    this.dropClients(organizationId);
    const row = await this.keys.find(organizationId);
    if (!row || row.keyVersion !== keyVersion) return;
    await this.runner.run(async (tx) => {
      if (
        !(await this.keys.setStatus(
          organizationId,
          keyVersion,
          'invalid',
          'provider_auth',
          this.now(),
          tx,
        ))
      ) {
        return;
      }
      await this.recordAudit(
        principal,
        scope,
        ASSISTANT_AUDIT.providerKeyInvalidated,
        null,
        {
          provider: row.provider,
          model: row.model,
          fingerprint: row.keyFingerprint,
          outcome: 'invalid',
        },
        tx,
      );
    });
    this.logger.warn({
      message: 'Assistant tenant provider key refused by the provider',
      provider: row.provider,
      fingerprint: row.keyFingerprint,
    });
  }

  /**
   * The probe (D7): the provider class's `probe` with ASSISTANT_TENANT_KEY_VALIDATION_TIMEOUT_MS.
   * `auth` (401/403) and `client_error` (e.g. an unknown model) → `rejected`; anything else →
   * `unverified`. Codes only: never the provider's message or the key.
   */
  async probe(
    key: { provider: 'anthropic' | 'openai'; model: string; apiKey: string },
    organizationPublicId: string,
  ): Promise<ProbeOutcome> {
    const signal = AbortSignal.timeout(this.config.ASSISTANT_TENANT_KEY_VALIDATION_TIMEOUT_MS);
    try {
      const provider = this.factory(tenantSpec(this.config, key, organizationPublicId));
      if (!provider.probe) return { outcome: 'unverified', code: 'provider_probe_unavailable' };
      await provider.probe(signal);
      return { outcome: 'valid' };
    } catch (error: unknown) {
      if (error instanceof LlmError) {
        if (error.reason === 'auth' || error.reason === 'client_error') {
          return { outcome: 'rejected', code: `provider_${error.reason}` };
        }
        return { outcome: 'unverified', code: `provider_${error.reason}` };
      }
      return {
        outcome: 'unverified',
        code: signal.aborted ? 'provider_timeout' : 'provider_unexpected',
      };
    }
  }

  private get defaults(): { retentionDays: number } {
    return { retentionDays: this.config.ASSISTANT_RETENTION_DEFAULT_DAYS };
  }

  private requireEnabled(): TenantKeyCipher {
    if (!this.config.ASSISTANT_TENANT_KEYS_ENABLED || this.cipher === null) {
      throw assistantTenantKeysDisabled();
    }
    return this.cipher;
  }

  private async assertSettingsVersion(scope: TenantScope, expected: number): Promise<void> {
    const settings = await this.settings.get(scope);
    if ((settings?.rowVersion ?? 0) !== expected) {
      throw assistantSettingsConflict(settings?.rowVersion ?? 0);
    }
  }

  private dropClients(organizationId: bigint): void {
    for (const key of [...this.clients.keys()]) {
      if (key.startsWith(`${organizationId}:`)) this.clients.delete(key);
    }
  }

  private recordAudit(
    principal: UserPrincipal,
    scope: TenantScope,
    action: string,
    sourceIp: string | null,
    metadata: { provider: string; model: string; fingerprint: string; outcome: string },
    tx: Parameters<AuditService['record']>[1],
  ): Promise<void> {
    return this.audit.record(
      {
        organizationId: scope.organizationId,
        actor: this.audit.actorFrom(principal),
        action,
        resourceType: AUDIT_RESOURCE.providerKey,
        resourceId: scopeOrganizationPublicId(principal),
        sourceIp,
        metadata,
      },
      tx,
    );
  }
}
