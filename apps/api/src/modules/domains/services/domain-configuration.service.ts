import { Inject, Injectable } from '@nestjs/common';
import type { DkimAlgorithm, Prisma } from '@email-gateway/database';
import { API_CONFIG } from '../../../api-config.token';
import type { TenantScope } from '../../../auth-contracts/tenant-scope';
import type { ApiConfig } from '../../../config';
import { SecretBox } from '../../../crypto/secret-box';
import { TransactionRunner } from '../../../database/transaction-runner';
import { OWNED_STATUSES } from '../domain/state-machine';
import { DAY_MS } from '../domains.constants';
import { type DkimKeyPair, generateDkimKeyPair, generateDkimSelector } from '../engine/dkim';
import { type GatewayDnsConfig, gatewayDnsConfigFrom } from '../engine/gateway-dns-config';
import { buildExpectedRecords } from '../engine/records';
import { generateVerificationToken } from '../engine/verification';
import { type DkimKeyRow, DkimKeysRepository } from '../repositories/dkim-keys.repository';
import { DnsRecordsRepository } from '../repositories/dns-records.repository';
import { type DomainRow, DomainsRepository } from '../repositories/domains.repository';
import { VerificationsRepository } from '../repositories/verifications.repository';

type Client = Prisma.TransactionClient;

export type DomainConfigurationConfig = Pick<
  ApiConfig,
  | 'GATEWAY_MX_HOSTS'
  | 'GATEWAY_SPF_INCLUDE'
  | 'GATEWAY_DMARC_RUA'
  | 'GATEWAY_DMARC_RUF'
  | 'DOMAIN_VERIFICATION_LABEL'
  | 'DOMAIN_VERIFICATION_TTL_DAYS'
>;

/** Additional authenticated data binding a DKIM private key to its domain and selector. */
export function dkimKeyAad(domainPublicId: string, selector: string): string {
  return `dkim:${domainPublicId}:${selector}`;
}

const SELECTOR_ATTEMPTS = 8;
/** Keys that make a family "present" for the configuration pass (D12). */
const LIVE_KEY_STATUSES = new Set(['pending', 'active']);
/** Record rows the configuration pass reconciles (D6, D12). */
const RECONCILED_PREFIXES = ['mx:', 'dkim:'];

/**
 * Configuration materialization (D12): makes a domain's verification row, DKIM key and DNS
 * record rows complete. Idempotent; called on create, before manual verification and by the
 * scheduler. Never changes the domain status. Key pairs are generated outside transactions
 * (they take a while), encrypted with `SecretBox` and inserted inside.
 */
@Injectable()
export class DomainConfigurationService {
  private readonly gateway: GatewayDnsConfig;

  constructor(
    @Inject(API_CONFIG) private readonly config: DomainConfigurationConfig,
    private readonly transactions: TransactionRunner,
    private readonly secretBox: SecretBox,
    private readonly domains: DomainsRepository,
    private readonly verifications: VerificationsRepository,
    private readonly records: DnsRecordsRepository,
    private readonly keys: DkimKeysRepository,
  ) {
    this.gateway = gatewayDnsConfigFrom(config);
  }

  /** `ensure(domain)` of D12 in its own transaction (with the domain row locked). */
  async ensure(scope: TenantScope, domainId: bigint, now: Date = new Date()): Promise<void> {
    const keys = await this.keys.listForDomain(scope, domainId);
    const generated = needsKey(keys, 'rsa_2048') ? [await generateDkimKeyPair('rsa_2048')] : [];
    await this.transactions.run(async (tx) => {
      const domain = await this.domains.lockById(tx, scope, domainId);
      if (!domain || domain.status === 'deleted') return;
      await this.materialize(tx, scope, domain, { generated, now });
    });
  }

  /**
   * The transactional part of `ensure`; the caller holds the domain row lock. `generated` are
   * pre-generated key pairs: each is inserted only if its algorithm has no pending/active key.
   */
  async materialize(
    tx: Client,
    scope: TenantScope,
    domain: DomainRow,
    options: { generated: readonly DkimKeyPair[]; now: Date },
  ): Promise<void> {
    const { now } = options;
    let verification = await this.verifications.findCurrent(scope, domain.id, tx);
    const expiresAt = new Date(now.getTime() + this.config.DOMAIN_VERIFICATION_TTL_DAYS * DAY_MS);
    if (!verification && domain.status === 'pending_verification') {
      verification = await this.verifications.create(tx, scope, {
        domainId: domain.id,
        token: generateVerificationToken(),
        status: 'pending',
        expiresAt,
        nextCheckAt: domain.nextCheckAt,
      });
    } else if (!verification && OWNED_STATUSES.has(domain.status)) {
      // A domain owned before this step (e.g. the seeded demo domain): monitor its ownership TXT.
      verification = await this.verifications.create(tx, scope, {
        domainId: domain.id,
        token: generateVerificationToken(),
        status: 'verified',
        expiresAt,
        verifiedAt: domain.verifiedAt ?? now,
      });
    }

    const keys = await this.keys.listForDomain(scope, domain.id, tx);
    for (const pair of options.generated) {
      if (!needsKey(keys, pair.algorithm)) continue;
      keys.push(await this.insertKey(tx, scope, domain, pair, keys, now));
    }
    await this.syncRecords(tx, scope, domain, verification?.token ?? null, keys);
  }

  /**
   * Inserts a pending key with a fresh selector (retried on collision with the domain's
   * selectors), its private key encrypted with AAD `dkim:<domain public id>:<selector>`.
   */
  async insertKey(
    tx: Client,
    scope: TenantScope,
    domain: Pick<DomainRow, 'id' | 'publicId'>,
    pair: DkimKeyPair,
    existing: readonly Pick<DkimKeyRow, 'selector'>[],
    now: Date,
  ): Promise<DkimKeyRow> {
    const taken = new Set(existing.map((k) => k.selector));
    let selector = generateDkimSelector(pair.algorithm, now);
    for (let i = 1; taken.has(selector); i++) {
      if (i >= SELECTOR_ATTEMPTS) throw new Error('Could not allocate a unique DKIM selector');
      selector = generateDkimSelector(pair.algorithm, now);
    }
    return this.keys.create(tx, scope, {
      domainId: domain.id,
      selector,
      algorithm: pair.algorithm,
      publicKey: pair.publicKeyDns,
      privateKeyCiphertext: this.secretBox.encrypt(
        pair.privateKeyPem,
        dkimKeyAad(domain.publicId, selector),
      ),
    });
  }

  /**
   * Upserts the D6 record rows by `record_key` (keeping the current SPF/DMARC recommendations)
   * and deletes `mx:*` rows of hosts no longer configured and `dkim:*` rows of keys that are no
   * longer published.
   */
  async syncRecords(
    tx: Client,
    scope: TenantScope,
    domain: Pick<DomainRow, 'id' | 'name'>,
    verificationToken: string | null,
    keys: readonly DkimKeyRow[],
  ): Promise<void> {
    const existing = await this.records.listForDomain(scope, domain.id, tx);
    const current = new Map(existing.map((r) => [r.recordKey, r]));
    const keyIds = new Map(keys.map((k) => [k.selector, k.id]));
    const expected = buildExpectedRecords({
      domain: domain.name,
      verificationToken,
      dkimKeys: keys.map((k) => ({
        selector: k.selector,
        algorithm: k.algorithm,
        publicKeyDns: k.publicKey,
        status: k.status,
      })),
      gateway: this.gateway,
      recommendations: {
        spf: current.get('spf')?.expectedValue,
        dmarc: current.get('dmarc')?.expectedValue,
      },
    });
    for (const record of expected) {
      await this.records.upsert(tx, scope, domain.id, {
        recordKey: record.recordKey,
        purpose: record.purpose,
        recordType: record.type,
        host: record.host,
        expectedValue: record.value,
        dkimKeyId: record.dkimSelector ? (keyIds.get(record.dkimSelector) ?? null) : null,
      });
    }
    const wanted = new Set(expected.map((r) => r.recordKey));
    const stale = existing
      .map((r) => r.recordKey)
      .filter((key) => !wanted.has(key) && RECONCILED_PREFIXES.some((p) => key.startsWith(p)));
    await this.records.deleteByKeys(tx, scope, domain.id, stale);
  }
}

/** True when the algorithm has no pending or active key (a new one is needed). */
export function needsKey(
  keys: readonly Pick<DkimKeyRow, 'algorithm' | 'status'>[],
  algorithm: DkimAlgorithm,
): boolean {
  return !keys.some((k) => k.algorithm === algorithm && LIVE_KEY_STATUSES.has(k.status));
}
