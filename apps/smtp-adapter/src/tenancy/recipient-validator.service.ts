import { Inject, Injectable } from '@nestjs/common';
import { type Counter, MetricsService, PrismaService } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import { z } from 'zod';
import { ADAPTER_CONFIG, ADAPTER_LOGGER, type SmtpAdapterConfig } from '../config';
import { cacheKeys } from './cache-keys';
import type { DomainPolicyView } from './domain-policy.service';
import { RedisJsonCache } from './redis-json-cache';

export type RecipientVerdict = 'accept' | 'reject';

/** `domain_recipient_addresses.local_part` is VARCHAR(64) of 1..64 octets. */
const MAX_LOCAL_PART_BYTES = 64;
const UNSUPPORTED_WARN_INTERVAL_MS = 60_000;
/** Bound on the per-domain warn timestamps kept in memory. */
const MAX_WARN_ENTRIES = 10_000;

export type RecipientValidatorConfig = Pick<
  SmtpAdapterConfig,
  'SMTP_RECIPIENT_DELIMITER' | 'SMTP_DOMAIN_CACHE_TTL_SECONDS' | 'SMTP_NEGATIVE_CACHE_TTL_SECONDS'
>;

/** Lower-cased, NFC: the form stored in `domain_recipient_addresses.local_part`. */
export function normalizeLocalPart(localPart: string): string {
  return localPart.normalize('NFC').toLowerCase();
}

/**
 * Inbound recipient validation per domain (step 2.2 D3):
 *
 * | settings                               | behaviour                                       |
 * | -------------------------------------- | ----------------------------------------------- |
 * | `none` / no row                        | accept-all                                      |
 * | `list` + `reject_unknown_recipients`   | authoritative allow-list: unknown → reject      |
 * | `list` without it                      | monitor: accept, count the would-reject         |
 * | `smtp_callout`, `ldap`                 | not implemented: accept, count, warn 1/min/dom. |
 *
 * Lookup: exact lower-cased local part; if absent and it contains one of the
 * SMTP_RECIPIENT_DELIMITER characters, retry with the part before the first one. Results are
 * cached per address (`sa:rcpt:{domainId}:{localPart}`). `reject` is returned only in the
 * authoritative mode; database errors propagate (the policy tempfails).
 */
@Injectable()
export class RecipientValidator {
  private readonly unknown: Counter<'enforced'>;
  private readonly unsupported: Counter;
  private readonly logger: Logger;
  private readonly warnedAt = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: RedisJsonCache,
    metrics: MetricsService,
    @Inject(ADAPTER_CONFIG) private readonly config: RecipientValidatorConfig,
    @Inject(ADAPTER_LOGGER) logger: Logger,
  ) {
    this.unknown = metrics.counter(
      'smtp_policy_recipient_unknown_total',
      'Recipients not in the domain allow-list (enforced = rejected, otherwise monitor mode)',
      ['enforced'],
    );
    this.unsupported = metrics.counter(
      'smtp_policy_recipient_validation_unsupported_total',
      'Recipients of domains configured with a recipient validation mode that is not implemented',
    );
    this.logger = logger.child({ component: 'recipient-validator' });
  }

  async validate(domain: DomainPolicyView, localPart: string): Promise<RecipientVerdict> {
    switch (domain.recipientValidation) {
      case 'none':
        return 'accept';
      case 'list': {
        if (await this.isListed(domain.domainId, localPart)) return 'accept';
        const enforced = domain.rejectUnknownRecipients;
        this.unknown.inc({ enforced: String(enforced) });
        if (enforced) return 'reject';
        this.logger.debug(
          { domainId: String(domain.domainId), domain: domain.name },
          'monitor mode: recipient not in the allow-list (accepted)',
        );
        return 'accept';
      }
      case 'smtp_callout':
      case 'ldap':
        this.unsupported.inc();
        this.warnUnsupported(domain);
        return 'accept';
      default:
        // An enum value this build does not know: never a definitive "no" (D3).
        this.unsupported.inc();
        this.warnUnsupported(domain);
        return 'accept';
    }
  }

  private async isListed(domainId: bigint, rawLocalPart: string): Promise<boolean> {
    const localPart = normalizeLocalPart(rawLocalPart);
    if (await this.lookup(domainId, localPart)) return true;
    const base = this.withoutExtension(localPart);
    return base !== null && (await this.lookup(domainId, base));
  }

  /** The part before the first delimiter character, or null when there is none. */
  private withoutExtension(localPart: string): string | null {
    const delimiters = this.config.SMTP_RECIPIENT_DELIMITER;
    if (delimiters === '') return null;
    let cut = -1;
    for (const delimiter of delimiters) {
      const index = localPart.indexOf(delimiter);
      if (index > 0 && (cut === -1 || index < cut)) cut = index;
    }
    return cut === -1 ? null : localPart.slice(0, cut);
  }

  private async lookup(domainId: bigint, localPart: string): Promise<boolean> {
    const bytes = Buffer.byteLength(localPart);
    if (bytes === 0 || bytes > MAX_LOCAL_PART_BYTES) return false;
    const found = await this.cache.getOrLoad<true>({
      cache: 'recipient',
      key: cacheKeys.recipient(domainId, localPart),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: z.literal(true),
      load: async () => {
        const row = await this.prisma.domainRecipientAddress.findUnique({
          where: { domainId_localPart: { domainId, localPart } },
          select: { id: true },
        });
        return row ? true : null;
      },
    });
    return found === true;
  }

  private warnUnsupported(domain: DomainPolicyView): void {
    const key = String(domain.domainId);
    const now = Date.now();
    if (now - (this.warnedAt.get(key) ?? 0) < UNSUPPORTED_WARN_INTERVAL_MS) return;
    if (this.warnedAt.size >= MAX_WARN_ENTRIES) this.warnedAt.clear();
    this.warnedAt.set(key, now);
    this.logger.warn(
      { domainId: key, domain: domain.name, mode: domain.recipientValidation },
      'recipient validation mode not implemented; accepting all recipients',
    );
  }
}
