import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import {
  DomainNameError,
  normalizeDomainName,
  type RecipientValidation,
  resolveActiveDomain,
} from '@email-gateway/database';
import { normalizeHostForComparison } from '@email-gateway/mail-routing';
import { z } from 'zod';
import { ADAPTER_CONFIG, type SmtpAdapterConfig } from '../config';
import { cacheKeys, domainInvalidationKeys, routingInvalidationKeys } from './cache-keys';
import { RedisJsonCache } from './redis-json-cache';

/** Everything the in-session services need to know about a tenant domain (step 2.2 D5). */
export interface DomainPolicyView {
  domainId: bigint;
  domainPublicId: string;
  organizationId: bigint;
  /** Normalized ASCII name. */
  name: string;
  inboundEnabled: boolean;
  outboundEnabled: boolean;
  recipientValidation: RecipientValidation;
  rejectUnknownRecipients: boolean;
  /** `domain_settings.max_message_size_bytes`; null = no domain-level limit. */
  maxMessageSizeBytes: number | null;
  /** Any `domain_dkim_keys` row with status `active`. */
  hasActiveDkimKey: boolean;
}

const decimal = z.string().regex(/^\d{1,20}$/);

/** Cached JSON form (bigints as decimal strings). */
const viewDto = z.object({
  domainId: decimal,
  domainPublicId: z.string(),
  organizationId: decimal,
  name: z.string(),
  inboundEnabled: z.boolean(),
  outboundEnabled: z.boolean(),
  recipientValidation: z.enum(['none', 'list', 'smtp_callout', 'ldap']),
  rejectUnknownRecipients: z.boolean(),
  maxMessageSizeBytes: z.number().int().nonnegative().nullable(),
  hasActiveDkimKey: z.boolean(),
});
type ViewDto = z.infer<typeof viewDto>;

export type DomainPolicyConfig = Pick<
  SmtpAdapterConfig,
  'SMTP_DOMAIN_CACHE_TTL_SECONDS' | 'SMTP_NEGATIVE_CACHE_TTL_SECONDS'
>;

/**
 * Tenant resolution for the policy and socketmap (step 2.2 D5): `resolveActiveDomain` (active
 * domain of an active organization, verified owner) plus the domain's settings and DKIM
 * readiness, read from the **writer** (ADR-0014) with at most three indexed queries on a miss,
 * and cached in Redis under `sa:dom:{name}` (positive and negative TTL). Cache errors fall back
 * to the database; database errors propagate (the caller fails closed).
 */
@Injectable()
export class DomainPolicyService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cache: RedisJsonCache,
    @Inject(ADAPTER_CONFIG) private readonly config: DomainPolicyConfig,
  ) {}

  /** Normalized ASCII name, or null when the input is not a valid domain name. */
  static normalize(rawName: string): string | null {
    try {
      return normalizeDomainName(rawName, { allowTestNames: true }).ascii;
    } catch (err) {
      if (err instanceof DomainNameError) return null;
      throw err;
    }
  }

  async get(rawName: string): Promise<DomainPolicyView | null> {
    const name = DomainPolicyService.normalize(rawName);
    if (name === null) return null;
    const dto = await this.cache.getOrLoad<ViewDto>({
      cache: 'domain',
      key: cacheKeys.domain(name),
      ttlSeconds: this.config.SMTP_DOMAIN_CACHE_TTL_SECONDS,
      negativeTtlSeconds: this.config.SMTP_NEGATIVE_CACHE_TTL_SECONDS,
      schema: viewDto,
      load: () => this.load(name),
    });
    return dto === null ? null : fromDto(dto);
  }

  /** Drops the cached view and the socketmap keys derived from the name (D5). */
  async invalidate(rawName: string): Promise<void> {
    const name = DomainPolicyService.normalize(rawName);
    if (name === null) return;
    await this.cache.delete('domain', domainInvalidationKeys(name));
  }

  /**
   * Drops the socketmap answers derived from a domain's destinations
   * (`domain.routing.changed.v1`, step 2.3 R2): the domain's route list and the TLS policies of
   * every named host (old and new). The domain view itself is unchanged by a routing change.
   */
  async invalidateRouting(rawName: string, hosts: readonly string[]): Promise<void> {
    const name = DomainPolicyService.normalize(rawName);
    if (name === null) return;
    const normalized = hosts
      .map((host) => normalizeHostForComparison(host))
      .filter((host) => host.length > 0);
    await this.cache.delete('route', routingInvalidationKeys(name, normalized));
  }

  private async load(name: string): Promise<ViewDto | null> {
    const domain = await resolveActiveDomain(this.prisma, name);
    if (!domain) return null;
    const [settings, dkimKey] = await Promise.all([
      this.prisma.domainSetting.findUnique({
        where: { domainId: domain.domainId },
        select: {
          recipientValidation: true,
          rejectUnknownRecipients: true,
          maxMessageSizeBytes: true,
        },
      }),
      this.prisma.domainDkimKey.findFirst({
        where: { domainId: domain.domainId, status: 'active' },
        select: { id: true },
      }),
    ]);
    return {
      domainId: domain.domainId.toString(),
      domainPublicId: domain.domainPublicId,
      organizationId: domain.organizationId.toString(),
      name: domain.name,
      inboundEnabled: domain.inboundEnabled,
      outboundEnabled: domain.outboundEnabled,
      recipientValidation: settings?.recipientValidation ?? 'none',
      rejectUnknownRecipients: settings?.rejectUnknownRecipients ?? false,
      maxMessageSizeBytes: settings?.maxMessageSizeBytes ?? null,
      hasActiveDkimKey: dkimKey !== null,
    };
  }
}

function fromDto(dto: ViewDto): DomainPolicyView {
  return {
    ...dto,
    domainId: BigInt(dto.domainId),
    organizationId: BigInt(dto.organizationId),
  };
}
