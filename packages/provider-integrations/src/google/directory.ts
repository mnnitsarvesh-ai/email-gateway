import { z } from 'zod';
import type { ProviderDirectory, ProviderDomainStatus, TenantIdentity } from '../directory';
import { ProviderRequestError } from '../errors';
import { GOOGLE_CUSTOMER_ID, isDomainName, type GrantRef } from '../types';
import type { GoogleAdminClient } from './admin-client';

export const GOOGLE_CUSTOMER_PATH = '/admin/directory/v1/customers/my_customer';
export const GOOGLE_DOMAINS_PATH = '/admin/directory/v1/customer/my_customer/domains';

const customer = z.object({
  id: z.string(),
  customerDomain: z.string().max(253).nullable().optional(),
  postalAddress: z
    .object({ organizationName: z.string().max(256).nullable().optional() })
    .nullable()
    .optional(),
});

const googleDomain = z.object({
  domainName: z.string().max(253),
  verified: z.boolean().nullable().optional(),
  isPrimary: z.boolean().nullable().optional(),
  domainAliases: z
    .array(
      z.object({
        domainAliasName: z.string().max(253),
        verified: z.boolean().nullable().optional(),
      }),
    )
    .nullable()
    .optional(),
});
type GoogleDomain = z.infer<typeof googleDomain>;

/**
 * Google Workspace directory facts through the Admin SDK (D1, D4): the customer
 * (`customers/my_customer`: id, primary domain, organization name) and its domains (`verified`,
 * primary or secondary; domain aliases are reported as `alias`). Google returns no MX target.
 */
export class GoogleDirectory implements ProviderDirectory {
  constructor(private readonly admin: GoogleAdminClient) {}

  async tenant(grant: GrantRef, signal: AbortSignal): Promise<TenantIdentity> {
    const parsed = customer.safeParse(await this.admin.get(grant, GOOGLE_CUSTOMER_PATH, signal));
    if (!parsed.success || !GOOGLE_CUSTOMER_ID.test(parsed.data.id)) {
      throw new ProviderRequestError('bad_response');
    }
    const domains = await this.domains(grant, signal);
    const primary = parsed.data.customerDomain?.toLowerCase() ?? '';
    return {
      tenantId: parsed.data.id,
      displayName: (parsed.data.postalAddress?.organizationName || primary).slice(0, 256),
      verifiedDomains: domains
        .filter((d) => d.verified === true)
        .map((d) => ({ name: d.domainName.toLowerCase(), isDefault: d.isPrimary === true }))
        .filter((d) => isDomainName(d.name)),
    };
  }

  async domain(grant: GrantRef, name: string, signal: AbortSignal): Promise<ProviderDomainStatus> {
    const wanted = name.trim().toLowerCase();
    if (!isDomainName(wanted)) throw new ProviderRequestError('bad_response');
    const domains = await this.domains(grant, signal);
    const own = domains.find((d) => d.domainName.toLowerCase() === wanted);
    if (own) return { status: own.verified === true ? 'verified' : 'unverified', mxHost: null };
    const alias = domains
      .flatMap((d) => d.domainAliases ?? [])
      .find((a) => a.domainAliasName.toLowerCase() === wanted);
    if (alias) return { status: 'alias', mxHost: null };
    return { status: 'absent', mxHost: null };
  }

  private async domains(grant: GrantRef, signal: AbortSignal): Promise<GoogleDomain[]> {
    const items =
      (await this.admin.list<unknown>(grant, GOOGLE_DOMAINS_PATH, signal, {
        itemsField: 'domains',
      })) ?? [];
    return items.map((item) => {
      const parsed = googleDomain.safeParse(item);
      if (!parsed.success) throw new ProviderRequestError('bad_response');
      return parsed.data;
    });
  }
}
