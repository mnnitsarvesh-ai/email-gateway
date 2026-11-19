import { z } from 'zod';
import type { ProviderDirectory, ProviderDomainStatus, TenantIdentity } from '../directory';
import { ProviderRequestError } from '../errors';
import { isDomainName, MICROSOFT_TENANT_ID, type GrantRef } from '../types';
import type { MicrosoftGraphClient } from './graph-client';

const organization = z.object({
  id: z.string(),
  displayName: z.string().max(256).nullable().optional(),
  verifiedDomains: z
    .array(z.object({ name: z.string().max(253), isDefault: z.boolean().nullable().optional() }))
    .max(5000)
    .nullable()
    .optional(),
});

const domainSchema = z.object({
  id: z.string().max(253),
  isVerified: z.boolean().nullable().optional(),
  supportedServices: z.array(z.string()).nullable().optional(),
});

const serviceRecord = z.object({
  recordType: z.string().nullable().optional(),
  supportedService: z.string().nullable().optional(),
  mailExchange: z.string().max(253).nullable().optional(),
  preference: z.number().nullable().optional(),
});

const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

/**
 * Microsoft 365 directory facts through Graph (D1, D4): `GET /organization` (tenant id, name,
 * verified domains), `GET /domains/{name}` (`isVerified`, `supportedServices` contains `Email`)
 * and its `serviceConfigurationRecords` (the `Mx` record's `mailExchange` = `provider_mx_host`).
 * Microsoft has no domain aliases: `alias` never occurs.
 */
export class MicrosoftDirectory implements ProviderDirectory {
  constructor(private readonly graph: MicrosoftGraphClient) {}

  async tenant(grant: GrantRef, signal: AbortSignal): Promise<TenantIdentity> {
    const items = await this.graph.list<unknown>(grant, '/organization', signal, {
      select: ['id', 'displayName', 'verifiedDomains'],
      maxPages: 1,
    });
    const parsed = organization.safeParse(items?.[0]);
    if (!parsed.success || !MICROSOFT_TENANT_ID.test(parsed.data.id.toLowerCase())) {
      throw new ProviderRequestError('bad_response');
    }
    return {
      tenantId: parsed.data.id.toLowerCase(),
      displayName: (parsed.data.displayName ?? '').slice(0, 256),
      verifiedDomains: (parsed.data.verifiedDomains ?? [])
        .map((d) => ({ name: d.name.toLowerCase(), isDefault: d.isDefault === true }))
        .filter((d) => isDomainName(d.name)),
    };
  }

  async domain(grant: GrantRef, name: string, signal: AbortSignal): Promise<ProviderDomainStatus> {
    const domain = name.trim().toLowerCase();
    if (!isDomainName(domain)) throw new ProviderRequestError('bad_response');
    const body = await this.graph.get<unknown>(grant, `/domains/${domain}`, signal, {
      select: ['id', 'isVerified', 'supportedServices'],
      nullOn: [404],
    });
    if (body === null) return { status: 'absent', mxHost: null };
    const parsed = domainSchema.safeParse(body);
    if (!parsed.success) throw new ProviderRequestError('bad_response');
    const verified =
      parsed.data.isVerified === true && (parsed.data.supportedServices ?? []).includes('Email');
    const records =
      (await this.graph.list<unknown>(
        grant,
        `/domains/${domain}/serviceConfigurationRecords`,
        signal,
        {
          nullOn: [404],
        },
      )) ?? [];
    return { status: verified ? 'verified' : 'unverified', mxHost: mxHostOf(records) };
  }
}

/** The Exchange MX target of a domain's service configuration records (lowest preference). */
export function mxHostOf(records: readonly unknown[]): string | null {
  const mx = records
    .map((r) => serviceRecord.safeParse(r))
    .filter((r) => r.success)
    .map((r) => r.data)
    .filter(
      (r) =>
        r.recordType?.toLowerCase() === 'mx' &&
        (!r.supportedService || r.supportedService.toLowerCase() === 'email') &&
        typeof r.mailExchange === 'string',
    )
    .map((r) => ({
      host: r.mailExchange!.trim().toLowerCase().replace(/\.$/, ''),
      preference: r.preference ?? 0,
    }))
    .filter((r) => HOST.test(r.host))
    .sort((a, b) => a.preference - b.preference);
  return mx[0]?.host ?? null;
}
