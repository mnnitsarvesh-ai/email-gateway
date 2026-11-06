import { registrableDomainOf } from '../normalize/url';
import { mapLimit } from '../net/limiter';
import { type GuardedFetcher } from '../net/fetcher';
import {
  clearAnswer,
  errorAnswer,
  type ProviderAnswer,
  type ReputationItem,
  type ReputationProvider,
} from './types';

/**
 * `rdap` (U6, domain age): `GET <base>/domain/<registrable domain>` through the guarded fetcher
 * (redirects validated), `events[eventAction=registration].eventDate`; younger than
 * `newDomainDays` → listed (category `other`, detail `new_domain`); 404 → clear (`not_found`);
 * everything else → error.
 */

export const RDAP_VERSION = 'rdap/1';
const MAX_RDAP_BYTES = 262_144;

export interface RdapOptions {
  /** URL_RDAP_BASE_URL (e.g. https://rdap.org or the local http://rdap.test). */
  baseUrl: string;
  /** URL_NEW_DOMAIN_DAYS. */
  newDomainDays: number;
  concurrency?: number;
  now?: () => number;
}

/** The registration date of an RDAP domain object, or null. */
export function rdapRegistrationDate(body: unknown): Date | null {
  if (!body || typeof body !== 'object') return null;
  const events = (body as { events?: unknown }).events;
  if (!Array.isArray(events)) return null;
  for (const event of events) {
    if (!event || typeof event !== 'object') continue;
    const { eventAction, eventDate } = event as { eventAction?: unknown; eventDate?: unknown };
    if (eventAction === 'registration' && typeof eventDate === 'string') {
      const date = new Date(eventDate);
      if (!Number.isNaN(date.getTime())) return date;
    }
  }
  return null;
}

export class RdapProvider implements ReputationProvider {
  readonly id = 'rdap';
  readonly version = RDAP_VERSION;
  readonly kinds = ['domain'] as const;
  readonly cacheable = true;
  private readonly base: string;

  constructor(
    private readonly fetcher: GuardedFetcher,
    private readonly options: RdapOptions,
  ) {
    const url = new URL(options.baseUrl);
    if (url.protocol !== 'http:' && url.protocol !== 'https:')
      throw new Error('URL_RDAP_BASE_URL must be http(s)');
    this.base = url.href.replace(/\/+$/, '');
  }

  async lookup(items: readonly ReputationItem[], signal: AbortSignal): Promise<ProviderAnswer[]> {
    return mapLimit(items, this.options.concurrency ?? 4, (item) => this.one(item, signal));
  }

  private async one(item: ReputationItem, signal: AbortSignal): Promise<ProviderAnswer> {
    if (item.kind !== 'domain') return clearAnswer(item, 'not_applicable');
    const domain = registrableDomainOf(item.value.toLowerCase());
    if (domain === null) return clearAnswer(item, 'not_applicable');
    const result = await this.fetcher.fetchResource(
      `${this.base}/domain/${encodeURIComponent(domain)}`,
      {
        accept: 'application/rdap+json, application/json;q=0.9',
        maxBytes: MAX_RDAP_BYTES,
        signal,
      },
    );
    if (result.status !== 'completed')
      return errorAnswer(item, result.status === 'blocked' ? 'blocked' : (result.error ?? 'error'));
    if (result.httpStatus === 404) return clearAnswer(item, 'not_found');
    if (result.httpStatus !== 200 || result.body === null) return errorAnswer(item, 'http_error');
    let body: unknown;
    try {
      body = JSON.parse(result.body.toString('utf8'));
    } catch {
      return errorAnswer(item, 'parse_error');
    }
    const registered = rdapRegistrationDate(body);
    if (registered === null) return errorAnswer(item, 'no_registration');
    const ageDays = ((this.options.now ?? Date.now)() - registered.getTime()) / 86_400_000;
    if (ageDays < this.options.newDomainDays) {
      return {
        kind: item.kind,
        value: item.value,
        status: 'listed',
        category: 'other',
        severity: 'medium',
        detail: 'new_domain',
      };
    }
    return clearAnswer(item);
  }
}
