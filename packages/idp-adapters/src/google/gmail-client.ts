/**
 * Gmail settings calls of the Google adapter (design note D8.3, D9.7): auto-forwarding, filters
 * and delegates of one mailbox. Every call impersonates the **mailbox owner** (domain-wide
 * delegation `sub` = the user, R1) through `ProviderConnectionAccess.acquireToken`; the user is
 * addressed by its primary address (deviation WP2-4). Plain HTTPS through `ProviderSession`; path
 * templates are logged, never addresses.
 *
 * The telemetry profile (`gmail.settings.basic`) issues reads only (PQ14); writes are made only by
 * response actions with the response profile.
 */
import { ProviderCallError } from '../core/errors';
import type { ProviderSession } from '../core/session';
import {
  autoForwardingSchema,
  delegatesSchema,
  filterSchema,
  filtersSchema,
  type AutoForwarding,
  type GmailFilter,
} from './schemas';

const BASE = '/gmail/v1/users';
const enc = encodeURIComponent;

export class GmailClient {
  constructor(
    private readonly session: ProviderSession,
    readonly profile: string,
  ) {}

  private base(mailbox: string) {
    return {
      family: 'gmail' as const,
      profile: this.profile,
      resource: 'google' as const,
      subject: mailbox,
    };
  }

  async getAutoForwarding(mailbox: string): Promise<AutoForwarding> {
    const response = await this.session.call({
      ...this.base(mailbox),
      method: 'GET',
      url: `${BASE}/${enc(mailbox)}/settings/autoForwarding`,
      pathTemplate: `${BASE}/{userId}/settings/autoForwarding`,
      schema: autoForwardingSchema,
    });
    return response.data;
  }

  /** Disables auto-forwarding (response action only). */
  async disableAutoForwarding(mailbox: string): Promise<void> {
    await this.session.call({
      ...this.base(mailbox),
      method: 'PUT',
      url: `${BASE}/${enc(mailbox)}/settings/autoForwarding`,
      pathTemplate: `${BASE}/{userId}/settings/autoForwarding`,
      body: { enabled: false },
    });
  }

  /** Raw filters (each validated by the settings mapper). */
  async listFilters(mailbox: string): Promise<unknown[]> {
    const response = await this.session.call({
      ...this.base(mailbox),
      method: 'GET',
      url: `${BASE}/${enc(mailbox)}/settings/filters`,
      pathTemplate: `${BASE}/{userId}/settings/filters`,
      schema: filtersSchema,
    });
    return response.data.filter ?? [];
  }

  /** A filter, or `null` when it no longer exists. */
  async getFilter(mailbox: string, filterId: string): Promise<GmailFilter | null> {
    try {
      const response = await this.session.call({
        ...this.base(mailbox),
        method: 'GET',
        url: `${BASE}/${enc(mailbox)}/settings/filters/${enc(filterId)}`,
        pathTemplate: `${BASE}/{userId}/settings/filters/{filterId}`,
        schema: filterSchema,
      });
      return response.data;
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return null;
      throw error;
    }
  }

  /** Deletes a filter (response action only). */
  async deleteFilter(mailbox: string, filterId: string): Promise<void> {
    await this.session.call({
      ...this.base(mailbox),
      method: 'DELETE',
      url: `${BASE}/${enc(mailbox)}/settings/filters/${enc(filterId)}`,
      pathTemplate: `${BASE}/{userId}/settings/filters/{filterId}`,
    });
  }

  async listDelegates(
    mailbox: string,
  ): Promise<{ delegateEmail: string; verificationStatus?: string | null }[]> {
    const response = await this.session.call({
      ...this.base(mailbox),
      method: 'GET',
      url: `${BASE}/${enc(mailbox)}/settings/delegates`,
      pathTemplate: `${BASE}/{userId}/settings/delegates`,
      schema: delegatesSchema,
    });
    return response.data.delegates ?? [];
  }
}
