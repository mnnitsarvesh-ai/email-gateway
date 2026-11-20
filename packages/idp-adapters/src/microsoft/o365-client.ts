/**
 * Office 365 Management Activity API calls (design note D7.4): content listing with
 * `NextPageUri` paging (same origin only), blob fetch by `contentUri` (same origin only), and the
 * idempotent `Audit.Exchange` subscription start after `AF20022` — the only non-action write of
 * the adapter (invariant 7).
 */
import { ProviderCallError } from '../core/errors';
import type { ProviderSession } from '../core/session';
import type { TimeWindow } from '../core/windows';
import { MICROSOFT_PROFILES } from '../requirements';
import { O365_CONTENT_TYPE, O365_NO_SUBSCRIPTION } from './constants';
import {
  o365BlobSchema,
  o365ContentListSchema,
  o365SubscriptionSchema,
  type O365ContentList,
} from './schemas';

const TELEMETRY = { profile: MICROSOFT_PROFILES.telemetry, resource: 'o365_management' as const };

export interface ContentListing {
  items: O365ContentList;
  /** Path + query (relative to the o365 base) of the next listing page. */
  nextPath: string | null;
}

export class O365Client {
  private subscriptionStarted = false;

  constructor(
    private readonly session: ProviderSession,
    private readonly tenantId: string,
    private readonly relativize: (link: string) => string,
  ) {}

  /** Path of the first listing page of a window. */
  listPath(window: TimeWindow): string {
    const params = new URLSearchParams({
      contentType: O365_CONTENT_TYPE,
      startTime: window.start.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      endTime: window.end.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    });
    return `/api/v1.0/${encodeURIComponent(this.tenantId)}/activity/feed/subscriptions/content?${params.toString()}`;
  }

  /** Lists one content page; starts the subscription once on `AF20022`, then retries. */
  async list(path: string): Promise<ContentListing> {
    try {
      return await this.listOnce(path);
    } catch (error) {
      if (
        error instanceof ProviderCallError &&
        error.providerCode === O365_NO_SUBSCRIPTION &&
        !this.subscriptionStarted
      ) {
        await this.startSubscription();
        return this.listOnce(path);
      }
      throw error;
    }
  }

  /**
   * Read-only listing for probes: never starts the subscription (invariant 7). `AF20022` is
   * returned as `subscription_missing` (the first ingest starts it).
   */
  async probe(window: TimeWindow): Promise<'ok' | 'subscription_missing'> {
    try {
      await this.listOnce(this.listPath(window));
      return 'ok';
    } catch (error) {
      if (error instanceof ProviderCallError && error.providerCode === O365_NO_SUBSCRIPTION) {
        return 'subscription_missing';
      }
      throw error;
    }
  }

  private async listOnce(path: string): Promise<ContentListing> {
    const response = await this.session.call({
      family: 'o365',
      method: 'GET',
      url: path,
      pathTemplate: '/api/v1.0/{tenant}/activity/feed/subscriptions/content',
      schema: o365ContentListSchema,
      ...TELEMETRY,
    });
    const next = response.headers.nextPageUri;
    return { items: response.data, nextPath: next ? this.relativize(next) : null };
  }

  async startSubscription(): Promise<void> {
    this.subscriptionStarted = true;
    await this.session.call({
      family: 'o365',
      method: 'POST',
      url: `/api/v1.0/${encodeURIComponent(this.tenantId)}/activity/feed/subscriptions/start?contentType=${O365_CONTENT_TYPE}`,
      pathTemplate: '/api/v1.0/{tenant}/activity/feed/subscriptions/start',
      schema: o365SubscriptionSchema,
      ...TELEMETRY,
    });
  }

  /** Records of one blob (`contentUri` must be same-origin). */
  async blob(contentUri: string): Promise<unknown[]> {
    const response = await this.session.call({
      family: 'o365',
      method: 'GET',
      url: this.relativize(contentUri),
      pathTemplate: '/api/v1.0/{tenant}/activity/feed/audit/{contentId}',
      schema: o365BlobSchema,
      ...TELEMETRY,
    });
    return response.data;
  }
}
