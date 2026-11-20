/**
 * Admin SDK Reports `activities.list` (design note §3.2, D7): applications `login` and `token`,
 * one page per call over a time window, impersonating the grant's delegated administrator. Plain
 * HTTPS through `ProviderSession` (budget, token, allow-listed origin); no vendor SDK. Path
 * templates are logged, never concrete queries.
 */
import type { ProviderSession } from '../core/session';
import { GOOGLE_PROFILES } from '../requirements';
import type { ReportsApplication } from './constants';
import { activitiesPageSchema, type ActivitiesPage } from './schemas';

export const REPORTS_PATH = '/admin/reports/v1/activity/users/all/applications';

export class ReportsClient {
  constructor(
    private readonly session: ProviderSession,
    /** Delegated administrator of the telemetry grant (`subjectEmail`). */
    private readonly subject: string | undefined,
  ) {}

  async page(input: {
    application: ReportsApplication;
    start: Date;
    end: Date;
    maxResults: number;
    pageToken?: string;
    eventName?: string;
  }): Promise<ActivitiesPage> {
    const params = new URLSearchParams({
      startTime: input.start.toISOString(),
      endTime: input.end.toISOString(),
      maxResults: String(Math.max(1, Math.min(1000, input.maxResults))),
    });
    if (input.eventName) params.set('eventName', input.eventName);
    if (input.pageToken) params.set('pageToken', input.pageToken);
    const response = await this.session.call({
      family: 'google_reports',
      method: 'GET',
      url: `${REPORTS_PATH}/${input.application}?${params.toString()}`,
      pathTemplate: `${REPORTS_PATH}/${input.application}`,
      schema: activitiesPageSchema,
      profile: GOOGLE_PROFILES.telemetry,
      resource: 'google',
      ...(this.subject ? { subject: this.subject } : {}),
    });
    return response.data;
  }
}
