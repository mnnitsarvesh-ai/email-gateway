import { fireEvent, screen, waitFor } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  TEST_ORG,
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { BillingPage, PRICING_UNAVAILABLE } from './billing-page';

const plan: SuccessBody<'BillingController_plan_v1'> = {
  organizationId: TEST_ORG.id,
  plan: { code: 'business', name: 'Business', description: 'Gateway protection for growing teams' },
  limits: [
    { key: 'max_users', value: 250, source: 'plan' },
    { key: 'max_domains', value: 20, source: 'override' },
  ],
  features: [
    { key: 'attachment_sandbox', enabled: true, source: 'override' },
    { key: 'sso', enabled: false, source: 'plan' },
  ],
  pricing: null,
  note: 'Prices, invoices and payments are not part of the platform.',
};

const monthly = (month: string): SuccessBody<'BillingController_usage_v1'> => ({
  organizationId: TEST_ORG.id,
  month,
  from: `${month}-01T00:00:00.000Z`,
  to: `${month}-13T10:00:00.000Z`,
  messages: { total: 5100, inbound: 4000, outbound: 1000, internal: 100 },
  users: 42,
  domains: 3,
  apiKeys: 2,
  limits: [{ key: 'max_users', value: 250, source: 'plan', used: 42 }],
  generatedAt: '2026-11-13T10:00:00.000Z',
});

const usage: SuccessBody<'UsageController_get_v1'> = {
  organizationId: TEST_ORG.id,
  period: { from: '2026-10-14T10:00:00.000Z', to: '2026-11-13T10:00:00.000Z' },
  users: { total: 42, active: 38, invited: 2, disabled: 1, locked: 1 },
  domains: { total: 3, verified: 3, pendingVerification: 0, active: 3, suspended: 0 },
  messages: { total: 9876, inbound: 8000, outbound: 1800, internal: 76, today: 120 },
  quarantine: { active: 17 },
  apiKeys: { active: 2 },
  sessions: { active: 11 },
  limits: [{ key: 'messages_per_day', value: 50000, source: 'plan', used: 120 }],
};

describe('Usage and billing', () => {
  it('shows the plan, entitlements with their source and the explicit pricing state', async () => {
    mockApi({ BillingController_plan_v1: () => okJson(plan) });
    const { container } = renderWithProviders(<BillingPage />, { route: '/billing' });
    expect(screen.getByText('Loading your plan …')).toBeInTheDocument();
    expect(await screen.findByText('Plan: Business')).toBeInTheDocument();
    expect(screen.getByText('Gateway protection for growing teams')).toBeInTheDocument();
    expect(screen.getByText(new RegExp(PRICING_UNAVAILABLE))).toBeInTheDocument();
    expect(screen.getByText('Not offered')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Limits of your plan' })).toHaveTextContent(
      /Max usersmax_users250Plan/,
    );
    expect(screen.getByRole('table', { name: 'Limits of your plan' })).toHaveTextContent(
      /Max domainsmax_domains20Override/,
    );
    expect(screen.getByRole('table', { name: 'Features of your plan' })).toHaveTextContent(
      /Attachment sandboxattachment_sandboxEnabledOverride/,
    );
    expect(screen.queryByText(/\$|€|price:/i)).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows the API error with code and request id', async () => {
    mockApi({
      BillingController_plan_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-bill-1' }),
    });
    renderWithProviders(<BillingPage />, { route: '/billing' });
    expect(await screen.findByText('internal_error')).toBeInTheDocument();
    expect(screen.getByText('req-bill-1')).toBeInTheDocument();
  });

  it('monthly usage: the month picker writes the URL and the request', async () => {
    const months: (string | null)[] = [];
    mockApi({
      BillingController_usage_v1: ({ url }) => {
        const month = url.searchParams.get('month');
        months.push(month);
        return okJson(monthly(month ?? '2026-11'));
      },
    });
    const { container } = renderWithProviders(<BillingPage />, { route: '/billing?tab=metered' });
    expect(await screen.findByText('Usage in 2026-11')).toBeInTheDocument();
    expect(months).toEqual([null]);
    expect(screen.getByRole('table', { name: 'Limits and their use' })).toHaveTextContent(
      /Max usersmax_users42250Plan/,
    );
    await expectNoAxeViolations(container);
    fireEvent.change(screen.getByLabelText('Month (UTC)'), { target: { value: '2026-09' } });
    await waitFor(() => expect(currentTestUrl()).toBe('/billing?tab=metered&month=2026-09'));
    expect(await screen.findByText('Usage in 2026-09')).toBeInTheDocument();
    expect(months.at(-1)).toBe('2026-09');
  });

  it('monthly usage: an old month shows the API message (usage_period_unavailable)', async () => {
    mockApi({
      BillingController_usage_v1: () =>
        apiErrorJson(400, 'usage_period_unavailable', 'month is older than the message retention'),
    });
    renderWithProviders(<BillingPage />, { route: '/billing?tab=metered&month=2025-01' });
    expect(
      await screen.findByText('month is older than the message retention'),
    ).toBeInTheDocument();
    expect(screen.getByText('usage_period_unavailable')).toBeInTheDocument();
  });

  it('current usage for users with organization:read only (no billing tabs)', async () => {
    mockApi({ UsageController_get_v1: () => okJson(usage) });
    const { container } = renderWithProviders(<BillingPage />, {
      route: '/billing',
      role: 'read_only_user',
    });
    expect(await screen.findByText('Active quarantine entries')).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Plan and entitlements' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Current usage' })).toBeInTheDocument();
    expect(screen.getByText('9,876')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Limits and their use' })).toHaveTextContent(
      /Messages per daymessages_per_day12050,000Plan/,
    );
    await expectNoAxeViolations(container);
  });

  it('switching tabs writes ?tab=', async () => {
    mockApi({
      BillingController_plan_v1: () => okJson(plan),
      UsageController_get_v1: () => okJson(usage),
    });
    const { user } = renderWithProviders(<BillingPage />, { route: '/billing' });
    await screen.findByText('Plan: Business');
    await user.click(screen.getByRole('tab', { name: 'Current usage' }));
    await waitFor(() => expect(currentTestUrl()).toBe('/billing?tab=current'));
    expect(await screen.findByText('Active sessions')).toBeInTheDocument();
  });

  it('mailbox users get the 403 page', () => {
    renderWithProviders(<BillingPage />, { route: '/billing', role: 'mailbox_user' });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});
