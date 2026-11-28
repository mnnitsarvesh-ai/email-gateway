import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import { visibleNavigation } from '@/lib/navigation';
import {
  ROLE_PERMISSIONS,
  expectNoAxeViolations,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { gapInfo } from '@/features/api-mode/parity-model';
import { ProtectionByModePage } from './protection-by-mode-page';

/**
 * Step API-4 WP6 (design A10, API4-15): the Protection by mode page — the capability matrix
 * (yes/partial/no with notes), totals per mode, the per-domain table (mode, inherited, inline and
 * API facts, gaps with fix links), cursor paging and the mode filter — and its navigation item in
 * Security (gated on the protection-coverage operation, `domain:read`).
 */

type Coverage = SuccessBody<'ApiModeOnboardingController_protectionCoverage_v1'>;
const A = '0193a000-0000-7000-8000-000000000001';
const B = '0193a000-0000-7000-8000-000000000002';
const CONN = '0193f400-0000-7000-8000-000000000001';

const coverage = (over: Partial<Coverage> = {}): Coverage => ({
  entitled: true,
  organizationMode: 'inline',
  totals: { inline: 3, api: 1, hybrid: 1 },
  capabilities: [
    {
      code: 'pre_delivery_blocking',
      inline: 'yes',
      api: 'no',
      hybrid: 'yes',
      noteCode: 'api_acts_after_delivery',
    },
    { code: 'outbound_dlp_detect', inline: 'yes', api: 'yes', hybrid: 'yes', noteCode: null },
    {
      code: 'tenant_policies',
      inline: 'yes',
      api: 'partial',
      hybrid: 'yes',
      noteCode: 'api_post_delivery_actions_only',
    },
  ],
  items: [
    {
      domainId: A,
      name: 'api.example.test',
      status: 'active',
      effectiveMode: 'api',
      inherited: false,
      inline: {
        applies: false,
        inboundEnabled: false,
        outboundEnabled: true,
        mxPointsToGateway: null,
      },
      api: {
        applies: true,
        connection: {
          id: CONN,
          provider: 'microsoft_365',
          health: 'degraded',
          mailboxAccess: 'missing',
        },
        intake: { journal: 'verified', feeds: 'off' },
        scope: 'mailboxes',
        mailboxes: { inScope: 4, covered: 3, gap: 1, total: 9 },
        remediation: {
          source: 'domain',
          mode: 'detect_only',
          detectOnlyUntil: '2026-12-04T09:00:00.000Z',
        },
        policyEvaluation: true,
        lastCopyAt: '2026-11-27T08:00:00.000Z',
      },
      gaps: ['api_no_mailbox_access', 'api_coverage_gaps', 'api_detect_only'],
    },
    {
      domainId: B,
      name: 'inline.example.test',
      status: 'active',
      effectiveMode: 'inline',
      inherited: true,
      inline: {
        applies: true,
        inboundEnabled: true,
        outboundEnabled: true,
        mxPointsToGateway: true,
      },
      api: null,
      gaps: [],
    },
  ],
  nextCursor: 'cursor-2',
  ...over,
});

describe('/protection-by-mode (A10)', () => {
  it('shows the matrix, totals, per-domain facts and gaps with fix links; pages and filters', async () => {
    const queries: URLSearchParams[] = [];
    mockApi({
      ApiModeOnboardingController_protectionCoverage_v1: ({ url }) => {
        queries.push(url.searchParams);
        return okJson(
          url.searchParams.get('cursor') ? coverage({ items: [], nextCursor: null }) : coverage(),
        );
      },
    });
    const { user, container } = renderWithProviders(<ProtectionByModePage />, {
      route: '/protection-by-mode',
    });
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Protection by mode' }),
    ).toBeVisible();
    const totals = await screen.findByRole('list', { name: 'Domains by protection mode' });
    expect(within(totals).getByText('3 domains')).toBeInTheDocument();
    const matrix = screen.getByRole('table', { name: 'What each protection mode covers' });
    const row = within(matrix).getByRole('row', { name: /Block threats before delivery/ });
    expect(within(row).getAllByText('Yes')).toHaveLength(2);
    expect(within(row).getByText('No')).toBeInTheDocument();
    expect(within(row).getByText(/API mode acts after delivery/)).toBeInTheDocument();
    expect(within(matrix).getByText('Partial')).toBeInTheDocument();

    const table = screen.getByRole('table', { name: 'Coverage of each domain' });
    expect(within(table).getByRole('link', { name: 'api.example.test' })).toHaveAttribute(
      'href',
      `/domains/${A}`,
    );
    expect(
      within(table).getByText(/Microsoft 365 · Degraded · mailbox access missing/),
    ).toBeInTheDocument();
    expect(
      within(table).getByText(/Selected mailboxes: 4 in scope, 3 covered, 1 with a gap/),
    ).toBeInTheDocument();
    const gaps = within(table).getByRole('list', { name: 'Gaps of api.example.test' });
    expect(within(gaps).getByRole('link', { name: /Grant mailbox access/ })).toHaveAttribute(
      'href',
      `/integrations/providers/${CONN}?tab=settings#mailbox-access`,
    );
    expect(within(table).getByText('No gaps')).toBeInTheDocument();
    await expectNoAxeViolations(container);

    await user.click(screen.getByRole('button', { name: /next page/i }));
    await waitFor(() => expect(queries.at(-1)?.get('cursor')).toBe('cursor-2'));
    await user.click(screen.getByRole('combobox', { name: 'Mode' }));
    await user.click(await screen.findByRole('option', { name: 'API (no MX change)' }));
    await waitFor(() => expect(queries.at(-1)?.get('effectiveMode')).toBe('api'));
  });

  it('gap codes map to the page that fixes them', () => {
    const item = { domainId: A, api: null };
    expect(gapInfo('inline_mx_not_at_gateway', item).href).toBe(`/domains/${A}?tab=dns`);
    expect(gapInfo('api_no_connection', item).href).toBe(
      `/domains/onboarding?domainId=${A}&step=connect`,
    );
    expect(gapInfo('api_detect_only', item).href).toBe('/api-mode?tab=remediation');
    expect(gapInfo('api_policy_evaluation_off', item).href).toBe('/api-mode?tab=settings');
  });

  it('navigation: in Security, gated on domain:read and the gateway profile', () => {
    const visible = (permissions: readonly string[], profile?: 'gateway' | 'archive_only') =>
      visibleNavigation(permissions, profile)
        .flatMap((section) => section.items)
        .some((item) => item.id === 'protection-by-mode');
    expect(visible(ROLE_PERMISSIONS.organization_admin)).toBe(true);
    expect(visible(ROLE_PERMISSIONS.read_only_user)).toBe(true);
    expect(visible(ROLE_PERMISSIONS.mailbox_user)).toBe(false);
    expect(visible(ROLE_PERMISSIONS.organization_admin, 'archive_only')).toBe(false);
    const security = visibleNavigation(ROLE_PERMISSIONS.organization_admin).find(
      (s) => s.id === 'security',
    );
    expect(security?.items.at(-1)?.href).toBe('/protection-by-mode');
  });

  it('refuses the page without domain:read', () => {
    renderWithProviders(<ProtectionByModePage />, {
      role: 'mailbox_user',
      route: '/protection-by-mode',
    });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});
