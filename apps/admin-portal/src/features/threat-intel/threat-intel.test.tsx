import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ListItem } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import {
  addHashBody,
  addHashSchema,
  addIndicatorBody,
  addIndicatorSchema,
  lookupSchema,
} from './schemas';
import { NOT_OFFERED, ThreatIntelligencePage } from './threat-intelligence-page';

const SHA = 'a'.repeat(64);
const hash = (i: number): ListItem<'ThreatHashesController_list_v1'> => ({
  sha256: i.toString(16).padStart(64, '0'),
  md5: null,
  severity: 'critical',
  family: `family-${i}`,
  source: 'analyst',
  reason: 'Seen in campaign <script>',
  expiresAt: null,
  addedByUserId: null,
  firstSeenAt: '2026-11-01T00:00:00.000Z',
  lastSeenAt: '2026-11-12T00:00:00.000Z',
  createdAt: '2026-11-01T00:00:00.000Z',
  updatedAt: '2026-11-01T00:00:00.000Z',
});
const indicator: ListItem<'ThreatIndicatorsController_list_v1'> = {
  id: '501',
  type: 'domain',
  value: 'login.evil-example.test',
  valueSha256: SHA,
  severity: 'high',
  category: 'phishing',
  source: 'analyst',
  reason: 'Credential phishing kit',
  expiresAt: '2026-12-31T23:59:59.000Z',
  addedByUserId: null,
  firstSeenAt: '2026-11-01T00:00:00.000Z',
  lastSeenAt: '2026-11-12T00:00:00.000Z',
  createdAt: '2026-11-01T00:00:00.000Z',
  updatedAt: '2026-11-01T00:00:00.000Z',
};

describe('Threat intelligence: lookup', () => {
  it('validates, looks up and shows matches; states what is not offered', async () => {
    let params: URLSearchParams | null = null;
    mockApi({
      ThreatIntelligenceController_lookup_v1: ({ url }) => (
        (params = url.searchParams),
        okJson({
          type: 'domain',
          valueSha256: SHA,
          known: true,
          matches: [
            {
              source: 'platform_indicator',
              severity: 'high',
              category: 'phishing',
              firstSeenAt: '2026-11-01T00:00:00.000Z',
              lastSeenAt: '2026-11-12T00:00:00.000Z',
              expiresAt: null,
            },
          ],
        })
      ),
    });
    const { container, user } = renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence',
    });
    expect(screen.getByText(NOT_OFFERED)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Look up' }));
    expect(await screen.findByText('Enter a value')).toBeInTheDocument();
    await user.type(screen.getByLabelText(/^Value/), 'not a domain!');
    await user.click(screen.getByRole('button', { name: 'Look up' }));
    expect(await screen.findByText(/Enter a domain name/)).toBeInTheDocument();
    await user.clear(screen.getByLabelText(/^Value/));
    await user.type(screen.getByLabelText(/^Value/), 'login.evil-example.test');
    await user.click(screen.getByRole('button', { name: 'Look up' }));
    expect(await screen.findByText('Known threat')).toBeInTheDocument();
    expect(params!.get('type')).toBe('domain');
    expect(params!.get('value')).toBe('login.evil-example.test');
    expect(screen.getByText('Platform indicator')).toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Hash catalogue' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows a rate limit error with its code', async () => {
    mockApi({
      ThreatIntelligenceController_lookup_v1: () =>
        apiErrorJson(429, 'rate_limited', 'Too many lookups', {
          requestId: 'req-ti-1',
          headers: { 'retry-after': '30' },
        }),
    });
    const { user } = renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence',
    });
    await user.type(screen.getByLabelText(/^Value/), 'example.com');
    await user.click(screen.getByRole('button', { name: 'Look up' }));
    expect(await screen.findByText('rate_limited')).toBeInTheDocument();
    expect(screen.getByText('req-ti-1')).toBeInTheDocument();
  });

  it('schemas match the request contracts', () => {
    expect(lookupSchema.parse({ type: 'sha256', value: 'A'.repeat(64) })).toEqual({
      type: 'sha256',
      value: 'a'.repeat(64),
    });
    expect(lookupSchema.safeParse({ type: 'url', value: 'ftp://x' }).success).toBe(false);
    expect(lookupSchema.safeParse({ type: 'ip', value: '2001:db8::1' }).success).toBe(true);
    expectRequestMatchesContract(
      'ThreatHashesController_add_v1',
      addHashBody(
        addHashSchema.parse({
          sha256: SHA,
          md5: '',
          severity: 'high',
          family: '',
          reason: 'r',
          expiresOn: '2099-01-01',
        }),
      ),
    );
    expectRequestMatchesContract(
      'ThreatIndicatorsController_add_v1',
      addIndicatorBody(
        addIndicatorSchema.parse({
          type: 'url',
          value: 'https://bad.example.test/x',
          severity: 'low',
          category: 'scam',
          reason: 'r',
          expiresOn: '',
        }),
      ),
    );
  });

  it('users without either permission get the 403 page', () => {
    renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence',
      role: 'read_only_user',
    });
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
  });
});

describe('Threat intelligence: platform catalogue', () => {
  it('lists hashes with cursors; attacker text is shown as text; adds a hash (legacy Idempotency-Key)', async () => {
    let addBody: unknown = null;
    let key: string | null = null;
    mockApi({
      ThreatHashesController_list_v1: ({ url }) =>
        url.searchParams.get('cursor') === 'p2'
          ? okJson({ data: [hash(99)], nextCursor: null })
          : okJson({ data: [hash(1), hash(2)], nextCursor: 'p2' }),
      ThreatHashesController_add_v1: ({ body, request }) => (
        (addBody = body),
        (key = request.headers.get('idempotency-key')),
        okJson(hash(3), 201)
      ),
    });
    const { container, user } = renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence?tab=hashes',
      role: 'platform_admin',
    });
    expect(await screen.findByText('family-1')).toBeInTheDocument();
    expect(screen.getAllByText('Seen in campaign <script>').length).toBe(2);
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('family-99')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add hash' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/^SHA-256/), SHA.toUpperCase());
    await user.type(within(dialog).getByLabelText(/^Reason/), 'Sandbox detonation 42');
    await user.click(within(dialog).getByRole('button', { name: 'Add hash' }));
    await waitFor(() =>
      expect(addBody).toEqual({ sha256: SHA, severity: 'high', reason: 'Sandbox detonation 42' }),
    );
    expect(key).toMatch(/^[0-9a-f-]{36}$/);
    expectRequestMatchesContract('ThreatHashesController_add_v1', addBody);
  });

  it('shows a duplicate hash (409) in the form', async () => {
    mockApi({
      ThreatHashesController_list_v1: () => okJson({ data: [], nextCursor: null }),
      ThreatHashesController_add_v1: () =>
        apiErrorJson(409, 'hash_exists', 'This hash is already catalogued'),
    });
    const { user } = renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence?tab=hashes',
      role: 'platform_admin',
    });
    expect(await screen.findByText('The catalogue is empty')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Add hash' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/^SHA-256/), SHA);
    await user.type(within(dialog).getByLabelText(/^Reason/), 'dup');
    await user.click(within(dialog).getByRole('button', { name: 'Add hash' }));
    expect(await within(dialog).findByText('This hash is already catalogued')).toBeInTheDocument();
  });

  it('removes an indicator with a reason after confirmation; filters write the URL', async () => {
    let removed: { id: string; reason: string | null } | null = null;
    const seen: URLSearchParams[] = [];
    mockApi({
      ThreatIndicatorsController_list_v1: ({ url }) => (
        seen.push(url.searchParams),
        okJson({ data: [indicator], nextCursor: null })
      ),
      ThreatIndicatorsController_remove_v1: ({ params, url }) => (
        (removed = { id: params.id!, reason: url.searchParams.get('reason') }),
        noContentResponse()
      ),
    });
    const { user } = renderWithProviders(<ThreatIntelligencePage />, {
      route: '/threat-intelligence?tab=indicators',
      role: 'platform_admin',
    });
    expect(await screen.findByText('login.evil-example.test')).toBeInTheDocument();
    await user.click(screen.getByRole('combobox', { name: 'Type' }));
    await user.click(await screen.findByRole('option', { name: 'Domain' }));
    await waitFor(() => expect(currentTestUrl()).toContain('type=domain'));
    await waitFor(() => expect(seen.at(-1)?.get('type')).toBe('domain'));
    await user.click(screen.getByRole('button', { name: /Actions for domain indicator/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Remove' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText(/^Reason/), 'False positive');
    await user.click(within(dialog).getByRole('button', { name: 'Remove indicator' }));
    await waitFor(() => expect(removed).toEqual({ id: '501', reason: 'False positive' }));
    expect(await screen.findByText('Indicator removed.')).toBeInTheDocument();
  });
});
