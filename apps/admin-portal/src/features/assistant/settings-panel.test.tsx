import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SETTINGS_TABS, SettingsPage } from '@/features/settings/settings-page';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { AssistantSettingsPanel, settingsBody, usageRange } from './settings-panel';
import { SETTINGS } from './test-data';
import type { AssistantUsage } from './types';

const USAGE: AssistantUsage = {
  from: '2026-10-22',
  to: '2026-11-20',
  rows: [
    {
      day: '2026-11-19',
      provider: 'fake',
      model: 'fake-model',
      turns: 4,
      inputTokens: 1200,
      outputTokens: 300,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costMicros: null,
    },
    {
      day: '2026-11-20',
      provider: 'anthropic',
      model: 'claude-opus-5-5',
      turns: 2,
      inputTokens: 900,
      outputTokens: 150,
      cacheReadTokens: 100,
      cacheWriteTokens: 50,
      costMicros: 12_500,
    },
  ],
  totals: {
    turns: 6,
    inputTokens: 2100,
    outputTokens: 450,
    cacheReadTokens: 100,
    cacheWriteTokens: 50,
    costMicros: 12_500,
  },
};

const ACK = /processed by the configured external AI provider/;

function mockSettings(settings = SETTINGS) {
  const usageQueries: Record<string, string | null>[] = [];
  mockApi({
    AssistantSettingsController_get_v1: () => okJson(settings),
    AssistantUsageController_get_v1: ({ url }) => {
      usageQueries.push({ from: url.searchParams.get('from'), to: url.searchParams.get('to') });
      return okJson(USAGE);
    },
  });
  return usageQueries;
}

describe('Settings → AI assistant (D13)', () => {
  it('is a settings tab only for assistant:configure', async () => {
    expect(SETTINGS_TABS.find((tab) => tab.id === 'assistant')).toMatchObject({
      label: 'AI assistant',
      ops: ['AssistantSettingsController_get_v1'],
    });
    mockSettings();
    const admin = renderWithProviders(<SettingsPage />, {
      role: 'organization_admin',
      route: '/settings?tab=assistant',
    });
    expect(screen.getByRole('tab', { name: 'AI assistant' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    admin.unmount();
    // The analyst falls back to the first tab it may open (Organization).
    mockApi({
      OrganizationsController_get_v1: () => apiErrorJson(403, 'forbidden'),
      OrganizationConfigurationController_getSettings_v1: () => apiErrorJson(403, 'forbidden'),
    });
    renderWithProviders(<SettingsPage />, {
      role: 'security_analyst',
      route: '/settings?tab=assistant',
    });
    expect(screen.queryByRole('tab', { name: 'AI assistant' })).not.toBeInTheDocument();
    await screen.findAllByRole('alert');
  });

  it('requires the acknowledgement to turn the assistant on, then saves with the row version', async () => {
    mockSettings();
    const bodies: unknown[] = [];
    mockApi({
      AssistantSettingsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson({
          ...SETTINGS,
          enabled: true,
          externalProcessingAcknowledged: true,
          externalProcessingAcknowledgedAt: '2026-11-20T10:00:00.000Z',
          dailyTokenBudget: 250000,
          rowVersion: 4,
        });
      },
    });
    const { user, container } = renderWithProviders(<AssistantSettingsPanel />);
    const form = await screen.findByRole('form', { name: 'AI assistant settings' });
    expect(within(form).getByText('Metadata only')).toBeInTheDocument();
    await user.click(within(form).getByRole('switch', { name: /Turn on the AI assistant/ }));
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    expect(
      await within(form).findByText(
        'Confirm the external processing before you turn the assistant on.',
      ),
    ).toBeInTheDocument();
    expect(bodies).toHaveLength(0);

    await user.click(within(form).getByRole('checkbox', { name: ACK }));
    await user.type(within(form).getByRole('spinbutton', { name: 'Daily token budget' }), '250000');
    const retention = within(form).getByRole('spinbutton', { name: /Conversation retention/ });
    await user.clear(retention);
    await user.type(retention, '90');
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      expectedRowVersion: 3,
      enabled: true,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: 250000,
      retentionDays: 90,
    });
    expectRequestMatchesContract('AssistantSettingsController_update_v1', bodies[0]);
    await expectNoAxeViolations(container);
  });

  it('validates the retention range (1-365 days)', async () => {
    mockSettings();
    const { user } = renderWithProviders(<AssistantSettingsPanel />);
    const form = await screen.findByRole('form', { name: 'AI assistant settings' });
    const retention = within(form).getByRole('spinbutton', { name: /Conversation retention/ });
    await user.clear(retention);
    await user.type(retention, '400');
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    expect(await within(form).findByText('At most 365 days')).toBeInTheDocument();
  });

  it('reports a concurrent change (409) and reloads the current settings', async () => {
    let version = 3;
    mockApi({
      AssistantSettingsController_get_v1: () => okJson({ ...SETTINGS, rowVersion: version }),
      AssistantUsageController_get_v1: () => okJson(USAGE),
      AssistantSettingsController_update_v1: () => {
        version = 5;
        return apiErrorJson(409, 'assistant_settings_conflict', 'Settings changed', {
          extra: { currentRowVersion: 5 },
        });
      },
    });
    const { user } = renderWithProviders(<AssistantSettingsPanel />);
    const form = await screen.findByRole('form', { name: 'AI assistant settings' });
    const retention = within(form).getByRole('spinbutton', { name: /Conversation retention/ });
    await user.clear(retention);
    await user.type(retention, '60');
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    expect(await within(form).findByRole('alert')).toHaveTextContent(
      'Someone else changed these settings',
    );
    await user.click(within(form).getByRole('button', { name: 'Reload the current settings' }));
    await waitFor(() =>
      expect(
        within(form).queryByRole('button', { name: 'Reload the current settings' }),
      ).not.toBeInTheDocument(),
    );
    expect(within(form).getByRole('spinbutton', { name: /Conversation retention/ })).toHaveValue(
      30,
    );
  });

  it('explains that the platform operator must enable the feature first', async () => {
    mockSettings({ ...SETTINGS, featureEnabled: false });
    renderWithProviders(<AssistantSettingsPanel />);
    const form = await screen.findByRole('form', { name: 'AI assistant settings' });
    expect(
      within(form).getByText(/feature is not enabled for this organization/),
    ).toBeInTheDocument();
    expect(within(form).getByRole('switch', { name: /Turn on the AI assistant/ })).toBeDisabled();
  });

  it('shows the usage of the last 30 days, newest first, with totals', async () => {
    const queries = mockSettings();
    renderWithProviders(<AssistantSettingsPanel />);
    const table = await screen.findByRole('table', { name: /AI assistant usage/ });
    const rows = within(table).getAllByRole('row');
    expect(rows).toHaveLength(3);
    expect(rows[1]).toHaveTextContent('2026-11-20');
    expect(rows[1]).toHaveTextContent('anthropic / claude-opus-5-5');
    expect(rows[2]).toHaveTextContent('—');
    expect(screen.getByText(/6 questions/)).toBeInTheDocument();
    const range = usageRange();
    expect(queries[0]).toEqual(range);
    expect(usageRange(new Date('2026-11-20T23:00:00Z'))).toEqual({
      from: '2026-10-22',
      to: '2026-11-20',
    });
  });

  it('builds the PUT body from the form values', () => {
    expect(
      settingsBody(
        {
          enabled: false,
          externalProcessingAcknowledged: false,
          dailyTokenBudget: null,
          retentionDays: 30,
        },
        0,
      ),
    ).toEqual({
      expectedRowVersion: 0,
      enabled: false,
      externalProcessingAcknowledged: false,
      dailyTokenBudget: null,
      retentionDays: 30,
    });
    // Step AI-6: the AI-6 fields are absent = unchanged (the administration page edits them).
    expect(
      Object.keys(
        settingsBody(
          {
            enabled: true,
            externalProcessingAcknowledged: true,
            dailyTokenBudget: 5,
            retentionDays: 7,
          },
          2,
        ),
      ),
    ).not.toContain('dataSharing');
  });

  it('shows the current data-sharing level and links to the AI administration page', async () => {
    mockSettings({ ...SETTINGS, dataSharing: 'pseudonymized' });
    renderWithProviders(<AssistantSettingsPanel />);
    const form = await screen.findByRole('form', { name: 'AI assistant settings' });
    expect(within(form).getByText('Pseudonymized')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open AI administration' })).toHaveAttribute(
      'href',
      '/assistant/admin',
    );
  });
});
