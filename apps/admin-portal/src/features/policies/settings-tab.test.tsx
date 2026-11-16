import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { PoliciesPage } from './policies-page';
import { settingsBody, settingsValuesOf } from './settings-tab';
import { POLICY_SETTINGS, REAL_CATALOG } from './test-data';

function mockReads() {
  mockApi({
    PolicySettingsController_get_v1: () => okJson(POLICY_SETTINGS),
    PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG),
  });
}

describe('Policy settings form (/policies?tab=settings, design B13)', () => {
  it('writes only changed values and keeps the presence of the stored keys', () => {
    const base = settingsValuesOf(POLICY_SETTINGS);
    expect(settingsBody(POLICY_SETTINGS, base)).toEqual(POLICY_SETTINGS.settings);
    expect(settingsBody(POLICY_SETTINGS, { ...base, alertsEnabled: true })).toEqual({
      ...POLICY_SETTINGS.settings,
      alerts: { enabled: true },
    });
    expect(settingsBody(POLICY_SETTINGS, { ...base, recipientSplit: 'off' })).toEqual({
      ...POLICY_SETTINGS.settings,
      recipientSplit: false,
    });
    const split = {
      ...POLICY_SETTINGS,
      settings: { ...POLICY_SETTINGS.settings, recipientSplit: true },
    };
    expect(settingsBody(split, { ...settingsValuesOf(split), recipientSplit: 'default' })).toEqual(
      POLICY_SETTINGS.settings,
    );
  });

  it('turning recommendation overrides on needs a confirmation; saves with expectedRowVersion and shows the generation', async () => {
    mockReads();
    const puts: unknown[] = [];
    mockApi({
      PolicySettingsController_put_v1: ({ body }) => {
        puts.push(body);
        return okJson({ ...POLICY_SETTINGS, generation: '43', rowVersion: 4 });
      },
    });
    const { user, container } = renderWithProviders(<PoliciesPage />, {
      role: 'organization_admin',
      route: '/policies?tab=settings',
    });
    const form = await screen.findByRole('form', { name: 'Policy settings' });
    expect(within(form).getByRole('button', { name: 'Save settings' })).toBeDisabled();
    await expectNoAxeViolations(container);
    await user.click(within(form).getByRole('switch', { name: 'Recommendation overrides' }));
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    const confirm = await screen.findByRole('alertdialog', {
      name: 'Allow recommendation overrides?',
    });
    expect(puts).toHaveLength(0);
    await user.click(within(confirm).getByRole('button', { name: 'Allow overrides and save' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expectRequestMatchesContract('PolicySettingsController_put_v1', puts[0]);
    expect(puts[0]).toEqual({
      settings: { allowRecommendationOverrides: true, tagging: { platformTagOutbound: false } },
      expectedRowVersion: 3,
    });
    await waitFor(() =>
      expect(
        screen
          .getAllByRole('status')
          .some((el) => /generation is now 43\..*next evaluation only/.test(el.textContent ?? '')),
      ).toBe(true),
    );
  });

  it('a 409 policy_conflict explains the change and offers a reload', async () => {
    mockReads();
    mockApi({
      PolicySettingsController_put_v1: () =>
        apiErrorJson(409, 'policy_conflict', 'Changed', { extra: { currentRowVersion: 4 } }),
    });
    const { user } = renderWithProviders(<PoliciesPage />, {
      role: 'organization_admin',
      route: '/policies?tab=settings',
    });
    const form = await screen.findByRole('form', { name: 'Policy settings' });
    await user.click(within(form).getByRole('switch', { name: 'Policy alerts' }));
    await user.click(within(form).getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText(/row version 4/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload the settings' })).toBeInTheDocument();
  });
});
