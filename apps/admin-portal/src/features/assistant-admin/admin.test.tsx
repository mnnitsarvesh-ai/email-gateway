import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
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
import { safePortalHref } from '@/features/assistant/portal-routes';
import { SETTINGS } from '@/features/assistant/test-data';
import { AssistantAdminPage } from './admin-page';
import { AuditConversationView } from './audit-detail';
import { limitsBody } from './limits-tab';
import {
  ADMIN_MAX_DAYS,
  customRange,
  formatCostMicros,
  presetRange,
  tenantKeyErrorText,
} from './model';
import { TenantKeySection } from './tenant-key';
import {
  AUDIT_CONVERSATION_ID,
  AUDIT_DETAIL,
  AUDIT_DETAIL_WITH_CONTENT,
  AUDIT_LIST,
  CONTENT_SENTINELS,
  EXECUTIONS_LIST,
  FEEDBACK_LIST,
  ORG_USAGE,
  SETTINGS_KEYS_OFFERED,
  SYNTHETIC_KEY,
  TENANT_KEY,
  USAGE_USERS,
} from './test-data';
import { dailyTokens } from './usage-tab';

const NOW = Date.parse('2026-11-26T12:00:00.000Z');

describe('AI administration helpers (step AI-6)', () => {
  it('formats the estimated cost from micro-USD, — without a price', () => {
    expect(formatCostMicros(12_500)).toBe('$0.0125');
    expect(formatCostMicros(2_000_000)).toBe('$2.00');
    expect(formatCostMicros(0)).toBe('$0.00');
    expect(formatCostMicros(null)).toBe('—');
  });

  it('resolves presets and validates custom windows (≤ 92 UTC days)', () => {
    expect(presetRange('30', NOW)).toMatchObject({
      fromDay: '2026-10-28',
      toDay: '2026-11-26',
      from: '2026-10-28T00:00:00.000Z',
      to: '2026-11-27T00:00:00.000Z',
      days: 30,
    });
    expect(customRange('2026-08-27', '2026-11-26', NOW)).toMatchObject({
      ok: true,
      range: { days: ADMIN_MAX_DAYS },
    });
    expect(customRange('2026-08-26', '2026-11-26', NOW)).toEqual({
      ok: false,
      message: 'Choose at most 92 days.',
    });
    expect(customRange('2026-11-20', '2026-11-19', NOW).ok).toBe(false);
    expect(customRange('2026-11-27', '2026-11-28', NOW).ok).toBe(false);
    expect(customRange('', '2026-11-28', NOW).ok).toBe(false);
  });

  it('sums the organization usage per day for the chart', () => {
    expect(dailyTokens(ORG_USAGE)).toEqual([
      { day: '2026-11-25', tokens: 750 },
      { day: '2026-11-26', tokens: 2000 },
    ]);
    expect(dailyTokens(undefined)).toEqual([]);
  });

  it('builds the settings body: enable and acknowledgement unchanged, the tab fields explicit', () => {
    const body = limitsBody(
      {
        dailyTokenBudget: 500_000,
        userDailyTokenBudget: 20_000,
        retentionDays: 60,
        dataSharing: 'pseudonymized',
        useTenantKey: false,
        tenantKeyFallbackToPlatform: false,
      },
      { ...SETTINGS, enabled: true, externalProcessingAcknowledged: true, rowVersion: 7 },
    );
    expect(body).toEqual({
      expectedRowVersion: 7,
      enabled: true,
      externalProcessingAcknowledged: true,
      dailyTokenBudget: 500_000,
      retentionDays: 60,
      dataSharing: 'pseudonymized',
      userDailyTokenBudget: 20_000,
      useTenantKey: false,
      tenantKeyFallbackToPlatform: false,
    });
    expectRequestMatchesContract('AssistantSettingsController_update_v1', body);
  });

  it('lets assistant text link the administration page (portal-routes allow-list)', () => {
    expect(safePortalHref('/assistant/admin')).toBe('/assistant/admin');
    expect(safePortalHref('/assistant/admin?tab=usage')).toBe('/assistant/admin?tab=usage');
    expect(safePortalHref(`/assistant/admin?tab=audit&audit=${AUDIT_CONVERSATION_ID}`)).toBe(
      `/assistant/admin?tab=audit&audit=${AUDIT_CONVERSATION_ID}`,
    );
    expect(safePortalHref('/assistant/admin/x')).toBeNull();
  });

  it('names tenant-key error codes in plain words', () => {
    expect(tenantKeyErrorText('provider_auth')).toBe('the provider rejected the key');
    expect(tenantKeyErrorText('something_new')).toBe('the key could not be checked');
    expect(tenantKeyErrorText(null)).toBeNull();
  });
});

function renderAdmin(options: Parameters<typeof renderWithProviders>[1] = {}) {
  return renderWithProviders(<AssistantAdminPage />, { route: '/assistant/admin', ...options });
}

describe('/assistant/admin tabs and gating (D1)', () => {
  it('shows every tab to an organization admin (assistant:configure + audit:read), usage first', async () => {
    mockApi({
      AssistantAdminController_usageByUser_v1: () => okJson(USAGE_USERS),
      AssistantUsageController_get_v1: () => okJson(ORG_USAGE),
    });
    renderAdmin({ role: 'organization_admin' });
    const tabs = screen.getByRole('tablist', { name: 'AI administration sections' });
    expect(
      within(tabs)
        .getAllByRole('tab')
        .map((tab) => tab.textContent),
    ).toEqual(['Usage', 'Limits and provider', 'Feedback', 'Conversation audit', 'Tool calls']);
    expect(screen.getByRole('tab', { name: 'Usage' })).toHaveAttribute('aria-selected', 'true');
    expect((await screen.findAllByText('Ada Analyst')).length).toBeGreaterThan(0);
  });

  it('shows only the audit tabs to a security analyst (audit:read, no assistant:configure)', async () => {
    mockApi({
      AssistantAdminAuditController_conversations_v1: () => okJson(AUDIT_LIST),
    });
    renderAdmin({ role: 'security_analyst', route: '/assistant/admin?tab=usage' });
    const tabs = screen.getByRole('tablist', { name: 'AI administration sections' });
    expect(
      within(tabs)
        .getAllByRole('tab')
        .map((tab) => tab.textContent),
    ).toEqual(['Conversation audit', 'Tool calls']);
    // `?tab=usage` is not permitted: the first allowed tab opens instead.
    expect(screen.getByRole('tab', { name: 'Conversation audit' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    await screen.findByRole('button', { name: /Open audit of the conversation/ });
  });

  it('is forbidden without either operation', () => {
    renderAdmin({ permissions: ['assistant:use'] });
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeVisible();
  });
});

describe('Usage tab (D1)', () => {
  it('lists usage per person and day with key source, totals, estimate labels and the chart', async () => {
    const queries: Record<string, string | null>[] = [];
    mockApi({
      AssistantAdminController_usageByUser_v1: ({ url }) => {
        queries.push({
          from: url.searchParams.get('from'),
          to: url.searchParams.get('to'),
          userId: url.searchParams.get('userId'),
        });
        return okJson(USAGE_USERS);
      },
      AssistantUsageController_get_v1: () => okJson(ORG_USAGE),
    });
    const { container, user } = renderAdmin({ role: 'organization_admin' });
    const table = await screen.findByRole('table', { name: /usage per person and day/ });
    const rows = within(table).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('2026-11-26');
    expect(rows[1]).toHaveTextContent('Ada Analyst');
    expect(rows[1]).toHaveTextContent('Platform key');
    expect(rows[1]).toHaveTextContent('2,000');
    expect(rows[1]).toHaveTextContent('$0.0125');
    // A user outside the organization (no name, no address) and a model without a price.
    expect(rows[2]).toHaveTextContent('User 01930000');
    expect(rows[2]).toHaveTextContent('Your key');
    expect(rows[2]).toHaveTextContent('—');
    const totals = screen.getByRole('region', { name: 'Usage totals' });
    expect(totals).toHaveTextContent('2,750');
    expect(totals).toHaveTextContent('Estimated cost (USD, estimate)');
    expect(totals).toHaveTextContent('$0.0125');
    expect(await screen.findByRole('figure', { name: 'Tokens per day' })).toBeInTheDocument();
    const days = presetRange('30');
    expect(queries[0]).toEqual({ from: days.fromDay, to: days.toDay, userId: null });
    await expectNoAxeViolations(container);

    // A person's totals row filters the page to that person.
    await user.click(screen.getByRole('button', { name: /Ada Analyst.*show only this person/ }));
    await waitFor(() =>
      expect(queries.at(-1)?.userId).toBe('01930000-0000-7000-8000-0000000a0001'),
    );
    expect(currentTestUrl()).toContain('user=01930000-0000-7000-8000-0000000a0001');
  });
});

describe('Limits and provider tab (D1, D3, D7)', () => {
  it('shows the effective limits read-only and saves budgets, retention and the data-sharing level', async () => {
    const bodies: unknown[] = [];
    mockApi({
      AssistantSettingsController_get_v1: () =>
        okJson({ ...SETTINGS, enabled: true, externalProcessingAcknowledged: true }),
      AssistantSettingsController_update_v1: ({ body }) => {
        bodies.push(body);
        return okJson({ ...SETTINGS, dataSharing: 'pseudonymized', rowVersion: 4 });
      },
    });
    const { user, container } = renderAdmin({ route: '/assistant/admin?tab=limits' });
    const form = await screen.findByRole('form', { name: 'AI limits and data sharing' });
    const limits = screen.getByRole('region', { name: 'Effective limits' });
    expect(limits).toHaveTextContent('6 per minute');
    expect(limits).toHaveTextContent('16 calls in 8 rounds');
    expect(limits).toHaveTextContent('5 min');
    expect(within(limits).queryByRole('textbox')).not.toBeInTheDocument();
    expect(within(limits).queryByRole('spinbutton')).not.toBeInTheDocument();
    await user.type(
      within(form).getByRole('spinbutton', { name: 'Daily token budget per person' }),
      '20000',
    );
    // The data-sharing select explains what pseudonymized replaces and its limitation.
    await user.click(
      within(form).getByRole('combobox', { name: 'Data shared with the AI provider' }),
    );
    await user.click(await screen.findByRole('option', { name: /Pseudonymized/ }));
    expect(form).toHaveTextContent(/e-mail addresses, IP addresses, domains and person names/);
    expect(form).toHaveTextContent(/names written in free text .* are not detected/);
    // Without a valid key the tenant-key switch stays off and disabled.
    expect(
      within(form).getByRole('switch', { name: /Use your organization.s provider key/ }),
    ).toBeDisabled();
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      expectedRowVersion: 3,
      enabled: true,
      externalProcessingAcknowledged: true,
      userDailyTokenBudget: 20000,
      dataSharing: 'pseudonymized',
      useTenantKey: false,
    });
    expectRequestMatchesContract('AssistantSettingsController_update_v1', bodies[0]);
    // Tenant keys not offered by the platform: an explanatory note, no key form.
    expect(screen.getByText(/not offered by the platform/)).toBeInTheDocument();
    expect(screen.queryByLabelText('API key')).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('shows the coded refusal of the settings save', async () => {
    mockApi({
      AssistantSettingsController_get_v1: () => okJson(SETTINGS),
      AssistantSettingsController_update_v1: () =>
        apiErrorJson(409, 'assistant_settings_conflict', 'conflict'),
    });
    const { user } = renderAdmin({ route: '/assistant/admin?tab=limits' });
    const form = await screen.findByRole('form', { name: 'AI limits and data sharing' });
    await user.click(within(form).getByRole('button', { name: 'Save' }));
    expect(await within(form).findByText(/Someone else changed these settings/)).toBeVisible();
    expect(within(form).getByRole('button', { name: 'Reload the current settings' })).toBeVisible();
  });
});

describe('tenant-supplied provider key (D7, I27)', () => {
  it('is a write-only password field that is cleared after the submit and never shown again', async () => {
    const bodies: Record<string, unknown>[] = [];
    let settings = SETTINGS_KEYS_OFFERED;
    mockApi({
      AssistantSettingsController_get_v1: () => okJson(settings),
      AssistantProviderKeyController_set_v1: ({ body }) => {
        bodies.push(body as Record<string, unknown>);
        settings = { ...settings, tenantKey: TENANT_KEY, rowVersion: settings.rowVersion + 1 };
        return okJson(TENANT_KEY);
      },
    });
    const { user, container } = renderWithProviders(
      <TenantKeySection settings={SETTINGS_KEYS_OFFERED} />,
    );
    const input = screen.getByLabelText('API key');
    expect(input).toHaveAttribute('type', 'password');
    expect(input).toHaveAttribute('autocomplete', 'off');
    expect(input).toHaveAttribute('spellcheck', 'false');
    await user.type(input, SYNTHETIC_KEY);
    expect(input).toHaveValue(SYNTHETIC_KEY);
    await user.click(screen.getByRole('button', { name: 'Store the key' }));
    // Cleared at once, before the answer.
    expect(input).toHaveValue('');
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({
      expectedRowVersion: SETTINGS_KEYS_OFFERED.rowVersion,
      provider: 'anthropic',
      model: 'claude-opus-5-5',
      apiKey: SYNTHETIC_KEY,
    });
    expectRequestMatchesContract('AssistantProviderKeyController_set_v1', bodies[0]);
    expect(
      await screen.findByText('The key was checked with the provider and stored.'),
    ).toBeVisible();
    // The key is nowhere in the document: not as text, not in an attribute or a value.
    expect(container.innerHTML).not.toContain(SYNTHETIC_KEY);
    expect(
      [...container.querySelectorAll('input')].some((element) => element.value === SYNTHETIC_KEY),
    ).toBe(false);
    await expectNoAxeViolations(container);
  });

  it('clears the field after a refused key and shows the coded reason (422, MFA)', async () => {
    const codes = ['assistant_tenant_key_rejected', 'mfa_required'];
    mockApi({
      AssistantProviderKeyController_set_v1: () => {
        const code = codes.shift() ?? 'assistant_tenant_key_unverified';
        return apiErrorJson(code === 'mfa_required' ? 403 : 422, code, code);
      },
    });
    const { user, container } = renderWithProviders(
      <TenantKeySection settings={SETTINGS_KEYS_OFFERED} />,
    );
    const input = screen.getByLabelText('API key');
    await user.type(input, SYNTHETIC_KEY);
    await user.click(screen.getByRole('button', { name: 'Store the key' }));
    expect(await screen.findByText(/The provider rejected this key/)).toBeVisible();
    expect(input).toHaveValue('');
    await user.type(input, SYNTHETIC_KEY);
    await user.click(screen.getByRole('button', { name: 'Store the key' }));
    expect(await screen.findByText(/multi-factor authentication. Verify/)).toBeVisible();
    expect(input).toHaveValue('');
    expect(container.innerHTML).not.toContain(SYNTHETIC_KEY);
  });

  it('refuses a malformed key locally without sending it', async () => {
    let calls = 0;
    mockApi({
      AssistantProviderKeyController_set_v1: () => {
        calls += 1;
        return okJson(TENANT_KEY);
      },
    });
    const { user } = renderWithProviders(<TenantKeySection settings={SETTINGS_KEYS_OFFERED} />);
    await user.type(screen.getByLabelText('API key'), 'too short');
    await user.click(screen.getByRole('button', { name: 'Store the key' }));
    expect(await screen.findByText(/20 to 512 characters/)).toBeVisible();
    expect(screen.getByLabelText('API key')).toHaveValue('');
    expect(calls).toBe(0);
  });

  it('empties the field when the form unmounts', async () => {
    const { user, unmount } = renderWithProviders(
      <TenantKeySection settings={SETTINGS_KEYS_OFFERED} />,
    );
    const input = screen.getByLabelText<HTMLInputElement>('API key');
    await user.type(input, SYNTHETIC_KEY);
    unmount();
    expect(input.value).toBe('');
  });

  it('shows only fingerprint and status of a stored key; validates and removes it (ConfirmDialog)', async () => {
    const removed: string[] = [];
    let validated = 0;
    mockApi({
      AssistantSettingsController_get_v1: () => okJson(SETTINGS_KEYS_OFFERED),
      AssistantProviderKeyController_validate_v1: () => {
        validated += 1;
        return okJson({ ...TENANT_KEY, status: 'invalid', lastErrorCode: 'provider_auth' });
      },
      AssistantProviderKeyController_remove_v1: ({ url }) => {
        removed.push(url.searchParams.get('expectedRowVersion') ?? '');
        return noContentResponse();
      },
    });
    const settings = {
      ...SETTINGS_KEYS_OFFERED,
      tenantKey: { ...TENANT_KEY, lastErrorCode: 'provider_auth' },
    };
    const { user } = renderWithProviders(<TenantKeySection settings={settings} />);
    expect(screen.getByText('0f1e2d3c4b5a6978')).toBeVisible();
    expect(screen.getByText('Valid')).toBeVisible();
    expect(screen.getByText(/by Ada Analyst/)).toBeVisible();
    expect(screen.getByText(/the provider rejected the key/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Check the key again' }));
    expect(await screen.findByText('The key is invalid.')).toBeVisible();
    expect(validated).toBe(1);
    await user.click(screen.getByRole('button', { name: 'Remove the key' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Remove the key' }));
    await waitFor(() => expect(removed).toEqual([String(SETTINGS_KEYS_OFFERED.rowVersion)]));
    expect(await screen.findByText(/The key was removed/)).toBeVisible();
  });
});

describe('Feedback tab (D2)', () => {
  it('lists ratings with reason, comment, turn and tools; filters by rating', async () => {
    const queries: Record<string, string | null>[] = [];
    mockApi({
      AssistantAdminController_feedback_v1: ({ url }) => {
        queries.push({
          rating: url.searchParams.get('rating'),
          from: url.searchParams.get('from'),
        });
        return okJson(FEEDBACK_LIST);
      },
    });
    const { user, container } = renderAdmin({ route: '/assistant/admin?tab=feedback' });
    const table = await screen.findByRole('table', { name: /Feedback on AI answers/ });
    const row = within(table).getAllByRole('row')[1]!;
    expect(row).toHaveTextContent('Not helpful');
    expect(row).toHaveTextContent('Incomplete');
    expect(row).toHaveTextContent('The quarantine count was missing.');
    expect(row).toHaveTextContent('assistant-system/7');
    expect(row).toHaveTextContent('pseudonymized');
    expect(row).toHaveTextContent('quarantine_entries_search');
    expect(queries[0]?.from).toBe(presetRange('30').from);
    await user.click(screen.getByRole('combobox', { name: 'Rating' }));
    await user.click(await screen.findByRole('option', { name: 'Not helpful' }));
    await waitFor(() => expect(queries.at(-1)?.rating).toBe('down'));
    await expectNoAxeViolations(container);
  });
});

describe('Conversation audit (D4, I24)', () => {
  it('lists conversations without a title and opens the metadata-only detail in a drawer', async () => {
    const detailIds: string[] = [];
    mockApi({
      AssistantAdminAuditController_conversations_v1: () => okJson(AUDIT_LIST),
      AssistantAdminAuditController_conversation_v1: ({ params }) => {
        detailIds.push(params.conversationId ?? '');
        return okJson(AUDIT_DETAIL_WITH_CONTENT);
      },
    });
    const { user } = renderAdmin({ route: '/assistant/admin?tab=audit' });
    const table = await screen.findByRole('table', { name: /AI conversations/ });
    expect(within(table).getAllByRole('row')[1]).toHaveTextContent('Ada Analyst');
    await user.click(within(table).getByRole('button', { name: /Open audit of the conversation/ }));
    const drawer = await screen.findByRole('dialog', { name: 'Conversation audit' });
    await within(drawer).findByRole('region', { name: 'Tool calls' });
    expect(detailIds).toEqual([AUDIT_CONVERSATION_ID]);
    expect(currentTestUrl()).toContain(`audit=${AUDIT_CONVERSATION_ID}`);
    // Only allow-listed fields render: no title, message, card or report HTML.
    for (const sentinel of CONTENT_SENTINELS)
      expect(document.body.innerHTML).not.toContain(sentinel);
    expect(drawer).toHaveTextContent('users_replace_roles');
    expect(drawer).toHaveTextContent('Not allowed in chat');
    expect(drawer).toHaveTextContent('PolicyManagementController_create_v1');
    expect(drawer).toHaveTextContent('@tenant.example.test');
    expect(drawer).toHaveTextContent('Incomplete');
  });

  it('renders the stored redacted parameters as JSON text and every section', async () => {
    const { container, user } = renderWithProviders(<AuditConversationView data={AUDIT_DETAIL} />);
    for (const name of ['Turns', 'Tool calls', 'Confirmations', 'Reports', 'Ratings'])
      expect(screen.getByRole('region', { name })).toBeInTheDocument();
    const summaries = screen.getAllByText('Redacted parameters');
    await user.click(summaries[1]!);
    const pre = container.querySelectorAll('pre')[1]!;
    expect(JSON.parse(pre.textContent ?? '')).toEqual({
      path: { userId: '01930000-0000-7000-8000-0000000a0001' },
      body: { roleKeys: ['super_admin'] },
    });
    expect(screen.getByText('assistant-system/7', { exact: false })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('searches tool calls (executions) with filters and opens the conversation audit', async () => {
    const queries: Record<string, string | null>[] = [];
    mockApi({
      AssistantAdminAuditController_executions_v1: ({ url }) => {
        queries.push({
          tool: url.searchParams.get('tool'),
          decision: url.searchParams.get('decision'),
        });
        return okJson(EXECUTIONS_LIST);
      },
      AssistantAdminAuditController_conversation_v1: () => okJson(AUDIT_DETAIL),
    });
    const { user, container } = renderAdmin({ route: '/assistant/admin?tab=executions' });
    const table = await screen.findByRole('table', { name: /AI tool calls/ });
    expect(within(table).getAllByRole('row')[1]).toHaveTextContent('quarantine_entries_search');
    await user.type(screen.getByLabelText('Tool name'), 'quarantine_entries_search');
    await user.click(screen.getByRole('button', { name: 'Search' }));
    await waitFor(() => expect(queries.at(-1)?.tool).toBe('quarantine_entries_search'));
    await user.click(screen.getByRole('combobox', { name: 'Decision' }));
    await user.click(await screen.findByRole('option', { name: 'Not allowed in chat' }));
    await waitFor(() => expect(queries.at(-1)?.decision).toBe('denied_guard'));
    await expectNoAxeViolations(container);
    await user.click(within(table).getByRole('button', { name: /Open audit/ }));
    expect(await screen.findByRole('dialog', { name: 'Conversation audit' })).toBeVisible();
  });
});
