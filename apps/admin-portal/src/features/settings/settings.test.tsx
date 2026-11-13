import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { screen, waitFor, within } from '@testing-library/react';
import Ajv from 'ajv';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  TEST_ORG,
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { toJsonSchema } from '@/test/contract';
import { alertDefaults, alertSettingsBody, preferencesSchema } from './notification-forms';
import { organizationSettingsSchema, settingsBody } from './organization-settings-form';
import {
  engineFields,
  engineFormDefaults,
  engineSettingsBody,
  fieldKey,
  type EngineView,
} from './scan-engine-fields';
import { SettingsPage } from './settings-page';
import { ATTACHMENT, BEC, DLP, RSPAMD, SANDBOX, SCAN_SETTINGS, URL_ENGINE } from './test-data';

const organization: SuccessBody<'OrganizationsController_get_v1'> = {
  id: TEST_ORG.id,
  slug: 'alpha',
  name: 'Alpha Industries (example)',
  kind: 'customer',
  status: 'active',
  statusReason: null,
  statusChangedAt: null,
  plan: { code: 'business', name: 'Business' },
  deploymentMode: 'saas',
  dataRegion: 'eu-west-1',
  deployments: [],
  deletion: null,
  createdAt: '2026-07-01T00:00:00.000Z',
  updatedAt: '2026-11-01T00:00:00.000Z',
};

const orgSettings: SuccessBody<'OrganizationConfigurationController_getSettings_v1'> = {
  organizationId: TEST_ORG.id,
  timezone: 'Europe/Berlin',
  locale: 'en-GB',
  quarantineRetentionDays: 30,
  quarantineRetentionMaxDays: 90,
  digestEnabled: true,
  digestSchedule: '0 8 * * 1-5',
  notificationEmail: 'security@example.com',
  mfaRequired: false,
  preferences: {},
  updatedAt: '2026-11-01T00:00:00.000Z',
};

const alerts = {
  threatDetected: { enabled: true, minSeverity: 'high' as const, throttleMinutes: 60 },
  domainDnsFailed: { enabled: true, throttleMinutes: 1440 },
  webhookDisabled: { enabled: false, throttleMinutes: 1440 },
  includeOrganizationContact: true,
};
const notificationSettings: SuccessBody<'NotificationsController_settings_v1'> = {
  settings: { alerts },
  stored: null,
  invalidStored: false,
  rowVersion: 4,
  updatedAt: null,
  defaults: { alerts },
  bounds: {
    threatDetected: { minThrottleMinutes: 15, maxThrottleMinutes: 1440 },
    domainDnsFailed: { minThrottleMinutes: 60, maxThrottleMinutes: 10080 },
    webhookDisabled: { minThrottleMinutes: 60, maxThrottleMinutes: 10080 },
  },
};

const preferences: SuccessBody<'NotificationsController_preferences_v1'> = {
  optOut: ['policy_alert'],
  quarantineDigestOptOut: false,
  quarantineDigestOptOutAllowed: true,
  kinds: ['threat_detected', 'domain_dns_failed', 'policy_alert'],
  invalidStored: false,
};

describe('Settings: organization tab', () => {
  it('edits the organization settings sending only the changed fields', async () => {
    let body: unknown = null;
    mockApi({
      OrganizationsController_get_v1: () => okJson(organization),
      OrganizationConfigurationController_getSettings_v1: () => okJson(orgSettings),
      OrganizationConfigurationController_updateSettings_v1: ({ body: b }) => (
        (body = b),
        okJson({ ...orgSettings, quarantineRetentionDays: 45 })
      ),
    });
    const { container, user } = renderWithProviders(<SettingsPage />, { route: '/settings' });
    const retention = await screen.findByLabelText(/^Quarantine retention \(days\)/);
    await expectNoAxeViolations(container);
    await user.clear(retention);
    await user.type(retention, '120');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('At most 90 days')).toBeInTheDocument();
    await user.clear(retention);
    await user.type(retention, '45');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(body).toEqual({ quarantineRetentionDays: 45 }));
    expectRequestMatchesContract('OrganizationConfigurationController_updateSettings_v1', body);
    expect(await screen.findByText('Organization settings saved.')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Quarantine settings' })).toHaveAttribute(
      'href',
      '/quarantine/settings',
    );
    expect(screen.getByRole('link', { name: 'Policy management' })).toHaveAttribute(
      'href',
      '/policies?tab=settings',
    );
  });

  it('maps an api validation error to the field', async () => {
    mockApi({
      OrganizationsController_get_v1: () => okJson(organization),
      OrganizationConfigurationController_getSettings_v1: () => okJson(orgSettings),
      OrganizationConfigurationController_updateSettings_v1: () =>
        apiErrorJson(400, 'validation_failed', ['timezone: unknown time zone']),
    });
    const { user } = renderWithProviders(<SettingsPage />, { route: '/settings?tab=organization' });
    const tz = await screen.findByLabelText(/^Time zone/);
    await user.clear(tz);
    await user.type(tz, 'Mars/Olympus');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('unknown time zone')).toBeInTheDocument();
  });

  it('schemas produce contract-conformant bodies', () => {
    const values = organizationSettingsSchema(90).parse({
      timezone: 'UTC',
      locale: 'de-DE',
      quarantineRetentionDays: '60',
      digestEnabled: false,
      digestSchedule: '0 7 * * *',
      notificationEmail: '',
      mfaRequired: true,
    });
    const body = settingsBody(values, orgSettings);
    expect(body).toEqual({
      timezone: 'UTC',
      locale: 'de-DE',
      quarantineRetentionDays: 60,
      digestEnabled: false,
      digestSchedule: '0 7 * * *',
      notificationEmail: null,
      mfaRequired: true,
    });
    expectRequestMatchesContract('OrganizationConfigurationController_updateSettings_v1', body);
    expectRequestMatchesContract(
      'NotificationsController_putSettings_v1',
      alertSettingsBody(alertDefaults(notificationSettings), 4),
    );
    expectRequestMatchesContract(
      'NotificationsController_putPreferences_v1',
      preferencesSchema.parse({ optOut: ['policy_alert'], quarantineDigestOptOut: true }),
    );
  });
});

describe('Settings: notifications and preferences', () => {
  it('saves alert settings with the row version; explains a version conflict', async () => {
    const bodies: unknown[] = [];
    mockApi({
      NotificationsController_settings_v1: () => okJson(notificationSettings),
      NotificationsController_putSettings_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(409, 'version_conflict', 'The settings changed since rowVersion 4')
          : okJson(notificationSettings);
      },
    });
    const { container, user } = renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=notifications',
    });
    await screen.findByRole('form', { name: 'Organization alerts' });
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('switch', { name: 'Send webhook alerts' }));
    await user.click(screen.getByRole('button', { name: 'Save alert settings' }));
    expect(await screen.findByText(/The settings changed since rowVersion 4/)).toBeInTheDocument();
    expect(bodies[0]).toMatchObject({
      expectedRowVersion: 4,
      settings: { alerts: { webhookDisabled: { enabled: true, throttleMinutes: 1440 } } },
    });
    expectRequestMatchesContract('NotificationsController_putSettings_v1', bodies[0]);
  });

  it('is read-only without settings:manage', async () => {
    mockApi({ NotificationsController_settings_v1: () => okJson(notificationSettings) });
    renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=notifications',
      role: 'security_analyst',
    });
    expect(await screen.findByText(/changing them needs settings:manage/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Save alert settings' })).not.toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Send threat alerts' })).toBeDisabled();
  });

  it('saves personal preferences (self-service)', async () => {
    let body: unknown = null;
    mockApi({
      NotificationsController_preferences_v1: () => okJson(preferences),
      NotificationsController_putPreferences_v1: ({ body: b }) => (
        (body = b),
        okJson({ ...preferences, optOut: [] })
      ),
    });
    const { user } = renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=preferences',
      role: 'mailbox_user',
    });
    await user.click(await screen.findByRole('checkbox', { name: 'Policy alerts' }));
    await user.click(screen.getByRole('checkbox', { name: 'Threat detected' }));
    await user.click(screen.getByRole('switch', { name: 'Receive the quarantine digest' }));
    await user.click(screen.getByRole('button', { name: 'Save preferences' }));
    await waitFor(() =>
      expect(body).toEqual({ optOut: ['threat_detected'], quarantineDigestOptOut: true }),
    );
    expectRequestMatchesContract('NotificationsController_putPreferences_v1', body);
  });

  it('mailbox users only get the self-service tabs', async () => {
    mockApi({ NotificationsController_preferences_v1: () => okJson(preferences) });
    renderWithProviders(<SettingsPage />, { route: '/settings', role: 'mailbox_user' });
    expect(await screen.findByRole('tab', { name: 'My notifications' })).toHaveAttribute(
      'aria-selected',
      'true',
    );
    expect(screen.queryByRole('tab', { name: 'Organization' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Scanning' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Security' })).toBeInTheDocument();
    await screen.findByRole('form', { name: 'Your notifications' });
  });

  it('archive tab says it arrives in 8.1; switching tabs writes the URL', async () => {
    mockApi({ NotificationsController_preferences_v1: () => okJson(preferences) });
    const { user, container } = renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=archive',
      role: 'mailbox_user',
    });
    expect(screen.getByText('Arrives in step 8.1')).toBeInTheDocument();
    expect(screen.getByText(/Archive and retention settings arrive in 8.1/)).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('tab', { name: 'My notifications' }));
    await waitFor(() => expect(currentTestUrl()).toBe('/settings?tab=preferences'));
    await screen.findByRole('form', { name: 'Your notifications' });
  });

  it('security tab hosts password, MFA and sessions', async () => {
    mockApi({ SessionsController_list_v1: () => okJson({ data: [], nextCursor: null }) });
    renderWithProviders(<SettingsPage />, { route: '/settings?tab=security' });
    expect(await screen.findByRole('form', { name: 'Change password' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Two-factor authentication' })).toBeInTheDocument();
  });
});

describe('Settings: scanning', () => {
  it('lists engines; edits the Rspamd override with bounds checks and a contract body', async () => {
    let body: unknown = null;
    mockApi({
      ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS),
      ScanSettingsController_replace_v1: ({ body: b, params }) => {
        body = b;
        expect(params.engine).toBe('rspamd');
        return okJson({ ...RSPAMD, version: 4, note: SCAN_SETTINGS.note });
      },
    });
    const { container, user } = renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=scanning',
    });
    const card = await screen.findByRole('region', { name: 'Spam filter (Rspamd)' });
    expect(within(card).getByText('Your override applies')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(within(card).getByRole('button', { name: 'Edit' }));
    const form = within(card).getByRole('form', { name: 'Spam filter (Rspamd) settings' });
    await user.click(within(form).getByRole('checkbox', { name: 'Override Spam score threshold' }));
    const score = within(form).getByLabelText('Spam score threshold');
    await user.clear(score);
    await user.type(score, '45');
    await user.click(within(form).getByRole('button', { name: 'Save override' }));
    expect(await within(form).findByText('At most 30')).toBeInTheDocument();
    await user.clear(score);
    await user.type(score, '7.5');
    await user.click(within(form).getByRole('button', { name: 'Save override' }));
    await waitFor(() =>
      expect(body).toEqual({
        expectedVersion: 3,
        settings: { spamScore: 7.5, dmarcRejectVerdict: 'malicious' },
      }),
    );
    expectRequestMatchesContract('ScanSettingsController_replace_v1', body);
  });

  it('maps 422 scan_settings_invalid violations to the field', async () => {
    mockApi({
      ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS),
      ScanSettingsController_replace_v1: () =>
        apiErrorJson(422, 'scan_settings_invalid', 'Invalid settings', {
          extra: {
            violations: [
              {
                path: 'rewrite.expiryDays',
                code: 'out_of_bounds',
                message: 'Must be at most 60 for your plan',
              },
            ],
          },
        }),
    });
    const { user } = renderWithProviders(<SettingsPage />, { route: '/settings?tab=scanning' });
    const card = await screen.findByRole('region', { name: 'URLs' });
    await user.click(within(card).getByRole('button', { name: 'Edit' }));
    await user.click(
      within(card).getByRole('checkbox', { name: 'Override Rewritten links expire after (days)' }),
    );
    await user.click(within(card).getByRole('button', { name: 'Save override' }));
    expect(await within(card).findByText('Must be at most 60 for your plan')).toBeInTheDocument();
  });

  it('resets an engine with confirmation (expectedVersion in the query)', async () => {
    let query: string | null = null;
    mockApi({
      ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS),
      ScanSettingsController_reset_v1: ({ url }) => (
        (query = url.searchParams.get('expectedVersion')),
        okJson({ ...RSPAMD, override: null, version: 4, note: SCAN_SETTINGS.note })
      ),
    });
    const { user } = renderWithProviders(<SettingsPage />, { route: '/settings?tab=scanning' });
    const card = await screen.findByRole('region', { name: 'Spam filter (Rspamd)' });
    await user.click(within(card).getByRole('button', { name: 'Reset to platform' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Reset to platform',
      }),
    );
    await waitFor(() => expect(query).toBe('3'));
  });

  it('read-only for users without scan:settings_manage', async () => {
    mockApi({ ScanSettingsController_list_v1: () => okJson(SCAN_SETTINGS) });
    renderWithProviders(<SettingsPage />, {
      route: '/settings?tab=scanning',
      role: 'read_only_user',
    });
    await screen.findByRole('region', { name: 'Attachments' });
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
  });

  it('engine forms produce override objects that match the OpenAPI override schemas', () => {
    const spec = JSON.parse(
      readFileSync(join(__dirname, '../../../../../docs/api/openapi.json'), 'utf8'),
    ) as {
      paths: Record<
        string,
        Record<
          string,
          { responses: Record<string, { content: Record<string, { schema: unknown }> }> }
        >
      >;
    };
    const listSchema = toJsonSchema(
      spec.paths['/api/v1/scan-settings']!.get!.responses['200']!.content['application/json']!
        .schema,
    ) as {
      properties: {
        data: {
          items: {
            oneOf?: { properties: Record<string, unknown> }[];
            anyOf?: { properties: Record<string, unknown> }[];
          };
        };
      };
    };
    const variants =
      listSchema.properties.data.items.oneOf ?? listSchema.properties.data.items.anyOf ?? [];
    const ajv = new Ajv({ allErrors: true, strict: false });
    const views: EngineView[] = [RSPAMD, ATTACHMENT, URL_ENGINE, BEC, DLP, SANDBOX];
    for (const view of views) {
      const variant = variants.find((v) =>
        (v.properties.engine as { enum?: string[] }).enum?.includes(view.engine),
      );
      expect(variant, view.engine).toBeTruthy();
      const validate = ajv.compile(variant!.properties.override as object);
      const values = engineFormDefaults(view);
      for (const def of engineFields(view)) values[fieldKey(def.path)]!.on = true;
      const settings = engineSettingsBody(view, values);
      expect(validate(settings), `${view.engine}: ${JSON.stringify(validate.errors)}`).toBe(true);
    }
  });
});
