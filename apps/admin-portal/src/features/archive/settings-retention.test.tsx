import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { RetentionPage } from './retention-page';
import { ArchiveSettingsPanel, draftOf, settingsBody } from './settings-panel';
import { policyBody, policyDraftOf } from './retention-page';
import { DOMAIN_ID, POLICY, POLICY_2, POLICY_ID, SETTINGS, STATUS } from './test-data';

const KEYS = {
  data: [
    {
      id: '01930000-0000-7000-8000-00000000c901',
      version: 1,
      status: 'active' as const,
      rootKeyId: 'root-EXAMPLE-1',
      algorithm: 'AES-256-GCM',
      rotationReason: null,
      createdBy: null,
      createdAt: '2026-10-01T08:00:00.000Z',
      activatedAt: '2026-10-01T08:00:00.000Z',
      retiredAt: null,
      destroyedAt: null,
    },
  ],
  nextCursor: null,
};

function mockSettings(settings = SETTINGS, extra: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    ArchiveAdminController_get_v1: () => okJson(settings),
    ArchiveAdminController_status_v1: () => okJson(STATUS),
    ArchiveAdminController_listKeys_v1: () => okJson(KEYS),
    ArchiveRetentionController_list_v1: () =>
      okJson({ data: [POLICY, POLICY_2], nextCursor: null }),
    DomainsController_list_v1: () =>
      okJson({ data: [{ id: DOMAIN_ID, name: 'corp.example.test' }], nextCursor: null } as never),
    DepartmentsController_list_v1: () => okJson({ data: [], nextCursor: null }),
    UsersController_list_v1: () => okJson({ data: [], nextCursor: null }),
    ...extra,
  });
}

describe('Settings → Archive and retention (A22, A28)', () => {
  it('builds a contract-valid full PUT body from the settings', () => {
    const body = settingsBody(
      { ...draftOf(SETTINGS), enabled: true, scopeMode: 'include', domainIds: [DOMAIN_ID] },
      3,
    );
    expectRequestMatchesContract('ArchiveAdminController_update_v1', body);
    expect(body.settings?.scope).toEqual({
      mode: 'include',
      domainIds: [DOMAIN_ID],
      departmentIds: [],
      userIds: [],
      addresses: [],
    });
  });

  it('shows status, availability and key versions; read-only for a compliance auditor', async () => {
    mockSettings();
    const { container } = renderWithProviders(<ArchiveSettingsPanel />, {
      role: 'compliance_auditor',
    });
    expect(
      await screen.findByText(/Immutable storage \(S3 Object Lock\) is available/),
    ).toBeInTheDocument();
    expect(
      await screen.findByText('12 active · 1 in review · 0 being disposed'),
    ).toBeInTheDocument();
    expect(screen.getByText(/needs the archive:manage permission/)).toBeInTheDocument();
    expect(screen.queryByRole('form', { name: 'Archive settings' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Rotate key' })).not.toBeInTheDocument();
    expect(await screen.findByText('root-EXAMPLE-1')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('warns when the plan has no archiving entitlement', async () => {
    mockSettings({ ...SETTINGS, entitled: false, objectLockAvailable: false });
    renderWithProviders(<ArchiveSettingsPanel />, { role: 'organization_admin' });
    expect(
      await screen.findByText(/Archiving is not part of your organization’s plan/),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Object Lock\) is not available on this deployment/),
    ).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: 'Compliance' })).toBeDisabled();
  });

  it('enables archiving with a CAS body and asks for typed confirmation before compliance immutability', async () => {
    const bodies: unknown[] = [];
    mockSettings(SETTINGS, {
      ArchiveAdminController_update_v1: ({ body, request }) => {
        bodies.push(body);
        expect(request.headers.get('idempotency-key')).toBeTruthy();
        return okJson({ ...SETTINGS, enabled: true, immutability: 'compliance', rowVersion: 4 });
      },
    });
    const { user } = renderWithProviders(<ArchiveSettingsPanel />, { role: 'organization_admin' });
    const form = await screen.findByRole('form', { name: 'Archive settings' });
    await user.click(
      within(form).getByRole('switch', { name: 'Archive mail of this organization' }),
    );
    await user.click(within(form).getByRole('radio', { name: 'Compliance' }));
    await user.click(within(form).getByRole('button', { name: 'Save archive settings' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/This cannot be undone/)).toBeInTheDocument();
    const confirm = within(dialog).getByRole('button', { name: 'Switch to compliance' });
    expect(confirm).toBeDisabled();
    expect(bodies).toHaveLength(0);
    await user.type(within(dialog).getByLabelText(/Type compliance to confirm/), 'compliance');
    await user.click(confirm);
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({
      expectedRowVersion: 3,
      enabled: true,
      immutability: 'compliance',
    });
    expectRequestMatchesContract('ArchiveAdminController_update_v1', bodies[0]);
  });

  it('offers reload or overwrite on a 409 archive_settings_conflict (currentRowVersion)', async () => {
    const versions: number[] = [];
    mockSettings(SETTINGS, {
      ArchiveAdminController_update_v1: ({ body }) => {
        const version = (body as { expectedRowVersion: number }).expectedRowVersion;
        versions.push(version);
        return version === 3
          ? apiErrorJson(409, 'archive_settings_conflict', 'stale', {
              extra: { currentRowVersion: 7 },
            })
          : okJson({
              ...SETTINGS,
              rowVersion: 8,
              settings: {
                ...SETTINGS.settings,
                include: { ...SETTINGS.settings.include, failed: true },
              },
            });
      },
    });
    const { user } = renderWithProviders(<ArchiveSettingsPanel />, { role: 'organization_admin' });
    const form = await screen.findByRole('form', { name: 'Archive settings' });
    await user.click(within(form).getByRole('checkbox', { name: 'Failed' }));
    await user.click(within(form).getByRole('button', { name: 'Save archive settings' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByText(/Someone else saved the archive settings/)).toBeInTheDocument();
    expect(
      within(dialog).getByRole('button', { name: 'Reload the current version' }),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Overwrite with my edit' }));
    await waitFor(() => expect(versions).toEqual([3, 7]));
  });

  it('maps 422 refusals to their fields and checks the draft before sending', async () => {
    let calls = 0;
    mockSettings(
      { ...SETTINGS, defaultRetentionPolicyId: null },
      {
        ArchiveAdminController_update_v1: () => {
          calls += 1;
          return apiErrorJson(422, 'archive_scope_reference_invalid', 'bad reference', {
            extra: { path: 'settings.scope.domainIds[0]' },
          });
        },
      },
    );
    const { user } = renderWithProviders(<ArchiveSettingsPanel />, { role: 'organization_admin' });
    const form = await screen.findByRole('form', { name: 'Archive settings' });
    await user.click(
      within(form).getByRole('switch', { name: 'Archive mail of this organization' }),
    );
    await user.click(within(form).getByRole('button', { name: 'Save archive settings' }));
    expect(
      within(form).getAllByText(/Choose a default retention policy before enabling archiving/)
        .length,
    ).toBeGreaterThan(0);
    expect(calls).toBe(0);
    await user.click(
      within(form).getByRole('switch', { name: 'Archive mail of this organization' }),
    );
    await user.click(within(form).getByRole('radio', { name: 'Only the chosen parties' }));
    await user.click(await within(form).findByRole('checkbox', { name: 'corp.example.test' }));
    await user.click(within(form).getByRole('button', { name: 'Save archive settings' }));
    await waitFor(() => expect(calls).toBe(1));
    expect(
      await within(form).findAllByText(/no longer exists in your organization/),
    ).not.toHaveLength(0);
  });

  it('rotates the key with a reason', async () => {
    let rotateBody: unknown = null;
    mockSettings(SETTINGS, {
      ArchiveAdminController_rotate_v1: ({ body }) => {
        rotateBody = body;
        return okJson({ key: { ...KEYS.data[0]!, version: 2 }, previousVersion: 1 }, 201);
      },
    });
    const { user } = renderWithProviders(<ArchiveSettingsPanel />, { role: 'organization_admin' });
    await user.click(await screen.findByRole('button', { name: 'Rotate key' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'EXAMPLE yearly rotation');
    await user.click(within(dialog).getByRole('button', { name: 'Rotate key' }));
    await waitFor(() => expect(rotateBody).toEqual({ reason: 'EXAMPLE yearly rotation' }));
    expectRequestMatchesContract('ArchiveAdminController_rotate_v1', rotateBody);
  });
});

describe('/archive/retention (A11, A13, A14, A28)', () => {
  it('builds contract-valid policy bodies', () => {
    const body = policyBody({ ...policyDraftOf(POLICY_2), categories: ['quarantined'] });
    expect(body).toEqual({
      name: 'Outbound review',
      retentionDays: 365,
      onExpiry: 'review',
      priority: 10,
      criteria: { directions: ['outbound'], categories: ['quarantined'] },
    });
    expectRequestMatchesContract('ArchiveRetentionController_create_v1', body);
    expectRequestMatchesContract('ArchiveRetentionController_update_v1', {
      ...body,
      expectedRowVersion: 2,
    });
  });

  it('lists policies with the default marked; creating maps the plan limit refusal to the field', async () => {
    let created: unknown = null;
    mockApi({
      ArchiveRetentionController_list_v1: () =>
        okJson({ data: [POLICY, POLICY_2], nextCursor: null }),
      ArchiveAdminController_get_v1: () => okJson(SETTINGS),
      ArchiveRetentionController_create_v1: ({ body }) => {
        created = body;
        return apiErrorJson(422, 'archive_retention_exceeds_limit', 'too long', {
          extra: { limit: 2555 },
        });
      },
    });
    const { user, container } = renderWithProviders(<RetentionPage />, {
      role: 'organization_admin',
      route: '/archive/retention',
    });
    expect(await screen.findByText('Default seven years')).toBeInTheDocument();
    expect(screen.getByText('Default')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'New retention policy' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Name (required)'), 'EXAMPLE ten years');
    const days = within(dialog).getByLabelText('Keep for (days, required)');
    await user.clear(days);
    await user.type(days, '3650');
    await user.click(within(dialog).getByRole('button', { name: 'Create policy' }));
    expect(
      await within(dialog).findByText(/longer than your plan allows \(at most 2555 days\)/),
    ).toBeInTheDocument();
    expectRequestMatchesContract('ArchiveRetentionController_create_v1', created);
  });

  it('is read-only for a read-only user and hides manage-only tabs', async () => {
    mockApi({
      ArchiveRetentionController_list_v1: () => okJson({ data: [POLICY], nextCursor: null }),
      ArchiveAdminController_get_v1: () => okJson(SETTINGS),
      ArchiveAdminController_disposals_v1: () => okJson({ data: [], nextCursor: null }),
    });
    renderWithProviders(<RetentionPage />, { role: 'read_only_user', route: '/archive/retention' });
    expect(await screen.findByText('Default seven years')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'New retention policy' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Capture issues' })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Review queue' })).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Disposal log' })).toBeInTheDocument();
  });

  it('retries a failed capture with an Idempotency-Key', async () => {
    let key: string | null = null;
    const issue = {
      messageId: '01930000-0000-7000-8000-00000000ca01',
      receivedAt: '2026-11-16T08:00:00.000Z',
      status: 'failed' as const,
      code: 'S3ServiceException',
      attempts: 4,
      sources: { journal: true, policy: false },
      nextCheckAt: '2026-11-17T09:00:00.000Z',
      createdAt: '2026-11-16T08:00:00.000Z',
    };
    mockApi({
      ArchiveAdminController_captureIssues_v1: () => okJson({ data: [issue], nextCursor: null }),
      ArchiveAdminController_retry_v1: ({ request }) => {
        key = request.headers.get('idempotency-key');
        return okJson({
          messageId: issue.messageId,
          status: 'pending',
          nextCheckAt: '2026-11-17T08:00:00.000Z',
        });
      },
    });
    const { user } = renderWithProviders(<RetentionPage />, {
      role: 'organization_admin',
      route: '/archive/retention?tab=capture',
    });
    expect(await screen.findByText('S3ServiceException')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Actions for/ }));
    await user.click(await screen.findByRole('menuitem', { name: 'Retry capture' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Retry capture' }));
    await waitFor(() => expect(key).toBeTruthy());
  });

  it('refuses deleting the default policy (menu item disabled) and deletes another', async () => {
    let deleted = false;
    mockApi({
      ArchiveRetentionController_list_v1: () =>
        okJson({ data: [POLICY, POLICY_2], nextCursor: null }),
      ArchiveAdminController_get_v1: () =>
        okJson({ ...SETTINGS, defaultRetentionPolicyId: POLICY_ID }),
      ArchiveRetentionController_delete_v1: () => {
        deleted = true;
        return noContentResponse();
      },
    });
    const { user } = renderWithProviders(<RetentionPage />, {
      role: 'organization_admin',
      route: '/archive/retention',
    });
    await screen.findByText('Default seven years');
    const menus = screen.getAllByRole('button', { name: /Actions for/ });
    await user.click(menus[0]!);
    expect(await screen.findByRole('menuitem', { name: 'Delete' })).toHaveAttribute(
      'data-disabled',
    );
    await user.keyboard('{Escape}');
    await user.click(menus[1]!);
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete' }),
    );
    await waitFor(() => expect(deleted).toBe(true));
  });
});
