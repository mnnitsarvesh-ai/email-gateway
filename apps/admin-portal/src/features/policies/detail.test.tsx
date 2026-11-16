import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
  type SystemRoleKey,
} from '@/test';
import { PolicyComparePage } from './compare-page';
import { PolicyDetail } from './policy-detail';
import {
  ADMIN,
  DEFINITION_V2,
  DEPARTMENTS_PAGE,
  POLICY_ID,
  POLICY_SETTINGS,
  REAL_CATALOG,
  USERS_PAGE,
  draftVersion,
  policyDetail,
  validateResponse,
  versionDetail,
  versionRow,
} from './test-data';

type AuditRow = SuccessBody<'AuditLogsController_search_v1'>['data'][number];

function mockDetailReads(policy = policyDetail()) {
  mockApi({
    PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG),
    DepartmentsController_list_v1: () => okJson(DEPARTMENTS_PAGE),
    UsersController_list_v1: () => okJson(USERS_PAGE),
    PolicySettingsController_get_v1: () => okJson(POLICY_SETTINGS),
    PolicyManagementController_get_v1: () => okJson(policy),
    PolicyManagementController_getVersion_v1: ({ params }) =>
      okJson(
        params.versionNo === '3'
          ? draftVersion()
          : versionDetail({
              versionNo: Number(params.versionNo),
              active: params.versionNo === '2',
            }),
      ),
    PolicyManagementController_listVersions_v1: () =>
      okJson({ data: [versionRow(3), versionRow(2), versionRow(1)], nextCursor: null }),
  });
}

function renderDetail(role: SystemRoleKey = 'organization_admin', query = '') {
  return renderWithProviders(<PolicyDetail policyId={POLICY_ID} />, {
    role,
    route: `/policies/${POLICY_ID}${query}`,
  });
}

async function rowActions(user: ReturnType<typeof renderDetail>['user'], versionNo: number) {
  await user.click(await screen.findByRole('button', { name: `Actions for version ${versionNo}` }));
  const menu = await screen.findByRole('menu');
  return within(menu)
    .getAllByRole('menuitem')
    .map((item) => item.textContent ?? '');
}

describe('Policy detail (/policies/[policyId], design B9–B11)', () => {
  it('shows the header, status, the active version summary and the executions link; axe', async () => {
    mockDetailReads();
    const { container } = renderDetail();
    expect(
      await screen.findByRole('heading', { name: 'Confidential data', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByRole('switch', { name: 'Enabled' })).toBeChecked();
    expect(await screen.findByText('42')).toBeInTheDocument(); // the organization generation
    expect(
      await screen.findByLabelText('Conditions of rule quarantine-confidential'),
    ).toHaveTextContent('DLP data categories contain any of Confidential');
    expect(
      screen.getByRole('link', { name: 'Open the execution history of this policy' }),
    ).toHaveAttribute('href', `/policies?tab=executions&policyId=${POLICY_ID}`);
    expect(screen.getByRole('link', { name: 'Open v2 in the builder' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}/versions/2`,
    );
    await expectNoAxeViolations(container);
  });

  it('versions table: actions per permission set, author names, two selected rows open the comparison', async () => {
    mockDetailReads();
    const admin = renderDetail('organization_admin', '?tab=versions');
    expect(await rowActions(admin.user, 3)).toEqual([
      'Edit draft',
      'Publish…',
      'Compare with active',
      'Delete draft…',
    ]);
    await admin.user.keyboard('{Escape}');
    expect(await rowActions(admin.user, 1)).toEqual([
      'Open',
      'New draft from this version',
      'Roll back to v1…',
      'Compare with active',
    ]);
    await admin.user.keyboard('{Escape}');
    expect(screen.getAllByText('Dana Admin').length).toBeGreaterThan(0);
    await admin.user.click(screen.getByRole('checkbox', { name: 'Select version 3' }));
    await admin.user.click(screen.getByRole('checkbox', { name: 'Select version 1' }));
    expect(screen.getByRole('link', { name: 'Compare v1 and v3' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}/compare?from=1&to=3`,
    );
    admin.unmount();

    const analyst = renderDetail('security_analyst', '?tab=versions');
    expect(await rowActions(analyst.user, 3)).toEqual([
      'Edit draft',
      'Compare with active',
      'Delete draft…',
    ]);
    await analyst.user.keyboard('{Escape}');
    expect(await rowActions(analyst.user, 1)).toEqual([
      'Open',
      'New draft from this version',
      'Compare with active',
    ]);
    analyst.unmount();

    const reader = renderDetail('read_only_user', '?tab=versions');
    expect(await rowActions(reader.user, 3)).toEqual(['Open', 'Compare with active']);
    await reader.user.keyboard('{Escape}');
    for (const name of [/^Rename/, /^Delete/, /^New draft/]) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', { name: 'Audit' })).not.toBeInTheDocument();
  });

  it('publishes a draft with an Idempotency-Key that the retry reuses; shows the generation', async () => {
    mockDetailReads();
    const keys: Array<string | null> = [];
    const bodies: unknown[] = [];
    const validated: unknown[] = [];
    mockApi({
      PolicyToolsController_validate_v1: ({ body }) => {
        validated.push(body);
        return okJson(validateResponse());
      },
      PolicyManagementController_publish_v1: ({ request, body }) => {
        keys.push(request.headers.get('idempotency-key'));
        bodies.push(body);
        if (keys.length === 1) return apiErrorJson(503, 'service_unavailable', 'Try again');
        return okJson({
          version: draftVersion({ status: 'published', active: true, rowVersion: 6 }),
          policy: policyDetail({ activeVersionNo: 3 }),
          generation: '43',
        });
      },
    });
    const { user } = renderDetail('organization_admin', '?tab=versions');
    await rowActions(user, 3);
    await user.click(screen.getByRole('menuitem', { name: 'Publish…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Publish version 3' });
    expect(
      await within(dialog).findByText(/The server accepts this version \(2 rules\)/),
    ).toBeInTheDocument();
    expect(validated).toHaveLength(1);
    expect(within(dialog).getByRole('switch', { name: 'Activate now' })).toBeChecked();
    await user.click(within(dialog).getByRole('button', { name: 'Publish and activate' }));
    expect(await within(dialog).findByText('service_unavailable')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Retry' }));
    expect(await within(dialog).findByText(/generation is now/)).toBeInTheDocument();
    expect(within(dialog).getByText('43')).toBeInTheDocument();
    expect(keys).toHaveLength(2);
    expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys[1]).toBe(keys[0]);
    for (const body of bodies)
      expectRequestMatchesContract('PolicyManagementController_publish_v1', body);
    expect(bodies[0]).toEqual({ activate: true, expectedRowVersion: 5 });
  });

  it('rolls back to an older version: active and target numbers, diff counts, policy rowVersion, 409 reload', async () => {
    mockDetailReads();
    const calls: Array<{ key: string | null; body: unknown }> = [];
    mockApi({
      PolicyManagementController_getVersion_v1: ({ params }) =>
        okJson(
          params.versionNo === '1'
            ? versionDetail({
                versionNo: 1,
                active: false,
                definition: { ...DEFINITION_V2, rules: [] },
              })
            : versionDetail({ versionNo: 2 }),
        ),
      PolicyManagementController_activate_v1: ({ request, body }) => {
        calls.push({ key: request.headers.get('idempotency-key'), body });
        if (calls.length === 1) {
          return apiErrorJson(409, 'policy_conflict', 'Changed', {
            extra: { currentRowVersion: 5 },
          });
        }
        return okJson({
          version: versionDetail({ versionNo: 1, active: true }),
          policy: policyDetail({ activeVersionNo: 1, rowVersion: 6 }),
          generation: '44',
        });
      },
    });
    const { user } = renderDetail('organization_admin', '?tab=versions');
    await rowActions(user, 1);
    await user.click(screen.getByRole('menuitem', { name: 'Roll back to v1…' }));
    const dialog = await screen.findByRole('dialog', { name: 'Roll back to v1?' });
    expect(await within(dialog).findByText(/Active now:/)).toHaveTextContent(
      'Active now: v2. After this: v1.',
    );
    expect(
      await within(dialog).findByText(/0 rules added, 1 removed, 0 changed/),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Compare the versions' })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}/compare?from=2&to=1`,
    );
    await user.click(within(dialog).getByRole('button', { name: 'Roll back to v1' }));
    expect(
      await within(dialog).findByText(/The policy changed since this dialog opened/),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Reload the policy' }));
    await user.click(within(dialog).getByRole('button', { name: 'Roll back to v1' }));
    expect(await within(dialog).findByText(/generation is now/)).toBeInTheDocument();
    expect(calls).toHaveLength(2);
    expect(calls[0]?.body).toEqual({ expectedRowVersion: 4 });
    expect(calls[0]?.key).toBeTruthy();
    expect(calls[1]?.key).not.toBe(calls[0]?.key); // a new confirmation is a new intent
    expectRequestMatchesContract('PolicyManagementController_activate_v1', calls[1]?.body);
  });

  it('disables with a confirmation; deletes a draft and the policy (typed name) with expectedRowVersion', async () => {
    mockDetailReads();
    const seen: string[] = [];
    mockApi({
      PolicyManagementController_disable_v1: ({ body }) => {
        expectRequestMatchesContract('PolicyManagementController_disable_v1', body);
        seen.push(`disable ${JSON.stringify(body)}`);
        return okJson(policyDetail({ status: 'disabled', rowVersion: 5 }));
      },
      PolicyManagementController_deleteDraft_v1: ({ url, params }) => {
        seen.push(`delete v${params.versionNo} ${url.searchParams.get('expectedRowVersion')}`);
        return noContentResponse();
      },
      PolicyManagementController_remove_v1: ({ url }) => {
        seen.push(`remove ${url.searchParams.get('expectedRowVersion')}`);
        return noContentResponse();
      },
    });
    const { user } = renderDetail('organization_admin', '?tab=versions');
    await user.click(await screen.findByRole('switch', { name: 'Enabled' }));
    const confirm = await screen.findByRole('alertdialog', { name: 'Disable this policy?' });
    await user.click(within(confirm).getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(seen).toContain('disable {"expectedRowVersion":4}'));
    await rowActions(user, 3);
    await user.click(screen.getByRole('menuitem', { name: 'Delete draft…' }));
    const draft = await screen.findByRole('alertdialog', { name: 'Delete draft v3?' });
    await user.click(within(draft).getByRole('button', { name: 'Delete draft' }));
    await waitFor(() => expect(seen).toContain('delete v3 5'));
    await user.click(screen.getByRole('button', { name: 'Delete policy' }));
    const remove = await screen.findByRole('alertdialog', { name: 'Delete this policy?' });
    const submit = within(remove).getByRole('button', { name: 'Delete policy' });
    expect(submit).toBeDisabled();
    await user.type(within(remove).getByRole('textbox'), 'Confidential data');
    await user.click(submit);
    await waitFor(() => expect(seen).toContain('remove 4'));
    await waitFor(() => expect(currentTestUrl()).toBe('/policies?tab=email'));
  });

  it('renames with the policy rowVersion; a taken name is a field error', async () => {
    mockDetailReads();
    const bodies: unknown[] = [];
    mockApi({
      PolicyManagementController_update_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(409, 'policy_name_taken', 'Taken')
          : okJson(policyDetail({ name: 'Confidential data (EU)', rowVersion: 5 }));
      },
    });
    const { user } = renderDetail();
    await user.click(await screen.findByRole('button', { name: 'Rename' }));
    const dialog = await screen.findByRole('dialog', { name: 'Rename the policy' });
    expect(
      within(dialog).getByText(/Direction and priority belong to its versions/),
    ).toBeInTheDocument();
    const name = within(dialog).getByLabelText(/^Name/);
    await user.clear(name);
    await user.type(name, 'Inbound threats');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText(/has this name/)).toBeInTheDocument();
    await user.clear(name);
    await user.type(name, 'Confidential data (EU)');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(bodies).toHaveLength(2));
    expectRequestMatchesContract('PolicyManagementController_update_v1', bodies[1]);
    expect(bodies[1]).toEqual({
      name: 'Confidential data (EU)',
      description: 'Quarantine high-risk inbound mail',
      expectedRowVersion: 4,
    });
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'Rename the policy' })).not.toBeInTheDocument(),
    );
  });

  it('audit tab: reads both resource types for 90 days and merges them by time', async () => {
    mockDetailReads();
    const reads: URLSearchParams[] = [];
    const row = (
      id: string,
      action: string,
      resourceType: string,
      at: string,
      metadata: Record<string, unknown>,
    ): AuditRow => ({
      id,
      createdAt: at,
      actor: { type: 'user', id: ADMIN },
      action,
      resourceType,
      resourceId: POLICY_ID,
      correlationId: null,
      sourceIp: null,
      metadata,
    });
    mockApi({
      AuditLogsController_search_v1: ({ url }) => {
        reads.push(url.searchParams);
        return okJson(
          url.searchParams.get('resourceType') === 'email_policy'
            ? {
                data: [
                  row('3', 'policy.disabled', 'email_policy', '2026-11-14T09:00:00.000Z', {
                    generation: 44,
                  }),
                ],
                nextCursor: null,
              }
            : {
                data: [
                  row(
                    '4',
                    'policy.version_activated',
                    'policy_version',
                    '2026-11-15T09:00:00.000Z',
                    {
                      versionNo: 1,
                      previousVersionNo: 2,
                      generation: 43,
                    },
                  ),
                  row(
                    '2',
                    'policy.version_published',
                    'policy_version',
                    '2026-11-13T09:00:00.000Z',
                    { versionNo: 2 },
                  ),
                ],
                nextCursor: null,
              },
        );
      },
    });
    const { container } = renderDetail('organization_admin', '?tab=audit');
    const table = await screen.findByRole('table', { name: 'Audit trail of the policy' });
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4));
    expect(reads.map((q) => q.get('resourceType')).sort()).toEqual([
      'email_policy',
      'policy_version',
    ]);
    for (const q of reads) {
      expect(q.get('resourceId')).toBe(POLICY_ID);
      expect(Date.parse(q.get('to') ?? '') - Date.parse(q.get('from') ?? '')).toBe(90 * 86_400_000);
    }
    const actions = within(table)
      .getAllByRole('row')
      .slice(1)
      .map((r) => within(r).getAllByRole('cell')[1]?.textContent);
    expect(actions).toEqual([
      'Version activatedpolicy.version_activated',
      'Disabledpolicy.disabled',
      'Version publishedpolicy.version_published',
    ]);
    expect(within(table).getByText('Previous version')).toBeInTheDocument();
    expect(within(table).getAllByText('Dana Admin').length).toBe(3);
    await expectNoAxeViolations(container);
  });

  it('renders not-found for unknown and foreign ids', async () => {
    mockApi({
      PolicyManagementController_get_v1: () =>
        apiErrorJson(404, 'policy_not_found', 'Not found', { requestId: 'req-pol' }),
      PolicySettingsController_get_v1: () => okJson(POLICY_SETTINGS),
      DepartmentsController_list_v1: () => okJson(DEPARTMENTS_PAGE),
      UsersController_list_v1: () => okJson(USERS_PAGE),
    });
    renderWithProviders(<PolicyDetail policyId={POLICY_ID} />, { role: 'security_analyst' });
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});

describe('Compare versions (/policies/[policyId]/compare, design B10)', () => {
  it('defaults to the active and the newest version; the view is in the URL', async () => {
    mockDetailReads();
    const { user, container } = renderWithProviders(<PolicyComparePage policyId={POLICY_ID} />, {
      route: `/policies/${POLICY_ID}/compare`,
    });
    expect(
      await screen.findByText('From v2 to v3: 1 rule added, 0 removed, 1 changed.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'From' })).toHaveTextContent('v2');
    expect(screen.getByRole('combobox', { name: 'To' })).toHaveTextContent('v3');
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('tab', { name: 'Raw JSON' }));
    await waitFor(() => expect(currentTestUrl()).toContain('view=json'));
  });
});
