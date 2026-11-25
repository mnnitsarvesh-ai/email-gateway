import type userEvent from '@testing-library/user-event';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SuccessBody } from '@/lib/api/types';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { TEST_RESPONSE } from '../builder/test-support/responses';
import {
  DEFINITION_V3,
  DEPARTMENTS_PAGE,
  POLICY_ID,
  REAL_CATALOG,
  USERS_PAGE,
  draftVersion,
  policyDetail,
  validateResponse,
  versionDetail,
  versionRow,
} from '../test-data';
import { PolicyVersionPage } from './version-page';

type Version = SuccessBody<'PolicyManagementController_getVersion_v1'>;

const ROWS = [versionRow(3), versionRow(2), versionRow(1)];

function mockReads(versions: Record<string, () => Version> = {}, policy = policyDetail()) {
  mockApi({
    PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG),
    DepartmentsController_list_v1: () => okJson(DEPARTMENTS_PAGE),
    UsersController_list_v1: () => okJson(USERS_PAGE),
    // The editor auto-validates 2 s after the last edit; a slow run can reach that point.
    PolicyToolsController_validate_v1: () => okJson(validateResponse()),
    PolicyManagementController_get_v1: () => okJson(policy),
    PolicyManagementController_getVersion_v1: ({ params }) => {
      const make = versions[params.versionNo ?? ''];
      if (make) return okJson(make());
      if (params.versionNo === '3') return okJson(draftVersion());
      if (params.versionNo === '2' || params.versionNo === '1') {
        return okJson(
          versionDetail({ versionNo: Number(params.versionNo), active: params.versionNo === '2' }),
        );
      }
      return apiErrorJson(404, 'policy_version_not_found', 'Not found');
    },
    PolicyManagementController_listVersions_v1: ({ url }) => {
      const status = url.searchParams.get('status');
      return okJson({ data: ROWS.filter((r) => !status || r.status === status), nextCursor: null });
    },
  });
}

const page = (versionNo: string, route = `/policies/${POLICY_ID}/versions/${versionNo}`) =>
  ({ ui: <PolicyVersionPage policyId={POLICY_ID} versionNo={versionNo} />, route }) as const;

async function setPriority(user: ReturnType<typeof userEvent.setup>, value: string) {
  const input = await screen.findByLabelText('Policy priority');
  await user.clear(input);
  await user.type(input, value);
}

describe('Policy version page (/policies/[id]/versions/[n], design B6–B9)', () => {
  const createObjectURL = vi.fn(() => 'blob:policy-definition');
  const revokeObjectURL = vi.fn();
  beforeEach(() => {
    Object.assign(URL, { createObjectURL, revokeObjectURL });
    // jsdom cannot navigate to the download; the file creation itself is asserted.
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
  });
  afterEach(() => {
    createObjectURL.mockClear();
  });

  it('edits a draft and saves it with expectedRowVersion; a conflict offers download and overwrite at the current row version', async () => {
    mockReads();
    const puts: Array<Record<string, unknown>> = [];
    mockApi({
      PolicyManagementController_updateDraft_v1: ({ body }) => {
        puts.push(body as Record<string, unknown>);
        if (puts.length === 1) {
          return apiErrorJson(409, 'policy_conflict', 'Changed', {
            extra: { currentRowVersion: 7 },
          });
        }
        return okJson(
          draftVersion({
            rowVersion: 8,
            definition: (body as { definition: unknown }).definition,
          }),
        );
      },
    });
    const { ui, route } = page('3');
    const { user, container } = renderWithProviders(ui, { route });
    expect(
      await screen.findByRole('heading', { name: 'Confidential data · v3', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText('Edit mode')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await setPriority(user, '20');
    expect(screen.getByText('Unsaved changes')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const dialog = await screen.findByRole('dialog', {
      name: 'The draft changed while you were editing',
    });
    expect(within(dialog).getByText(/row version 7/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Download my definition' }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    await user.click(within(dialog).getByRole('button', { name: 'Overwrite with mine' }));
    await waitFor(() => expect(puts).toHaveLength(2));
    for (const body of puts)
      expectRequestMatchesContract('PolicyManagementController_updateDraft_v1', body);
    expect(puts[0]).toMatchObject({
      expectedRowVersion: 5,
      definition: { ...DEFINITION_V3, priority: 20 },
    });
    expect(puts[1]).toMatchObject({
      expectedRowVersion: 7,
      definition: { ...DEFINITION_V3, priority: 20 },
    });
    await waitFor(() => expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument());
    expect(
      screen.queryByRole('dialog', { name: 'The draft changed while you were editing' }),
    ).not.toBeInTheDocument();
  });

  it('"Reload theirs" discards the local edits and loads the saved draft', async () => {
    let reads = 0;
    mockReads({
      '3': () => {
        reads += 1;
        return reads === 1
          ? draftVersion()
          : draftVersion({ rowVersion: 7, definition: { ...DEFINITION_V3, priority: 30 } });
      },
    });
    mockApi({
      PolicyManagementController_updateDraft_v1: () =>
        apiErrorJson(409, 'policy_conflict', 'Changed', { extra: { currentRowVersion: 7 } }),
    });
    const { ui, route } = page('3');
    const { user } = renderWithProviders(ui, { route });
    await setPriority(user, '20');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await user.click(await screen.findByRole('button', { name: 'Reload theirs' }));
    await waitFor(() => expect(screen.getByLabelText('Policy priority')).toHaveValue(30));
    expect(screen.queryByText('Unsaved changes')).not.toBeInTheDocument();
  });

  it('409 policy_version_immutable offers "Save as a new draft" with the local definition', async () => {
    mockReads();
    const created: unknown[] = [];
    mockApi({
      PolicyManagementController_updateDraft_v1: () =>
        apiErrorJson(409, 'policy_version_immutable', 'Published'),
      PolicyManagementController_createDraft_v1: ({ body }) => {
        created.push(body);
        return okJson(draftVersion({ versionNo: 4, rowVersion: 1 }), 201);
      },
    });
    const { ui, route } = page('3');
    const { user } = renderWithProviders(ui, { route });
    await setPriority(user, '25');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    const dialog = await screen.findByRole('dialog', { name: 'Version 3 was published meanwhile' });
    await user.click(within(dialog).getByRole('button', { name: 'Save as a new draft' }));
    await waitFor(() => expect(created).toHaveLength(1));
    expectRequestMatchesContract('PolicyManagementController_createDraft_v1', created[0]);
    expect(created[0]).toMatchObject({ definition: { ...DEFINITION_V3, priority: 25 } });
    await waitFor(() => expect(currentTestUrl()).toBe(`/policies/${POLICY_ID}/versions/4`));
  });

  it('save errors: 400 violations land on their nodes; 413 shows the request-size message', async () => {
    mockReads();
    let call = 0;
    mockApi({
      PolicyManagementController_updateDraft_v1: () => {
        call += 1;
        return call === 1
          ? apiErrorJson(400, 'policy_definition_invalid', 'Invalid', {
              extra: {
                violations: [
                  {
                    path: 'rules[0].when.all[1].value',
                    code: 'value_invalid',
                    message: 'Not a domain',
                  },
                ],
              },
            })
          : apiErrorJson(413, 'payload_too_large', 'Too large');
      },
    });
    const { ui, route } = page('3');
    const { user } = renderWithProviders(ui, { route });
    await setPriority(user, '11');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    // Wait for the server verdict first (the condition row exists before the save); under a
    // loaded parallel run the save round trip can exceed the default 1 s find timeout.
    expect(
      await screen.findByRole(
        'heading',
        { name: 'The server reported 1 problem' },
        { timeout: 10_000 },
      ),
    ).toBeInTheDocument();
    const row = screen.getByRole('group', { name: /^Condition 2 of 2/ });
    expect(within(row).getByText('Not a domain')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(
      await screen.findByText(
        /larger than the policy document limit; split it into several policies\. Document size: .* of 256\.0 KiB\./,
      ),
    ).toBeInTheDocument();
  });

  it('Validate shows the server verdict: problems on nodes, unknown directory references as warnings', async () => {
    mockReads();
    let call = 0;
    mockApi({
      PolicyToolsController_validate_v1: ({ body }) => {
        call += 1;
        expectRequestMatchesContract('PolicyToolsController_validate_v1', body);
        return okJson(
          call === 1
            ? validateResponse({
                referenceViolations: [
                  {
                    path: 'exceptions[0].value[0]',
                    code: 'department_unknown',
                    message: 'The department does not exist',
                  },
                ],
              })
            : validateResponse({
                valid: false,
                violations: [
                  {
                    path: 'rules[1].when.value',
                    code: 'value_invalid',
                    message: 'Must be a whole number',
                  },
                ],
                ruleCount: null,
                hasOverrideRules: null,
                references: null,
                definitionSha256: null,
              }),
        );
      },
    });
    const { ui, route } = page('3');
    const { user } = renderWithProviders(ui, { route });
    await user.click(await screen.findByRole('button', { name: 'Validate' }));
    expect(await screen.findByText('The server accepts this document.')).toBeInTheDocument();
    expect(screen.getByText('One directory reference does not exist (yet)')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Validate' }));
    expect(
      await screen.findByText('The server reported 1 problem with this document.'),
    ).toBeInTheDocument();
  });

  it('read-only users see the version in view mode: no inputs and no mutation controls', async () => {
    mockReads();
    const { ui, route } = page('2');
    const { container } = renderWithProviders(ui, { role: 'read_only_user', route });
    expect(
      await screen.findByRole('heading', { name: 'Confidential data · v2', level: 1 }),
    ).toBeInTheDocument();
    expect(screen.getByText('View mode')).toBeInTheDocument();
    const editor = container.querySelector('[data-builder="editor"]');
    expect(editor).not.toBeNull();
    expect(within(editor as HTMLElement).queryAllByRole('textbox')).toHaveLength(0);
    expect(within(editor as HTMLElement).queryAllByRole('combobox')).toHaveLength(0);
    for (const name of [
      /^Save/,
      /^Validate/,
      /^Test/,
      /^Dry run/,
      /^Publish/,
      /^Activate/,
      /^Roll back/,
      /^New draft/,
      /^Delete/,
    ]) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    }
    await expectNoAxeViolations(container);
  });

  it('security analysts edit, validate, test and dry-run drafts but cannot publish', async () => {
    mockReads();
    const { ui, route } = page('3');
    renderWithProviders(ui, { role: 'security_analyst', route });
    expect(await screen.findByRole('button', { name: 'Save' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Validate' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Test' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Dry run' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete draft' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Publish/ })).not.toBeInTheDocument();
  });

  it('an older published version offers "Roll back to v1", "New draft from this version" and the comparison', async () => {
    mockReads();
    const created: unknown[] = [];
    mockApi({
      PolicyManagementController_createDraft_v1: ({ body }) => {
        created.push(body);
        return okJson(draftVersion({ versionNo: 4, rowVersion: 1 }), 201);
      },
    });
    const { ui, route } = page('1');
    const { user } = renderWithProviders(ui, { route });
    expect(await screen.findByRole('button', { name: 'Roll back to v1' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Compare with active \(v2\)/ })).toHaveAttribute(
      'href',
      `/policies/${POLICY_ID}/compare?from=2&to=1`,
    );
    await user.click(screen.getByRole('button', { name: 'New draft from this version' }));
    await waitFor(() => expect(created).toEqual([{ basedOnVersionNo: 1 }]));
    expectRequestMatchesContract('PolicyManagementController_createDraft_v1', created[0]);
    await waitFor(() => expect(currentTestUrl()).toBe(`/policies/${POLICY_ID}/versions/4`));
  });

  it('a legacy definition is shown as JSON with the reason', async () => {
    mockReads({
      '1': () =>
        versionDetail({
          versionNo: 1,
          status: 'superseded',
          active: false,
          dslVersion: null,
          definition: { version: 1, rules: [{ match: 'risk >= 600' }] },
          validation: {
            valid: false,
            violations: [{ path: 'dslVersion', code: 'version_unsupported', message: 'Legacy' }],
          },
        }),
    });
    const { ui, route } = page('1');
    renderWithProviders(ui, { route });
    expect(await screen.findByText(/not a policy-dsl\/1 document/)).toBeInTheDocument();
    expect(screen.getByTestId('policy-definition')).toHaveTextContent('risk >= 600');
    expect(screen.queryByRole('button', { name: 'Roll back to v1' })).not.toBeInTheDocument();
  });

  it('another organization’s or an unknown policy is not found; malformed ids never reach the api', async () => {
    mockApi({
      PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG),
      PolicyManagementController_get_v1: () => apiErrorJson(404, 'policy_not_found', 'Not found'),
      PolicyManagementController_getVersion_v1: () =>
        apiErrorJson(404, 'policy_not_found', 'Not found'),
    });
    const { ui, route } = page('3');
    const { unmount } = renderWithProviders(ui, { route });
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
    unmount();
    renderWithProviders(<PolicyVersionPage policyId="not-a-uuid" versionNo="x" />);
    expect(await screen.findByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });

  it('?highlight= outlines the node; Save and test saves the edits first and tests the saved draft', async () => {
    mockReads();
    const order: string[] = [];
    const tests: unknown[] = [];
    mockApi({
      PolicyManagementController_updateDraft_v1: ({ body }) => {
        order.push('save');
        return okJson(
          draftVersion({ rowVersion: 6, definition: (body as { definition: unknown }).definition }),
        );
      },
      PolicyToolsController_test_v1: ({ body }) => {
        order.push('test');
        tests.push(body);
        return okJson({ ...TEST_RESPONSE });
      },
    });
    const { ui } = page('3');
    const { user } = renderWithProviders(ui, {
      route: `/policies/${POLICY_ID}/versions/3?highlight=rules[0].when.all[1]`,
    });
    const row = await screen.findByRole('group', { name: /^Condition 2 of 2/ });
    expect(row.className).toContain('ring-2');
    await setPriority(user, '12');
    await user.click(screen.getByRole('button', { name: 'Test' }));
    await waitFor(() => expect(currentTestUrl()).toContain('panel=test'));
    const panel = await screen.findByRole('dialog', { name: 'Test with synthetic facts' });
    expect(within(panel).getByRole('radio', { name: 'This draft' })).toBeChecked();
    await user.click(within(panel).getByRole('button', { name: 'Save and test' }));
    await waitFor(() => expect(order).toEqual(['save', 'test']));
    expectRequestMatchesContract('PolicyToolsController_test_v1', tests[0]);
    expect((tests[0] as { target: unknown }).target).toEqual({ policyId: POLICY_ID, versionNo: 3 });
    // Trace rows of this version get "Show in editor"; other policies' rows do not.
    expect(
      await within(panel).findByRole('button', { name: 'Show in editor: rules[0].when.all[0]' }),
    ).toBeInTheDocument();
    expect(
      within(panel).queryByRole('button', { name: 'Show in editor: rules[0].when' }),
    ).not.toBeInTheDocument();
    await user.click(
      within(panel).getByRole('button', { name: 'Show in editor: rules[0].when.all[0]' }),
    );
    await waitFor(() =>
      expect(currentTestUrl()).toContain('highlight=rules%5B0%5D.when.all%5B0%5D'),
    );
    expect(currentTestUrl()).not.toContain('panel=');
  });
});
