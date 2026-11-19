import { screen, waitFor, within } from '@testing-library/react';
import type userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  okJson,
  renderWithProviders,
  testRouter,
} from '@/test';
import { TEST_RESPONSE } from '../builder/test-support/responses';
import {
  DEPARTMENTS_PAGE,
  POLICY_ID,
  REAL_CATALOG,
  USERS_PAGE,
  draftVersion,
  policyDetail,
  validateResponse,
} from '../test-data';
import { NewPolicyPage } from './new-policy-page';

type User = ReturnType<typeof userEvent.setup>;

const INLINE_ID = '00000000-0000-7000-8000-000000000000';

function mockReads() {
  mockApi({
    PolicyToolsController_catalog_v1: () => okJson(REAL_CATALOG),
    DepartmentsController_list_v1: () => okJson(DEPARTMENTS_PAGE),
    UsersController_list_v1: () => okJson(USERS_PAGE),
    // The editor auto-validates 2 s after the last edit; a slow run can reach that point.
    PolicyToolsController_validate_v1: () => okJson(validateResponse()),
  });
}

/** Builds "DLP data categories contain any of Confidential → Quarantine" in the empty rule. */
async function buildConfidentialRule(user: User) {
  await user.click(await screen.findByRole('combobox', { name: 'Field Choose a field' }));
  await user.click(
    screen.getByRole('option', { name: (name) => name.startsWith('DLP data categories') }),
  );
  await user.click(screen.getByRole('checkbox', { name: 'Confidential' }));
  await user.click(screen.getByRole('button', { name: 'Add action' }));
  await user.click(
    within(await screen.findByRole('menu')).getByRole('menuitem', { name: 'Quarantine' }),
  );
}

const EXPECTED_DEFINITION = {
  dslVersion: 'policy-dsl/1',
  direction: 'any',
  priority: 100,
  rules: [
    {
      id: 'rule-1',
      priority: 0,
      when: { all: [{ field: 'dlp.categories', op: 'contains_any', value: ['confidential'] }] },
      actions: [{ type: 'QUARANTINE' }],
    },
  ],
};

describe('New policy (/policies/new, design B6)', () => {
  it('builds a policy, shows the live summary, saves draft version 1 and opens it', async () => {
    mockReads();
    const bodies: unknown[] = [];
    mockApi({
      PolicyManagementController_create_v1: ({ body }) => {
        bodies.push(body);
        return okJson(
          {
            policy: policyDetail({ status: 'draft', activeVersionNo: null, latestVersionNo: 1 }),
            version: draftVersion({ versionNo: 1, rowVersion: 1 }),
          },
          201,
        );
      },
    });
    const { user, container } = renderWithProviders(<NewPolicyPage />, {
      role: 'organization_admin',
      route: '/policies/new',
    });
    expect(
      await screen.findByRole('heading', { name: 'New policy', level: 1 }),
    ).toBeInTheDocument();
    await user.type(await screen.findByLabelText(/^Name\s*\(required\)/), 'Confidential outbound');
    await user.type(screen.getByLabelText('Change note'), 'First version');
    await buildConfidentialRule(user);
    const summary = screen.getByRole('complementary', { name: 'Readable summary of the policy' });
    expect(within(summary).getByLabelText('Conditions of rule rule-1')).toHaveTextContent(
      'DLP data categories contain any of Confidential',
    );
    expect(within(summary).getByLabelText('Actions of rule rule-1')).toHaveTextContent(
      'Quarantine',
    );
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expectRequestMatchesContract('PolicyManagementController_create_v1', bodies[0]);
    expect(bodies[0]).toEqual({
      name: 'Confidential outbound',
      definition: EXPECTED_DEFINITION,
      changeNote: 'First version',
    });
    await waitFor(() => expect(currentTestUrl()).toBe(`/policies/${POLICY_ID}/versions/1`));
  });

  it('409 policy_name_taken lands on the name; 409 policy_limit_reached is a form error with the limit', async () => {
    mockReads();
    let call = 0;
    mockApi({
      PolicyManagementController_create_v1: () => {
        call += 1;
        return call === 1
          ? apiErrorJson(409, 'policy_name_taken', 'Taken')
          : apiErrorJson(409, 'policy_limit_reached', 'Limit', { extra: { limit: 100 } });
      },
    });
    const { user } = renderWithProviders(<NewPolicyPage />, { route: '/policies/new' });
    await user.type(await screen.findByLabelText(/^Name\s*\(required\)/), 'Inbound threats');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(
      await screen.findByText(/Another policy of your organization \(possibly a deleted one\)/),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(/^Name\s*\(required\)/)).toHaveAttribute('aria-invalid', 'true');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText(/reached its limit of 100 policies/)).toBeInTheDocument();
    expect(testRouter.push).not.toHaveBeenCalled();
  });

  it('400 policy_definition_invalid violations are listed and shown on their nodes', async () => {
    mockReads();
    mockApi({
      PolicyManagementController_create_v1: () =>
        apiErrorJson(400, 'policy_definition_invalid', 'Invalid', {
          extra: {
            violations: [
              {
                path: 'rules[0].when.all[0].value',
                code: 'value_required',
                message: 'Choose at least one category',
              },
              { path: 'rules[0].actions', code: 'value_required', message: 'Add an action' },
            ],
          },
        }),
    });
    const { user } = renderWithProviders(<NewPolicyPage />, { route: '/policies/new' });
    await user.type(await screen.findByLabelText(/^Name\s*\(required\)/), 'Draft');
    await user.click(screen.getByRole('button', { name: 'Save draft' }));
    expect(await screen.findByText(/The server refused the definition/)).toBeInTheDocument();
    const list = screen.getByRole('heading', { name: 'The server reported 2 problems' });
    expect(list).toBeInTheDocument();
    const row = screen.getByRole('group', { name: /^Condition 1 of 1/ });
    expect(within(row).getByText('Choose at least one category')).toBeInTheDocument();
  });

  it('Validate checks the document on the server and lists its problems; unsaved work is guarded', async () => {
    mockReads();
    const validated: unknown[] = [];
    mockApi({
      PolicyToolsController_validate_v1: ({ body }) => {
        validated.push(body);
        return okJson(
          validateResponse({
            valid: false,
            violations: [
              { path: 'rules[0].actions', code: 'value_required', message: 'Add an action' },
            ],
            ruleCount: null,
            hasOverrideRules: null,
            references: null,
            definitionSha256: null,
          }),
        );
      },
    });
    const { user } = renderWithProviders(<NewPolicyPage />, { route: '/policies/new' });
    await user.click(await screen.findByRole('button', { name: 'Validate' }));
    await waitFor(() => expect(validated).toHaveLength(1));
    expectRequestMatchesContract('PolicyToolsController_validate_v1', validated[0]);
    expect(
      await screen.findByText('The server reported 1 problem with this document.'),
    ).toBeInTheDocument();
    // Dirty: Cancel asks before leaving.
    await user.type(screen.getByLabelText(/^Name\s*\(required\)/), 'x');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(
      await screen.findByRole('alertdialog', { name: 'Discard unsaved changes?' }),
    ).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Stay on this page' }));
    expect(testRouter.push).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await user.click(await screen.findByRole('button', { name: 'Discard and leave' }));
    await waitFor(() => expect(currentTestUrl()).toBe('/policies?tab=email'));
  });

  it('tests the unsaved policy inline ({ definition }) and shows the server result', async () => {
    mockReads();
    const tests: unknown[] = [];
    mockApi({
      PolicyToolsController_test_v1: ({ body }) => {
        tests.push(body);
        const ref = `${INLINE_ID}#1/rule-1`;
        return okJson({
          ...TEST_RESPONSE,
          result: {
            ...TEST_RESPONSE.result,
            trace: [
              {
                ref,
                result: 'matched',
                at: 'when',
                path: 'rules[0].when.all[0]',
                field: 'dlp.categories',
                op: 'contains_any',
              },
            ],
          },
        });
      },
    });
    const { user } = renderWithProviders(<NewPolicyPage />, { route: '/policies/new' });
    await buildConfidentialRule(user);
    await user.click(screen.getByRole('button', { name: 'Test' }));
    const panel = await screen.findByRole('dialog', { name: 'Test with synthetic facts' });
    expect(within(panel).getByRole('radio', { name: 'This new policy (unsaved)' })).toBeChecked();
    await user.click(within(panel).getByRole('combobox', { name: 'Start from an example' }));
    await user.click(await screen.findByRole('option', { name: 'Outbound confidential data' }));
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(tests).toHaveLength(1));
    expectRequestMatchesContract('PolicyToolsController_test_v1', tests[0]);
    expect((tests[0] as { target: unknown }).target).toEqual({ definition: EXPECTED_DEFINITION });
    expect(
      await within(panel).findByRole('heading', { name: 'Test result (evaluated by the server)' }),
    ).toBeInTheDocument();
    await user.click(
      within(panel).getByRole('button', { name: 'Show in editor: rules[0].when.all[0]' }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole('dialog', { name: 'Test with synthetic facts' }),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByRole('group', { name: /^Condition 1 of 1/ }).className).toContain('ring-2');
  });

  it('?testPreset=outbound_high_risk_account opens the test panel with the ATO example (step 8.4 D23)', async () => {
    mockReads();
    const tests: unknown[] = [];
    mockApi({
      PolicyToolsController_test_v1: ({ body }) => {
        tests.push(body);
        return okJson(TEST_RESPONSE);
      },
    });
    const { user } = renderWithProviders(<NewPolicyPage />, {
      route: '/policies/new?testPreset=outbound_high_risk_account',
    });
    const panel = await screen.findByRole('dialog', { name: 'Test with synthetic facts' });
    expect(
      within(panel).getByRole('combobox', { name: 'Start from an example' }),
    ).toHaveTextContent('Outbound from a high-risk account');
    expect(within(panel).getByRole('group', { name: 'Account takeover' })).toBeInTheDocument();
    await user.click(within(panel).getByRole('button', { name: 'Run test' }));
    await waitFor(() => expect(tests).toHaveLength(1));
    expectRequestMatchesContract('PolicyToolsController_test_v1', tests[0]);
    expect((tests[0] as { facts: { ato?: unknown } }).facts.ato).toEqual({
      riskScore: 65,
      riskLevel: 'high',
    });
  });

  it('an unknown ?testPreset is ignored (no panel opens)', async () => {
    mockReads();
    renderWithProviders(<NewPolicyPage />, { route: '/policies/new?testPreset=nope' });
    expect(
      await screen.findByRole('heading', { name: 'New policy', level: 1 }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('dialog', { name: 'Test with synthetic facts' }),
    ).not.toBeInTheDocument();
  });

  it('is forbidden without policy:manage', async () => {
    renderWithProviders(<NewPolicyPage />, { role: 'read_only_user', route: '/policies/new' });
    expect(await screen.findByText(/policy:manage/)).toBeInTheDocument();
  });
});
