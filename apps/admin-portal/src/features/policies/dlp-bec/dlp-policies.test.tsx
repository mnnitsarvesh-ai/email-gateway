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
import { DlpTab } from '../dlp-bec';
import { SELECTOR_REQUIRED } from './dlp-schemas';
import {
  DICTIONARY_ID,
  PATTERN_ID,
  POLICY_ID,
  dlpDictionaryRow,
  dlpPattern,
  dlpPolicy,
  dlpPolicyDetail,
  dlpRule,
  page,
} from './test-data';

const ROUTE = '/policies?tab=dlp';

describe('DLP policies (WP5)', () => {
  it('creates a policy: server 400 on the name, 409 name taken, then 201 with a contract body; axe', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([dlpPolicy()])),
      DlpPoliciesController_create_v1: ({ body }) => {
        bodies.push(body);
        if (bodies.length === 1) {
          return apiErrorJson(
            400,
            'validation_failed',
            ['name: Must not contain control characters'],
            {
              requestId: 'req-dlp-400',
            },
          );
        }
        if (bodies.length === 2) {
          return apiErrorJson(409, 'dlp_policy_exists', 'A DLP policy with this name exists', {
            extra: { id: POLICY_ID },
          });
        }
        return okJson(dlpPolicyDetail({ name: 'Bank details', rules: [] }), 201);
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await screen.findByText('Payment cards outbound');
    await user.click(screen.getByRole('button', { name: 'New DLP policy' }));
    const sheet = await screen.findByRole('dialog', { name: 'New DLP policy' });
    // Responsive (design §2 B14): full width on phones, a side panel from 640 px.
    expect(sheet).toHaveClass('w-full', 'sm:max-w-xl');
    await expectNoAxeViolations(document.body);

    await user.type(within(sheet).getByLabelText(/^Name/), 'Bank details');
    await user.selectOptions(within(sheet).getByLabelText(/^Mode/), 'monitor');
    await user.clear(within(sheet).getByLabelText(/^Priority/));
    await user.type(within(sheet).getByLabelText(/^Priority/), '20');
    await user.click(within(sheet).getByRole('checkbox', { name: 'Internal' }));
    await user.click(within(sheet).getByRole('button', { name: 'Create DLP policy' }));

    expect(
      await within(sheet).findByText('Must not contain control characters'),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('req-dlp-400')).toBeInTheDocument();
    expect(within(sheet).getByText('validation_failed')).toBeInTheDocument();
    expect(within(sheet).getByLabelText(/^Name/)).toHaveAttribute('aria-invalid', 'true');

    await user.click(within(sheet).getByRole('button', { name: 'Create DLP policy' }));
    expect(
      await within(sheet).findByText('A DLP policy with this name exists. Choose another name.'),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('dlp_policy_exists')).toBeInTheDocument();

    await user.click(within(sheet).getByRole('button', { name: 'Create DLP policy' }));
    expect(await screen.findByText('DLP policy created.')).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole('dialog', { name: 'New DLP policy' })).not.toBeInTheDocument(),
    );
    expect(bodies[2]).toEqual({
      name: 'Bank details',
      enabled: true,
      mode: 'monitor',
      priority: 20,
      directions: ['outbound'],
    });
    expectRequestMatchesContract('DlpPoliciesController_create_v1', bodies[2]);
  });

  it('validates in the browser before sending (required name, priority range, a direction)', async () => {
    let calls = 0;
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([])),
      DlpPoliciesController_create_v1: () => ((calls += 1), okJson(dlpPolicyDetail(), 201)),
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    await screen.findByText('No DLP policies');
    await user.click(screen.getByRole('button', { name: 'New DLP policy' }));
    const sheet = await screen.findByRole('dialog', { name: 'New DLP policy' });
    await user.clear(within(sheet).getByLabelText(/^Priority/));
    await user.type(within(sheet).getByLabelText(/^Priority/), '5000');
    await user.click(within(sheet).getByRole('checkbox', { name: 'Outbound' }));
    await user.click(within(sheet).getByRole('checkbox', { name: 'Internal' }));
    await user.click(within(sheet).getByRole('button', { name: 'Create DLP policy' }));
    expect(await within(sheet).findByText('Enter a name')).toBeInTheDocument();
    expect(within(sheet).getByText('Enter a number from 0 to 1000')).toBeInTheDocument();
    expect(within(sheet).getByText('Choose at least one direction')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('edits a policy (enabled state, priority) with its version; 409 version_conflict loads the current version', async () => {
    const bodies: unknown[] = [];
    let current = dlpPolicy();
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([current])),
      DlpPoliciesController_update_v1: ({ body, params }) => {
        bodies.push(body);
        expect(params.id).toBe(POLICY_ID);
        if (bodies.length === 1) {
          current = dlpPolicy({ version: 4, description: 'Changed elsewhere' });
          return apiErrorJson(409, 'version_conflict', 'The resource changed', {
            extra: { currentVersion: 4 },
          });
        }
        return okJson({ ...dlpPolicyDetail(), enabled: false, version: 5 });
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(
      await screen.findByRole('button', { name: 'Actions for Payment cards outbound' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    let sheet = await screen.findByRole('dialog', { name: 'Edit Payment cards outbound' });
    await user.click(within(sheet).getByRole('switch', { name: 'Enabled' }));
    await user.clear(within(sheet).getByLabelText(/^Priority/));
    await user.type(within(sheet).getByLabelText(/^Priority/), '15');
    await user.click(within(sheet).getByRole('button', { name: 'Save DLP policy' }));
    expect(await within(sheet).findByText(/now version 4/)).toBeInTheDocument();
    expect(bodies[0]).toEqual({ version: 3, enabled: false, priority: 15 });
    expectRequestMatchesContract('DlpPoliciesController_update_v1', bodies[0]);

    await user.click(within(sheet).getByRole('button', { name: 'Load the current version' }));
    sheet = await screen.findByRole('dialog', { name: 'Edit Payment cards outbound' });
    await waitFor(() =>
      expect(within(sheet).getByLabelText('Description (optional)')).toHaveValue(
        'Changed elsewhere',
      ),
    );
    await user.click(within(sheet).getByRole('switch', { name: 'Enabled' }));
    await user.click(within(sheet).getByRole('button', { name: 'Save DLP policy' }));
    expect(await screen.findByText('DLP policy saved.')).toBeInTheDocument();
    expect(bodies[1]).toEqual({ version: 4, enabled: false });
  });

  it('a background refetch never replaces the policy being edited (no silent loss, the save keeps its version)', async () => {
    let current = dlpPolicy();
    let lists = 0;
    const bodies: unknown[] = [];
    mockApi({
      DlpPoliciesController_list_v1: () => ((lists += 1), okJson(page([current]))),
      DlpPoliciesController_update_v1: ({ body }) => (
        bodies.push(body),
        apiErrorJson(409, 'version_conflict', 'The resource changed', {
          extra: { currentVersion: 4 },
        })
      ),
    });
    const { user, queryClient } = renderWithProviders(<DlpTab />, {
      role: 'security_analyst',
      route: ROUTE,
    });
    await user.click(
      await screen.findByRole('button', { name: 'Actions for Payment cards outbound' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const sheet = await screen.findByRole('dialog', { name: 'Edit Payment cards outbound' });
    await user.type(within(sheet).getByLabelText('Description (optional)'), 'Mine');
    current = dlpPolicy({ version: 4, description: 'Theirs' });
    await queryClient.invalidateQueries({ queryKey: ['DlpPoliciesController_list_v1'] });
    await waitFor(() => expect(lists).toBe(2));
    expect(within(sheet).getByLabelText('Description (optional)')).toHaveValue('Mine');
    await user.click(within(sheet).getByRole('button', { name: 'Save DLP policy' }));
    expect(await within(sheet).findByText(/now version 4/)).toBeInTheDocument();
    expect(bodies).toEqual([{ version: 3, description: 'Mine' }]);
  });

  it('narrowing directions under existing rules shows dlp_directions_invalid on the directions', async () => {
    mockApi({
      DlpPoliciesController_list_v1: () =>
        okJson(page([dlpPolicy({ directions: ['outbound', 'internal'] })])),
      DlpPoliciesController_update_v1: () =>
        apiErrorJson(400, 'dlp_directions_invalid', 'Rule directions must be a subset', {
          extra: { references: 2 },
        }),
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    await user.click(
      await screen.findByRole('button', { name: 'Actions for Payment cards outbound' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const sheet = await screen.findByRole('dialog', { name: 'Edit Payment cards outbound' });
    await user.click(within(sheet).getByRole('checkbox', { name: 'Internal' }));
    await user.click(within(sheet).getByRole('button', { name: 'Save DLP policy' }));
    expect(
      await within(sheet).findByText(
        '2 rule(s) of this policy use a direction you removed. Change those rules first.',
      ),
    ).toBeInTheDocument();
  });

  it('deletes a policy after typing its name, with the version; 409 dlp_policy_in_use is explained', async () => {
    const versions: (string | null)[] = [];
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([dlpPolicy()])),
      DlpPoliciesController_remove_v1: ({ url }) => {
        versions.push(url.searchParams.get('version'));
        return versions.length === 1
          ? apiErrorJson(409, 'dlp_policy_in_use', 'Exceptions target this policy', {
              extra: { references: 2 },
            })
          : noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(
      await screen.findByRole('button', { name: 'Actions for Payment cards outbound' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    await expectNoAxeViolations(document.body);
    const button = within(confirm).getByRole('button', { name: 'Delete DLP policy' });
    expect(button).toBeDisabled();
    await user.type(within(confirm).getByRole('textbox'), 'Payment cards outbound');
    await user.click(button);
    expect(
      await within(confirm).findByText(
        'Exceptions target this policy or one of its rules (2). Change those first, then delete again.',
      ),
    ).toBeInTheDocument();
    expect(within(confirm).getByText('dlp_policy_in_use')).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Delete DLP policy' }));
    expect(await screen.findByText('DLP policy deleted.')).toBeInTheDocument();
    expect(versions).toEqual(['3', '3']);
  });
});

describe('DLP rules of a policy (WP5)', () => {
  function mockRules(extra: Parameters<typeof mockApi>[0] = {}) {
    const seen: string[] = [];
    mockApi({
      DlpPoliciesController_list_v1: () => okJson(page([dlpPolicy()])),
      DlpPoliciesController_get_v1: ({ params }) => {
        seen.push(`detail:${params.id}`);
        return okJson(dlpPolicyDetail());
      },
      DlpPatternsController_list_v1: ({ url }) => {
        seen.push(`patterns:${url.searchParams.get('limit')}`);
        return okJson(page([dlpPattern()]));
      },
      DlpDictionariesController_list_v1: ({ url }) => {
        seen.push(`dictionaries:${url.searchParams.get('limit')}`);
        return okJson(page([dlpDictionaryRow()]));
      },
      ...extra,
    });
    return seen;
  }

  async function openRules(user: ReturnType<typeof renderWithProviders>['user']) {
    await user.click(
      await screen.findByRole('button', { name: 'Actions for Payment cards outbound' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Rules' }));
    return screen.findByRole('dialog', { name: 'Rules of Payment cards outbound' });
  }

  it('adds a rule: selectors required in the browser, server 400 on a sender address line, then 201; axe', async () => {
    const bodies: unknown[] = [];
    const seen = mockRules({
      DlpPoliciesController_createRule_v1: ({ body, params }) => {
        bodies.push(body);
        expect(params.id).toBe(POLICY_ID);
        return bodies.length === 1
          ? apiErrorJson(400, 'validation_failed', [
              'conditions.sender.addresses.1: Expected a lower-case address',
            ])
          : okJson(dlpRule({ name: 'Personal data', action: 'quarantine' }), 201);
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const rules = await openRules(user);
    expect(await within(rules).findByText('Block card numbers')).toBeInTheDocument();
    expect(seen).toEqual([`detail:${POLICY_ID}`]);
    expect(rules).toHaveClass('w-full', 'sm:max-w-3xl');
    await expectNoAxeViolations(document.body);

    await user.click(within(rules).getByRole('button', { name: 'Add rule' }));
    const editor = await screen.findByRole('dialog', {
      name: 'New rule in Payment cards outbound',
    });
    expect(
      await within(editor).findByRole('checkbox', { name: 'Employee ID' }),
    ).toBeInTheDocument();
    expect(seen).toEqual(expect.arrayContaining(['patterns:100', 'dictionaries:100']));
    await expectNoAxeViolations(document.body);

    await user.type(within(editor).getByLabelText(/^Name/), 'Personal data');
    await user.click(within(editor).getByRole('button', { name: 'Add rule' }));
    expect(await within(editor).findByText(SELECTOR_REQUIRED)).toBeInTheDocument();
    expect(bodies).toHaveLength(0);

    await user.selectOptions(within(editor).getByLabelText(/^Action/), 'quarantine');
    await user.click(within(editor).getByRole('checkbox', { name: 'Personal information' }));
    await user.click(within(editor).getByRole('checkbox', { name: 'Employee ID' }));
    await user.click(within(editor).getByRole('checkbox', { name: 'Project names' }));
    await user.type(
      within(editor).getByLabelText('Sender addresses'),
      'First@Alpha.example.test{Enter}{Enter}second@alpha.example.test',
    );
    await user.click(
      within(editor).getByRole('checkbox', { name: /Only findings in attachments/ }),
    );
    await user.click(within(editor).getByRole('button', { name: 'Add rule' }));
    expect(
      await within(editor).findByText('Line 3: Expected a lower-case address'),
    ).toBeInTheDocument();
    expect(within(editor).getByLabelText('Sender addresses')).toHaveAttribute(
      'aria-invalid',
      'true',
    );

    await user.click(within(editor).getByRole('button', { name: 'Add rule' }));
    expect(await screen.findByText('DLP rule added.')).toBeInTheDocument();
    expect(bodies[1]).toEqual({
      name: 'Personal data',
      enabled: true,
      priority: 100,
      conditions: {
        selectors: {
          categories: ['personal_info'],
          customPatternIds: [PATTERN_ID],
          dictionaryIds: [DICTIONARY_ID],
        },
        sender: { addresses: ['first@alpha.example.test', 'second@alpha.example.test'] },
        attachmentsOnly: true,
      },
      action: 'quarantine',
    });
    expectRequestMatchesContract('DlpPoliciesController_createRule_v1', bodies[1]);
  });

  it('edits a rule with its version and only the changed fields; a deleted pattern reference is explained', async () => {
    const bodies: unknown[] = [];
    mockRules({
      DlpPoliciesController_updateRule_v1: ({ body, params }) => {
        bodies.push(body);
        expect(params.ruleId).toBe(dlpRule().id);
        return bodies.length === 1
          ? apiErrorJson(
              400,
              'dlp_reference_invalid',
              'A referenced id is not the organization’s',
              {
                extra: { field: 'conditions.selectors.customPatternIds', index: 0 },
              },
            )
          : okJson(dlpRule({ action: 'quarantine', version: 3 }));
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    const rules = await openRules(user);
    await user.click(
      await within(rules).findByRole('button', { name: 'Actions for Block card numbers' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const editor = await screen.findByRole('dialog', { name: 'Edit rule Block card numbers' });
    await within(editor).findByRole('checkbox', { name: 'Employee ID' });
    await user.selectOptions(within(editor).getByLabelText(/^Action/), 'quarantine');
    await user.click(within(editor).getByRole('button', { name: 'Save rule' }));
    expect(
      await within(editor).findByText(/A selected custom pattern is not one of your organization/),
    ).toBeInTheDocument();
    expect(bodies[0]).toEqual({ version: 2, action: 'quarantine' });
    expectRequestMatchesContract('DlpPoliciesController_updateRule_v1', bodies[0]);
    await user.click(within(editor).getByRole('button', { name: 'Save rule' }));
    expect(await screen.findByText('DLP rule saved.')).toBeInTheDocument();
  });

  it('deletes a rule with a confirm; 409 dlp_rule_in_use is explained', async () => {
    const calls: string[] = [];
    mockRules({
      DlpPoliciesController_removeRule_v1: ({ url, params }) => {
        calls.push(`${params.ruleId}@${url.searchParams.get('version')}`);
        return calls.length === 1
          ? apiErrorJson(409, 'dlp_rule_in_use', 'Exceptions target this rule', {
              extra: { references: 1 },
            })
          : noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    const rules = await openRules(user);
    await user.click(
      await within(rules).findByRole('button', { name: 'Actions for Block card numbers' }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Delete rule' }));
    expect(
      await within(confirm).findByText(
        'Exceptions target this rule (1). Change those first, then delete again.',
      ),
    ).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Delete rule' }));
    expect(await screen.findByText('DLP rule deleted.')).toBeInTheDocument();
    expect(calls).toEqual([`${dlpRule().id}@2`, `${dlpRule().id}@2`]);
  });

  it('a dlp:read role sees the rules but no editing control', async () => {
    mockRules();
    const { user } = renderWithProviders(<DlpTab />, { role: 'compliance_auditor', route: ROUTE });
    const rules = await openRules(user);
    expect(await within(rules).findByText('Block card numbers')).toBeInTheDocument();
    expect(within(rules).queryByRole('button', { name: 'Add rule' })).not.toBeInTheDocument();
    expect(
      within(rules).queryByRole('button', { name: 'Actions for Block card numbers' }),
    ).not.toBeInTheDocument();
  });
});
