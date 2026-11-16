import { fireEvent, screen, waitFor, within } from '@testing-library/react';
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
import { SENDER_WARNING } from './dlp-exceptions';
import {
  EXCEPTION_ID,
  POLICY_ID,
  RULE_ID,
  dayAhead,
  dlpException,
  dlpPolicy,
  dlpPolicyDetail,
  page,
} from './test-data';

const ROUTE = '/policies?tab=dlp&section=exceptions';

describe('DLP exceptions (WP5)', () => {
  it('adds an exception for one rule with filters; 400 on the expiry and 409 duplicate are on their fields; axe', async () => {
    const bodies: unknown[] = [];
    const requested: string[] = [];
    mockApi({
      DlpExceptionsController_list_v1: () => okJson(page([dlpException()])),
      DlpPoliciesController_list_v1: ({ url }) => {
        requested.push(`policies:${url.searchParams.get('limit')}`);
        return okJson(page([dlpPolicy()]));
      },
      DlpPoliciesController_get_v1: ({ params }) => {
        requested.push(`detail:${params.id}`);
        return okJson(dlpPolicyDetail());
      },
      DlpExceptionsController_create_v1: ({ body }) => {
        bodies.push(body);
        if (bodies.length === 1) {
          return apiErrorJson(400, 'validation_failed', [
            'expiresAt: Must be at most 365 days ahead',
          ]);
        }
        if (bodies.length === 2) {
          return apiErrorJson(409, 'dlp_exception_exists', 'Exists', {
            extra: { id: EXCEPTION_ID },
          });
        }
        return okJson(dlpException({ id: '01933c3a-1b2c-7d4e-8f00-0000000d0402' }), 201);
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    expect(await screen.findByText('auditor.example.test')).toBeInTheDocument();
    expect(requested).toEqual([]);
    await user.click(screen.getByRole('button', { name: 'New exception' }));
    const sheet = await screen.findByRole('dialog', { name: 'New DLP exception' });
    await expectNoAxeViolations(document.body);

    await user.selectOptions(within(sheet).getByLabelText(/^Scope/), 'sender_address');
    expect(within(sheet).getByText(SENDER_WARNING)).toBeInTheDocument();
    await user.type(within(sheet).getByLabelText(/^Address/), 'reports@alpha.example.test');
    await user.selectOptions(within(sheet).getByLabelText(/^Applies to/), 'rule');
    const policySelect = within(sheet).getByLabelText(/^Policy/);
    await within(policySelect).findByRole('option', { name: 'Payment cards outbound' });
    await user.selectOptions(policySelect, POLICY_ID);
    const ruleSelect = within(sheet).getByLabelText(/^Rule/);
    await within(ruleSelect).findByRole('option', { name: 'Block card numbers' });
    await user.selectOptions(ruleSelect, RULE_ID);
    await user.click(within(sheet).getByRole('checkbox', { name: 'Payment cards' }));
    await user.click(within(sheet).getByRole('checkbox', { name: 'Payment card number PC1' }));
    await user.type(within(sheet).getByLabelText(/^Reason/), 'Monthly card reconciliation');
    const expiry = dayAhead(400);
    fireEvent.change(within(sheet).getByLabelText(/^Expires/), { target: { value: expiry } });
    await user.click(within(sheet).getByRole('button', { name: 'Add exception' }));

    expect(await within(sheet).findByText('Must be at most 365 days ahead')).toBeInTheDocument();
    expect(within(sheet).getByLabelText(/^Expires/)).toHaveAttribute('aria-invalid', 'true');
    expect(requested).toEqual(['policies:100', `detail:${POLICY_ID}`]);
    expect(bodies[0]).toEqual({
      scope: 'sender_address',
      value: 'reports@alpha.example.test',
      ruleId: RULE_ID,
      filters: { detectors: ['PC1'], categories: ['payment_card'] },
      reason: 'Monthly card reconciliation',
      expiresAt: `${expiry}T23:59:59.000Z`,
      enabled: true,
    });
    expectRequestMatchesContract('DlpExceptionsController_create_v1', bodies[0]);

    fireEvent.change(within(sheet).getByLabelText(/^Expires/), {
      target: { value: dayAhead(90) },
    });
    await user.click(within(sheet).getByRole('button', { name: 'Add exception' }));
    expect(
      await within(sheet).findByText(/An exception for this scope, value and target exists/),
    ).toBeInTheDocument();

    await user.click(within(sheet).getByRole('button', { name: 'Add exception' }));
    expect(await screen.findByText('DLP exception added.')).toBeInTheDocument();
    expect(bodies).toHaveLength(3);
  });

  it('checks the value shape by scope and the expiry in the browser', async () => {
    let calls = 0;
    mockApi({
      DlpExceptionsController_list_v1: () => okJson(page([])),
      DlpExceptionsController_create_v1: () => ((calls += 1), okJson(dlpException(), 201)),
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'organization_admin', route: ROUTE });
    await screen.findByText('No exceptions');
    await user.click(screen.getByRole('button', { name: 'New exception' }));
    const sheet = await screen.findByRole('dialog', { name: 'New DLP exception' });
    await user.type(within(sheet).getByLabelText(/^Domain/), 'someone@example.test');
    fireEvent.change(within(sheet).getByLabelText(/^Expires/), { target: { value: '2020-01-01' } });
    await user.click(within(sheet).getByRole('button', { name: 'Add exception' }));
    expect(
      await within(sheet).findByText('Enter a domain such as example.com'),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('Enter a reason')).toBeInTheDocument();
    expect(within(sheet).getByText('Choose a date in the future')).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it('edits reason, state and filters (removed → null) with the version; an unchanged past expiry is not sent', async () => {
    const bodies: unknown[] = [];
    mockApi({
      DlpExceptionsController_list_v1: () =>
        okJson(page([dlpException({ expiresAt: '2026-01-01T00:00:00.000Z', expired: true })])),
      DlpExceptionsController_update_v1: ({ body, params }) => {
        bodies.push(body);
        expect(params.id).toBe(EXCEPTION_ID);
        return okJson(dlpException({ version: 6 }));
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(
      await screen.findByRole('button', {
        name: 'Actions for Recipient domain auditor.example.test',
      }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const sheet = await screen.findByRole('dialog', { name: 'Edit DLP exception' });
    await expectNoAxeViolations(document.body);
    expect(within(sheet).getByText('auditor.example.test')).toBeInTheDocument();
    await user.click(within(sheet).getByRole('checkbox', { name: 'Payment cards' }));
    await user.clear(within(sheet).getByLabelText(/^Reason/));
    await user.type(within(sheet).getByLabelText(/^Reason/), 'Quarterly audit');
    await user.click(within(sheet).getByRole('switch', { name: 'Enabled' }));
    await user.click(within(sheet).getByRole('button', { name: 'Save exception' }));
    expect(await screen.findByText('DLP exception saved.')).toBeInTheDocument();
    expect(bodies[0]).toEqual({
      version: 5,
      reason: 'Quarterly audit',
      enabled: false,
      filters: null,
    });
    expectRequestMatchesContract('DlpExceptionsController_update_v1', bodies[0]);
  });

  it('removes an exception with a confirm and the version shown; after a version conflict the next confirm uses the current version', async () => {
    const versions: (string | null)[] = [];
    let current = dlpException();
    mockApi({
      DlpExceptionsController_list_v1: () => okJson(page([current])),
      DlpExceptionsController_remove_v1: ({ url }) => {
        versions.push(url.searchParams.get('version'));
        if (versions.length === 1) {
          current = dlpException({ version: 6, reason: 'Changed elsewhere' });
          return apiErrorJson(409, 'version_conflict', 'The resource changed', {
            extra: { currentVersion: 6 },
          });
        }
        return noContentResponse();
      },
    });
    const { user } = renderWithProviders(<DlpTab />, { role: 'security_analyst', route: ROUTE });
    await user.click(
      await screen.findByRole('button', {
        name: 'Actions for Recipient domain auditor.example.test',
      }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog', { name: 'Remove this DLP exception?' });
    await user.click(within(confirm).getByRole('button', { name: 'Remove exception' }));
    expect(await within(confirm).findByText(/now version 6/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Remove exception' }));
    expect(await screen.findByText('DLP exception removed.')).toBeInTheDocument();
    await waitFor(() => expect(versions).toEqual(['5', '6']));
  });
});
