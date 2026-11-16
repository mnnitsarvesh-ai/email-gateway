import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { onSessionEvent, type SessionEvent } from '@/lib/session/events';
import {
  apiErrorJson,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  okJson,
  renderWithProviders,
} from '@/test';
import { DlpTab } from '../dlp-bec';
import { RECORD_EXPLANATION, WITHDRAW_EXPLANATION } from './dlp-compliance';
import { compliance, dayAhead, meWithMfa } from './test-data';

const ROUTE = '/policies?tab=dlp&section=compliance';

let unsubscribe: (() => void) | null = null;
afterEach(() => {
  unsubscribe?.();
  unsubscribe = null;
});

function captureSessionEvents(): SessionEvent[] {
  const events: SessionEvent[] = [];
  unsubscribe = onSessionEvent((event) => events.push(event));
  return events;
}

const RECORDED = compliance(
  {
    enabled: true,
    active: true,
    basis: 'regulatory_obligation',
    reference: 'POL-DP-7',
    attested: true,
    recordedByUserId: '01930000-0000-7000-8000-000000000101',
    recordedAt: '2026-10-01T09:00:00.000Z',
    reviewDueAt: '2027-03-31T23:59:59.000Z',
  },
  3,
);

describe('DLP compliance: Aadhaar detection basis (WP5)', () => {
  it('records the basis after a confirm with the explanation: Idempotency-Key and a contract body; axe', async () => {
    const calls: { body: unknown; key: string | null }[] = [];
    mockApi({
      DlpComplianceController_get_v1: () => okJson(compliance()),
      DlpComplianceController_enable_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return okJson(RECORDED);
      },
    });
    const { user } = renderWithProviders(<DlpTab />, {
      me: meWithMfa('organization_admin', true),
      route: ROUTE,
    });
    expect(await screen.findByText('Aadhaar detection')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Withdraw basis' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Record basis' }));
    const sheet = await screen.findByRole('dialog', {
      name: 'Record the Aadhaar detection basis',
    });
    await expectNoAxeViolations(document.body);
    await user.click(within(sheet).getByRole('button', { name: 'Record basis' }));
    expect(
      await within(sheet).findByText('Confirm the attestation to record the basis'),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('Enter the document or approval reference')).toBeInTheDocument();
    expect(within(sheet).getByText('Choose the review date')).toBeInTheDocument();

    await user.selectOptions(within(sheet).getByLabelText(/^Basis/), 'data_protection_policy');
    await user.type(within(sheet).getByLabelText(/^Document or approval reference/), 'DPP-2026-04');
    const review = dayAhead(180);
    fireEvent.change(within(sheet).getByLabelText(/^Review date/), { target: { value: review } });
    await user.click(within(sheet).getByRole('checkbox', { name: /I attest/ }));
    await user.click(within(sheet).getByRole('button', { name: 'Record basis' }));

    const confirm = await screen.findByRole('alertdialog', {
      name: 'Record the Aadhaar detection basis?',
    });
    expect(within(confirm).getByText(RECORD_EXPLANATION)).toBeInTheDocument();
    expect(calls).toHaveLength(0);
    await expectNoAxeViolations(document.body);
    await user.click(within(confirm).getByRole('button', { name: 'Record basis' }));
    expect(await screen.findByText('Aadhaar detection basis recorded.')).toBeInTheDocument();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.key).toEqual(expect.any(String));
    expect(calls[0]?.body).toEqual({
      expectedVersion: 0,
      basis: 'data_protection_policy',
      reference: 'DPP-2026-04',
      attested: true,
      reviewDueAt: `${review}T23:59:59.000Z`,
    });
    expectRequestMatchesContract('DlpComplianceController_enable_v1', calls[0]?.body);
  });

  it('withdraws the basis after a confirm with the explanation (expectedVersion and Idempotency-Key)', async () => {
    const calls: { version: string | null; key: string | null }[] = [];
    mockApi({
      DlpComplianceController_get_v1: () => okJson(RECORDED),
      DlpComplianceController_disable_v1: ({ url, request }) => {
        calls.push({
          version: url.searchParams.get('expectedVersion'),
          key: request.headers.get('idempotency-key'),
        });
        return okJson(compliance({}, 4));
      },
    });
    const { user } = renderWithProviders(<DlpTab />, {
      me: meWithMfa('organization_admin', true),
      route: ROUTE,
    });
    expect(await screen.findByText('POL-DP-7')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Update basis' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Withdraw basis' }));
    const confirm = await screen.findByRole('alertdialog', {
      name: 'Withdraw the Aadhaar detection basis?',
    });
    expect(within(confirm).getByText(WITHDRAW_EXPLANATION)).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Withdraw basis' }));
    expect(await screen.findByText('Aadhaar detection basis withdrawn.')).toBeInTheDocument();
    expect(calls).toEqual([{ version: '3', key: expect.any(String) }]);
  });

  it('a session without MFA sees the MFA-required state with the API code instead of the actions', async () => {
    const events = captureSessionEvents();
    mockApi({ DlpComplianceController_get_v1: () => okJson(RECORDED) });
    const { user, container } = renderWithProviders(<DlpTab />, {
      me: meWithMfa('organization_admin', false),
      route: ROUTE,
    });
    const note = await screen.findByRole('note', {
      name: 'Multi-factor authentication required',
    });
    expect(
      within(note).getByText('Requires a session with multi-factor authentication'),
    ).toBeInTheDocument();
    expect(within(note).getByText('mfa_required')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Update basis' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Withdraw basis' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(within(note).getByRole('button', { name: 'Sign in again with MFA' }));
    expect(events).toContainEqual({ type: 'mfa-required' });
  });

  it('a 403 mfa_required from the API shows the MFA state in the form (and raises the MFA dialog)', async () => {
    const events = captureSessionEvents();
    mockApi({
      DlpComplianceController_get_v1: () => okJson(compliance()),
      DlpComplianceController_enable_v1: () =>
        apiErrorJson(403, 'mfa_required', 'This operation requires an MFA-authenticated session', {
          requestId: 'req-mfa-1',
        }),
    });
    const { user } = renderWithProviders(<DlpTab />, {
      me: meWithMfa('super_admin', true),
      route: ROUTE,
    });
    await user.click(await screen.findByRole('button', { name: 'Record basis' }));
    const sheet = await screen.findByRole('dialog', {
      name: 'Record the Aadhaar detection basis',
    });
    await user.type(within(sheet).getByLabelText(/^Document or approval reference/), 'REF-1');
    fireEvent.change(within(sheet).getByLabelText(/^Review date/), {
      target: { value: dayAhead(30) },
    });
    await user.click(within(sheet).getByRole('checkbox', { name: /I attest/ }));
    await user.click(within(sheet).getByRole('button', { name: 'Record basis' }));
    const confirm = await screen.findByRole('alertdialog');
    await user.click(within(confirm).getByRole('button', { name: 'Record basis' }));
    const note = await within(sheet).findByRole('note', {
      name: 'Multi-factor authentication required',
    });
    expect(within(note).getByText('mfa_required')).toBeInTheDocument();
    expect(within(note).getByText('req-mfa-1')).toBeInTheDocument();
    await waitFor(() => expect(events).toContainEqual({ type: 'mfa-required' }));
  });

  it('409 version_conflict on record offers to load the current version', async () => {
    let version = 0;
    mockApi({
      DlpComplianceController_get_v1: () => okJson(compliance({}, version)),
      DlpComplianceController_enable_v1: () => {
        version = 1;
        return apiErrorJson(409, 'version_conflict', 'Changed', { extra: { currentVersion: 1 } });
      },
    });
    const { user } = renderWithProviders(<DlpTab />, {
      me: meWithMfa('organization_admin', true),
      route: ROUTE,
    });
    await user.click(await screen.findByRole('button', { name: 'Record basis' }));
    const sheet = await screen.findByRole('dialog', {
      name: 'Record the Aadhaar detection basis',
    });
    await user.type(within(sheet).getByLabelText(/^Document or approval reference/), 'REF-2');
    fireEvent.change(within(sheet).getByLabelText(/^Review date/), {
      target: { value: dayAhead(30) },
    });
    await user.click(within(sheet).getByRole('checkbox', { name: /I attest/ }));
    await user.click(within(sheet).getByRole('button', { name: 'Record basis' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Record basis' }),
    );
    expect(await within(sheet).findByText(/now version 1/)).toBeInTheDocument();
    expect(
      within(sheet).getByRole('button', { name: 'Load the current version' }),
    ).toBeInTheDocument();
  });

  it('only organization admins and super admins get compliance controls (not security analysts)', async () => {
    mockApi({ DlpComplianceController_get_v1: () => okJson(RECORDED) });
    const analyst = renderWithProviders(<DlpTab />, {
      me: meWithMfa('security_analyst', true),
      route: ROUTE,
    });
    expect(await screen.findByText('POL-DP-7')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Update basis' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Withdraw basis' })).not.toBeInTheDocument();
    expect(screen.queryByRole('note', { name: 'Multi-factor authentication required' })).toBeNull();
    analyst.unmount();
    const admin = renderWithProviders(<DlpTab />, {
      me: makeMe({ role: 'super_admin' }),
      route: ROUTE,
    });
    expect(await screen.findByRole('button', { name: 'Update basis' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Withdraw basis' })).toBeInTheDocument();
    admin.unmount();
  });
});
