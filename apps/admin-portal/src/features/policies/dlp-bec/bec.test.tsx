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
import { BecTab } from '../dlp-bec';
import {
  EXECUTIVE_ID,
  SUPPRESSION_ID,
  TRUSTED_ID,
  VENDOR_ID,
  dayAhead,
  executive,
  page,
  suppression,
  trustedSender,
  vendor,
} from './test-data';

describe('BEC executives (WP5)', () => {
  it('creates, edits and deletes an executive; 409 executive_exists is on the name; axe', async () => {
    const created: unknown[] = [];
    const updated: unknown[] = [];
    const deleted: (string | null)[] = [];
    mockApi({
      BecExecutivesController_list_v1: () => okJson(page([executive()])),
      BecExecutivesController_create_v1: ({ body }) => {
        created.push(body);
        return created.length === 1
          ? apiErrorJson(409, 'executive_exists', 'Exists', { extra: { id: EXECUTIVE_ID } })
          : okJson(
              executive({ id: '01933c3a-1b2c-7d4e-8f00-0000000be002', displayName: 'Ravi Kumar' }),
              201,
            );
      },
      BecExecutivesController_update_v1: ({ body }) => (
        updated.push(body),
        okJson(executive({ version: 2 }))
      ),
      BecExecutivesController_remove_v1: ({ url }) => (
        deleted.push(url.searchParams.get('version')),
        noContentResponse()
      ),
    });
    const { user } = renderWithProviders(<BecTab />, {
      role: 'security_analyst',
      route: '/policies?tab=bec',
    });
    await screen.findByText('Dana Whitfield');
    await user.click(screen.getByRole('button', { name: 'New executive' }));
    let sheet = await screen.findByRole('dialog', { name: 'New executive' });
    await expectNoAxeViolations(document.body);
    await user.type(within(sheet).getByLabelText(/^Display name/), 'Ravi Kumar');
    await user.type(within(sheet).getByLabelText(/^Job title/), 'CFO');
    await user.type(within(sheet).getByLabelText(/^Aliases/), 'R. Kumar{Enter}Ravi K');
    await user.type(within(sheet).getByLabelText(/^Known addresses/), 'cfo@alpha.example.test');
    await user.click(within(sheet).getByRole('button', { name: 'Add executive' }));
    expect(
      await within(sheet).findByText(/An executive with this name exists/),
    ).toBeInTheDocument();
    expect(within(sheet).getByLabelText(/^Display name/)).toHaveAttribute('aria-invalid', 'true');
    await user.click(within(sheet).getByRole('button', { name: 'Add executive' }));
    expect(await screen.findByText('Executive added.')).toBeInTheDocument();
    expect(created[1]).toEqual({
      displayName: 'Ravi Kumar',
      aliases: ['R. Kumar', 'Ravi K'],
      knownAddresses: ['cfo@alpha.example.test'],
      title: 'CFO',
      enabled: true,
    });
    expectRequestMatchesContract('BecExecutivesController_create_v1', created[1]);

    await user.click(screen.getByRole('button', { name: 'Actions for Dana Whitfield' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    sheet = await screen.findByRole('dialog', { name: 'Edit Dana Whitfield' });
    await user.clear(within(sheet).getByLabelText(/^Job title/));
    await user.type(within(sheet).getByLabelText(/^Aliases/), 'D. Whitfield');
    await user.click(within(sheet).getByRole('button', { name: 'Save executive' }));
    expect(await screen.findByText('Executive saved.')).toBeInTheDocument();
    expect(updated[0]).toEqual({ version: 1, aliases: ['D. Whitfield'], title: null });
    expectRequestMatchesContract('BecExecutivesController_update_v1', updated[0]);

    await user.click(screen.getByRole('button', { name: 'Actions for Dana Whitfield' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog', { name: 'Remove Dana Whitfield?' });
    await user.click(within(confirm).getByRole('button', { name: 'Remove executive' }));
    expect(await screen.findByText('Executive removed.')).toBeInTheDocument();
    expect(deleted).toEqual(['1']);
  });
});

describe('BEC vendors (WP5)', () => {
  it('creates a vendor: 422 vendor_domain_freemail names the domain line; edits and deletes', async () => {
    const created: unknown[] = [];
    const updated: unknown[] = [];
    mockApi({
      BecVendorsController_list_v1: () => okJson(page([vendor()])),
      BecVendorsController_create_v1: ({ body }) => {
        created.push(body);
        return created.length === 1
          ? apiErrorJson(422, 'vendor_domain_freemail', 'A free-mail domain', {
              extra: { index: 1 },
              requestId: 'req-422',
            })
          : okJson(
              vendor({ id: '01933c3a-1b2c-7d4e-8f00-0000000be102', name: 'Charlie Supplies' }),
              201,
            );
      },
      BecVendorsController_update_v1: ({ body, params }) => {
        updated.push(body);
        expect(params.id).toBe(VENDOR_ID);
        return okJson(vendor({ version: 3 }));
      },
      BecVendorsController_remove_v1: () => noContentResponse(),
    });
    const { user } = renderWithProviders(<BecTab />, {
      role: 'organization_admin',
      route: '/policies?tab=bec&section=vendors',
    });
    await screen.findByText('Bravo Logistics');
    await user.click(screen.getByRole('button', { name: 'New vendor' }));
    const sheet = await screen.findByRole('dialog', { name: 'New vendor' });
    await expectNoAxeViolations(document.body);
    await user.type(within(sheet).getByLabelText(/^Vendor name/), 'Charlie Supplies');
    await user.type(
      within(sheet).getByLabelText(/^Domains/),
      'charlie.example.test{Enter}{Enter}freemail.example.test',
    );
    await user.click(
      within(sheet).getByRole('switch', { name: 'Flag payment-change wording from this vendor' }),
    );
    await user.click(within(sheet).getByRole('button', { name: 'Add vendor' }));
    expect(
      await within(sheet).findByText(/Line 3: a free-mail domain cannot be a vendor domain/),
    ).toBeInTheDocument();
    expect(within(sheet).getByText('vendor_domain_freemail')).toBeInTheDocument();
    expect(within(sheet).getByText('req-422')).toBeInTheDocument();
    expect(created[0]).toEqual({
      name: 'Charlie Supplies',
      aliases: [],
      domains: ['charlie.example.test', 'freemail.example.test'],
      knownSenders: [],
      paymentChangeSensitive: false,
      enabled: true,
    });
    expectRequestMatchesContract('BecVendorsController_create_v1', created[0]);
    await user.clear(within(sheet).getByLabelText(/^Domains/));
    await user.type(within(sheet).getByLabelText(/^Domains/), 'charlie.example.test');
    await user.click(within(sheet).getByRole('button', { name: 'Add vendor' }));
    expect(await screen.findByText('Vendor added.')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Actions for Bravo Logistics' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog', { name: 'Edit Bravo Logistics' });
    await user.type(
      within(edit).getByLabelText(/^Known sender addresses/),
      '{Enter}ap@bravo.example.test',
    );
    await user.click(within(edit).getByRole('button', { name: 'Save vendor' }));
    expect(await screen.findByText('Vendor saved.')).toBeInTheDocument();
    expect(updated[0]).toEqual({
      version: 2,
      knownSenders: ['billing@bravo.example.test', 'ap@bravo.example.test'],
    });
    expectRequestMatchesContract('BecVendorsController_update_v1', updated[0]);

    await user.click(screen.getByRole('button', { name: 'Actions for Bravo Logistics' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Remove vendor' }),
    );
    expect(await screen.findByText('Vendor removed.')).toBeInTheDocument();
  });

  it('requires at least one domain in the browser', async () => {
    mockApi({ BecVendorsController_list_v1: () => okJson(page([])) });
    const { user } = renderWithProviders(<BecTab />, {
      role: 'security_analyst',
      route: '/policies?tab=bec&section=vendors',
    });
    await screen.findByText('No vendors');
    await user.click(screen.getByRole('button', { name: 'New vendor' }));
    const sheet = await screen.findByRole('dialog', { name: 'New vendor' });
    await user.type(within(sheet).getByLabelText(/^Vendor name/), 'Delta');
    await user.click(within(sheet).getByRole('button', { name: 'Add vendor' }));
    expect(await within(sheet).findByText('Enter at least one domain')).toBeInTheDocument();
  });
});

describe('BEC trusted senders (WP5)', () => {
  it('adds a trusted sender (422 free-mail, 409 duplicate on the value), edits reason and expiry, deletes', async () => {
    const created: unknown[] = [];
    const updated: unknown[] = [];
    mockApi({
      BecTrustedSendersController_list_v1: () =>
        okJson(page([trustedSender({ expiresAt: '2027-02-01T23:59:59.000Z' })])),
      BecTrustedSendersController_create_v1: ({ body }) => {
        created.push(body);
        if (created.length === 1) {
          return apiErrorJson(
            422,
            'trusted_domain_freemail',
            'A free-mail domain cannot be trusted',
          );
        }
        if (created.length === 2) {
          return apiErrorJson(409, 'trusted_sender_exists', 'Exists', {
            extra: { id: TRUSTED_ID },
          });
        }
        return okJson(trustedSender({ id: '01933c3a-1b2c-7d4e-8f00-0000000be202' }), 201);
      },
      BecTrustedSendersController_update_v1: ({ body, params }) => {
        updated.push(body);
        expect(params.id).toBe(TRUSTED_ID);
        return okJson(trustedSender({ version: 2 }));
      },
      BecTrustedSendersController_remove_v1: () => noContentResponse(),
    });
    const { user } = renderWithProviders(<BecTab />, {
      role: 'security_analyst',
      route: '/policies?tab=bec&section=trusted',
    });
    await screen.findByText('partner.example.test');
    await user.click(screen.getByRole('button', { name: 'New trusted sender' }));
    const sheet = await screen.findByRole('dialog', { name: 'New trusted sender' });
    await expectNoAxeViolations(document.body);
    await user.type(within(sheet).getByLabelText(/^Registrable domain/), 'webmail.example.test');
    await user.type(within(sheet).getByLabelText(/^Reason/), 'Supplier portal');
    const expiry = dayAhead(120);
    fireEvent.change(within(sheet).getByLabelText(/^Expires/), { target: { value: expiry } });
    await user.click(within(sheet).getByRole('button', { name: 'Add trusted sender' }));
    expect(
      await within(sheet).findByText(/A free-mail domain cannot be trusted/),
    ).toBeInTheDocument();
    expect(created[0]).toEqual({
      kind: 'domain',
      value: 'webmail.example.test',
      reason: 'Supplier portal',
      expiresAt: `${expiry}T23:59:59.000Z`,
    });
    expectRequestMatchesContract('BecTrustedSendersController_create_v1', created[0]);
    await user.click(within(sheet).getByRole('button', { name: 'Add trusted sender' }));
    expect(await within(sheet).findByText('This sender is already trusted.')).toBeInTheDocument();
    await user.click(within(sheet).getByRole('button', { name: 'Add trusted sender' }));
    expect(await screen.findByText('Trusted sender added.')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Actions for partner.example.test' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    const edit = await screen.findByRole('dialog', { name: 'Edit trusted sender' });
    fireEvent.change(within(edit).getByLabelText(/^Expires/), { target: { value: '' } });
    await user.click(within(edit).getByRole('button', { name: 'Save trusted sender' }));
    expect(await screen.findByText('Trusted sender saved.')).toBeInTheDocument();
    expect(updated[0]).toEqual({ version: 1, expiresAt: null });
    expectRequestMatchesContract('BecTrustedSendersController_update_v1', updated[0]);

    await user.click(screen.getByRole('button', { name: 'Actions for partner.example.test' }));
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Remove trusted sender',
      }),
    );
    expect(await screen.findByText('Trusted sender removed.')).toBeInTheDocument();
  });
});

describe('BEC suppressions (WP5)', () => {
  it('lifts a suppression after a confirm; a 404 is shown with its code', async () => {
    const lifted: string[] = [];
    mockApi({
      BecFeedbackController_listSuppressions_v1: () => okJson(page([suppression()])),
      BecFeedbackController_deleteSuppression_v1: ({ params }) => {
        lifted.push(params.id ?? '');
        return lifted.length === 1
          ? apiErrorJson(404, 'bec_suppression_not_found', 'Suppression rule not found')
          : noContentResponse();
      },
    });
    const { user } = renderWithProviders(<BecTab />, {
      role: 'security_analyst',
      route: '/policies?tab=bec&section=suppressions',
    });
    await screen.findByText('bec.content.urgency');
    await user.click(
      screen.getByRole('button', {
        name: 'Actions for bec.content.urgency for partner.example.test',
      }),
    );
    await user.click(await screen.findByRole('menuitem', { name: 'Lift suppression' }));
    const confirm = await screen.findByRole('alertdialog', { name: 'Lift this suppression?' });
    await expectNoAxeViolations(document.body);
    await user.click(within(confirm).getByRole('button', { name: 'Lift suppression' }));
    expect(await within(confirm).findByText('bec_suppression_not_found')).toBeInTheDocument();
    await user.click(within(confirm).getByRole('button', { name: 'Lift suppression' }));
    expect(await screen.findByText('Suppression lifted.')).toBeInTheDocument();
    await waitFor(() => expect(lifted).toEqual([SUPPRESSION_ID, SUPPRESSION_ID]));
  });

  it('offers no communication-history purge and no feedback export (data operations, not in 7.3)', async () => {
    mockApi({
      BecFeedbackController_list_v1: () => okJson(page([])),
    });
    renderWithProviders(<BecTab />, {
      role: 'organization_admin',
      route: '/policies?tab=bec&section=feedback',
    });
    await screen.findByText('No feedback recorded');
    expect(screen.queryByRole('button', { name: /purge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /export/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /history/i })).not.toBeInTheDocument();
  });
});
