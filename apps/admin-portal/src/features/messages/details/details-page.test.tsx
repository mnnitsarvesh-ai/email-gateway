import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  okJson,
  renderWithProviders,
  type SystemRoleKey,
} from '@/test';
import { HOSTILE_SUBJECT, expectNoInjectedMarkup, messageDetail } from '../test-data';
import { MessageDetails } from './message-details';
import { SECTIONS } from './sections';
import {
  MESSAGE_ID,
  detailsRoute,
  lifecycleBody,
  mockDetails,
  setViewportWidth,
} from './test-helpers';

let restoreViewport: (() => void) | null = null;
afterEach(() => {
  restoreViewport?.();
  restoreViewport = null;
});

const ALL = SECTIONS.map((section) => section.label);
const WITHOUT_DLP_AUDIT = ALL.filter(
  (label) => label !== 'DLP results' && label !== 'Audit history',
);

const ROLE_SECTIONS: [SystemRoleKey, string[], boolean][] = [
  ['organization_admin', ALL, true],
  ['security_analyst', ALL, true],
  ['compliance_auditor', ALL, true],
  ['read_only_user', WITHOUT_DLP_AUDIT, false],
  ['quarantine_reviewer', WITHOUT_DLP_AUDIT, false],
];

describe('Email details (/messages/[messageId]): page', () => {
  it('shows the summary by default with the masked subject, identifiers and lifecycle; passes axe', async () => {
    const { calls } = mockDetails({
      MessagesController_detail_v1: () =>
        okJson(
          messageDetail({ clientHelo: HOSTILE_SUBJECT, envelopeFrom: '<b>x</b>@example.com' }),
        ),
    });
    const { container } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'security_analyst',
      route: detailsRoute(),
    });
    expect(await screen.findByRole('heading', { name: 'Message summary' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Email details', level: 1 })).toBeInTheDocument();
    // The subject is withheld by the api: a masked pill, never "(no subject)".
    const subject = screen.getByText('Subject', { selector: 'dt' })
      .nextElementSibling as HTMLElement;
    expect(within(subject).getByText('Hidden')).toBeInTheDocument();
    expect(within(subject).getByText('(masked)')).toBeInTheDocument();
    for (const label of ['Envelope sender', 'Header From', 'Internet Message-ID', 'MTA queue ID']) {
      expect(screen.getByText(label, { selector: 'dt' })).toBeInTheDocument();
    }
    expect(await screen.findByText('Parsed')).toBeInTheDocument();
    expect(screen.getByText('Rescan possible now', { selector: 'dt' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /All scan rounds/ })).toHaveAttribute(
      'href',
      `/messages/${MESSAGE_ID}/scans`,
    );
    expectNoInjectedMarkup(container);
    // Lazy: only the summary's reads ran.
    expect(calls('MessageScansController_scansOf_v1')).toHaveLength(0);
    expect(calls('MessagesController_recipients_v1')).toHaveLength(0);
    expect(calls('QuarantineEntriesController_search_v1')).toHaveLength(0);
    expect(calls('MessageRevealController_reveal_v1')).toHaveLength(0);
    await expectNoAxeViolations(container);
  });

  it('renders the not-found state for unknown or foreign ids (loading first)', async () => {
    mockDetails({
      MessagesController_detail_v1: async () => {
        await new Promise((resolve) => setTimeout(resolve, 20));
        return apiErrorJson(404, 'message_not_found', 'Message not found', {
          requestId: 'req-404',
        });
      },
    });
    renderWithProviders(<MessageDetails messageId="01933c3a-1b2c-7d4e-8f00-0000000000ff" />);
    expect(screen.getByText(/Loading message/)).toBeInTheDocument();
    const alert = await screen.findByRole('alert');
    expect(within(alert).getByText('Not found')).toBeInTheDocument();
    expect(within(alert).getByText('message_not_found')).toBeInTheDocument();
    expect(within(alert).getByText('req-404')).toBeInTheDocument();
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
  });

  it.each(ROLE_SECTIONS)(
    'lists exactly the sections %s may open, and Reveal only with message:reveal',
    async (role, expected, reveal) => {
      mockDetails();
      renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
        role,
        route: detailsRoute(),
      });
      const tabs = await screen.findByRole('tablist', { name: 'Message sections' });
      expect(
        within(tabs)
          .getAllByRole('tab')
          .map((tab) => tab.textContent),
      ).toEqual(expected);
      expect(screen.queryAllByRole('button', { name: 'Reveal' })).toHaveLength(reveal ? 1 : 0);
      const rescan = role === 'organization_admin' || role === 'security_analyst';
      expect(screen.queryAllByRole('button', { name: 'Rescan' })).toHaveLength(rescan ? 1 : 0);
    },
  );

  it.each([
    ['read_only_user', 'dlp', 'DLP results', 'dlp:read'],
    ['quarantine_reviewer', 'audit', 'Audit history', 'audit:read'],
  ] as const)(
    'a direct ?section= without permission (%s, %s) renders the forbidden state and loads nothing',
    async (role, section, label, permission) => {
      const { calls } = mockDetails();
      const { container } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
        role,
        route: detailsRoute(`section=${section}`),
      });
      const alert = await screen.findByRole('alert');
      expect(within(alert).getByText('You do not have access to this section')).toBeInTheDocument();
      expect(within(alert).getByText(permission)).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: label })).toBeInTheDocument();
      expect(calls('MessageScansController_scansOf_v1')).toHaveLength(0);
      expect(calls('AuditLogsController_search_v1')).toHaveLength(0);
      await expectNoAxeViolations(container);
    },
  );

  it('falls back to the summary for an unknown section and keeps the section in the URL', async () => {
    const { calls } = mockDetails();
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute('section=bogus'),
    });
    expect(await screen.findByRole('heading', { name: 'Message summary' })).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Spam score' }));
    await waitFor(() => expect(currentTestUrl()).toContain('section=spam'));
    expect(await screen.findByText('FROM_NEQ_ENVFROM')).toBeInTheDocument();
    expect(calls('MessageScansController_scansOf_v1')).toHaveLength(1);
    // Moving between round-scoped sections reuses the cached scans page (one request).
    await user.click(screen.getByRole('tab', { name: 'Risk score' }));
    expect(await screen.findByText('Signal contributions')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Phishing analysis' }));
    expect(await screen.findByText('Matched rules')).toBeInTheDocument();
    expect(calls('MessageScansController_scansOf_v1')).toHaveLength(1);
  });

  it.each([
    [1440, 'vertical'],
    [834, 'horizontal'],
  ] as const)('at %i px the section navigation is a %s tab list', async (width, orientation) => {
    restoreViewport = setViewportWidth(width);
    mockDetails();
    const { container } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute(),
    });
    const tabs = await screen.findByRole('tablist', { name: 'Message sections' });
    expect(tabs).toHaveAttribute('aria-orientation', orientation);
    expect(screen.queryByRole('combobox', { name: 'Section' })).not.toBeInTheDocument();
    await screen.findByText('Parsed');
    await expectNoAxeViolations(container);
  });

  it('at 390 px the section navigation is a labelled native select', async () => {
    restoreViewport = setViewportWidth(390);
    mockDetails();
    const { user, container } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'read_only_user',
      route: detailsRoute(),
    });
    const select = await screen.findByRole('combobox', { name: 'Section' });
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    expect(within(select).getAllByRole('option')).toHaveLength(12);
    await user.selectOptions(select, 'headers');
    await waitFor(() => expect(currentTestUrl()).toContain('section=headers'));
    expect(await screen.findByRole('region', { name: 'Email headers' })).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('rescans with a contract body, an Idempotency-Key and the detail version; a retry reuses the key', async () => {
    const keys: string[] = [];
    let attempt = 0;
    const { calls } = mockDetails({
      MessageLifecycleController_rescan_v1: ({ body, request }) => {
        keys.push(request.headers.get('idempotency-key') ?? '');
        expectRequestMatchesContract('MessageLifecycleController_rescan_v1', body);
        attempt += 1;
        return attempt === 1
          ? apiErrorJson(503, 'service_unavailable', 'Try again', { requestId: 'req-503' })
          : okJson(
              {
                messageId: MESSAGE_ID,
                state: 'scanning',
                version: 7,
                lifecycleRound: 1,
                rescanEventId: '01933c3a-1b2c-7d4e-8f00-0000000ee001',
                note: 'ok',
              },
              202,
            );
      },
    });
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'security_analyst',
      route: detailsRoute(),
    });
    await user.click(await screen.findByRole('button', { name: 'Rescan' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(within(dialog).getByLabelText('Reason (required)'), 'short');
    await user.click(within(dialog).getByRole('button', { name: 'Rescan' }));
    expect(await within(dialog).findByText(/Enter at least 10 characters/)).toBeInTheDocument();
    expect(calls('MessageLifecycleController_rescan_v1')).toHaveLength(0);
    await user.clear(within(dialog).getByLabelText('Reason (required)'));
    await user.type(
      within(dialog).getByLabelText('Reason (required)'),
      'New signatures for this campaign',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Rescan' }));
    expect(await within(dialog).findByText('Code: service_unavailable')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Retry the same request' }));
    await waitFor(() => expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument());
    expect(keys).toHaveLength(2);
    expect(keys[0]).toMatch(/^[0-9a-f-]{36}$/);
    expect(keys[1]).toBe(keys[0]);
    expect(calls('MessageLifecycleController_rescan_v1')[0]?.body).toEqual({
      expectedVersion: messageDetail().version,
      reason: 'New signatures for this campaign',
    });
    expect(await screen.findByText(/Rescan started: round 1/)).toBeInTheDocument();
  });

  it('a rescan version conflict explains it and reloads the detail', async () => {
    const { calls } = mockDetails({
      MessageLifecycleController_rescan_v1: () =>
        apiErrorJson(409, 'message_version_conflict', 'Version conflict', {
          extra: { currentVersion: 8, currentState: 'quarantined' },
        }),
      MessageLifecycleController_lifecycle_v1: () => okJson(lifecycleBody()),
    });
    const { user } = renderWithProviders(<MessageDetails messageId={MESSAGE_ID} />, {
      role: 'organization_admin',
      route: detailsRoute(),
    });
    await user.click(await screen.findByRole('button', { name: 'Rescan' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.type(
      within(dialog).getByLabelText('Reason (required)'),
      'Re-check after feed update',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Rescan' }));
    expect(
      await within(dialog).findByText(/The message changed since you opened it/),
    ).toBeInTheDocument();
    await waitFor(() => expect(calls('MessagesController_detail_v1').length).toBeGreaterThan(1));
    expect(within(dialog).queryByRole('button', { name: 'Retry the same request' })).toBeNull();
  });
});
