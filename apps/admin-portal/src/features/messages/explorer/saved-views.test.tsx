import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  makeMe,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { MessageExplorer } from './message-explorer';
import { VIEW_ID, mockExplorer, savedView, type SavedViewBody } from './test-helpers';

beforeEach(() => localStorage.clear());

const OTHER_ID = '01933c3a-1b2c-7d4e-8f00-0000000f0002';

async function openViews(user: ReturnType<typeof renderWithProviders>['user']) {
  await user.click(await screen.findByRole('button', { name: /^Views/ }));
  return screen.findByRole('menu');
}

describe('Email explorer: saved views (§2 E4, E10)', () => {
  it('lists the views and applies one: URL state, column set and the menu label', async () => {
    const view = savedView({
      definition: {
        version: 1,
        filters: { direction: 'inbound', verdict: 'phishing', senderDomain: 'example.com' },
        sort: 'receivedAt',
        range: { kind: 'relative', preset: '7d' },
        columns: ['receivedAt', 'from', 'subject', 'verdict'],
      },
    });
    const mocks = mockExplorer({ views: [view, savedView({ id: OTHER_ID, name: 'Second' })] });
    const { user, router, container } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages?status=delivered',
    });
    await screen.findByRole('link', { name: /open message details/ });
    const menu = await openViews(user);
    await expectNoAxeViolations(container.ownerDocument.body);
    await user.click(within(menu).getByRole('menuitemradio', { name: 'Inbound phishing' }));
    await waitFor(() => expect(mocks.last().get('senderDomain')).toBe('example.com'));
    const q = mocks.last();
    expect(q.get('direction')).toBe('inbound');
    expect(q.get('verdict')).toBe('phishing');
    expect(q.has('status')).toBe(false);
    expect(q.get('sort')).toBe('receivedAt');
    expect(Date.parse(q.get('to') ?? '') - Date.parse(q.get('from') ?? '')).toBe(7 * 86_400_000);
    expect(currentTestUrl()).toContain(`view=${VIEW_ID}`);
    expect(router.push).toHaveBeenCalled();
    expect(screen.queryByRole('columnheader', { name: 'Size' })).not.toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Verdict' })).toBeInTheDocument();
    expect(
      await screen.findByRole('button', { name: 'Views: Inbound phishing' }),
    ).toBeInTheDocument();
    expect(screen.queryByText(/no longer apply/)).not.toBeInTheDocument();
  });

  it('an outdated view applies what it can and says what was left out', async () => {
    mockExplorer({
      views: [
        savedView({
          definition: {
            version: 1,
            filters: { 'riskScore.gt': '700', hasAttachments: 'true' },
            sort: '-receivedAt',
            range: { kind: 'relative', preset: '30d' },
            columns: ['receivedAt', 'subject', 'legacyScore'],
          },
        }),
      ],
    });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(
      within(await openViews(user)).getByRole('menuitemradio', { name: 'Inbound phishing' }),
    );
    const notice = await screen.findByText(/Some settings of this view no longer apply/);
    expect(notice).toHaveTextContent('riskScore.gt');
    expect(notice).toHaveTextContent('legacyScore');
    expect(currentTestUrl()).toContain('attachments=true');
  });

  it('"Save as" sends a contract-valid body and selects the new view', async () => {
    const created: unknown[] = [];
    let listCalls = 0;
    mockExplorer({
      viewsHandler: () => {
        listCalls += 1;
        return okJson({ data: [], nextCursor: null });
      },
    });
    mockApi({
      SavedViewsController_create_v1: ({ body }) => {
        created.push(body);
        const request = body as { name: string; definition: SavedViewBody['definition'] };
        return okJson(
          savedView({
            id: OTHER_ID,
            name: request.name,
            definition: request.definition,
            rowVersion: 1,
          }),
          201,
        );
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      role: 'security_analyst',
      route: '/messages?range=7d&verdict=phishing,malware&quarantineStatus=held',
    });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(
      within(await openViews(user)).getByRole('menuitem', { name: 'Save as new view …' }),
    );
    const dialog = await screen.findByRole('dialog', { name: 'Save as new view' });
    await user.click(within(dialog).getByRole('button', { name: 'Save view' }));
    expect(await within(dialog).findByText('Enter a name.')).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText('Name (required)'), '  Held phishing  ');
    await user.click(within(dialog).getByRole('button', { name: 'Save view' }));
    await waitFor(() => expect(created).toHaveLength(1));
    expectRequestMatchesContract('SavedViewsController_create_v1', created[0]);
    expect(created[0]).toEqual({
      kind: 'message_explorer',
      name: 'Held phishing',
      definition: {
        version: 1,
        filters: { verdict: 'phishing,malware', quarantineStatus: 'held' },
        sort: '-receivedAt',
        range: { kind: 'relative', preset: '7d' },
        columns: null,
      },
    });
    await waitFor(() => expect(currentTestUrl()).toContain(`view=${OTHER_ID}`));
    await waitFor(() => expect(listCalls).toBe(2));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('"Save as" explains 409 saved_view_name_taken at the name and the limit at form level', async () => {
    mockExplorer();
    let calls = 0;
    mockApi({
      SavedViewsController_create_v1: () => {
        calls += 1;
        return calls === 1
          ? apiErrorJson(409, 'saved_view_name_taken', 'Name taken')
          : apiErrorJson(409, 'saved_view_limit_reached', 'Limit', {
              requestId: 'req-limit-1',
              extra: { limit: 50 },
            });
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, { route: '/messages' });
    await screen.findByRole('link', { name: /open message details/ });
    await user.click(
      within(await openViews(user)).getByRole('menuitem', { name: 'Save as new view …' }),
    );
    const dialog = await screen.findByRole('dialog', { name: 'Save as new view' });
    await user.type(within(dialog).getByLabelText('Name (required)'), 'Daily');
    await user.click(within(dialog).getByRole('button', { name: 'Save view' }));
    expect(
      await within(dialog).findByText(/already have a view with this name/),
    ).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Save view' }));
    expect(
      await within(dialog).findByText(/maximum number of saved views \(50\)/),
    ).toBeInTheDocument();
    expect(within(dialog).getByText('req-limit-1')).toBeInTheDocument();
  });

  it('"Save changes" sends PUT with expectedRowVersion; a 409 conflict reloads the list', async () => {
    const view = savedView();
    let listCalls = 0;
    const mocks = mockExplorer({
      viewsHandler: () => {
        listCalls += 1;
        return okJson({ data: [view], nextCursor: null });
      },
    });
    const puts: unknown[] = [];
    mockApi({
      SavedViewsController_update_v1: ({ body, params }) => {
        puts.push(body);
        expect(params.viewId).toBe(VIEW_ID);
        return puts.length === 1
          ? okJson({ ...view, ...(body as object), rowVersion: 4 })
          : apiErrorJson(409, 'saved_view_conflict', 'Changed', {
              extra: { currentRowVersion: 5 },
            });
      },
    });
    const { user } = renderWithProviders(<MessageExplorer />, {
      route: `/messages?range=7d&direction=inbound&verdict=phishing&view=${VIEW_ID}`,
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(
      await screen.findByRole('button', { name: 'Views: Inbound phishing' }),
    ).toBeInTheDocument();
    let menu = await openViews(user);
    expect(
      within(menu).getByRole('menuitem', { name: 'Save changes to “Inbound phishing”' }),
    ).toHaveAttribute('aria-disabled', 'true');
    await user.keyboard('{Escape}');
    await user.click(screen.getByLabelText('Attachments'));
    await user.click(await screen.findByRole('option', { name: 'With attachments' }));
    await waitFor(() => expect(mocks.last().get('hasAttachments')).toBe('true'));
    expect(
      await screen.findByRole('button', { name: 'Views: Inbound phishing (modified)' }),
    ).toBeInTheDocument();
    menu = await openViews(user);
    await user.click(
      within(menu).getByRole('menuitem', { name: 'Save changes to “Inbound phishing”' }),
    );
    await waitFor(() => expect(puts).toHaveLength(1));
    expectRequestMatchesContract('SavedViewsController_update_v1', puts[0]);
    expect(puts[0]).toMatchObject({
      name: 'Inbound phishing',
      expectedRowVersion: 3,
      definition: {
        filters: { direction: 'inbound', verdict: 'phishing', hasAttachments: 'true' },
        range: { kind: 'relative', preset: '7d' },
      },
    });

    await user.click(screen.getByLabelText('Attachments'));
    await user.click(await screen.findByRole('option', { name: 'Without attachments' }));
    await waitFor(() => expect(mocks.last().get('hasAttachments')).toBe('false'));
    const before = listCalls;
    menu = await openViews(user);
    await user.click(
      within(menu).getByRole('menuitem', { name: 'Save changes to “Inbound phishing”' }),
    );
    expect(await screen.findByText(/This view was changed elsewhere/)).toBeInTheDocument();
    await waitFor(() => expect(listCalls).toBeGreaterThan(before));
  });

  it('renames a view with its saved definition, and deletes it after confirmation', async () => {
    const view = savedView();
    mockExplorer({ views: [view] });
    const puts: unknown[] = [];
    let deleted = '';
    mockApi({
      SavedViewsController_update_v1: ({ body }) => {
        puts.push(body);
        return okJson({ ...view, name: (body as { name: string }).name, rowVersion: 4 });
      },
      SavedViewsController_remove_v1: ({ params }) => {
        deleted = params.viewId ?? '';
        return noContentResponse();
      },
    });
    const { user, container } = renderWithProviders(<MessageExplorer />, {
      route: `/messages?range=24h&view=${VIEW_ID}`,
    });
    await screen.findByRole('link', { name: /open message details/ });
    await screen.findByRole('button', { name: /^Views: Inbound phishing/ });
    await user.click(
      within(await openViews(user)).getByRole('menuitem', { name: 'Rename “Inbound phishing” …' }),
    );
    const dialog = await screen.findByRole('dialog', { name: 'Rename view' });
    await expectNoAxeViolations(container.ownerDocument.body);
    const name = within(dialog).getByLabelText('Name (required)');
    expect(name).toHaveValue('Inbound phishing');
    await user.clear(name);
    await user.type(name, 'Phishing (inbound)');
    await user.click(within(dialog).getByRole('button', { name: 'Rename' }));
    await waitFor(() => expect(puts).toHaveLength(1));
    expectRequestMatchesContract('SavedViewsController_update_v1', puts[0]);
    expect(puts[0]).toEqual({
      name: 'Phishing (inbound)',
      definition: view.definition,
      expectedRowVersion: 3,
    });
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await user.click(
      within(await openViews(user)).getByRole('menuitem', { name: 'Delete “Inbound phishing” …' }),
    );
    const confirm = await screen.findByRole('alertdialog', { name: 'Delete saved view' });
    await user.click(within(confirm).getByRole('button', { name: 'Delete view' }));
    await waitFor(() => expect(deleted).toBe(VIEW_ID));
    await waitFor(() => expect(currentTestUrl()).not.toContain('view='));
  });

  it('platform override sessions: the menu is replaced by an explanation (no list request)', async () => {
    let listCalls = 0;
    mockExplorer({
      viewsHandler: () => {
        listCalls += 1;
        return okJson({ data: [], nextCursor: null });
      },
    });
    renderWithProviders(<MessageExplorer />, {
      me: makeMe({
        role: 'platform_admin',
        permissions: ['message:read'],
        overrides: {
          override: {
            id: 'ovr-1',
            reason: 'Ticket OPS-1',
            organizationId: 'org-b',
            expiresAt: '2026-11-14T12:00:00.000Z',
          },
        },
      }),
      route: '/messages',
    });
    await screen.findByRole('link', { name: /open message details/ });
    expect(screen.getByTestId('saved-views-member-only')).toHaveTextContent(
      'Saved views belong to the members of an organization',
    );
    expect(screen.queryByRole('button', { name: /^Views/ })).not.toBeInTheDocument();
    expect(listCalls).toBe(0);
  });

  it('403 saved_views_member_only from the api hides the menu too', async () => {
    mockExplorer({
      viewsHandler: () => apiErrorJson(403, 'saved_views_member_only', 'Members only'),
    });
    renderWithProviders(<MessageExplorer />, { route: '/messages' });
    expect(await screen.findByTestId('saved-views-member-only')).toBeInTheDocument();
  });
});
