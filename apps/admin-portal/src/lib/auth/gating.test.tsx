import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { apiErrorJson, expectNoAxeViolations, mockApi, renderWithProviders } from '@/test';
import { Can } from './can';
import { RouteGate } from './route-gate';

describe('<Can> and <RouteGate> (design P11)', () => {
  it('Can hides actions the user cannot perform', () => {
    renderWithProviders(
      <div>
        <Can op="DomainsController_create_v1">
          <button type="button">Add domain</button>
        </Can>
        <Can op="DomainsController_list_v1">
          <span>list visible</span>
        </Can>
      </div>,
      { role: 'read_only_user' },
    );
    expect(screen.queryByRole('button', { name: 'Add domain' })).not.toBeInTheDocument();
    expect(screen.getByText('list visible')).toBeInTheDocument();
  });

  it('RouteGate renders the page or the 403 view', async () => {
    const { container } = renderWithProviders(
      <RouteGate gate={['UsersController_list_v1']}>
        <p>users page</p>
      </RouteGate>,
      { role: 'security_analyst' },
    );
    expect(
      screen.getByRole('heading', { name: 'You do not have access to this page' }),
    ).toBeInTheDocument();
    expect(screen.getByText('user:read')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    renderWithProviders(
      <RouteGate gate={['UsersController_list_v1']}>
        <p>users page</p>
      </RouteGate>,
      { role: 'organization_admin' },
    );
    expect(screen.getByText('users page')).toBeInTheDocument();
  });

  it('RouteGate shows the error state when /auth/me fails', async () => {
    mockApi({
      AuthController_me_v1: () => apiErrorJson(500, 'internal_error', 'x', { requestId: 'rq-me' }),
    });
    renderWithProviders(
      <RouteGate gate="authenticated">
        <p>page</p>
      </RouteGate>,
      { role: null },
    );
    expect(await screen.findByText('rq-me')).toBeInTheDocument();
  });
});
