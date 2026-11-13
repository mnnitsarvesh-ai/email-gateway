import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import {
  apiErrorJson,
  currentTestUrl,
  expectNoAxeViolations,
  expectRequestMatchesContract,
  mockApi,
  noContentResponse,
  okJson,
  renderWithProviders,
} from '@/test';
import { RoleDetailPage } from './role-detail-page';
import { roleCreateBody, roleCreateSchema, roleUpdateBody, roleUpdateSchema } from './role-form';
import { RolesPage } from './roles-page';

const T = '2026-11-12T09:00:00.000Z';
const CATALOG = {
  data: [
    { key: 'domain:read', description: 'View domains', category: 'domain' },
    { key: 'domain:manage', description: 'Add, verify and configure domains', category: 'domain' },
    { key: 'user:read', description: 'View users', category: 'user' },
    {
      key: 'organization:manage',
      description: 'Change organization settings',
      category: 'organization',
    },
  ],
};
const role = (key: string, permissions: string[], system: boolean) => ({
  key,
  name: key === 'read_only_user' ? 'Read-only User' : 'Mail flow operator',
  description: null,
  system,
  permissions,
  createdAt: T,
  updatedAt: T,
});
const SYSTEM = role('read_only_user', ['domain:read', 'user:read'], true);
const CUSTOM = role('mail_flow_operator', ['domain:read'], false);

describe('RolesPage', () => {
  it('lists system (read-only) and custom roles and shows the matrix view (axe clean)', async () => {
    mockApi({
      RolesController_list_v1: () => okJson({ data: [SYSTEM, CUSTOM] }),
      PermissionsController_list_v1: () => okJson(CATALOG),
    });
    const { container, user } = renderWithProviders(<RolesPage />, { route: '/roles' });
    expect(screen.getByText(/Loading Roles/)).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Read-only User' })).toHaveAttribute(
      'href',
      '/roles/read_only_user',
    );
    expect(screen.getByText('System (read-only)')).toBeInTheDocument();
    expect(screen.getByText('Custom')).toBeInTheDocument();
    await expectNoAxeViolations(container);
    await user.click(screen.getByRole('tab', { name: 'Permission matrix' }));
    expect(currentTestUrl()).toBe('/roles?view=matrix');
    const matrix = await screen.findByRole('table', { name: 'Permissions granted by each role' });
    const row = within(matrix).getByRole('row', { name: /user:read/ });
    expect(within(row).getAllByText('Granted')).toHaveLength(1);
    expect(within(row).getAllByText('Not granted')).toHaveLength(1);
    await expectNoAxeViolations(container);
  });

  it('shows the error with code and request id', async () => {
    mockApi({
      RolesController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-r-1' }),
      PermissionsController_list_v1: () => okJson(CATALOG),
    });
    renderWithProviders(<RolesPage />, { route: '/roles' });
    expect(await screen.findByText('req-r-1')).toBeInTheDocument();
  });

  it('creates a custom role with only held permissions (contract) and explains 403', async () => {
    const bodies: unknown[] = [];
    mockApi({
      RolesController_list_v1: () => okJson({ data: [SYSTEM] }),
      PermissionsController_list_v1: () => okJson(CATALOG),
      RolesController_create_v1: ({ body }) => {
        bodies.push(body);
        return bodies.length === 1
          ? apiErrorJson(403, 'forbidden', 'You cannot grant permissions you do not hold')
          : okJson({ ...CUSTOM, key: 'helpdesk' }, 201);
      },
    });
    const { user, router } = renderWithProviders(<RolesPage />, {
      permissions: ['role:read', 'role:manage', 'domain:read', 'domain:manage', 'user:read'],
      route: '/roles',
    });
    await screen.findByRole('link', { name: 'Read-only User' });
    await user.click(screen.getByRole('button', { name: 'New custom role' }));
    const dialog = await screen.findByRole('dialog', { name: 'New custom role' });
    await user.type(within(dialog).getByLabelText('Key (required)'), 'Bad Key');
    await user.click(within(dialog).getByRole('button', { name: 'Create role' }));
    expect(await within(dialog).findByText(/Lower-case letters/)).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText('Key (required)'));
    await user.type(within(dialog).getByLabelText('Key (required)'), 'helpdesk');
    await user.type(within(dialog).getByLabelText('Name (required)'), 'Helpdesk');
    expect(within(dialog).getByRole('checkbox', { name: /organization:manage/ })).toBeDisabled();
    await user.click(within(dialog).getByRole('checkbox', { name: /domain:read/ }));
    await user.click(within(dialog).getByRole('button', { name: 'Create role' }));
    expect(await within(dialog).findByText(/only grant permissions you hold/)).toBeInTheDocument();
    expect(bodies[0]).toEqual({ key: 'helpdesk', name: 'Helpdesk', permissions: ['domain:read'] });
    expectRequestMatchesContract('RolesController_create_v1', bodies[0]);
    await user.click(within(dialog).getByRole('button', { name: 'Create role' }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith('/roles/helpdesk'));
  });

  it('hides creation without role:manage and refuses users without role:read', async () => {
    mockApi({
      RolesController_list_v1: () => okJson({ data: [SYSTEM] }),
      PermissionsController_list_v1: () => okJson(CATALOG),
    });
    const { unmount } = renderWithProviders(<RolesPage />, {
      role: 'read_only_user',
      route: '/roles',
    });
    await screen.findByRole('link', { name: 'Read-only User' });
    expect(screen.queryByRole('button', { name: 'New custom role' })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<RolesPage />, { role: 'domain_admin', route: '/roles' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });
});

describe('RoleDetailPage', () => {
  it('shows a system role read-only, grouped with descriptions (axe clean)', async () => {
    mockApi({
      RolesController_get_v1: () => okJson(SYSTEM),
      PermissionsController_list_v1: () => okJson(CATALOG),
    });
    const { container } = renderWithProviders(<RoleDetailPage roleKey="read_only_user" />);
    expect(
      await screen.findByRole('heading', { level: 1, name: 'Read-only User' }),
    ).toBeInTheDocument();
    expect(screen.getByText(/cannot be changed or deleted/)).toBeInTheDocument();
    expect(screen.getByText('View domains')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit role' })).not.toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('renders the 404 page for an unknown role and a malformed key', async () => {
    mockApi({
      RolesController_get_v1: () => apiErrorJson(404, 'not_found', 'Role not found'),
      PermissionsController_list_v1: () => okJson(CATALOG),
    });
    const { unmount } = renderWithProviders(<RoleDetailPage roleKey="platform_admin" />);
    expect(await screen.findByText('Page not found')).toBeInTheDocument();
    unmount();
    renderWithProviders(<RoleDetailPage roleKey="../x" />);
    expect(screen.getByText('Page not found')).toBeInTheDocument();
  });

  it('edits a custom role (contract) and explains the 409 of deleting an assigned role', async () => {
    const calls: Record<string, unknown> = {};
    mockApi({
      RolesController_get_v1: () => okJson(CUSTOM),
      PermissionsController_list_v1: () => okJson(CATALOG),
      RolesController_update_v1: ({ body }) => (
        (calls.update = body),
        okJson({ ...CUSTOM, permissions: ['domain:read', 'domain:manage'] })
      ),
      RolesController_remove_v1: () =>
        apiErrorJson(409, 'conflict', 'The role is assigned to users'),
    });
    const { user } = renderWithProviders(<RoleDetailPage roleKey="mail_flow_operator" />);
    await user.click(await screen.findByRole('button', { name: 'Edit role' }));
    await user.click(screen.getByRole('checkbox', { name: /domain:manage/ }));
    await user.click(screen.getByRole('button', { name: 'Save role' }));
    await waitFor(() =>
      expect(calls.update).toEqual({
        name: 'Mail flow operator',
        description: null,
        permissions: ['domain:read', 'domain:manage'],
      }),
    );
    expectRequestMatchesContract('RolesController_update_v1', calls.update);
    await user.click(screen.getByRole('button', { name: 'Delete role' }));
    const dialog = await screen.findByRole('alertdialog');
    await user.click(within(dialog).getByRole('button', { name: 'Delete role' }));
    expect(
      await within(dialog).findByText('Remove the role from every user first.'),
    ).toBeInTheDocument();
  });

  it('deletes an unassigned custom role', async () => {
    let deleted = false;
    mockApi({
      RolesController_get_v1: () => okJson(CUSTOM),
      PermissionsController_list_v1: () => okJson(CATALOG),
      RolesController_remove_v1: () => ((deleted = true), noContentResponse()),
    });
    const { user, router } = renderWithProviders(<RoleDetailPage roleKey="mail_flow_operator" />);
    await user.click(await screen.findByRole('button', { name: 'Delete role' }));
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Delete role' }),
    );
    await waitFor(() => expect(deleted).toBe(true));
    expect(router.push).toHaveBeenCalledWith('/roles');
  });
});

describe('role forms', () => {
  it('mirror the request contracts', () => {
    expectRequestMatchesContract(
      'RolesController_create_v1',
      roleCreateBody(
        roleCreateSchema.parse({
          key: 'abc',
          name: 'A',
          description: 'd',
          permissions: ['domain:read'],
        }),
      ),
    );
    expectRequestMatchesContract(
      'RolesController_update_v1',
      roleUpdateBody(
        roleUpdateSchema.parse({ name: 'A', description: '', permissions: ['user:read'] }),
      ),
    );
    expect(
      roleUpdateSchema.safeParse({ name: 'A', description: '', permissions: [] }).success,
    ).toBe(false);
  });
});
