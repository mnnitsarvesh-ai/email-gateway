import { screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
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
import {
  departmentCreateBody,
  departmentSchema,
  departmentUpdateBody,
  memberBody,
  memberSchema,
} from './departments-tab';
import { UserDetailPage } from './user-detail-page';
import {
  profileBody,
  profileSchema,
  rolesSchema,
  userStatusBody,
  userStatusSchema,
} from './user-detail-page';
import { UsersPage } from './users-page';
import { inviteSchema } from './users-tab';

const T = '2026-11-12T09:00:00.000Z';
const USER_ID = '0193d000-0000-7000-8000-000000000001';
const user = (i: number, overrides: Record<string, unknown> = {}) => ({
  id: `0193d000-0000-7000-8000-${String(i).padStart(12, '0')}`,
  email: `user${i}@example.com`,
  displayName: `User ${i}`,
  status: 'active',
  statusReason: null,
  roles: [{ key: 'read_only_user', name: 'Read-only User' }],
  mfaEnabled: true,
  emailVerified: true,
  lockedUntil: null,
  lastLoginAt: T,
  createdAt: T,
  updatedAt: T,
  ...overrides,
});
const role = (key: string, permissions: string[], system = true) => ({
  key,
  name: key.replace(/_/g, ' '),
  description: null,
  system,
  permissions,
  createdAt: T,
  updatedAt: T,
});
const ROLES = {
  data: [
    role('read_only_user', ['domain:read', 'user:read']),
    role('domain_admin', ['domain:read', 'domain:manage']),
    role('platform_ops', ['platform:operations'], false),
  ],
};

function mockList(total = 3, requests: URL[] = []) {
  mockApi({
    RolesController_list_v1: () => okJson(ROLES),
    UsersController_list_v1: ({ url }) => {
      requests.push(url);
      const all = Array.from({ length: total }, (_, i) => user(i + 1));
      const offset = Number(url.searchParams.get('cursor') ?? '0');
      return okJson({
        data: all.slice(offset, offset + 25),
        nextCursor: offset + 25 < total ? String(offset + 25) : null,
      });
    },
  });
}

describe('UsersPage', () => {
  it('loads, lists users and passes axe; filters and search go to the URL and the request', async () => {
    const requests: URL[] = [];
    mockList(30, requests);
    const { container, user: u } = renderWithProviders(<UsersPage />, { route: '/users' });
    expect(screen.getByText(/Loading Users/)).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'User 1' })).toHaveAttribute(
      'href',
      `/users/${user(1).id}`,
    );
    await expectNoAxeViolations(container);
    await u.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('cursor')).toBe('25'));
    await u.click(screen.getByRole('combobox', { name: 'Status' }));
    await u.click(await screen.findByRole('option', { name: 'Locked' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('status')).toBe('locked'));
    await u.click(screen.getByRole('combobox', { name: 'Role' }));
    await u.click(await screen.findByRole('option', { name: 'domain admin' }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get('role')).toBe('domain_admin'));
    expect(currentTestUrl()).toBe('/users?status=locked&role=domain_admin');
  });

  it('shows empty and error states', async () => {
    mockApi({
      RolesController_list_v1: () => okJson(ROLES),
      UsersController_list_v1: () =>
        apiErrorJson(500, 'internal_error', 'Boom', { requestId: 'req-u-1' }),
    });
    const { unmount } = renderWithProviders(<UsersPage />, { route: '/users' });
    expect(await screen.findByText('req-u-1')).toBeInTheDocument();
    unmount();
    mockApi({ UsersController_list_v1: () => okJson({ data: [], nextCursor: null }) });
    renderWithProviders(<UsersPage />, { route: '/users' });
    expect(await screen.findByText('No users yet')).toBeInTheDocument();
  });

  it('invites with roles the caller holds (legacy Idempotency-Key, contract) and explains 403', async () => {
    const calls: { body: unknown; key: string | null }[] = [];
    mockList(1);
    mockApi({
      UsersController_invite_v1: ({ body, request }) => {
        calls.push({ body, key: request.headers.get('idempotency-key') });
        return calls.length === 1
          ? apiErrorJson(403, 'forbidden', 'You cannot grant this role')
          : okJson(user(9, { status: 'invited' }), 201);
      },
    });
    const { user: u, router } = renderWithProviders(<UsersPage />, {
      permissions: ['user:read', 'user:manage', 'role:read', 'domain:read', 'domain:manage'],
      route: '/users',
    });
    await u.click(await screen.findByRole('button', { name: 'Invite user' }));
    const dialog = await screen.findByRole('dialog', { name: 'Invite a user' });
    await u.click(within(dialog).getByRole('button', { name: 'Send invitation' }));
    expect(await within(dialog).findByText('Choose at least one role')).toBeInTheDocument();
    await u.type(within(dialog).getByLabelText('Email (required)'), 'new.person@example.com');
    await u.type(within(dialog).getByLabelText('Name (required)'), 'New Person');
    expect(within(dialog).getByRole('checkbox', { name: /platform ops/ })).toBeDisabled();
    await u.click(within(dialog).getByRole('checkbox', { name: /domain admin/ }));
    await u.click(within(dialog).getByRole('button', { name: 'Send invitation' }));
    expect(
      await within(dialog).findByText(/only grant roles whose permissions you hold/),
    ).toBeInTheDocument();
    expect(calls[0]?.body).toEqual({
      email: 'new.person@example.com',
      displayName: 'New Person',
      roleKeys: ['domain_admin'],
    });
    expectRequestMatchesContract('UsersController_invite_v1', calls[0]?.body);
    expect(calls[0]?.key).toMatch(/^[0-9a-f-]{36}$/);
    await u.click(within(dialog).getByRole('button', { name: 'Send invitation' }));
    await waitFor(() => expect(router.push).toHaveBeenCalledWith(`/users/${user(9).id}`));
    expect(calls[1]?.key).not.toBe(calls[0]?.key);
  });

  it('hides invite from read-only users and refuses roles without user:read', async () => {
    mockList(1);
    const { unmount } = renderWithProviders(<UsersPage />, {
      role: 'read_only_user',
      route: '/users',
    });
    await screen.findByRole('link', { name: 'User 1' });
    expect(screen.queryByRole('button', { name: 'Invite user' })).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<UsersPage />, { role: 'security_analyst', route: '/users' });
    expect(screen.getByText('You do not have access to this page')).toBeInTheDocument();
  });

  it('departments: create (contract), edit with row version, delete in use, members add/remove', async () => {
    const calls: Record<string, unknown> = {};
    const dept = {
      id: '0193e000-0000-7000-8000-000000000001',
      name: 'Finance',
      description: null,
      memberCount: 1,
      rowVersion: 3,
      createdByUserId: null,
      updatedByUserId: null,
      createdAt: T,
      updatedAt: T,
    };
    mockApi({
      DepartmentsController_list_v1: () => okJson({ data: [dept], nextCursor: null }),
      DepartmentsController_create_v1: ({ body }) => (
        (calls.create = body),
        okJson({ ...dept, id: '0193e000-0000-7000-8000-000000000002', name: 'Legal' }, 201)
      ),
      DepartmentsController_update_v1: ({ body }) => (
        (calls.update = body),
        okJson({ ...dept, name: 'Finance team', rowVersion: 4 })
      ),
      DepartmentsController_remove_v1: ({ url }) => (
        (calls.removeVersion = url.searchParams.get('expectedRowVersion')),
        apiErrorJson(409, 'department_in_use', 'In use', {
          extra: { policies: [{ policyId: 'p1' }] },
        })
      ),
      DepartmentsController_listMembers_v1: () =>
        okJson({
          data: [
            {
              id: '0193e000-0000-7000-8000-0000000000a1',
              departmentId: dept.id,
              kind: 'address',
              address: 'cfo@alpha.example.test',
              userId: null,
              createdByUserId: null,
              createdAt: T,
            },
          ],
          nextCursor: null,
        }),
      DepartmentsController_addMember_v1: ({ body }) => (
        (calls.add = body),
        okJson(
          {
            id: '0193e000-0000-7000-8000-0000000000a2',
            departmentId: dept.id,
            kind: 'address',
            address: 'ap@alpha.example.test',
            userId: null,
            createdByUserId: null,
            createdAt: T,
          },
          201,
        )
      ),
      DepartmentsController_removeMember_v1: ({ params }) => (
        (calls.removeMember = params.memberId),
        noContentResponse()
      ),
    });
    const { user: u, container } = renderWithProviders(<UsersPage />, {
      route: '/users?tab=departments',
    });
    await screen.findByText('Finance');
    await expectNoAxeViolations(container);

    await u.click(screen.getByRole('button', { name: 'New department' }));
    let dialog = await screen.findByRole('dialog', { name: 'New department' });
    await u.type(within(dialog).getByLabelText('Name (required)'), 'Legal');
    await u.click(within(dialog).getByRole('button', { name: 'Create department' }));
    await waitFor(() => expect(calls.create).toEqual({ name: 'Legal' }));
    expectRequestMatchesContract('DepartmentsController_create_v1', calls.create);

    await u.click(screen.getByRole('button', { name: 'Actions for Finance' }));
    await u.click(await screen.findByRole('menuitem', { name: 'Edit' }));
    dialog = await screen.findByRole('dialog', { name: 'Edit Finance' });
    const name = within(dialog).getByLabelText('Name (required)');
    await u.clear(name);
    await u.type(name, 'Finance team');
    await u.click(within(dialog).getByRole('button', { name: 'Save department' }));
    await waitFor(() =>
      expect(calls.update).toEqual({ expectedRowVersion: 3, name: 'Finance team' }),
    );
    expectRequestMatchesContract('DepartmentsController_update_v1', calls.update);

    await u.click(screen.getByRole('button', { name: 'Actions for Finance' }));
    await u.click(await screen.findByRole('menuitem', { name: 'Delete' }));
    const confirm = await screen.findByRole('alertdialog');
    await u.click(within(confirm).getByRole('button', { name: 'Delete department' }));
    expect(await within(confirm).findByText(/Referenced by 1 active policy/)).toBeInTheDocument();
    expect(calls.removeVersion).toBe('3');
    await u.click(within(confirm).getByRole('button', { name: 'Cancel' }));

    await u.click(screen.getByRole('button', { name: 'Actions for Finance' }));
    await u.click(await screen.findByRole('menuitem', { name: 'Members' }));
    dialog = await screen.findByRole('dialog', { name: 'Members of Finance' });
    expect(await within(dialog).findByText('cfo@alpha.example.test')).toBeInTheDocument();
    await u.type(within(dialog).getByLabelText('Email address'), 'ap@alpha.example.test');
    await u.click(within(dialog).getByRole('button', { name: 'Add member' }));
    await waitFor(() => expect(calls.add).toEqual({ address: 'ap@alpha.example.test' }));
    expectRequestMatchesContract('DepartmentsController_addMember_v1', calls.add);
    await u.click(
      within(dialog).getByRole('button', { name: 'Actions for cfo@alpha.example.test' }),
    );
    await u.click(await screen.findByRole('menuitem', { name: 'Remove' }));
    await u.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Remove' }),
    );
    await waitFor(() => expect(calls.removeMember).toBe('0193e000-0000-7000-8000-0000000000a1'));
  });
});

function mockDetail(overrides: Parameters<typeof mockApi>[0] = {}) {
  mockApi({
    UsersController_get_v1: () => okJson(user(1)),
    RolesController_list_v1: () => okJson(ROLES),
    UsersController_listSessions_v1: () =>
      okJson({
        data: [
          {
            id: '0193f000-0000-7000-8000-000000000001',
            current: false,
            authenticatedAt: T,
            lastUsedAt: T,
            expiresAt: T,
            ipAddress: '198.51.100.9',
            userAgent: '<b>Firefox</b>',
            mfaAuthenticated: true,
          },
        ],
      }),
    ...overrides,
  });
}

describe('UserDetailPage', () => {
  it('shows the profile, roles and sessions (axe clean)', async () => {
    mockDetail();
    const { container } = renderWithProviders(<UserDetailPage userId={USER_ID} />);
    expect(await screen.findByRole('heading', { level: 1, name: 'User 1' })).toBeInTheDocument();
    expect(await screen.findByText('<b>Firefox</b>')).toBeInTheDocument();
    await expectNoAxeViolations(container);
  });

  it('renders the 404 page for a foreign or unknown user and a malformed id', async () => {
    mockApi({ UsersController_get_v1: () => apiErrorJson(404, 'not_found', 'User not found') });
    const { unmount } = renderWithProviders(<UserDetailPage userId={USER_ID} />);
    expect(await screen.findByText('Page not found')).toBeInTheDocument();
    unmount();
    renderWithProviders(<UserDetailPage userId="x" />);
    expect(screen.getByText('Page not found')).toBeInTheDocument();
  });

  it('edits the profile (only changed fields, contract) and replaces roles; explains 403', async () => {
    const calls: Record<string, unknown> = {};
    mockDetail({
      UsersController_update_v1: ({ body }) => (
        (calls.update = body),
        okJson(user(1, { displayName: 'Renamed' }))
      ),
      UsersController_replaceRoles_v1: ({ body }) => (
        (calls.roles = body),
        apiErrorJson(403, 'forbidden', 'You cannot act on this user')
      ),
    });
    const { user: u } = renderWithProviders(<UserDetailPage userId={USER_ID} />);
    await u.click(await screen.findByRole('button', { name: 'Edit profile' }));
    const dialog = await screen.findByRole('dialog', { name: 'Edit profile' });
    const name = within(dialog).getByLabelText('Name (required)');
    await u.clear(name);
    await u.type(name, 'Renamed');
    await u.click(within(dialog).getByRole('button', { name: 'Save profile' }));
    await waitFor(() => expect(calls.update).toEqual({ displayName: 'Renamed' }));
    expectRequestMatchesContract('UsersController_update_v1', calls.update);

    await u.click(await screen.findByRole('checkbox', { name: /domain admin/ }));
    await u.click(screen.getByRole('button', { name: 'Save roles' }));
    await waitFor(() =>
      expect(calls.roles).toEqual({ roleKeys: ['read_only_user', 'domain_admin'] }),
    );
    expectRequestMatchesContract('UsersController_replaceRoles_v1', calls.roles);
    expect(
      await screen.findByText(/only grant roles whose permissions you hold/),
    ).toBeInTheDocument();
  });

  it('disables, resends the invitation, resets MFA (mfa_required explained) and revokes sessions', async () => {
    const calls: Record<string, unknown> = {};
    mockDetail({
      UsersController_get_v1: () => okJson(user(1, { status: 'invited' })),
      UsersController_changeStatus_v1: ({ body }) => (
        (calls.status = body),
        okJson(user(1, { status: 'disabled' }))
      ),
      UsersController_resendInvitation_v1: ({ request }) => (
        (calls.resendKey = request.headers.get('idempotency-key')),
        okJson({ expiresAt: '2026-11-20T09:00:00.000Z' }, 202)
      ),
      UsersController_resetMfa_v1: () =>
        apiErrorJson(403, 'mfa_required', 'This action requires an MFA-authenticated session'),
      UsersController_revokeSession_v1: () => ((calls.revoked = true), noContentResponse()),
      UsersController_revokeAllSessions_v1: () => ((calls.revokedAll = true), noContentResponse()),
    });
    const { user: u } = renderWithProviders(<UserDetailPage userId={USER_ID} />);
    await u.click(await screen.findByRole('button', { name: 'Resend invitation' }));
    expect(await screen.findByText(/Invitation sent again/)).toBeInTheDocument();
    expect(calls.resendKey).toMatch(/^[0-9a-f-]{36}$/);

    await u.click(screen.getByRole('button', { name: 'Disable' }));
    let dialog = await screen.findByRole('alertdialog');
    await u.type(within(dialog).getByLabelText('Reason (optional)'), 'Left');
    await u.click(within(dialog).getByRole('button', { name: 'Disable' }));
    await waitFor(() => expect(calls.status).toEqual({ status: 'disabled', reason: 'Left' }));
    expectRequestMatchesContract('UsersController_changeStatus_v1', calls.status);

    await u.click(screen.getByRole('button', { name: 'Reset MFA' }));
    dialog = await screen.findByRole('alertdialog');
    await u.click(within(dialog).getByRole('button', { name: 'Reset MFA' }));
    expect(await within(dialog).findByText(/needs an MFA session/)).toBeInTheDocument();
    await u.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    await u.click(screen.getByRole('button', { name: 'Sign out session from 198.51.100.9' }));
    await u.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Sign out session',
      }),
    );
    await waitFor(() => expect(calls.revoked).toBe(true));
    await u.click(screen.getByRole('button', { name: 'Sign out everywhere' }));
    await u.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Sign out everywhere',
      }),
    );
    await waitFor(() => expect(calls.revokedAll).toBe(true));
  });

  it('deletes after typing the email', async () => {
    let deleted = false;
    mockDetail({ UsersController_remove_v1: () => ((deleted = true), noContentResponse()) });
    const { user: u, router } = renderWithProviders(<UserDetailPage userId={USER_ID} />);
    await u.click(await screen.findByRole('button', { name: 'Delete user' }));
    const dialog = await screen.findByRole('alertdialog');
    expect(within(dialog).getByRole('button', { name: 'Delete user' })).toBeDisabled();
    await u.type(within(dialog).getByRole('textbox'), 'user1@example.com');
    await u.click(within(dialog).getByRole('button', { name: 'Delete user' }));
    await waitFor(() => expect(deleted).toBe(true));
    expect(router.push).toHaveBeenCalledWith('/users');
  });

  it('read-only users and domain admins see no change actions; no sessions without session:manage', async () => {
    mockApi({
      UsersController_get_v1: () => okJson(user(1)),
      RolesController_list_v1: () => okJson(ROLES),
    });
    const { unmount } = renderWithProviders(<UserDetailPage userId={USER_ID} />, {
      role: 'read_only_user',
    });
    await screen.findByRole('heading', { level: 1, name: 'User 1' });
    for (const name of ['Edit profile', 'Disable', 'Reset MFA', 'Delete user', 'Save roles'])
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    expect(screen.queryByText('Sessions')).not.toBeInTheDocument();
    unmount();
    renderWithProviders(<UserDetailPage userId={USER_ID} />, { role: 'domain_admin' });
    await screen.findByRole('heading', { level: 1, name: 'User 1' });
    expect(screen.queryByRole('button', { name: 'Edit profile' })).not.toBeInTheDocument();
  });

  it('never offers disabling or deleting yourself', async () => {
    mockDetail({ UsersController_get_v1: () => okJson(user(1, { id: makeMe().user.id })) });
    renderWithProviders(<UserDetailPage userId={makeMe().user.id} />);
    expect(await screen.findByText('You')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete user' })).not.toBeInTheDocument();
  });
});

describe('user forms', () => {
  it('mirror the request contracts', () => {
    expectRequestMatchesContract(
      'UsersController_invite_v1',
      inviteSchema.parse({
        email: 'a@example.com',
        displayName: 'A',
        roleKeys: ['read_only_user'],
      }),
    );
    expectRequestMatchesContract(
      'UsersController_update_v1',
      profileBody(
        { displayName: 'A', email: 'a@example.com' },
        profileSchema.parse({ displayName: 'B', email: 'b@example.com' }),
      ),
    );
    expectRequestMatchesContract(
      'UsersController_replaceRoles_v1',
      rolesSchema.parse({ roleKeys: ['read_only_user'] }),
    );
    expect(rolesSchema.safeParse({ roleKeys: [] }).success).toBe(false);
    expectRequestMatchesContract(
      'UsersController_changeStatus_v1',
      userStatusBody(userStatusSchema.parse({ status: 'active', reason: '' })),
    );
    expectRequestMatchesContract(
      'DepartmentsController_create_v1',
      departmentCreateBody(departmentSchema.parse({ name: 'X', description: 'Y' })),
    );
    expectRequestMatchesContract(
      'DepartmentsController_update_v1',
      departmentUpdateBody(
        { name: 'X', description: 'Y', rowVersion: 2 },
        departmentSchema.parse({ name: 'X', description: '' }),
      ),
    );
    expectRequestMatchesContract(
      'DepartmentsController_addMember_v1',
      memberBody(memberSchema.parse({ kind: 'user', userId: USER_ID })),
    );
  });
});
