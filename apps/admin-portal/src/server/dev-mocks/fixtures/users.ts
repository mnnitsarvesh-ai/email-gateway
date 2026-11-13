import 'server-only';
import type { RequestBody, SuccessBody } from '@/lib/api/types';
import { SeededRandom, paginate, stableUuid, syntheticPerson } from '../generator';
import { apiError, noContent, ok, type FixtureHandlers, type FixtureRequest } from '../types';
import { DAY, HOUR, MINUTE, bodyOf, guarded, isoAgo, type FixturePrincipal } from './domains';
import { assignedRoleKeys, roleRef, rolesOf } from './roles';
import { fixtures as sessionFixtures } from './session';

export { DEV_MOCK_MARKER } from '../types';

/**
 * Dev fixtures of the `users` feature (WP4, design P9): users (every status, ≥ 30 for paging),
 * invitations, roles with the no-escalation rule, status, MFA reset (needs an MFA session),
 * sessions, departments and members. Synthetic `example.com` people, per organization.
 */

type User = SuccessBody<'UsersController_get_v1'>;
type Session = SuccessBody<'UsersController_listSessions_v1'>['data'][number];
type Department = SuccessBody<'DepartmentsController_get_v1'>;
type Member = SuccessBody<'DepartmentsController_listMembers_v1'>['data'][number];

interface OrgState {
  users: User[];
  deleted: Set<string>;
  sessions: Map<string, Session[]>;
  departments: Department[];
  members: Map<string, Member[]>;
}
const globalState = globalThis as typeof globalThis & {
  __egDevFixtureUsers?: Map<string, OrgState>;
};
const orgs: Map<string, OrgState> = (globalState.__egDevFixtureUsers ??= new Map<
  string,
  OrgState
>());

const ROLE_CYCLE = [
  'read_only_user',
  'security_analyst',
  'domain_admin',
  'quarantine_reviewer',
  'compliance_auditor',
  'mailbox_user',
  'helpdesk',
];
const STATUS_CYCLE: User['status'][] = [
  'active',
  'active',
  'active',
  'invited',
  'active',
  'disabled',
  'active',
  'locked',
];

function seed(organizationId: string): OrgState {
  const random = new SeededRandom(`${organizationId}:users`);
  const roles = rolesOf(organizationId);
  const ref = (key: string) => roleRef(organizationId, key) ?? { key, name: key };
  const users: User[] = [];
  // The fixture sign-in identities first, so they appear in the directory.
  for (const key of ['organization_admin', 'domain_admin', 'read_only_user'].filter((k) =>
    roles.some((r) => r.key === k),
  )) {
    const created = isoAgo(200 * DAY);
    users.push({
      id: stableUuid(`user:${key}@example.com`),
      email: `${key}@example.com`,
      displayName: key
        .split('_')
        .map((w) => w[0]?.toUpperCase() + w.slice(1))
        .join(' '),
      status: 'active',
      statusReason: null,
      roles: [ref(key)],
      mfaEnabled: key === 'organization_admin',
      emailVerified: true,
      lockedUntil: null,
      lastLoginAt: isoAgo(2 * HOUR),
      createdAt: created,
      updatedAt: created,
    });
  }
  const count = roles.some((r) => r.key === 'organization_admin') ? 32 : 4;
  for (let i = 0; i < count; i += 1) {
    const person = syntheticPerson(random);
    const status = STATUS_CYCLE[i % STATUS_CYCLE.length] ?? 'active';
    const roleKey = ROLE_CYCLE[i % ROLE_CYCLE.length] ?? 'read_only_user';
    const created = isoAgo((i + 1) * 4 * DAY);
    users.push({
      id: stableUuid(`${organizationId}:user:${i}`),
      email: person.email.replace('@', `.${i}@`),
      displayName: person.displayName,
      status,
      statusReason: status === 'disabled' ? 'Left the company' : null,
      roles: roles.some((r) => r.key === roleKey) ? [ref(roleKey)] : [ref('read_only_user')],
      mfaEnabled: i % 3 === 0 && status !== 'invited',
      emailVerified: status !== 'invited',
      lockedUntil: status === 'locked' ? new Date(Date.now() + 25 * MINUTE).toISOString() : null,
      lastLoginAt: status === 'invited' ? null : isoAgo(random.int(1, 400) * HOUR),
      createdAt: created,
      updatedAt: created,
    });
  }
  for (const user of users)
    for (const role of user.roles) assignedRoleKeys.add(`${organizationId}:${role.key}`);
  const sessions = new Map<string, Session[]>();
  for (const user of users.filter((u) => u.status === 'active').slice(0, 10)) {
    sessions.set(
      user.id,
      [0, 1].map((n) => ({
        id: stableUuid(`${user.id}:session:${n}`),
        current: false,
        authenticatedAt: isoAgo((n + 1) * 20 * HOUR),
        lastUsedAt: isoAgo((n + 1) * 30 * MINUTE),
        expiresAt: new Date(Date.now() + 6 * DAY).toISOString(),
        ipAddress: n === 0 ? '198.51.100.23' : '2001:db8:4::17',
        userAgent:
          n === 0
            ? 'Mozilla/5.0 (Macintosh) Firefox/140.0'
            : 'Mozilla/5.0 (Windows NT 10.0) Edg/141.0',
        mfaAuthenticated: user.mfaEnabled,
      })),
    );
  }
  const departments: Department[] = ['Finance', 'Executive office', 'Engineering', 'Support'].map(
    (name, i) => ({
      id: stableUuid(`${organizationId}:department:${i}`),
      name,
      description: i === 1 ? 'C-level and their assistants (BEC policies)' : null,
      memberCount: 0,
      rowVersion: 1 + i,
      createdByUserId: users[0]?.id ?? null,
      updatedByUserId: users[0]?.id ?? null,
      createdAt: isoAgo((40 - i) * DAY),
      updatedAt: isoAgo((10 - i) * DAY),
    }),
  );
  const members = new Map<string, Member[]>();
  departments.forEach((department, i) => {
    const list: Member[] = Array.from({ length: i === 0 ? 3 : 1 }, (_, n) => ({
      id: stableUuid(`${department.id}:member:${n}`),
      departmentId: department.id,
      kind: n === 2 ? 'user' : 'address',
      address:
        n === 2
          ? null
          : `${department.name.toLowerCase().replace(/\s+/g, '.')}${n}@alpha-1.example.test`,
      userId: n === 2 ? (users[0]?.id ?? null) : null,
      createdByUserId: users[0]?.id ?? null,
      createdAt: isoAgo((n + 1) * DAY),
    }));
    members.set(department.id, list);
    department.memberCount = list.length;
  });
  return { users, deleted: new Set(), sessions, departments, members };
}

function org(organizationId: string): OrgState {
  let state = orgs.get(organizationId);
  if (!state) {
    state = seed(organizationId);
    orgs.set(organizationId, state);
  }
  return state;
}

const userNotFound = () => apiError(404, 'not_found', 'User not found');

function findUser(p: FixturePrincipal, id: string | undefined): User | null {
  const state = org(p.organizationId);
  return state.users.find((u) => u.id === id && !state.deleted.has(u.id)) ?? null;
}

/** No escalation on the target: the caller must hold every permission of the target's roles. */
function escalation(p: FixturePrincipal, user: User): ReturnType<typeof apiError> | null {
  const roles = rolesOf(p.organizationId);
  const needed = user.roles.flatMap(
    (r) => roles.find((role) => role.key === r.key)?.permissions ?? [],
  );
  const lacking = needed.filter((perm) => !p.permissions.includes(perm));
  return lacking.length > 0
    ? apiError(403, 'forbidden', 'You cannot act on a user who holds permissions you lack')
    : null;
}

function rolesFor(p: FixturePrincipal, keys: unknown) {
  const list = Array.isArray(keys) ? keys.map(String) : [];
  if (list.length === 0) return apiError(400, 'validation_failed', ['roleKeys: at least one role']);
  const roles = rolesOf(p.organizationId);
  const refs = [];
  for (const key of list) {
    const role = roles.find((r) => r.key === key);
    if (!role) return apiError(400, 'validation_failed', [`roleKeys: unknown role ${key}`]);
    if (role.permissions.some((perm) => !p.permissions.includes(perm)))
      return apiError(
        403,
        'forbidden',
        `You cannot grant the role ${role.name}: it holds permissions you lack`,
      );
    refs.push({ key: role.key, name: role.name });
  }
  return refs;
}

/** Whether the caller's fixture session is MFA-authenticated (from the session fixtures' `me`). */
function mfaSession(request: FixtureRequest): boolean {
  const me = sessionFixtures.AuthController_me_v1?.(request);
  if (!me || me instanceof Promise || me.status !== 200) return false;
  const body = me.body as { session?: { mfaAuthenticated?: boolean } } | undefined;
  return body?.session?.mfaAuthenticated === true;
}

const departmentNotFound = () => apiError(404, 'department_not_found', 'Department not found');

export const fixtures: FixtureHandlers = {
  UsersController_list_v1: guarded('UsersController_list_v1', (request, p) => {
    const state = org(p.organizationId);
    const q = request.query.get('q')?.toLowerCase() ?? '';
    const role = request.query.get('role');
    const status = request.query.get('status');
    const rows = state.users.filter(
      (u) =>
        !state.deleted.has(u.id) &&
        (!q || u.email.startsWith(q) || u.displayName.toLowerCase().startsWith(q)) &&
        (!role || u.roles.some((r) => r.key === role)) &&
        (!status || u.status === status),
    );
    return { status: 200, body: paginate(rows, request.query) };
  }),
  UsersController_get_v1: guarded('UsersController_get_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    return user ? ok('UsersController_get_v1', user) : userNotFound();
  }),
  UsersController_invite_v1: guarded('UsersController_invite_v1', (request, p) => {
    const state = org(p.organizationId);
    const body = bodyOf<RequestBody<'UsersController_invite_v1'>>(request);
    const email = String(body.email ?? '')
      .trim()
      .toLowerCase();
    if (!email.includes('@')) return apiError(400, 'validation_failed', ['email: Invalid email']);
    if (state.users.some((u) => u.email === email && !state.deleted.has(u.id)))
      return apiError(409, 'conflict', 'A user with this email already exists');
    const roles = rolesFor(p, body.roleKeys);
    if (!Array.isArray(roles)) return roles;
    const now = new Date().toISOString();
    const user: User = {
      id: stableUuid(`${p.organizationId}:user:${email}:${now}`),
      email,
      displayName: String(body.displayName ?? email),
      status: 'invited',
      statusReason: null,
      roles,
      mfaEnabled: false,
      emailVerified: false,
      lockedUntil: null,
      lastLoginAt: null,
      createdAt: now,
      updatedAt: now,
    };
    state.users.unshift(user);
    for (const role of roles) assignedRoleKeys.add(`${p.organizationId}:${role.key}`);
    return ok('UsersController_invite_v1', user, 201);
  }),
  UsersController_update_v1: guarded('UsersController_update_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    const refused = escalation(p, user);
    if (refused) return refused;
    const body = bodyOf<RequestBody<'UsersController_update_v1'>>(request);
    if (body.displayName) user.displayName = body.displayName;
    if (body.email) {
      user.email = body.email.toLowerCase();
      user.emailVerified = false;
    }
    user.updatedAt = new Date().toISOString();
    return ok('UsersController_update_v1', user);
  }),
  UsersController_remove_v1: guarded('UsersController_remove_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    const refused = escalation(p, user);
    if (refused) return refused;
    org(p.organizationId).deleted.add(user.id);
    return noContent();
  }),
  UsersController_resendInvitation_v1: guarded(
    'UsersController_resendInvitation_v1',
    (request, p) => {
      const user = findUser(p, request.params.id);
      if (!user) return userNotFound();
      if (user.status !== 'invited')
        return apiError(409, 'conflict', 'Only invited users can receive a new invitation');
      return ok(
        'UsersController_resendInvitation_v1',
        { expiresAt: new Date(Date.now() + 7 * DAY).toISOString() },
        202,
      );
    },
  ),
  UsersController_changeStatus_v1: guarded('UsersController_changeStatus_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    const refused = escalation(p, user);
    if (refused) return refused;
    const body = bodyOf<RequestBody<'UsersController_changeStatus_v1'>>(request);
    if (body.status === 'active') {
      user.status = user.emailVerified ? 'active' : 'invited';
      user.lockedUntil = null;
      user.statusReason = body.reason ?? null;
    } else if (body.status === 'disabled') {
      user.status = 'disabled';
      user.statusReason = body.reason ?? null;
      org(p.organizationId).sessions.delete(user.id);
    } else return apiError(400, 'validation_failed', ['status: Invalid enum value']);
    user.updatedAt = new Date().toISOString();
    return ok('UsersController_changeStatus_v1', user);
  }),
  UsersController_replaceRoles_v1: guarded('UsersController_replaceRoles_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    const refused = escalation(p, user);
    if (refused) return refused;
    const roles = rolesFor(
      p,
      bodyOf<RequestBody<'UsersController_replaceRoles_v1'>>(request).roleKeys,
    );
    if (!Array.isArray(roles)) return roles;
    user.roles = roles;
    for (const role of roles) assignedRoleKeys.add(`${p.organizationId}:${role.key}`);
    user.updatedAt = new Date().toISOString();
    return ok('UsersController_replaceRoles_v1', user);
  }),
  UsersController_resetMfa_v1: guarded('UsersController_resetMfa_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    // The api needs the caller's own MFA-authenticated session; fixture sessions of
    // `mfa.<role>@example.com` carry it, others answer 403 mfa_required like the api.
    if (!mfaSession(request))
      return apiError(403, 'mfa_required', 'This action requires an MFA-authenticated session');
    user.mfaEnabled = false;
    org(p.organizationId).sessions.delete(user.id);
    return noContent();
  }),
  UsersController_listSessions_v1: guarded('UsersController_listSessions_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    return ok('UsersController_listSessions_v1', {
      data: org(p.organizationId).sessions.get(user.id) ?? [],
    });
  }),
  UsersController_revokeAllSessions_v1: guarded(
    'UsersController_revokeAllSessions_v1',
    (request, p) => {
      const user = findUser(p, request.params.id);
      if (!user) return userNotFound();
      org(p.organizationId).sessions.delete(user.id);
      return noContent();
    },
  ),
  UsersController_revokeSession_v1: guarded('UsersController_revokeSession_v1', (request, p) => {
    const user = findUser(p, request.params.id);
    if (!user) return userNotFound();
    const state = org(p.organizationId);
    const list = state.sessions.get(user.id) ?? [];
    if (!list.some((s) => s.id === request.params.sessionId))
      return apiError(404, 'not_found', 'Session not found');
    state.sessions.set(
      user.id,
      list.filter((s) => s.id !== request.params.sessionId),
    );
    return noContent();
  }),
  DepartmentsController_list_v1: guarded('DepartmentsController_list_v1', (request, p) => ({
    status: 200,
    body: paginate(org(p.organizationId).departments, request.query),
  })),
  DepartmentsController_get_v1: guarded('DepartmentsController_get_v1', (request, p) => {
    const department = org(p.organizationId).departments.find(
      (d) => d.id === request.params.departmentId,
    );
    return department ? ok('DepartmentsController_get_v1', department) : departmentNotFound();
  }),
  DepartmentsController_create_v1: guarded('DepartmentsController_create_v1', (request, p) => {
    const state = org(p.organizationId);
    const body = bodyOf<RequestBody<'DepartmentsController_create_v1'>>(request);
    const name = String(body.name ?? '').trim();
    if (state.departments.some((d) => d.name.toLowerCase() === name.toLowerCase()))
      return apiError(409, 'department_name_taken', 'A department with this name exists');
    const now = new Date().toISOString();
    const department: Department = {
      id: stableUuid(`${p.organizationId}:department:${name}:${now}`),
      name,
      description: body.description ?? null,
      memberCount: 0,
      rowVersion: 1,
      createdByUserId: null,
      updatedByUserId: null,
      createdAt: now,
      updatedAt: now,
    };
    state.departments.unshift(department);
    state.members.set(department.id, []);
    return ok('DepartmentsController_create_v1', department, 201);
  }),
  DepartmentsController_update_v1: guarded('DepartmentsController_update_v1', (request, p) => {
    const department = org(p.organizationId).departments.find(
      (d) => d.id === request.params.departmentId,
    );
    if (!department) return departmentNotFound();
    const body = bodyOf<RequestBody<'DepartmentsController_update_v1'>>(request);
    if (body.expectedRowVersion !== department.rowVersion)
      return apiError(409, 'department_conflict', 'The department was changed', {
        currentRowVersion: department.rowVersion,
      });
    if (body.name) department.name = body.name;
    if (body.description !== undefined) department.description = body.description;
    department.rowVersion += 1;
    department.updatedAt = new Date().toISOString();
    return ok('DepartmentsController_update_v1', department);
  }),
  DepartmentsController_remove_v1: guarded('DepartmentsController_remove_v1', (request, p) => {
    const state = org(p.organizationId);
    const department = state.departments.find((d) => d.id === request.params.departmentId);
    if (!department) return departmentNotFound();
    if (Number(request.query.get('expectedRowVersion')) !== department.rowVersion)
      return apiError(409, 'department_conflict', 'The department was changed');
    if (department.name === 'Executive office')
      return apiError(
        409,
        'department_in_use',
        'The department is referenced by an active policy',
        { policies: [{ policyId: stableUuid('policy:bec-executives') }] },
      );
    state.departments = state.departments.filter((d) => d.id !== department.id);
    return noContent();
  }),
  DepartmentsController_listMembers_v1: guarded(
    'DepartmentsController_listMembers_v1',
    (request, p) => {
      const state = org(p.organizationId);
      if (!state.departments.some((d) => d.id === request.params.departmentId))
        return departmentNotFound();
      return {
        status: 200,
        body: paginate(state.members.get(request.params.departmentId ?? '') ?? [], request.query),
      };
    },
  ),
  DepartmentsController_addMember_v1: guarded(
    'DepartmentsController_addMember_v1',
    (request, p) => {
      const state = org(p.organizationId);
      const department = state.departments.find((d) => d.id === request.params.departmentId);
      if (!department) return departmentNotFound();
      const body = bodyOf<{ address?: string; userId?: string }>(request);
      const list = state.members.get(department.id) ?? [];
      if (body.address && !/@[a-z0-9.-]+\.example\.test$/i.test(body.address))
        return apiError(
          400,
          'member_address_not_tenant',
          'The address is not in an active domain of the organization',
        );
      if (body.userId && !state.users.some((u) => u.id === body.userId))
        return apiError(400, 'member_user_not_tenant', 'Unknown user');
      if (
        list.some(
          (m) =>
            (body.address && m.address === body.address.toLowerCase()) ||
            (body.userId && m.userId === body.userId),
        )
      )
        return apiError(409, 'department_member_exists', 'Already a member');
      const member: Member = {
        id: stableUuid(`${department.id}:member:${body.address ?? body.userId}:${Date.now()}`),
        departmentId: department.id,
        kind: body.address ? 'address' : 'user',
        address: body.address?.toLowerCase() ?? null,
        userId: body.userId ?? null,
        createdByUserId: null,
        createdAt: new Date().toISOString(),
      };
      state.members.set(department.id, [member, ...list]);
      department.memberCount = list.length + 1;
      return ok('DepartmentsController_addMember_v1', member, 201);
    },
  ),
  DepartmentsController_removeMember_v1: guarded(
    'DepartmentsController_removeMember_v1',
    (request, p) => {
      const state = org(p.organizationId);
      const department = state.departments.find((d) => d.id === request.params.departmentId);
      if (!department) return departmentNotFound();
      const list = state.members.get(department.id) ?? [];
      if (!list.some((m) => m.id === request.params.memberId))
        return apiError(404, 'department_member_not_found', 'Member not found');
      state.members.set(
        department.id,
        list.filter((m) => m.id !== request.params.memberId),
      );
      department.memberCount = list.length - 1;
      return noContent();
    },
  ),
};
