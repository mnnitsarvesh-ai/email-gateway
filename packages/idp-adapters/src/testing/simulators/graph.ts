/**
 * Microsoft Graph v1.0 simulator (design note D12): exactly the endpoints, query parameters,
 * paging and error shapes the Microsoft adapter uses. Bearer tokens are checked against the token
 * registry and every endpoint enforces its permission, so missing-permission paths are real.
 */
import { json, type SimRequest, type SimResponse, type Simulator } from './server';
import type { SimScript } from './script';
import { hasPermission, type ResolvedToken } from './tokens';
import { matches, ODataError, parseFilter } from './odata';
import type { MsDirectory, MsMessageRule, MsUser } from './types';

const LICENSE_CODE = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant';
const DEFAULT_TOP = 100;
const MAX_TOP = 1000;

function encodeSkip(offset: number): string {
  return Buffer.from(`o:${offset}`, 'utf8').toString('base64url');
}

function decodeSkip(token: string | null): number | null {
  if (token === null) return 0;
  const text = Buffer.from(token, 'base64url').toString('utf8');
  const match = /^o:(\d+)$/.exec(text);
  return match ? Number(match[1]) : null;
}

function publicUser(user: MsUser): Record<string, unknown> {
  return {
    id: user.id,
    userPrincipalName: user.userPrincipalName,
    mail: user.mail,
    displayName: user.displayName,
    accountEnabled: user.accountEnabled,
    onPremisesSyncEnabled: user.onPremisesSyncEnabled,
    proxyAddresses: user.proxyAddresses,
  };
}

export class GraphSimulator implements Simulator {
  readonly name = 'graph';

  constructor(
    private readonly script: SimScript,
    readonly prefix = '/graph',
  ) {}

  errorBody(_status: number, code: string): unknown {
    return {
      error: { code, message: 'Simulated error.', innerError: { 'request-id': 'EXAMPLE' } },
    };
  }

  private error(status: number, code: string): SimResponse {
    return json(status, this.errorBody(status, code));
  }

  private denied(): SimResponse {
    return this.error(403, 'Authorization_RequestDenied');
  }

  private notFound(): SimResponse {
    return this.error(404, 'Request_ResourceNotFound');
  }

  private directories(): MsDirectory[] {
    return this.script.dataset.microsoft?.directories ?? [];
  }

  private authenticate(
    request: SimRequest,
  ): { token: ResolvedToken; directory: MsDirectory } | SimResponse {
    const header = request.headers.authorization;
    const token = this.script.tokens.resolve(
      typeof header === 'string' ? header : undefined,
      this.directories()[0]?.tenantId,
    );
    if (!token || (token.resource !== null && token.resource !== 'graph')) {
      return this.error(401, 'InvalidAuthenticationToken');
    }
    const directory = this.directories().find((d) => d.tenantId === token.directoryId);
    if (!directory) return this.error(401, 'InvalidAuthenticationToken');
    return { token, directory };
  }

  private page<T>(request: SimRequest, items: readonly T[]): SimResponse {
    const top = Math.min(Number(request.query.get('$top') ?? DEFAULT_TOP) || DEFAULT_TOP, MAX_TOP);
    const offset = decodeSkip(request.query.get('$skiptoken'));
    if (offset === null) return this.error(400, 'Request_BadRequest');
    const slice = items.slice(offset, offset + top);
    const body: Record<string, unknown> = { value: slice };
    if (offset + top < items.length) {
      const params = new URLSearchParams(request.query);
      params.set('$skiptoken', encodeSkip(offset + top));
      body['@odata.nextLink'] = `${request.publicBase}${request.path}?${params.toString()}`;
    }
    return json(200, body);
  }

  private filtered<T>(request: SimRequest, items: readonly T[]): T[] | SimResponse {
    try {
      const clauses = parseFilter(request.query.get('$filter'));
      return items.filter((item) => matches(item, clauses));
    } catch (error) {
      if (error instanceof ODataError) return this.error(400, 'Request_UnsupportedQuery');
      throw error;
    }
  }

  private user(directory: MsDirectory, key: string): MsUser | undefined {
    const lowered = decodeURIComponent(key).toLowerCase();
    return directory.users.find(
      (u) => u.id.toLowerCase() === lowered || u.userPrincipalName.toLowerCase() === lowered,
    );
  }

  handle(request: SimRequest): SimResponse {
    const auth = this.authenticate(request);
    if ('status' in auth) return auth;
    const { token, directory } = auth;
    const respond = (response: SimResponse): SimResponse => ({
      ...response,
      ...(token.subject ? { subject: token.subject } : {}),
    });
    const p = request.path;
    const m = request.method;
    let match: RegExpExecArray | null;

    if (m === 'GET' && p === '/v1.0/auditLogs/signIns') {
      if (
        !hasPermission(token, ['AuditLog.Read.All']) ||
        !hasPermission(token, ['Directory.Read.All'])
      )
        return this.denied();
      if (!directory.licenses.entraP1 && !directory.licenses.entraP2)
        return this.error(403, LICENSE_CODE);
      const items = this.filtered(request, [...directory.signIns].sort(byDate('createdDateTime')));
      return Array.isArray(items) ? respond(this.page(request, items)) : items;
    }
    if (m === 'GET' && p === '/v1.0/identityProtection/riskDetections') {
      if (!hasPermission(token, ['IdentityRiskEvent.Read.All', 'IdentityRiskEvent.ReadWrite.All']))
        return this.denied();
      if (!directory.licenses.entraP1 && !directory.licenses.entraP2)
        return this.error(403, LICENSE_CODE);
      const visible = directory.riskDetections.map((d) =>
        directory.licenses.entraP2 ? d : { ...d, riskLevel: 'hidden', riskDetail: 'hidden' },
      );
      const items = this.filtered(request, visible.sort(byDate('lastUpdatedDateTime')));
      return Array.isArray(items) ? respond(this.page(request, items)) : items;
    }
    if (m === 'GET' && p === '/v1.0/auditLogs/directoryAudits') {
      if (!hasPermission(token, ['AuditLog.Read.All'])) return this.denied();
      const items = this.filtered(
        request,
        [...directory.directoryAudits].sort(byDate('activityDateTime')),
      );
      return Array.isArray(items) ? respond(this.page(request, items)) : items;
    }
    if (m === 'GET' && (match = /^\/v1\.0\/servicePrincipals\/([^/]+)$/.exec(p))) {
      if (!hasPermission(token, ['Application.Read.All', 'Directory.Read.All']))
        return this.denied();
      const spId = decodeURIComponent(match[1] as string);
      const sp = directory.servicePrincipals.find((s) => s.id === spId);
      return sp ? respond(json(200, sp)) : this.notFound();
    }
    if (m === 'GET' && p === '/v1.0/users') {
      if (!hasPermission(token, ['User.Read.All', 'Directory.Read.All', 'User.ReadWrite.All']))
        return this.denied();
      const filter = request.query.get('$filter') ?? '';
      if (/\/any\(/.test(filter)) {
        const consistency = request.headers.consistencylevel;
        if (consistency !== 'eventual') return this.error(400, 'Request_UnsupportedQuery');
      }
      const items = this.filtered(
        request,
        directory.users.map((u) => publicUser(this.script.readBack(`user:${u.id}`, u))),
      );
      return Array.isArray(items) ? respond(this.page(request, items)) : items;
    }
    if ((match = /^\/v1\.0\/users\/([^/]+)$/.exec(p))) {
      const user = this.user(directory, match[1] as string);
      if (m === 'GET') {
        if (!hasPermission(token, ['User.Read.All', 'Directory.Read.All', 'User.ReadWrite.All']))
          return this.denied();
        if (!user) return this.notFound();
        return respond(json(200, publicUser(this.script.readBack(`user:${user.id}`, user))));
      }
      if (m === 'PATCH') return respond(this.patchUser(token, user, request.body));
    }
    if (m === 'POST' && (match = /^\/v1\.0\/users\/([^/]+)\/revokeSignInSessions$/.exec(p))) {
      if (!hasPermission(token, ['User.RevokeSessions.All', 'User.ReadWrite.All']))
        return this.denied();
      const user = this.user(directory, match[1] as string);
      if (!user) return this.notFound();
      return respond(json(200, { '@odata.context': 'EXAMPLE', value: true }));
    }
    if (
      (match = /^\/v1\.0\/users\/([^/]+)\/mailFolders\/inbox\/messageRules(?:\/([^/]+))?$/.exec(p))
    ) {
      const ruleId = match[2] === undefined ? undefined : decodeURIComponent(match[2]);
      return respond(this.rules(token, directory, m, match[1] as string, ruleId, request.body));
    }
    if (m === 'GET' && (match = /^\/v1\.0\/users\/([^/]+)\/oauth2PermissionGrants$/.exec(p))) {
      if (
        !hasPermission(token, [
          'DelegatedPermissionGrant.ReadWrite.All',
          'DelegatedPermissionGrant.Read.All',
          'Directory.Read.All',
        ])
      ) {
        return this.denied();
      }
      const user = this.user(directory, match[1] as string);
      if (!user) return this.notFound();
      const grants = directory.oauth2PermissionGrants.filter((g) => g.principalId === user.id);
      return respond(this.page(request, this.script.readBack(`grants:${user.id}`, grants)));
    }
    if (m === 'DELETE' && (match = /^\/v1\.0\/oauth2PermissionGrants\/([^/]+)$/.exec(p))) {
      if (!hasPermission(token, ['DelegatedPermissionGrant.ReadWrite.All'])) return this.denied();
      const grantId = decodeURIComponent(match[1] as string);
      const index = directory.oauth2PermissionGrants.findIndex((g) => g.id === grantId);
      if (index < 0) return this.notFound();
      const grant = directory.oauth2PermissionGrants[index];
      if (grant?.principalId) {
        const before = directory.oauth2PermissionGrants.filter(
          (g) => g.principalId === grant.principalId,
        );
        this.script.beforeWrite([[`grants:${grant.principalId}`, before]]);
      }
      directory.oauth2PermissionGrants.splice(index, 1);
      return respond(json(204));
    }
    if ((match = /^\/v1\.0\/groups\/([^/]+)(\/members(?:\/\$ref|\/([^/]+)\/\$ref)?)?$/.exec(p))) {
      return respond(
        this.groups(
          token,
          directory,
          request,
          decodeURIComponent(match[1] as string),
          match[2],
          match[3] === undefined ? undefined : decodeURIComponent(match[3]),
        ),
      );
    }
    return this.error(404, 'Request_ResourceNotFound');
  }

  private patchUser(token: ResolvedToken, user: MsUser | undefined, body: unknown): SimResponse {
    if (!body || typeof body !== 'object') return this.error(400, 'Request_BadRequest');
    const patch = body as { accountEnabled?: unknown; passwordProfile?: unknown };
    const keys = Object.keys(patch);
    if (keys.length === 0 || keys.some((k) => k !== 'accountEnabled' && k !== 'passwordProfile')) {
      return this.error(400, 'Request_BadRequest');
    }
    if (
      patch.accountEnabled !== undefined &&
      !hasPermission(token, ['User.EnableDisableAccount.All', 'User.ReadWrite.All'])
    ) {
      return this.denied();
    }
    if (
      patch.passwordProfile !== undefined &&
      !hasPermission(token, ['User-PasswordProfile.ReadWrite.All', 'User.ReadWrite.All'])
    ) {
      return this.denied();
    }
    if (!user) return this.notFound();
    if (user.privileged) return this.denied(); // needs a directory role for the app
    if (patch.passwordProfile !== undefined && user.onPremisesSyncEnabled) {
      return this.error(400, 'Request_BadRequest');
    }
    this.script.beforeWrite([[`user:${user.id}`, user]]);
    if (typeof patch.accountEnabled === 'boolean') user.accountEnabled = patch.accountEnabled;
    if (patch.passwordProfile && typeof patch.passwordProfile === 'object') {
      const force = (patch.passwordProfile as { forceChangePasswordNextSignIn?: unknown })
        .forceChangePasswordNextSignIn;
      user.passwordProfile = { forceChangePasswordNextSignIn: force === true };
    }
    return json(204);
  }

  private rules(
    token: ResolvedToken,
    directory: MsDirectory,
    method: string,
    userKey: string,
    ruleId: string | undefined,
    body: unknown,
  ): SimResponse {
    const write = method !== 'GET';
    const allowed = write
      ? hasPermission(token, ['MailboxSettings.ReadWrite'])
      : hasPermission(token, ['MailboxSettings.Read', 'MailboxSettings.ReadWrite']);
    if (!allowed) return this.denied();
    const user = this.user(directory, userKey);
    if (!user) return this.notFound();
    const rules = (directory.messageRules[user.id] ??= []);
    if (ruleId === undefined) {
      if (method !== 'GET') return this.error(405, 'Request_BadRequest');
      return json(200, { value: this.script.readBack(`rules:${user.id}`, rules) });
    }
    const index = rules.findIndex((r) => r.id === ruleId);
    const key = `rule:${user.id}:${ruleId}`;
    if (method === 'GET') {
      const current: MsMessageRule | undefined = index >= 0 ? rules[index] : undefined;
      const visible = this.script.readBack<MsMessageRule | undefined>(key, current);
      return visible ? json(200, visible) : this.notFound();
    }
    if (index < 0) return this.notFound();
    const rule = rules[index] as MsMessageRule;
    if (method === 'PATCH') {
      const patch = body as { isEnabled?: unknown } | undefined;
      if (!patch || typeof patch.isEnabled !== 'boolean' || Object.keys(patch).length !== 1) {
        return this.error(400, 'Request_BadRequest');
      }
      this.script.beforeWrite([
        [key, rule],
        [`rules:${user.id}`, rules],
      ]);
      rule.isEnabled = patch.isEnabled;
      return json(200, rule);
    }
    if (method === 'DELETE') {
      this.script.beforeWrite([
        [key, rule],
        [`rules:${user.id}`, rules],
      ]);
      rules.splice(index, 1);
      return json(204);
    }
    return this.error(405, 'Request_BadRequest');
  }

  private groups(
    token: ResolvedToken,
    directory: MsDirectory,
    request: SimRequest,
    groupId: string,
    membersPart: string | undefined,
    memberId: string | undefined,
  ): SimResponse {
    const group = directory.groups.find((g) => g.id === groupId);
    const method = request.method;
    if (membersPart === undefined) {
      if (method !== 'GET') return this.error(405, 'Request_BadRequest');
      if (
        !hasPermission(token, [
          'GroupMember.Read.All',
          'GroupMember.ReadWrite.All',
          'Group.Read.All',
          'Directory.Read.All',
        ])
      ) {
        return this.denied();
      }
      return group ? json(200, { id: group.id, displayName: group.displayName }) : this.notFound();
    }
    if (method === 'GET' && membersPart === '/members') {
      if (
        !hasPermission(token, [
          'GroupMember.Read.All',
          'GroupMember.ReadWrite.All',
          'Group.Read.All',
          'Directory.Read.All',
        ])
      ) {
        return this.denied();
      }
      if (!group) return this.notFound();
      let clauses;
      try {
        clauses = parseFilter(request.query.get('$filter'));
      } catch {
        return this.error(400, 'Request_UnsupportedQuery');
      }
      const members = group.members
        .filter((id) => this.script.readBack(`member:${group.id}:${id}`, true))
        .map((id) => ({ id }));
      // Members removed while a read-back is delayed are still listed.
      for (const [key, view] of this.script.staleViews) {
        const prefix = `member:${group.id}:`;
        if (key.startsWith(prefix) && view.value === true && view.remaining > 0) {
          const id = key.slice(prefix.length);
          if (!group.members.includes(id)) {
            view.remaining -= 1;
            members.push({ id });
          }
        }
      }
      return json(200, { value: members.filter((member) => matches(member, clauses)) });
    }
    if (!hasPermission(token, ['GroupMember.ReadWrite.All'])) return this.denied();
    if (!group) return this.notFound();
    if (method === 'POST' && membersPart === '/members/$ref') {
      const ref = (request.body as { '@odata.id'?: unknown } | undefined)?.['@odata.id'];
      const id =
        typeof ref === 'string' ? /\/directoryObjects\/([^/]+)$/.exec(ref)?.[1] : undefined;
      if (!id) return this.error(400, 'Request_BadRequest');
      if (!directory.users.some((u) => u.id === id)) return this.notFound();
      if (group.members.includes(id)) return this.error(400, 'Request_BadRequest');
      this.script.beforeWrite([[`member:${group.id}:${id}`, false]]);
      group.members.push(id);
      return json(204);
    }
    if (method === 'DELETE' && memberId !== undefined) {
      const index = group.members.indexOf(memberId);
      if (index < 0) return this.notFound();
      this.script.beforeWrite([[`member:${group.id}:${memberId}`, true]]);
      group.members.splice(index, 1);
      return json(204);
    }
    return this.error(405, 'Request_BadRequest');
  }
}

function byDate<K extends string>(field: K) {
  return (a: Record<K, string>, b: Record<K, string>) =>
    Date.parse(a[field]) - Date.parse(b[field]);
}

export const createGraphSimulator = (script: SimScript): Simulator => new GraphSimulator(script);
