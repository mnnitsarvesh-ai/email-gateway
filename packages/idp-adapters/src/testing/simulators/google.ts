/**
 * Google Workspace simulators (design note D12): exactly the endpoints, query parameters, paging
 * and error shapes the Google adapter uses.
 *
 * - `GoogleSimulator` (prefix `/google-admin`, production origin `admin.googleapis.com`): Admin SDK
 *   Reports `activities.list` (applications `login` and `token`; `startTime`, `endTime`,
 *   `maxResults`, `pageToken`, `eventName`) and Directory (`users.list`, `users.get` by id, primary
 *   address or alias, `users.update`, `users.signOut`, `tokens.list`, `tokens.delete`,
 *   `orgunits.get`).
 * - `GmailSimulator` (prefix `/gmail`, production origin `gmail.googleapis.com`): Gmail settings
 *   `autoForwarding` (get, update), `filters` (list, get, delete) and `delegates` (list).
 *
 * Bearer tokens are checked against the token registry and every endpoint enforces its OAuth
 * scope, so missing-scope paths are real. Admin SDK calls must impersonate an administrator; Gmail
 * calls must impersonate the mailbox owner (domain-wide delegation `sub`). Errors use Google's
 * shape `{ error: { code, message, errors: [{ domain, reason, message }], status } }`, including
 * the throttling and quota reasons `rateLimitExceeded`, `userRateLimitExceeded`,
 * `dailyLimitExceeded` and `quotaExceeded` (injected through the script API).
 */
import { json, type SimRequest, type SimResponse, type Simulator } from './server';
import type { SimScript } from './script';
import { hasPermission, type ResolvedToken } from './tokens';
import type { GsActivity, GsCustomer, GsGmailSettings, GsUser } from './google-types';

const SCOPE = 'https://www.googleapis.com/auth/';
export const GOOGLE_SIM_SCOPES = {
  reportsAudit: `${SCOPE}admin.reports.audit.readonly`,
  directoryUserReadonly: `${SCOPE}admin.directory.user.readonly`,
  directoryUser: `${SCOPE}admin.directory.user`,
  directoryUserSecurity: `${SCOPE}admin.directory.user.security`,
  directoryOrgunitReadonly: `${SCOPE}admin.directory.orgunit.readonly`,
  directoryOrgunit: `${SCOPE}admin.directory.orgunit`,
  gmailSettingsBasic: `${SCOPE}gmail.settings.basic`,
  gmailSettingsSharing: `${SCOPE}gmail.settings.sharing`,
} as const;

const DAY_MS = 24 * 60 * 60 * 1000;
const STATUS_OF: Readonly<Record<number, string>> = {
  400: 'INVALID_ARGUMENT',
  401: 'UNAUTHENTICATED',
  403: 'PERMISSION_DENIED',
  404: 'NOT_FOUND',
  409: 'ABORTED',
  412: 'FAILED_PRECONDITION',
  429: 'RESOURCE_EXHAUSTED',
};
const REASON_OF: Readonly<Record<number, string>> = {
  400: 'invalid',
  401: 'authError',
  403: 'forbidden',
  404: 'notFound',
  409: 'conflict',
  412: 'conditionNotMet',
  429: 'rateLimitExceeded',
};

/** Google error body; a Google status code (`PERMISSION_DENIED`) given as `code` is kept. */
export function googleErrorBody(status: number, code?: string, reason?: string): unknown {
  const googleStatus =
    code && /^[A-Z_]{3,64}$/.test(code)
      ? code
      : (STATUS_OF[status] ?? (status >= 500 ? 'UNAVAILABLE' : 'UNKNOWN'));
  const googleReason = reason ?? REASON_OF[status] ?? (status >= 500 ? 'backendError' : 'unknown');
  return {
    error: {
      code: status,
      message: 'Simulated error.',
      errors: [{ domain: 'global', reason: googleReason, message: 'Simulated error.' }],
      status: googleStatus,
    },
  };
}

function encodePage(offset: number): string {
  return Buffer.from(`g:${offset}`, 'utf8').toString('base64url');
}

function decodePage(token: string | null): number | null {
  if (token === null || token === '') return 0;
  const match = /^g:(\d+)$/.exec(Buffer.from(token, 'base64url').toString('utf8'));
  return match ? Number(match[1]) : null;
}

/** RFC 3339 with an explicit zone, as the Reports API requires. */
function parseRfc3339(value: string | null): number | null {
  if (value === null) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    return null;
  }
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : ms;
}

function publicUser(user: GsUser): Record<string, unknown> {
  return {
    kind: 'admin#directory#user',
    id: user.id,
    primaryEmail: user.primaryEmail,
    aliases: user.aliases,
    suspended: user.suspended,
    archived: user.archived ?? false,
    orgUnitPath: user.orgUnitPath,
    changePasswordAtNextLogin: user.changePasswordAtNextLogin,
    isAdmin: user.isAdmin,
    isDelegatedAdmin: user.isDelegatedAdmin ?? false,
  };
}

abstract class GoogleBase {
  constructor(protected readonly script: SimScript) {}

  errorBody(status: number, code: string, reason?: string): unknown {
    return googleErrorBody(status, code, reason);
  }

  protected error(status: number, reason?: string, statusCode?: string): SimResponse {
    return json(status, googleErrorBody(status, statusCode, reason));
  }

  protected denied(): SimResponse {
    return this.error(403, 'insufficientPermissions', 'PERMISSION_DENIED');
  }

  protected customers(): GsCustomer[] {
    return this.script.dataset.google?.customers ?? [];
  }

  protected authenticate(
    request: SimRequest,
  ): { token: ResolvedToken; customer: GsCustomer } | SimResponse {
    const header = request.headers.authorization;
    const token = this.script.tokens.resolve(
      typeof header === 'string' ? header : undefined,
      this.customers()[0]?.customerId,
    );
    if (!token || (token.resource !== null && token.resource !== 'google')) {
      return this.error(401, 'authError', 'UNAUTHENTICATED');
    }
    const customer = this.customers().find((c) => c.customerId === token.directoryId);
    if (!customer) return this.error(401, 'authError', 'UNAUTHENTICATED');
    return { token, customer };
  }

  protected findUser(customer: GsCustomer, key: string): GsUser | undefined {
    const lowered = key.toLowerCase();
    return customer.users.find(
      (u) =>
        u.id === key ||
        u.primaryEmail.toLowerCase() === lowered ||
        u.aliases.some((alias) => alias.toLowerCase() === lowered),
    );
  }
}

export class GoogleSimulator extends GoogleBase implements Simulator {
  readonly name = 'google-admin';

  constructor(
    script: SimScript,
    readonly prefix = '/google-admin',
  ) {
    super(script);
  }

  handle(request: SimRequest): SimResponse {
    const auth = this.authenticate(request);
    if ('status' in auth) return auth;
    const { token, customer } = auth;
    // Admin SDK calls impersonate an administrator of the customer (domain-wide delegation).
    let actor: GsUser | undefined;
    if (token.subject !== undefined) {
      actor = this.findUser(customer, token.subject);
      if (!actor || !(actor.isAdmin || actor.isDelegatedAdmin)) {
        return { ...this.error(403, 'forbidden', 'PERMISSION_DENIED'), subject: token.subject };
      }
    }
    const response = this.route(request, token, customer, actor);
    return token.subject ? { ...response, subject: token.subject } : response;
  }

  private route(
    request: SimRequest,
    token: ResolvedToken,
    customer: GsCustomer,
    actor: GsUser | undefined,
  ): SimResponse {
    const p = request.path;
    const m = request.method;
    let match: RegExpExecArray | null;

    if (
      (match = /^\/admin\/reports\/v1\/activity\/users\/([^/]+)\/applications\/([^/]+)$/.exec(p))
    ) {
      if (m !== 'GET') return this.error(405, 'methodNotAllowed');
      if (!hasPermission(token, [GOOGLE_SIM_SCOPES.reportsAudit])) return this.denied();
      return this.activities(
        request,
        customer,
        decodeURIComponent(match[1] as string),
        decodeURIComponent(match[2] as string),
      );
    }
    if (p === '/admin/directory/v1/users') {
      if (m !== 'GET') return this.error(405, 'methodNotAllowed');
      if (
        !hasPermission(token, [
          GOOGLE_SIM_SCOPES.directoryUserReadonly,
          GOOGLE_SIM_SCOPES.directoryUser,
        ])
      ) {
        return this.denied();
      }
      return this.listUsers(request, customer);
    }
    if ((match = /^\/admin\/directory\/v1\/users\/([^/]+)$/.exec(p))) {
      const user = this.findUser(customer, decodeURIComponent(match[1] as string));
      if (m === 'GET') {
        if (
          !hasPermission(token, [
            GOOGLE_SIM_SCOPES.directoryUserReadonly,
            GOOGLE_SIM_SCOPES.directoryUser,
          ])
        ) {
          return this.denied();
        }
        if (!user) return this.error(404, 'notFound', 'NOT_FOUND');
        return json(200, publicUser(this.script.readBack(`user:${user.id}`, user)));
      }
      if (m === 'PUT' || m === 'PATCH') {
        if (!hasPermission(token, [GOOGLE_SIM_SCOPES.directoryUser])) return this.denied();
        if (!user) return this.error(404, 'notFound', 'NOT_FOUND');
        return this.updateUser(customer, user, actor, request.body);
      }
      return this.error(405, 'methodNotAllowed');
    }
    if ((match = /^\/admin\/directory\/v1\/users\/([^/]+)\/signOut$/.exec(p))) {
      if (m !== 'POST') return this.error(405, 'methodNotAllowed');
      if (!hasPermission(token, [GOOGLE_SIM_SCOPES.directoryUserSecurity])) return this.denied();
      const user = this.findUser(customer, decodeURIComponent(match[1] as string));
      if (!user) return this.error(404, 'notFound', 'NOT_FOUND');
      if (!this.mayWrite(actor, user)) return this.error(403, 'forbidden', 'PERMISSION_DENIED');
      return json(204);
    }
    if ((match = /^\/admin\/directory\/v1\/users\/([^/]+)\/tokens(?:\/([^/]+))?$/.exec(p))) {
      if (!hasPermission(token, [GOOGLE_SIM_SCOPES.directoryUserSecurity])) return this.denied();
      const user = this.findUser(customer, decodeURIComponent(match[1] as string));
      if (!user) return this.error(404, 'notFound', 'NOT_FOUND');
      const tokens = (customer.tokens[user.id] ??= []);
      const clientId = match[2] === undefined ? undefined : decodeURIComponent(match[2]);
      if (m === 'GET' && clientId === undefined) {
        const visible = this.script.readBack(`tokens:${user.id}`, tokens);
        return json(200, {
          kind: 'admin#directory#tokenList',
          items: visible.map((t) => ({ kind: 'admin#directory#token', userKey: user.id, ...t })),
        });
      }
      if (m === 'DELETE' && clientId !== undefined) {
        if (!this.mayWrite(actor, user)) return this.error(403, 'forbidden', 'PERMISSION_DENIED');
        const index = tokens.findIndex((t) => t.clientId === clientId);
        if (index < 0) return this.error(404, 'notFound', 'NOT_FOUND');
        this.script.beforeWrite([[`tokens:${user.id}`, tokens]]);
        tokens.splice(index, 1);
        return json(204);
      }
      return this.error(405, 'methodNotAllowed');
    }
    if ((match = /^\/admin\/directory\/v1\/customer\/([^/]+)\/orgunits\/(.+)$/.exec(p))) {
      if (m !== 'GET') return this.error(405, 'methodNotAllowed');
      if (
        !hasPermission(token, [
          GOOGLE_SIM_SCOPES.directoryOrgunitReadonly,
          GOOGLE_SIM_SCOPES.directoryOrgunit,
        ])
      ) {
        return this.denied();
      }
      const customerKey = decodeURIComponent(match[1] as string);
      if (customerKey !== 'my_customer' && customerKey !== customer.customerId) {
        return this.error(403, 'forbidden', 'PERMISSION_DENIED');
      }
      const path = `/${decodeURIComponent(match[2] as string).replace(/^\/+/, '')}`;
      const unit = customer.orgUnits.find((u) => u.orgUnitPath === path);
      return unit
        ? json(200, { kind: 'admin#directory#orgUnit', ...unit })
        : this.error(404, 'notFound', 'NOT_FOUND');
    }
    return this.error(404, 'notFound', 'NOT_FOUND');
  }

  /** A delegated administrator may not change a super administrator. */
  private mayWrite(actor: GsUser | undefined, target: GsUser): boolean {
    return !(target.isAdmin && actor !== undefined && !actor.isAdmin);
  }

  private activities(
    request: SimRequest,
    customer: GsCustomer,
    userKey: string,
    application: string,
  ): SimResponse {
    if (application !== 'login' && application !== 'token') {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const q = request.query;
    const start = q.has('startTime') ? parseRfc3339(q.get('startTime')) : null;
    const end = q.has('endTime') ? parseRfc3339(q.get('endTime')) : null;
    if ((q.has('startTime') && start === null) || (q.has('endTime') && end === null)) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const now = this.script.now();
    const retentionMs = (customer.reportsRetentionDays ?? 180) * DAY_MS;
    if (start !== null && (start < now - retentionMs || (end !== null && start > end))) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const maxResults = Number(q.get('maxResults') ?? '1000');
    if (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > 1000) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const offset = decodePage(q.get('pageToken'));
    if (offset === null) return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    const eventName = q.get('eventName');
    const all = customer.activities
      .filter((activity: GsActivity) => {
        if (activity.id.applicationName !== application) return false;
        const time = Date.parse(activity.id.time);
        if (start !== null && time < start) return false;
        if (end !== null && time > end) return false;
        if (userKey !== 'all') {
          const user = this.findUser(customer, userKey);
          if (!user || activity.actor.profileId !== user.id) return false;
        }
        return eventName === null || activity.events.some((e) => e.name === eventName);
      })
      // Newest first, as the Reports API answers.
      .sort((a, b) => Date.parse(b.id.time) - Date.parse(a.id.time));
    const slice = all.slice(offset, offset + maxResults);
    const body: Record<string, unknown> = { kind: 'admin#reports#activities' };
    if (slice.length > 0) {
      body.items = slice.map((activity) => ({ kind: 'admin#reports#activity', ...activity }));
    }
    if (offset + maxResults < all.length) body.nextPageToken = encodePage(offset + maxResults);
    return json(200, body);
  }

  private listUsers(request: SimRequest, customer: GsCustomer): SimResponse {
    const q = request.query;
    const customerKey = q.get('customer');
    if (customerKey !== 'my_customer' && customerKey !== customer.customerId) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const query = q.get('query');
    if (query !== null && query !== 'isSuspended=false') {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const maxResults = Number(q.get('maxResults') ?? '100');
    if (!Number.isInteger(maxResults) || maxResults < 1 || maxResults > 500) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    const offset = decodePage(q.get('pageToken'));
    if (offset === null) return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    const users = customer.users
      .map((u) => this.script.readBack(`user:${u.id}`, u))
      .filter((u) => query === null || !u.suspended);
    const slice = users.slice(offset, offset + maxResults);
    const body: Record<string, unknown> = {
      kind: 'admin#directory#users',
      users: slice.map(publicUser),
    };
    if (offset + maxResults < users.length) body.nextPageToken = encodePage(offset + maxResults);
    return json(200, body);
  }

  private updateUser(
    customer: GsCustomer,
    user: GsUser,
    actor: GsUser | undefined,
    body: unknown,
  ): SimResponse {
    if (!body || typeof body !== 'object') return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    const patch = body as Record<string, unknown>;
    const keys = Object.keys(patch);
    const allowed = new Set(['suspended', 'changePasswordAtNextLogin', 'orgUnitPath']);
    if (keys.length === 0 || keys.some((key) => !allowed.has(key))) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    if (
      (patch.suspended !== undefined && typeof patch.suspended !== 'boolean') ||
      (patch.changePasswordAtNextLogin !== undefined &&
        typeof patch.changePasswordAtNextLogin !== 'boolean') ||
      (patch.orgUnitPath !== undefined && typeof patch.orgUnitPath !== 'string')
    ) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    if (!this.mayWrite(actor, user)) return this.error(403, 'forbidden', 'PERMISSION_DENIED');
    if (
      typeof patch.orgUnitPath === 'string' &&
      !customer.orgUnits.some((unit) => unit.orgUnitPath === patch.orgUnitPath)
    ) {
      return this.error(400, 'invalid', 'INVALID_ARGUMENT');
    }
    this.script.beforeWrite([[`user:${user.id}`, user]]);
    if (typeof patch.suspended === 'boolean') user.suspended = patch.suspended;
    if (typeof patch.changePasswordAtNextLogin === 'boolean') {
      user.changePasswordAtNextLogin = patch.changePasswordAtNextLogin;
    }
    if (typeof patch.orgUnitPath === 'string') user.orgUnitPath = patch.orgUnitPath;
    return json(200, publicUser(user));
  }
}

export class GmailSimulator extends GoogleBase implements Simulator {
  readonly name = 'gmail';

  constructor(
    script: SimScript,
    readonly prefix = '/gmail',
  ) {
    super(script);
  }

  handle(request: SimRequest): SimResponse {
    const auth = this.authenticate(request);
    if ('status' in auth) return auth;
    const { token, customer } = auth;
    const match =
      /^\/gmail\/v1\/users\/([^/]+)\/settings\/(autoForwarding|filters|delegates)(?:\/([^/]+))?$/.exec(
        request.path,
      );
    if (!match) return this.error(404, 'notFound', 'NOT_FOUND');
    const userKey = decodeURIComponent(match[1] as string);
    // The mailbox owner is impersonated: `me` or the owner's own address/id must match `sub`.
    let user: GsUser | undefined;
    if (userKey === 'me') {
      user = token.subject === undefined ? undefined : this.findUser(customer, token.subject);
      if (!user) return this.error(400, 'failedPrecondition', 'FAILED_PRECONDITION');
    } else {
      user = this.findUser(customer, userKey);
      if (!user) return this.error(404, 'notFound', 'NOT_FOUND');
      if (token.subject !== undefined && this.findUser(customer, token.subject) !== user) {
        return { ...this.error(403, 'forbidden', 'PERMISSION_DENIED'), subject: token.subject };
      }
    }
    const subject = token.subject;
    const respond = (response: SimResponse): SimResponse =>
      subject ? { ...response, subject } : response;
    if (user.suspended || user.gmailEnabled === false) {
      return respond(this.error(400, 'failedPrecondition', 'FAILED_PRECONDITION'));
    }
    const settings = (customer.gmail[user.id] ??= {
      autoForwarding: { enabled: false },
      filters: [],
      delegates: [],
    });
    const kind = match[2] as 'autoForwarding' | 'filters' | 'delegates';
    const id = match[3] === undefined ? undefined : decodeURIComponent(match[3]);
    return respond(this.settings(token, request, user, settings, kind, id));
  }

  private settings(
    token: ResolvedToken,
    request: SimRequest,
    user: GsUser,
    settings: GsGmailSettings,
    kind: 'autoForwarding' | 'filters' | 'delegates',
    id: string | undefined,
  ): SimResponse {
    const m = request.method;
    const basic = GOOGLE_SIM_SCOPES.gmailSettingsBasic;
    const sharing = GOOGLE_SIM_SCOPES.gmailSettingsSharing;
    if (kind === 'autoForwarding') {
      if (id !== undefined) return this.error(404, 'notFound', 'NOT_FOUND');
      const key = `autofwd:${user.id}`;
      if (m === 'GET') {
        if (!hasPermission(token, [basic, sharing])) return this.denied();
        return json(200, this.script.readBack(key, settings.autoForwarding));
      }
      if (m === 'PUT') {
        if (!hasPermission(token, [sharing])) return this.denied();
        const body = request.body as Record<string, unknown> | undefined;
        if (!body || typeof body.enabled !== 'boolean') {
          return this.error(400, 'invalid', 'INVALID_ARGUMENT');
        }
        if (body.enabled && typeof body.emailAddress !== 'string') {
          return this.error(400, 'invalid', 'INVALID_ARGUMENT');
        }
        this.script.beforeWrite([[key, settings.autoForwarding]]);
        settings.autoForwarding = body.enabled
          ? {
              enabled: true,
              emailAddress: body.emailAddress as string,
              disposition: 'leaveInInbox',
            }
          : { enabled: false };
        return json(200, settings.autoForwarding);
      }
      return this.error(405, 'methodNotAllowed');
    }
    if (kind === 'delegates') {
      if (id !== undefined || m !== 'GET') return this.error(405, 'methodNotAllowed');
      if (!hasPermission(token, [basic, sharing])) return this.denied();
      return json(200, { delegates: settings.delegates });
    }
    // filters
    if (id === undefined) {
      if (m !== 'GET') return this.error(405, 'methodNotAllowed');
      if (!hasPermission(token, [basic])) return this.denied();
      const visible = this.script.readBack(`filters:${user.id}`, settings.filters);
      return json(200, visible.length > 0 ? { filter: visible } : {});
    }
    const index = settings.filters.findIndex((f) => f.id === id);
    const key = `filter:${user.id}:${id}`;
    if (m === 'GET') {
      if (!hasPermission(token, [basic])) return this.denied();
      const visible = this.script.readBack(key, index >= 0 ? settings.filters[index] : undefined);
      return visible ? json(200, visible) : this.error(404, 'notFound', 'NOT_FOUND');
    }
    if (m === 'DELETE') {
      if (!hasPermission(token, [basic])) return this.denied();
      if (index < 0) return this.error(404, 'notFound', 'NOT_FOUND');
      this.script.beforeWrite([
        [key, settings.filters[index]],
        [`filters:${user.id}`, settings.filters],
      ]);
      settings.filters.splice(index, 1);
      return json(204);
    }
    return this.error(405, 'methodNotAllowed');
  }
}

export const createGoogleSimulator = (script: SimScript): Simulator => new GoogleSimulator(script);
export const createGmailSimulator = (script: SimScript): Simulator => new GmailSimulator(script);

/** Both Google simulators (registered in `ALL_SIMULATORS` with one line). */
export const GOOGLE_SIMULATORS = [createGoogleSimulator, createGmailSimulator] as const;
