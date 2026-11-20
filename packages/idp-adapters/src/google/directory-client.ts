/**
 * Admin SDK Directory calls of the Google adapter (design note D8.3, D9, §3.3): users (list, get,
 * update, sign-out), OAuth tokens (list, delete) and organizational units (get). Every call
 * impersonates the delegated administrator of the profile's grant (`subjectEmail`). Plain HTTPS
 * through `ProviderSession`; path templates are logged, never user keys or queries.
 */
import { ProviderCallError } from '../core/errors';
import type { ProviderSession } from '../core/session';
import { ACTIVE_USERS_QUERY } from './constants';
import {
  directoryUserSchema,
  orgUnitSchema,
  tokensSchema,
  usersPageSchema,
  type DirectoryToken,
  type DirectoryUser,
  type UsersPage,
} from './schemas';

const BASE = '/admin/directory/v1';
const enc = encodeURIComponent;

function isNotFound(error: unknown): boolean {
  return error instanceof ProviderCallError && error.code === 'not_found';
}

export class DirectoryClient {
  constructor(
    private readonly session: ProviderSession,
    /** Permission profile whose grant (and delegated administrator) the calls use. */
    readonly profile: string,
  ) {}

  private get subject(): string | undefined {
    return this.session.grant(this.profile)?.subjectEmail ?? undefined;
  }

  private base() {
    const subject = this.subject;
    return {
      family: 'google_directory' as const,
      profile: this.profile,
      resource: 'google' as const,
      ...(subject ? { subject } : {}),
    };
  }

  /** One page of the customer's active users (`customer=my_customer`, D8.3). */
  async listUsers(maxResults: number, pageToken?: string): Promise<UsersPage> {
    const params = new URLSearchParams({
      customer: 'my_customer',
      maxResults: String(Math.max(1, Math.min(500, maxResults))),
      query: ACTIVE_USERS_QUERY,
    });
    if (pageToken) params.set('pageToken', pageToken);
    const response = await this.session.call({
      ...this.base(),
      method: 'GET',
      url: `${BASE}/users?${params.toString()}`,
      pathTemplate: `${BASE}/users`,
      schema: usersPageSchema,
    });
    return response.data;
  }

  /** `users.get` by id, primary address or alias; `null` when the user does not exist. */
  async getUser(userKey: string): Promise<DirectoryUser | null> {
    try {
      const response = await this.session.call({
        ...this.base(),
        method: 'GET',
        url: `${BASE}/users/${enc(userKey)}`,
        pathTemplate: `${BASE}/users/{userKey}`,
        schema: directoryUserSchema,
      });
      return response.data;
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  }

  /** `users.update` with partial fields (patch semantics). */
  async updateUser(
    userKey: string,
    body: { suspended?: boolean; changePasswordAtNextLogin?: boolean; orgUnitPath?: string },
  ): Promise<void> {
    await this.session.call({
      ...this.base(),
      method: 'PUT',
      url: `${BASE}/users/${enc(userKey)}`,
      pathTemplate: `${BASE}/users/{userKey}`,
      body,
    });
  }

  async signOut(userKey: string): Promise<void> {
    await this.session.call({
      ...this.base(),
      method: 'POST',
      url: `${BASE}/users/${enc(userKey)}/signOut`,
      pathTemplate: `${BASE}/users/{userKey}/signOut`,
    });
  }

  async listTokens(userKey: string): Promise<DirectoryToken[]> {
    const response = await this.session.call({
      ...this.base(),
      method: 'GET',
      url: `${BASE}/users/${enc(userKey)}/tokens`,
      pathTemplate: `${BASE}/users/{userKey}/tokens`,
      schema: tokensSchema,
    });
    return response.data.items ?? [];
  }

  /** Deletes one OAuth token; `false` when it no longer exists. */
  async deleteToken(userKey: string, clientId: string): Promise<boolean> {
    try {
      await this.session.call({
        ...this.base(),
        method: 'DELETE',
        url: `${BASE}/users/${enc(userKey)}/tokens/${enc(clientId)}`,
        pathTemplate: `${BASE}/users/{userKey}/tokens/{clientId}`,
      });
      return true;
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
  }

  /** Whether an organizational unit exists (`orgunits.get`, read-only). */
  async orgUnitExists(orgUnitPath: string): Promise<boolean> {
    const relative = orgUnitPath.replace(/^\/+/, '');
    const encoded = relative.split('/').map(enc).join('/');
    try {
      await this.session.call({
        ...this.base(),
        method: 'GET',
        url: `${BASE}/customer/my_customer/orgunits/${encoded}`,
        pathTemplate: `${BASE}/customer/my_customer/orgunits/{orgUnitPath}`,
        schema: orgUnitSchema,
      });
      return true;
    } catch (error) {
      if (isNotFound(error)) return false;
      throw error;
    }
  }
}
