/**
 * Microsoft Graph v1.0 calls of the adapter (design note §3.2, §3.3, D9). Plain HTTPS through
 * `ProviderSession` (budget, token, allow-listed origin); no vendor SDK. Path templates are logged,
 * never concrete paths or queries.
 */
import { ProviderCallError } from '../core/errors';
import type { ProviderSession } from '../core/session';
import { MICROSOFT_PROFILES } from '../requirements';
import {
  graphPageSchema,
  graphUserSchema,
  groupSchema,
  membersSchema,
  messageRuleSchema,
  messageRulesSchema,
  oauthGrantsSchema,
  revokeSessionsSchema,
  servicePrincipalSchema,
  type GraphPage,
  type GraphUser,
} from './schemas';

export const GRAPH_USER_SELECT = 'id,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled';

const enc = encodeURIComponent;

/** OData string literal (single quotes doubled). */
export function odataString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export class GraphClient {
  constructor(
    private readonly session: ProviderSession,
    /** The HTTP client's same-origin check of provider links (throws `blocked_host`). */
    private readonly relativize: (link: string) => string,
  ) {}

  private get telemetry() {
    return { profile: MICROSOFT_PROFILES.telemetry, resource: 'graph' as const };
  }

  /** One page of a collection (first page path or a followed `@odata.nextLink`). */
  async page(
    url: string,
    pathTemplate: string,
    profile: string = MICROSOFT_PROFILES.telemetry,
    headers?: Record<string, string>,
  ): Promise<GraphPage> {
    const response = await this.session.call({
      family: 'graph',
      method: 'GET',
      url,
      pathTemplate,
      schema: graphPageSchema,
      profile,
      resource: 'graph',
      ...(headers ? { headers } : {}),
    });
    return response.data;
  }

  /** `$skiptoken` value of a nextLink (after the same-origin check of the HTTP client). */
  skipToken(nextLink: string): string {
    const relative = this.relativize(nextLink);
    const query = relative.includes('?') ? relative.slice(relative.indexOf('?') + 1) : '';
    const token = new URLSearchParams(query).get('$skiptoken');
    if (!token) throw new ProviderCallError('unexpected_response', { retryable: false });
    return token;
  }

  async getUser(
    key: string,
    profile: string = MICROSOFT_PROFILES.telemetry,
  ): Promise<GraphUser | null> {
    try {
      const response = await this.session.call({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/users/${enc(key)}?$select=${GRAPH_USER_SELECT}`,
        pathTemplate: '/v1.0/users/{id}',
        schema: graphUserSchema,
        profile,
        resource: 'graph',
      });
      return response.data;
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return null;
      throw error;
    }
  }

  async findUsers(filter: string, advanced: boolean): Promise<GraphUser[]> {
    const params = new URLSearchParams({ $filter: filter, $select: GRAPH_USER_SELECT, $top: '2' });
    if (advanced) params.set('$count', 'true');
    const page = await this.page(
      `/v1.0/users?${params.toString()}`,
      '/v1.0/users{filter}',
      MICROSOFT_PROFILES.telemetry,
      advanced ? { ConsistencyLevel: 'eventual' } : undefined,
    );
    return page.value
      .map((raw) => graphUserSchema.safeParse(raw))
      .filter((r) => r.success)
      .map((r) => r.data);
  }

  async listRules(
    userId: string,
    profile: string = MICROSOFT_PROFILES.telemetry,
  ): Promise<unknown[]> {
    const response = await this.session.call({
      family: 'graph',
      method: 'GET',
      url: `/v1.0/users/${enc(userId)}/mailFolders/inbox/messageRules`,
      pathTemplate: '/v1.0/users/{id}/mailFolders/inbox/messageRules',
      schema: messageRulesSchema,
      profile,
      resource: 'graph',
    });
    return response.data.value;
  }

  /** A rule, or `null` when it no longer exists. */
  async getRule(
    userId: string,
    ruleId: string,
    profile: string,
  ): Promise<{ isEnabled: boolean } | null> {
    try {
      const response = await this.session.call({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/users/${enc(userId)}/mailFolders/inbox/messageRules/${enc(ruleId)}`,
        pathTemplate: '/v1.0/users/{id}/mailFolders/inbox/messageRules/{ruleId}',
        schema: messageRuleSchema,
        profile,
        resource: 'graph',
      });
      return { isEnabled: response.data.isEnabled === true };
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return null;
      throw error;
    }
  }

  async setRuleEnabled(
    userId: string,
    ruleId: string,
    enabled: boolean,
    profile: string,
    requestId: string,
  ): Promise<string> {
    const response = await this.session.call({
      family: 'graph',
      method: 'PATCH',
      url: `/v1.0/users/${enc(userId)}/mailFolders/inbox/messageRules/${enc(ruleId)}`,
      pathTemplate: '/v1.0/users/{id}/mailFolders/inbox/messageRules/{ruleId}',
      body: { isEnabled: enabled },
      profile,
      resource: 'graph',
      requestId,
    });
    return response.requestId;
  }

  async deleteRule(
    userId: string,
    ruleId: string,
    profile: string,
    requestId: string,
  ): Promise<void> {
    await this.session.call({
      family: 'graph',
      method: 'DELETE',
      url: `/v1.0/users/${enc(userId)}/mailFolders/inbox/messageRules/${enc(ruleId)}`,
      pathTemplate: '/v1.0/users/{id}/mailFolders/inbox/messageRules/{ruleId}',
      profile,
      resource: 'graph',
      requestId,
    });
  }

  async revokeSessions(userId: string, profile: string, requestId: string): Promise<void> {
    await this.session.call({
      family: 'graph',
      method: 'POST',
      url: `/v1.0/users/${enc(userId)}/revokeSignInSessions`,
      pathTemplate: '/v1.0/users/{id}/revokeSignInSessions',
      schema: revokeSessionsSchema,
      profile,
      resource: 'graph',
      requestId,
    });
  }

  async patchUser(
    userId: string,
    body: Record<string, unknown>,
    profile: string,
    requestId: string,
  ): Promise<void> {
    await this.session.call({
      family: 'graph',
      method: 'PATCH',
      url: `/v1.0/users/${enc(userId)}`,
      pathTemplate: '/v1.0/users/{id}',
      body,
      profile,
      resource: 'graph',
      requestId,
    });
  }

  async groupExists(groupId: string, profile: string): Promise<boolean> {
    try {
      await this.session.call({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/groups/${enc(groupId)}?$select=id`,
        pathTemplate: '/v1.0/groups/{id}',
        schema: groupSchema,
        profile,
        resource: 'graph',
      });
      return true;
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return false;
      throw error;
    }
  }

  async isMember(groupId: string, userId: string, profile: string): Promise<boolean> {
    const params = new URLSearchParams({ $filter: `id eq ${odataString(userId)}`, $select: 'id' });
    const response = await this.session.call({
      family: 'graph',
      method: 'GET',
      url: `/v1.0/groups/${enc(groupId)}/members?${params.toString()}`,
      pathTemplate: '/v1.0/groups/{id}/members{filter}',
      schema: membersSchema,
      profile,
      resource: 'graph',
    });
    return response.data.value.some((member) => member.id === userId);
  }

  /** Adds a member; an "already exists" answer (400) counts as done. */
  async addMember(
    groupId: string,
    userId: string,
    profile: string,
    requestId: string,
  ): Promise<void> {
    try {
      await this.session.call({
        family: 'graph',
        method: 'POST',
        url: `/v1.0/groups/${enc(groupId)}/members/$ref`,
        pathTemplate: '/v1.0/groups/{id}/members/$ref',
        body: { '@odata.id': `${this.session.family('graph')}/v1.0/directoryObjects/${userId}` },
        profile,
        resource: 'graph',
        requestId,
      });
    } catch (error) {
      if (
        error instanceof ProviderCallError &&
        error.code === 'bad_request' &&
        (await this.isMember(groupId, userId, profile))
      ) {
        return;
      }
      throw error;
    }
  }

  /** Removes a member; an absent member (404) counts as done. */
  async removeMember(
    groupId: string,
    userId: string,
    profile: string,
    requestId: string,
  ): Promise<void> {
    try {
      await this.session.call({
        family: 'graph',
        method: 'DELETE',
        url: `/v1.0/groups/${enc(groupId)}/members/${enc(userId)}/$ref`,
        pathTemplate: '/v1.0/groups/{id}/members/{memberId}/$ref',
        profile,
        resource: 'graph',
        requestId,
      });
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return;
      throw error;
    }
  }

  async listGrants(userId: string, profile: string): Promise<{ id: string; clientId: string }[]> {
    const grants: { id: string; clientId: string }[] = [];
    let url: string | null = `/v1.0/users/${enc(userId)}/oauth2PermissionGrants`;
    for (let pages = 0; url !== null && pages < 10; pages += 1) {
      const response: {
        data: { value: { id: string; clientId: string }[]; '@odata.nextLink'?: string };
      } = await this.session.call({
        family: 'graph',
        method: 'GET',
        url,
        pathTemplate: '/v1.0/users/{id}/oauth2PermissionGrants',
        schema: oauthGrantsSchema,
        profile,
        resource: 'graph',
      });
      grants.push(...response.data.value.map((g) => ({ id: g.id, clientId: g.clientId })));
      const next = response.data['@odata.nextLink'];
      url = next ? this.relativize(next) : null;
    }
    return grants;
  }

  /** Deletes a grant; an absent grant (404) counts as done. */
  async deleteGrant(grantId: string, profile: string, requestId: string): Promise<void> {
    try {
      await this.session.call({
        family: 'graph',
        method: 'DELETE',
        url: `/v1.0/oauth2PermissionGrants/${enc(grantId)}`,
        pathTemplate: '/v1.0/oauth2PermissionGrants/{id}',
        profile,
        resource: 'graph',
        requestId,
      });
    } catch (error) {
      if (error instanceof ProviderCallError && error.code === 'not_found') return;
      throw error;
    }
  }

  /** `verifiedPublisher` of a service principal; `undefined` when unreadable. */
  async publisherVerified(servicePrincipalId: string): Promise<boolean | undefined> {
    try {
      const response = await this.session.call({
        family: 'graph',
        method: 'GET',
        url: `/v1.0/servicePrincipals/${enc(servicePrincipalId)}?$select=id,verifiedPublisher`,
        pathTemplate: '/v1.0/servicePrincipals/{id}',
        schema: servicePrincipalSchema,
        ...this.telemetry,
      });
      return Boolean(response.data.verifiedPublisher?.verifiedPublisherId);
    } catch (error) {
      if (
        error instanceof ProviderCallError &&
        ['not_found', 'missing_permission', 'forbidden'].includes(error.code)
      ) {
        return undefined;
      }
      throw error;
    }
  }
}
