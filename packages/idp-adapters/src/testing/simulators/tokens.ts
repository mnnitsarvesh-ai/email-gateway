/**
 * Token registry of the simulators (design note D12). In-process, tokens are minted by
 * `InMemoryConnectionAccess` with the permissions of their grant (live: revoking a permission
 * affects issued tokens), so missing-permission paths are real. Stack mode (`permissive`): any
 * non-empty bearer token is accepted with the permissions set per directory through the admin API.
 *
 * Tokens look like `EXAMPLE-sim-token-<n>`; they are never valid anywhere else.
 */

export type SimTokenResource = 'graph' | 'o365_management' | 'google';

export interface SimTokenInfo {
  directoryId: string;
  resource: SimTokenResource;
  profile: string;
  subject?: string;
  expiresAt: number;
}

export interface ResolvedToken {
  directoryId: string;
  resource: SimTokenResource | null;
  profile: string | null;
  subject?: string;
  permissions: ReadonlySet<string>;
}

export const ALL_PERMISSIONS = '*';

export class SimTokenRegistry {
  private readonly tokens = new Map<string, SimTokenInfo>();
  /** Granted permissions per `directoryId|profile`. */
  private readonly grants = new Map<string, Set<string>>();
  /** Stack mode: permissions per directory for any bearer token. */
  private readonly directoryPermissions = new Map<string, Set<string>>();
  private readonly revoked = new Set<string>();
  private counter = 0;

  constructor(
    private readonly options: {
      permissive?: boolean;
      /** Directory used for permissive tokens when the request does not name one. */
      defaultDirectoryId?: string;
      now?: () => number;
    } = {},
  ) {}

  get permissive(): boolean {
    return this.options.permissive === true;
  }

  setDefaultDirectory(directoryId: string): void {
    this.options.defaultDirectoryId = directoryId;
  }

  setGrant(directoryId: string, profile: string, permissions: readonly string[]): void {
    this.grants.set(`${directoryId}|${profile}`, new Set(permissions));
  }

  /** Stack mode: the permissions any token of this directory has (`*` = all). */
  setDirectoryPermissions(directoryId: string, permissions: readonly string[]): void {
    this.directoryPermissions.set(directoryId, new Set(permissions));
  }

  /** Removes a permission from every grant (of one directory, or all). */
  revokePermission(name: string, directoryId?: string): void {
    for (const [key, set] of this.grants) {
      if (directoryId === undefined || key.startsWith(`${directoryId}|`)) set.delete(name);
    }
    for (const [key, set] of this.directoryPermissions) {
      if (directoryId === undefined || key === directoryId) {
        if (set.has(ALL_PERMISSIONS)) continue;
        set.delete(name);
      }
    }
  }

  /** Permissions currently granted to `directoryId|profile` (live: reflects revocations). */
  grantedPermissions(directoryId: string, profile: string): string[] {
    return [...(this.grants.get(`${directoryId}|${profile}`) ?? [])];
  }

  grantPermission(name: string, directoryId: string, profile: string): void {
    const key = `${directoryId}|${profile}`;
    const set = this.grants.get(key) ?? new Set<string>();
    set.add(name);
    this.grants.set(key, set);
  }

  issue(info: SimTokenInfo): string {
    this.counter += 1;
    const token = `EXAMPLE-sim-token-${this.counter}`;
    this.tokens.set(token, info);
    return token;
  }

  /** Makes one issued token invalid (the simulators answer 401 for it). */
  invalidate(token: string): void {
    this.revoked.add(token);
  }

  /** Invalidates every token issued so far. */
  invalidateAll(): void {
    for (const token of this.tokens.keys()) this.revoked.add(token);
  }

  issuedCount(): number {
    return this.counter;
  }

  reset(): void {
    this.tokens.clear();
    this.grants.clear();
    this.directoryPermissions.clear();
    this.revoked.clear();
  }

  resolve(authorization: string | undefined, directoryHint?: string): ResolvedToken | null {
    if (!authorization || !authorization.startsWith('Bearer ')) return null;
    const token = authorization.slice('Bearer '.length).trim();
    if (token.length === 0 || this.revoked.has(token)) return null;
    const info = this.tokens.get(token);
    const now = (this.options.now ?? Date.now)();
    if (info) {
      if (info.expiresAt <= now) return null;
      const permissions =
        this.grants.get(`${info.directoryId}|${info.profile}`) ?? new Set<string>();
      return {
        directoryId: info.directoryId,
        resource: info.resource,
        profile: info.profile,
        subject: info.subject,
        permissions,
      };
    }
    if (!this.permissive) return null;
    const directoryId = directoryHint ?? this.options.defaultDirectoryId;
    if (!directoryId) return null;
    return {
      directoryId,
      resource: null,
      profile: null,
      permissions: this.directoryPermissions.get(directoryId) ?? new Set([ALL_PERMISSIONS]),
    };
  }
}

export function hasPermission(token: ResolvedToken, anyOf: readonly string[]): boolean {
  if (token.permissions.has(ALL_PERMISSIONS)) return true;
  return anyOf.some((name) => token.permissions.has(name));
}
