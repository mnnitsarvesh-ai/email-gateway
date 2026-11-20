/**
 * Api binding (design note §0.3, §6 route 3; merge note M4): a READ-ONLY directory of the
 * organization's step 8.2 connections with the data the api needs to decide whether a connection
 * can be bound to ATO (D4) — never a token, credential or provider call. The api's providers
 * service adds what only ATO knows (the connections already bound) through `eligibilityOf`.
 * Together with `kinds.ts` and `provider-connections.ts` this is the only code of the package that
 * knows 8.2's names.
 */
import type { Prisma, PrismaClient } from '@email-gateway/database';
import {
  comparePermissions,
  profilesFor,
  ProviderConnectionReader,
} from '@email-gateway/provider-integrations';
import { providerKindFromConnection, type AtoProviderKind } from '../kinds';
import type { ProviderConnectionView, ProviderGrantView } from '../port/connection-port';
import { PERMISSION_REQUIREMENTS } from '../requirements';
import { toPortConnection, type ConnectionReads } from './provider-connections';

/** One ATO permission profile of a connection: required, granted and missing permissions. */
export interface DirectoryProfileView {
  profile: string;
  purpose: 'ato_telemetry' | 'ato_response';
  title: string;
  readOnly: boolean;
  required: string[];
  grant: {
    publicId: string;
    status: ProviderGrantView['status'];
    /** `null` while 8.2 never verified the grant. */
    observed: string[] | null;
    missing: string[];
    excess: string[];
  } | null;
  /**
   * Required permissions 8.2's Graph token cannot show (the Office 365 Management APIs
   * `ActivityFeed.Read` of another resource): proven only by the ato-worker's probe (D6).
   */
  notObservable: string[];
}

export type ConnectionEligibility = 'eligible' | 'already_bound' | 'wrong_provider' | 'inactive';

/** Why a connection is not eligible (stable codes for the api and portal). */
export type IneligibilityReason =
  | 'already_bound'
  | 'wrong_provider'
  | 'connection_inactive'
  | 'telemetry_grant_missing'
  | 'telemetry_grant_inactive';

export interface DirectoryConnection {
  connection: ProviderConnectionView;
  /** ATO kind of the connection's provider, `null` for a provider ATO does not support. */
  kind: AtoProviderKind | null;
  /** ATO profiles of the provider in registry order (telemetry first). */
  profiles: DirectoryProfileView[];
  /** Linked domains verified in the provider tenant (the D9 guard set). */
  providerVerifiedDomains: string[];
}

/** Permissions of a profile that are not on the 8.2 token (other API resources). */
function notObservableOf(profileKey: string): string[] {
  for (const requirements of Object.values(PERMISSION_REQUIREMENTS)) {
    const profile = requirements.profiles.find((p) => p.key === profileKey);
    if (profile)
      return profile.permissions.filter((p) => p.api === 'o365_management').map((p) => p.name);
  }
  return [];
}

function profileViews(connection: ProviderConnectionView): DirectoryProfileView[] {
  const views: DirectoryProfileView[] = [];
  for (const purpose of ['ato_telemetry', 'ato_response'] as const) {
    for (const profile of profilesFor(connection.provider, purpose)) {
      const grant = connection.grants.find((g) => g.profile === profile.key) ?? null;
      const observed = grant?.observedPermissions ? [...grant.observedPermissions] : null;
      const notObservable = notObservableOf(profile.key);
      const comparable = {
        ...profile,
        permissions: profile.permissions.filter((p) => !notObservable.includes(p)),
      };
      const { missing, excess } = comparePermissions(comparable, observed ?? []);
      views.push({
        profile: profile.key,
        purpose,
        title: profile.title,
        readOnly: profile.readOnly,
        required: [...profile.permissions],
        grant: grant
          ? {
              publicId: grant.publicId,
              status: grant.status,
              observed,
              missing: observed === null ? [...comparable.permissions] : missing,
              excess: observed === null ? [] : excess,
            }
          : null,
        notObservable,
      });
    }
  }
  return views;
}

/** Builds the directory entry of one connection (pure; exposed for tests). */
export function toDirectoryConnection(connection: ProviderConnectionView): DirectoryConnection {
  return {
    connection,
    kind: providerKindFromConnection(connection.provider),
    profiles: profileViews(connection),
    providerVerifiedDomains: connection.linkedDomains
      .filter((d) => d.providerVerified)
      .map((d) => d.name)
      .sort(),
  };
}

/**
 * D4 eligibility of a directory entry. `boundConnectionIds` are the connection public ids of the
 * organization's non-disabled ATO integrations (the api reads them from
 * `ato_provider_integrations.connector_ref`).
 */
export function eligibilityOf(
  entry: DirectoryConnection,
  boundConnectionIds: ReadonlySet<string>,
): { eligibility: ConnectionEligibility; reasons: IneligibilityReason[] } {
  if (entry.kind === null) return { eligibility: 'wrong_provider', reasons: ['wrong_provider'] };
  if (boundConnectionIds.has(entry.connection.publicId)) {
    return { eligibility: 'already_bound', reasons: ['already_bound'] };
  }
  const reasons: IneligibilityReason[] = [];
  if (entry.connection.status !== 'active') reasons.push('connection_inactive');
  const telemetry = entry.profiles.find((p) => p.purpose === 'ato_telemetry');
  if (!telemetry?.grant) reasons.push('telemetry_grant_missing');
  else if (telemetry.grant.status !== 'active') reasons.push('telemetry_grant_inactive');
  return { eligibility: reasons.length === 0 ? 'eligible' : 'inactive', reasons };
}

/** Read-only listing of 8.2 connections for the api (reader or a test double). */
export class ConnectionDirectory {
  constructor(private readonly connections: ConnectionReads) {}

  /** Every connection of the organization (disabled ones included), oldest first. */
  async list(organizationId: bigint): Promise<DirectoryConnection[]> {
    const views = await this.connections.listForOrganization(organizationId);
    return views
      .filter((v) => v.organizationId === organizationId.toString())
      .map((v) => toDirectoryConnection(toPortConnection(v)));
  }

  /** One connection of the organization, or null (another organization's id answers null). */
  async get(
    organizationId: bigint,
    connectionPublicId: string,
  ): Promise<DirectoryConnection | null> {
    const view = await this.connections.get(organizationId, connectionPublicId);
    if (!view || view.organizationId !== organizationId.toString()) return null;
    return toDirectoryConnection(toPortConnection(view));
  }
}

/** The api's directory over 8.2's reader (the writer or the replica, as the caller chooses). */
export function createConnectionDirectory(
  db: PrismaClient | Prisma.TransactionClient,
): ConnectionDirectory {
  return new ConnectionDirectory(new ProviderConnectionReader(db));
}
