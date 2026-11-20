/**
 * Entra directory audits (consent activities) → OAuth events (design note §3.2):
 * `appIdHash` = SHA-256(service principal object id), scopes parsed from
 * `ConsentAction.Permissions`, consent type from `ConsentContext.IsAdminConsent`, publisher
 * verification from the service principal (looked up by the adapter, cached).
 */
import { appIdHash } from '../../core/hash';
import {
  boundedText,
  canonicalIp,
  eventIdPart,
  isoUtc,
  normalizedAddress,
  safeDisplayText,
} from '../../core/normalize';
import { oauthScopeCodes } from '../../core/oauth-scopes';
import type { ProviderEvent } from '../../port/ato-port';
import { CONSENT_ACTIVITIES, MICROSOFT_PROVIDER } from '../constants';
import { directoryAuditSchema } from '../schemas';

export type AuditMapResult =
  | { kind: 'event'; event: ProviderEvent; servicePrincipalId: string }
  | { kind: 'dropped' }
  | { kind: 'invalid' };

const SCOPE_TOKEN = /^[A-Za-z0-9._:/-]{1,128}$/;

/** Scopes from `ConsentAction.Permissions` values (`… Scope: Mail.Read offline_access, …`). */
export function parseConsentScopes(values: readonly string[]): string[] {
  const scopes = new Set<string>();
  for (const value of values) {
    const pattern = /Scope:\s*([^,\]]*)/g;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(value)) !== null) {
      for (const token of (match[1] ?? '').split(/\s+/)) {
        const scope = token.replace(/^"+|"+$/g, '').trim();
        if (scope && SCOPE_TOKEN.test(scope)) scopes.add(scope);
        if (scopes.size >= 50) return [...scopes];
      }
    }
  }
  return [...scopes];
}

function unquote(value: string | null | undefined): string {
  return (value ?? '').replace(/^"+|"+$/g, '').trim();
}

export function mapDirectoryAudit(raw: unknown): AuditMapResult {
  const parsed = directoryAuditSchema.safeParse(raw);
  if (!parsed.success) return { kind: 'invalid' };
  const record = parsed.data;
  if (!(CONSENT_ACTIVITIES as readonly string[]).includes(record.activityDisplayName)) {
    return { kind: 'dropped' };
  }
  if (record.result && record.result.toLowerCase() !== 'success') return { kind: 'dropped' };
  const user = record.initiatedBy.user;
  if (!user) return { kind: 'invalid' };
  const target = record.targetResources.find(
    (resource) => (resource.type ?? '').toLowerCase() === 'serviceprincipal' && resource.id,
  );
  if (!target?.id) return { kind: 'invalid' };
  const occurredAt = isoUtc(record.activityDateTime);
  if (!occurredAt) return { kind: 'invalid' };
  const properties = target.modifiedProperties ?? [];
  const permissionValues = properties
    .filter((p) => (p.displayName ?? '').toLowerCase() === 'consentaction.permissions')
    .map((p) => p.newValue ?? '');
  const adminConsent = properties.find(
    (p) => (p.displayName ?? '').toLowerCase() === 'consentcontext.isadminconsent',
  );
  const upn = boundedText(user.userPrincipalName, 256);
  const email = normalizedAddress(upn);
  const appName = safeDisplayText(target.displayName, 128);
  const event: ProviderEvent = {
    provider: MICROSOFT_PROVIDER,
    eventId: `entra:audit:${eventIdPart(record.id)}`.slice(0, 128),
    stream: 'oauth_consents',
    occurredAt,
    identity: {
      provider: MICROSOFT_PROVIDER,
      externalId: user.id,
      ...(upn ? { userPrincipalName: upn } : {}),
      ...(email ? { primaryEmail: email } : {}),
    },
    oauth: {
      appIdHash: appIdHash(target.id),
      ...(appName ? { appDisplayName: appName } : {}),
      scopes: oauthScopeCodes(MICROSOFT_PROVIDER, parseConsentScopes(permissionValues)),
      consentType: unquote(adminConsent?.newValue).toLowerCase() === 'true' ? 'admin' : 'user',
    },
  };
  const ip = canonicalIp(user.ipAddress);
  if (ip) event.ip = ip;
  return { kind: 'event', event, servicePrincipalId: target.id };
}
