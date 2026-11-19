import { createHash, randomUUID, type KeyObject } from 'node:crypto';
import { SignJWT, decodeJwt } from 'jose';
import { z } from 'zod';
import { ProviderRequestError } from '../errors';
import { httpOptions, providerRequest, type ProviderHttpSettings } from '../http/provider-http';
import { MICROSOFT_CLIENT_ID, MICROSOFT_TENANT_ID } from '../types';

/**
 * Microsoft identity platform client-credentials token acquisition (D2): client secret, or a
 * certificate assertion (RS256 JWT with the `x5t` thumbprint, signed with `jose`).
 */
export type MicrosoftClientCredential =
  | { kind: 'secret'; secret: string }
  | {
      kind: 'certificate';
      privateKey: KeyObject;
      /** SHA-1 thumbprint of the certificate, hex (as Entra shows it). */
      thumbprint: string;
    };

export interface MicrosoftTokenRequest {
  loginUrl: URL;
  tenantId: string;
  clientId: string;
  credential: MicrosoftClientCredential;
  /** `<resource>/.default`. */
  scope: string;
  signal: AbortSignal;
  http?: ProviderHttpSettings;
  now?: () => Date;
}

export interface AcquiredToken {
  token: string;
  expiresAt: Date;
  observedPermissions: string[];
}

const tokenResponse = z.object({
  token_type: z.string().regex(/^bearer$/i),
  expires_in: z.coerce.number().int().positive().max(86_400),
  access_token: z.string().min(16).max(16_384),
});

const THUMBPRINT = /^[0-9a-fA-F]{40}$/;

/** The token endpoint path of a tenant (tenant ids validated before they reach a URL path). */
export function microsoftTokenPath(tenantId: string): string {
  if (!MICROSOFT_TENANT_ID.test(tenantId)) throw new ProviderRequestError('tenant_not_found');
  return `/${tenantId}/oauth2/v2.0/token`;
}

/** The certificate client assertion (claims per the Microsoft identity platform). */
export async function microsoftClientAssertion(input: {
  audience: string;
  clientId: string;
  privateKey: KeyObject;
  thumbprint: string;
  now: Date;
}): Promise<string> {
  if (!THUMBPRINT.test(input.thumbprint)) throw new ProviderRequestError('credential_unavailable');
  const x5t = Buffer.from(input.thumbprint, 'hex').toString('base64url');
  const iat = Math.floor(input.now.getTime() / 1000);
  return new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', x5t })
    .setIssuer(input.clientId)
    .setSubject(input.clientId)
    .setAudience(input.audience)
    .setJti(randomUUID())
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .setExpirationTime(iat + 600)
    .sign(input.privateKey);
}

/** Application permissions from the access token's `roles` claim (reporting only, D3.4). */
export function rolesFromAccessToken(token: string): string[] {
  try {
    const claims = decodeJwt(token);
    return Array.isArray(claims.roles)
      ? claims.roles.filter((r): r is string => typeof r === 'string').sort()
      : [];
  } catch {
    return [];
  }
}

export async function requestMicrosoftToken(
  request: MicrosoftTokenRequest,
): Promise<AcquiredToken> {
  if (!MICROSOFT_CLIENT_ID.test(request.clientId))
    throw new ProviderRequestError('credential_unavailable');
  const path = microsoftTokenPath(request.tenantId);
  const now = (request.now ?? (() => new Date()))();
  const form = new URLSearchParams({
    client_id: request.clientId,
    scope: request.scope,
    grant_type: 'client_credentials',
  });
  if (request.credential.kind === 'secret') {
    form.set('client_secret', request.credential.secret);
  } else {
    const base = request.loginUrl.href.replace(/\/+$/, '');
    form.set('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
    form.set(
      'client_assertion',
      await microsoftClientAssertion({
        audience: `${base}${path}`,
        clientId: request.clientId,
        privateKey: request.credential.privateKey,
        thumbprint: request.credential.thumbprint,
        now,
      }),
    );
  }
  const response = await providerRequest({
    ...httpOptions(request.http),
    origin: request.loginUrl,
    method: 'POST',
    path,
    body: form,
    signal: request.signal,
    api: 'm365.token',
    tokenEndpoint: 'microsoft',
  });
  const parsed = tokenResponse.safeParse(response.json);
  if (!parsed.success) throw new ProviderRequestError('bad_response', { status: response.status });
  return {
    token: parsed.data.access_token,
    expiresAt: new Date(now.getTime() + parsed.data.expires_in * 1000),
    observedPermissions: rolesFromAccessToken(parsed.data.access_token),
  };
}

/** SHA-1 thumbprint (hex, upper case) of a DER certificate, as Entra displays it. */
export const certificateThumbprint = (der: Buffer): string =>
  createHash('sha1').update(der).digest('hex').toUpperCase();
