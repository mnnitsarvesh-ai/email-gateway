import { createPrivateKey } from 'node:crypto';
import { SignJWT } from 'jose';
import { z } from 'zod';
import type { ServiceAccountKey } from '../crypto/credential-cipher';
import { ProviderRequestError } from '../errors';
import { httpOptions, providerRequest, type ProviderHttpSettings } from '../http/provider-http';
import type { AcquiredToken } from '../microsoft/token';
import { isEmailAddress } from '../types';

/**
 * Google OAuth 2.0 JWT bearer grant for service accounts with domain-wide delegation (D2):
 * RS256 assertion, `iss` = service-account e-mail, `sub` = the impersonated user (the grant's
 * delegated admin by default), `scope` = the profile's scopes, `aud` = the configured token URL,
 * lifetime ≤ 1 hour.
 */
export interface GoogleTokenRequest {
  tokenUrl: URL;
  key: ServiceAccountKey;
  subject: string;
  scopes: readonly string[];
  signal: AbortSignal;
  http?: ProviderHttpSettings;
  now?: () => Date;
}

const tokenResponse = z.object({
  access_token: z.string().min(16).max(16_384),
  expires_in: z.coerce.number().int().positive().max(86_400),
  token_type: z.string().regex(/^bearer$/i),
  scope: z.string().max(4096).optional(),
});

export const GOOGLE_ASSERTION_LIFETIME_SECONDS = 3600;

export async function googleJwtAssertion(input: {
  key: ServiceAccountKey;
  subject: string;
  scopes: readonly string[];
  audience: string;
  now: Date;
}): Promise<string> {
  let privateKey;
  try {
    privateKey = createPrivateKey({ key: input.key.private_key, format: 'pem' });
  } catch {
    throw new ProviderRequestError('credential_unavailable');
  }
  const iat = Math.floor(input.now.getTime() / 1000);
  return new SignJWT({ scope: input.scopes.join(' ') })
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: input.key.private_key_id })
    .setIssuer(input.key.client_email)
    .setSubject(input.subject)
    .setAudience(input.audience)
    .setIssuedAt(iat)
    .setExpirationTime(iat + GOOGLE_ASSERTION_LIFETIME_SECONDS)
    .sign(privateKey);
}

export async function requestGoogleToken(request: GoogleTokenRequest): Promise<AcquiredToken> {
  if (!isEmailAddress(request.subject)) throw new ProviderRequestError('credential_unavailable');
  if (request.scopes.length === 0) throw new ProviderRequestError('credential_unavailable');
  const now = (request.now ?? (() => new Date()))();
  const audience = request.tokenUrl.href.replace(/\/+$/, '');
  const assertion = await googleJwtAssertion({
    key: request.key,
    subject: request.subject.toLowerCase(),
    scopes: request.scopes,
    audience,
    now,
  });
  const response = await providerRequest({
    ...httpOptions(request.http),
    origin: request.tokenUrl,
    method: 'POST',
    // The token URL is the complete endpoint: post to its own path.
    path: '',
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
    signal: request.signal,
    api: 'google.token',
    tokenEndpoint: 'google',
  });
  const parsed = tokenResponse.safeParse(response.json);
  if (!parsed.success) throw new ProviderRequestError('bad_response', { status: response.status });
  // Google refuses the whole grant when any requested scope is not delegated, so a token means
  // every requested scope was granted; a `scope` field, when present, is reported as is.
  const observed = parsed.data.scope
    ? parsed.data.scope.split(/\s+/).filter(Boolean).sort()
    : [...request.scopes].sort();
  return {
    token: parsed.data.access_token,
    expiresAt: new Date(now.getTime() + parsed.data.expires_in * 1000),
    observedPermissions: observed,
  };
}
