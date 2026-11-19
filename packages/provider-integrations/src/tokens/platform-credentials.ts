import { createPrivateKey, type KeyObject } from 'node:crypto';
import { parseServiceAccountKey, type ServiceAccountKey } from '../crypto/credential-cipher';
import type { PermissionProfile } from '../profiles/types';

/**
 * Operator-owned platform credentials, per profile key (D2, D5): held only by the decrypting
 * worker. The api holds only the client ids (consent URLs, delegation instructions).
 */
export interface PlatformMicrosoftApp {
  clientId: string;
  secret?: string;
  certificate?: { privateKey: KeyObject; thumbprint: string };
}

export interface PlatformCredentials {
  microsoft: ReadonlyMap<string, PlatformMicrosoftApp>;
  google: ReadonlyMap<string, ServiceAccountKey>;
}

export const EMPTY_PLATFORM_CREDENTIALS: PlatformCredentials = Object.freeze({
  microsoft: new Map(),
  google: new Map(),
});

/** Thrown when a configured platform credential is unusable; names keys, never values. */
export class PlatformCredentialConfigError extends Error {
  override readonly name = 'PlatformCredentialConfigError';
}

export interface PlatformCredentialEnvOptions {
  /** Reads a configured file path (certificate private key PEM, service-account key JSON). */
  readFile: (path: string) => string;
  /** `PROVIDER_GOOGLE_TOKEN_URL`: the service-account key's `token_uri` must equal it. */
  googleTokenUrl: string;
  /**
   * `PROVIDER_M365_ALLOW_PLATFORM_SECRET`: a platform client secret is refused unless true
   * (production uses a certificate, D2).
   */
  allowPlatformSecret: boolean;
}

/**
 * Builds the platform credentials of every given profile from configuration values, using the
 * key NAMES in `profile.platformApp` (D1). A profile whose client id key is empty has no
 * platform app (the method is unavailable). 8.5's profiles name their own keys and are loaded
 * by the same function.
 */
export function platformCredentialsFromEnv(
  env: Readonly<Record<string, string | undefined>>,
  profiles: readonly PermissionProfile[],
  options: PlatformCredentialEnvOptions,
): PlatformCredentials {
  const microsoft = new Map<string, PlatformMicrosoftApp>();
  const google = new Map<string, ServiceAccountKey>();
  const value = (key: string | undefined) => (key ? env[key]?.trim() || undefined : undefined);

  for (const profile of profiles) {
    const keys = profile.platformApp;
    if (profile.provider === 'microsoft_365') {
      const clientId = value(keys.clientIdKey);
      if (!clientId) continue;
      const app: PlatformMicrosoftApp = { clientId };
      const certPath = value(keys.certFileKey);
      const thumbprint = value(keys.certThumbprintKey);
      if (certPath) {
        if (!thumbprint || !/^[0-9a-fA-F]{40}$/.test(thumbprint)) {
          throw new PlatformCredentialConfigError(
            `${keys.certThumbprintKey ?? 'certificate thumbprint'} must be a 40-character hex SHA-1 thumbprint`,
          );
        }
        let privateKey: KeyObject;
        try {
          privateKey = createPrivateKey({ key: options.readFile(certPath), format: 'pem' });
        } catch {
          throw new PlatformCredentialConfigError(
            `${keys.certFileKey} does not hold a readable private key`,
          );
        }
        app.certificate = { privateKey, thumbprint };
      }
      const secret = value(keys.secretKey);
      if (secret) {
        if (!options.allowPlatformSecret) {
          throw new PlatformCredentialConfigError(
            `${keys.secretKey} is refused unless PROVIDER_M365_ALLOW_PLATFORM_SECRET=true (use a certificate)`,
          );
        }
        app.secret = secret;
      }
      if (!app.secret && !app.certificate) {
        throw new PlatformCredentialConfigError(
          `${keys.clientIdKey} is set but neither a certificate nor a client secret is configured`,
        );
      }
      microsoft.set(profile.key, app);
    } else {
      const path = value(keys.saKeyFileKey);
      if (!path) continue;
      let raw: string;
      try {
        raw = options.readFile(path);
      } catch {
        throw new PlatformCredentialConfigError(`${keys.saKeyFileKey} is not readable`);
      }
      try {
        google.set(profile.key, parseServiceAccountKey(raw, { tokenUrl: options.googleTokenUrl }));
      } catch {
        throw new PlatformCredentialConfigError(
          `${keys.saKeyFileKey} is not a valid service-account key`,
        );
      }
    }
  }
  return { microsoft, google };
}
