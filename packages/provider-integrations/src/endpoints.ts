import { ProviderRequestError } from './errors';
import { assertProviderOrigin } from './http/provider-http';

/**
 * Provider endpoints are configuration, never tenant input (D2). Defaults are the public
 * endpoints; local and CI point at the provider fake with `allowHttp`.
 */
export interface ProviderEndpointsConfig {
  /** `PROVIDER_M365_LOGIN_URL` (`https://login.microsoftonline.com`). */
  m365LoginUrl: string;
  /** `PROVIDER_M365_GRAPH_URL` (`https://graph.microsoft.com`). */
  m365GraphUrl: string;
  /**
   * `PROVIDER_M365_MANAGEMENT_URL` (`https://manage.office.com`): only the token resource of
   * `o365_management` (R1); step 8.5 adds the configuration key, 8.2 only this option.
   */
  m365ManagementUrl?: string;
  /** The Graph token resource (`https://graph.microsoft.com/.default`). */
  m365GraphScope?: string;
  /** `PROVIDER_GOOGLE_TOKEN_URL` (`https://oauth2.googleapis.com/token`). */
  googleTokenUrl: string;
  /** `PROVIDER_GOOGLE_ADMIN_URL` (`https://admin.googleapis.com`). */
  googleAdminUrl: string;
  /** `PROVIDER_ALLOW_HTTP_ENDPOINTS` (refused outside local/ci by the apps' configuration). */
  allowHttp?: boolean;
}

export const DEFAULT_PROVIDER_ENDPOINTS: Readonly<ProviderEndpointsConfig> = Object.freeze({
  m365LoginUrl: 'https://login.microsoftonline.com',
  m365GraphUrl: 'https://graph.microsoft.com',
  m365ManagementUrl: 'https://manage.office.com',
  m365GraphScope: 'https://graph.microsoft.com/.default',
  googleTokenUrl: 'https://oauth2.googleapis.com/token',
  googleAdminUrl: 'https://admin.googleapis.com',
  allowHttp: false,
});

/** Parsed, validated endpoints. */
export interface ProviderEndpoints {
  m365Login: URL;
  m365Graph: URL;
  m365Management: URL;
  m365GraphScope: string;
  m365ManagementScope: string;
  googleToken: URL;
  googleAdmin: URL;
  allowHttp: boolean;
}

function parse(value: string, allowHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProviderRequestError('bad_response');
  }
  assertProviderOrigin(url, allowHttp);
  return url;
}

export function resolveProviderEndpoints(config: ProviderEndpointsConfig): ProviderEndpoints {
  const allowHttp = config.allowHttp === true;
  const management = parse(
    config.m365ManagementUrl ?? DEFAULT_PROVIDER_ENDPOINTS.m365ManagementUrl!,
    allowHttp,
  );
  return {
    m365Login: parse(config.m365LoginUrl, allowHttp),
    m365Graph: parse(config.m365GraphUrl, allowHttp),
    m365Management: management,
    m365GraphScope: config.m365GraphScope ?? DEFAULT_PROVIDER_ENDPOINTS.m365GraphScope!,
    // R1: the configured management origin + `/.default`.
    m365ManagementScope: `${management.origin}/.default`,
    googleToken: parse(config.googleTokenUrl, allowHttp),
    googleAdmin: parse(config.googleAdminUrl, allowHttp),
    allowHttp,
  };
}

/** The exact token URL string (for the Google JWT `aud` and the service-account `token_uri`). */
export const urlString = (url: URL): string => url.href.replace(/\/+$/, '');
