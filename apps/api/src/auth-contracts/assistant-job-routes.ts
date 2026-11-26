import { reportJobRoutePaths } from '@email-gateway/assistant';

/**
 * The routes an assistant report job token may call (step AI-6 D5, ADR-0096, I26): `GET` on the
 * path templates of the report source tools, derived from the package's report source plan
 * (`reportJobRoutePaths()`: `/api/v1/reports/{traffic,threats,url-clicks,delivery,processing,
 * top-domains}`, `/api/v1/quarantine/summary`, `/api/v1/ato/overview`, `/api/v1/ato/accounts`).
 * Anything else answers `401` (the authentication guard).
 */
export const ASSISTANT_JOB_ROUTES: ReadonlySet<string> = new Set(reportJobRoutePaths());

/** The only method a job token may use. */
export const ASSISTANT_JOB_METHOD = 'GET';

/** An Express route template (`/api/v1/users/:id`) in the registry's form (`/api/v1/users/{id}`). */
export function registryPathOf(template: string): string {
  return template.replace(/:([A-Za-z0-9_]+)/g, '{$1}');
}

/** Whether a job token may call `method` on the matched route template. */
export function isAssistantJobRoute(method: string, template: string): boolean {
  return (
    method.toUpperCase() === ASSISTANT_JOB_METHOD &&
    ASSISTANT_JOB_ROUTES.has(registryPathOf(template))
  );
}
