import { RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA, VERSION_METADATA } from '@nestjs/common/constants';
import { reportJobRoutePaths } from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import { API_GLOBAL_PREFIX } from '../http/configure-api-app';
import { AtoAccountsController } from '../modules/ato/controllers/ato-accounts.controller';
import { AtoOverviewController } from '../modules/ato/controllers/ato-overview.controller';
import { QuarantineToolsController } from '../modules/quarantine/controllers/quarantine-tools.controller';
import { ReportsController } from '../modules/reports/reports.controller';
import { ASSISTANT_JOB_ROUTES, isAssistantJobRoute, registryPathOf } from './assistant-job-routes';

/** The GET routes of a controller as `/api/v<version>/<path>` templates (registry form). */
function getRoutes(controller: abstract new (...args: never[]) => unknown): string[] {
  const join = (...parts: string[]) =>
    `/${parts
      .flatMap((p) => p.split('/'))
      .filter(Boolean)
      .join('/')}`;
  const base = Reflect.getMetadata(PATH_METADATA, controller) as string;
  const version = Reflect.getMetadata(VERSION_METADATA, controller) as string;
  const proto = controller.prototype as Record<string, unknown>;
  return Object.getOwnPropertyNames(proto).flatMap((name) => {
    const handler = proto[name];
    if (typeof handler !== 'function' || name === 'constructor') return [];
    if (Reflect.getMetadata(METHOD_METADATA, handler) !== RequestMethod.GET) return [];
    const path = (Reflect.getMetadata(PATH_METADATA, handler) as string | undefined) ?? '';
    return [registryPathOf(join(API_GLOBAL_PREFIX, `v${version}`, base, path))];
  });
}

describe('ASSISTANT_JOB_ROUTES (step AI-6 D5, ADR-0096, I26)', () => {
  it('is exactly the package’s report source route list (single source)', () => {
    expect([...ASSISTANT_JOB_ROUTES].sort()).toEqual([...reportJobRoutePaths()].sort());
    expect([...ASSISTANT_JOB_ROUTES].sort()).toEqual([
      '/api/v1/ato/accounts',
      '/api/v1/ato/overview',
      '/api/v1/quarantine/summary',
      '/api/v1/reports/delivery',
      '/api/v1/reports/processing',
      '/api/v1/reports/threats',
      '/api/v1/reports/top-domains',
      '/api/v1/reports/traffic',
      '/api/v1/reports/url-clicks',
    ]);
  });

  it('names only existing GET controller routes', () => {
    const served = new Set(
      [
        ReportsController,
        QuarantineToolsController,
        AtoOverviewController,
        AtoAccountsController,
      ].flatMap((c) => getRoutes(c)),
    );
    for (const path of ASSISTANT_JOB_ROUTES) expect(served).toContain(path);
  });

  it('allows GET on those templates only', () => {
    expect(isAssistantJobRoute('GET', '/api/v1/reports/traffic')).toBe(true);
    expect(isAssistantJobRoute('get', '/api/v1/ato/accounts')).toBe(true);
    expect(isAssistantJobRoute('POST', '/api/v1/reports/traffic')).toBe(false);
    expect(isAssistantJobRoute('HEAD', '/api/v1/reports/traffic')).toBe(false);
    expect(isAssistantJobRoute('GET', '/api/v1/ato/accounts/:accountId')).toBe(false);
    expect(isAssistantJobRoute('GET', 'unmatched')).toBe(false);
    expect(registryPathOf('/api/v1/users/:id/roles/:roleId')).toBe(
      '/api/v1/users/{id}/roles/{roleId}',
    );
  });
});
