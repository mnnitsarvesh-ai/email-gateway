import { RequestMethod } from '@nestjs/common';
import { METHOD_METADATA, PATH_METADATA, VERSION_METADATA } from '@nestjs/common/constants';
import { describe, expect, it } from 'vitest';
import {
  AUTHZ_KEY,
  CURSOR_LIST_KEY,
  REQUIRE_MFA_KEY,
  USER_ONLY_KEY,
} from '../../../auth-contracts/decorators';
import { RATE_CLASS_KEY } from '../../../rate-limit/rate-class.decorator';
import { AssistantAdminAuditController, AssistantAdminController } from './admin.controller';
import { AssistantFeedbackController } from './feedback.controller';
import { AssistantSearchController } from './search.controller';

/** `DECORATORS.API_TAGS` of @nestjs/swagger (its constants are not exported). */
const API_TAGS = 'swagger/apiUseTags';

type Controller = abstract new (...args: never[]) => unknown;

/**
 * Contracts §35.6: one row per route (operation id = `<Controller>_<method>_v1`), the permission
 * of the guard, the rate class and the cursor encoding.
 */
const ROUTES: Array<{
  controller: Controller;
  handler: string;
  method: RequestMethod;
  path: string;
  permission: string;
  rateClass: string | undefined;
  cursor: string | undefined;
}> = [
  {
    controller: AssistantSearchController,
    handler: 'search',
    method: RequestMethod.GET,
    path: 'assistant/search',
    permission: 'assistant:use',
    rateClass: 'expensive',
    cursor: 'v1',
  },
  {
    controller: AssistantFeedbackController,
    handler: 'set',
    method: RequestMethod.PUT,
    path: 'assistant/messages/:messageId/feedback',
    permission: 'assistant:use',
    rateClass: undefined,
    cursor: undefined,
  },
  {
    controller: AssistantFeedbackController,
    handler: 'remove',
    method: RequestMethod.DELETE,
    path: 'assistant/messages/:messageId/feedback',
    permission: 'assistant:use',
    rateClass: undefined,
    cursor: undefined,
  },
  {
    controller: AssistantAdminController,
    handler: 'usageByUser',
    method: RequestMethod.GET,
    path: 'assistant/admin/usage/users',
    permission: 'assistant:configure',
    rateClass: undefined,
    cursor: 'v1',
  },
  {
    controller: AssistantAdminController,
    handler: 'feedback',
    method: RequestMethod.GET,
    path: 'assistant/admin/feedback',
    permission: 'assistant:configure',
    rateClass: undefined,
    cursor: 'v1',
  },
  {
    controller: AssistantAdminAuditController,
    handler: 'conversations',
    method: RequestMethod.GET,
    path: 'assistant/admin/conversations',
    permission: 'audit:read',
    rateClass: undefined,
    cursor: 'v1',
  },
  {
    controller: AssistantAdminAuditController,
    handler: 'conversation',
    method: RequestMethod.GET,
    path: 'assistant/admin/conversations/:conversationId',
    permission: 'audit:read',
    rateClass: undefined,
    cursor: undefined,
  },
  {
    controller: AssistantAdminAuditController,
    handler: 'executions',
    method: RequestMethod.GET,
    path: 'assistant/admin/executions',
    permission: 'audit:read',
    rateClass: undefined,
    cursor: 'v1',
  },
];

const join = (...parts: string[]) =>
  parts
    .filter((p) => p !== '' && p !== '/')
    .map((p) => p.replace(/^\/+|\/+$/g, ''))
    .join('/');

describe('insights controllers (contracts §35.6)', () => {
  it.each(ROUTES)('$controller.name.$handler: route, permission, user-only, v1, tag', (route) => {
    const fn = (route.controller.prototype as Record<string, unknown>)[route.handler] as object;
    expect(typeof fn).toBe('function');
    // Route: method, path and version 1 under the controller's path.
    expect(Reflect.getMetadata(METHOD_METADATA, fn)).toBe(route.method);
    const base = Reflect.getMetadata(PATH_METADATA, route.controller) as string;
    expect(join(base, Reflect.getMetadata(PATH_METADATA, fn) as string)).toBe(route.path);
    expect(Reflect.getMetadata(VERSION_METADATA, route.controller)).toBe('1');
    // Exactly the documented permission, users only, no MFA requirement.
    expect(Reflect.getMetadata(AUTHZ_KEY, fn)).toEqual({
      mode: 'all',
      permissions: [route.permission],
    });
    expect(Reflect.getMetadata(USER_ONLY_KEY, route.controller)).toBe(true);
    expect(Reflect.getMetadata(REQUIRE_MFA_KEY, fn)).toBeUndefined();
    expect(Reflect.getMetadata(RATE_CLASS_KEY, fn)).toBe(route.rateClass);
    expect(Reflect.getMetadata(CURSOR_LIST_KEY, fn)).toBe(route.cursor);
    // Same OpenAPI tag as the assistant routes (the registry classifies them not_applicable).
    expect(Reflect.getMetadata(API_TAGS, route.controller)).toEqual(['assistant']);
  });

  it('covers every handler of the four controllers', () => {
    const handlers = [
      AssistantSearchController,
      AssistantFeedbackController,
      AssistantAdminController,
      AssistantAdminAuditController,
    ].flatMap((c) =>
      Object.getOwnPropertyNames(c.prototype)
        .filter((name) => name !== 'constructor')
        .map((name) => `${c.name}.${name}`),
    );
    expect(handlers.sort()).toEqual(
      ROUTES.map((r) => `${(r.controller as { name: string }).name}.${r.handler}`).sort(),
    );
  });
});
