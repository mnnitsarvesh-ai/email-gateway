import { GUARD_MESSAGES } from '@email-gateway/assistant';
import { describe, expect, it } from 'vitest';
import type { ExecutionWithRefs } from '../repositories/executions.repository';
import { DENIAL_MESSAGES, refusalMessageOf } from './denials';
import { executionView } from './views';

const row = (overrides: Partial<ExecutionWithRefs>): ExecutionWithRefs => ({
  id: 7n,
  publicId: '0193b000-0000-7000-8000-000000000701',
  organizationId: 1n,
  userId: 2n,
  conversationId: 3n,
  turnId: 4n,
  parentExecutionId: null,
  seq: 2,
  toolName: 'users_replace_roles',
  operationId: 'UsersController_replaceRoles_v1',
  httpMethod: 'PUT',
  access: 'write',
  risk: 'high',
  decision: 'denied_guard',
  status: 'refused',
  httpStatus: null,
  errorCode: 'denied_guard',
  correlationId: 'corr-base.2',
  paramsRedacted: null,
  resourceRef: null,
  resultCard: null,
  resultRefs: null,
  nextCursor: null,
  latencyMs: null,
  createdAt: new Date('2026-11-23T08:00:00.000Z'),
  conversationPublicId: '0193b000-0000-7000-8000-000000000703',
  turnPublicId: '0193b000-0000-7000-8000-000000000704',
  parentPublicId: null,
  ...overrides,
});

describe('refusal message of an execution view (step AI-3 D12)', () => {
  it('is the guard message of the stored operation for denied_guard', () => {
    expect(refusalMessageOf('denied_guard', 'UsersController_replaceRoles_v1')).toBe(
      GUARD_MESSAGES.self,
    );
    expect(refusalMessageOf('denied_guard', 'RolesController_update_v1')).toBe(
      GUARD_MESSAGES.assistant_configure,
    );
    expect(
      refusalMessageOf('denied_guard', 'OrganizationConfigurationController_overrideFeature_v1'),
    ).toBe(GUARD_MESSAGES.assistant_feature);
    // An operation without guards (never stored as denied_guard): the generic fallback.
    expect(refusalMessageOf('denied_guard', 'unknown')).toBe(DENIAL_MESSAGES.denied_guard);
  });

  it('is the fixed text of the decision for other refusals and null when allowed', () => {
    expect(refusalMessageOf('denied_permission', 'UsersController_replaceRoles_v1')).toBe(
      DENIAL_MESSAGES.denied_permission,
    );
    expect(refusalMessageOf('denied_schema', 'unknown')).toBe(DENIAL_MESSAGES.denied_schema);
    expect(refusalMessageOf('allowed', 'UsersController_replaceRoles_v1')).toBeNull();
  });

  it('puts the guard message and the tool title on a stored denied execution', () => {
    const view = executionView(row({}));
    expect(view.decision).toBe('denied_guard');
    expect(view.errorCode).toBe('denied_guard');
    expect(view.message).toBe(GUARD_MESSAGES.self);
    expect(view.title).not.toBe('users_replace_roles');
    expect(view.title.length).toBeGreaterThan(0);
    expect(view.card).toBeNull();
  });

  it('keeps an allowed execution without a message; an unknown tool is titled by its name', () => {
    const view = executionView(
      row({
        toolName: 'no_such_tool',
        operationId: 'unknown',
        decision: 'allowed',
        status: 'succeeded',
        errorCode: null,
      }),
    );
    expect(view.message).toBeNull();
    expect(view.title).toBe('no_such_tool');
  });

  it('shows the native report guards’ fixed messages (step AI-R D2 step 1, D5 step 2)', () => {
    expect(refusalMessageOf('denied_guard', 'AssistantNative_reportSendEmail')).toMatch(
      /^Reports can be emailed only to your own address/,
    );
    expect(refusalMessageOf('denied_guard', 'AssistantNative_reportGenerate')).toMatch(
      /platform override/,
    );
    expect(refusalMessageOf('denied_budget', 'AssistantNative_reportGenerate')).toBe(
      DENIAL_MESSAGES.denied_budget,
    );
    expect(
      refusalMessageOf(
        'denied_budget',
        'AssistantNative_reportGenerate',
        'assistant_report_generation_limit',
      ),
    ).toMatch(/daily limit of security reports/);
  });
});
