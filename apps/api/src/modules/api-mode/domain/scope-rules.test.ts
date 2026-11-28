import { describe, expect, it } from 'vitest';
import {
  checkScopeChange,
  departmentIdsOf,
  type ScopeChangeInput,
  storedDepartmentIds,
} from './scope-rules';

const DEPT = '0192f3a0-7777-7000-8000-000000000007';

function input(patch: Partial<ScopeChangeInput> = {}): ScopeChangeInput {
  return {
    effectiveMode: 'api',
    currentRowVersion: null,
    expectedRowVersion: null,
    scope: { kind: 'all' },
    knownDepartmentIds: new Set(),
    mailboxIds: [],
    domainMailboxMatches: 0,
    ...patch,
  };
}

describe('mailbox scope rules (step API-4 B6)', () => {
  it('accepts api and hybrid domains, refuses inline ones', () => {
    expect(checkScopeChange(input())).toBeNull();
    expect(checkScopeChange(input({ effectiveMode: 'hybrid' }))).toBeNull();
    expect(checkScopeChange(input({ effectiveMode: 'inline' }))).toEqual({
      code: 'api_mode_scope_domain_not_api',
      effectiveMode: 'inline',
    });
  });

  it('CAS: null creates; a mismatch is a conflict with the current version', () => {
    expect(checkScopeChange(input({ currentRowVersion: 2, expectedRowVersion: 2 }))).toBeNull();
    expect(checkScopeChange(input({ currentRowVersion: 2, expectedRowVersion: null }))).toEqual({
      code: 'api_mode_scope_conflict',
      currentRowVersion: 2,
    });
    expect(checkScopeChange(input({ currentRowVersion: null, expectedRowVersion: 1 }))).toEqual({
      code: 'api_mode_scope_conflict',
      currentRowVersion: null,
    });
  });

  it('departments must belong to the organization (case-insensitive)', () => {
    const scope = { kind: 'departments' as const, departmentIds: [DEPT.toUpperCase()] };
    expect(checkScopeChange(input({ scope, knownDepartmentIds: new Set([DEPT]) }))).toBeNull();
    expect(checkScopeChange(input({ scope }))).toEqual({
      code: 'api_mode_scope_department_invalid',
      departmentIds: [DEPT.toUpperCase()],
    });
  });

  it('selected mailboxes must all be mailboxes of the domain', () => {
    const scope = { kind: 'mailboxes' as const };
    const ids = ['0192f3a0-5555-7000-8000-000000000005', '0192f3a0-5555-7000-8000-000000000015'];
    expect(checkScopeChange(input({ scope, mailboxIds: ids, domainMailboxMatches: 2 }))).toBeNull();
    expect(checkScopeChange(input({ scope, mailboxIds: ids, domainMailboxMatches: 1 }))).toEqual({
      code: 'api_mode_scope_mailbox_invalid',
      invalid: 1,
    });
  });

  it('the mode is checked before CAS, CAS before departments', () => {
    expect(
      checkScopeChange(
        input({ effectiveMode: 'inline', currentRowVersion: 3, expectedRowVersion: 1 }),
      )?.code,
    ).toBe('api_mode_scope_domain_not_api');
    expect(
      checkScopeChange(
        input({
          currentRowVersion: 3,
          expectedRowVersion: 1,
          scope: { kind: 'departments', departmentIds: [DEPT] },
        }),
      )?.code,
    ).toBe('api_mode_scope_conflict');
  });

  it('stores lower-case department ids only for departments scopes', () => {
    expect(
      storedDepartmentIds({ kind: 'departments', departmentIds: [DEPT.toUpperCase()] }),
    ).toEqual([DEPT]);
    expect(storedDepartmentIds({ kind: 'all' })).toBeNull();
    expect(departmentIdsOf([DEPT, 3, null])).toEqual([DEPT]);
    expect(departmentIdsOf(null)).toEqual([]);
  });
});
