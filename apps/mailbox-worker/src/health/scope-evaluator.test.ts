import { describe, expect, it } from 'vitest';
import { evaluateMailboxScope, scopeDepartmentIds } from './scope-evaluator';

const members = {
  addresses: new Set(['alice@corp.example']),
  userEmails: new Set(['bob@corp.example']),
};

describe('evaluateMailboxScope (B6)', () => {
  it('all → in scope; mailboxes → the selection', () => {
    expect(evaluateMailboxScope('all', { scopeSelected: false, addresses: [] }, null)).toBe(
      'in_scope',
    );
    expect(evaluateMailboxScope('mailboxes', { scopeSelected: true, addresses: [] }, null)).toBe(
      'in_scope',
    );
    expect(evaluateMailboxScope('mailboxes', { scopeSelected: false, addresses: [] }, null)).toBe(
      'excluded',
    );
  });

  it('departments: a member address or an active member user, primary or alias, case-insensitive', () => {
    const at = (addresses: string[]) =>
      evaluateMailboxScope('departments', { scopeSelected: false, addresses }, members);
    expect(at(['ALICE@corp.example'])).toBe('in_scope');
    expect(at(['b.alias@corp.example', 'bob@corp.example'])).toBe('in_scope');
    expect(at(['carol@corp.example'])).toBe('excluded');
    expect(evaluateMailboxScope('departments', { scopeSelected: true, addresses: [] }, null)).toBe(
      'excluded',
    );
  });

  it('reads bounded, unique department ids from the stored JSON', () => {
    const a = '0193a000-0000-7000-8000-000000000001';
    const b = '0193a000-0000-7000-8000-000000000002';
    expect(scopeDepartmentIds(JSON.stringify([a, a.toUpperCase(), 'x', b]), 20)).toEqual([a, b]);
    expect(scopeDepartmentIds([a, b], 1)).toEqual([a]);
    expect(scopeDepartmentIds(null, 20)).toEqual([]);
  });
});
