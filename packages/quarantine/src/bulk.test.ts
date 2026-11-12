import { describe, expect, it } from 'vitest';
import {
  BULK_ACTION_PERMISSIONS,
  BULK_ACTIONS,
  bulkActionNeedsUserMfa,
  bulkResult,
  bulkResultSchema,
  checkBulkRequest,
} from './bulk';

const id = (n: number) => `01930000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const ids = (n: number) => Array.from({ length: n }, (_, i) => id(i + 1));

describe('bulk actions (Q18)', () => {
  it('lists the actions and their permissions', () => {
    expect(BULK_ACTIONS).toEqual(['release', 'reject', 'delete', 'approve', 'deny']);
    expect(BULK_ACTION_PERMISSIONS).toEqual({
      release: 'quarantine:release',
      reject: 'quarantine:reject',
      delete: 'quarantine:delete',
      approve: 'quarantine:approve',
      deny: 'quarantine:approve',
    });
    expect(BULK_ACTIONS.filter(bulkActionNeedsUserMfa)).toEqual(['approve', 'deny']);
  });
  it('accepts 1..maxItems unique ids', () => {
    const r = checkBulkRequest(
      { action: 'reject', ids: ids(100), reason: 'spam wave' },
      { maxItems: 100 },
    );
    expect(r.ok).toBe(true);
    expect(
      checkBulkRequest(
        { action: 'release', ids: ids(1), reason: 'x', notifySender: true },
        { maxItems: 100 },
      ).ok,
    ).toBe(true);
  });
  it.each([
    [{ action: 'reject', ids: [], reason: 'x' }, 100, 'empty'],
    [{ action: 'reject', ids: ids(101), reason: 'x' }, 100, 'too_many'],
    [{ action: 'reject', ids: ids(6), reason: 'x' }, 5, 'too_many'],
    [{ action: 'reject', ids: ids(501), reason: 'x' }, 500, 'too_many'],
    [{ action: 'reject', ids: [id(1), id(1)], reason: 'x' }, 100, 'duplicate_ids'],
    [{ action: 'purge', ids: ids(1), reason: 'x' }, 100, 'invalid'],
    [{ action: 'reject', ids: ['nope'], reason: 'x' }, 100, 'invalid'],
    [{ action: 'reject', ids: ids(1), reason: '  ' }, 100, 'invalid'],
    [{ action: 'reject', ids: ids(1), reason: 'x'.repeat(513) }, 100, 'invalid'],
    [{ action: 'reject', ids: ids(1), reason: 'x', extra: 1 }, 100, 'invalid'],
    [null, 100, 'invalid'],
  ])('refuses %j (max %i) → %s', (body, maxItems, cause) => {
    expect(checkBulkRequest(body, { maxItems })).toEqual({
      ok: false,
      code: 'quarantine_bulk_limit',
      cause,
    });
  });
  it('the platform bound caps a misconfigured limit at 500', () => {
    expect(
      checkBulkRequest({ action: 'delete', ids: ids(500), reason: 'x' }, { maxItems: 10_000 }).ok,
    ).toBe(true);
  });
  it('builds a per-item result with counts', () => {
    const r = bulkResult('release', [
      { id: id(1), status: 'queued', releaseId: id(9) },
      { id: id(2), status: 'approval_requested', approvalRequestId: id(8) },
      { id: id(3), status: 'refused', code: 'quarantine_rescan_required' },
      { id: id(4), status: 'not_found' },
      { id: id(5), status: 'skipped', code: 'deadline' },
    ]);
    expect(r.counts).toEqual({
      queued: 1,
      approval_requested: 1,
      done: 0,
      refused: 1,
      not_found: 1,
      skipped: 1,
    });
    expect(bulkResultSchema.parse(r)).toEqual(r);
  });
});
