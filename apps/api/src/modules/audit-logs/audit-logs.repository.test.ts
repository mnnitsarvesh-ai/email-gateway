import { describe, expect, it } from 'vitest';
import {
  AUDIT_RESOURCE_INDEX,
  AUDIT_TIME_INDEX,
  auditSql,
  type AuditSearch,
  residualOf,
  resourceOf,
} from './audit-logs.repository';

const flat = (sql: { sql: string }) => sql.sql.replace(/\s+/g, ' ');
const search: AuditSearch = {
  owner: { kind: 'organization', organizationId: 40n },
  from: new Date('2026-11-01T00:00:00Z'),
  to: new Date('2026-11-08T00:00:00Z'),
  direction: 'desc',
  after: { createdAt: new Date('2026-11-05T00:00:00Z'), id: 77n },
};
const resource = { type: 'message', id: "m-1' OR 1=1" };

describe('audit resource plan SQL (step 7.2 §2 E3, §3.2)', () => {
  it('reads the organization-led resource index in keyset order, exact comparisons pushed down', () => {
    const sql = auditSql.resourcePage(search, resource, 26);
    const text = flat(sql);
    expect(text).toContain(`FROM audit_logs FORCE INDEX (${AUDIT_RESOURCE_INDEX})`);
    expect(text).toMatch(
      /WHERE organization_id = \? AND created_at >= \? AND created_at < \? AND \(created_at < \? OR \(created_at = \? AND id < \?\)\) AND resource_type = \? AND resource_id = \? AND resource_type = \? COLLATE utf8mb4_0900_bin AND resource_id = \? COLLATE utf8mb4_0900_bin/,
    );
    expect(text).toContain('ORDER BY created_at DESC, id DESC LIMIT ?');
    expect(sql.sql).not.toContain(resource.id);
    expect(sql.values).toContain(resource.id);
  });

  it('uses organization_id IS NULL for the platform rows', () => {
    const text = flat(
      auditSql.resourcePage({ ...search, owner: { kind: 'platform' } }, resource, 5),
    );
    expect(text).toContain('WHERE organization_id IS NULL AND created_at >= ?');
    expect(text).toContain(`FORCE INDEX (${AUDIT_RESOURCE_INDEX})`);
  });

  it('budgeted with other filters: index-only boundary, residuals in the page', () => {
    const boundary = auditSql.resourceBoundary(search, resource, 5000);
    expect(flat(boundary)).toContain(`FORCE INDEX (${AUDIT_RESOURCE_INDEX})`);
    expect(flat(boundary)).toContain('LIMIT 1 OFFSET ?');
    expect(boundary.values.at(-1)).toBe(4999);
    const page = flat(
      auditSql.resourceFiltered(
        search,
        resource,
        { actionPrefix: 'message.', actorType: 'user' },
        { createdAt: new Date('2026-11-02T00:00:00Z'), id: 5n },
        26,
      ),
    );
    expect(page).toContain('(created_at > ? OR (created_at = ? AND id >= ?))');
    expect(page).toContain('actor_type = ? COLLATE utf8mb4_0900_bin');
    expect(page).toContain('action LIKE ? COLLATE utf8mb4_0900_bin');
  });

  it('selects the plan only when both resource fields are present', () => {
    expect(resourceOf({ resourceType: 'message', resourceId: 'x', action: 'a' })).toEqual({
      type: 'message',
      id: 'x',
    });
    expect(resourceOf({ resourceType: 'message' })).toBeNull();
    expect(resourceOf({ resourceId: 'x' })).toBeNull();
    expect(residualOf({ resourceType: 'message', resourceId: 'x', actorId: 'u' })).toEqual({
      actorId: 'u',
    });
  });
});

describe('the 6.1 audit statements name their index since step 7.2', () => {
  it('page, boundary and filtered force (organization_id, created_at)', () => {
    for (const sql of [
      auditSql.page(search, 26),
      auditSql.boundary(search, 5000),
      auditSql.filtered(search, { actionPrefix: 'quarantine.' }, null, 26),
    ]) {
      expect(flat(sql)).toContain(`FROM audit_logs FORCE INDEX (${AUDIT_TIME_INDEX})`);
    }
  });
});
