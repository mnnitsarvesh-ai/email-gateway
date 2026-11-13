import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ROLE_PERMISSIONS, SYSTEM_ROLE_KEYS } from './roles';

describe('role permission fixtures', () => {
  it('equal the matrix in docs/security/rbac.md', () => {
    const md = readFileSync(join(__dirname, '../../../../docs/security/rbac.md'), 'utf8');
    const section = md.slice(md.indexOf('### Permission matrix'));
    const header = section.split('\n').find((l) => l.startsWith('| Permission'));
    expect(header).toBeDefined();
    const columns = (header ?? '')
      .split('|')
      .slice(2, -1)
      .map((c) => c.trim());
    const abbreviations: Record<string, string> = {
      SA: 'super_admin',
      PA: 'platform_admin',
      OA: 'organization_admin',
      DA: 'domain_admin',
      SAn: 'security_analyst',
      QR: 'quarantine_reviewer',
      CA: 'compliance_auditor',
      RO: 'read_only_user',
      MU: 'mailbox_user',
    };
    const parsed: Record<string, string[]> = Object.fromEntries(
      columns.map((c) => [abbreviations[c] ?? c, []]),
    );
    for (const line of section.split('\n').filter((l) => l.startsWith('| `'))) {
      const cells = line
        .split('|')
        .slice(1, -1)
        .map((c) => c.trim());
      const permission = (cells[0] ?? '').replace(/`/g, '');
      cells.slice(1).forEach((cell, index) => {
        if (cell === '✓') parsed[abbreviations[columns[index] ?? ''] ?? '']?.push(permission);
      });
    }
    expect(Object.keys(parsed).sort()).toEqual([...SYSTEM_ROLE_KEYS].sort());
    for (const role of SYSTEM_ROLE_KEYS)
      expect([...ROLE_PERMISSIONS[role]].sort(), role).toEqual(parsed[role]?.sort());
  });
});
