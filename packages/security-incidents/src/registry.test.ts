import { describe, expect, it } from 'vitest';
import { IncidentCategoryRegistry } from './registry';
import { fakeCategoryHandler } from './testing';

const ato = () =>
  fakeCategoryHandler({ category: 'account_takeover', read: 'ato:read', manage: 'ato:manage' });

describe('IncidentCategoryRegistry', () => {
  it('registers, finds and gets handlers', () => {
    const registry = new IncidentCategoryRegistry([ato()]);
    expect(registry.has('account_takeover')).toBe(true);
    expect(registry.get('account_takeover').permissions.read).toBe('ato:read');
    expect(registry.find('fake_category')).toBeUndefined();
    expect(() => registry.get('fake_category')).toThrow(/not registered/);
    expect(registry.categories()).toEqual(['account_takeover']);
  });

  it('refuses duplicates, malformed permissions and empty subject types', () => {
    const registry = new IncidentCategoryRegistry([ato()]);
    expect(() => registry.register(ato())).toThrow(/already registered/);
    expect(() =>
      new IncidentCategoryRegistry().register(fakeCategoryHandler({ read: 'Not A Permission' })),
    ).toThrow(/malformed/);
    expect(() =>
      new IncidentCategoryRegistry().register(fakeCategoryHandler({ subjectTypes: [] })),
    ).toThrow(/no subject type/);
  });

  it('lists read and manage permissions of every category (unique, sorted)', () => {
    const registry = new IncidentCategoryRegistry([
      ato(),
      fakeCategoryHandler(),
      fakeCategoryHandler({ category: 'shared_perm', read: 'ato:read', manage: 'ato:manage' }),
    ]);
    expect(registry.readPermissions()).toEqual(['ato:read', 'fake:read']);
    expect(registry.managePermissions()).toEqual(['ato:manage', 'fake:manage']);
  });

  it('restricts categories to the permissions held (isolation by category)', () => {
    const registry = new IncidentCategoryRegistry([ato(), fakeCategoryHandler()]);
    expect(registry.categoriesReadableBy(['ato:read'])).toEqual(['account_takeover']);
    expect(registry.categoriesReadableBy(['fake:read'])).toEqual(['fake_category']);
    expect(registry.categoriesReadableBy(['fake:read', 'ato:read'])).toEqual([
      'account_takeover',
      'fake_category',
    ]);
    expect(registry.categoriesReadableBy(['ato:manage'])).toEqual([]);
    expect(registry.categoriesReadableBy([])).toEqual([]);
    expect(registry.categoriesManageableBy(new Set(['ato:manage']))).toEqual(['account_takeover']);
    expect(registry.categoriesManageableBy(['ato:read'])).toEqual([]);
  });
});
