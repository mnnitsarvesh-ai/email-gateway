import { describe, expect, it } from 'vitest';
import {
  ENGINE_CATALOG,
  ENGINE_NAME_PATTERN,
  ENGINE_NAMES,
  engineCatalogEntry,
  isEngineName,
  parseEnabledEngines,
  requiredEngines,
  SECURITY_STAGES,
} from './index';

describe('engine catalog (S4)', () => {
  it('registers only rspamd in step 4.1, required and not disableable, on scan.spam', () => {
    expect(ENGINE_CATALOG).toHaveLength(1);
    expect(ENGINE_CATALOG[0]).toMatchObject({
      name: 'rspamd',
      stage: 'antispam',
      queue: 'scan.spam',
      requiredByDefault: true,
      tenantMayDisable: false,
    });
    expect(ENGINE_CATALOG[0]!.description.length).toBeGreaterThan(0);
    expect(Object.isFrozen(ENGINE_CATALOG)).toBe(true);
    expect(Object.isFrozen(ENGINE_CATALOG[0])).toBe(true);
  });

  it('knows every planned engine name and stage, and every name fits the row/event pattern', () => {
    expect([...ENGINE_NAMES]).toEqual(['rspamd', 'clamav', 'yara', 'url', 'bec', 'dlp', 'sandbox']);
    expect([...SECURITY_STAGES]).toEqual([
      'antispam',
      'antivirus',
      'yara',
      'url',
      'bec',
      'dlp',
      'sandbox',
    ]);
    for (const name of ENGINE_NAMES) expect(ENGINE_NAME_PATTERN.test(name), name).toBe(true);
    for (const entry of ENGINE_CATALOG) {
      expect(ENGINE_NAMES).toContain(entry.name);
      expect(SECURITY_STAGES).toContain(entry.stage);
      expect(entry.queue).toMatch(/^scan\.[a-z]+$/);
    }
    expect(new Set(ENGINE_CATALOG.map((e) => e.queue)).size).toBe(ENGINE_CATALOG.length);
  });

  it('looks up entries and names', () => {
    expect(engineCatalogEntry('rspamd')?.queue).toBe('scan.spam');
    expect(engineCatalogEntry('clamav')).toBeUndefined();
    expect(isEngineName('clamav')).toBe(true);
    expect(isEngineName('spamassassin')).toBe(false);
  });

  it('parses SCAN_ENGINES and refuses empty, duplicate and unregistered engines', () => {
    expect(parseEnabledEngines('rspamd')).toEqual(['rspamd']);
    expect(parseEnabledEngines(' rspamd , ')).toEqual(['rspamd']);
    expect(() => parseEnabledEngines('')).toThrow(/No scan engine/);
    expect(() => parseEnabledEngines('rspamd,rspamd')).toThrow(/twice/);
    expect(() => parseEnabledEngines('rspamd,clamav')).toThrow(/not in the catalog: clamav/);
  });

  it('snapshots the required engines; a tenant cannot drop an engine it may not disable', () => {
    expect(requiredEngines(['rspamd'])).toEqual(['rspamd']);
    expect(requiredEngines(['rspamd'], ['rspamd'])).toEqual(['rspamd']);
    expect(requiredEngines([])).toEqual([]);
  });
});
