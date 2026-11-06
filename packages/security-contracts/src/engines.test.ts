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
  it('registers rspamd (4.1), attachment (4.2) and url (4.3), required and not disableable', () => {
    expect(ENGINE_CATALOG).toHaveLength(3);
    expect(ENGINE_CATALOG[0]).toMatchObject({
      name: 'rspamd',
      stage: 'antispam',
      queue: 'scan.spam',
      requiredByDefault: true,
      tenantMayDisable: false,
    });
    expect(ENGINE_CATALOG[1]).toEqual({
      name: 'attachment',
      stage: 'attachment',
      queue: 'scan.attachment',
      requiredByDefault: true,
      tenantMayDisable: false,
      description:
        'Attachments: file type, known-threat hashes, ClamAV, YARA, archive limits (step 4.2)',
    });
    expect(ENGINE_CATALOG[2]).toEqual({
      name: 'url',
      stage: 'url',
      queue: 'scan.url',
      requiredByDefault: true,
      tenantMayDisable: false,
      description:
        'URLs: extraction, normalization, reputation, lookalikes, redirect chains, rewriting (step 4.3)',
    });
    for (const entry of ENGINE_CATALOG) {
      expect(entry.description.length).toBeGreaterThan(0);
      expect(Object.isFrozen(entry)).toBe(true);
    }
    expect(Object.isFrozen(ENGINE_CATALOG)).toBe(true);
  });

  it('knows every planned engine name and stage, and every name fits the row/event pattern', () => {
    // Step 4.2 A1: ClamAV and YARA are components of the attachment engine, not engines.
    expect([...ENGINE_NAMES]).toEqual(['rspamd', 'attachment', 'url', 'bec', 'dlp', 'sandbox']);
    expect([...SECURITY_STAGES]).toEqual([
      'antispam',
      'attachment',
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
      expect(entry.queue).toBe(entry.name === 'rspamd' ? 'scan.spam' : `scan.${entry.name}`);
    }
    expect(new Set(ENGINE_CATALOG.map((e) => e.queue)).size).toBe(ENGINE_CATALOG.length);
  });

  it('looks up entries and names', () => {
    expect(engineCatalogEntry('rspamd')?.queue).toBe('scan.spam');
    expect(engineCatalogEntry('attachment')?.queue).toBe('scan.attachment');
    expect(engineCatalogEntry('url')?.queue).toBe('scan.url');
    expect(engineCatalogEntry('bec')).toBeUndefined();
    expect(engineCatalogEntry('clamav')).toBeUndefined();
    expect(isEngineName('url')).toBe(true);
    expect(isEngineName('clamav')).toBe(false);
    expect(isEngineName('yara')).toBe(false);
    expect(isEngineName('spamassassin')).toBe(false);
  });

  it('parses SCAN_ENGINES and refuses empty, duplicate and unregistered engines', () => {
    expect(parseEnabledEngines('rspamd')).toEqual(['rspamd']);
    expect(parseEnabledEngines(' rspamd , ')).toEqual(['rspamd']);
    expect(parseEnabledEngines('rspamd,attachment')).toEqual(['rspamd', 'attachment']);
    expect(parseEnabledEngines('attachment')).toEqual(['attachment']);
    expect(() => parseEnabledEngines('')).toThrow(/No scan engine/);
    expect(() => parseEnabledEngines('rspamd,rspamd')).toThrow(/twice/);
    expect(() => parseEnabledEngines('rspamd,clamav')).toThrow(/not in the catalog: clamav/);
    expect(parseEnabledEngines('rspamd,attachment,url')).toEqual(['rspamd', 'attachment', 'url']);
    expect(() => parseEnabledEngines('rspamd,bec')).toThrow(/not in the catalog: bec/);
  });

  it('snapshots the required engines; a tenant cannot drop an engine it may not disable', () => {
    expect(requiredEngines(['rspamd'])).toEqual(['rspamd']);
    expect(requiredEngines(['rspamd'], ['rspamd'])).toEqual(['rspamd']);
    expect(requiredEngines([])).toEqual([]);
    // Catalog order, whatever the order of SCAN_ENGINES; attachment cannot be disabled either.
    expect(requiredEngines(['attachment', 'rspamd'])).toEqual(['rspamd', 'attachment']);
    expect(requiredEngines(['rspamd', 'attachment'], ['attachment', 'rspamd'])).toEqual([
      'rspamd',
      'attachment',
    ]);
    // Step 4.3 U1: the url engine is required for every tenant.
    expect(requiredEngines(['url', 'attachment', 'rspamd'], ['url'])).toEqual([
      'rspamd',
      'attachment',
      'url',
    ]);
  });
});
