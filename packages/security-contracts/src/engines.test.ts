import { describe, expect, it } from 'vitest';
import {
  ENGINE_CATALOG,
  ENGINE_NAME_PATTERN,
  ENGINE_NAMES,
  type EngineCatalogEntry,
  engineCatalogEntry,
  isEngineName,
  isStage2Engine,
  parseEnabledEngines,
  requiredEngines,
  SECURITY_STAGES,
  stage2Engines,
  validateCatalog,
} from './index';

describe('engine catalog (S4)', () => {
  it('registers rspamd (4.1), attachment (4.2), url (4.3) and bec (4.4), required and not disableable', () => {
    expect(ENGINE_CATALOG).toHaveLength(4);
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
    // Step 4.4 B1: a stage-2 engine on its own queue, depending on rspamd and url.
    expect(ENGINE_CATALOG[3]).toEqual({
      name: 'bec',
      stage: 'bec',
      queue: 'scan.bec',
      requiredByDefault: true,
      tenantMayDisable: false,
      dependsOn: ['rspamd', 'url'],
      description:
        'Phishing and BEC: sender identity, impersonation, lookalikes, payment/urgency cues, credential links, communication history; optional AI layer (step 4.4)',
    });
    expect(Object.isFrozen(ENGINE_CATALOG[3]!.dependsOn)).toBe(true);
    for (const entry of ENGINE_CATALOG.slice(0, 3)) expect(entry.dependsOn).toBeUndefined();
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
    expect(engineCatalogEntry('bec')?.queue).toBe('scan.bec');
    expect(engineCatalogEntry('dlp')).toBeUndefined();
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
    expect(parseEnabledEngines('rspamd,attachment,url,bec')).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
    ]);
    expect(() => parseEnabledEngines('rspamd,dlp')).toThrow(/not in the catalog: dlp/);
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
    // Step 4.4 B1: bec is required for every tenant and cannot be disabled either.
    expect(requiredEngines(['bec', 'url', 'attachment', 'rspamd'], ['bec', 'url'])).toEqual([
      'rspamd',
      'attachment',
      'url',
      'bec',
    ]);
  });
});

describe('engine dependencies (step 4.4 B2)', () => {
  const entry = (
    name: EngineCatalogEntry['name'],
    dependsOn?: EngineCatalogEntry['name'][],
  ): EngineCatalogEntry => ({
    name,
    stage: 'bec',
    queue: `scan.${name}`,
    requiredByDefault: true,
    tenantMayDisable: false,
    ...(dependsOn === undefined ? {} : { dependsOn }),
    description: name,
  });

  it('validates the registered catalog: bec is the only stage-2 engine', () => {
    expect(() => validateCatalog()).not.toThrow();
    expect(() => validateCatalog(ENGINE_CATALOG)).not.toThrow();
    expect(stage2Engines()).toEqual(['bec']);
    expect(ENGINE_CATALOG.filter((e) => !isStage2Engine(e)).map((e) => e.name)).toEqual([
      'rspamd',
      'attachment',
      'url',
    ]);
    expect(isStage2Engine({})).toBe(false);
    expect(isStage2Engine({ dependsOn: [] })).toBe(false);
    expect(isStage2Engine({ dependsOn: ['rspamd'] })).toBe(true);
  });

  it('refuses an unknown, self, duplicate or depth > 1 dependency', () => {
    expect(() => validateCatalog([entry('rspamd'), entry('bec', ['rspamd', 'url'])])).toThrow(
      'Engine bec depends on url, which is not in the catalog',
    );
    expect(() => validateCatalog([entry('rspamd'), entry('bec', ['bec'])])).toThrow(
      'Engine bec depends on itself',
    );
    expect(() => validateCatalog([entry('rspamd'), entry('bec', ['rspamd', 'rspamd'])])).toThrow(
      'Engine bec lists a dependency twice',
    );
    expect(() =>
      validateCatalog([entry('rspamd'), entry('url', ['rspamd']), entry('bec', ['url'])]),
    ).toThrow('Engine bec depends on url, which has dependencies itself (depth > 1)');
    expect(() => validateCatalog([entry('rspamd'), entry('rspamd')])).toThrow(
      'Engine listed twice in the catalog: rspamd',
    );
    expect(() => validateCatalog([entry('rspamd'), entry('url'), entry('bec', [])])).not.toThrow();
    expect(stage2Engines([entry('rspamd'), entry('dlp', ['rspamd'])])).toEqual(['dlp']);
  });
});
