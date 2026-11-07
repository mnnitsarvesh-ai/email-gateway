import { describe, expect, it } from 'vitest';
import { lookalikeVersion, loadBrands } from '@email-gateway/url-security';
import { becEngineVersion, brandsHash, loadBecStaticData } from './static-data';

describe('static data and versions (B16)', () => {
  it('engine version is bec/1;lex=;fm=;br= and ≤ 64 characters', () => {
    const data = loadBecStaticData();
    expect(data.engineVersion).toMatch(/^bec\/1;lex=[0-9a-f]{8};fm=[0-9a-f]{8};br=[0-9a-f]{8}$/);
    expect(data.engineVersion.length).toBeLessThanOrEqual(64);
    expect(data.engineVersion).toContain(`lex=${data.lexicon.version}`);
    expect(data.engineVersion).toContain(`fm=${data.freemail.version}`);
  });
  it('the brands hash is the one of url-security lookalikeVersion', () => {
    const brands = loadBrands();
    expect(lookalikeVersion(brands).endsWith(`;brands=${brandsHash(brands)}`)).toBe(true);
  });
  it('refuses a version longer than 64 characters', () => {
    expect(() => becEngineVersion('x'.repeat(40), 'y'.repeat(8), 'z'.repeat(8))).toThrow(/64/);
  });
});
