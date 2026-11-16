import { describe, expect, it } from 'vitest';
import {
  CatalogShapeError,
  groupFields,
  isAllDirections,
  limitOf,
  operatorsFor,
  toBuilderCatalog,
} from './catalog';
import { RAW_TEST_CATALOG, TEST_CATALOG } from './test-support/catalog';

describe('toBuilderCatalog (design §4.1, §4.7)', () => {
  it('keeps exactly the keys the builder reads and ignores extra keys (non-strict)', () => {
    const catalog = toBuilderCatalog({ ...RAW_TEST_CATALOG, newerKey: { anything: true } });
    expect(Object.keys(catalog).sort()).toEqual(
      [
        'actionDefinitions',
        'contextRules',
        'enforcement',
        'fieldGroups',
        'fields',
        'limits',
        'messageDirections',
        'operatorDefinitions',
        'policyDirections',
        'quantifiers',
        'scopeNouns',
        'timeZones',
        'versions',
        'weekdays',
      ].sort(),
    );
    expect(catalog.versions).toEqual({ dsl: 'policy-dsl/1' });
    expect('authenticatedIdentity' in catalog.fields[0]!).toBe(false);
    expect(catalog.fields).toHaveLength(RAW_TEST_CATALOG.fields.length);
  });

  it('throws CatalogShapeError naming the problems of a catalogue that cannot drive the builder', () => {
    const { operatorDefinitions: _ops, ...withoutOperators } = RAW_TEST_CATALOG;
    expect(() => toBuilderCatalog(withoutOperators)).toThrow(CatalogShapeError);
    try {
      toBuilderCatalog({
        ...RAW_TEST_CATALOG,
        fields: [{ ...RAW_TEST_CATALOG.fields[0]!, contexts: undefined }],
      });
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(CatalogShapeError);
      expect((error as CatalogShapeError).issues[0]).toMatch(/^fields\.0\.contexts/);
    }
    expect(() => toBuilderCatalog(null)).toThrow(CatalogShapeError);
  });

  it('refuses a catalogue of another DSL version', () => {
    expect(() =>
      toBuilderCatalog({ ...RAW_TEST_CATALOG, versions: { dsl: 'policy-dsl/2' } }),
    ).toThrow(/edits policy-dsl\/1 documents, the catalogue describes policy-dsl\/2/);
  });

  it('offers no operator whose value shape the builder has no widget for', () => {
    const catalog = toBuilderCatalog({
      ...RAW_TEST_CATALOG,
      operatorDefinitions: RAW_TEST_CATALOG.operatorDefinitions.map((o) =>
        o.op === 'in' ? { ...o, valueShape: 'matrix' } : o,
      ),
    });
    expect(operatorsFor(catalog, 'auth.spf', 'when').map((o) => o.op)).toEqual(['equals']);
  });

  it('reads limits from the catalogue (absent = no client-side cap)', () => {
    expect(limitOf(TEST_CATALOG.limits, 'depth')).toBe(6);
    expect(limitOf(TEST_CATALOG.limits, 'unknownLimit')).toBe(Number.POSITIVE_INFINITY);
    expect(limitOf(undefined, 'depth')).toBe(Number.POSITIVE_INFINITY);
  });

  it('groups fields in fieldGroups order with their labels; unknown groups last', () => {
    const fields = [
      { ...TEST_CATALOG.fields.find((f) => f.name === 'time.window')!, group: 'future' },
      TEST_CATALOG.fields.find((f) => f.name === 'dlp.categories')!,
      TEST_CATALOG.fields.find((f) => f.name === 'direction')!,
    ];
    expect(
      groupFields(TEST_CATALOG, fields).map((g) => [g.label, g.fields.map((f) => f.name)]),
    ).toEqual([
      ['Message', ['direction']],
      ['Data loss prevention', ['dlp.categories']],
      ['Other fields', ['time.window']],
    ]);
  });

  it('recognizes the all-directions policy direction as the one that is not a message direction', () => {
    expect(isAllDirections(TEST_CATALOG, 'any')).toBe(true);
    expect(isAllDirections(TEST_CATALOG, 'inbound')).toBe(false);
    expect(isAllDirections(TEST_CATALOG, 'sideways')).toBe(false);
  });
});
