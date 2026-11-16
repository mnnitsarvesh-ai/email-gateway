import { screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { renderWithProviders } from '@/test';
import {
  buildDefinition,
  changeLeafOperator,
  defaultLeaf,
  operatorsFor,
  summarizeDefinition,
  summaryToText,
  type BuilderLeaf,
} from './builder';
import { EditorHarness, modelOf } from './builder/test-support/harness';
import { REAL_BUILDER_CATALOG, REAL_CATALOG } from './test-data';

/**
 * The real catalogue snapshot drives the builder (design §11, §9.3 WP3): docs/api/policy-catalog.json
 * (with a concrete time-zone list) parses, every field offers every one of its operators, and
 * every field × operator builds a condition the summary renders and the editor can edit.
 */

const catalog = REAL_BUILDER_CATALOG;

function leafJson(leaf: BuilderLeaf): Record<string, unknown> {
  return {
    field: leaf.field,
    op: leaf.op,
    ...(leaf.value !== undefined ? { value: leaf.value } : {}),
    ...(leaf.quantifier !== undefined ? { quantifier: leaf.quantifier } : {}),
  };
}

/** Every field × operator the catalogue offers in a rule's conditions. */
function pairs(): Array<{ field: string; op: string; leaf: BuilderLeaf }> {
  return catalog.fields.flatMap((field) =>
    operatorsFor(catalog, field.name, 'when').map((operator) => ({
      field: field.name,
      op: operator.op,
      leaf: changeLeafOperator(catalog, defaultLeaf(catalog, field.name, 'when'), operator.op),
    })),
  );
}

const ruleDoc = (when: unknown) => ({
  dslVersion: 'policy-dsl/1',
  direction: 'any',
  priority: 1,
  rules: [{ id: 'smoke', priority: 0, when, actions: [{ type: 'ALERT', severity: 'info' }] }],
});

describe('the real catalogue snapshot drives the builder', () => {
  it('toBuilderCatalog accepts docs/api/policy-catalog.json with a time-zone list', () => {
    expect(catalog.fields).toHaveLength(REAL_CATALOG.fields.length);
    expect(catalog.fields.length).toBeGreaterThanOrEqual(76);
    expect(catalog.operatorDefinitions).toHaveLength(18);
    expect(catalog.actionDefinitions).toHaveLength(9);
    expect(catalog.timeZones).toContain('UTC');
    expect(catalog.limits.documentBytes).toBe(262_144);
  });

  it('every field offers every operator of its `ops` (each has a known value shape)', () => {
    for (const field of catalog.fields) {
      expect(
        operatorsFor(catalog, field.name, 'when').map((o) => o.op),
        field.name,
      ).toEqual(field.ops);
    }
  });

  it('for every field and each of its operators defaultLeaf builds and the summary renders a line', () => {
    const all = pairs();
    expect(all.length).toBeGreaterThanOrEqual(200);
    for (const { field, op, leaf } of all) {
      expect(leaf.field, `${field} ${op}`).toBe(field);
      expect(leaf.op, `${field} ${op}`).toBe(op);
      const summary = summarizeDefinition(ruleDoc(leafJson(leaf)), catalog);
      const rule = summary.rules[0];
      expect(rule, `${field} ${op}`).toBeDefined();
      const label = catalog.fields.find((f) => f.name === field)?.label ?? '';
      const phrase = catalog.operatorDefinitions.find((o) => o.op === op)?.phrase ?? '';
      const text = summaryToText(summary);
      expect(text, `${field} ${op}`).toContain(label);
      expect(text, `${field} ${op}`).toContain(phrase);
    }
  });

  it('every field × operator gets a value editor (none is left "cannot be edited")', () => {
    const all = pairs();
    const doc = ruleDoc({ all: all.map(({ leaf }) => leafJson(leaf)) });
    const model = modelOf(doc);
    renderWithProviders(<EditorHarness initial={model} catalog={catalog} />);
    expect(screen.getAllByRole('group', { name: /^Condition \d+ of \d+/ })).toHaveLength(
      all.length,
    );
    expect(screen.queryByText(/value cannot be edited here/)).not.toBeInTheDocument();
    // The model builds back to the same document (nothing lost on the way through the editor).
    expect(buildDefinition(model).definition).toEqual(doc);
  });
});
