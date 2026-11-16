import type { BuilderCatalog, CatalogField } from '../catalog';

/**
 * Seeded generator of `policy-dsl/1`-shaped documents for the round-trip tests (design §9.3).
 * Documents follow the document grammar but carry arbitrary values (the model carries values
 * through unvalidated), random optional-key presence, nested groups and NOT chains.
 */

export class SeededRandom {
  private state: number;
  constructor(seed: number) {
    this.state = seed >>> 0;
  }
  /** mulberry32 */
  next(): number {
    this.state = (this.state + 0x6d2b79f5) >>> 0;
    let t = this.state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  int(maxExclusive: number): number {
    return Math.floor(this.next() * maxExclusive);
  }
  bool(probability = 0.5): boolean {
    return this.next() < probability;
  }
  pick<T>(items: readonly T[]): T {
    return items[this.int(items.length)]!;
  }
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

const WORDS = [
  'alpha',
  'beta',
  'gamma',
  'example.com',
  'Ünïcode',
  'with space',
  '',
  '*.example',
  'a"b',
];

function randomJson(rng: SeededRandom, depth = 0): Json {
  const roll = rng.int(depth > 2 ? 5 : 7);
  switch (roll) {
    case 0:
      return null;
    case 1:
      return rng.bool();
    case 2:
      return rng.int(2_000_000) - 1000;
    case 3:
    case 4:
      return rng.pick(WORDS);
    case 5:
      return Array.from({ length: rng.int(4) }, () => randomJson(rng, depth + 1));
    default: {
      const out: { [key: string]: Json } = {};
      for (let i = rng.int(3); i > 0; i -= 1)
        out[rng.pick(['pattern', 'flags', 'k', 'timeZone'])] = randomJson(rng, depth + 1);
      return out;
    }
  }
}

function valueFor(
  rng: SeededRandom,
  catalog: BuilderCatalog,
  field: CatalogField,
  op: string,
): Json | undefined {
  const def = catalog.operatorDefinitions.find((o) => o.op === op);
  if (rng.bool(0.1)) return randomJson(rng);
  switch (def?.valueShape) {
    case 'none':
      return undefined;
    case 'boolean':
      return rng.bool();
    case 'range':
      return [rng.int(1000), 1000 + rng.int(1_000_000)];
    case 'time':
      return rng.bool()
        ? {
            timeZone: rng.pick(catalog.timeZones),
            days: catalog.weekdays.filter(() => rng.bool()),
            from: '09:00',
            to: rng.pick(['18:00', '24:00']),
          }
        : { timeZone: rng.pick(catalog.timeZones), from: '2026-12-24', to: '2026-12-26' };
    case 'list': {
      const n = 1 + rng.int(7);
      return Array.from({ length: n }, () => {
        if (def.itemKind === 'regex' && rng.bool())
          return { pattern: `^${rng.pick(WORDS)}$`, flags: rng.pick(['', 'i']) };
        if (field.values) return rng.pick(field.values);
        if (field.type === 'id')
          return `01930000-0000-7000-8000-${String(rng.int(1e12)).padStart(12, '0')}`;
        return rng.pick(WORDS);
      });
    }
    default:
      if (field.values) return rng.pick(field.values);
      if (field.type === 'int') return rng.int(1_000_000);
      return rng.pick(WORDS);
  }
}

function randomLeaf(rng: SeededRandom, catalog: BuilderCatalog): Json {
  const leaf: { [key: string]: Json } = {};
  const field = rng.pick(catalog.fields);
  if (!rng.bool(0.05)) leaf.field = rng.bool(0.05) ? 'unknown.field' : field.name;
  const op = rng.bool(0.05) ? 'unknown_op' : rng.pick(field.ops);
  if (!rng.bool(0.05)) leaf.op = op;
  const value = valueFor(rng, catalog, field, op);
  if (value !== undefined) leaf.value = value;
  if (field.quantified ? rng.bool(0.5) : rng.bool(0.05)) leaf.quantifier = rng.pick(['any', 'all']);
  return leaf;
}

function randomNode(rng: SeededRandom, catalog: BuilderCatalog, depth: number): Json {
  const roll = depth >= 5 ? 0 : rng.int(10);
  if (roll <= 4) return randomLeaf(rng, catalog);
  if (roll <= 6) return { not: randomNode(rng, catalog, depth + 1) };
  const joiner = rng.bool() ? 'all' : 'any';
  return {
    [joiner]: Array.from({ length: rng.int(4) }, () => randomNode(rng, catalog, depth + 1)),
  };
}

function randomAction(rng: SeededRandom, catalog: BuilderCatalog): Json {
  const def = rng.pick(catalog.actionDefinitions);
  const action: { [key: string]: Json } = { type: def.type };
  for (const param of def.params) {
    if (!rng.bool(0.5)) continue;
    action[param.name] =
      param.type === 'boolean'
        ? rng.bool()
        : param.values
          ? rng.pick(param.values)
          : rng.bool(0.8)
            ? rng.pick(WORDS)
            : randomJson(rng);
  }
  if (rng.bool(0.05)) action.unknownParam = randomJson(rng);
  return action;
}

/** One random document; `n` makes rule ids distinct across rules. */
export function randomDocument(
  rng: SeededRandom,
  catalog: BuilderCatalog,
): { [key: string]: Json } {
  const doc: { [key: string]: Json } = {
    dslVersion: 'policy-dsl/1',
    direction: rng.pick(catalog.policyDirections),
    priority: rng.int(10_001),
    rules: Array.from({ length: 1 + rng.int(4) }, (_, i) => {
      const rule: { [key: string]: Json } = { id: `rule-${i + 1}`, priority: i * 10 + rng.int(10) };
      if (rng.bool(0.4)) rule.description = rng.pick(WORDS);
      if (rng.bool(0.3)) rule.enabled = rng.bool();
      if (rng.bool(0.3)) rule.directions = catalog.messageDirections.filter(() => rng.bool());
      rule.when = randomNode(rng, catalog, 1);
      if (rng.bool(0.4))
        rule.unless = Array.from({ length: rng.int(3) }, () => randomNode(rng, catalog, 1));
      rule.actions = Array.from({ length: rng.int(4) }, () => randomAction(rng, catalog));
      if (rng.bool(0.3)) rule.stop = rng.bool();
      if (rng.bool(0.3)) rule.override = rng.bool();
      return rule;
    }),
  };
  if (rng.bool(0.3))
    doc.exceptions = Array.from({ length: rng.int(3) }, () => randomNode(rng, catalog, 1));
  return doc;
}
