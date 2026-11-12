import { z } from 'zod';
import { describe, expect, it } from 'vitest';
import { defineListQuery } from '../http/listing/list-query';
import { isStrictRequestSchema } from './strict-schema';

describe('isStrictRequestSchema (step 6.1 D1)', () => {
  it('accepts strict objects at every depth', () => {
    const schema = z.strictObject({
      name: z.string(),
      nested: z.strictObject({ a: z.number() }).optional(),
      list: z.array(z.strictObject({ b: z.boolean() })).default([]),
      map: z.record(z.string(), z.strictObject({ c: z.string() })),
      either: z.union([z.strictObject({ k: z.literal('a') }), z.literal('none')]),
      both: z.intersection(z.strictObject({ x: z.string() }), z.strictObject({ y: z.string() })),
      tuple: z.tuple([z.strictObject({})]),
      wrapped: z.strictObject({}).nullable().readonly().catch({}),
      lazy: z.lazy(() => z.strictObject({ z: z.string() })),
    });
    expect(isStrictRequestSchema(schema)).toEqual([]);
    expect(isStrictRequestSchema(z.string())).toEqual([]);
    expect(isStrictRequestSchema(z.object({}).strict())).toEqual([]);
  });

  it('names every non-strict object node by path', () => {
    const schema = z.object({
      ok: z.strictObject({ inner: z.object({}) }),
      list: z.array(z.looseObject({ a: z.string() })),
      map: z.record(z.string(), z.object({})),
      either: z.discriminatedUnion('k', [
        z.strictObject({ k: z.literal('a') }),
        z.object({ k: z.literal('b'), deep: z.strictObject({ e: z.object({}) }) }),
      ]),
      both: z.intersection(z.strictObject({}), z.object({})),
      tuple: z.tuple([z.string()], z.object({})),
    });
    expect(isStrictRequestSchema(schema).sort()).toEqual(
      [
        '(root)',
        'ok.inner',
        'list[]',
        'map[*]',
        'either',
        'either.deep.e',
        'both',
        'tuple[]',
      ].sort(),
    );
  });

  it('inspects the input side of pipes and transforms, not the output', () => {
    const input = z.object({ a: z.string() }).transform((v) => ({ ...v, b: 1 }));
    expect(isStrictRequestSchema(input)).toEqual(['(root)']);
    const strictIn = z
      .strictObject({ raw: z.string() })
      .pipe(z.object({ raw: z.string() }))
      .optional();
    expect(isStrictRequestSchema(strictIn)).toEqual([]);
    const coerced = z.strictObject({ n: z.string().transform(Number).pipe(z.number()) });
    expect(isStrictRequestSchema(coerced)).toEqual([]);
  });

  it('accepts the list query schemas of defineListQuery', () => {
    const query = defineListQuery({
      filters: { direction: { type: 'enum', values: ['inbound', 'outbound'] } },
      sorts: ['-receivedAt'],
      defaultSort: '-receivedAt',
      range: true,
    });
    expect(isStrictRequestSchema(query)).toEqual([]);
  });

  it('survives recursive schemas', () => {
    interface Node {
      children: Node[];
    }
    const node: z.ZodType<Node> = z.lazy(() => z.strictObject({ children: z.array(node) }));
    expect(isStrictRequestSchema(node)).toEqual([]);
  });
});
