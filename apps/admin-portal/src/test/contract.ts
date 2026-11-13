import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv, { type ValidateFunction } from 'ajv';
import addFormats from 'ajv-formats';
import { expect } from 'vitest';
import { operations } from '@/lib/api/operations.gen';
import type { OperationId } from '@/lib/api/types';

type Json = Record<string, unknown>;

let spec: Json | null = null;
function openapi(): Json {
  spec ??= JSON.parse(
    readFileSync(join(__dirname, '../../../../docs/api/openapi.json'), 'utf8'),
  ) as Json;
  return spec;
}

function resolveRef(ref: string): unknown {
  const parts = ref.replace(/^#\//, '').split('/');
  let node: unknown = openapi();
  for (const part of parts) node = (node as Json)[part];
  return node;
}

/**
 * OpenAPI 3.0 schema → JSON Schema for Ajv: `$ref`s inlined, `nullable` turned into a null type,
 * and every object closed (`additionalProperties: false` unless declared) so unknown keys fail.
 */
export function toJsonSchema(schema: unknown, depth = 0): unknown {
  if (depth > 40 || schema === null || typeof schema !== 'object') return schema;
  if (Array.isArray(schema)) return schema.map((s) => toJsonSchema(s, depth + 1));
  const node = schema as Json;
  if (typeof node.$ref === 'string') return toJsonSchema(resolveRef(node.$ref), depth + 1);
  const out: Json = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === 'nullable' || key === 'example' || key === 'examples' || key.startsWith('x-'))
      continue;
    out[key] = toJsonSchema(value, depth + 1);
  }
  if (node.nullable === true) {
    if (typeof out.type === 'string') out.type = [out.type, 'null'];
    if (Array.isArray(out.enum)) out.enum = [...(out.enum as unknown[]), null];
  }
  if (
    out.type === 'object' &&
    out.properties &&
    out.additionalProperties === undefined &&
    !out.allOf
  ) {
    out.additionalProperties = false;
  }
  return out;
}

const ajv = new Ajv({ allErrors: true, strict: false });
addFormats(ajv);
const cache = new Map<OperationId, ValidateFunction>();

export function requestSchemaOf(operationId: OperationId): unknown {
  const op = operations[operationId];
  const pathItem = (openapi().paths as Json)[op.path] as Json;
  const operation = pathItem[op.method.toLowerCase()] as Json;
  const requestBody = operation.requestBody as Json | undefined;
  const schema = (
    (requestBody?.content as Json | undefined)?.['application/json'] as Json | undefined
  )?.schema;
  if (!schema) throw new Error(`${operationId} has no JSON request body`);
  return toJsonSchema(schema);
}

/** Validates a form's output against the operation's request schema (design P8). */
export function validateRequestBody(operationId: OperationId, body: unknown): string[] {
  let validate = cache.get(operationId);
  if (!validate) {
    validate = ajv.compile(requestSchemaOf(operationId) as object);
    cache.set(operationId, validate);
  }
  if (validate(body)) return [];
  return (validate.errors ?? []).map(
    (e) =>
      `${e.instancePath || '(root)'} ${e.message ?? ''}${e.params && 'additionalProperty' in e.params ? `: ${String(e.params.additionalProperty)}` : ''}`,
  );
}

export function expectRequestMatchesContract(operationId: OperationId, body: unknown): void {
  const errors = validateRequestBody(operationId, body);
  expect(errors, `request body of ${operationId} violates the OpenAPI contract`).toEqual([]);
}
