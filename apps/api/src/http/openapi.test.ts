import type { OpenAPIObject } from '@nestjs/swagger';
import { describe, expect, it } from 'vitest';
import { postProcessOpenApiDocument } from './openapi';

function doc(): OpenAPIObject {
  return {
    openapi: '3.0.0',
    info: { title: 't', version: 'v1' },
    paths: {
      '/metrics': { get: { responses: { '200': { description: 'ok' } } } },
      '/health/live': { get: { responses: { '200': { description: 'ok' } } } },
      '/health/ready': { get: { responses: { '200': { description: 'ok' } } } },
      '/api/v1/meta': { get: { responses: { '200': { description: 'ok' } } } },
      '/api/v1/things/{id}': {
        post: {
          security: [{ 'access-token': [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            '201': { description: 'created', headers: { 'x-request-id': { description: 'own' } } },
            '404': { description: 'mine', content: {} },
          },
          'x-eg-idempotency': 'required',
        } as never,
      },
    },
  };
}

interface Resp {
  description?: string;
  content: Record<string, { schema?: unknown }>;
  headers: Record<string, unknown>;
}

describe('postProcessOpenApiDocument (step 6.1 D13, D14)', () => {
  const out = postProcessOpenApiDocument(doc());
  const op = (
    out.paths['/api/v1/things/{id}'] as Record<string, { responses: Record<string, Resp> }>
  ).post!;
  const meta = (out.paths['/api/v1/meta'] as Record<string, { responses: Record<string, Resp> }>)
    .get!;

  it('removes the internal endpoints', () => {
    expect(Object.keys(out.paths)).toEqual(['/api/v1/meta', '/api/v1/things/{id}']);
  });

  it('adds the shared schemas and headers', () => {
    expect(Object.keys(out.components!.schemas!)).toEqual(
      expect.arrayContaining(['ErrorBody', 'ValidationErrorBody', 'RateLimitedErrorBody']),
    );
    expect(Object.keys(out.components!.headers!).sort()).toEqual(
      [
        'Idempotency-Replayed',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'Retry-After',
        'X-Correlation-Id',
        'X-Request-Id',
      ].sort(),
    );
  });

  it('adds the missing standard responses and keeps the documented ones', () => {
    expect(Object.keys(op.responses).sort()).toEqual(
      ['201', '400', '401', '403', '404', '429', '500', '503'].sort(),
    );
    expect(op.responses['404']!.description).toBe('mine');
    expect(op.responses['400']!.content['application/json']!.schema).toEqual({
      $ref: '#/components/schemas/ValidationErrorBody',
    });
    expect(op.responses['401']!.content['application/json']!.schema).toEqual({
      $ref: '#/components/schemas/ErrorBody',
    });
    expect(op.responses['429']!.content['application/json']!.schema).toEqual({
      $ref: '#/components/schemas/RateLimitedErrorBody',
    });
    // A public operation without parameters gets neither 400, 401/403 nor 404.
    expect(Object.keys(meta.responses).sort()).toEqual(['200', '429', '500', '503']);
  });

  it('adds the response headers without overwriting documented ones', () => {
    expect(Object.keys(op.responses['201']!.headers).sort()).toEqual(
      [
        'Idempotency-Replayed',
        'RateLimit-Limit',
        'RateLimit-Remaining',
        'RateLimit-Reset',
        'X-Correlation-Id',
        'x-request-id',
      ].sort(),
    );
    expect(op.responses['201']!.headers['x-request-id']).toEqual({ description: 'own' });
    expect(op.responses['429']!.headers).toHaveProperty('Retry-After');
    expect(op.responses['400']!.headers).not.toHaveProperty('Idempotency-Replayed');
    expect(Object.keys(meta.responses['200']!.headers).sort()).toEqual([
      'X-Correlation-Id',
      'X-Request-Id',
    ]);
  });
});
