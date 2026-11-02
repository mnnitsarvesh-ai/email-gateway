import { randomBytes } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import {
  configureHttpApp,
  PrismaReadService,
  PrismaService,
  RedisService,
  S3Service,
} from '@email-gateway/common';
import { createLogger } from '@email-gateway/logger';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { loadApiConfig } from '../src/config';
import { EmailSender } from '../src/email/email-sender';
import { configureApiApp } from '../src/http/configure-api-app';
import { ACCESS_TOKEN_SCHEME, API_KEY_SCHEME, buildOpenApiDocument } from '../src/http/openapi';
import { KeyValueStore } from '../src/kv/key-value-store';
import { InMemoryKeyValueStore } from './support/in-memory-key-value-store';
import { RecordingEmailSender } from './support/recording-email-sender';
import { TEST_DOMAIN_ENV } from './support/test-env';

const config = loadApiConfig({
  ...TEST_DOMAIN_ENV,
  NODE_ENV: 'test',
  HTTP_PORT: '3000',
  DATABASE_URL: 'mysql://test:test@localhost:3306/test',
  REDIS_URL: 'redis://localhost:6379',
  S3_REGION: 'us-east-1',
  S3_BUCKET_MAIL: 'test-mail',
  S3_BUCKET_ARCHIVE: 'test-archive',
  // Random per run: tests never use real secrets.
  AUTH_JWT_SECRET: randomBytes(32).toString('hex'),
  AUTH_TOKEN_PEPPER: randomBytes(32).toString('hex'),
  DATA_ENCRYPTION_KEY: randomBytes(32).toString('hex'),
  AUTH_BACKGROUND_JOBS_ENABLED: 'false',
  HTTP_TRUST_PROXY: '1',
});

const healthy = (healthName: string) => ({ healthName, checkHealth: () => Promise.resolve() });
let dbHealthy = true;
const readerDetails = {
  mode: 'writer-fallback',
  lagSeconds: 42,
  maxLagSeconds: 10,
  reason: 'lag 42s > max 10s',
};

describe('API (e2e, dependencies stubbed)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule.forRoot(config)] })
      .overrideProvider(PrismaService)
      .useValue({
        healthName: 'mysql',
        checkHealth: () => (dbHealthy ? Promise.resolve() : Promise.reject(new Error('down'))),
      })
      .overrideProvider(PrismaReadService)
      .useValue({ healthName: 'mysql-reader', checkHealth: () => Promise.resolve(readerDetails) })
      .overrideProvider(RedisService)
      .useValue(healthy('redis'))
      .overrideProvider(S3Service)
      .useValue(healthy('s3'))
      .overrideProvider(KeyValueStore)
      .useValue(new InMemoryKeyValueStore())
      .overrideProvider(EmailSender)
      .useValue(new RecordingEmailSender())
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    configureHttpApp(app, createLogger({ service: 'api-test', level: 'silent' }));
    configureApiApp(app, config);
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health/live is unversioned and always ok', async () => {
    const res = await request(app.getHttpServer()).get('/health/live').expect(200);
    expect(res.body).toMatchObject({ service: 'api', status: 'ok' });
  });

  it('GET /health/ready reports each dependency', async () => {
    dbHealthy = true;
    const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
    expect(res.body.checks.map((c: { name: string }) => c.name)).toEqual([
      'mysql',
      'mysql-reader',
      'redis',
      's3',
    ]);
  });

  it('GET /health/ready reports read replica details without failing on a lagging replica', async () => {
    dbHealthy = true;
    const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
    expect(res.body.status).toBe('ok');
    const reader = res.body.checks.find((c: { name: string }) => c.name === 'mysql-reader');
    expect(reader).toMatchObject({ status: 'ok', details: readerDetails });
    expect(res.body.checks.find((c: { name: string }) => c.name === 'mysql')).not.toHaveProperty(
      'details',
    );
  });

  it('GET /health/ready returns 503 when a dependency is down', async () => {
    dbHealthy = false;
    const res = await request(app.getHttpServer()).get('/health/ready').expect(503);
    expect(res.body.status).toBe('error');
    dbHealthy = true;
  });

  it('serves business routes under /api/v1 (ADR-0015)', async () => {
    const res = await request(app.getHttpServer()).get('/api/v1/meta').expect(200);
    expect(res.body).toMatchObject({ apiVersion: 'v1' });
    await request(app.getHttpServer()).get('/v1/meta').expect(404);
    await request(app.getHttpServer()).get('/meta').expect(404);
    await request(app.getHttpServer()).get('/api/meta').expect(404);
  });

  it('keeps the probes unprefixed', async () => {
    await request(app.getHttpServer()).get('/api/health/live').expect(404);
    await request(app.getHttpServer()).get('/api/health/ready').expect(404);
    await request(app.getHttpServer()).get('/api/v1/health/live').expect(404);
  });

  it('applies the configured trust proxy hop count', () => {
    const express = app.getHttpAdapter().getInstance() as { get: (key: string) => unknown };
    expect(express.get('trust proxy')).toBe(1);
  });

  it('builds the OpenAPI document with both security schemes and /api/v1 paths', () => {
    const doc = buildOpenApiDocument(app);
    expect(doc.components?.securitySchemes?.[ACCESS_TOKEN_SCHEME]).toMatchObject({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
    });
    expect(doc.components?.securitySchemes?.[API_KEY_SCHEME]).toMatchObject({
      type: 'apiKey',
      in: 'header',
      name: 'X-API-Key',
    });
    expect(Object.keys(doc.paths)).toContain('/api/v1/meta');
    expect(Object.keys(doc.paths)).not.toContain('/v1/meta');
  });

  it('echoes a valid correlation id and mints one otherwise', async () => {
    const echoed = await request(app.getHttpServer())
      .get('/health/live')
      .set('x-correlation-id', 'client-req-0001');
    expect(echoed.headers['x-correlation-id']).toBe('client-req-0001');

    const minted = await request(app.getHttpServer())
      .get('/health/live')
      .set('x-correlation-id', 'bad id with spaces');
    expect(minted.headers['x-correlation-id']).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('returns structured errors with the correlation id', async () => {
    const res = await request(app.getHttpServer())
      .get('/api/v1/x')
      .set('x-correlation-id', 'client-req-0002')
      .expect(404);
    expect(res.body).toMatchObject({ statusCode: 404, correlationId: 'client-req-0002' });
  });
});
