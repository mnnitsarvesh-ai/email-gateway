import type { databaseClientUrl } from '@email-gateway/database';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PrismaService, writerUrlOptions } from './prisma.service';

type ClientUrl = typeof databaseClientUrl;
const { calls } = vi.hoisted(() => ({ calls: [] as Array<{ url: string; options: unknown }> }));

vi.mock('@email-gateway/database', async (importOriginal) => {
  const actual = await importOriginal<{ databaseClientUrl: ClientUrl }>();
  return {
    ...actual,
    databaseClientUrl: (url: string, options: Parameters<ClientUrl>[1]) => {
      calls.push({ url, options });
      return actual.databaseClientUrl(url, options);
    },
  };
});

const url = 'mysql://test:test@localhost:3306/test';

describe('PrismaService pool options (step AI-4 D14)', () => {
  afterEach(() => {
    calls.length = 0;
  });

  it('passes connectionLimit and poolTimeoutSeconds to databaseClientUrl', () => {
    const service = new PrismaService({ url, connectionLimit: 32, poolTimeoutSeconds: 30 });
    expect(service.healthName).toBe('mysql');
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(url);
    expect(calls[0]!.options).toMatchObject({ connectionLimit: 32, poolTimeoutSeconds: 30 });
  });

  it('passes no pool options when the module options carry none (other services unchanged)', () => {
    new PrismaService({ url, socketTimeoutSeconds: 0 });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.options).toEqual({ socketTimeoutSeconds: 0 });
  });

  it('refuses out-of-range pool options at construction', () => {
    expect(() => new PrismaService({ url, connectionLimit: 0 })).toThrow(RangeError);
    expect(() => new PrismaService({ url, poolTimeoutSeconds: 601 })).toThrow(RangeError);
  });
});

describe('writerUrlOptions', () => {
  it('keeps absent keys absent and copies given ones', () => {
    expect(writerUrlOptions({ url, socketTimeoutSeconds: 4 })).toEqual({
      socketTimeoutSeconds: 4,
    });
    expect(
      writerUrlOptions({
        url,
        socketTimeoutSeconds: 0,
        connectionLimit: 8,
        poolTimeoutSeconds: 12,
      }),
    ).toEqual({ socketTimeoutSeconds: 0, connectionLimit: 8, poolTimeoutSeconds: 12 });
  });
});
