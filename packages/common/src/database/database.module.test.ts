import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { DatabaseModule, PrismaService } from './database.module';
import { DATABASE_READ_OPTIONS } from './database.options';
import { PrismaReadService } from './prisma-read.service';
import { socketTimeoutOf } from './prisma.service';

const url = 'mysql://test:test@localhost:3306/test';

/** Compiles the module without init, so no connection is attempted. */
describe('DatabaseModule', () => {
  it('registers only the writer without read options', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [DatabaseModule.forRoot({ url })],
    }).compile();
    expect(moduleRef.get(PrismaService, { strict: false }).healthName).toBe('mysql');
    expect(() => moduleRef.get(PrismaReadService, { strict: false })).toThrow();
  });

  it('also registers and exports the reader with read options', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        DatabaseModule.forRoot({
          url,
          read: { maxLagSeconds: 10, lagCheckIntervalMs: 5_000 },
        }),
      ],
    }).compile();
    const reader = moduleRef.get(PrismaReadService, { strict: false });
    expect(reader).toBeInstanceOf(PrismaReadService);
    expect(reader.client).toBe(moduleRef.get(PrismaService, { strict: false }));
    expect(reader.status().mode).toBe('writer-only');
  });

  it('gives the reader the writer socket timeout unless it sets its own', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        DatabaseModule.forRoot({
          url,
          socketTimeoutSeconds: 9,
          read: { maxLagSeconds: 10, lagCheckIntervalMs: 5_000 },
        }),
      ],
    }).compile();
    expect(moduleRef.get(DATABASE_READ_OPTIONS, { strict: false })).toMatchObject({
      socketTimeoutSeconds: 9,
    });
  });
});

describe('socketTimeoutOf', () => {
  it('prefers the option, else DATABASE_SOCKET_TIMEOUT_SECONDS, else 0', () => {
    const saved = process.env.DATABASE_SOCKET_TIMEOUT_SECONDS;
    try {
      delete process.env.DATABASE_SOCKET_TIMEOUT_SECONDS;
      expect(socketTimeoutOf({})).toBe(0);
      process.env.DATABASE_SOCKET_TIMEOUT_SECONDS = '11';
      expect(socketTimeoutOf({})).toBe(11);
      expect(socketTimeoutOf({ socketTimeoutSeconds: 3 })).toBe(3);
    } finally {
      if (saved === undefined) delete process.env.DATABASE_SOCKET_TIMEOUT_SECONDS;
      else process.env.DATABASE_SOCKET_TIMEOUT_SECONDS = saved;
    }
  });
});
