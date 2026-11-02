import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { DatabaseModule, PrismaService } from './database.module';
import { PrismaReadService } from './prisma-read.service';

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
});
