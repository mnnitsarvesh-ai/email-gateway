import { Injectable } from '@nestjs/common';
import { PrismaService } from '@email-gateway/common';
import type { Prisma } from '@email-gateway/database';

export interface TransactionOptions {
  isolationLevel?: Prisma.TransactionIsolationLevel;
  /** Longest the transaction may run (default 15 s; Argon2 hashing may happen inside). */
  timeoutMs?: number;
  /** Longest to wait for a connection (default 5 s). */
  maxWaitMs?: number;
}

/**
 * Interactive writer transactions for services (D2): services own the unit of work and pass the
 * `Prisma.TransactionClient` to repository methods; only repositories issue queries.
 */
@Injectable()
export class TransactionRunner {
  constructor(private readonly prisma: PrismaService) {}

  run<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
    options: TransactionOptions = {},
  ): Promise<T> {
    return this.prisma.$transaction(fn, {
      timeout: options.timeoutMs ?? 15_000,
      maxWait: options.maxWaitMs ?? 5_000,
      ...(options.isolationLevel && { isolationLevel: options.isolationLevel }),
    });
  }
}
