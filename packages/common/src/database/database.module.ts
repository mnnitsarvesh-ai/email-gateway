import { type DynamicModule, Global, Module, type Provider } from '@nestjs/common';
import {
  DATABASE_OPTIONS,
  DATABASE_READ_OPTIONS,
  type DatabaseModuleOptions,
} from './database.options';
import { PrismaReadService } from './prisma-read.service';
import { PrismaService } from './prisma.service';

export type { DatabaseModuleOptions, DatabaseReadOptions } from './database.options';
export { PrismaService } from './prisma.service';

@Global()
@Module({})
export class DatabaseModule {
  /**
   * Registers the writer (PrismaService). With `read`, also registers PrismaReadService for
   * control-plane reads. Without it, injecting PrismaReadService is a DI error, which is how
   * data-plane services stay on the writer (ADR-0014).
   */
  static forRoot(options: DatabaseModuleOptions): DynamicModule {
    const providers: Provider[] = [{ provide: DATABASE_OPTIONS, useValue: options }, PrismaService];
    const exports: Provider[] = [PrismaService];
    if (options.read) {
      providers.push({ provide: DATABASE_READ_OPTIONS, useValue: options.read }, PrismaReadService);
      exports.push(PrismaReadService);
    }
    return { module: DatabaseModule, providers, exports };
  }
}
