import { Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import type { HealthIndicator } from './health-indicator';
import { HealthModule } from './health.module';
import { HealthService } from './health.service';

@Injectable()
class FeatureBrokerHealth implements HealthIndicator {
  readonly healthName = 'rabbitmq-feature';
  checkHealth(): Promise<void> {
    return Promise.resolve();
  }
}

/** A non-global feature module exporting its own indicator (e.g. the email-worker's scan role). */
@Module({ providers: [FeatureBrokerHealth], exports: [FeatureBrokerHealth] })
class FeatureModule {}

describe('HealthModule', () => {
  it('resolves indicators exported by a non-global module through `imports`', async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        FeatureModule,
        HealthModule.forRoot({
          service: { name: 'svc', version: '1.0.0' },
          indicators: [FeatureBrokerHealth],
          imports: [FeatureModule],
        }),
      ],
    }).compile();
    const report = await moduleRef.get(HealthService).readiness();
    expect(report.checks.map((c) => c.name)).toEqual(['rabbitmq-feature']);
    expect(report.status).toBe('ok');
    await moduleRef.close();
  });

  it('cannot see a non-global module indicator without `imports`', async () => {
    await expect(
      Test.createTestingModule({
        imports: [
          FeatureModule,
          HealthModule.forRoot({
            service: { name: 'svc', version: '1.0.0' },
            indicators: [FeatureBrokerHealth],
          }),
        ],
      }).compile(),
    ).rejects.toThrow();
  });
});
