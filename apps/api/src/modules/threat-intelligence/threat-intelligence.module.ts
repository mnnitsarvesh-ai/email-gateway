import { Module } from '@nestjs/common';
import { ThreatIntelligenceController } from './threat-intelligence.controller';
import { ThreatIntelligenceRepository } from './threat-intelligence.repository';
import { ThreatIntelligenceService } from './threat-intelligence.service';

/**
 * Step 6.1 (docs/plan/steps/18-rest-api.md §3.3): the tenant lookup over platform threat
 * intelligence (`GET /threat-intelligence/lookup`).
 */
@Module({
  controllers: [ThreatIntelligenceController],
  providers: [ThreatIntelligenceRepository, ThreatIntelligenceService],
})
export class ThreatIntelligenceModule {}
