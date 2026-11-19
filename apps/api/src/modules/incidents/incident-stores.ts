import { Inject, Injectable } from '@nestjs/common';
import { AtoStore } from '@email-gateway/ato-detection';
import { type IncidentCategoryRegistry, IncidentStore } from '@email-gateway/security-incidents';
import { API_CONFIG } from '../../api-config.token';
import type { AtoApiConfigKeys } from '../../config';
import {
  buildIncidentRegistry,
  type IncidentCategoryDefinition,
  incidentCategoryDefinitions,
} from './incident-categories';

/**
 * The transactional stores the api writes through (step 8.4 §4.4, D24): the category registry
 * (every registered handler, `account_takeover` first), the shared `IncidentStore` and the
 * `AtoStore` (with the response safeguards of the api configuration). Both stores take the
 * caller's writer transaction; the api never writes an incident or ATO table directly.
 */
@Injectable()
export class IncidentStores {
  readonly registry: IncidentCategoryRegistry;
  readonly incidents: IncidentStore;
  readonly ato: AtoStore;
  readonly definitions: readonly IncidentCategoryDefinition[];

  constructor(
    @Inject(API_CONFIG)
    config: Pick<
      AtoApiConfigKeys,
      | 'API_ATO_REPORT_MAX_ITEMS'
      | 'ATO_APPROVAL_TTL_HOURS'
      | 'ATO_AUTOMATED_RESPONSES_ENABLED'
      | 'ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR'
      | 'ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG'
    >,
  ) {
    this.definitions = incidentCategoryDefinitions();
    const holder: { ato?: AtoStore } = {};
    this.registry = buildIncidentRegistry({
      ato: () => {
        if (!holder.ato) throw new Error('AtoStore not initialized');
        return holder.ato;
      },
      reportMaxItems: config.API_ATO_REPORT_MAX_ITEMS,
    });
    this.incidents = new IncidentStore({ registry: this.registry, now: () => this.now() });
    holder.ato = new AtoStore({
      incidents: this.incidents,
      now: () => this.now(),
      config: {
        approvalTtlHours: config.ATO_APPROVAL_TTL_HOURS,
        automatedResponsesEnabled: config.ATO_AUTOMATED_RESPONSES_ENABLED,
        maxAutomatedPerOrgPerHour: config.ATO_MAX_AUTOMATED_RESPONSES_PER_ORG_PER_HOUR,
        maxActiveRestrictionsPerOrg: config.ATO_MAX_ACTIVE_RESTRICTIONS_PER_ORG,
      },
    });
    this.ato = holder.ato;
  }

  /** The clock of both stores (integration tests replace it). */
  now(): Date {
    return new Date();
  }

  definition(category: string): IncidentCategoryDefinition | undefined {
    return this.definitions.find((d) => d.category === category);
  }
}
