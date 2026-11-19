import { Injectable } from '@nestjs/common';
import { type Counter, MetricsService } from '@email-gateway/common';

/**
 * The api's incident series (step 8.4 D19): `incident_operations_total{category,operation,result}`
 * (operations `create`, `update`, `note`, `report`). Bounded labels; never a tenant or an id.
 */
@Injectable()
export class IncidentMetrics {
  readonly operations: Counter<'category' | 'operation' | 'result'>;

  constructor(metrics: MetricsService) {
    this.operations = metrics.counter(
      'incident_operations_total',
      'Security incident operations of the api by category, operation (create, update, note, report) and result',
      ['category', 'operation', 'result'],
    );
  }
}
