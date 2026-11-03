import { Inject, Injectable } from '@nestjs/common';
import { collectDefaultMetrics, Counter, Gauge, Histogram, Registry } from 'prom-client';

/** Metric types handed out by MetricsService, so services need no direct prom-client import. */
export type { Counter, Gauge, Histogram } from 'prom-client';

export const METRICS_OPTIONS = Symbol('METRICS_OPTIONS');

export interface MetricsModuleOptions {
  /** Value of the `service` default label on every series (e.g. `smtp-adapter`). */
  service: string;
}

type MetricKind = 'counter' | 'gauge' | 'histogram';

interface Registered {
  kind: MetricKind;
  labelNames: readonly string[];
  metric: Counter<string> | Gauge<string> | Histogram<string>;
}

/** Prometheus metric names and label names (https://prometheus.io/docs/concepts/data_model/). */
const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Prometheus metrics of one service (step 2.2 D16, ADR-0019 amending ADR-0011).
 *
 * Each instance owns a dedicated registry (never prom-client's global one), with the default
 * process metrics and a `service` default label. Metrics are declared through idempotent
 * get-or-create helpers, so two modules that ask for the same name share one instance;
 * asking for an existing name with another type or other label names is a programming error
 * and throws.
 */
@Injectable()
export class MetricsService {
  readonly registry: Registry;
  private readonly metricsByName = new Map<string, Registered>();

  constructor(@Inject(METRICS_OPTIONS) options: MetricsModuleOptions) {
    if (!options.service.trim()) throw new Error('MetricsModule needs a service name');
    this.registry = new Registry();
    this.registry.setDefaultLabels({ service: options.service });
    collectDefaultMetrics({ register: this.registry });
  }

  /** Content type of the exposition format served by `metrics()`. */
  get contentType(): string {
    return this.registry.contentType;
  }

  /** Every series in the Prometheus text exposition format. */
  metrics(): Promise<string> {
    return this.registry.metrics();
  }

  counter<L extends string>(name: string, help: string, labelNames: readonly L[] = []): Counter<L> {
    return this.getOrCreate(
      'counter',
      name,
      labelNames,
      () => new Counter<L>({ name, help, labelNames, registers: [this.registry] }),
    ) as Counter<L>;
  }

  gauge<L extends string>(name: string, help: string, labelNames: readonly L[] = []): Gauge<L> {
    return this.getOrCreate(
      'gauge',
      name,
      labelNames,
      () => new Gauge<L>({ name, help, labelNames, registers: [this.registry] }),
    ) as Gauge<L>;
  }

  /** `buckets` in seconds (or the metric's unit); prom-client's defaults when omitted. */
  histogram<L extends string>(
    name: string,
    help: string,
    labelNames: readonly L[] = [],
    buckets?: readonly number[],
  ): Histogram<L> {
    return this.getOrCreate('histogram', name, labelNames, () => {
      if (buckets !== undefined) {
        return new Histogram<L>({
          name,
          help,
          labelNames,
          buckets: [...buckets],
          registers: [this.registry],
        });
      }
      return new Histogram<L>({ name, help, labelNames, registers: [this.registry] });
    }) as Histogram<L>;
  }

  private getOrCreate(
    kind: MetricKind,
    name: string,
    labelNames: readonly string[],
    create: () => Registered['metric'],
  ): Registered['metric'] {
    const existing = this.metricsByName.get(name);
    if (existing) {
      if (existing.kind !== kind) {
        throw new Error(`Metric ${name} is already registered as a ${existing.kind}`);
      }
      if (!sameLabels(existing.labelNames, labelNames)) {
        throw new Error(
          `Metric ${name} is already registered with labels [${existing.labelNames.join(', ')}]`,
        );
      }
      return existing.metric;
    }
    if (!METRIC_NAME.test(name)) throw new Error(`Invalid metric name: ${name}`);
    for (const label of labelNames) {
      if (!LABEL_NAME.test(label) || label.startsWith('__') || label === 'service') {
        throw new Error(`Invalid label name for ${name}: ${label}`);
      }
    }
    const metric = create();
    this.metricsByName.set(name, { kind, labelNames: [...labelNames], metric });
    return metric;
  }
}

function sameLabels(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedB = [...b].sort();
  return [...a].sort().every((label, i) => label === sortedB[i]);
}
