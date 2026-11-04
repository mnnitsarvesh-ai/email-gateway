import type { Topology } from './topology';

/**
 * RabbitMQ management definitions (`POST /api/definitions/{vhost}`) generated from the topology
 * (step 3.2 Q5). The output is committed as `infrastructure/rabbitmq/definitions.json` and
 * imported by `infrastructure/rabbitmq/init.mjs`, which strips `topology_version` and sets
 * `vhost` on every object to the target vhost.
 */

export interface RabbitExchangeDefinition {
  name: string;
  vhost: string;
  type: 'topic';
  durable: true;
  auto_delete: false;
  internal: false;
  arguments: Record<string, never>;
}

export interface RabbitQueueDefinition {
  name: string;
  vhost: string;
  durable: true;
  auto_delete: false;
  arguments: { 'x-queue-type': 'quorum' };
}

export interface RabbitBindingDefinition {
  source: string;
  vhost: string;
  destination: string;
  destination_type: 'queue' | 'exchange';
  routing_key: string;
  arguments: Record<string, never>;
}

export interface RabbitPolicyDefinition {
  vhost: string;
  name: string;
  pattern: string;
  'apply-to': 'queues';
  priority: number;
  definition: Record<string, string | number>;
}

export interface RabbitDefinitions {
  topology_version: number;
  exchanges: RabbitExchangeDefinition[];
  queues: RabbitQueueDefinition[];
  bindings: RabbitBindingDefinition[];
  policies: RabbitPolicyDefinition[];
}

/** Priority of the generated `eg.<queue>` policies. */
export const POLICY_PRIORITY = 10;

/** Name of the policy that applies to `queue`. */
export function policyName(queue: string): string {
  return `eg.${queue}`;
}

/** Anchored regular expression matching exactly `name`. */
export function exactNamePattern(name: string): string {
  return `^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`;
}

function compareBindings(a: RabbitBindingDefinition, b: RabbitBindingDefinition): number {
  const keyA = [a.source, a.destination_type, a.destination, a.routing_key];
  const keyB = [b.source, b.destination_type, b.destination, b.routing_key];
  for (let i = 0; i < keyA.length; i += 1) {
    const x = keyA[i] ?? '';
    const y = keyB[i] ?? '';
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Deterministic definitions: exchanges and queues in topology order, bindings sorted by
 * (source, destination type, destination, routing key), one policy per queue in queue order.
 */
export function toRabbitDefinitions(
  topology: Topology,
  options: { vhost: string },
): RabbitDefinitions {
  const { vhost } = options;
  const bindings: RabbitBindingDefinition[] = [
    ...topology.exchangeBindings.map((b) => ({
      source: b.source,
      vhost,
      destination: b.destination,
      destination_type: 'exchange' as const,
      routing_key: b.routingKey,
      arguments: {},
    })),
    ...topology.queues.flatMap((queue) =>
      queue.bindings.map((b) => ({
        source: b.exchange,
        vhost,
        destination: queue.name,
        destination_type: 'queue' as const,
        routing_key: b.routingKey,
        arguments: {},
      })),
    ),
  ].sort(compareBindings);

  return {
    topology_version: topology.version,
    exchanges: topology.exchanges.map((name) => ({
      name,
      vhost,
      type: 'topic',
      durable: true,
      auto_delete: false,
      internal: false,
      arguments: {},
    })),
    queues: topology.queues.map((queue) => ({
      name: queue.name,
      vhost,
      durable: true,
      auto_delete: false,
      arguments: { 'x-queue-type': 'quorum' },
    })),
    bindings,
    policies: topology.queues.map((queue) => ({
      vhost,
      name: policyName(queue.name),
      pattern: exactNamePattern(queue.name),
      'apply-to': 'queues',
      priority: POLICY_PRIORITY,
      definition: { ...queue.policy },
    })),
  };
}
