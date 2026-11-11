import { stack } from './env';

/**
 * Prometheus text exposition of a service's `GET /metrics` (step 2.2 D16, step 2.3 R14, step 3.2
 * §5.3) as seen from the host: smtp-adapter, delivery-worker, email-worker, event-relay, api and
 * (step 5.2) policy-engine and notification-worker (their `*_HOST_PORT`). Sums every series of `name` whose labels include `labels`.
 */
export async function metricValue(
  service:
    | 'smtp-adapter'
    | 'delivery-worker'
    | 'email-worker'
    | 'event-relay'
    | 'api'
    | 'policy-engine'
    | 'notification-worker',
  name: string,
  labels: Record<string, string> = {},
): Promise<number> {
  const res = await fetch(`http://${stack.host}:${stack.ports.services[service]}/metrics`, {
    signal: AbortSignal.timeout(5_000),
  });
  if (!res.ok) throw new Error(`${service} /metrics answered ${res.status}`);
  const text = await res.text();
  let total = 0;
  for (const line of text.split('\n')) {
    if (!line.startsWith(`${name}{`) && !line.startsWith(`${name} `)) continue;
    const match = /^[^{ ]+(?:\{([^}]*)\})? ([0-9.eE+-]+)$/.exec(line);
    if (!match) continue;
    const present = new Map(
      [...(match[1] ?? '').matchAll(/(\w+)="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]),
    );
    if (Object.entries(labels).every(([k, v]) => present.get(k) === v)) total += Number(match[2]);
  }
  return total;
}
