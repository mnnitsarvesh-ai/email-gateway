import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * Deployment check (step AI-4 D14, docs/deployment/account-takeover.md "Writer pool and transient
 * database errors"): the ATO worker Deployments at their HPA maximum must stay inside their share
 * of the MySQL writer's connection budget. Each process holds `ATO_DATABASE_CONNECTION_LIMIT`
 * pool connections plus one advisory-lock connection. The writer budget is 80 % of
 * `max_connections`, and the ATO workers may take at most 60 % of it, so the other services keep
 * the rest. A manifest or overlay that raises a pool size or a replica maximum past the budget
 * fails `pnpm test`.
 */
const ROOT = resolve(__dirname, '../../../..');
const KUBE = join(ROOT, 'infrastructure/kubernetes');
const BASE = join(KUBE, 'base');
const MYSQL_CNF = join(ROOT, 'infrastructure/mysql/conf.d/gateway.cnf');
const ATO_DEPLOYMENTS = ['ato-detect', 'ato-respond'] as const;
const WRITER_BUDGET_SHARE = 0.8;
const ATO_SHARE = 0.6;

function yamlFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return yamlFiles(path);
    return /\.ya?ml$/.test(name) ? [path] : [];
  });
}

const documents = (file: string): string[] => readFileSync(file, 'utf8').split(/^---\s*$/m);

/** The YAML document of `kind` named `name` in the base manifest `<name>.yaml`. */
function baseDocument(name: string, kind: string): string | null {
  return (
    documents(join(BASE, `${name}.yaml`)).find(
      (doc) =>
        new RegExp(`^kind:\\s*${kind}\\s*$`, 'm').test(doc) &&
        new RegExp(`^\\s*name:\\s*${name}\\s*$`, 'm').test(doc),
    ) ?? null
  );
}

function intField(doc: string, pattern: RegExp, what: string): number {
  const match = pattern.exec(doc);
  if (!match) throw new Error(`${what} not found`);
  return Number(match[1]);
}

interface Pool {
  name: string;
  maxReplicas: number;
  connectionLimit: number;
}

function poolOf(name: string): Pool {
  const deployment = baseDocument(name, 'Deployment');
  if (!deployment) throw new Error(`Deployment ${name} not found`);
  const connectionLimit = intField(
    deployment,
    /name:\s*ATO_DATABASE_CONNECTION_LIMIT,\s*value:\s*'(\d+)'/,
    `${name} ATO_DATABASE_CONNECTION_LIMIT`,
  );
  const hpa = baseDocument(name, 'HorizontalPodAutoscaler');
  const maxReplicas = hpa
    ? intField(hpa, /^\s*maxReplicas:\s*(\d+)\s*$/m, `${name} maxReplicas`)
    : intField(deployment, /^\s*replicas:\s*(\d+)\s*$/m, `${name} replicas`);
  return { name, maxReplicas, connectionLimit };
}

const maxConnections = (): number =>
  intField(
    readFileSync(MYSQL_CNF, 'utf8'),
    /^\s*max_connections\s*=\s*(\d+)\s*$/m,
    'max_connections',
  );

/** Connections of the ATO workers at HPA maximum (pool + 1 advisory-lock connection each). */
const atoConnections = (pools: readonly Pool[]): number =>
  pools.reduce((sum, p) => sum + p.maxReplicas * (p.connectionLimit + 1), 0);

describe('ATO worker connection budget (step AI-4 D14)', () => {
  const pools = ATO_DEPLOYMENTS.map(poolOf);
  const budget = Math.floor(maxConnections() * WRITER_BUDGET_SHARE * ATO_SHARE);

  it('the base manifests at HPA maximum stay within the ATO share of the writer budget', () => {
    expect(maxConnections()).toBe(300);
    expect(budget).toBe(144);
    expect(pools).toEqual([
      { name: 'ato-detect', maxReplicas: 8, connectionLimit: 12 },
      { name: 'ato-respond', maxReplicas: 1, connectionLimit: 32 },
    ]);
    expect(atoConnections(pools)).toBe(137);
    expect(atoConnections(pools)).toBeLessThanOrEqual(budget);
  });

  it('every pool keeps the worker config bounds (4–200)', () => {
    for (const pool of pools) {
      expect(pool.connectionLimit, pool.name).toBeGreaterThanOrEqual(4);
      expect(pool.connectionLimit, pool.name).toBeLessThanOrEqual(200);
    }
  });

  it('overlays and components never raise a pool size or a replica maximum past the base', () => {
    const outside = yamlFiles(KUBE).filter((file) => !file.startsWith(BASE));
    for (const file of outside) {
      const text = readFileSync(file, 'utf8');
      // A pool size set outside the base would bypass this budget check.
      expect(text, relative(ROOT, file)).not.toMatch(/ATO_DATABASE_CONNECTION_LIMIT/);
      for (const match of text.matchAll(/path:\s*\/spec\/maxReplicas\s*\n\s*value:\s*(\d+)/g)) {
        // Overlay HPA patches (every HPA) may only lower the maximum of a pool that has one.
        for (const pool of pools.filter((p) => baseDocument(p.name, 'HorizontalPodAutoscaler'))) {
          expect(Number(match[1]), `${relative(ROOT, file)} ${pool.name}`).toBeLessThanOrEqual(
            pool.maxReplicas,
          );
        }
      }
    }
  });

  it('the previous pool of 32 on ato-detect would have broken the budget (the review finding)', () => {
    const before = pools.map((p) => (p.name === 'ato-detect' ? { ...p, connectionLimit: 32 } : p));
    expect(atoConnections(before)).toBe(297);
    expect(atoConnections(before)).toBeGreaterThan(budget);
  });
});
