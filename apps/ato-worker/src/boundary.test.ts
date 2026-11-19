import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

function files(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...files(path));
    else if (name.endsWith('.ts') && !name.endsWith('.test.ts')) out.push(path);
  }
  return out;
}

const runtime = files(__dirname).map((f) => ({
  path: relative(__dirname, f),
  text: readFileSync(f, 'utf8'),
}));

describe('ato-worker boundaries', () => {
  it('only enrichment/reputation.ts calls ReputationService (D7 Reputation contract, PO5)', () => {
    const lookups =
      /\b(ReputationService|createReputationProviders|LocalFeedProvider|DnsblProvider)\b/;
    const users = runtime
      .filter((f) =>
        [...f.text.matchAll(/import\s*\{([^}]*)\}\s*from\s*'@email-gateway\/url-security'/g)].some(
          (m) => lookups.test(m[1] ?? ''),
        ),
      )
      .map((f) => f.path)
      .sort();
    expect(users).toEqual(['enrichment/reputation.ts']);
  });

  it('never reads threat_indicators of type ip directly (only through ReputationService)', () => {
    const direct = runtime.filter(
      (f) => /indicatorType:\s*'ip'/.test(f.text) || /indicator_type\s*=\s*'ip'/.test(f.text),
    );
    expect(direct.map((f) => f.path)).toEqual([]);
  });

  it('never imports the test kits at runtime', () => {
    const offenders = runtime.filter((f) =>
      /from '@email-gateway\/(ato-detection|security-incidents)\/testing'|from 'vitest'/.test(
        f.text,
      ),
    );
    expect(offenders.map((f) => f.path)).toEqual([]);
  });

  it('has no object-storage client (no S3 access, D20)', () => {
    const s3 = runtime.filter((f) => /@aws-sdk|S3Module|S3Service/.test(f.text));
    expect(s3.map((f) => f.path)).toEqual([]);
  });

  it('reads only the writer (no replica client in the data plane, ADR-0014)', () => {
    const replica = runtime.filter((f) => /PrismaReadService|DATABASE_READ_URL/.test(f.text));
    expect(replica.map((f) => f.path)).toEqual([]);
  });
});
