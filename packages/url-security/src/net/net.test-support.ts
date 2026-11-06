import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type http from 'node:http';
import type https from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RestrictedResolver, type DnsBackend } from './resolver';
import { SsrfGuard } from './ssrf-guard';
import type { DialTarget } from './fetcher';

/**
 * Test support for the fetcher and proxy tests: in-process HTTP/HTTPS servers on 127.0.0.1, a
 * fake DNS backend (names → documentation addresses) and the TEST-ONLY dial map that sends the
 * validated documentation address to the local port. Certificates are generated at test time
 * with the openssl CLI (never committed).
 */

export interface TestServer {
  port: number;
  close(): Promise<void>;
}

export async function listen(server: http.Server | https.Server): Promise<TestServer> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    port,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}

export interface TestPki {
  ca: string;
  key: string;
  cert: string;
  otherCa: string;
}

/** A test CA, a leaf for the given DNS names, and an unrelated CA (for the untrusted case). */
export function generatePki(names: readonly string[]): TestPki {
  const dir = mkdtempSync(join(tmpdir(), 'url-security-pki-'));
  const run = (args: string[]): void => {
    execFileSync('openssl', args, { stdio: 'ignore' });
  };
  try {
    for (const ca of ['ca', 'other']) {
      run([
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-sha256',
        '-days',
        '2',
        '-subj',
        `/CN=url-security test ${ca}`,
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
        '-keyout',
        join(dir, `${ca}.key`),
        '-out',
        join(dir, `${ca}.pem`),
      ]);
    }
    run([
      'req',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-sha256',
      '-subj',
      `/CN=${names[0] ?? 'test'}`,
      '-keyout',
      join(dir, 'leaf.key'),
      '-out',
      join(dir, 'leaf.csr'),
    ]);
    writeFileSync(
      join(dir, 'ext.cnf'),
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${names.map((n) => `DNS:${n}`).join(',')}\n`,
    );
    run([
      'x509',
      '-req',
      '-in',
      join(dir, 'leaf.csr'),
      '-CA',
      join(dir, 'ca.pem'),
      '-CAkey',
      join(dir, 'ca.key'),
      '-CAcreateserial',
      '-days',
      '2',
      '-sha256',
      '-extfile',
      join(dir, 'ext.cnf'),
      '-out',
      join(dir, 'leaf.pem'),
    ]);
    return {
      ca: readFileSync(join(dir, 'ca.pem'), 'utf8'),
      key: readFileSync(join(dir, 'leaf.key'), 'utf8'),
      cert: readFileSync(join(dir, 'leaf.pem'), 'utf8'),
      otherCa: readFileSync(join(dir, 'other.pem'), 'utf8'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Fake DNS: name → { v4, v6 }; unknown names are NXDOMAIN. Counts queries. */
export function fakeDns(records: Record<string, { v4?: string[]; v6?: string[] }>): {
  resolver: RestrictedResolver;
  queries: string[];
} {
  const queries: string[] = [];
  const factory = (): DnsBackend => {
    const make =
      (family: 'v4' | 'v6') =>
      (name: string): Promise<string[]> => {
        queries.push(`${family}:${name}`);
        const record = records[name];
        if (!record) return Promise.reject(Object.assign(new Error('nx'), { code: 'ENOTFOUND' }));
        const value = record[family];
        if (!value) return Promise.reject(Object.assign(new Error('nodata'), { code: 'ENODATA' }));
        return Promise.resolve(value);
      };
    return { resolve4: make('v4'), resolve6: make('v6'), cancel: () => undefined };
  };
  return { resolver: new RestrictedResolver({}, factory), queries };
}

/** The guard of the tests: production defaults + the documentation test allowance. */
export const testGuard = (extra: ConstructorParameters<typeof SsrfGuard>[0] = {}): SsrfGuard =>
  new SsrfGuard({ testAllowCidrs: ['203.0.113.0/24'], nodeEnv: 'test', ...extra });

export function dialMap(entries: Record<string, number>): Map<string, DialTarget> {
  return new Map(
    Object.entries(entries).map(([from, port]) => [from, { host: '127.0.0.1', port }]),
  );
}
