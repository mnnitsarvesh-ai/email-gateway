import { isIP } from 'node:net';
import { type SelfTestReport, selfTestReportSchema } from './runner-reports';

/**
 * Judgement of the probe runner's self-report (step 4.6 X6 self-test). Pure. The probe runs
 * `bootstrap.mjs --self-test` inside a runner created with the exact hardened spec (and verified
 * after create); it must prove uid ≠ 0, no effective/permitted/bounding capabilities,
 * no_new_privs = 1, seccomp filter mode (2), a read-only root, a writable /scratch, no route except
 * the directly connected detonation subnet (no default route), the sinkhole as the only DNS server
 * and its answer for a probe name, no Docker socket and an empty environment (only `PATH`, plus
 * `HOSTNAME`/`HOME` which the runtime always sets). Any failure → `spec_not_enforced`.
 *
 * The runner is LOCAL/CI ONLY and NOT A VM BOUNDARY; passing this self-test proves the container
 * restrictions are in force, nothing more.
 */

export const ALLOWED_ENV_KEYS: ReadonlySet<string> = new Set(['PATH', 'HOSTNAME', 'HOME']);

export interface SelfTestExpectations {
  sinkholeDns: string;
  /** The daemon reports AppArmor: the probe must be confined by `docker-default`. */
  apparmor: boolean;
}

export interface SelfTestJudgement {
  ok: boolean;
  /** Names of the failed checks (never values). */
  failures: string[];
  details: Record<string, string | number | boolean>;
}

const ipToInt = (ip: string): number | null => {
  if (isIP(ip) !== 4) return null;
  return ip.split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
};
const isZeroHex = (value: string | null): boolean => value !== null && /^0+$/.test(value);

/** Evaluates an (unvalidated) self-test report. */
export function judgeSelfTest(raw: unknown, expected: SelfTestExpectations): SelfTestJudgement {
  const parsed = selfTestReportSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      ok: false,
      failures: ['report_invalid'],
      details: { apparmor: false, seccomp: false },
    };
  }
  const r: SelfTestReport = parsed.data;
  const failures: string[] = [];
  const check = (ok: boolean, name: string) => {
    if (!ok) failures.push(name);
  };
  check(r.uid !== 0 && r.gid !== 0, 'uid');
  check(isZeroHex(r.capEff), 'cap_eff');
  check(isZeroHex(r.capPrm), 'cap_prm');
  check(isZeroHex(r.capBnd), 'cap_bnd');
  check(r.noNewPrivs === '1', 'no_new_privs');
  check(r.seccomp === '2', 'seccomp');
  check(r.rootWrite !== true, 'root_read_only');
  check(r.etcWrite !== true, 'etc_read_only');
  check(r.scratchWrite === true, 'scratch_writable');

  const sinkhole = ipToInt(expected.sinkholeDns);
  const routesOk =
    r.routes.length > 0 &&
    r.routes.every((route) => route.destination !== '0.0.0.0' && route.gateway === '0.0.0.0') &&
    sinkhole !== null &&
    r.routes.some((route) => {
      const dest = ipToInt(route.destination);
      const mask = ipToInt(route.mask);
      return dest !== null && mask !== null && (sinkhole & mask) >>> 0 === dest;
    });
  check(routesOk, 'routes');

  const { nameservers, extServers } = r.resolver;
  const embedded = nameservers.length === 1 && nameservers[0] === '127.0.0.11';
  const resolverOk = embedded
    ? extServers.length === 1 && extServers[0] === expected.sinkholeDns
    : nameservers.length === 1 && nameservers[0] === expected.sinkholeDns;
  check(resolverOk, 'resolver');
  check(r.dnsAnswer === expected.sinkholeDns, 'dns_answer');
  check(!r.dockerSocket, 'docker_socket');
  check(
    r.envKeys.every((key) => ALLOWED_ENV_KEYS.has(key)),
    'environment',
  );
  const confined = r.apparmor !== null && r.apparmor.startsWith('docker-default');
  if (expected.apparmor) check(confined, 'apparmor');

  return {
    ok: failures.length === 0,
    failures,
    details: {
      apparmor: expected.apparmor && confined,
      seccomp: r.seccomp === '2',
      noNewPrivs: r.noNewPrivs === '1',
      capabilities: isZeroHex(r.capEff) ? 'none' : 'present',
      uid: r.uid,
      rootReadOnly: r.rootWrite !== true,
      dnsSinkhole: r.dnsAnswer === expected.sinkholeDns,
      defaultRoute: r.routes.some((route) => route.destination === '0.0.0.0'),
      dockerSocket: r.dockerSocket,
    },
  };
}
