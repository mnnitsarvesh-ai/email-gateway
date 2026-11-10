import { describe, expect, it } from 'vitest';
import { judgeSelfTest } from './self-test';

const SINKHOLE = '172.31.253.53';
const cgroup = {
  cpuUsageUsec: 1,
  nrThrottled: 0,
  throttledUsec: 0,
  oomKill: 0,
  cpuMax: '50000 100000',
  pidsMax: '32',
  memoryMax: '134217728',
};

/** The report the runner image wrote on this host (Docker Desktop, embedded DNS). */
const good = () => ({
  v: 1,
  mode: 'self-test',
  uid: 65532,
  gid: 65532,
  capEff: '0000000000000000',
  capPrm: '0000000000000000',
  capBnd: '0000000000000000',
  noNewPrivs: '1',
  seccomp: '2',
  rootWrite: 'EROFS',
  etcWrite: 'EROFS',
  scratchWrite: true,
  routes: [
    { iface: 'eth0', destination: '172.31.253.0', gateway: '0.0.0.0', mask: '255.255.255.0' },
  ],
  resolver: { nameservers: ['127.0.0.11'], extServers: [SINKHOLE] },
  dnsAnswer: SINKHOLE,
  dockerSocket: false,
  envKeys: ['HOME', 'HOSTNAME', 'PATH'],
  apparmor: 'unconfined',
  cgroup,
});

describe('judgeSelfTest', () => {
  it('accepts a correctly restricted runner (no AppArmor on the daemon)', () => {
    const result = judgeSelfTest(good(), { sinkholeDns: SINKHOLE, apparmor: false });
    expect(result.ok).toBe(true);
    expect(result.failures).toEqual([]);
    expect(result.details).toMatchObject({
      apparmor: false,
      seccomp: true,
      capabilities: 'none',
      defaultRoute: false,
    });
  });

  it('accepts a direct sinkhole resolver (no embedded DNS)', () => {
    const report = { ...good(), resolver: { nameservers: [SINKHOLE], extServers: [] } };
    expect(judgeSelfTest(report, { sinkholeDns: SINKHOLE, apparmor: false }).ok).toBe(true);
  });

  it.each([
    ['root uid', { uid: 0 }, 'uid'],
    ['effective capabilities', { capEff: '00000000a80425fb' }, 'cap_eff'],
    ['permitted capabilities', { capPrm: '0000000000000400' }, 'cap_prm'],
    ['bounding capabilities', { capBnd: '00000000a80425fb' }, 'cap_bnd'],
    ['no_new_privs off', { noNewPrivs: '0' }, 'no_new_privs'],
    ['seccomp off', { seccomp: '0' }, 'seccomp'],
    ['writable root', { rootWrite: true }, 'root_read_only'],
    ['writable /etc', { etcWrite: true }, 'etc_read_only'],
    ['read-only scratch', { scratchWrite: 'EROFS' }, 'scratch_writable'],
    [
      'default route',
      {
        routes: [
          { iface: 'eth0', destination: '0.0.0.0', gateway: '172.31.253.1', mask: '0.0.0.0' },
        ],
      },
      'routes',
    ],
    [
      'routed subnet',
      {
        routes: [
          { iface: 'eth0', destination: '10.0.0.0', gateway: '172.31.253.1', mask: '255.0.0.0' },
        ],
      },
      'routes',
    ],
    [
      'sinkhole outside the subnet',
      {
        routes: [
          { iface: 'eth0', destination: '172.18.0.0', gateway: '0.0.0.0', mask: '255.255.0.0' },
        ],
      },
      'routes',
    ],
    ['no routes', { routes: [] }, 'routes'],
    [
      'other upstream',
      { resolver: { nameservers: ['127.0.0.11'], extServers: ['192.168.65.7'] } },
      'resolver',
    ],
    [
      'extra upstream',
      { resolver: { nameservers: ['127.0.0.11'], extServers: [SINKHOLE, '8.8.8.8'] } },
      'resolver',
    ],
    ['public resolver', { resolver: { nameservers: ['8.8.8.8'], extServers: [] } }, 'resolver'],
    ['dns answered by someone else', { dnsAnswer: '93.184.216.34' }, 'dns_answer'],
    ['dns error', { dnsAnswer: 'error:ENOTFOUND' }, 'dns_answer'],
    ['docker socket', { dockerSocket: true }, 'docker_socket'],
    ['environment leak', { envKeys: ['PATH', 'DATABASE_URL'] }, 'environment'],
  ])('%s → refused', (_name, patch, failure) => {
    const result = judgeSelfTest(
      { ...good(), ...patch },
      { sinkholeDns: SINKHOLE, apparmor: false },
    );
    expect(result.ok).toBe(false);
    expect(result.failures).toContain(failure);
  });

  it('requires the docker-default AppArmor profile when the daemon has AppArmor', () => {
    expect(judgeSelfTest(good(), { sinkholeDns: SINKHOLE, apparmor: true }).failures).toEqual([
      'apparmor',
    ]);
    const confined = { ...good(), apparmor: 'docker-default (enforce)' };
    const result = judgeSelfTest(confined, { sinkholeDns: SINKHOLE, apparmor: true });
    expect(result.ok).toBe(true);
    expect(result.details.apparmor).toBe(true);
  });

  it('an invalid or tampered report is refused', () => {
    expect(judgeSelfTest(null, { sinkholeDns: SINKHOLE, apparmor: false }).failures).toEqual([
      'report_invalid',
    ]);
    expect(
      judgeSelfTest({ ...good(), extra: 1 }, { sinkholeDns: SINKHOLE, apparmor: false }).ok,
    ).toBe(false);
    expect(
      judgeSelfTest({ ...good(), mode: 'execute' }, { sinkholeDns: SINKHOLE, apparmor: false }).ok,
    ).toBe(false);
  });
});
