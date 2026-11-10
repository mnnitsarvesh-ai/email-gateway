import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  docker,
  findingCodes,
  harness,
  NETWORK,
  probe,
  type ProbeRun,
  serviceIps,
  SINKHOLE_IP,
} from './support';

/**
 * Escape-resistance suite of the hardened-container runner (step 4.6 §9.3; threat model §4.4,
 * §4.5, §5, §9; docs/security/sandbox-escape-testing.md). Host-run against the real Docker daemon,
 * the exec override's recording sinkhole and the internal detonation network. Every probe is a
 * synthetic benign script from `samples/probes/` that attempts ONE forbidden action. After every
 * probe the harness asserts: zero containers labelled `eg.sandbox.runner=1`, an empty controller
 * scratch directory and zero sinkhole records.
 *
 * LOCAL/CI ONLY — the runner is NOT A VM BOUNDARY; passing this suite proves the container
 * restrictions hold on this Docker host, not that unknown files can be executed safely.
 */

const h = harness();
const BLOCKED =
  /^RESULT \S+ \S+ \d+ BLOCKED (ECONNREFUSED|ENETUNREACH|EHOSTUNREACH|ETIMEDOUT|EADDRNOTAVAIL|ENOTFOUND|EAI_AGAIN|ECONNRESET)$/;

function only(run: ProbeRun, prefix: string): string {
  const lines = run.lines.filter((l) => l.startsWith(`RESULT ${prefix} `));
  expect(lines, `${prefix}: ${JSON.stringify(run.lines)}`).toHaveLength(1);
  return lines[0]!;
}

async function connect(host: string, port: number): Promise<ProbeRun> {
  const run = await h.run(probe('tcp-connect.js', { HOST: host, PORT: port }), 'script_js');
  expect(run.observation.status).toBe('completed');
  expect(run.observation.executed).toBe(true);
  const line = only(run, 'tcp-connect');
  expect(line, line).toMatch(BLOCKED);
  return run;
}

beforeAll(async () => {
  await h.setup();
}, 180_000);

afterAll(async () => {
  await h.teardown();
}, 180_000);

describe('cloud metadata (threat model A4, §4.5)', () => {
  it('169.254.169.254:80 is unreachable (no route)', async () => {
    const run = await connect('169.254.169.254', 80);
    expect(only(run, 'tcp-connect')).toMatch(/ENETUNREACH|EHOSTUNREACH/);
    expect(run.observation.observations.network.connections).toContainEqual({
      ip: '169.254.169.254',
      port: 80,
      protocol: 'tcp',
      outcome: 'unreachable',
    });
    expect(findingCodes(run.observation)).toContain('behaviour.metadata_access');
    const finding = run.observation.observations.findings.find(
      (f) => f.code === 'behaviour.metadata_access',
    );
    expect(finding?.severity).toBe('critical');
  });

  it('[fd00:ec2::254]:80 is unreachable', async () => {
    const run = await connect('fd00:ec2::254', 80);
    expect(run.observation.observations.network.connections.map((c) => c.ip)).toContain(
      'fd00:ec2::254',
    );
    expect(findingCodes(run.observation)).toContain('behaviour.metadata_access');
  });

  it('metadata.google.internal resolves to the sinkhole only, never a metadata service', async () => {
    const run = await h.run(
      probe('http-get.js', { HOST: 'metadata.google.internal', PATH: '/computeMetadata/v1/' }),
      'script_js',
    );
    const line = only(run, 'http-get');
    expect(line).toBe(
      `RESULT http-get metadata.google.internal ANSWERED ${SINKHOLE_IP} status=200 body="ok"`,
    );
    const network = run.observation.observations.network;
    expect(network.dns.map((d) => d.name)).toContain('metadata.google.internal');
    expect(network.http.map((r) => r.host)).toContain('metadata.google.internal');
    expect(findingCodes(run.observation)).toContain('behaviour.metadata_access');
  });
});

describe('internal network (threat model §4.5)', () => {
  const services: Array<[string, number]> = [
    ['mysql', 3306],
    ['mysql-replica', 3306],
    ['rabbitmq', 5672],
    ['redis', 6379],
    ['minio', 9000],
    ['api', 3000],
    ['email-worker', 3000],
    ['sandbox-controller', 3092],
  ];

  it.each(services)(
    '%s by name resolves only to the sinkhole and is refused',
    async (name, port) => {
      const run = await connect(name, port);
      expect(only(run, 'tcp-connect')).toMatch(/ECONNREFUSED/);
      expect(run.observation.observations.network.dns.map((d) => d.name)).toContain(name);
      expect(run.observation.observations.network.connections).toContainEqual({
        ip: SINKHOLE_IP,
        port,
        protocol: 'tcp',
        outcome: 'refused',
      });
      expect(findingCodes(run.observation)).toContain('behaviour.internal_network_access');
    },
  );

  it('every running stack container is unreachable by its current IPs (read from Docker)', async () => {
    const ips = await serviceIps();
    const targets = [...ips.entries()]
      .filter(([service]) => service !== 'sandbox-sinkhole')
      .flatMap(([service, list]) => list.map((ip) => [service, ip] as const));
    expect(targets.length).toBeGreaterThan(0);
    const ports: Record<string, number> = {
      mysql: 3306,
      'mysql-replica': 3306,
      rabbitmq: 5672,
      redis: 6379,
      minio: 9000,
    };
    for (const [service, ip] of targets) {
      const run = await connect(ip, ports[service] ?? 80);
      const connection = run.observation.observations.network.connections.find((c) => c.ip === ip);
      expect(connection?.outcome, `${service} ${ip}`).toMatch(/^(unreachable|refused|timeout)$/);
      // Private addresses are internal; the url-test network uses TEST-NET-3 (203.0.113.0/24).
      expect(findingCodes(run.observation)).toEqual(
        expect.arrayContaining([
          ip.startsWith('203.0.113.')
            ? 'behaviour.direct_ip_connect'
            : 'behaviour.internal_network_access',
        ]),
      );
    }
  });

  it.each(['host.docker.internal', 'gateway.docker.internal'])(
    '%s on the published host ports is refused (resolves to the sinkhole)',
    async (name) => {
      for (const port of [3307, 3308, 6390, 5672, 9000, 3200]) {
        const run = await connect(name, port);
        expect(only(run, 'tcp-connect')).toMatch(/ECONNREFUSED/);
        expect(run.observation.observations.network.dns.map((d) => d.name)).toContain(name);
      }
    },
  );

  it.each([
    ['172.17.0.1', 80],
    ['10.0.0.1', 80],
    ['192.168.65.254', 80],
    ['192.168.65.254', 3307],
  ] as const)('%s:%i is unreachable', async (ip, port) => {
    const run = await connect(ip, port);
    expect(only(run, 'tcp-connect')).toMatch(/ENETUNREACH|EHOSTUNREACH|ETIMEDOUT/);
  });

  it('the detonation bridge has no Docker-host address: nothing answers at .1 / .128', async () => {
    // Without `gateway_mode_ipv4=isolated` the bridge gateway (172.31.253.128) is the Docker VM and
    // its TCP 111 answered (§12 WP4); compose.exec.yml isolates the bridge.
    const network = await docker.inspectNetwork(NETWORK);
    expect(network?.Options?.['com.docker.network.bridge.gateway_mode_ipv4']).toBe('isolated');
    expect(network?.IPAM?.Config?.[0]?.Gateway ?? null).toBeNull();
    for (const host of ['172.31.253.1', '172.31.253.128', '172.31.253.254']) {
      const run = await h.run(probe('tcp-scan.js', { HOST: host }), 'script_js', 'execute', {
        wallTimeoutMs: 20_000,
      });
      expect(run.lines.length).toBe(19);
      for (const line of run.lines) expect(line, line).toMatch(BLOCKED);
    }
  });
});

describe('service protocol handshakes fail (MySQL, RabbitMQ, Redis)', () => {
  it.each([
    ['mysql-handshake.js', 'mysql', 3306],
    ['amqp-handshake.js', 'rabbitmq', 5672],
    ['redis-handshake.js', 'redis', 6379],
  ] as const)('%s to %s by name and by IP', async (file, service, port) => {
    const ips = (await serviceIps()).get(service) ?? [];
    for (const host of [service, ...ips]) {
      const run = await h.run(probe(file, { HOST: host, PORT: port }), 'script_js');
      const lines = run.lines;
      expect(lines, JSON.stringify(lines)).toHaveLength(1);
      expect(lines[0]).not.toMatch(/HANDSHAKE/);
      expect(lines[0]).toMatch(/BLOCKED/);
    }
  });
});

describe('file system', () => {
  it.each([
    '/eg-probe',
    '/etc/eg-probe',
    '/usr/eg-probe',
    '/opt/eg/eg-probe',
    '/home/eg-probe',
    '/proc/sys/kernel/hostname',
  ])('writing %s fails', async (path) => {
    const run = await h.run(probe('fs-write.sh', { PATH: path }), 'script_shell');
    expect(only(run, 'fs-write')).toBe(`RESULT fs-write ${path} BLOCKED`);
    expect(run.observation.observations.files.deniedWrites).toBeGreaterThanOrEqual(1);
    expect(findingCodes(run.observation)).toContain('behaviour.write_outside_scratch');
  });

  it('writing /scratch works', async () => {
    const run = await h.run(
      probe('fs-write.sh', { PATH: '/scratch/work/eg-probe' }),
      'script_shell',
    );
    expect(only(run, 'fs-write')).toBe('RESULT fs-write /scratch/work/eg-probe WRITTEN');
    expect(run.observation.observations.files.deniedWrites).toBe(0);
  });

  it('filling /scratch hits ENOSPC at the tmpfs size (limit.scratch_full)', async () => {
    const run = await h.run(probe('scratch-fill.sh'), 'script_shell', 'execute', { scratchMb: 16 });
    const bytes = Number(only(run, 'scratch-fill').split(' ')[2]);
    expect(bytes).toBeGreaterThan(14 * 1024 * 1024);
    expect(bytes).toBeLessThanOrEqual(16 * 1024 * 1024);
    expect(run.observation.observations.limitsHit).toContain('scratch_full');
    expect(findingCodes(run.observation)).toContain('limit.scratch_full');
  });

  it('dropped files are hashed and captured (EICAR test string built at run time, an executable script)', async () => {
    const run = await h.run(probe('drop-files.sh'), 'script_shell');
    const eicar = Buffer.from(
      ['X5O!P%@AP[4\\PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'].join(''),
      'latin1',
    );
    const dropped = run.observation.observations.files.dropped;
    expect(dropped).toHaveLength(2);
    expect(dropped.map((d) => d.typeHint).sort()).toEqual(['script_shell', 'text']);
    const files = run.observation.artifacts.filter((a) => a.kind === 'dropped_file');
    expect(files.some((f) => f.bytes.equals(eicar))).toBe(true);
    expect(findingCodes(run.observation)).toEqual(
      expect.arrayContaining(['behaviour.dropped_files', 'behaviour.dropped_executable']),
    );
  });
});

describe('privileges', () => {
  it('uid ≠ 0, CapEff 0, NoNewPrivs 1, Seccomp 2, no Docker socket, empty environment', async () => {
    const run = await h.run(probe('privileges.sh'), 'script_shell');
    expect(run.lines).toEqual(
      expect.arrayContaining([
        'RESULT uid 65532',
        'RESULT status CapEff 0000000000000000',
        'RESULT status CapPrm 0000000000000000',
        'RESULT status CapBnd 0000000000000000',
        'RESULT status NoNewPrivs 1',
        'RESULT status Seccomp 2',
        'RESULT docker-socket /var/run/docker.sock ABSENT',
        'RESULT docker-socket /run/docker.sock ABSENT',
      ]),
    );
    const envKeys = run.lines
      .filter((l) => l.startsWith('RESULT env-key '))
      .map((l) => l.slice(15));
    expect(envKeys).toEqual(['PATH']);
  });

  it.each([
    ['priv-mount.sh', 'script_shell', 'priv-mount'],
    ['priv-unshare.sh', 'script_shell', 'priv-unshare'],
    ['priv-chroot.sh', 'script_shell', 'priv-chroot'],
    ['priv-setuid.js', 'script_js', 'priv-setuid'],
  ] as const)(
    '%s fails and is reported as a privilege escalation attempt',
    async (file, type, name) => {
      const run = await h.run(probe(file), type);
      expect(only(run, name)).toMatch(new RegExp(`^RESULT ${name} BLOCKED`));
      expect(findingCodes(run.observation)).toContain('behaviour.privilege_escalation_attempt');
    },
  );
});

describe('resource limits', () => {
  it('a fork bomb is capped at the pids limit and killed at the timeout', async () => {
    const wall = 8_000;
    const run = await h.run(probe('fork-bomb.sh'), 'script_shell', 'execute', {
      pids: 48,
      wallTimeoutMs: wall,
    });
    expect(run.observation.status).toBe('completed');
    expect(run.observation.observations.limitsHit).toEqual(
      expect.arrayContaining(['pids', 'wall_timeout']),
    );
    expect(run.elapsedMs).toBeLessThan(wall + 5_000 + 10_000);
    expect(run.observation.cleanup.runnerRemoved).toBe(true);
  });

  it('a memory bomb is OOM-killed (limit.memory)', async () => {
    const run = await h.run(probe('memory-bomb.js'), 'script_js', 'execute', { memoryMb: 160 });
    expect(run.observation.status).toBe('completed');
    expect(run.observation.observations.limitsHit).toContain('memory');
    expect(findingCodes(run.observation)).toContain('limit.memory');
  });

  it('a 4-thread CPU burner gets cpu.max = the quota and CPU time ≤ 1.2 × wall', async () => {
    const run = await h.run(probe('cpu-burner.js', { SECONDS: 5 }), 'script_js', 'execute', {
      cpuMillis: 1_000,
      wallTimeoutMs: 20_000,
    });
    expect(run.lines).toContain('RESULT cpu-burner cpu.max 100000_100000');
    const usage = run.lines.find((l) => l.startsWith('RESULT cpu-burner usage_usec'))!.split(' ');
    const used = Number(usage[3]);
    const wall = Number(usage[5]);
    expect(used).toBeGreaterThan(0);
    expect(used).toBeLessThanOrEqual(1.2 * wall);
    expect(run.observation.observations.limitsHit).toContain('cpu');
  });

  it('a sleep past the wall timeout is killed within wall + 5 s (limit.wall_timeout)', async () => {
    const wall = 6_000;
    const run = await h.run(probe('long-sleep.sh'), 'script_shell', 'execute', {
      wallTimeoutMs: wall,
    });
    expect(run.lines).toEqual(['RESULT long-sleep START']);
    expect(run.observation.observations.limitsHit).toContain('wall_timeout');
    expect(findingCodes(run.observation)).toEqual(
      expect.arrayContaining(['limit.wall_timeout', 'evasion.long_sleep']),
    );
    expect(run.elapsedMs).toBeLessThan(wall + 5_000 + 3_000);
  });
});

describe('a benign self-marking probe is executed (and observed) by this backend', () => {
  it.each([
    ['benign-marker.sh', 'script_shell'],
    ['benign-marker.js', 'script_js'],
  ] as const)('%s', async (file, type) => {
    const run = await h.run(probe(file), type);
    expect(run.lines).toEqual(['RESULT benign-marker EXECUTED']);
    expect(run.observation.executed).toBe(true);
    expect(run.observation.observations.files.dropped).toHaveLength(1);
    expect(run.observation.observations.network.dns.map((d) => d.name)).toContain(
      'eg-probe-marker.sandbox.invalid',
    );
  });
});
