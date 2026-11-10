import { describe, expect, it } from 'vitest';
import type { ContainerInspect } from './docker-client';
import {
  assertHardenedSpec,
  BROWSER_ENTRYPOINT,
  buildRunnerSpec,
  daemonHasAppArmor,
  daemonHasSeccomp,
  effectiveLimits,
  HardenedSpecError,
  MIB,
  type RunnerContainerSpec,
  type RunnerPolicy,
  type RunnerProfile,
  verifyCreated,
} from './hardened-spec';

const policy: RunnerPolicy = {
  images: {
    runner: 'email-gateway/sandbox-runner:local',
    browser: 'email-gateway/url-browser-worker:local',
  },
  network: 'email-gateway_sandbox-detonation',
  sinkholeDns: '172.31.253.53',
  controllerName: 'sandbox-controller-local',
  apparmor: false,
};
const limits = { wallTimeoutMs: 60_000, memoryMb: 512, cpuMillis: 1_000, pids: 128, scratchMb: 64 };
const NOW = 1_800_000_000_000;

const build = (profile: RunnerProfile = 'execute', p: RunnerPolicy = policy) =>
  buildRunnerSpec(
    {
      taskId: '0190c3a2-7b1e-7cc1-8f00-000000000001',
      profile,
      limits,
      nowMs: NOW,
      graceMs: 30_000,
      hostname: 'sbx-0123456789ab',
    },
    p,
  );

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

/** The inspect the daemon returns for a correctly created runner. */
function inspectFor(spec: RunnerContainerSpec): ContainerInspect {
  return {
    Id: 'a'.repeat(64),
    AppArmorProfile: '',
    Mounts: [],
    State: { Status: 'created', Running: false },
    Config: {
      User: spec.User,
      Image: spec.Image,
      Tty: false,
      OpenStdin: true,
      StdinOnce: true,
      Labels: { ...spec.Labels, 'org.opencontainers.image.title': 'x' },
      Env: ['PATH=/usr/local/bin:/usr/bin:/bin'],
    },
    HostConfig: {
      ...clone(spec.HostConfig),
      CapAdd: null,
      Binds: null,
      Mounts: null,
      DnsSearch: null,
      ExtraHosts: null,
      CgroupnsMode: 'private',
      MaskedPaths: ['/proc/kcore'],
    },
    NetworkSettings: { Networks: { [policy.network]: { IPAddress: '' } } },
  };
}

describe('buildRunnerSpec (X6)', () => {
  it('builds exactly the hardened execute spec', () => {
    const spec = build();
    expect(spec).toMatchObject({
      Image: policy.images.runner,
      User: '65532:65532',
      Env: [],
      Cmd: [],
      OpenStdin: true,
      StdinOnce: true,
      Tty: false,
      NetworkDisabled: false,
      Labels: {
        'eg.sandbox.runner': '1',
        'eg.sandbox.controller': 'sandbox-controller-local',
        'eg.sandbox.task': '0190c3a2-7b1e-7cc1-8f00-000000000001',
        'eg.sandbox.expires': String((NOW + 60_000 + 30_000) / 1000),
        'eg.sandbox.isolation': 'container-not-vm',
        'eg.sandbox.profile': 'execute',
      },
      HostConfig: {
        NetworkMode: policy.network,
        Dns: ['172.31.253.53'],
        DnsSearch: [],
        ExtraHosts: [],
        CapDrop: ['ALL'],
        CapAdd: [],
        SecurityOpt: ['no-new-privileges:true'],
        ReadonlyRootfs: true,
        Tmpfs: {
          '/scratch': 'rw,nosuid,nodev,size=64m,mode=0700,uid=65532,gid=65532',
          '/tmp': 'rw,nosuid,nodev,size=16m',
        },
        Memory: 512 * MIB,
        MemorySwap: 512 * MIB,
        NanoCpus: 1_000_000_000,
        PidsLimit: 128,
        IpcMode: 'private',
        PidMode: '',
        Privileged: false,
        Devices: [],
        Binds: [],
        Mounts: [],
        VolumesFrom: [],
        PortBindings: {},
        PublishAllPorts: false,
        Ulimits: [
          { Name: 'nofile', Soft: 256, Hard: 256 },
          { Name: 'core', Soft: 0, Hard: 0 },
        ],
        OomKillDisable: false,
        Init: true,
        AutoRemove: false,
      },
      NetworkingConfig: { EndpointsConfig: { [policy.network]: {} } },
    });
    expect(spec.Entrypoint).toBeUndefined();
  });

  it('adds apparmor=docker-default only when the daemon reports AppArmor', () => {
    expect(build('execute', { ...policy, apparmor: true }).HostConfig.SecurityOpt).toEqual([
      'no-new-privileges:true',
      'apparmor=docker-default',
    ]);
  });

  it('browser: browser image, render entrypoint, ≥ 1 GiB, ≥ 256 pids, ≥ 128 MiB scratch, 1024 files', () => {
    const spec = build('browser');
    expect(spec.Image).toBe(policy.images.browser);
    expect(spec.Entrypoint).toEqual([...BROWSER_ENTRYPOINT]);
    expect(spec.WorkingDir).toBe('/app');
    expect(spec.HostConfig.Memory).toBe(1024 * MIB);
    expect(spec.HostConfig.PidsLimit).toBe(256);
    expect(spec.HostConfig.Tmpfs['/scratch']).toContain('size=128m');
    expect(spec.HostConfig.Ulimits[0]).toEqual({ Name: 'nofile', Soft: 1024, Hard: 1024 });
    expect(
      effectiveLimits('browser', { memoryMb: 2048, cpuMillis: 500, pids: 512, scratchMb: 256 }),
    ).toEqual({
      memoryMb: 2048,
      cpuMillis: 500,
      pids: 512,
      scratchMb: 256,
    });
  });

  it('self-test: runner image with --self-test', () => {
    expect(build('self-test').Cmd).toEqual(['--self-test']);
  });

  it('random hostnames', () => {
    const a = buildRunnerSpec(
      { taskId: 't1', profile: 'execute', limits, nowMs: NOW, graceMs: 0 },
      policy,
    );
    const b = buildRunnerSpec(
      { taskId: 't1', profile: 'execute', limits, nowMs: NOW, graceMs: 0 },
      policy,
    );
    expect(a.Hostname).toMatch(/^sbx-[0-9a-f]{12}$/);
    expect(a.Hostname).not.toBe(b.Hostname);
  });

  it('refuses a bad task id, controller name or a root user', () => {
    expect(() =>
      buildRunnerSpec(
        { taskId: 'a/b', profile: 'execute', limits, nowMs: NOW, graceMs: 0 },
        policy,
      ),
    ).toThrow(HardenedSpecError);
    expect(() => build('execute', { ...policy, controllerName: 'bad name' })).toThrow(
      /controller_name/,
    );
    expect(() => build('execute', { ...policy, user: '0:0' })).toThrow(/User/);
    expect(() => build('execute', { ...policy, user: 'root' })).toThrow(/User/);
    expect(
      build('execute', { ...policy, user: '1000:1000' }).HostConfig.Tmpfs['/scratch'],
    ).toContain('uid=1000,gid=1000');
  });
});

describe('assertHardenedSpec rejects every forbidden field', () => {
  type Mutation = [
    string,
    (s: Record<string, unknown> & { HostConfig: Record<string, unknown> }) => void,
    string,
  ];
  const mutations: Mutation[] = [
    ['unknown top-level field', (s) => (s.Volumes = { '/x': {} }), 'Volumes'],
    ['ExposedPorts', (s) => (s.ExposedPorts = { '80/tcp': {} }), 'ExposedPorts'],
    ['image outside the allow-list', (s) => (s.Image = 'alpine:latest'), 'Image'],
    ['browser image for execute', (s) => (s.Image = policy.images.browser), 'Image'],
    ['root user', (s) => (s.User = '0:0'), 'User'],
    ['no user', (s) => delete s.User, 'User'],
    ['fixed hostname', (s) => (s.Hostname = 'mysql'), 'Hostname'],
    ['environment', (s) => (s.Env = ['DATABASE_URL=x']), 'Env'],
    ['entrypoint override', (s) => (s.Entrypoint = ['/bin/sh']), 'Entrypoint'],
    ['working dir', (s) => (s.WorkingDir = '/'), 'WorkingDir'],
    ['cmd', (s) => (s.Cmd = ['-c', 'id']), 'Cmd'],
    ['tty', (s) => (s.Tty = true), 'Tty'],
    ['stdin not once', (s) => (s.StdinOnce = false), 'OpenStdin'],
    ['network disabled', (s) => (s.NetworkDisabled = true), 'NetworkDisabled'],
    [
      'missing isolation label',
      (s) => delete (s.Labels as Record<string, string>)['eg.sandbox.isolation'],
      'Labels.isolation',
    ],
    [
      'wrong isolation label',
      (s) => ((s.Labels as Record<string, string>)['eg.sandbox.isolation'] = 'vm'),
      'Labels.isolation',
    ],
    [
      'other controller',
      (s) => ((s.Labels as Record<string, string>)['eg.sandbox.controller'] = 'x'),
      'Labels.controller',
    ],
    [
      'extra label',
      (s) => ((s.Labels as Record<string, string>)['com.docker.compose.project'] = 'x'),
      'Labels.extra',
    ],
    [
      'no expiry',
      (s) => ((s.Labels as Record<string, string>)['eg.sandbox.expires'] = 'never'),
      'Labels.expires',
    ],
    [
      'second network',
      (s) =>
        ((
          s.NetworkingConfig as { EndpointsConfig: Record<string, object> }
        ).EndpointsConfig.bridge = {}),
      'NetworkingConfig',
    ],
    [
      'unknown host config field',
      (s) => (s.HostConfig.CgroupParent = '/'),
      'HostConfig.CgroupParent',
    ],
    ['runtime', (s) => (s.HostConfig.Runtime = 'runc'), 'HostConfig.Runtime'],
    [
      'sysctls',
      (s) => (s.HostConfig.Sysctls = { 'net.ipv4.ip_forward': '1' }),
      'HostConfig.Sysctls',
    ],
    ['host network', (s) => (s.HostConfig.NetworkMode = 'host'), 'HostConfig.NetworkMode'],
    ['bridge network', (s) => (s.HostConfig.NetworkMode = 'bridge'), 'HostConfig.NetworkMode'],
    ['other resolver', (s) => (s.HostConfig.Dns = ['8.8.8.8']), 'HostConfig.Dns'],
    ['extra resolver', (s) => (s.HostConfig.Dns = ['172.31.253.53', '8.8.8.8']), 'HostConfig.Dns'],
    ['dns search', (s) => (s.HostConfig.DnsSearch = ['internal']), 'HostConfig.DnsSearch'],
    [
      'extra hosts',
      (s) => (s.HostConfig.ExtraHosts = ['host.docker.internal:host-gateway']),
      'HostConfig.ExtraHosts',
    ],
    ['a capability', (s) => (s.HostConfig.CapAdd = ['NET_RAW']), 'HostConfig.CapAdd'],
    ['caps not dropped', (s) => (s.HostConfig.CapDrop = []), 'HostConfig.CapDrop'],
    ['no-new-privileges missing', (s) => (s.HostConfig.SecurityOpt = []), 'HostConfig.SecurityOpt'],
    [
      'seccomp unconfined',
      (s) => (s.HostConfig.SecurityOpt = ['no-new-privileges:true', 'seccomp=unconfined']),
      'HostConfig.SecurityOpt',
    ],
    [
      'apparmor unconfined',
      (s) => (s.HostConfig.SecurityOpt = ['no-new-privileges:true', 'apparmor=unconfined']),
      'HostConfig.SecurityOpt',
    ],
    ['writable root', (s) => (s.HostConfig.ReadonlyRootfs = false), 'HostConfig.ReadonlyRootfs'],
    ['privileged', (s) => (s.HostConfig.Privileged = true), 'HostConfig.Privileged'],
    ['host ipc', (s) => (s.HostConfig.IpcMode = 'host'), 'HostConfig.IpcMode'],
    ['host pid', (s) => (s.HostConfig.PidMode = 'host'), 'HostConfig.PidMode'],
    ['host uts', (s) => (s.HostConfig.UTSMode = 'host'), 'HostConfig.UTSMode'],
    ['host userns', (s) => (s.HostConfig.UsernsMode = 'host'), 'HostConfig.UsernsMode'],
    [
      'a device',
      (s) => (s.HostConfig.Devices = [{ PathOnHost: '/dev/kvm' }]),
      'HostConfig.Devices',
    ],
    ['a gpu', (s) => (s.HostConfig.DeviceRequests = [{ Count: -1 }]), 'HostConfig.DeviceRequests'],
    [
      'a bind',
      (s) => (s.HostConfig.Binds = ['/var/run/docker.sock:/var/run/docker.sock']),
      'HostConfig.Binds',
    ],
    [
      'a mount',
      (s) => (s.HostConfig.Mounts = [{ Type: 'bind', Source: '/', Target: '/host' }]),
      'HostConfig.Mounts',
    ],
    ['volumes from', (s) => (s.HostConfig.VolumesFrom = ['mysql']), 'HostConfig.VolumesFrom'],
    [
      'port binding',
      (s) => (s.HostConfig.PortBindings = { '80/tcp': [{ HostPort: '8080' }] }),
      'HostConfig.PortBindings',
    ],
    ['publish all', (s) => (s.HostConfig.PublishAllPorts = true), 'HostConfig.PublishAllPorts'],
    ['oom kill disabled', (s) => (s.HostConfig.OomKillDisable = true), 'HostConfig.OomKillDisable'],
    ['no init', (s) => (s.HostConfig.Init = false), 'HostConfig.Init'],
    ['auto remove', (s) => (s.HostConfig.AutoRemove = true), 'HostConfig.AutoRemove'],
    [
      'restart policy',
      (s) => (s.HostConfig.RestartPolicy = { Name: 'always' }),
      'HostConfig.RestartPolicy',
    ],
    [
      'logging',
      (s) => (s.HostConfig.LogConfig = { Type: 'json-file', Config: {} }),
      'HostConfig.LogConfig',
    ],
    ['no memory limit', (s) => (s.HostConfig.Memory = 0), 'HostConfig.Memory'],
    ['swap above memory', (s) => (s.HostConfig.MemorySwap = -1), 'HostConfig.MemorySwap'],
    ['no cpu limit', (s) => delete s.HostConfig.NanoCpus, 'HostConfig.NanoCpus'],
    ['no pids limit', (s) => (s.HostConfig.PidsLimit = -1), 'HostConfig.PidsLimit'],
    [
      'extra tmpfs',
      (s) => ((s.HostConfig.Tmpfs as Record<string, string>)['/dev/shm'] = 'rw'),
      'HostConfig.Tmpfs',
    ],
    [
      'exec scratch with suid',
      (s) => ((s.HostConfig.Tmpfs as Record<string, string>)['/scratch'] = 'rw,size=64m'),
      'HostConfig.Tmpfs./scratch',
    ],
    [
      'big /tmp',
      (s) => ((s.HostConfig.Tmpfs as Record<string, string>)['/tmp'] = 'rw,nosuid,nodev,size=1g'),
      'HostConfig.Tmpfs./tmp',
    ],
    ['no ulimits', (s) => (s.HostConfig.Ulimits = []), 'HostConfig.Ulimits'],
    [
      'core dumps',
      (s) =>
        (s.HostConfig.Ulimits = [
          { Name: 'nofile', Soft: 256, Hard: 256 },
          { Name: 'core', Soft: -1, Hard: -1 },
        ]),
      'HostConfig.Ulimits',
    ],
  ];

  it.each(mutations)('%s', (_name, mutate, field) => {
    const spec = clone(build()) as unknown as Record<string, unknown> & {
      HostConfig: Record<string, unknown>;
    };
    mutate(spec);
    let error: unknown;
    try {
      assertHardenedSpec(spec, policy, 'execute');
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(HardenedSpecError);
    expect((error as HardenedSpecError).field).toBe(field);
  });

  it('accepts the built spec for every profile', () => {
    for (const profile of ['execute', 'browser', 'self-test'] as const) {
      expect(() => assertHardenedSpec(build(profile), policy, profile)).not.toThrow();
    }
  });

  it('refuses a browser spec under the execute profile and vice versa', () => {
    expect(() => assertHardenedSpec(build('browser'), policy, 'execute')).toThrow(
      HardenedSpecError,
    );
    expect(() => assertHardenedSpec(build('execute'), policy, 'browser')).toThrow(
      HardenedSpecError,
    );
    expect(() => assertHardenedSpec(null, policy, 'execute')).toThrow(HardenedSpecError);
  });
});

describe('verifyCreated (effective configuration after create)', () => {
  const spec = build();

  it('accepts the daemon view of a correct runner', () => {
    expect(verifyCreated(inspectFor(spec), { policy, spec })).toEqual({ ok: true });
  });

  type InspectMutation = [
    string,
    (i: ContainerInspect & { HostConfig: Record<string, unknown> }) => void,
    string,
  ];
  const mutations: InspectMutation[] = [
    ['already running', (i) => (i.State = { Status: 'running', Running: true }), 'State'],
    ['image swapped', (i) => (i.Config!.Image = 'alpine'), 'Config.Image'],
    ['user dropped (image default root)', (i) => (i.Config!.User = ''), 'Config.User'],
    ['tty', (i) => (i.Config!.Tty = true), 'Config.Tty'],
    ['exposed port', (i) => (i.Config!.ExposedPorts = { '80/tcp': {} }), 'Config.ExposedPorts'],
    [
      'label missing',
      (i) => delete i.Config!.Labels!['eg.sandbox.isolation'],
      'Config.Labels.eg.sandbox.isolation',
    ],
    ['privileged', (i) => (i.HostConfig.Privileged = true), 'HostConfig.Privileged'],
    ['capability added', (i) => (i.HostConfig.CapAdd = ['SYS_ADMIN']), 'HostConfig.CapAdd'],
    ['caps kept', (i) => (i.HostConfig.CapDrop = null), 'HostConfig.CapDrop'],
    ['writable root', (i) => (i.HostConfig.ReadonlyRootfs = false), 'HostConfig.ReadonlyRootfs'],
    ['bind', (i) => (i.HostConfig.Binds = ['/:/host']), 'HostConfig.Binds'],
    ['mount', (i) => (i.HostConfig.Mounts = [{ Type: 'bind' }]), 'HostConfig.Mounts'],
    ['volume mount', (i) => (i.Mounts = [{ Type: 'volume', Destination: '/data' }]), 'Mounts'],
    ['device', (i) => (i.HostConfig.Devices = [{ PathOnHost: '/dev/mem' }]), 'HostConfig.Devices'],
    ['device request', (i) => (i.HostConfig.DeviceRequests = [{}]), 'HostConfig.DeviceRequests'],
    ['volumes from', (i) => (i.HostConfig.VolumesFrom = ['x']), 'HostConfig.VolumesFrom'],
    [
      'port binding',
      (i) => (i.HostConfig.PortBindings = { '80/tcp': [] }),
      'HostConfig.PortBindings',
    ],
    ['publish all', (i) => (i.HostConfig.PublishAllPorts = true), 'HostConfig.PublishAllPorts'],
    ['other network mode', (i) => (i.HostConfig.NetworkMode = 'bridge'), 'HostConfig.NetworkMode'],
    [
      'second network attached',
      (i) => (i.NetworkSettings!.Networks!.bridge = {}),
      'NetworkSettings.Networks',
    ],
    ['resolver changed', (i) => (i.HostConfig.Dns = ['1.1.1.1']), 'HostConfig.Dns'],
    ['dns search', (i) => (i.HostConfig.DnsSearch = ['x']), 'HostConfig.DnsSearch'],
    ['extra hosts', (i) => (i.HostConfig.ExtraHosts = ['a:1.2.3.4']), 'HostConfig.ExtraHosts'],
    [
      'no-new-privileges gone',
      (i) => (i.HostConfig.SecurityOpt = []),
      'HostConfig.SecurityOpt.no-new-privileges',
    ],
    [
      'seccomp unconfined',
      (i) => (i.HostConfig.SecurityOpt = ['no-new-privileges:true', 'seccomp=unconfined']),
      'HostConfig.SecurityOpt.seccomp',
    ],
    [
      'label disable',
      (i) => (i.HostConfig.SecurityOpt = ['no-new-privileges', 'label=disable']),
      'HostConfig.SecurityOpt.unconfined',
    ],
    ['host ipc', (i) => (i.HostConfig.IpcMode = 'host'), 'HostConfig.IpcMode'],
    ['shareable ipc', (i) => (i.HostConfig.IpcMode = 'shareable'), 'HostConfig.IpcMode'],
    ['host pid', (i) => (i.HostConfig.PidMode = 'host'), 'HostConfig.PidMode'],
    ['host uts', (i) => (i.HostConfig.UTSMode = 'host'), 'HostConfig.UTSMode'],
    ['host userns', (i) => (i.HostConfig.UsernsMode = 'host'), 'HostConfig.UsernsMode'],
    ['host cgroupns', (i) => (i.HostConfig.CgroupnsMode = 'host'), 'HostConfig.CgroupnsMode'],
    ['memory ignored', (i) => (i.HostConfig.Memory = 0), 'HostConfig.Memory'],
    ['swap unlimited', (i) => (i.HostConfig.MemorySwap = -1), 'HostConfig.MemorySwap'],
    ['cpu ignored', (i) => (i.HostConfig.NanoCpus = 0), 'HostConfig.NanoCpus'],
    ['pids ignored', (i) => (i.HostConfig.PidsLimit = 0), 'HostConfig.PidsLimit'],
    ['oom kill disabled', (i) => (i.HostConfig.OomKillDisable = true), 'HostConfig.OomKillDisable'],
    ['no init', (i) => (i.HostConfig.Init = false), 'HostConfig.Init'],
    ['auto remove', (i) => (i.HostConfig.AutoRemove = true), 'HostConfig.AutoRemove'],
    ['tmpfs changed', (i) => (i.HostConfig.Tmpfs = { '/scratch': 'rw' }), 'HostConfig.Tmpfs'],
    ['no masked paths', (i) => (i.HostConfig.MaskedPaths = []), 'HostConfig.MaskedPaths'],
  ];

  it.each(mutations)('%s → mismatch (removed without start)', (_name, mutate, field) => {
    const inspect = clone(inspectFor(spec)) as ContainerInspect & {
      HostConfig: Record<string, unknown>;
    };
    mutate(inspect);
    const result = verifyCreated(inspect, { policy, spec });
    expect(result.ok).toBe(false);
    expect(result.ok ? [] : result.mismatches).toContain(field);
  });

  it('missing container → mismatch', () => {
    expect(verifyCreated(null, { policy, spec })).toEqual({ ok: false, mismatches: ['missing'] });
  });

  it('with AppArmor on the daemon the docker-default profile is required', () => {
    const p = { ...policy, apparmor: true };
    const s = build('execute', p);
    const inspect = inspectFor(s);
    expect(verifyCreated(inspect, { policy: p, spec: s })).toEqual({
      ok: false,
      mismatches: ['AppArmorProfile'],
    });
    inspect.AppArmorProfile = 'docker-default';
    expect(verifyCreated(inspect, { policy: p, spec: s })).toEqual({ ok: true });
  });
});

describe('daemon security options', () => {
  it('detects AppArmor and seccomp in /info SecurityOptions', () => {
    expect(daemonHasAppArmor(['name=seccomp,profile=builtin', 'name=cgroupns'])).toBe(false);
    expect(daemonHasAppArmor(['name=apparmor', 'name=seccomp,profile=builtin'])).toBe(true);
    expect(daemonHasSeccomp(['name=seccomp,profile=builtin'])).toBe(true);
    expect(daemonHasSeccomp(null)).toBe(false);
  });
});
