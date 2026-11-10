import { randomBytes } from 'node:crypto';
import type { ContainerInspect } from './docker-client';

/**
 * The hardened runner container spec (step 4.6 X6; docs/plan/steps/14-sandbox.md). Pure.
 *
 * LOCAL/CI ONLY — a hardened shared-kernel container is NOT A VM BOUNDARY (labelled
 * `eg.sandbox.isolation=container-not-vm` on every runner). `buildRunnerSpec` builds exactly the X6
 * `containers/create` body, `assertHardenedSpec` refuses anything else before create, and
 * `verifyCreated` re-checks the EFFECTIVE configuration the daemon reports after create; the
 * backend removes the container without starting it on any mismatch (`spec_not_enforced`).
 */

export const RUNNER_USER = '65532:65532';
export const RUNNER_LABELS = Object.freeze({
  runner: 'eg.sandbox.runner',
  controller: 'eg.sandbox.controller',
  task: 'eg.sandbox.task',
  expires: 'eg.sandbox.expires',
  isolation: 'eg.sandbox.isolation',
  profile: 'eg.sandbox.profile',
});
export const ISOLATION_LABEL_VALUE = 'container-not-vm';
export const BROWSER_ENTRYPOINT = Object.freeze([
  '/usr/local/bin/node',
  'dist/sandbox-render/render-main.js',
]);
export const BROWSER_WORKDIR = '/app';
/** Browser runners need more than script runners (X6): at least 1 GiB, 256 pids, 128 MiB scratch. */
export const BROWSER_FLOORS = Object.freeze({ memoryMb: 1024, pids: 256, scratchMb: 128 });
export const TMP_TMPFS = 'rw,nosuid,nodev,size=16m';
export const MIB = 1024 * 1024;

export type RunnerProfile = 'execute' | 'browser' | 'self-test';

export interface RunnerPolicy {
  /** `SANDBOX_RUNNER_IMAGE` (execute + self-test) and `SANDBOX_BROWSER_IMAGE` (browser). */
  images: { runner: string; browser: string };
  /** `SANDBOX_RUNNER_NETWORK`: the internal detonation network, the runner's only network. */
  network: string;
  /** `SANDBOX_SINKHOLE_DNS`: the runner's only resolver. */
  sinkholeDns: string;
  /** `SANDBOX_CONTROLLER_NAME`. */
  controllerName: string;
  /** True when `/info` reports AppArmor: then `apparmor=docker-default` is required. */
  apparmor: boolean;
  /** Non-root `uid:gid` of the sample (default `RUNNER_USER`, the images' user 65532). */
  user?: string;
}

export interface RunnerSpecInput {
  taskId: string;
  profile: RunnerProfile;
  limits: {
    wallTimeoutMs: number;
    memoryMb: number;
    cpuMillis: number;
    pids: number;
    scratchMb: number;
  };
  /** Epoch ms of creation (expiry label = now + wall + grace). */
  nowMs: number;
  /** Cleanup grace added to the expiry label (outer timeout slack + removal). */
  graceMs: number;
  /** Tests: fixed hostname. */
  hostname?: string;
}

export interface ResourceLimits {
  memoryMb: number;
  cpuMillis: number;
  pids: number;
  scratchMb: number;
}

export interface RunnerContainerSpec {
  Image: string;
  User: string;
  Hostname: string;
  Env: string[];
  Cmd: string[];
  Entrypoint?: string[];
  WorkingDir?: string;
  Labels: Record<string, string>;
  OpenStdin: true;
  StdinOnce: true;
  AttachStdin: true;
  AttachStdout: true;
  AttachStderr: true;
  Tty: false;
  NetworkDisabled: false;
  HostConfig: {
    NetworkMode: string;
    Dns: string[];
    DnsSearch: string[];
    DnsOptions: string[];
    ExtraHosts: string[];
    CapDrop: string[];
    CapAdd: string[];
    SecurityOpt: string[];
    ReadonlyRootfs: true;
    Tmpfs: Record<string, string>;
    Memory: number;
    MemorySwap: number;
    NanoCpus: number;
    PidsLimit: number;
    IpcMode: 'private';
    PidMode: '';
    UTSMode: '';
    UsernsMode: '';
    Privileged: false;
    Devices: never[];
    DeviceRequests: never[];
    Binds: never[];
    Mounts: never[];
    VolumesFrom: never[];
    PortBindings: Record<string, never>;
    PublishAllPorts: false;
    Ulimits: Array<{ Name: string; Soft: number; Hard: number }>;
    OomKillDisable: false;
    Init: true;
    AutoRemove: false;
    RestartPolicy: { Name: 'no' };
    LogConfig: { Type: 'none'; Config: Record<string, never> };
  };
  NetworkingConfig: { EndpointsConfig: Record<string, Record<string, never>> };
}

export class HardenedSpecError extends Error {
  constructor(readonly field: string) {
    super(`runner spec refused: ${field}`);
    this.name = 'HardenedSpecError';
  }
}

const TASK_ID_PATTERN = /^[A-Za-z0-9-]{1,64}$/;
const CONTROLLER_NAME_PATTERN = /^[A-Za-z0-9._-]{1,63}$/;
const HOSTNAME_PATTERN = /^sbx-[0-9a-f]{12}$/;

/** The limits a profile actually gets (browser floors applied). */
export function effectiveLimits(profile: RunnerProfile, limits: ResourceLimits): ResourceLimits {
  if (profile !== 'browser') return { ...limits };
  return {
    memoryMb: Math.max(limits.memoryMb, BROWSER_FLOORS.memoryMb),
    cpuMillis: limits.cpuMillis,
    pids: Math.max(limits.pids, BROWSER_FLOORS.pids),
    scratchMb: Math.max(limits.scratchMb, BROWSER_FLOORS.scratchMb),
  };
}

export const scratchTmpfs = (scratchMb: number, user: string = RUNNER_USER): string => {
  const [uid, gid] = user.split(':');
  return `rw,nosuid,nodev,size=${scratchMb}m,mode=0700,uid=${uid},gid=${gid}`;
};

const USER_PATTERN = /^[1-9]\d{0,9}:[1-9]\d{0,9}$/;

/** The runner user of a policy; refuses root or a malformed value. */
export function runnerUser(policy: RunnerPolicy): string {
  const user = policy.user ?? RUNNER_USER;
  if (!USER_PATTERN.test(user)) throw new HardenedSpecError('User');
  return user;
}

/** The open-files limit per profile: Chromium needs more descriptors than a script. */
export const nofileLimit = (profile: RunnerProfile): number => (profile === 'browser' ? 1024 : 256);

export const securityOpts = (apparmor: boolean): string[] =>
  apparmor ? ['no-new-privileges:true', 'apparmor=docker-default'] : ['no-new-privileges:true'];

export const randomHostname = (): string => `sbx-${randomBytes(6).toString('hex')}`;

/** Builds the X6 `containers/create` body (pure apart from the random hostname). */
export function buildRunnerSpec(input: RunnerSpecInput, policy: RunnerPolicy): RunnerContainerSpec {
  if (!TASK_ID_PATTERN.test(input.taskId)) throw new HardenedSpecError('task_id');
  if (!CONTROLLER_NAME_PATTERN.test(policy.controllerName)) {
    throw new HardenedSpecError('controller_name');
  }
  const limits = effectiveLimits(input.profile, input.limits);
  const image = input.profile === 'browser' ? policy.images.browser : policy.images.runner;
  const expires = Math.ceil((input.nowMs + input.limits.wallTimeoutMs + input.graceMs) / 1000);
  const nofile = nofileLimit(input.profile);
  const user = runnerUser(policy);
  const spec: RunnerContainerSpec = {
    Image: image,
    User: user,
    Hostname: input.hostname ?? randomHostname(),
    Env: [],
    Cmd: input.profile === 'self-test' ? ['--self-test'] : [],
    ...(input.profile === 'browser'
      ? { Entrypoint: [...BROWSER_ENTRYPOINT], WorkingDir: BROWSER_WORKDIR }
      : {}),
    Labels: {
      [RUNNER_LABELS.runner]: '1',
      [RUNNER_LABELS.controller]: policy.controllerName,
      [RUNNER_LABELS.task]: input.taskId,
      [RUNNER_LABELS.expires]: String(expires),
      [RUNNER_LABELS.isolation]: ISOLATION_LABEL_VALUE,
      [RUNNER_LABELS.profile]: input.profile,
    },
    OpenStdin: true,
    StdinOnce: true,
    AttachStdin: true,
    AttachStdout: true,
    AttachStderr: true,
    Tty: false,
    NetworkDisabled: false,
    HostConfig: {
      NetworkMode: policy.network,
      Dns: [policy.sinkholeDns],
      DnsSearch: [],
      DnsOptions: [],
      ExtraHosts: [],
      CapDrop: ['ALL'],
      CapAdd: [],
      SecurityOpt: securityOpts(policy.apparmor),
      ReadonlyRootfs: true,
      Tmpfs: { '/scratch': scratchTmpfs(limits.scratchMb, user), '/tmp': TMP_TMPFS },
      Memory: limits.memoryMb * MIB,
      MemorySwap: limits.memoryMb * MIB,
      NanoCpus: limits.cpuMillis * 1_000_000,
      PidsLimit: limits.pids,
      IpcMode: 'private',
      PidMode: '',
      UTSMode: '',
      UsernsMode: '',
      Privileged: false,
      Devices: [],
      DeviceRequests: [],
      Binds: [],
      Mounts: [],
      VolumesFrom: [],
      PortBindings: {},
      PublishAllPorts: false,
      Ulimits: [
        { Name: 'nofile', Soft: nofile, Hard: nofile },
        { Name: 'core', Soft: 0, Hard: 0 },
      ],
      OomKillDisable: false,
      Init: true,
      AutoRemove: false,
      RestartPolicy: { Name: 'no' },
      LogConfig: { Type: 'none', Config: {} },
    },
    NetworkingConfig: { EndpointsConfig: { [policy.network]: {} } },
  };
  assertHardenedSpec(spec, policy, input.profile);
  return spec;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);
const sameStrings = (a: unknown, b: readonly string[]): boolean =>
  Array.isArray(a) && a.length === b.length && a.every((v, i) => v === b[i]);
const emptyList = (value: unknown): boolean =>
  value === undefined || value === null || (Array.isArray(value) && value.length === 0);
const emptyMap = (value: unknown): boolean =>
  value === undefined || value === null || (isRecord(value) && Object.keys(value).length === 0);

const ALLOWED_TOP_LEVEL = new Set([
  'Image',
  'User',
  'Hostname',
  'Env',
  'Cmd',
  'Entrypoint',
  'WorkingDir',
  'Labels',
  'OpenStdin',
  'StdinOnce',
  'AttachStdin',
  'AttachStdout',
  'AttachStderr',
  'Tty',
  'NetworkDisabled',
  'HostConfig',
  'NetworkingConfig',
]);
const ALLOWED_HOST_CONFIG = new Set([
  'NetworkMode',
  'Dns',
  'DnsSearch',
  'DnsOptions',
  'ExtraHosts',
  'CapDrop',
  'CapAdd',
  'SecurityOpt',
  'ReadonlyRootfs',
  'Tmpfs',
  'Memory',
  'MemorySwap',
  'NanoCpus',
  'PidsLimit',
  'IpcMode',
  'PidMode',
  'UTSMode',
  'UsernsMode',
  'Privileged',
  'Devices',
  'DeviceRequests',
  'Binds',
  'Mounts',
  'VolumesFrom',
  'PortBindings',
  'PublishAllPorts',
  'Ulimits',
  'OomKillDisable',
  'Init',
  'AutoRemove',
  'RestartPolicy',
  'LogConfig',
]);

/**
 * Refuses any spec that is not exactly the hardened shape: unknown fields (e.g. `Volumes`,
 * `ExposedPorts`, `CgroupParent`, `Runtime`, `Sysctls`), any capability, privileged mode, host
 * namespaces, binds/mounts/devices/ports, a writable root, a network or resolver other than the
 * detonation network and the sinkhole, an image outside the allow-list, a non-empty environment,
 * missing labels or limits. Throws `HardenedSpecError(field)`.
 */
export function assertHardenedSpec(
  spec: unknown,
  policy: RunnerPolicy,
  profile: RunnerProfile,
): asserts spec is RunnerContainerSpec {
  const fail = (field: string): never => {
    throw new HardenedSpecError(field);
  };
  if (!isRecord(spec)) fail('spec');
  const s = spec as Record<string, unknown>;
  for (const key of Object.keys(s)) if (!ALLOWED_TOP_LEVEL.has(key)) fail(key);
  const expectedImage = profile === 'browser' ? policy.images.browser : policy.images.runner;
  if (s.Image !== expectedImage) fail('Image');
  const user = runnerUser(policy);
  if (s.User !== user) fail('User');
  if (typeof s.Hostname !== 'string' || !HOSTNAME_PATTERN.test(s.Hostname)) fail('Hostname');
  if (!emptyList(s.Env)) fail('Env');
  if (profile === 'browser') {
    if (!sameStrings(s.Entrypoint, BROWSER_ENTRYPOINT)) fail('Entrypoint');
    if (s.WorkingDir !== BROWSER_WORKDIR) fail('WorkingDir');
    if (!sameStrings(s.Cmd, [])) fail('Cmd');
  } else {
    if (s.Entrypoint !== undefined) fail('Entrypoint');
    if (s.WorkingDir !== undefined) fail('WorkingDir');
    if (!sameStrings(s.Cmd, profile === 'self-test' ? ['--self-test'] : [])) fail('Cmd');
  }
  if (s.OpenStdin !== true || s.StdinOnce !== true) fail('OpenStdin');
  if (s.AttachStdin !== true || s.AttachStdout !== true || s.AttachStderr !== true) {
    fail('Attach');
  }
  if (s.Tty !== false) fail('Tty');
  if (s.NetworkDisabled !== false) fail('NetworkDisabled');

  const labels = s.Labels;
  if (!isRecord(labels)) fail('Labels');
  const l = labels as Record<string, unknown>;
  if (l[RUNNER_LABELS.runner] !== '1') fail('Labels.runner');
  if (l[RUNNER_LABELS.controller] !== policy.controllerName) fail('Labels.controller');
  const taskLabel = l[RUNNER_LABELS.task];
  if (typeof taskLabel !== 'string' || !TASK_ID_PATTERN.test(taskLabel)) fail('Labels.task');
  if (!/^\d{10,11}$/.test(String(l[RUNNER_LABELS.expires]))) fail('Labels.expires');
  if (l[RUNNER_LABELS.isolation] !== ISOLATION_LABEL_VALUE) fail('Labels.isolation');
  if (l[RUNNER_LABELS.profile] !== profile) fail('Labels.profile');
  if (Object.keys(l).length !== Object.keys(RUNNER_LABELS).length) fail('Labels.extra');

  const net = s.NetworkingConfig;
  if (
    !isRecord(net) ||
    !isRecord(net.EndpointsConfig) ||
    !sameStrings(Object.keys(net.EndpointsConfig), [policy.network]) ||
    !emptyMap(net.EndpointsConfig[policy.network])
  ) {
    fail('NetworkingConfig');
  }

  if (!isRecord(s.HostConfig)) fail('HostConfig');
  const h = s.HostConfig as Record<string, unknown>;
  for (const key of Object.keys(h)) if (!ALLOWED_HOST_CONFIG.has(key)) fail(`HostConfig.${key}`);
  if (h.NetworkMode !== policy.network) fail('HostConfig.NetworkMode');
  if (!sameStrings(h.Dns, [policy.sinkholeDns])) fail('HostConfig.Dns');
  for (const key of ['DnsSearch', 'DnsOptions', 'ExtraHosts', 'CapAdd', 'Devices']) {
    if (!emptyList(h[key])) fail(`HostConfig.${key}`);
  }
  for (const key of ['DeviceRequests', 'Binds', 'Mounts', 'VolumesFrom']) {
    if (!emptyList(h[key])) fail(`HostConfig.${key}`);
  }
  if (!sameStrings(h.CapDrop, ['ALL'])) fail('HostConfig.CapDrop');
  if (!sameStrings(h.SecurityOpt, securityOpts(policy.apparmor))) fail('HostConfig.SecurityOpt');
  if (h.ReadonlyRootfs !== true) fail('HostConfig.ReadonlyRootfs');
  if (h.Privileged !== false) fail('HostConfig.Privileged');
  if (h.IpcMode !== 'private') fail('HostConfig.IpcMode');
  for (const key of ['PidMode', 'UTSMode', 'UsernsMode']) {
    if (h[key] !== '') fail(`HostConfig.${key}`);
  }
  if (!emptyMap(h.PortBindings)) fail('HostConfig.PortBindings');
  if (h.PublishAllPorts !== false) fail('HostConfig.PublishAllPorts');
  if (h.OomKillDisable !== false) fail('HostConfig.OomKillDisable');
  if (h.Init !== true) fail('HostConfig.Init');
  if (h.AutoRemove !== false) fail('HostConfig.AutoRemove');
  if (!isRecord(h.RestartPolicy) || h.RestartPolicy.Name !== 'no') fail('HostConfig.RestartPolicy');
  if (!isRecord(h.LogConfig) || h.LogConfig.Type !== 'none') fail('HostConfig.LogConfig');

  const positiveInt = (value: unknown) => Number.isSafeInteger(value) && (value as number) > 0;
  if (!positiveInt(h.Memory)) fail('HostConfig.Memory');
  if (h.MemorySwap !== h.Memory) fail('HostConfig.MemorySwap');
  if (!positiveInt(h.NanoCpus)) fail('HostConfig.NanoCpus');
  if (!positiveInt(h.PidsLimit)) fail('HostConfig.PidsLimit');

  const tmpfs = h.Tmpfs;
  if (!isRecord(tmpfs) || !sameStrings(Object.keys(tmpfs).sort(), ['/scratch', '/tmp'])) {
    fail('HostConfig.Tmpfs');
  }
  const t = tmpfs as Record<string, unknown>;
  const scratch = t['/scratch'];
  const size = typeof scratch === 'string' ? /size=(\d{1,5})m/.exec(scratch)?.[1] : undefined;
  if (size === undefined || scratch !== scratchTmpfs(Number(size), user) || Number(size) < 1) {
    fail('HostConfig.Tmpfs./scratch');
  }
  if (t['/tmp'] !== TMP_TMPFS) fail('HostConfig.Tmpfs./tmp');

  const nofile = nofileLimit(profile);
  const ulimits = h.Ulimits;
  if (
    !Array.isArray(ulimits) ||
    ulimits.length !== 2 ||
    !ulimits.some(
      (u: unknown) => isRecord(u) && u.Name === 'nofile' && u.Soft === nofile && u.Hard === nofile,
    ) ||
    !ulimits.some((u: unknown) => isRecord(u) && u.Name === 'core' && u.Soft === 0 && u.Hard === 0)
  ) {
    fail('HostConfig.Ulimits');
  }
}

export interface VerifyExpectations {
  policy: RunnerPolicy;
  spec: RunnerContainerSpec;
}

export type VerifyResult = { ok: true } | { ok: false; mismatches: string[] };

/**
 * Re-checks the effective configuration of a created (not yet started) runner against the spec
 * that was sent (X6): image, user, capabilities, privileged, read-only root, no binds / mounts /
 * devices / ports, network exactly the detonation network, resolver the sinkhole only,
 * no-new-privileges present, seccomp not unconfined, AppArmor `docker-default` when the daemon
 * has AppArmor, private IPC, no host PID/UTS/user namespaces, limits and tmpfs as requested, the
 * isolation label. Every mismatch is listed (field names only).
 */
export function verifyCreated(
  inspect: ContainerInspect | null,
  expected: VerifyExpectations,
): VerifyResult {
  const mismatches: string[] = [];
  const check = (ok: boolean, field: string) => {
    if (!ok) mismatches.push(field);
  };
  if (!inspect) return { ok: false, mismatches: ['missing'] };
  const { spec, policy } = expected;
  const config = inspect.Config ?? {};
  const host = inspect.HostConfig ?? {};
  check(inspect.State?.Running !== true && inspect.State?.Status === 'created', 'State');
  check(config.Image === spec.Image, 'Config.Image');
  check(config.User === spec.User && spec.User === runnerUser(policy), 'Config.User');
  check(config.Tty === false, 'Config.Tty');
  check(config.OpenStdin === true && config.StdinOnce === true, 'Config.OpenStdin');
  check(config.NetworkDisabled !== true, 'Config.NetworkDisabled');
  check(emptyMap(config.ExposedPorts), 'Config.ExposedPorts');
  const labels = config.Labels ?? {};
  for (const [key, value] of Object.entries(spec.Labels)) {
    check(labels[key] === value, `Config.Labels.${key}`);
  }
  check(host.Privileged === false, 'HostConfig.Privileged');
  check(emptyList(host.CapAdd), 'HostConfig.CapAdd');
  check(Array.isArray(host.CapDrop) && host.CapDrop.includes('ALL'), 'HostConfig.CapDrop');
  check(host.ReadonlyRootfs === true, 'HostConfig.ReadonlyRootfs');
  check(emptyList(host.Binds), 'HostConfig.Binds');
  check(emptyList(host.Mounts), 'HostConfig.Mounts');
  check(emptyList(inspect.Mounts), 'Mounts');
  check(emptyList(host.Devices), 'HostConfig.Devices');
  check(emptyList(host.DeviceRequests), 'HostConfig.DeviceRequests');
  check(emptyList(host.VolumesFrom), 'HostConfig.VolumesFrom');
  check(emptyMap(host.PortBindings), 'HostConfig.PortBindings');
  check(host.PublishAllPorts !== true, 'HostConfig.PublishAllPorts');
  check(host.NetworkMode === policy.network, 'HostConfig.NetworkMode');
  const networks = Object.keys(inspect.NetworkSettings?.Networks ?? {});
  check(sameStrings(networks, [policy.network]), 'NetworkSettings.Networks');
  check(sameStrings(host.Dns, [policy.sinkholeDns]), 'HostConfig.Dns');
  check(emptyList(host.DnsSearch), 'HostConfig.DnsSearch');
  check(emptyList(host.ExtraHosts), 'HostConfig.ExtraHosts');
  const securityOpt = Array.isArray(host.SecurityOpt) ? (host.SecurityOpt as unknown[]) : [];
  const opts = securityOpt.filter((o): o is string => typeof o === 'string');
  check(
    opts.some((o) => /^no-new-privileges(:true|=true)?$/.test(o)),
    'HostConfig.SecurityOpt.no-new-privileges',
  );
  check(!opts.some((o) => /^seccomp[:=]unconfined$/.test(o)), 'HostConfig.SecurityOpt.seccomp');
  check(
    !opts.some((o) =>
      /^(apparmor[:=]unconfined|label[:=]disable|systempaths[:=]unconfined)$/.test(o),
    ),
    'HostConfig.SecurityOpt.unconfined',
  );
  if (policy.apparmor) {
    check(inspect.AppArmorProfile === 'docker-default', 'AppArmorProfile');
  }
  check(host.IpcMode === 'private', 'HostConfig.IpcMode');
  check(host.PidMode === '' || host.PidMode === undefined, 'HostConfig.PidMode');
  check(host.UTSMode === '' || host.UTSMode === undefined, 'HostConfig.UTSMode');
  check(host.UsernsMode === '' || host.UsernsMode === undefined, 'HostConfig.UsernsMode');
  check(host.CgroupnsMode !== 'host', 'HostConfig.CgroupnsMode');
  check(host.Memory === spec.HostConfig.Memory, 'HostConfig.Memory');
  check(host.MemorySwap === spec.HostConfig.MemorySwap, 'HostConfig.MemorySwap');
  check(host.NanoCpus === spec.HostConfig.NanoCpus, 'HostConfig.NanoCpus');
  check(host.PidsLimit === spec.HostConfig.PidsLimit, 'HostConfig.PidsLimit');
  check(host.OomKillDisable !== true, 'HostConfig.OomKillDisable');
  check(host.Init === true, 'HostConfig.Init');
  check(host.AutoRemove !== true, 'HostConfig.AutoRemove');
  const tmpfs = isRecord(host.Tmpfs) ? host.Tmpfs : {};
  check(
    tmpfs['/scratch'] === spec.HostConfig.Tmpfs['/scratch'] &&
      tmpfs['/tmp'] === spec.HostConfig.Tmpfs['/tmp'] &&
      Object.keys(tmpfs).length === 2,
    'HostConfig.Tmpfs',
  );
  if (Array.isArray(host.MaskedPaths)) {
    check(host.MaskedPaths.length > 0, 'HostConfig.MaskedPaths');
  }
  return mismatches.length === 0 ? { ok: true } : { ok: false, mismatches };
}

/** True when `/info` SecurityOptions report AppArmor. */
export function daemonHasAppArmor(securityOptions: readonly string[] | null | undefined): boolean {
  return (securityOptions ?? []).some((o) => /(^|,)name=apparmor(,|$)/.test(o));
}

/** True when `/info` SecurityOptions report a seccomp profile. */
export function daemonHasSeccomp(securityOptions: readonly string[] | null | undefined): boolean {
  return (securityOptions ?? []).some((o) => /(^|,)name=seccomp(,|$)/.test(o));
}
