import type {
  AttachOutput,
  AttachStream,
  ContainerInspect,
  ContainerSummary,
  DockerApi,
  DockerInfo,
  DockerVersion,
  ImageInspect,
  NetworkInspect,
  WaitResult,
} from './docker-client';
import type { RunnerContainerSpec } from './hardened-spec';

/**
 * An in-memory Docker Engine for the hardened-container backend's unit tests (no daemon). A
 * started container "runs" `behavior(spec, stdin)`; `wait` resolves after its delay or a kill.
 */

export interface Behavior {
  stdout?: Buffer;
  exitCode?: number;
  oomKilled?: boolean;
  /** ms until the runner exits by itself (default 5). */
  delayMs?: number;
  /** Never exits by itself (only a kill ends it). */
  hang?: boolean;
}

interface FakeContainer {
  id: string;
  name: string;
  spec: RunnerContainerSpec;
  state: 'created' | 'running' | 'exited';
  exitCode: number;
  oomKilled: boolean;
  ip: string;
  stdin: Buffer[];
  output: Buffer;
  exited: Promise<void>;
  exit: () => void;
  timer?: NodeJS.Timeout;
}

let counter = 0;

export class FakeDocker implements DockerApi {
  readonly containers = new Map<string, FakeContainer>();
  readonly calls: string[] = [];
  behavior: (spec: RunnerContainerSpec, stdin: Buffer) => Behavior = () => ({});
  /** Extra containers the list endpoint returns (orphans). */
  orphans: ContainerSummary[] = [];
  removedOrphans: string[] = [];
  pingError: Error | null = null;
  createError: Error | null = null;
  startError: Error | null = null;
  removeErrors = 0;
  image: ImageInspect | null = { Id: 'sha256:' + 'f'.repeat(64) };
  network: NetworkInspect | null = {
    Id: 'n',
    Name: 'email-gateway_sandbox-detonation',
    Internal: true,
    Options: { 'com.docker.network.bridge.gateway_mode_ipv4': 'isolated' },
  };
  securityOptions = ['name=seccomp,profile=builtin', 'name=cgroupns'];
  inspectPatch: ((inspect: ContainerInspect) => ContainerInspect) | null = null;

  ping(): Promise<void> {
    this.calls.push('ping');
    return this.pingError ? Promise.reject(this.pingError) : Promise.resolve();
  }
  version(): Promise<DockerVersion> {
    return Promise.resolve({ Version: '29.0.0', ApiVersion: '1.56' });
  }
  info(): Promise<DockerInfo> {
    this.calls.push('info');
    return Promise.resolve({ SecurityOptions: this.securityOptions });
  }
  inspectImage(): Promise<ImageInspect | null> {
    return Promise.resolve(this.image);
  }
  inspectNetwork(): Promise<NetworkInspect | null> {
    return Promise.resolve(this.network);
  }
  createContainer(spec: object, name: string): Promise<{ Id: string }> {
    this.calls.push('create');
    if (this.createError) return Promise.reject(this.createError);
    counter += 1;
    const id = counter.toString(16).padStart(64, '0');
    let exit = () => undefined as void;
    const exited = new Promise<void>((resolve) => {
      exit = resolve;
    });
    this.containers.set(id, {
      id,
      name,
      spec: spec as RunnerContainerSpec,
      state: 'created',
      exitCode: 0,
      oomKilled: false,
      ip: `172.31.253.${128 + (counter % 100)}`,
      stdin: [],
      output: Buffer.alloc(0),
      exited,
      exit,
    });
    return Promise.resolve({ Id: id });
  }
  inspectContainer(id: string): Promise<ContainerInspect | null> {
    this.calls.push('inspect');
    const c = this.containers.get(id);
    if (!c) return Promise.resolve(null);
    const network = c.spec.HostConfig.NetworkMode;
    const inspect: ContainerInspect = {
      Id: c.id,
      AppArmorProfile: '',
      Mounts: [],
      State: {
        Status: c.state,
        Running: c.state === 'running',
        OOMKilled: c.oomKilled,
        ExitCode: c.exitCode,
      },
      Config: {
        User: c.spec.User,
        Image: c.spec.Image,
        Tty: false,
        OpenStdin: true,
        StdinOnce: true,
        Labels: { ...c.spec.Labels },
      },
      HostConfig: JSON.parse(JSON.stringify(c.spec.HostConfig)) as Record<string, unknown>,
      NetworkSettings: {
        Networks: { [network]: { IPAddress: c.state === 'running' ? c.ip : '' } },
      },
    };
    return Promise.resolve(this.inspectPatch ? this.inspectPatch(inspect) : inspect);
  }
  startContainer(id: string): Promise<void> {
    this.calls.push('start');
    if (this.startError) return Promise.reject(this.startError);
    const c = this.containers.get(id)!;
    c.state = 'running';
    return Promise.resolve();
  }
  attachContainer(id: string): Promise<AttachStream> {
    this.calls.push('attach');
    const c = this.containers.get(id)!;
    let ended = false;
    return Promise.resolve({
      write: (data: Buffer) => {
        c.stdin.push(data);
        return Promise.resolve();
      },
      endStdin: () => {
        if (ended) return;
        ended = true;
        const behavior = this.behavior(c.spec, Buffer.concat(c.stdin));
        c.output = behavior.stdout ?? Buffer.alloc(0);
        if (!behavior.hang) {
          c.timer = setTimeout(() => {
            c.exitCode = behavior.exitCode ?? 0;
            c.oomKilled = behavior.oomKilled ?? false;
            c.state = 'exited';
            c.exit();
          }, behavior.delayMs ?? 5);
        }
      },
      collect: async (): Promise<AttachOutput> => {
        await c.exited;
        return {
          stdout: c.output,
          stdoutBytes: c.output.length,
          stdoutTruncated: false,
          stderrBytes: 0,
          framingError: false,
        };
      },
      destroy: () => undefined,
    });
  }
  async waitContainer(id: string, signal?: AbortSignal): Promise<WaitResult> {
    this.calls.push('wait');
    const c = this.containers.get(id)!;
    await new Promise<void>((resolve, reject) => {
      void c.exited.then(resolve);
      signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
    });
    return { StatusCode: c.exitCode };
  }
  killContainer(id: string): Promise<void> {
    this.calls.push('kill');
    const c = this.containers.get(id);
    if (c && c.state !== 'exited') {
      if (c.timer) clearTimeout(c.timer);
      c.exitCode = 137;
      c.state = 'exited';
      c.exit();
    }
    return Promise.resolve();
  }
  removeContainer(id: string): Promise<boolean> {
    this.calls.push('remove');
    if (this.removeErrors > 0) {
      this.removeErrors -= 1;
      return Promise.reject(new Error('remove failed'));
    }
    const orphan = this.orphans.find((o) => o.Id === id);
    if (orphan) {
      this.orphans = this.orphans.filter((o) => o.Id !== id);
      this.removedOrphans.push(id);
      return Promise.resolve(true);
    }
    return Promise.resolve(this.containers.delete(id));
  }
  listContainers(labels: readonly string[]): Promise<ContainerSummary[]> {
    this.calls.push(`list:${labels.join(',')}`);
    const live = [...this.containers.values()].map((c) => ({ Id: c.id, Labels: c.spec.Labels }));
    return Promise.resolve([...live, ...this.orphans]);
  }
}
