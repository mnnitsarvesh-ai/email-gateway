import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Logger } from '@email-gateway/logger';
import { type ControllerConfig, TEST_ENVIRONMENTS } from '../config';
import {
  HardenedContainerBackend,
  type HardenedContainerBackendOptions,
} from '../runner/hardened-container.backend';
import type { SinkholeTransport } from '../runner/sinkhole-client';
import type { ScratchArea } from '../scratch/scratch';
import { BackendRefusedError, type SandboxBackend } from './backend';
import { withStaticAnalysis } from './composite';
import { DisabledBackend } from './disabled.backend';
import { AnalyzerChildRunner } from './static/child-runner';
import { StaticBackend } from './static/static.backend';
import { InClusterKubernetesClient, type KubernetesClient } from './vm/k8s-client';
import { VmBackend } from './vm/vm.backend';

/**
 * Builds the configured isolation backend (step 4.6 X3): `disabled`, `static` (the static
 * analyzer through `withStaticAnalysis(…, null)`), `hardened-container` (the static analyzer
 * first, then WP4's disposable runner: `withStaticAnalysis(static, runner)`) and `vm` (preflight
 * contract that always refuses; its runner is not implemented).
 *
 * `hardened-container` is a LOCAL/CI TEST HARNESS and NOT A VM BOUNDARY (shared kernel). The
 * configuration has already refused it outside APP_ENV local/ci, inside Kubernetes and without
 * `SANDBOX_ALLOW_NON_VM_EXECUTION=true`; the factory re-checks the same three conditions (defence
 * in depth, refusal codes `execution_not_allowed_in_environment`, `execution_refused_in_kubernetes`,
 * `non_vm_execution_not_opted_in`) and the sinkhole token (`sinkhole_token_missing`).
 *
 * The runner backend gets no metric callbacks: the task handler and the reaper already count its
 * cleanup failures, reaped runners and limit hits from the observation and the reap report
 * (passing them again would double-count `sandbox_cleanup_failures_total` / `sandbox_reaped_total`).
 */

export type FactoryConfig = Pick<
  ControllerConfig,
  | 'SANDBOX_BACKEND'
  | 'SANDBOX_STATIC_HEAP_MB'
  | 'SANDBOX_STATIC_MAX_RSS_MB'
  | 'SANDBOX_STATIC_CPU_SECONDS'
  | 'SANDBOX_STATIC_TIMEOUT_MS'
  | 'SANDBOX_VM_RUNTIME_CLASS'
  | 'SANDBOX_VM_ALLOWED_HANDLERS'
  | 'SANDBOX_VM_NAMESPACE'
  | 'KUBERNETES_SERVICE_HOST'
  | 'KUBERNETES_SERVICE_PORT'
  | 'APP_ENV'
  | 'SANDBOX_ALLOW_NON_VM_EXECUTION'
  | 'SANDBOX_CONTROLLER_NAME'
  | 'SANDBOX_DOCKER_SOCKET'
  | 'SANDBOX_RUNNER_IMAGE'
  | 'SANDBOX_BROWSER_IMAGE'
  | 'SANDBOX_RUNNER_NETWORK'
  | 'SANDBOX_SINKHOLE_DNS'
  | 'SANDBOX_SINKHOLE_ADMIN_URL'
  | 'SANDBOX_SINKHOLE_ADMIN_TOKEN'
>;

export interface FactoryDeps {
  scratch: ScratchArea;
  logger: Logger;
  /** Overrides (tests): the compiled analyzer child, a fake Kubernetes client. */
  analyzerChildEntry?: string;
  kubernetes?: KubernetesClient;
  /** Unit tests only: lets the analyzer child honour selftest probes. */
  analyzerSelftest?: boolean;
  /**
   * Tests only (hardened-container): a fake Docker API, and a relay for the sinkhole admin API
   * (host-run tests cannot route to the internal `sandbox-control` network). Production passes
   * neither: the backend talks to `SANDBOX_DOCKER_SOCKET` and `SANDBOX_SINKHOLE_ADMIN_URL`.
   */
  docker?: HardenedContainerBackendOptions['docker'];
  sinkholeTransport?: SinkholeTransport;
}

/**
 * The compiled analyzer child: next to this module in `dist/` (production), else the app's
 * `dist/` (source runs of the tests: `pnpm --filter @email-gateway/sandbox-controller build`
 * first).
 */
export function resolveAnalyzerChildEntry(): string {
  const sibling = join(__dirname, 'static', 'analyzer-child.js');
  if (existsSync(sibling)) return sibling;
  return resolve(__dirname, '..', '..', 'dist', 'backends', 'static', 'analyzer-child.js');
}

export function createStaticBackend(config: FactoryConfig, deps: FactoryDeps): StaticBackend {
  const entry = deps.analyzerChildEntry ?? resolveAnalyzerChildEntry();
  if (!existsSync(entry)) throw new BackendRefusedError('analyzer_child_missing');
  const runner = new AnalyzerChildRunner({
    entry,
    heapMb: config.SANDBOX_STATIC_HEAP_MB,
    maxRssMb: config.SANDBOX_STATIC_MAX_RSS_MB,
    cpuSeconds: config.SANDBOX_STATIC_CPU_SECONDS,
    timeoutMs: config.SANDBOX_STATIC_TIMEOUT_MS,
    ...(deps.analyzerSelftest ? { selftest: true } : {}),
  });
  return new StaticBackend({ runner, scratch: deps.scratch, logger: deps.logger });
}

export function createBackend(config: FactoryConfig, deps: FactoryDeps): SandboxBackend {
  switch (config.SANDBOX_BACKEND) {
    case 'disabled':
      return new DisabledBackend();
    case 'static':
      return withStaticAnalysis(createStaticBackend(config, deps), null);
    case 'vm':
      return new VmBackend({
        client:
          deps.kubernetes ??
          new InClusterKubernetesClient({
            host: config.KUBERNETES_SERVICE_HOST,
            port: config.KUBERNETES_SERVICE_PORT,
          }),
        runtimeClass: config.SANDBOX_VM_RUNTIME_CLASS,
        allowedHandlers: config.SANDBOX_VM_ALLOWED_HANDLERS,
        namespace: config.SANDBOX_VM_NAMESPACE,
      });
    case 'hardened-container':
      return withStaticAnalysis(
        createStaticBackend(config, deps),
        createHardenedContainerBackend(config, deps),
      );
  }
}

/**
 * The local/CI runner (X6), NOT A VM BOUNDARY. Re-checks the configuration's refusals before
 * anything touches the Docker socket.
 */
export function createHardenedContainerBackend(
  config: FactoryConfig,
  deps: FactoryDeps,
): HardenedContainerBackend {
  if (!TEST_ENVIRONMENTS.includes(config.APP_ENV)) {
    throw new BackendRefusedError('execution_not_allowed_in_environment');
  }
  if (config.KUBERNETES_SERVICE_HOST) {
    throw new BackendRefusedError('execution_refused_in_kubernetes');
  }
  if (!config.SANDBOX_ALLOW_NON_VM_EXECUTION) {
    throw new BackendRefusedError('non_vm_execution_not_opted_in');
  }
  const token = config.SANDBOX_SINKHOLE_ADMIN_TOKEN;
  if (!token) throw new BackendRefusedError('sinkhole_token_missing');
  return new HardenedContainerBackend({
    socketPath: config.SANDBOX_DOCKER_SOCKET,
    images: { runner: config.SANDBOX_RUNNER_IMAGE, browser: config.SANDBOX_BROWSER_IMAGE },
    network: config.SANDBOX_RUNNER_NETWORK,
    sinkhole: {
      dns: config.SANDBOX_SINKHOLE_DNS,
      adminUrl: config.SANDBOX_SINKHOLE_ADMIN_URL,
      token,
      ...(deps.sinkholeTransport ? { transport: deps.sinkholeTransport } : {}),
    },
    controllerName: config.SANDBOX_CONTROLLER_NAME,
    logger: deps.logger,
    ...(deps.docker ? { docker: deps.docker } : {}),
  });
}

/** Backends whose failing self-test refuses the start (X1): the executing ones. */
export function refusesStartOnFailedSelfTest(backend: SandboxBackend): boolean {
  return backend.name === 'vm' || backend.name === 'hardened-container';
}
