import {
  type BackendObservation,
  BackendRefusedError,
  type BackendSelfTest,
  type ReapReport,
  type SandboxBackend,
} from '../backend';
import type { KubernetesClient } from './k8s-client';

/**
 * The `vm` backend contract (step 4.6 X9; ADR-0039 decision 2; threat model §8): preflight only.
 * Its runner (self-test pod, runner pods, out-of-guest collection) is NOT implemented in 4.6, so
 * the self-test always ends in a refusal and the controller refuses to start with this backend:
 *
 * 1. Kubernetes detected (`KUBERNETES_SERVICE_HOST` + the service-account token) else
 *    `not_in_kubernetes`;
 * 2. `GET /apis/node.k8s.io/v1/runtimeclasses/<SANDBOX_VM_RUNTIME_CLASS>`: 404 →
 *    `runtime_class_missing`, 401/403 → `rbac_denied`, other failure → `preflight_failed`;
 * 3. its `handler` ∈ `SANDBOX_VM_ALLOWED_HANDLERS` else `handler_not_allowed`;
 * 4. then always `vm_runner_not_implemented`.
 *
 * The refusal is the specified behaviour of this step, not a stand-in for a runner: `supports()`
 * answers `profile_not_supported` and `run()` throws `BackendRefusedError`.
 */

export interface VmBackendOptions {
  client: KubernetesClient;
  runtimeClass: string;
  allowedHandlers: readonly string[];
  namespace: string;
}

export class VmBackend implements SandboxBackend {
  readonly name = 'vm' as const;
  readonly isolation = 'vm' as const;
  readonly version = 'vm/0-preflight';
  /** It would execute samples — which is why it refuses until a proven runner exists. */
  readonly executes = true;

  constructor(private readonly options: VmBackendOptions) {}

  async selfTest(signal: AbortSignal): Promise<BackendSelfTest> {
    const details: Record<string, string | number | boolean> = {
      runtimeClass: this.options.runtimeClass,
      namespace: this.options.namespace,
      runnerImplemented: false,
    };
    if (!(await this.options.client.inCluster())) {
      return { ok: false, code: 'not_in_kubernetes', details: { ...details, inCluster: false } };
    }
    details.inCluster = true;
    let response;
    try {
      response = await this.options.client.get(
        `/apis/node.k8s.io/v1/runtimeclasses/${encodeURIComponent(this.options.runtimeClass)}`,
        signal,
      );
    } catch {
      return {
        ok: false,
        code: 'preflight_failed',
        details: { ...details, step: 'runtime_class' },
      };
    }
    details.httpStatus = response.status;
    if (response.status === 404) return { ok: false, code: 'runtime_class_missing', details };
    if (response.status === 401 || response.status === 403)
      return { ok: false, code: 'rbac_denied', details };
    if (response.status !== 200) return { ok: false, code: 'preflight_failed', details };
    const handler = (response.body as { handler?: unknown } | null)?.handler;
    if (typeof handler !== 'string' || !/^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/.test(handler)) {
      return {
        ok: false,
        code: 'handler_not_allowed',
        details: { ...details, handler: 'invalid' },
      };
    }
    details.handler = handler;
    if (!this.options.allowedHandlers.includes(handler)) {
      return { ok: false, code: 'handler_not_allowed', details };
    }
    // Every proof this step can make passed; the self-test pod and the runner do not exist.
    return { ok: false, code: 'vm_runner_not_implemented', details };
  }

  supports(): { ok: false; reason: 'profile_not_supported' } {
    return { ok: false, reason: 'profile_not_supported' };
  }

  run(): Promise<BackendObservation> {
    return Promise.reject(new BackendRefusedError('vm_runner_not_implemented'));
  }

  reap(): Promise<ReapReport> {
    return Promise.resolve({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 });
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}
