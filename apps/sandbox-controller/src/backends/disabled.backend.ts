import { emptySandboxObservations } from '@email-gateway/security-contracts';
import type {
  BackendObservation,
  BackendSelfTest,
  ReapReport,
  SandboxBackend,
  SandboxTaskInput,
} from './backend';

/**
 * The `disabled` backend (step 4.6 X3; the default in every environment): nothing is read,
 * written or run. Every task is answered `not_executed` / `backend_disabled` with empty
 * observations and no artifacts — never `clean` (`sandbox-map/1` rule N1 → `unknown`).
 * `supports()` already refuses, so the task handler never fetches the sample or creates scratch.
 */
export class DisabledBackend implements SandboxBackend {
  readonly name = 'disabled' as const;
  readonly isolation = 'none' as const;
  readonly version = 'disabled/1';
  readonly executes = false;

  selfTest(): Promise<BackendSelfTest> {
    return Promise.resolve({ ok: true, code: 'ok', details: { execution: false } });
  }

  supports(): { ok: false; reason: 'backend_disabled' } {
    return { ok: false, reason: 'backend_disabled' };
  }

  run(_task: SandboxTaskInput): Promise<BackendObservation> {
    return Promise.resolve(disabledObservation());
  }

  reap(): Promise<ReapReport> {
    return Promise.resolve({ runnersRemoved: 0, scratchRemoved: 0, failures: 0 });
  }

  close(): Promise<void> {
    return Promise.resolve();
  }
}

export function disabledObservation(): BackendObservation {
  return {
    status: 'not_executed',
    executed: false,
    notExecutedReason: 'backend_disabled',
    errorCode: null,
    observations: emptySandboxObservations(),
    artifacts: [],
    analyzerVersion: null,
    cleanup: { runnerRemoved: null, scratchRemoved: true },
  };
}
