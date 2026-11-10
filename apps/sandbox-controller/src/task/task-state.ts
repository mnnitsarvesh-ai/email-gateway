/**
 * The task state machine of the sandbox-controller (step 4.6 X7): a pure transition table, a
 * tracker that refuses any other transition, and the invariants the unit tests prove over every
 * path of the table:
 *
 * - every path that created scratch or a runner (`running`) passes through `cleaned` before
 *   `published`, `acked` or `transient_failure` (a retry);
 * - `published` precedes `acked` (confirm first), except the in-process duplicate, which is
 *   acked without a second run or a second result;
 * - no state produces a verdict (the controller publishes observations; `sandbox-map/1` runs in
 *   the email-worker), so no path can yield `clean`.
 *
 * Main line: received → validated → admitted → (not_executed | fetching) → running → collected →
 * cleaned → stored → published → acked. Side exits: `rejected` (schema/tenant → dead-letter),
 * `transient_failure` (S3/broker/backend outage → retry with hold, no result), `failed` (budget
 * exhausted or a non-retryable failure → a `failed` result is published), `deadline_passed`
 * (→ a `not_executed` result), `duplicate` (already in flight in this process → acked).
 */

export const TASK_STATES = [
  'received',
  'validated',
  'admitted',
  'not_executed',
  'fetching',
  'running',
  'collected',
  'cleaned',
  'stored',
  'published',
  'acked',
  'rejected',
  'transient_failure',
  'failed',
  'deadline_passed',
  'duplicate',
] as const;
export type TaskState = (typeof TASK_STATES)[number];

export const TASK_TRANSITIONS: Readonly<Record<TaskState, readonly TaskState[]>> = Object.freeze({
  received: ['validated', 'rejected', 'duplicate'],
  validated: ['admitted', 'deadline_passed'],
  admitted: ['not_executed', 'fetching'],
  // Before the scratch exists: the sample is unavailable / not authentic (failed result) or the
  // bucket is down (retry). `running` creates the scratch directory.
  fetching: ['running', 'failed', 'transient_failure'],
  running: ['collected'],
  // Whatever the backend did (observation, failure, throw), its outcome is collected and the
  // runner and scratch are removed before anything else happens.
  collected: ['cleaned'],
  cleaned: ['stored', 'failed', 'transient_failure'],
  stored: ['published', 'transient_failure', 'failed'],
  not_executed: ['published', 'transient_failure'],
  deadline_passed: ['published', 'transient_failure'],
  failed: ['published', 'transient_failure'],
  published: ['acked'],
  duplicate: ['acked'],
  acked: [],
  rejected: [],
  transient_failure: [],
});

export const TERMINAL_STATES: readonly TaskState[] = ['acked', 'rejected', 'transient_failure'];

export class InvalidTransitionError extends Error {
  override readonly name = 'InvalidTransitionError';
  constructor(
    readonly from: TaskState,
    readonly to: TaskState,
  ) {
    super(`invalid task transition ${from} → ${to}`);
  }
}

export function canTransition(from: TaskState, to: TaskState): boolean {
  return TASK_TRANSITIONS[from].includes(to);
}

/** Records the path of one task; throws on a transition the table does not allow. */
export class TaskStateTracker {
  private readonly path: TaskState[] = ['received'];

  get state(): TaskState {
    return this.path[this.path.length - 1] as TaskState;
  }

  get history(): readonly TaskState[] {
    return this.path;
  }

  /** True once the task created scratch / a runner (it entered `running`). */
  get createdResources(): boolean {
    return this.path.includes('running');
  }

  to(next: TaskState): void {
    if (!canTransition(this.state, next)) throw new InvalidTransitionError(this.state, next);
    this.path.push(next);
  }

  /** Is the task in `state` now? */
  is(state: TaskState): boolean {
    return this.state === state;
  }
}

/** Every path of the table from `received` to a terminal state (the table is acyclic). */
export function allPaths(): TaskState[][] {
  const out: TaskState[][] = [];
  const walk = (path: TaskState[]): void => {
    const last = path[path.length - 1] as TaskState;
    const next = TASK_TRANSITIONS[last];
    if (next.length === 0) {
      out.push(path);
      return;
    }
    for (const state of next) walk([...path, state]);
  };
  walk(['received']);
  return out;
}

/** The invariant violations of one path (empty when it is valid). */
export function pathViolations(path: readonly TaskState[]): string[] {
  const violations: string[] = [];
  const running = path.indexOf('running');
  const cleaned = path.indexOf('cleaned');
  if (running >= 0) {
    for (const exit of ['published', 'acked', 'transient_failure'] as const) {
      const at = path.indexOf(exit);
      if (at >= 0 && (cleaned < 0 || cleaned > at)) violations.push(`${exit} before cleaned`);
    }
  }
  const acked = path.indexOf('acked');
  if (acked >= 0) {
    const published = path.indexOf('published');
    const duplicate = path.indexOf('duplicate');
    if (!((published >= 0 && published < acked) || (duplicate >= 0 && duplicate < acked))) {
      violations.push('acked without a confirmed publish');
    }
    if (duplicate >= 0 && path.includes('running')) violations.push('duplicate ran the backend');
  }
  return violations;
}
