import type { AdvisoryLocks } from '@email-gateway/common';
import type { Logger } from '@email-gateway/logger';
import type { DeliveryApprovalConsumer } from './approvals/delivery-approval.consumer';
import type { DeliveryReconciler } from './reconciler/delivery-reconciler';
import type { ReinjectionScheduler } from './reinjection/reinjection-scheduler';
import type { PostfixLogTailer } from './status/postfix-log-tailer';

export interface WorkerRoles {
  DELIVERY_APPROVALS_ENABLED: boolean;
  DELIVERY_REINJECTION_ENABLED: boolean;
  DELIVERY_STATUS_LOG_ENABLED: boolean;
}

export interface WorkerComponents {
  approvals: DeliveryApprovalConsumer;
  scheduler: ReinjectionScheduler;
  tailer: PostfixLogTailer;
  reconciler: DeliveryReconciler;
  locks: AdvisoryLocks;
}

type Role = 'approvals' | 'reinjection' | 'status_log' | 'reconciler';

/**
 * Starts the background loops of the enabled roles (after the application bootstrapped, so the
 * database and Redis clients are connected) and stops them before the clients close:
 * consumers first (no new work), then the scheduler (in-flight sessions get the shutdown grace,
 * leases are released), then the tailer and the reconciler, then the lock connection.
 *
 * Roles: approvals (planner of the policy-engine's and the release's approvals; the development
 * pass-through was removed by step 5.2), reinjection (scheduler and reconciler), status log
 * (tailer). The production log sidecar runs only the status log role.
 */
export class WorkerLifecycle {
  private readonly started = new Set<Role>();

  constructor(
    private readonly components: WorkerComponents,
    private readonly roles: WorkerRoles,
    private readonly logger: Logger,
  ) {}

  get startedRoles(): Role[] {
    return [...this.started];
  }

  start(): void {
    const c = this.components;
    if (this.roles.DELIVERY_APPROVALS_ENABLED) {
      c.approvals.start();
      this.started.add('approvals');
    }
    if (this.roles.DELIVERY_REINJECTION_ENABLED) {
      c.scheduler.start();
      c.reconciler.start();
      this.started.add('reinjection');
      this.started.add('reconciler');
    }
    if (this.roles.DELIVERY_STATUS_LOG_ENABLED) {
      c.tailer.start();
      this.started.add('status_log');
    }
    this.logger.info({ roles: this.startedRoles }, 'delivery-worker roles started');
  }

  async stop(): Promise<void> {
    const c = this.components;
    const step = async (role: Role, fn: () => Promise<void>): Promise<void> => {
      if (!this.started.delete(role)) return;
      try {
        await fn();
      } catch (err) {
        this.logger.warn({ err, role }, 'role did not stop cleanly');
      }
    };
    await step('approvals', () => c.approvals.stop());
    await step('reinjection', () => c.scheduler.stop());
    await step('status_log', () => c.tailer.stop());
    await step('reconciler', () => c.reconciler.stop());
    await c.locks
      .close()
      .catch((err: unknown) => this.logger.warn({ err }, 'lock connection close failed'));
  }
}
