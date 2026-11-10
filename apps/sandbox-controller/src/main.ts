import { bootstrapService } from '@email-gateway/common';
import { ConfigValidationError } from '@email-gateway/config';
import { createLogger } from '@email-gateway/logger';
import { AppModule, SERVICE_NAME } from './app.module';
import { BackendRefusedError, type BackendSelfTest } from './backends/backend';
import { createBackend, refusesStartOnFailedSelfTest } from './backends/factory';
import { loadControllerConfig } from './config';
import { boundaryOf } from './health/backend-health';
import { ScratchArea } from './scratch/scratch';

/**
 * Startup order of the sandbox-controller (step 4.6 X1):
 *
 * 1. configuration: forbidden keys and every bound / backend rule (exit 1, keys named only);
 * 2. the backend (factory; a refused backend exits 1: `sandbox backend refused: <code>`);
 * 3. `backend.selfTest()`: a failing self-test of `vm` or `hardened-container` refuses to start
 *    (exit 1); `disabled` and `static` start and report readiness (a failing `static` self-test
 *    keeps the consumer paused);
 * 4. Nest: the reaper's startup pass, then the consumer (ControllerLifecycle).
 */
async function main(): Promise<void> {
  let config;
  try {
    config = loadControllerConfig();
  } catch (error) {
    const fallback = createLogger({ service: SERVICE_NAME });
    if (error instanceof ConfigValidationError) {
      // Issues name keys and rules, never values.
      fallback.fatal({ issues: error.issues }, 'sandbox-controller configuration refused');
    } else {
      fallback.fatal(
        { errName: (error as Error)?.name },
        'sandbox-controller configuration failed',
      );
    }
    process.exit(1);
  }
  const logger = createLogger({
    service: SERVICE_NAME,
    level: config.LOG_LEVEL,
    version: config.SERVICE_VERSION,
  });

  const scratch = new ScratchArea(config.SANDBOX_SCRATCH_DIR);
  try {
    await scratch.init();
  } catch {
    logger.fatal({ refusal: 'scratch_unavailable' }, 'sandbox scratch directory unusable');
    process.exit(1);
  }

  let backend;
  try {
    backend = createBackend(config, { scratch, logger });
  } catch (error) {
    const code = error instanceof BackendRefusedError ? error.code : 'backend_construction_failed';
    logger.fatal(
      { backend: config.SANDBOX_BACKEND, refusal: code },
      `sandbox backend refused: ${code}`,
    );
    process.exit(1);
  }

  let selfTest: BackendSelfTest;
  try {
    selfTest = await backend.selfTest(AbortSignal.timeout(60_000));
  } catch {
    selfTest = { ok: false, code: 'self_test_failed', details: {} };
  }
  if (!selfTest.ok && refusesStartOnFailedSelfTest(backend)) {
    logger.fatal(
      {
        backend: backend.name,
        isolation: backend.isolation,
        refusal: selfTest.code,
        details: selfTest.details,
      },
      `sandbox backend refused: ${selfTest.code}`,
    );
    await backend.close().catch(() => undefined);
    process.exit(1);
  }
  logger.info(
    {
      backend: backend.name,
      backendVersion: backend.version,
      isolation: backend.isolation,
      executes: backend.executes,
      boundary: boundaryOf(backend.isolation),
      selfTest: selfTest.code,
    },
    backend.isolation === 'container'
      ? 'sandbox backend ready: hardened container, NOT a VM boundary (local/CI test harness)'
      : selfTest.ok
        ? 'sandbox backend ready'
        : 'sandbox backend not ready; the consumer stays paused until its self-test passes',
  );

  await bootstrapService({
    name: SERVICE_NAME,
    version: config.SERVICE_VERSION,
    logLevel: config.LOG_LEVEL,
    rootModule: AppModule.forRoot(config, { backend, scratch, selfTest }),
    port: config.SANDBOX_HTTP_PORT,
    host: config.HTTP_HOST,
  });
}

void main();
