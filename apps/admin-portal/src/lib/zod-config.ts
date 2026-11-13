import { z } from 'zod';

/**
 * Zod 4 probes `new Function('')` once to decide whether it may compile object parsers (its JIT
 * fast path). Under the portal's CSP (`script-src` without `'unsafe-eval'`, design P10) the probe
 * is refused and the browser reports a `securitypolicyviolation` on every page that parses an
 * object schema. `jitless` turns the probe and the JIT off; parsing results are identical.
 * Imported first by the client providers (step 7.1 WP6; found by the e2e CSP check).
 */
z.config({ jitless: true });

export const ZOD_JITLESS = true;
