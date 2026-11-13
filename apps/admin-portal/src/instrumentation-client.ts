/**
 * Runs in the browser before any application module (Next.js `instrumentation-client`). Zod
 * must be configured before the first schema is constructed: page modules build their schemas
 * at import time, before the root layout's providers are evaluated (src/lib/zod-config.ts).
 */
import '@/lib/zod-config';
