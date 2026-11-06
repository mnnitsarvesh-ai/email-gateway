import { startTracing } from '@email-gateway/logger/tracing';

// `/c/<token>` and `/c/<token>/continue?n=<nonce>` are never traced: tokens and nonces must not
// reach span attributes (ADR-0031). The guarded fetcher suppresses tracing on its own (U8).
startTracing('click-service', { untracedIncomingPaths: ['/c/'] });
