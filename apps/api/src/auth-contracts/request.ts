import type { Request } from 'express';
import type { Principal } from './principal';
import type { TenantScope } from './tenant-scope';

/** Set by the authentication guard (WP3) on every non-public route. */
export type AuthenticatedRequest = Request & { principal?: Principal; tenantScope?: TenantScope };
