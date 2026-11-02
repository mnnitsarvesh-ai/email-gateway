import { SetMetadata } from '@nestjs/common';

/** Metadata key read by the API's authentication guard. */
export const IS_PUBLIC_KEY = 'auth:isPublic';

/**
 * Marks a route or controller as reachable without credentials. Services without an
 * authentication guard ignore it; in `api` every route that lacks it requires a principal.
 */
export const Public = (): MethodDecorator & ClassDecorator => SetMetadata(IS_PUBLIC_KEY, true);
