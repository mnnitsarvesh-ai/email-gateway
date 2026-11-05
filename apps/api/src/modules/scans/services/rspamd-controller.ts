import { Inject, Injectable } from '@nestjs/common';
import { RspamdClient } from '@email-gateway/rspamd';
import { API_CONFIG } from '../../../api-config.token';
import type { ApiConfig } from '../../../config';

/** Upper bound of one controller call (learning streams a whole message). */
export const RSPAMD_CONTROLLER_TIMEOUT_MS = 30_000;
/** Concurrent controller calls of this api instance (the route is also rate limited). */
export const RSPAMD_CONTROLLER_MAX_IN_FLIGHT = 4;

type ControllerConfig = Pick<
  ApiConfig,
  'RSPAMD_CONTROLLER_URL' | 'RSPAMD_CONTROLLER_ENABLE_PASSWORD' | 'SCAN_FUZZY_WEIGHT'
>;

/**
 * The Rspamd controller client of the platform training route (step 4.1 S13, S18): learning and
 * fuzzy operations with the enable password, which the api alone holds. Rspamd accepts the
 * enable password for `/stat` too, so the version is read with it. `client` is null when the
 * controller URL or the enable password is not configured (the route then answers 503).
 */
@Injectable()
export class RspamdController {
  readonly client: RspamdClient | null;
  readonly fuzzyWeight: number;

  constructor(@Inject(API_CONFIG) config: ControllerConfig) {
    const url = config.RSPAMD_CONTROLLER_URL;
    const password = config.RSPAMD_CONTROLLER_ENABLE_PASSWORD;
    this.fuzzyWeight = config.SCAN_FUZZY_WEIGHT;
    this.client =
      url && password
        ? new RspamdClient({
            // The normal worker is never called by the api; the controller URL stands in.
            baseUrl: url,
            controllerUrl: url,
            controllerPassword: password,
            controllerEnablePassword: password,
            timeoutMs: RSPAMD_CONTROLLER_TIMEOUT_MS,
            maxInFlight: RSPAMD_CONTROLLER_MAX_IN_FLIGHT,
          })
        : null;
  }
}
