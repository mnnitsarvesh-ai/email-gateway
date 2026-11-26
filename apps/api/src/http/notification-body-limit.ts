import type { INestApplication } from '@nestjs/common';
import express, { type NextFunction, type Request, type Response } from 'express';
import {
  NOTIFICATION_BODY_LIMIT_BYTES,
  NOTIFICATION_ROUTES,
} from '../modules/api-mode/api-mode.constants';

/**
 * Step API-1 D12.4: the route-level JSON body limit of the public Graph notification callbacks
 * (256 KiB: Graph batches up to 1 000 small items). Registered on the Express instance before
 * Nest's global 100 KiB parser (at init), which skips a body that was already read; a larger body
 * is answered `413 payload_too_large`. The function is named so Nest's "already applied" check
 * (`layer.handle.name === 'jsonParser'`) does not mistake it for the global parser.
 */
export function useNotificationBodyLimit(app: INestApplication): void {
  const parser = express.json({ limit: NOTIFICATION_BODY_LIMIT_BYTES });
  const notificationJsonBody = (req: Request, res: Response, next: NextFunction): void =>
    parser(req, res, next);
  app.use([NOTIFICATION_ROUTES.graph, NOTIFICATION_ROUTES.lifecycle], notificationJsonBody);
}
