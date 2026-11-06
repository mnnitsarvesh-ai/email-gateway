import { type ArgumentsHost, Catch, type ExceptionFilter, HttpException } from '@nestjs/common';
import type { Logger } from '@email-gateway/logger';
import type { Response } from 'express';
import { errorPage, invalidPage } from './pages';

/**
 * Every error of the public listener is a constant HTML page (never JSON, never an error
 * message): an unknown route or method is the generic "link not valid" 404, anything else a 500.
 * The security headers were set by the middleware before routing.
 */
@Catch()
export class PublicExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: Logger) {}

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();
    const status = exception instanceof HttpException ? exception.getStatus() : 500;
    if (status >= 500) {
      this.logger.error(
        { errName: exception instanceof Error ? exception.name : typeof exception },
        'click request failed',
      );
    }
    if (res.headersSent) return;
    if (status === 404 || status === 405) {
      res.status(404).type('text/html; charset=utf-8').send(invalidPage());
      return;
    }
    res
      .status(status >= 400 && status < 500 ? status : 500)
      .type('text/html; charset=utf-8')
      .send(errorPage());
  }
}
