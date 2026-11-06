import { Controller, Get, Inject, Param, Query, Req, Res, VERSION_NEUTRAL } from '@nestjs/common';
import type { Request, Response } from 'express';
import { ClickService, type ClickResponse } from '../click/click.service';
import { STYLESHEET, STYLESHEET_PATH } from './pages';

/**
 * The only public routes of the click-service (U14): `GET /c/:token`, `GET /c/:token/continue`
 * and the stylesheet. No business logic here: the service decides, this sends.
 */
@Controller({ version: VERSION_NEUTRAL })
export class ClickController {
  constructor(@Inject(ClickService) private readonly clicks: ClickService) {}

  @Get('c/:token')
  async click(
    @Param('token') token: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    send(res, await this.clicks.handle({ token, clientIp: req.ip }));
  }

  @Get('c/:token/continue')
  async continue(
    @Param('token') token: string,
    @Query('n') nonce: unknown,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    send(
      res,
      await this.clicks.handle({
        token,
        clientIp: req.ip,
        nonce: typeof nonce === 'string' ? nonce : '',
      }),
    );
  }

  @Get(STYLESHEET_PATH.slice(1))
  stylesheet(@Res() res: Response): void {
    res.status(200).type('text/css; charset=utf-8').send(STYLESHEET);
  }
}

function send(res: Response, response: ClickResponse): void {
  if (response.kind === 'redirect') {
    res.status(302).setHeader('Location', response.location);
    res.end();
    return;
  }
  res.status(response.status).type('text/html; charset=utf-8').send(response.html);
}
