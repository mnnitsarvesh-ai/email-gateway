import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { type ApiMeta, MetaService } from './meta.service';

/** Controllers only translate HTTP to service calls; logic lives in services. */
@ApiTags('meta')
@Controller({ path: 'meta', version: '1' })
export class MetaController {
  constructor(private readonly meta: MetaService) {}

  @Get()
  @ApiOkResponse({ description: 'API build and version information' })
  get(): ApiMeta {
    return this.meta.describe();
  }
}
