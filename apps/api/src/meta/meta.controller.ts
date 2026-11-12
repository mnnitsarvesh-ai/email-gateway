import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { Public } from '../auth-contracts/decorators';
import { RateLimit } from '../rate-limit/rate-limit.decorator';
import { ApiErrors } from '../modules/auth/api-docs';
import { zodToOpenApi } from '../validation/zod-openapi';
import { type ApiMeta, MetaService } from './meta.service';

/** Documentation of the response (step 6.1 route inventory: every 2xx has a schema). */
const ApiMetaSchema = z.strictObject({
  service: z.literal('email-gateway-api'),
  version: z.string(),
  apiVersion: z.literal('v1'),
  environment: z.string(),
});

/** Controllers only translate HTTP to service calls; logic lives in services. */
@ApiTags('meta')
@Public()
@Controller({ path: 'meta', version: '1' })
export class MetaController {
  constructor(private readonly meta: MetaService) {}

  @Get()
  // Step 6.1 D8: public routes keep per-IP limits; the global API limiter covers only
  // authenticated routes.
  @RateLimit({ bucket: 'meta', limit: 120, windowSeconds: 60, by: 'ip' })
  @ApiOperation({
    summary: 'API build and version information',
    description: 'Public, unauthenticated; limited to 120 requests per minute per client IP.',
  })
  @ApiOkResponse({
    description: 'API build and version information',
    schema: zodToOpenApi(ApiMetaSchema),
  })
  @ApiErrors(429)
  get(): ApiMeta {
    return this.meta.describe();
  }
}
