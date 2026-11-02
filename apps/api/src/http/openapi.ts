import type { INestApplication } from '@nestjs/common';
import { DocumentBuilder, type OpenAPIObject, SwaggerModule } from '@nestjs/swagger';

/** Security scheme names used by `@ApiBearerAuth(...)` and `@ApiSecurity(...)`. */
export const ACCESS_TOKEN_SCHEME = 'access-token';
export const API_KEY_SCHEME = 'api-key';

/** Path of the Swagger UI (served outside production only). */
export const OPENAPI_PATH = 'docs';

/** Builds the OpenAPI 3 document of the running app (paths include the `/api` prefix). */
export function buildOpenApiDocument(app: INestApplication): OpenAPIObject {
  const config = new DocumentBuilder()
    .setTitle('Email Security Gateway API')
    .setDescription(
      'Control-plane API. Business routes are under /api/v1 (ADR-0015). Authenticate with a ' +
        'bearer access token or, where accepted, an X-API-Key header.',
    )
    .setVersion('v1')
    .addBearerAuth({ type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }, ACCESS_TOKEN_SCHEME)
    .addApiKey({ type: 'apiKey', in: 'header', name: 'X-API-Key' }, API_KEY_SCHEME)
    .build();
  return SwaggerModule.createDocument(app, config);
}

/** Serves Swagger UI at `/docs` (and the JSON at `/docs-json`). Callers skip it in production. */
export function setupOpenApi(app: INestApplication): void {
  SwaggerModule.setup(OPENAPI_PATH, app, () => buildOpenApiDocument(app));
}
