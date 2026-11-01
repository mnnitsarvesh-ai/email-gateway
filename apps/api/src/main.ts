import './instrumentation';
import { bootstrapService } from '@email-gateway/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule, SERVICE_NAME } from './app.module';
import { loadApiConfig } from './config';

const config = loadApiConfig();

void bootstrapService({
  name: SERVICE_NAME,
  version: config.SERVICE_VERSION,
  logLevel: config.LOG_LEVEL,
  rootModule: AppModule.forRoot(config),
  port: config.HTTP_PORT,
  host: config.HTTP_HOST,
  configure: (app) => {
    app.use(helmet());
    app.enableCors({ origin: config.CORS_ORIGINS, credentials: true });
    if (config.NODE_ENV !== 'production') {
      const doc = new DocumentBuilder()
        .setTitle('Email Security Gateway API')
        .setVersion('v1')
        .build();
      SwaggerModule.setup('docs', app, () => SwaggerModule.createDocument(app, doc));
    }
  },
});
