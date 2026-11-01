import { Inject, Injectable } from '@nestjs/common';
import { API_CONFIG } from '../api-config.token';
import type { ApiConfig } from '../config';

export interface ApiMeta {
  service: string;
  version: string;
  apiVersion: string;
  environment: string;
}

@Injectable()
export class MetaService {
  constructor(@Inject(API_CONFIG) private readonly config: Readonly<ApiConfig>) {}

  describe(): ApiMeta {
    return {
      service: 'email-gateway-api',
      version: this.config.SERVICE_VERSION,
      apiVersion: 'v1',
      environment: this.config.APP_ENV,
    };
  }
}
