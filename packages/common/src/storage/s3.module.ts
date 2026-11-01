import { HeadBucketCommand, S3Client } from '@aws-sdk/client-s3';
import {
  type DynamicModule,
  Global,
  Inject,
  Injectable,
  Module,
  type OnModuleDestroy,
} from '@nestjs/common';
import type { S3Config } from '@email-gateway/config';
import type { HealthIndicator } from '../health/health-indicator';

const S3_OPTIONS = Symbol('S3_OPTIONS');

/** Object storage for EML bodies, attachments and archive copies (AWS S3 or MinIO locally). */
@Injectable()
export class S3Service implements OnModuleDestroy, HealthIndicator {
  readonly healthName = 's3';
  readonly client: S3Client;

  constructor(@Inject(S3_OPTIONS) private readonly options: S3Config) {
    this.client = new S3Client({
      region: options.S3_REGION,
      endpoint: options.S3_ENDPOINT,
      forcePathStyle: options.S3_FORCE_PATH_STYLE,
      credentials:
        options.S3_ACCESS_KEY_ID && options.S3_SECRET_ACCESS_KEY
          ? { accessKeyId: options.S3_ACCESS_KEY_ID, secretAccessKey: options.S3_SECRET_ACCESS_KEY }
          : undefined,
    });
  }

  get mailBucket(): string {
    return this.options.S3_BUCKET_MAIL;
  }

  get archiveBucket(): string {
    return this.options.S3_BUCKET_ARCHIVE;
  }

  async checkHealth(): Promise<void> {
    await this.client.send(new HeadBucketCommand({ Bucket: this.options.S3_BUCKET_MAIL }));
  }

  onModuleDestroy(): void {
    this.client.destroy();
  }
}

@Global()
@Module({})
export class S3Module {
  static forRoot(options: S3Config): DynamicModule {
    return {
      module: S3Module,
      providers: [{ provide: S3_OPTIONS, useValue: options }, S3Service],
      exports: [S3Service],
    };
  }
}
