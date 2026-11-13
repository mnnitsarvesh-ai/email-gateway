/**
 * Database and object-store clients of the seeder: the Prisma writer (DATABASE_URL), the
 * replica reader (DATABASE_READ_URL, visibility checks only) and the MinIO mail bucket.
 */
import { S3Client } from '@aws-sdk/client-s3';
import { PrismaClient } from '@email-gateway/database';
import { optionalEnv, requireEnv } from '../support/env';

export function writer(): PrismaClient {
  return new PrismaClient({ datasourceUrl: requireEnv('DATABASE_URL') });
}

export function reader(): PrismaClient {
  return new PrismaClient({ datasourceUrl: requireEnv('DATABASE_READ_URL') });
}

export function mailBucket(): { s3: S3Client; bucket: string } {
  const s3 = new S3Client({
    region: optionalEnv('S3_REGION', 'us-east-1'),
    endpoint: requireEnv('S3_ENDPOINT'),
    forcePathStyle: optionalEnv('S3_FORCE_PATH_STYLE', 'true') === 'true',
    credentials: {
      accessKeyId: requireEnv('S3_ACCESS_KEY_ID'),
      secretAccessKey: requireEnv('S3_SECRET_ACCESS_KEY'),
    },
  });
  return { s3, bucket: requireEnv('S3_BUCKET_MAIL') };
}
