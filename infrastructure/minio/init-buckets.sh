#!/bin/sh
# Creates the local buckets with versioning and blocks anonymous access. Idempotent.
set -eu
mc alias set local "http://minio:9000" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null
for bucket in "${S3_BUCKET_MAIL}" "${S3_BUCKET_ARCHIVE}"; do
  mc mb --ignore-existing "local/${bucket}"
  mc version enable "local/${bucket}"
  mc anonymous set none "local/${bucket}"
done
echo "buckets ready"
