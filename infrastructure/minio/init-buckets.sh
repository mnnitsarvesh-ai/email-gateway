#!/bin/sh
# Creates the local buckets with versioning and blocks anonymous access. Idempotent.
#
# Step 4.3 (docs/plan/steps/11-url-protection.md U11): the mail bucket gets a lifecycle rule that
# expires rewritten EML copies (objects tagged eg-object=rewrite, written by the url engine under
# org/<org>/rewrite/…; attempt orphans included) after URL_REWRITE_OBJECT_RETENTION_DAYS, and
# removes their noncurrent versions one day later (the buckets are versioned). The mail bucket's
# lifecycle configuration is owned by this script: `mc ilm import` replaces it as a whole, so
# re-running is idempotent. Production S3: the same rule (Terraform / docs/deployment/url-protection.md).
set -eu
mc alias set local "http://minio:9000" "${MINIO_ROOT_USER}" "${MINIO_ROOT_PASSWORD}" >/dev/null
for bucket in "${S3_BUCKET_MAIL}" "${S3_BUCKET_ARCHIVE}"; do
  mc mb --ignore-existing "local/${bucket}"
  mc version enable "local/${bucket}"
  mc anonymous set none "local/${bucket}"
done

days="${URL_REWRITE_OBJECT_RETENTION_DAYS:-30}"
case "$days" in
  '' | *[!0-9]*) echo "URL_REWRITE_OBJECT_RETENTION_DAYS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$days" -lt 1 ] || [ "$days" -gt 3650 ]; then
  echo "URL_REWRITE_OBJECT_RETENTION_DAYS must be 1..3650" >&2
  exit 1
fi
printf '{"Rules":[{"ID":"eg-rewrite-expiry","Status":"Enabled","Filter":{"Tag":{"Key":"eg-object","Value":"rewrite"}},"Expiration":{"Days":%s},"NoncurrentVersionExpiration":{"NoncurrentDays":1}}]}' "$days" \
  | mc ilm import "local/${S3_BUCKET_MAIL}" >/dev/null
echo "lifecycle: ${S3_BUCKET_MAIL} objects tagged eg-object=rewrite expire after ${days} days"
echo "buckets ready"
