#!/bin/sh
# Creates the local buckets with versioning and blocks anonymous access. Idempotent.
#
# Step 4.3 (docs/plan/steps/11-url-protection.md U11): the mail bucket gets a lifecycle rule that
# expires rewritten EML copies (objects tagged eg-object=rewrite, written by the url engine under
# org/<org>/rewrite/…; attempt orphans included) after URL_REWRITE_OBJECT_RETENTION_DAYS, and
# removes their noncurrent versions one day later (the buckets are versioned). The mail bucket's
# lifecycle configuration is owned by this script: `mc ilm import` replaces it as a whole, so
# re-running is idempotent. Production S3: the same rule (Terraform / docs/deployment/url-protection.md).
#
# Step 5.2 (docs/plan/steps/16-policy-engine.md P21): the same lifecycle configuration also holds
# eg-policy-copy-expiry, expiring policy copies (objects tagged eg-object=policy-copy, written by
# the policy-engine under org/<org>/policy/…; orphans of rolled-back evaluations included) after
# POLICY_COPY_RETENTION_DAYS (1..365, default 30) and their noncurrent versions one day later.
# Production S3: docs/deployment/policy-engine.md.
#
# Step 4.6 (docs/plan/steps/14-sandbox.md X12, ADR-0040): the restricted sandbox bucket
# SANDBOX_S3_BUCKET (versioning OFF so a purge is a real delete, anonymous none) with lifecycle
# backstops for samples/ (SANDBOX_SAMPLE_RETENTION_HOURS rounded up to whole days, >= 1) and
# artifacts/ (SANDBOX_ARTIFACT_RETENTION_DAYS + 1), and the MinIO user SANDBOX_S3_ACCESS_KEY_ID of
# the sandbox-controller with the policy eg-sandbox-controller: s3:GetObject on
# <bucket>/samples/* and s3:PutObject on <bucket>/artifacts/*, nothing else (no list, no other
# bucket). Re-running updates the user's secret, the policy and the lifecycle in place. Logs names
# and counts only, never a secret. Production S3: docs/deployment/sandbox.md (IAM).
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
policy_days="${POLICY_COPY_RETENTION_DAYS:-30}"
case "$policy_days" in
  '' | *[!0-9]*) echo "POLICY_COPY_RETENTION_DAYS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$policy_days" -lt 1 ] || [ "$policy_days" -gt 365 ]; then
  echo "POLICY_COPY_RETENTION_DAYS must be 1..365" >&2
  exit 1
fi
printf '{"Rules":[{"ID":"eg-rewrite-expiry","Status":"Enabled","Filter":{"Tag":{"Key":"eg-object","Value":"rewrite"}},"Expiration":{"Days":%s},"NoncurrentVersionExpiration":{"NoncurrentDays":1}},{"ID":"eg-policy-copy-expiry","Status":"Enabled","Filter":{"Tag":{"Key":"eg-object","Value":"policy-copy"}},"Expiration":{"Days":%s},"NoncurrentVersionExpiration":{"NoncurrentDays":1}}]}' "$days" "$policy_days" \
  | mc ilm import "local/${S3_BUCKET_MAIL}" >/dev/null
echo "lifecycle: ${S3_BUCKET_MAIL} objects tagged eg-object=rewrite expire after ${days} days"
echo "lifecycle: ${S3_BUCKET_MAIL} objects tagged eg-object=policy-copy expire after ${policy_days} days"

# ---------------------------------------------------------------- sandbox bucket (step 4.6)
fail() {
  echo "$1" >&2
  exit 1
}
is_uint() {
  case "$1" in
    '' | *[!0-9]*) return 1 ;;
  esac
  return 0
}
sandbox_bucket="${SANDBOX_S3_BUCKET:-}"
sandbox_user="${SANDBOX_S3_ACCESS_KEY_ID:-}"
sandbox_secret="${SANDBOX_S3_SECRET_ACCESS_KEY:-}"
sample_hours="${SANDBOX_SAMPLE_RETENTION_HOURS:-24}"
artifact_days="${SANDBOX_ARTIFACT_RETENTION_DAYS:-30}"
# S3 bucket naming rules (lower case, digits, dots, hyphens; 3..63), distinct from the mail buckets.
printf '%s' "$sandbox_bucket" | grep -Eq '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' ||
  fail "SANDBOX_S3_BUCKET must be a valid bucket name (3..63 of a-z 0-9 . -)"
if [ "$sandbox_bucket" = "${S3_BUCKET_MAIL}" ] || [ "$sandbox_bucket" = "${S3_BUCKET_ARCHIVE}" ]; then
  fail "SANDBOX_S3_BUCKET must differ from the mail and archive buckets"
fi
printf '%s' "$sandbox_user" | grep -Eq '^[A-Za-z0-9._-]{3,64}$' ||
  fail "SANDBOX_S3_ACCESS_KEY_ID must be 3..64 of A-Z a-z 0-9 . _ -"
if [ "$sandbox_user" = "${MINIO_ROOT_USER}" ]; then
  fail "SANDBOX_S3_ACCESS_KEY_ID must not be the MinIO root user"
fi
# MinIO requires 8..40 characters; the value is never printed.
secret_length=$(printf '%s' "$sandbox_secret" | wc -c | tr -d ' ')
if [ "$secret_length" -lt 8 ] || [ "$secret_length" -gt 40 ]; then
  fail "SANDBOX_S3_SECRET_ACCESS_KEY must be 8..40 characters"
fi
case "$sandbox_secret" in
  *[!A-Za-z0-9]*) fail "SANDBOX_S3_SECRET_ACCESS_KEY must be alphanumeric" ;;
esac
is_uint "$sample_hours" || fail "SANDBOX_SAMPLE_RETENTION_HOURS must be a positive integer"
if [ "$sample_hours" -lt 1 ] || [ "$sample_hours" -gt 48 ]; then
  fail "SANDBOX_SAMPLE_RETENTION_HOURS must be 1..48"
fi
is_uint "$artifact_days" || fail "SANDBOX_ARTIFACT_RETENTION_DAYS must be a positive integer"
if [ "$artifact_days" -lt 1 ] || [ "$artifact_days" -gt 180 ]; then
  fail "SANDBOX_ARTIFACT_RETENTION_DAYS must be 1..180"
fi

mc mb --ignore-existing "local/${sandbox_bucket}"
# Versioning stays off: a bucket that was ever versioned is suspended (MinIO cannot un-version).
if mc version info "local/${sandbox_bucket}" --json | grep -q '"status":"Enabled"'; then
  mc version suspend "local/${sandbox_bucket}"
fi
mc anonymous set none "local/${sandbox_bucket}"

sample_days=$(((sample_hours + 23) / 24))
expire_artifacts=$((artifact_days + 1))
printf '{"Rules":[{"ID":"eg-sandbox-samples","Status":"Enabled","Filter":{"Prefix":"samples/"},"Expiration":{"Days":%s},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}},{"ID":"eg-sandbox-artifacts","Status":"Enabled","Filter":{"Prefix":"artifacts/"},"Expiration":{"Days":%s},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}]}' \
  "$sample_days" "$expire_artifacts" | mc ilm import "local/${sandbox_bucket}" >/dev/null
echo "lifecycle: ${sandbox_bucket} samples/ expire after ${sample_days} day(s), artifacts/ after ${expire_artifacts} days"

# The controller's user and its only policy.
policy_file=$(mktemp)
trap 'rm -f "$policy_file"' EXIT
printf '{"Version":"2012-10-17","Statement":[{"Sid":"ReadSamples","Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::%s/samples/*"]},{"Sid":"WriteArtifacts","Effect":"Allow","Action":["s3:PutObject"],"Resource":["arn:aws:s3:::%s/artifacts/*"]}]}' \
  "$sandbox_bucket" "$sandbox_bucket" >"$policy_file"
mc admin policy create local eg-sandbox-controller "$policy_file" >/dev/null
# `user add` creates or updates the user (the secret is passed as an argument inside this one-shot
# container only and never echoed).
mc admin user add local "$sandbox_user" "$sandbox_secret" >/dev/null
mc admin user enable local "$sandbox_user" >/dev/null
if ! mc admin user info local "$sandbox_user" --json | grep -q '"policyName":"eg-sandbox-controller"'; then
  mc admin policy attach local eg-sandbox-controller --user "$sandbox_user" >/dev/null
fi
attached=$(mc admin user info local "$sandbox_user" --json | sed -n 's/.*"policyName":"\([^"]*\)".*/\1/p')
[ "$attached" = "eg-sandbox-controller" ] ||
  fail "user ${sandbox_user} must have exactly the policy eg-sandbox-controller (has: ${attached:-none})"
echo "sandbox: bucket ${sandbox_bucket} (versioning off, anonymous none), user ${sandbox_user} with policy eg-sandbox-controller"
echo "buckets ready"
