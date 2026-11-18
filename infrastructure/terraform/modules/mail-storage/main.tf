# S3 storage for raw messages (EML), extracted attachments and the optional archive.
# Keys are tenant-prefixed (org/{tenant_id}/...) so per-tenant export, deletion and IAM
# prefix conditions are prefix operations.
#
# Step 8.1 (docs/plan/steps/23-journaling-archiving.md A10, A29, A30; ADR-0066; docs/deployment/
# archive.md): the archive bucket is created WITH S3 Object Lock and no default retention. The
# archive-worker sets the mode (GOVERNANCE / COMPLIANCE) and the retain-until date per object for
# tenants that require immutability, and extends it (never shortens). Object Lock can only be
# chosen at bucket creation in this resource: changing `object_lock_enabled` on an existing bucket
# forces a replacement, so it is set before the first apply of the archive bucket (step 10.1).
# The archive lifecycle never expires archive records: deletion is the archive-worker's disposal
# pipeline only (A14).

resource "aws_s3_bucket" "this" {
  for_each            = local.buckets
  bucket              = each.value.name
  object_lock_enabled = each.value.object_lock
  tags                = merge(var.tags, { Purpose = each.key })
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each                = aws_s3_bucket.this
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mail" {
  bucket = aws_s3_bucket.this["mail"].id

  rule {
    id     = "expire-processed-mail"
    status = "Enabled"
    filter {}
    expiration {
      days = var.mail_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

# Archive bucket lifecycle (step 8.1 A11, A18, A29): abort incomplete multipart uploads (capture
# attempts that crashed mid-upload), expire eDiscovery export packages (objects tagged
# eg-object=archive-export, never locked; the archive-worker deletes them at
# ARCHIVE_EXPORT_TTL_HOURS, this is the backstop) and, optionally, move archived objects to
# cheaper storage classes. There is deliberately NO expiration of archive records.
resource "aws_s3_bucket_lifecycle_configuration" "archive" {
  bucket = aws_s3_bucket.this["archive"].id

  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  rule {
    id     = "expire-archive-exports"
    status = "Enabled"
    filter {
      tag {
        key   = "eg-object"
        value = "archive-export"
      }
    }
    expiration {
      days = var.archive_export_expiry_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  dynamic "rule" {
    for_each = length(var.archive_storage_transitions) > 0 ? [1] : []
    content {
      id     = "archive-storage-tiering"
      status = "Enabled"
      filter {
        prefix = "org/"
      }
      dynamic "transition" {
        for_each = var.archive_storage_transitions
        content {
          days          = transition.value.days
          storage_class = transition.value.storage_class
        }
      }
    }
  }
}

resource "aws_s3_bucket_policy" "tls_only" {
  for_each = aws_s3_bucket.this
  bucket   = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [each.value.arn, "${each.value.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

locals {
  buckets = {
    mail    = { name = "${var.name_prefix}-mail", object_lock = false }
    archive = { name = "${var.name_prefix}-archive", object_lock = true }
  }
}
