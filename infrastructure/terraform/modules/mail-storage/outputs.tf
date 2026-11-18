output "mail_bucket" {
  value = aws_s3_bucket.this["mail"].bucket
}

output "archive_bucket" {
  value = aws_s3_bucket.this["archive"].bucket
}

output "bucket_arns" {
  value = { for k, b in aws_s3_bucket.this : k => b.arn }
}

# Step 8.1: what the archive-worker's ARCHIVE_REPLICA_TARGETS must list once step 10.2 configures
# replication (null until then). Informational; this module creates no replication.
output "archive_replica_target" {
  value = var.archive_replication_destination_bucket_arn == null ? null : (
    var.archive_replication_destination_region == null
    ? element(split(":::", var.archive_replication_destination_bucket_arn), 1)
    : "${element(split(":::", var.archive_replication_destination_bucket_arn), 1)}@${var.archive_replication_destination_region}"
  )
}
