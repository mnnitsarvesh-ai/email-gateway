output "mail_bucket" {
  value = aws_s3_bucket.this["mail"].bucket
}

output "archive_bucket" {
  value = aws_s3_bucket.this["archive"].bucket
}

output "bucket_arns" {
  value = { for k, b in aws_s3_bucket.this : k => b.arn }
}
