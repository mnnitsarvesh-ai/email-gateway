variable "name_prefix" {
  description = "Prefix for bucket names, e.g. eg-prod-aps1."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key used for SSE-KMS."
  type        = string
}

variable "mail_retention_days" {
  description = "Days to keep processed EML/attachments in the mail bucket. Archive retention is per tenant."
  type        = number
  default     = 30
}

variable "archive_export_expiry_days" {
  description = "Days after which eDiscovery export packages (objects tagged eg-object=archive-export) expire in the archive bucket: ceil(ARCHIVE_EXPORT_TTL_HOURS / 24) + 1 (step 8.1 A18, A29). A backstop; the archive-worker deletes exports at their TTL."
  type        = number
  default     = 8
  validation {
    condition     = var.archive_export_expiry_days >= 1 && var.archive_export_expiry_days <= 366
    error_message = "archive_export_expiry_days must be 1..366."
  }
}

variable "archive_storage_transitions" {
  description = "Optional storage-class transitions of archived objects (prefix org/), e.g. [{ days = 90, storage_class = \"GLACIER_IR\" }]. Default: none. Archive records are never expired by lifecycle (step 8.1 A30)."
  type = list(object({
    days          = number
    storage_class = string
  }))
  default = []
  validation {
    condition = alltrue([
      for t in var.archive_storage_transitions :
      t.days >= 30 && contains(["STANDARD_IA", "INTELLIGENT_TIERING", "GLACIER_IR", "GLACIER", "DEEP_ARCHIVE"], t.storage_class)
    ])
    error_message = "Each transition needs days >= 30 and a storage class of STANDARD_IA, INTELLIGENT_TIERING, GLACIER_IR, GLACIER or DEEP_ARCHIVE."
  }
}

# Replication of the archive bucket to a DR bucket (step 10.2). Documented here, NOT applied by
# this module: S3 replication never replicates version deletes, so the archive-worker deletes the
# versions of disposed records in every bucket listed in ARCHIVE_REPLICA_TARGETS (step 8.1 A14).
variable "archive_replication_destination_bucket_arn" {
  description = "DOCUMENTATION ONLY (not applied; step 10.2): ARN of the Object Lock enabled DR bucket the archive bucket will replicate to. Its name must also be listed in the archive-worker's ARCHIVE_REPLICA_TARGETS."
  type        = string
  default     = null
}

variable "archive_replication_destination_region" {
  description = "DOCUMENTATION ONLY (not applied; step 10.2): region of the DR bucket (ARCHIVE_REPLICA_TARGETS entry `bucket@region`)."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
