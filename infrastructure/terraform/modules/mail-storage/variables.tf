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

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default     = {}
}
