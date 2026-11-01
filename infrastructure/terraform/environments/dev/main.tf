terraform {
  required_version = ">= 1.9"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  # Remote state: bucket/table are per AWS account and passed via -backend-config=backend.hcl.
  backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project     = "email-gateway"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

resource "aws_kms_key" "data" {
  description         = "email-gateway dev data encryption"
  enable_key_rotation = true
}

module "mail_storage" {
  source      = "../../modules/mail-storage"
  name_prefix = "eg-dev-aps1"
  kms_key_arn = aws_kms_key.data.arn
}
