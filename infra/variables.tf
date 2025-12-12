variable "project" {
  description = "Project name prefix for resources (e.g. bayguard-prod)"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "owner" {
  description = "Owner tag"
  type        = string
  default     = "BayAreaLa8s"
}

variable "env" {
  description = "Environment tag"
  type        = string
  default     = "prod"
}

variable "custom_domain_name" {
  description = "Optional custom domain name for the HTTP API (e.g. bayguard.bayareala8s.com). Leave empty to skip."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Optional Route53 hosted zone ID for the root domain (e.g. Z0123456789ABCDEFG for bayareala8s.com). Required if custom_domain_name is set and you want Terraform to manage DNS."
  type        = string
  default     = ""
}
