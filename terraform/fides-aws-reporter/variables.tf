variable "name" {
  type        = string
  default     = "fides-reporter"
  description = "Name prefix for created resources."
}

variable "image" {
  type        = string
  description = "The fides + aws-cli reporter image (build Dockerfile.aws-reporter and push to ECR/GHCR)."
}

variable "ecs_cluster_arn" {
  type        = string
  description = "ARN of the ECS cluster to RUN the reporter task in."
}

variable "target_cluster_name" {
  type        = string
  description = "Name of the ECS cluster to SNAPSHOT (often the same as the run cluster)."
}

variable "subnet_ids" {
  type        = list(string)
  description = "Subnets for the Fargate task ENI (need egress to the Fides server + AWS APIs)."
}

variable "security_group_ids" {
  type        = list(string)
  description = "Security groups for the Fargate task ENI."
}

variable "assign_public_ip" {
  type        = bool
  default     = false
  description = "Assign a public IP to the task ENI (true for public subnets without a NAT)."
}

variable "fides_server_url" {
  type        = string
  description = "Base URL of the Fides server, e.g. https://fides.example.com."
}

variable "fides_environment_id" {
  type        = string
  description = "The Fides environment UUID to report snapshots into."
}

variable "fides_token_secret_arn" {
  type        = string
  description = "Secrets Manager ARN whose value is the FIDES_API_TOKEN."
}

variable "snapshot_target" {
  type        = string
  default     = "ecs"
  description = "Runtime to snapshot: ecs | lambda."
  validation {
    condition     = contains(["ecs", "lambda"], var.snapshot_target)
    error_message = "snapshot_target must be \"ecs\" or \"lambda\"."
  }
}

variable "schedule_expression" {
  type        = string
  default     = "rate(10 minutes)"
  description = "EventBridge Scheduler expression for how often to snapshot."
}

variable "cpu" {
  type    = string
  default = "256"
}

variable "memory" {
  type    = string
  default = "512"
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "tags" {
  type    = map(string)
  default = {}
}
