output "task_definition_arn" {
  value       = aws_ecs_task_definition.this.arn
  description = "ARN of the reporter ECS task definition."
}

output "schedule_name" {
  value       = aws_scheduler_schedule.this.name
  description = "Name of the EventBridge schedule driving the reporter."
}

output "task_role_arn" {
  value       = aws_iam_role.task.arn
  description = "ARN of the task role (read-only snapshot permissions)."
}

output "log_group" {
  value       = aws_cloudwatch_log_group.this.name
  description = "CloudWatch log group for reporter runs."
}
