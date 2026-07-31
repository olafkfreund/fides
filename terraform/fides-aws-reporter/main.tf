data "aws_region" "current" {}

locals {
  command = var.snapshot_target == "ecs" ? [
    "snapshot", "ecs", "--env", var.fides_environment_id, "--cluster", var.target_cluster_name
    ] : [
    "snapshot", "lambda", "--env", var.fides_environment_id
  ]
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/fides/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

# --- IAM: task execution role (pull image, write logs, read the token secret) ---
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secret" {
  name = "${var.name}-read-token"
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.fides_token_secret_arn]
    }]
  })
}

# --- IAM: task role (read-only describe of the runtime being snapshotted) ---
resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "task_readonly" {
  name = "${var.name}-snapshot-readonly"
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ecs:ListTasks",
        "ecs:DescribeTasks",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "lambda:ListFunctions"
      ]
      Resource = ["*"]
    }]
  })
}

# --- ECS task definition (Fargate) ---
resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  tags                     = var.tags

  container_definitions = jsonencode([{
    name      = "reporter"
    image     = var.image
    essential = true
    command   = local.command
    environment = [
      { name = "FIDES_SERVER_URL", value = var.fides_server_url }
    ]
    secrets = [
      { name = "FIDES_API_TOKEN", valueFrom = var.fides_token_secret_arn }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.this.name
        "awslogs-region"        = data.aws_region.current.region
        "awslogs-stream-prefix" = "reporter"
      }
    }
  }])
}

# --- EventBridge Scheduler -> ECS RunTask on a schedule ---
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy" "scheduler_runtask" {
  name = "${var.name}-runtask"
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = [aws_ecs_task_definition.this.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.execution.arn, aws_iam_role.task.arn]
      }
    ]
  })
}

resource "aws_scheduler_schedule" "this" {
  name = var.name
  flexible_time_window {
    mode = "OFF"
  }
  schedule_expression = var.schedule_expression

  target {
    arn      = var.ecs_cluster_arn
    role_arn = aws_iam_role.scheduler.arn

    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.this.arn
      launch_type         = "FARGATE"
      network_configuration {
        subnets          = var.subnet_ids
        security_groups  = var.security_group_ids
        assign_public_ip = var.assign_public_ip
      }
    }
  }
}
