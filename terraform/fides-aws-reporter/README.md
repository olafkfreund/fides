# terraform-aws-fides-reporter

Terraform module that runs the Fides reporter on AWS as a **scheduled Fargate
task**: on a cron, it snapshots the running **ECS** (or **Lambda**) workloads and
reports them to a Fides server, which diffs successive snapshots into drift /
shadow-change findings. The AWS analogue of the `fides-k8s-reporter` Helm chart.

## How it works

```
EventBridge Scheduler ──RunTask──▶ Fargate task (fides + aws-cli)
                                     └─ fides snapshot ecs --env <id> --cluster <name>
                                        (aws ecs list-tasks/describe-tasks) ──▶ POST /api/v1/snapshots
```

Read-only: the task role only `Describe`s the runtime. The `FIDES_API_TOKEN`
is injected from Secrets Manager (never in state or task env).

## Prerequisites

1. The reporter image — build `Dockerfile.aws-reporter` (fides CLI + AWS CLI) and push to ECR/GHCR:
   ```bash
   docker build -f Dockerfile.aws-reporter -t <acct>.dkr.ecr.<region>.amazonaws.com/fides-aws-reporter:1.0.0 .
   docker push <acct>.dkr.ecr.<region>.amazonaws.com/fides-aws-reporter:1.0.0
   ```
2. A Fides **environment** (`fides env create --name my-ecs --type ecs`) — note its UUID.
3. The `FIDES_API_TOKEN` stored in **Secrets Manager**.

## Usage

```hcl
module "fides_reporter" {
  source = "github.com/olafkfreund/fides//terraform/fides-aws-reporter"

  name                   = "fides-reporter"
  image                  = "<acct>.dkr.ecr.eu-west-2.amazonaws.com/fides-aws-reporter:1.0.0"
  ecs_cluster_arn        = aws_ecs_cluster.app.arn
  target_cluster_name    = aws_ecs_cluster.app.name
  subnet_ids             = module.vpc.private_subnets
  security_group_ids     = [aws_security_group.egress.id]
  fides_server_url       = "https://fides.example.com"
  fides_environment_id   = "88d2eeb1-5bc4-4e05-89b0-8b4f09fbb703"
  fides_token_secret_arn = aws_secretsmanager_secret.fides_token.arn
  snapshot_target        = "ecs"          # or "lambda"
  schedule_expression    = "rate(10 minutes)"
}
```

## Inputs (key)

| Variable | Description |
|----------|-------------|
| `image` | fides + aws-cli reporter image |
| `ecs_cluster_arn` | cluster to **run** the task in |
| `target_cluster_name` | cluster to **snapshot** |
| `fides_server_url` / `fides_environment_id` | Fides target |
| `fides_token_secret_arn` | Secrets Manager ARN of the API token |
| `snapshot_target` | `ecs` (default) or `lambda` |
| `schedule_expression` | default `rate(10 minutes)` |

## Outputs

`task_definition_arn`, `schedule_name`, `task_role_arn`, `log_group`.
