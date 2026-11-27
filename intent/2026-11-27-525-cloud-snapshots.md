---
status: approved
issue: 525
author: olafkfreund
---

# Intent: Record running artifacts across Cloud Run, Azure and S3

## Problem

Fides has ECS and Lambda snapshots. Cloud Run, Azure App Service and Functions, and S3 resources are outside the current snapshot coverage.

## Proposed outcome

CLI snapshots capture stable evidence from Cloud Run revisions, Azure deployments and S3 bucket or prefix contents. Each has fixture-driven tests and a documented environment type in Terraform.

## Affected users and systems

Snapshot CLI, managed cloud environments, Terraform and docs.

## Constraints

Reuse the existing snapshot flow. Define artifact identity from provider evidence with attention to mutable tags, pagination and versioning.

## Open questions

Confirm the CLI syntax and Terraform scope because the CLI uses a positional runtime and the provider has no environment resource. Which provider identity and consistency guarantees are required for Azure deployments and S3 content?
