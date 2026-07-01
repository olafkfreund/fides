# terraform-provider-fides

A Terraform provider for managing [Fides](../) resources as code. It is a
**separate Go module** (its own `go.mod`) so the Terraform Plugin Framework
dependency does not affect the main `fides` module.

## Provider configuration

```hcl
terraform {
  required_providers {
    fides = {
      source = "olafkfreund/fides"
    }
  }
}

provider "fides" {
  endpoint  = "https://fides.example.com"   # or FIDES_SERVER_URL
  api_token = var.fides_api_token           # or FIDES_API_TOKEN (a token or service-account key)
}
```

## Resources

### `fides_control` — a governance control

```hcl
resource "fides_control" "vuln_scan" {
  key            = "SOC2-CC7.1"
  name           = "All production artifacts pass a vulnerability scan"
  framework      = "SOC2"
  required_types = ["trivy", "snyk"]
}
```

- **Create/Update** → `POST /api/v1/controls` (upsert by key).
- **Read** → `GET /api/v1/controls` (matched by `key`).
- **Delete** → archives the control (`POST /api/v1/controls/{id}/archive`) —
  controls are archived, never hard-deleted, preserving history.
- **Import**: `terraform import fides_control.vuln_scan SOC2-CC7.1` (by key).

## Build & local install

```bash
go build -o terraform-provider-fides
# then place it under ~/.terraform.d/plugins/... or use a dev_overrides block.
```

Additional resources (flows, environments, policies, service accounts) follow
the same client/resource pattern in `internal/provider/`.
