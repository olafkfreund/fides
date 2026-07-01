terraform {
  required_providers {
    fides = { source = "olafkfreund/fides" }
  }
}

provider "fides" {
  # endpoint  = "https://fides.example.com"   # or FIDES_SERVER_URL
  # api_token = var.fides_api_token           # or FIDES_API_TOKEN
}

resource "fides_control" "vuln_scan" {
  key            = "SOC2-CC7.1"
  name           = "Production artifacts pass a vulnerability scan"
  framework      = "SOC2"
  required_types = ["trivy", "snyk"]
}

resource "fides_control" "unit_tests" {
  key            = "SOC2-CC8.1"
  name           = "Changes are covered by passing tests"
  framework      = "SOC2"
  required_types = ["junit"]
}
