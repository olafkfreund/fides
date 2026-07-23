package api

import (
	"net/http"
)

// SwaggerUIHTML serves the Swagger UI web client loaded via CDN
const SwaggerUIHTML = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Fides API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <link rel="icon" type="image/png" href="https://unpkg.com/swagger-ui-dist@5.9.0/favicon-32x32.png" sizes="32x32" />
    <style>
      html { box-sizing: border-box; overflow: -grow-y; }
      *, *:before, *:after { box-sizing: inherit; }
      body { margin:0; background: #fafafa; }
    </style>
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
      window.onload = () => {
        window.ui = SwaggerUIBundle({
          url: '/api/v1/swagger.json',
          dom_id: '#swagger-ui',
          presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIStandalonePreset
          ],
          layout: "BaseLayout",
          deepLinking: true,
          showExtensions: true,
          showCommonExtensions: true
        });
      };
    </script>
  </body>
</html>`

// SwaggerJSON holds the OpenAPI 3.0 specification for Fides
const SwaggerJSON = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Fides Compliance & Provenance API",
    "description": "Fides supply-chain integrity & compliance API — build trails, artifacts, attestations, JQ policies, and LLM-assisted compliance. This is a curated subset of endpoints; the full CLI/API surface is documented in cli-reference.md.",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "Relative API Server Gateway"
    }
  ],
  "paths": {
    "/impact": {
      "get": {
        "summary": "Artifacts + running environments affected by a CVE (VEX not_affected suppressed)",
        "parameters": [{ "name": "cve", "in": "query", "required": true, "schema": { "type": "string" } }],
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/vex": {
      "post": {
        "summary": "Record a VEX statement (product may be '', an artifact sha256, or a component purl)",
        "responses": { "201": { "description": "Created" } }
      }
    },
    "/vulnerabilities/backfill": {
      "post": {
        "summary": "Backfill the CVE index from existing trivy/snyk/sarif attestations (admin)",
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/metrics/dora": {
      "get": {
        "summary": "DORA metrics: deployment frequency, change-failure rate, lead time, MTTR",
        "parameters": [{ "name": "days", "in": "query", "schema": { "type": "integer" } }],
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/trails/{id}/verify-chain": {
      "get": {
        "summary": "Verify a trail's tamper-evidence chain (+ external RFC3161 anchor status)",
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/trails/{id}/anchor": {
      "post": {
        "summary": "Anchor a trail's chain head to an external RFC3161 timestamp authority (admin)",
        "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }],
        "responses": { "201": { "description": "Created" } }
      }
    },
    "/reports/framework/{framework}": {
      "get": {
        "summary": "Auditor-ready per-framework report (SOC2/ISO27001/.../SLSA/CRA); ?format=oscal for OSCAL",
        "parameters": [{ "name": "framework", "in": "path", "required": true, "schema": { "type": "string" } }],
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/reports/cra-incidents": {
      "get": {
        "summary": "EU CRA 24h exploited-vulnerability / incident reporting set",
        "parameters": [{ "name": "hours", "in": "query", "schema": { "type": "integer" } }],
        "responses": { "200": { "description": "Success" } }
      }
    },
    "/controls/import-framework": {
      "post": {
        "summary": "Adopt a regulated framework's control catalog",
        "responses": { "201": { "description": "Created" } }
      }
    },
    "/orgs": {
      "get": {
        "summary": "List all organizations (tenants)",
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Create a new organization",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": { "type": "string" },
                  "description": { "type": "string" }
                },
                "required": ["name"]
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Created" }
        }
      }
    },
    "/flows": {
      "get": {
        "summary": "List compliance flows for a tenant",
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Register a new flow (pipeline component)",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "org_id": { "type": "string", "format": "uuid" },
                  "name": { "type": "string" },
                  "description": { "type": "string" }
                },
                "required": ["org_id", "name"]
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Created" }
        }
      }
    },
    "/trails": {
      "post": {
        "summary": "Start a new build trail (execution run)",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "flow_id": { "type": "string", "format": "uuid" },
                  "name": { "type": "string" },
                  "git_repository": { "type": "string" },
                  "git_commit": { "type": "string" },
                  "git_branch": { "type": "string" },
                  "git_message": { "type": "string" }
                },
                "required": ["flow_id", "name"]
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Created" }
        }
      }
    },
    "/artifacts": {
      "get": {
        "summary": "List all registered artifacts",
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Report a build artifact digest",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "org_id": { "type": "string", "format": "uuid" },
                  "trail_id": { "type": "string", "format": "uuid" },
                  "sha256": { "type": "string", "maxLength": 64 },
                  "name": { "type": "string" },
                  "type": { "type": "string" }
                },
                "required": ["org_id", "trail_id", "sha256", "name"]
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Registered" }
        }
      }
    },
    "/attestations": {
      "post": {
        "summary": "Record a security scan, test report, or evidence",
        "description": "Multi-part form payload containing raw files and metadata. Symmetric AES-256-GCM payload encryption supported.",
        "requestBody": {
          "required": true,
          "content": {
            "multipart/form-data": {
              "schema": {
                "type": "object",
                "properties": {
                  "trail_id": { "type": "string", "format": "uuid" },
                  "artifact_sha256": { "type": "string" },
                  "name": { "type": "string" },
                  "type_name": { "type": "string" },
                  "payload": { "type": "string" },
                  "encrypted": { "type": "string", "enum": ["true", "false"] },
                  "attachments": { "type": "string", "format": "binary" }
                },
                "required": ["trail_id", "name", "type_name", "payload"]
              }
            }
          }
        },
        "responses": {
          "201": { "description": "Attested" }
        }
      }
    },
    "/compliance": {
      "get": {
        "summary": "Evaluate policy gate compliance for an artifact digest",
        "parameters": [
          { "name": "sha256", "in": "query", "required": true, "schema": { "type": "string" } },
          { "name": "policy", "in": "query", "schema": { "type": "string" } }
        ],
        "responses": {
          "200": { "description": "Success" }
        }
      }
    },
    "/environments": {
      "get": {
        "summary": "List tracked runtime environments & drifts",
        "responses": {
          "200": { "description": "Success" }
        }
      }
    },
    "/tenant/settings": {
      "get": {
        "summary": "Get multi-tenant storage, secrets, and SSO configurations",
        "parameters": [
          { "name": "org_id", "in": "query", "schema": { "type": "string", "format": "uuid" } }
        ],
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Update storage, vault, and SSO configurations",
        "responses": {
          "200": { "description": "Saved" }
        }
      }
    },
    "/tenant/users": {
      "get": {
        "summary": "List all configured users and roles",
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Add or update a user and role",
        "responses": {
          "200": { "description": "Saved" }
        }
      }
    },
    "/tenant/group-mappings": {
      "get": {
        "summary": "List external SSO groups mappings",
        "responses": {
          "200": { "description": "Success" }
        }
      },
      "post": {
        "summary": "Create/update an SSO group mapping to a role",
        "responses": {
          "200": { "description": "Saved" }
        }
      }
    },
    "/telemetry/metrics": {
      "get": {
        "summary": "JSON metrics format for portal dashboard",
        "responses": {
          "200": { "description": "Success" }
        }
      }
    }
  }
}`

func (s *Server) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(SwaggerJSON))
}

func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(SwaggerUIHTML))
}
