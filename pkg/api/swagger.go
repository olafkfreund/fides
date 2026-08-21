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
    "description": "Fides supply-chain integrity & compliance API \u2014 build trails, artifacts, attestations, JQ policies, and LLM-assisted compliance.\n\nEvery /api/v1 route the server registers appears here; a route added without an entry fails TestEveryRouteIsDocumented. Entries marked \"schemas not yet described\" are complete as to path, method and auth, and incomplete as to body shape \u2014 see docs/cli-reference.md for those.",
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
        "parameters": [
          {
            "name": "cve",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/vex": {
      "post": {
        "summary": "Record a VEX statement (product may be '', an artifact sha256, or a component purl)",
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/vulnerabilities/backfill": {
      "post": {
        "summary": "Backfill the CVE index from existing trivy/snyk/sarif attestations (admin)",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/metrics/dora": {
      "get": {
        "summary": "DORA metrics: deployment frequency, change-failure rate, lead time, MTTR",
        "parameters": [
          {
            "name": "days",
            "in": "query",
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/trails/{id}/verify-chain": {
      "get": {
        "summary": "Verify a trail's tamper-evidence chain (+ external RFC3161 anchor status)",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "format": "uuid"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/trails/{id}/anchor": {
      "post": {
        "summary": "Anchor a trail's chain head to an external RFC3161 timestamp authority (admin)",
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string",
              "format": "uuid"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/reports/framework/{framework}": {
      "get": {
        "summary": "Auditor-ready per-framework report (SOC2/ISO27001/.../SLSA/CRA); ?format=oscal for OSCAL",
        "parameters": [
          {
            "name": "framework",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/reports/cra-incidents": {
      "get": {
        "summary": "EU CRA 24h exploited-vulnerability / incident reporting set",
        "parameters": [
          {
            "name": "hours",
            "in": "query",
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/controls/import-framework": {
      "post": {
        "summary": "Adopt a regulated framework's control catalog",
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/orgs": {
      "get": {
        "summary": "List all organizations (tenants)",
        "responses": {
          "200": {
            "description": "Success"
          }
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
                  "name": {
                    "type": "string"
                  },
                  "description": {
                    "type": "string"
                  }
                },
                "required": [
                  "name"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/flows": {
      "get": {
        "summary": "List compliance flows for a tenant",
        "responses": {
          "200": {
            "description": "Success"
          }
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
                  "org_id": {
                    "type": "string",
                    "format": "uuid"
                  },
                  "name": {
                    "type": "string"
                  },
                  "description": {
                    "type": "string"
                  }
                },
                "required": [
                  "org_id",
                  "name"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created"
          }
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
                  "flow_id": {
                    "type": "string",
                    "format": "uuid"
                  },
                  "name": {
                    "type": "string"
                  },
                  "git_repository": {
                    "type": "string"
                  },
                  "git_commit": {
                    "type": "string"
                  },
                  "git_branch": {
                    "type": "string"
                  },
                  "git_message": {
                    "type": "string"
                  }
                },
                "required": [
                  "flow_id",
                  "name"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Created"
          }
        }
      }
    },
    "/artifacts": {
      "get": {
        "summary": "List all registered artifacts",
        "responses": {
          "200": {
            "description": "Success"
          }
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
                  "org_id": {
                    "type": "string",
                    "format": "uuid"
                  },
                  "trail_id": {
                    "type": "string",
                    "format": "uuid"
                  },
                  "sha256": {
                    "type": "string",
                    "maxLength": 64
                  },
                  "name": {
                    "type": "string"
                  },
                  "type": {
                    "type": "string"
                  }
                },
                "required": [
                  "org_id",
                  "trail_id",
                  "sha256",
                  "name"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Registered"
          }
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
                  "trail_id": {
                    "type": "string",
                    "format": "uuid"
                  },
                  "artifact_sha256": {
                    "type": "string"
                  },
                  "name": {
                    "type": "string"
                  },
                  "type_name": {
                    "type": "string"
                  },
                  "payload": {
                    "type": "string"
                  },
                  "encrypted": {
                    "type": "string",
                    "enum": [
                      "true",
                      "false"
                    ]
                  },
                  "attachments": {
                    "type": "string",
                    "format": "binary"
                  }
                },
                "required": [
                  "trail_id",
                  "name",
                  "type_name",
                  "payload"
                ]
              }
            }
          }
        },
        "responses": {
          "201": {
            "description": "Attested"
          }
        }
      }
    },
    "/compliance": {
      "get": {
        "summary": "Evaluate policy gate compliance for an artifact digest",
        "parameters": [
          {
            "name": "sha256",
            "in": "query",
            "required": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "policy",
            "in": "query",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/environments": {
      "get": {
        "summary": "List tracked runtime environments & drifts",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/tenant/settings": {
      "get": {
        "summary": "Get multi-tenant storage, secrets, and SSO configurations",
        "parameters": [
          {
            "name": "org_id",
            "in": "query",
            "schema": {
              "type": "string",
              "format": "uuid"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      },
      "post": {
        "summary": "Update storage, vault, and SSO configurations",
        "responses": {
          "200": {
            "description": "Saved"
          }
        }
      }
    },
    "/tenant/users": {
      "get": {
        "summary": "List all configured users and roles",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      },
      "post": {
        "summary": "Add or update a user and role",
        "responses": {
          "200": {
            "description": "Saved"
          }
        }
      }
    },
    "/tenant/group-mappings": {
      "get": {
        "summary": "List external SSO groups mappings",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      },
      "post": {
        "summary": "Create/update an SSO group mapping to a role",
        "responses": {
          "200": {
            "description": "Saved"
          }
        }
      }
    },
    "/telemetry/metrics": {
      "get": {
        "summary": "JSON metrics format for portal dashboard",
        "responses": {
          "200": {
            "description": "Success"
          }
        }
      }
    },
    "/admission/validate": {
      "post": {
        "tags": [
          "Admission"
        ],
        "summary": "Admission Validate",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/ai-assessments": {
      "get": {
        "tags": [
          "Ai Assessments"
        ],
        "summary": "List A I Assessments",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/ai/chat": {
      "post": {
        "tags": [
          "Ai"
        ],
        "summary": "A I Chat",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/ai/generate-policy": {
      "post": {
        "tags": [
          "Ai"
        ],
        "summary": "A I Generate Policy",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/ai/lint-policy": {
      "post": {
        "tags": [
          "Ai"
        ],
        "summary": "A I Lint Policy",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/attest/fetch": {
      "post": {
        "tags": [
          "Attest"
        ],
        "summary": "Attest Fetch",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/attestation-types": {
      "post": {
        "tags": [
          "Attestation Types"
        ],
        "summary": "Create Attestation Type",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/attestations/{id}": {
      "get": {
        "tags": [
          "Attestations"
        ],
        "summary": "Get Attestation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/audit-pack": {
      "get": {
        "tags": [
          "Audit Pack"
        ],
        "summary": "Audit Pack",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/auth/callback": {
      "get": {
        "tags": [
          "Auth"
        ],
        "summary": "Auth Callback",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/auth/local-login": {
      "post": {
        "tags": [
          "Auth"
        ],
        "summary": "Local Login",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/auth/login": {
      "get": {
        "tags": [
          "Auth"
        ],
        "summary": "Auth Login",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/console/stream": {
      "get": {
        "tags": [
          "Console"
        ],
        "summary": "Console Stream",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/console/summary": {
      "get": {
        "tags": [
          "Console"
        ],
        "summary": "Console Summary",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/control-catalog": {
      "get": {
        "tags": [
          "Control Catalog"
        ],
        "summary": "Control Catalog",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/controls": {
      "get": {
        "tags": [
          "Controls"
        ],
        "summary": "List Controls",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Controls"
        ],
        "summary": "Create Control",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/controls/coverage": {
      "get": {
        "tags": [
          "Controls"
        ],
        "summary": "Controls Coverage",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/controls/timeline": {
      "get": {
        "tags": [
          "Controls"
        ],
        "summary": "Control Timeline",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/controls/{id}/archive": {
      "post": {
        "tags": [
          "Controls"
        ],
        "summary": "Archive Control",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/controls/{id}/unarchive": {
      "post": {
        "tags": [
          "Controls"
        ],
        "summary": "Unarchive Control",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/controls/{key}/enforce": {
      "post": {
        "tags": [
          "Controls"
        ],
        "summary": "Enforce Control",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "key",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/export": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "Export Environment Audit",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/environments/mcp": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "List Environment M C P Servers",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Save Environment M C P Server",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/environments/mcp/query": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Query Environment M C P Server",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/environments/mcp/verify": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Verify Environment Compliance",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/environments/{id}/allowlist": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "List Allowlist",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      },
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Add Allowlist",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/allowlist/{sha}": {
      "delete": {
        "tags": [
          "Environments"
        ],
        "summary": "Remove Allowlist",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "sha",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/archive": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Archive Environment",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/policies": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "List Env Policies",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      },
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Create Policy",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/policies/{policyId}": {
      "delete": {
        "tags": [
          "Environments"
        ],
        "summary": "Delete Policy",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "policyId",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/policy-check": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "Policy Check",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/snapshots/diff": {
      "get": {
        "tags": [
          "Environments"
        ],
        "summary": "Snapshot Diff",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/snapshots/reevaluate-change": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Drift Reevaluate Change",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/tags": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Set Env Tags",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/environments/{id}/unarchive": {
      "post": {
        "tags": [
          "Environments"
        ],
        "summary": "Unarchive Environment",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/exceptions": {
      "get": {
        "tags": [
          "Exceptions"
        ],
        "summary": "List Exceptions",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Exceptions"
        ],
        "summary": "Create Exception",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/exceptions/{id}/revoke": {
      "post": {
        "tags": [
          "Exceptions"
        ],
        "summary": "Revoke Exception",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/flags/changed": {
      "post": {
        "tags": [
          "Flags"
        ],
        "summary": "Record Flag Change",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/flags/history": {
      "get": {
        "tags": [
          "Flags"
        ],
        "summary": "Flag History",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/flags/webhook/{provider}": {
      "post": {
        "tags": [
          "Flags"
        ],
        "summary": "Flag Webhook",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "provider",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/flows/{id}/artifacts": {
      "get": {
        "tags": [
          "Flows"
        ],
        "summary": "List Flow Artifacts",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/flows/{id}/tags": {
      "post": {
        "tags": [
          "Flows"
        ],
        "summary": "Set Flow Tags",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/flows/{id}/trails": {
      "get": {
        "tags": [
          "Flows"
        ],
        "summary": "List Flow Trails",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/frameworks": {
      "get": {
        "tags": [
          "Frameworks"
        ],
        "summary": "List Frameworks",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/logical-environments": {
      "get": {
        "tags": [
          "Logical Environments"
        ],
        "summary": "List Logical Env",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Logical Environments"
        ],
        "summary": "Create Logical Env",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/logical-environments/{id}/members": {
      "post": {
        "tags": [
          "Logical Environments"
        ],
        "summary": "Add Logical Member",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/logical-environments/{id}/members/{envId}": {
      "delete": {
        "tags": [
          "Logical Environments"
        ],
        "summary": "Remove Logical Member",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "envId",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/logical-environments/{id}/state": {
      "get": {
        "tags": [
          "Logical Environments"
        ],
        "summary": "Logical Env State",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/mcp": {
      "post": {
        "tags": [
          "Mcp"
        ],
        "summary": "M C P Server",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/metrics/compliance-correlation": {
      "get": {
        "tags": [
          "Metrics"
        ],
        "summary": "Compliance Correlation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/metrics/deployment-frequency": {
      "get": {
        "tags": [
          "Metrics"
        ],
        "summary": "Deployment Frequency",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/policies": {
      "get": {
        "tags": [
          "Policies"
        ],
        "summary": "List Policies",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Policies"
        ],
        "summary": "Save Policy",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/policies/create": {
      "post": {
        "tags": [
          "Policies"
        ],
        "summary": "Create Policy Global",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/policies/{id}": {
      "delete": {
        "tags": [
          "Policies"
        ],
        "summary": "Delete Policy Global",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/remediation": {
      "get": {
        "tags": [
          "Remediation"
        ],
        "summary": "List Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Remediation"
        ],
        "summary": "Propose Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/remediation/{id}": {
      "get": {
        "tags": [
          "Remediation"
        ],
        "summary": "Get Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/remediation/{id}/apply": {
      "post": {
        "tags": [
          "Remediation"
        ],
        "summary": "Apply Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/remediation/{id}/approve": {
      "post": {
        "tags": [
          "Remediation"
        ],
        "summary": "Approve Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/remediation/{id}/reject": {
      "post": {
        "tags": [
          "Remediation"
        ],
        "summary": "Reject Remediation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/risk-register": {
      "get": {
        "tags": [
          "Risk Register"
        ],
        "summary": "Risk Register",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/sdlc": {
      "get": {
        "tags": [
          "Sdlc"
        ],
        "summary": "S D L C",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/search/artifacts": {
      "get": {
        "tags": [
          "Search"
        ],
        "summary": "Search Artifacts",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/search/attestations": {
      "get": {
        "tags": [
          "Search"
        ],
        "summary": "Search Attestations",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/search/components": {
      "get": {
        "tags": [
          "Search"
        ],
        "summary": "Search Components",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/servicenow/change-check": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Change Check",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/change-gate": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Change Gate",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/change-status": {
      "get": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Change Status",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/servicenow/cmdb": {
      "get": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Search C M D B",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/servicenow/deployment-anchor": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Anchor Deployment",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/grounding": {
      "get": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Grounding",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/servicenow/incident": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Create Incident",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/link-control": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "Service Now Link Control",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/mcp/call": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "S N M C P Call",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/mcp/lookup": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "S N M C P Lookup",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/servicenow/mcp/servers": {
      "get": {
        "tags": [
          "Servicenow"
        ],
        "summary": "S N M C P Servers",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/servicenow/mcp/tools": {
      "post": {
        "tags": [
          "Servicenow"
        ],
        "summary": "S N M C P Tools",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/services": {
      "get": {
        "tags": [
          "Services"
        ],
        "summary": "List Services",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Services"
        ],
        "summary": "Save Service",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/snapshots": {
      "post": {
        "tags": [
          "Snapshots"
        ],
        "summary": "Report Snapshot",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/swagger.json": {
      "get": {
        "tags": [
          "Swagger.Json"
        ],
        "summary": "Swagger J S O N",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/tenant/git-providers": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "List Git Providers",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Save Git Provider",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/tenant/service-accounts": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "List Service Accounts",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Create Service Account",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/tenant/service-accounts/{id}/delegation": {
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Set Service Account Delegation",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/tenant/service-accounts/{id}/keys": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "List Service Account Keys",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Issue Service Account Key",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/tenant/service-accounts/{id}/keys/{keyId}": {
      "delete": {
        "tags": [
          "Tenant"
        ],
        "summary": "Revoke Service Account Key",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "keyId",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/tenant/servicenow": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "Get Service Now",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Save Service Now",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/tenant/servicenow/events": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "Service Now Events",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      }
    },
    "/tenant/slack": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "Get Slack",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Save Slack",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/tenant/users/{id}/password": {
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Set User Password",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/tenant/webhooks": {
      "get": {
        "tags": [
          "Tenant"
        ],
        "summary": "List Webhooks",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Tenant"
        ],
        "summary": "Save Webhook",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/trails/{id}/approvals": {
      "get": {
        "tags": [
          "Trails"
        ],
        "summary": "List Approvals",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      },
      "post": {
        "tags": [
          "Trails"
        ],
        "summary": "Record Approval",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/trails/{id}/audit-package": {
      "get": {
        "tags": [
          "Trails"
        ],
        "summary": "Trail Audit Package",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/trails/{id}/change-gate": {
      "get": {
        "tags": [
          "Trails"
        ],
        "summary": "Change Gate",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/trails/{id}/deployment-anchors": {
      "get": {
        "tags": [
          "Trails"
        ],
        "summary": "List Deployment Anchors",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        },
        "parameters": [
          {
            "name": "id",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
      }
    },
    "/training": {
      "get": {
        "tags": [
          "Training"
        ],
        "summary": "List Training",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          }
        }
      },
      "post": {
        "tags": [
          "Training"
        ],
        "summary": "Record Training",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/verify-branch-protection": {
      "post": {
        "tags": [
          "Verify Branch Protection"
        ],
        "summary": "Verify Branch Protection",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        }
      }
    },
    "/webhooks/{provider}": {
      "post": {
        "tags": [
          "Webhooks"
        ],
        "summary": "Inbound Webhook",
        "description": "Registered endpoint. Request and response schemas are not yet described here \u2014 see docs/cli-reference.md for the shapes this endpoint accepts.",
        "responses": {
          "200": {
            "description": "Success"
          },
          "401": {
            "description": "Authentication required"
          },
          "403": {
            "description": "Insufficient role"
          }
        },
        "parameters": [
          {
            "name": "provider",
            "in": "path",
            "required": true,
            "schema": {
              "type": "string"
            }
          }
        ]
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
