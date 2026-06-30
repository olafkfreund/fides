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
    "description": "Heart of the Fides supply chain integrity and compliance vault platform. Tracks build trails, artifacts, attestations, JQ policies, and LLM-assisted compliance checks.",
    "version": "1.0.0"
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "Relative API Server Gateway"
    }
  ],
  "paths": {
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
