# Fides CLI Reference

Set `FIDES_SERVER_URL` and `FIDES_API_TOKEN` (a static token or a service-account
key). Optionally `FIDES_ENCRYPTION_KEY` to encrypt attestation payloads.

## Pipeline (build/CI)
| Command | Purpose |
|---|---|
| `fides trail start --flow <id> --trail <name> [--repository --commit --branch --message]` | Begin a build trail |
| `fides artifact report --org <id> --trail <id> --sha256 <hex>\|--file <path> --name <n> --type docker` | Register an artifact |
| `fides attest --trail <id> --name <n> --type <t> --payload <json\|file> [--attachments a,b] [--encrypt]` | Generic attestation |
| `fides attest junit\|snyk\|trivy --trail <id> --file <report> [--name --artifact-sha]` | Parse a report into an attestation |
| `fides assert --sha256 <hex> --policy <name>` | Policy gate for an artifact |
| `fides verify-chain --trail <id>` | Verify the tamper-evidence chain (exit 2 if broken) |
| `fides audit --trail <id> [--output <file.zip>]` | Download the trail audit package |

## Runtime snapshots
| Command | Purpose |
|---|---|
| `fides snapshot docker --env <id> [--container <n>]` | Docker runtime |
| `fides snapshot k8s --env <id> [--namespace <ns>]` | Kubernetes (via kubectl) |
| `fides snapshot ecs --env <id> --cluster <name>` | AWS ECS (via aws CLI) |
| `fides snapshot lambda --env <id>` | AWS Lambda (via aws CLI) |

## Environments, policies, approvals
| Command | Purpose |
|---|---|
| `fides allowlist add\|list\|check\|remove --env <id> [--sha <hex> --reason <r>]` | Per-environment artifact approvals (`check` exits 2 if not approved) |
| `fides flow list \| trails --flow <id> \| artifacts --flow <id>` | List flows and their trails / artifacts |
| `fides policy create --name --rules-file \| delete --id \| generate --framework --description` | Global policies: create, delete, and AI-draft rules (via the LLM) |
| `fides policy add\|list\|check --env <id> [--name --require t1,t2 --if-tag --if-value --trail]` | Environment policies (`check` exits 2 on non-compliance) |
| `fides env diff --env <id> [--from <snap> --to <snap>]` | Diff two snapshots |
| `fides logical-env create\|list\|add-member\|state [--name --id --env]` | Logical (aggregate) environments |

## Search & metrics
| Command | Purpose |
|---|---|
| `fides search artifacts [--sha --commit --name]` | Search artifacts |
| `fides search attestations [--type --trail --compliant]` | Search attestations |
| `fides metrics [--days N]` | DORA delivery metrics |
| `fides metrics deployment-frequency [--weeks N]` | Weekly deployment frequency per environment |

## Integration & admin config
| Command | Purpose |
|---|---|
| `fides servicenow config\|get\|change-check [...]` | ServiceNow connection + change gate |
| `fides slack config --secret-path <ref> [--disable]` | Slack notifications |
| `fides git-provider config --provider --host --api-base --token-path [--inbound-secret-path]` | GitHub/GitLab provider |
| `fides webhook config --name --url --secret-path [--events] [--disable]` | Outbound signed webhook |
| `fides service-account create\|list\|issue-key\|revoke-key [...]` | Service accounts + API keys |
| `fides user set-password --user <id> --password <pw>` | Set a user's local password |

## AI tools (MCP)
Fides ships **`fides-mcp`**, a Model Context Protocol server so Claude Code, Cursor, and Claude Desktop can query your compliance data (flows, environments, artifacts, attestations, controls coverage, deployment frequency) **and read the Fides docs** in-conversation. See **[mcp-server.md](mcp-server.md)**.

See [features.md](features.md) for worked examples of each.
